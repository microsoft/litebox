// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed guest process creation, child termination, and signals
//! between processes.

use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::process::{ProcessExitStatus, ProcessIdentity, ProcessTermination};
use litebox_broker_protocol::signal::PendingSignal;
use litebox_broker_protocol::{ObjectHandle, ProcessId};
use litebox_platform::time::TimeProvider;

use crate::LiteBox;
use crate::broker::{
    BrokerControl, BrokerPollableRegistry, error::BrokerControlError, readiness_events,
};
use crate::event::{Events, IOPollable, observer::Observer, polling::Pollee};
use crate::fs::FileFd;
use crate::pipes::PipeFd;
use crate::sync::RawSyncPrimitivesProvider;

/// Error returned by the broker-backed process service.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProcessError {
    /// This LiteBox process has no broker process service.
    #[error("process creation is unavailable")]
    Unavailable,
    /// The broker association failed.
    #[error("process service failed")]
    ServiceFailed,
    /// Process duplication is disabled by policy.
    #[error("process duplication is denied")]
    PolicyDenied,
    /// Another pending child process already exists.
    #[error("a child process is already pending")]
    Busy,
    /// Process capacity is exhausted.
    #[error("process capacity is exhausted")]
    ResourceExhausted,
    /// Memory capacity is exhausted.
    #[error("process memory is exhausted")]
    OutOfMemory,
    /// The child process is invalid or no longer available.
    #[error("invalid child process")]
    InvalidChild,
    /// A descriptor passed to the child process is closed.
    #[error("descriptor is closed")]
    ClosedDescriptor,
    /// No process has the target process ID.
    #[error("no such process")]
    NoSuchProcess,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Allocates one pending child process.
    pub fn allocate_child_process(&self) -> Result<Process<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        let child = broker.allocate_child_process()?;
        Ok(Process::new(self, broker, child.identity, child.handle))
    }

    /// Reports this process's final termination status, which its parent
    /// observes once this process's runner exits.
    pub fn report_exit_status(&self, exit_status: ProcessExitStatus) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.report_exit_status(exit_status)?)
    }

    /// Sets whether this process's children are reaped when they terminate.
    ///
    /// Each child applies the setting in effect when it terminates, so a
    /// change does not affect children that already terminated.
    pub fn set_child_reaping(&self, enabled: bool) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.set_child_reaping(enabled)?)
    }

    /// Sends `signal` to process `process_id`, or only checks that the process
    /// exists if `signal` is zero.
    ///
    /// The target takes the signal through [`Signals`]. A signal already
    /// pending for the target is not sent again.
    pub fn send_signal(&self, process_id: ProcessId, signal: u32) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        match broker.send_signal(process_id, signal) {
            Err(BrokerControlError::Broker(ErrorCode::UnknownObject)) => {
                Err(ProcessError::NoSuchProcess)
            }
            result => Ok(result?),
        }
    }

    /// Opens the signals other processes send to this process, including
    /// those sent before it is opened.
    ///
    /// A process may hold only one [`Signals`] at a time.
    pub fn open_signals(&self) -> Result<Signals<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        let handle = broker.open_signals()?;
        Ok(Signals::new(self, broker, handle))
    }
}

/// A descriptor a pending child process can inherit through [`Process::inherit`].
///
/// This identifies only the object. The shim records guest-specific details, such as the
/// descriptor number, in the child's startup payload alongside the handle `inherit` returns.
pub enum InheritableFd<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    /// A file, adopted with [`LiteBox::adopt_inherited_file`].
    File(Arc<FileFd>),
    /// A pipe end, adopted with [`LiteBox::adopt_inherited_pipe`].
    Pipe(Arc<PipeFd<Platform>>),
}

/// Termination state of a child process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildStatus {
    /// The process has not terminated.
    Live,
    /// The process terminated with this status and waits to be reported.
    Terminated(ProcessExitStatus),
    /// The process terminated with this status and was reaped as it
    /// terminated, so no wait reports it.
    Reaped(ProcessExitStatus),
}

/// A broker process object.
///
/// It reports [`Events::IN`] once the process terminates. Dropping it closes
/// its handle, releases the process's retained exit status, and wakes its
/// observers to recheck their state.
pub struct Process<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    identity: ProcessIdentity,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Process<Platform> {
    fn new(
        litebox: &LiteBox<Platform>,
        broker: Arc<dyn BrokerControl>,
        identity: ProcessIdentity,
        handle: ObjectHandle,
    ) -> Self {
        let pollable_registry = litebox.broker_pollable_registry();
        let pollee = Arc::new(Pollee::new());
        pollable_registry.register_pollable(handle, &pollee);
        Self {
            broker,
            identity,
            handle,
            pollable_registry,
            pollee,
        }
    }

    /// Returns the broker-assigned process and initial thread IDs.
    pub fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    /// Starts this pending child process in a fresh runner.
    pub fn start(&self, payload: &[u8]) -> Result<(), ProcessError> {
        Ok(self
            .broker
            .start_child_process(self.identity.process_id, payload)?)
    }

    /// Gives this pending child process its own references to the objects
    /// `fds` refer to, returning the child's handles in the same order.
    ///
    /// Like descriptors a Linux child inherits, each child reference shares
    /// its object's state, such as a file's offset or a pipe's buffer.
    /// Descriptors sharing an open file description get the same handle. The
    /// child adopts each handle as the [`InheritableFd`] variant describes and
    /// releases its references when it terminates. If this fails, the child
    /// receives none of them.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns fewer handles than were duplicated.
    pub fn inherit(
        &self,
        litebox: &LiteBox<Platform>,
        fds: &[InheritableFd<Platform>],
    ) -> Result<Vec<ObjectHandle>, ProcessError> {
        // Holding the objects keeps their handles open until the child has its own.
        let mut held_files = Vec::new();
        let mut held_pipes = Vec::new();
        let mut fd_handles = Vec::new();
        for fd in fds {
            let handle = match fd {
                InheritableFd::File(file) => {
                    let file = litebox
                        .broker_file(file)
                        .ok_or(ProcessError::ClosedDescriptor)?;
                    let handle = file.handle();
                    held_files.push(file);
                    handle
                }
                InheritableFd::Pipe(pipe) => {
                    let pipe = litebox
                        .broker_pipe_end(pipe)
                        .ok_or(ProcessError::ClosedDescriptor)?;
                    let handle = pipe.handle();
                    held_pipes.push(pipe);
                    handle
                }
            };
            fd_handles.push(handle);
        }
        let mut handles = fd_handles.clone();
        handles.sort_unstable();
        handles.dedup();
        let inherited = self
            .broker
            .duplicate_objects_to_child(self.identity.process_id, &handles)?;
        Ok(fd_handles
            .iter()
            .map(|handle| {
                let index = handles
                    .binary_search(handle)
                    .expect("every descriptor handle was duplicated");
                inherited[index]
            })
            .collect())
    }

    /// Records that this pending child process exited without starting a
    /// runner, leaving it a zombie reporting `exit_status`.
    pub fn exit(&self, exit_status: ProcessExitStatus) -> Result<(), ProcessError> {
        Ok(self
            .broker
            .exit_child_process(self.identity.process_id, exit_status)?)
    }

    /// Returns the process's termination state.
    pub fn status(&self) -> Result<ChildStatus, ProcessError> {
        match self.broker.process_exit_status(self.handle) {
            Ok(ProcessTermination {
                exit_status,
                reaped: false,
            }) => Ok(ChildStatus::Terminated(exit_status)),
            Ok(ProcessTermination {
                exit_status,
                reaped: true,
            }) => Ok(ChildStatus::Reaped(exit_status)),
            Err(BrokerControlError::Broker(ErrorCode::WouldBlock)) => Ok(ChildStatus::Live),
            Err(error) => Err(error.into()),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for Process<Platform> {
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
        // Another waiter may still be blocked on this process's exit
        // notification, which is discarded once the handle is unregistered.
        self.pollee.wake_observers();
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for Process<Platform> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        self.broker
            .check_readiness(self.handle)
            .map_or(Events::ERR, readiness_events)
    }
}

/// The signals other processes send to this process.
///
/// It reports [`Events::IN`] while a signal is pending.
pub struct Signals<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Signals<Platform> {
    fn new(
        litebox: &LiteBox<Platform>,
        broker: Arc<dyn BrokerControl>,
        handle: ObjectHandle,
    ) -> Self {
        let pollable_registry = litebox.broker_pollable_registry();
        let pollee = Arc::new(Pollee::new());
        pollable_registry.register_pollable(handle, &pollee);
        Self {
            broker,
            handle,
            pollable_registry,
            pollee,
        }
    }

    /// Takes the lowest-numbered pending signal, or returns `None` if none is
    /// pending.
    pub fn take(&self) -> Result<Option<PendingSignal>, ProcessError> {
        match self.broker.take_signal(self.handle) {
            Ok(signal) => Ok(Some(signal)),
            Err(BrokerControlError::Broker(ErrorCode::WouldBlock)) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for Signals<Platform> {
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for Signals<Platform> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        self.broker
            .check_readiness(self.handle)
            .map_or(Events::ERR, readiness_events)
    }
}

impl From<BrokerControlError> for ProcessError {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::AssociationFailed => Self::ServiceFailed,
            BrokerControlError::Broker(ErrorCode::UnsupportedOperation) => Self::Unavailable,
            BrokerControlError::Broker(ErrorCode::PolicyDenied) => Self::PolicyDenied,
            BrokerControlError::Broker(ErrorCode::WouldBlock) => Self::Busy,
            BrokerControlError::Broker(ErrorCode::ResourceExhausted) => Self::ResourceExhausted,
            BrokerControlError::Broker(ErrorCode::OutOfMemory) => Self::OutOfMemory,
            BrokerControlError::Broker(
                ErrorCode::UnknownObject | ErrorCode::PeerClosed | ErrorCode::ProtocolState,
            ) => Self::InvalidChild,
            BrokerControlError::Broker(error) => {
                panic!("process service returned unexpected error: {error}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicBool, Ordering};

    use litebox_broker_local::test_support::test_broker_local;
    use litebox_broker_protocol::message::{
        BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult,
    };
    use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
    use litebox_broker_protocol::{ProcessId, ThreadId};
    use litebox_broker_transport::channel::LocalCallChannel;
    use litebox_broker_transport::shared_memory::{SharedMemory, SharedMemoryError};

    use super::*;
    use crate::platform::mock::MockPlatform;

    #[test]
    fn dropping_process_wakes_observers() {
        let litebox = LiteBox::new_with_broker_local(
            MockPlatform::new(),
            test_broker_local(CloseChannel, Arc::new(NoopSharedMemory)),
        );
        let process = Process::new(
            &litebox,
            litebox.broker_control().unwrap(),
            ProcessIdentity {
                process_id: ProcessId(3),
                initial_thread_id: ThreadId(4),
            },
            ObjectHandle(7),
        );
        let observer = Arc::new(WakeObserver(AtomicBool::new(false)));
        process.register_observer(Arc::downgrade(&observer) as _, Events::IN);

        // A waiter that reaps this process may drop it before the exit
        // notification arrives, so other waiters must still wake.
        drop(process);

        assert!(observer.0.load(Ordering::SeqCst));
    }

    struct WakeObserver(AtomicBool);

    impl Observer<Events> for WakeObserver {
        fn on_events(&self, _events: &Events) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    struct CloseChannel;

    impl LocalCallChannel for CloseChannel {
        type Error = ();

        fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Self::Error> {
            assert_eq!(
                request.operation,
                BrokerOperation::CloseObject(ObjectHandle(7))
            );
            Ok(BrokerResponse {
                request_id: request.request_id,
                result: BrokerResult::ObjectClosed,
            })
        }
    }

    struct NoopSharedMemory;

    impl SharedMemory for NoopSharedMemory {
        fn len(&self) -> usize {
            SHARED_BUFFER_POOL_SIZE
        }

        fn read(&self, _offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
            destination.fill(0);
            Ok(())
        }

        fn write(&self, _offset: usize, _source: &[u8]) -> Result<(), SharedMemoryError> {
            Ok(())
        }
    }
}
