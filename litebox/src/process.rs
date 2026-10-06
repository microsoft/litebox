// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed guest process creation, the process tree, process groups
//! and sessions, and signals between processes.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::process::{
    ChildExit, ChildSelector, MAX_CHILD_MEMORY_WRITE_SIZE, ProcessExitStatus, ProcessIdentity,
    ProcessInfo,
};
use litebox_broker_protocol::signal::{SignalEvent, SignalTarget};
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
    /// The operation is denied by policy or by process group rules.
    #[error("process operation is denied")]
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
    pub fn allocate_child_process(&self) -> Result<PendingChild, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        let identity = broker.allocate_child_process()?;
        Ok(PendingChild {
            broker,
            identity,
            pending: AtomicBool::new(true),
        })
    }

    /// Reports this process's final termination status, which its parent
    /// reaps once this process's runner exits.
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

    /// Sets whether this process adopts the children of its exiting
    /// descendants.
    ///
    /// The children of an exiting process move to its nearest running ancestor
    /// that adopts them, or are left without a parent, which reaps each as it
    /// terminates.
    pub fn set_orphan_adoption(&self, enabled: bool) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.set_orphan_adoption(enabled)?)
    }

    /// Reaps the oldest of this process's terminated children that `selector`
    /// matches, in the order this process gained them, returning its exit.
    ///
    /// Returns `None` if every matching child is live, and
    /// [`ProcessError::NoSuchProcess`] if no child matches. Each child that
    /// terminates, or leaves without terminating, such as a child whose
    /// startup failed, is also reported through [`Signals`].
    pub fn reap_child(&self, selector: ChildSelector) -> Result<Option<ChildExit>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        match broker.reap_child(selector) {
            Ok(exit) => Ok(Some(exit)),
            Err(BrokerControlError::Broker(ErrorCode::WouldBlock)) => Ok(None),
            Err(error) => Err(no_such_process(error)),
        }
    }

    /// Returns the place of process `process_id` in the process tree.
    pub fn process_info(&self, process_id: ProcessId) -> Result<ProcessInfo, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        broker.process_info(process_id).map_err(no_such_process)
    }

    /// Sends `signal` to the processes `target` selects, or only checks that
    /// one exists if `signal` is zero.
    ///
    /// Each target takes the signal through [`Signals`]. A signal already
    /// pending for a target is not sent again. Returns
    /// [`ProcessError::NoSuchProcess`] if no process is targeted.
    pub fn send_signal(&self, target: SignalTarget, signal: u32) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        broker.send_signal(target, signal).map_err(no_such_process)
    }

    /// Moves process `process_id`, which is this process or one of its
    /// children, into `process_group`, creating the group if it is
    /// `process_id`.
    ///
    /// Returns [`ProcessError::PolicyDenied`] if the process is in another
    /// session than this process or leads a session, or if `process_group` is
    /// neither `process_id` nor an existing group in this process's session.
    pub fn set_process_group(
        &self,
        process_id: ProcessId,
        process_group: ProcessId,
    ) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        broker
            .set_process_group(process_id, process_group)
            .map_err(no_such_process)
    }

    /// Makes process `process_id`, which is this process or its pending
    /// child, the leader of a new session and of a new process group in it.
    ///
    /// Returns [`ProcessError::PolicyDenied`] if a process group already has
    /// the ID `process_id`.
    pub fn create_session(&self, process_id: ProcessId) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        broker.create_session(process_id).map_err(no_such_process)
    }

    /// Opens the signals other processes send to this process and the exits
    /// of its children, including those before it is opened.
    ///
    /// A process may hold only one [`Signals`] at a time.
    pub fn open_signals(&self) -> Result<Signals<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        let handle = broker.open_signals()?;
        Ok(Signals::new(self, broker, handle))
    }
}

/// A descriptor a pending child process can inherit through [`PendingChild::inherit`].
///
/// This identifies only the object. The shim records guest-specific details, such as the
/// descriptor number, in the child's startup payload alongside the handle `inherit` returns.
pub enum InheritableFd<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    /// A file, adopted with [`LiteBox::adopt_inherited_file`].
    File(Arc<FileFd>),
    /// A pipe end, adopted with [`LiteBox::adopt_inherited_pipe`].
    Pipe(Arc<PipeFd<Platform>>),
}

/// A child process that has not started.
///
/// Dropping it before it starts or exits discards the child, as if it had
/// never been created, except that its parent learns it was removed.
pub struct PendingChild {
    broker: Arc<dyn BrokerControl>,
    identity: ProcessIdentity,
    /// Cleared once the child starts or exits.
    pending: AtomicBool,
}

impl PendingChild {
    /// Returns the broker-assigned process and initial thread IDs.
    pub fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    /// Starts this pending child process in a fresh runner.
    pub fn start(&self, payload: &[u8]) -> Result<(), ProcessError> {
        self.broker
            .start_child_process(self.identity.process_id, payload)?;
        self.pending.store(false, Ordering::Relaxed);
        Ok(())
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
    pub fn inherit<Platform: RawSyncPrimitivesProvider + TimeProvider>(
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

    /// Writes `data` at `offset` of this pending child process's memory image,
    /// which the child's runner receives when the child starts.
    ///
    /// The image is zero-filled where nothing was written.
    pub fn write_memory(&self, offset: u64, data: &[u8]) -> Result<(), ProcessError> {
        let mut offset = offset;
        for chunk in data.chunks(MAX_CHILD_MEMORY_WRITE_SIZE as usize) {
            self.broker
                .write_child_memory(self.identity.process_id, offset, chunk)?;
            offset = offset
                .checked_add(chunk.len() as u64)
                .ok_or(ProcessError::ResourceExhausted)?;
        }
        Ok(())
    }

    /// Records that this pending child process exited without starting a
    /// runner, leaving it a zombie reporting `exit_status`.
    pub fn exit(&self, exit_status: ProcessExitStatus) -> Result<(), ProcessError> {
        self.broker
            .exit_child_process(self.identity.process_id, exit_status)?;
        self.pending.store(false, Ordering::Relaxed);
        Ok(())
    }
}

impl Drop for PendingChild {
    fn drop(&mut self) {
        if self.pending.load(Ordering::Relaxed) {
            // Failure means the child is already gone or the process service failed.
            let _ = self.broker.cancel_child_process(self.identity.process_id);
        }
    }
}

/// The signals other processes send to this process, and the exits of its
/// children.
///
/// It reports [`Events::IN`] while either is pending.
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

    /// Takes the lowest-numbered pending signal, or else a pending child
    /// exit, or else a pending child removal, or returns `None` if none is
    /// pending.
    ///
    /// Child events are coalesced: while one is pending, later events of its
    /// kind are not reported, so a taker reaps children until none has
    /// terminated.
    pub fn take(&self) -> Result<Option<SignalEvent>, ProcessError> {
        match self.broker.take_signal(self.handle) {
            Ok(event) => Ok(Some(event)),
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

/// Converts an error from a request that targets processes by ID.
fn no_such_process(error: BrokerControlError) -> ProcessError {
    match error {
        BrokerControlError::Broker(ErrorCode::UnknownObject) => ProcessError::NoSuchProcess,
        error => error.into(),
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
    use core::sync::atomic::AtomicUsize;

    use litebox_broker_local::test_support::test_broker_local;
    use litebox_broker_protocol::message::{
        BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult,
    };
    use litebox_broker_protocol::process::{CreateThreadRequest, CreateThreadResponse};
    use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
    use litebox_broker_protocol::{ProcessId, ThreadId};
    use litebox_broker_transport::channel::LocalCallChannel;
    use litebox_broker_transport::shared_memory::{SharedMemory, SharedMemoryError};

    use super::*;
    use crate::platform::mock::MockPlatform;

    #[test]
    fn dropping_a_pending_child_cancels_it() {
        let cancels = Arc::new(AtomicUsize::new(0));
        let litebox = LiteBox::new_with_broker_local(
            MockPlatform::new(),
            test_broker_local(ChildChannel(cancels.clone()), Arc::new(NoopSharedMemory)),
        );

        drop(litebox.allocate_child_process().unwrap());
        assert_eq!(cancels.load(Ordering::SeqCst), 1);

        let child = litebox.allocate_child_process().unwrap();
        child.exit(ProcessExitStatus::Exited { code: 0 }).unwrap();
        drop(child);
        assert_eq!(cancels.load(Ordering::SeqCst), 1);
    }

    /// Serves one pending child at a time, counting its cancellations.
    struct ChildChannel(Arc<AtomicUsize>);

    impl LocalCallChannel for ChildChannel {
        type Error = ();

        fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Self::Error> {
            let child = ProcessId(3);
            let result = match request.operation {
                BrokerOperation::CreateThread(CreateThreadRequest::Process) => {
                    BrokerResult::CreateThread(CreateThreadResponse::Process(ProcessIdentity {
                        process_id: child,
                        initial_thread_id: ThreadId(4),
                    }))
                }
                BrokerOperation::ExitChildProcess(request) if request.child_process_id == child => {
                    BrokerResult::ProcessExited
                }
                BrokerOperation::CancelChildProcess(process_id) if process_id == child => {
                    self.0.fetch_add(1, Ordering::SeqCst);
                    BrokerResult::ChildProcessCancelled
                }
                operation => panic!("unexpected operation {operation:?}"),
            };
            Ok(BrokerResponse {
                request_id: request.request_id,
                result,
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
