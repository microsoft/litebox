// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed guest process creation and child termination.

use alloc::sync::Arc;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::process::{ProcessExitStatus, ProcessIdentity};
use litebox_platform::time::TimeProvider;

use crate::LiteBox;
use crate::broker::{
    BrokerControl, BrokerPollableRegistry, error::BrokerControlError, readiness_events,
};
use crate::event::{Events, IOPollable, observer::Observer, polling::Pollee};
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
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Allocates one pending child process.
    pub fn allocate_child_process(&self) -> Result<Process<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        let child = broker.allocate_child_process()?;
        Ok(Process::new(self, broker, child.identity, child.handle))
    }
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

    /// Records that this pending child process exited without starting a
    /// runner, leaving it a zombie reporting `exit_status`.
    pub fn exit(&self, exit_status: ProcessExitStatus) -> Result<(), ProcessError> {
        Ok(self
            .broker
            .exit_child_process(self.identity.process_id, exit_status)?)
    }

    /// Returns the process's termination status, or `None` while the process is live.
    pub fn exit_status(&self) -> Result<Option<ProcessExitStatus>, ProcessError> {
        match self.broker.process_exit_status(self.handle) {
            Ok(status) => Ok(Some(status)),
            Err(BrokerControlError::Broker(ErrorCode::WouldBlock)) => Ok(None),
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
