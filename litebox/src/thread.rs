// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local thread lifecycle.

use alloc::sync::Arc;

use litebox_broker_protocol::ThreadId;

use crate::{
    LiteBox,
    broker::{BrokerControl, error::BrokerControlError},
    sync::RawSyncPrimitivesProvider,
};

/// Error returned while creating a thread.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CreateError {
    /// Thread creation is unavailable.
    #[error("thread creation is unavailable")]
    Unavailable,
    /// The thread service is no longer usable.
    #[error("thread service failed")]
    ServiceFailed,
    /// Another thread cannot be created.
    #[error("thread capacity is exhausted")]
    ResourceExhausted,
}

/// Error returned while exiting a thread.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExitError {
    /// The thread service is no longer usable.
    #[error("thread service failed")]
    ServiceFailed,
    /// The thread is not owned by this process.
    #[error("unknown thread")]
    UnknownThread,
}

/// One thread belonging to this LiteBox process.
///
/// The shim owns this value for the lifetime of its local task. Normal task
/// teardown must call [`Self::exit`] after guest and local thread cleanup.
/// Dropping it without exiting leaves ownership in place until process teardown.
#[must_use = "normal thread teardown must call Thread::exit"]
pub struct Thread {
    id: ThreadId,
    broker: Arc<dyn BrokerControl>,
}

impl Thread {
    /// Returns the assigned thread ID.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id.0
    }

    /// Records normal thread exit after local teardown completes.
    ///
    /// # Panics
    ///
    /// Panics if the thread service returns an error that is invalid for thread
    /// teardown.
    pub fn exit(self) -> Result<(), ExitError> {
        self.broker.exit_thread(self.id).map_err(ExitError::from)
    }
}

impl<Platform: RawSyncPrimitivesProvider> LiteBox<Platform> {
    /// Adopts a broker thread allocated during process negotiation.
    ///
    /// The caller must pass the initial thread ID from the negotiated broker
    /// association exactly once.
    pub fn adopt_thread(&self, id: ThreadId) -> Result<Thread, CreateError> {
        let broker = self.broker_control().ok_or(CreateError::Unavailable)?;
        Ok(Thread { id, broker })
    }

    /// Creates a thread belonging to this LiteBox process.
    ///
    /// # Panics
    ///
    /// Panics if the thread service returns an error that is invalid for thread
    /// creation.
    pub fn create_thread(&self) -> Result<Thread, CreateError> {
        let broker = self.broker_control().ok_or(CreateError::Unavailable)?;
        let id = broker.create_thread().map_err(CreateError::from)?;
        Ok(Thread { id, broker })
    }
}

impl From<BrokerControlError> for CreateError {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::AssociationFailed => Self::ServiceFailed,
            BrokerControlError::Broker(
                litebox_broker_protocol::error::ErrorCode::ResourceExhausted
                | litebox_broker_protocol::error::ErrorCode::OutOfMemory,
            ) => Self::ResourceExhausted,
            BrokerControlError::Broker(error) => {
                panic!("thread service returned unexpected create-thread error: {error}")
            }
        }
    }
}

impl From<BrokerControlError> for ExitError {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::AssociationFailed => Self::ServiceFailed,
            BrokerControlError::Broker(
                litebox_broker_protocol::error::ErrorCode::UnknownObject,
            ) => Self::UnknownThread,
            BrokerControlError::Broker(error) => {
                panic!("thread service returned unexpected exit-thread error: {error}")
            }
        }
    }
}
