// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local thread lifecycle backed by the broker process.

use alloc::sync::Arc;

use litebox_broker_protocol::ThreadId;

use crate::{
    LiteBox,
    broker::{BrokerControl, error::BrokerControlError},
    sync::RawSyncPrimitivesProvider,
};

/// Error returned while creating a broker-backed thread.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CreateError {
    /// This LiteBox instance has no broker association.
    #[error("thread creation requires a broker")]
    BrokerRequired,
    /// The broker association is no longer usable.
    #[error("broker association failed")]
    AssociationFailed,
    /// The broker cannot create another thread.
    #[error("thread capacity is exhausted")]
    ResourceExhausted,
}

/// Error returned while finishing a broker-backed thread.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum FinishError {
    /// The broker association is no longer usable.
    #[error("broker association failed")]
    AssociationFailed,
    /// The thread is not owned by this process.
    #[error("unknown thread")]
    UnknownThread,
}

/// One broker-backed thread belonging to the associated process.
///
/// The shim owns this value for the lifetime of its local task. Normal task
/// teardown must call [`Self::finish`] after guest and local thread cleanup.
/// Dropping it without finishing leaves broker ownership in place until process
/// teardown.
#[must_use = "normal thread teardown must call Thread::finish"]
pub struct Thread {
    id: ThreadId,
    broker: Arc<dyn BrokerControl>,
}

impl Thread {
    /// Returns the broker-assigned thread ID.
    #[must_use]
    pub const fn id(&self) -> ThreadId {
        self.id
    }

    /// Completes normal thread teardown.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns an error that is invalid for thread
    /// teardown.
    pub fn finish(self) -> Result<(), FinishError> {
        self.broker.finish_thread(self.id).map_err(map_finish_error)
    }
}

impl<Platform: RawSyncPrimitivesProvider> LiteBox<Platform> {
    /// Creates a broker-backed thread belonging to this process.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns an error that is invalid for thread
    /// creation.
    pub fn create_thread(&self) -> Result<Thread, CreateError> {
        let broker = self.broker_control().ok_or(CreateError::BrokerRequired)?;
        let id = broker.create_thread().map_err(map_create_error)?;
        Ok(Thread { id, broker })
    }
}

fn map_create_error(error: BrokerControlError) -> CreateError {
    match error {
        BrokerControlError::AssociationFailed => CreateError::AssociationFailed,
        BrokerControlError::Broker(
            litebox_broker_protocol::error::ErrorCode::ResourceExhausted
            | litebox_broker_protocol::error::ErrorCode::OutOfMemory,
        ) => CreateError::ResourceExhausted,
        BrokerControlError::Broker(error) => {
            panic!("broker returned unexpected create-thread error: {error}")
        }
    }
}

fn map_finish_error(error: BrokerControlError) -> FinishError {
    match error {
        BrokerControlError::AssociationFailed => FinishError::AssociationFailed,
        BrokerControlError::Broker(litebox_broker_protocol::error::ErrorCode::UnknownObject) => {
            FinishError::UnknownThread
        }
        BrokerControlError::Broker(error) => {
            panic!("broker returned unexpected finish-thread error: {error}")
        }
    }
}
