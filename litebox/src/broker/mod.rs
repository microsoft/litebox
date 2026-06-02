// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use litebox_broker_protocol::{BrokerRequest, BrokerResponse};

use crate::sync::{RawSyncPrimitivesProvider, RwLock};

mod event_counter;
pub use event_counter::{EventCounter, EventCounterConsumeMode, EventCounterError};

/// Error returned by the deployment-provided broker control path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrokerControlError;

/// Local-core access to the negotiated broker control channel.
///
/// LiteBox owns broker-backed local objects and constructs broker protocol
/// requests. Deployment code owns endpoint selection and supplies the connected
/// transport behind this protocol-level boundary.
pub trait BrokerControl: Send + Sync {
    /// Sends one active broker request and returns its response.
    fn request(
        &self,
        request: BrokerRequest,
    ) -> core::result::Result<BrokerResponse, BrokerControlError>;
}

pub(crate) struct BrokerState<Platform: RawSyncPrimitivesProvider> {
    control: RwLock<Platform, Option<Arc<dyn BrokerControl>>>,
}

impl<Platform: RawSyncPrimitivesProvider> BrokerState<Platform> {
    pub(crate) fn new() -> Self {
        Self {
            control: RwLock::new(None),
        }
    }

    pub(crate) fn set_control(&self, broker_control: Arc<dyn BrokerControl>) {
        *self.control.write() = Some(broker_control);
    }
}
