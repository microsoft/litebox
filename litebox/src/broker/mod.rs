// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use litebox_broker_protocol::{CoreRequest, CoreResponse};

use crate::sync::{RawSyncPrimitivesProvider, RwLock};

mod error;
mod event;
pub use error::{BrokerControlError, EventCounterError};
pub use event::EventCounter;
pub use litebox_broker_protocol::EventConsumeMode;

/// Local-core access to the negotiated broker control channel.
///
/// LiteBox owns broker-backed local objects and constructs broker protocol
/// requests. Deployment code owns endpoint selection and supplies the connected
/// transport behind this protocol-level boundary.
pub trait BrokerControl: Send + Sync {
    /// Sends one active BrokerCore request and returns its response.
    fn request(
        &self,
        request: CoreRequest,
    ) -> core::result::Result<CoreResponse, BrokerControlError>;
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
