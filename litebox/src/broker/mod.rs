// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use litebox_broker_protocol::{CoreRequest, CoreResponse, ErrorCode};

use crate::sync::{RawSyncPrimitivesProvider, RwLock};

mod event;
pub use event::{EventCounter, EventCounterError};
pub use litebox_broker_protocol::EventConsumeMode;

/// Error returned by the deployment-provided broker control path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BrokerControlError {
    /// The broker control transport failed.
    Transport,
    /// The broker returned an operation error.
    Broker(ErrorCode),
    /// The broker returned a response shape that does not match the request.
    UnexpectedResponse,
}

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
