// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use litebox_broker_protocol::{CoreRequest, CoreResponse};

use crate::sync::RawSyncPrimitivesProvider;

mod error;
pub(crate) mod event;
pub use error::BrokerControlError;

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
    control: Option<Arc<dyn BrokerControl>>,
    _marker: core::marker::PhantomData<Platform>,
}

impl<Platform: RawSyncPrimitivesProvider> BrokerState<Platform> {
    pub(crate) fn new(control: Option<Arc<dyn BrokerControl>>) -> Self {
        Self {
            control,
            _marker: core::marker::PhantomData,
        }
    }
}
