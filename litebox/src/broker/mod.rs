// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use litebox_broker_local::{BrokerLocal, BrokerLocalError};
use litebox_broker_protocol::{CoreRequest, CoreResponse, LocalControlChannel};

use crate::sync::{Mutex, RawSyncPrimitivesProvider};

pub(crate) mod error;
use error::BrokerControlError;

/// Local-core access to the negotiated broker control channel.
///
/// LiteBox owns broker-backed local objects and constructs broker protocol
/// requests. Deployment code owns endpoint selection and supplies the connected
/// transport behind this protocol-level boundary.
pub(crate) trait BrokerControl: Send + Sync {
    /// Sends one active BrokerCore request and returns its response.
    fn request(
        &self,
        request: CoreRequest,
    ) -> core::result::Result<CoreResponse, BrokerControlError>;
}

pub(crate) struct BrokerLocalControl<Platform: RawSyncPrimitivesProvider, T> {
    local: Mutex<Platform, BrokerLocal<T>>,
}

impl<Platform, T> BrokerLocalControl<Platform, T>
where
    Platform: RawSyncPrimitivesProvider,
{
    pub(crate) const fn new(local: BrokerLocal<T>) -> Self {
        Self {
            local: Mutex::new(local),
        }
    }
}

impl<Platform, T> BrokerControl for BrokerLocalControl<Platform, T>
where
    Platform: RawSyncPrimitivesProvider,
    T: LocalControlChannel + Send,
{
    fn request(
        &self,
        request: CoreRequest,
    ) -> core::result::Result<CoreResponse, BrokerControlError> {
        self.local
            .lock()
            .active_core_request(request)
            .map_err(|error| match error {
                BrokerLocalError::Broker(error) => BrokerControlError::Broker(error),
                BrokerLocalError::UnexpectedResponse(_) => BrokerControlError::UnexpectedResponse,
                _ => BrokerControlError::Transport,
            })
    }
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

    pub(crate) fn control(&self) -> Option<Arc<dyn BrokerControl>> {
        self.control.clone()
    }
}
