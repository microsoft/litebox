// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::channel::LocalControlChannel;
use litebox_broker_protocol::message::{BrokerRequest, BrokerResponse};

use crate::sync::{Mutex, RawSyncPrimitivesProvider};

pub(crate) mod error;
use error::BrokerControlError;

/// Local-core access to the negotiated broker control channel.
///
/// LiteBox owns broker-backed local objects and constructs broker protocol
/// requests. Deployment code owns endpoint selection and supplies the connected
/// transport behind this protocol-level boundary.
///
/// The current interface is intentionally blocking for the initial broker POC.
/// Longer-term broker integrations should move away from blocking control calls
/// once the local-core wait and notification model supports that shape.
pub(crate) trait BrokerControl: Send + Sync {
    /// Sends one active broker request and returns its response.
    fn request(
        &self,
        request: BrokerRequest,
    ) -> core::result::Result<BrokerResponse, BrokerControlError>;
}

pub(crate) struct BrokerLocalControl<
    Platform: RawSyncPrimitivesProvider,
    Channel: LocalControlChannel + Send,
> {
    local: Mutex<Platform, BrokerLocal<Channel>>,
}

impl<Platform, Channel> BrokerLocalControl<Platform, Channel>
where
    Platform: RawSyncPrimitivesProvider,
    Channel: LocalControlChannel + Send,
{
    pub(crate) const fn new(local: BrokerLocal<Channel>) -> Self {
        Self {
            local: Mutex::new(local),
        }
    }
}

impl<Platform, Channel> BrokerControl for BrokerLocalControl<Platform, Channel>
where
    Platform: RawSyncPrimitivesProvider,
    Channel: LocalControlChannel + Send,
{
    fn request(
        &self,
        request: BrokerRequest,
    ) -> core::result::Result<BrokerResponse, BrokerControlError> {
        Ok(self.local.lock().request(request)?)
    }
}
