// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::channel::LocalControlChannel;
use litebox_broker_protocol::event::{ConsumeEventResponse, EventConsumeMode, ReadinessState};

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
    fn create_event_with_count(
        &self,
        initial_count: u64,
    ) -> core::result::Result<ObjectHandle, BrokerControlError>;

    fn wait_event(
        &self,
        handle: ObjectHandle,
    ) -> core::result::Result<ReadinessState, BrokerControlError>;

    fn add_event(
        &self,
        handle: ObjectHandle,
        value: u64,
    ) -> core::result::Result<ReadinessState, BrokerControlError>;

    fn consume_event(
        &self,
        handle: ObjectHandle,
        mode: EventConsumeMode,
    ) -> core::result::Result<ConsumeEventResponse, BrokerControlError>;

    fn close_object(&self, handle: ObjectHandle) -> core::result::Result<(), BrokerControlError>;
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
    fn create_event_with_count(
        &self,
        initial_count: u64,
    ) -> core::result::Result<ObjectHandle, BrokerControlError> {
        Ok(self.local.lock().create_event_with_count(initial_count)?)
    }

    fn wait_event(
        &self,
        handle: ObjectHandle,
    ) -> core::result::Result<ReadinessState, BrokerControlError> {
        Ok(self.local.lock().wait_event(handle)?)
    }

    fn add_event(
        &self,
        handle: ObjectHandle,
        value: u64,
    ) -> core::result::Result<ReadinessState, BrokerControlError> {
        Ok(self.local.lock().add_event(handle, value)?)
    }

    fn consume_event(
        &self,
        handle: ObjectHandle,
        mode: EventConsumeMode,
    ) -> core::result::Result<ConsumeEventResponse, BrokerControlError> {
        Ok(self.local.lock().consume_event(handle, mode)?)
    }

    fn close_object(&self, handle: ObjectHandle) -> core::result::Result<(), BrokerControlError> {
        Ok(self.local.lock().close_object(handle)?)
    }
}
