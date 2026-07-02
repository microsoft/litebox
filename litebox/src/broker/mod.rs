// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::{Arc, Weak};

use hashbrown::HashMap;
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::channel::LocalControlChannel;
use litebox_broker_protocol::event::{ConsumeEventResponse, EventConsumeMode, ReadinessState};

use crate::event::counter::EventCounterWakeups;
use crate::platform::TimeProvider;
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

pub(crate) struct BrokerEventRegistry<Platform: RawSyncPrimitivesProvider> {
    events: Mutex<Platform, HashMap<ObjectHandle, Weak<EventCounterWakeups<Platform>>>>,
}

impl<Platform: RawSyncPrimitivesProvider> BrokerEventRegistry<Platform> {
    pub(crate) fn new() -> Self {
        Self {
            events: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn register_event(
        &self,
        handle: ObjectHandle,
        wakeups: &Arc<EventCounterWakeups<Platform>>,
    ) {
        self.events.lock().insert(handle, Arc::downgrade(wakeups));
    }

    pub(crate) fn unregister_event(&self, handle: ObjectHandle) {
        self.events.lock().remove(&handle);
    }
}

impl<Platform> BrokerEventRegistry<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    pub(crate) fn notify_event_readiness(&self, handle: ObjectHandle, readiness: ReadinessState) {
        let wakeups = {
            let mut events = self.events.lock();
            if let Some(wakeups) = events.get(&handle).and_then(Weak::upgrade) {
                Some(wakeups)
            } else {
                events.remove(&handle);
                None
            }
        };
        if let Some(wakeups) = wakeups {
            wakeups.notify_readiness(readiness);
        }
    }
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
