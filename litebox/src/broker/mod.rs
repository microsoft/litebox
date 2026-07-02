// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};

use hashbrown::HashMap;
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::channel::LocalControlChannel;
use litebox_broker_protocol::event::{ConsumeEventResponse, EventConsumeMode, ReadinessState};

use crate::event::{Events, polling::Pollee};
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

pub(crate) struct BrokerHandleRegistry<Platform: RawSyncPrimitivesProvider> {
    handles: Mutex<Platform, HashMap<ObjectHandle, BrokerHandleEntry<Platform>>>,
}

impl<Platform: RawSyncPrimitivesProvider> BrokerHandleRegistry<Platform> {
    pub(crate) fn new() -> Self {
        Self {
            handles: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn register_pollable(&self, handle: ObjectHandle, pollee: &Arc<Pollee<Platform>>) {
        self.handles
            .lock()
            .entry(handle)
            .or_insert_with(BrokerHandleEntry::new)
            .register_pollable(pollee);
    }

    pub(crate) fn unregister_pollable(&self, handle: ObjectHandle, pollee: &Arc<Pollee<Platform>>) {
        let mut handles = self.handles.lock();
        if let Some(entry) = handles.get_mut(&handle) {
            entry.unregister_pollable(pollee);
            if entry.is_empty() {
                handles.remove(&handle);
            }
        }
    }

    pub(crate) fn notify_readiness(&self, handle: ObjectHandle, readiness: ReadinessState)
    where
        Platform: TimeProvider,
    {
        let mut handles = self.handles.lock();
        let Some(entry) = handles.get_mut(&handle) else {
            return;
        };
        entry.prune_stale_pollables();
        if entry.is_empty() {
            handles.remove(&handle);
            return;
        }

        let mut events = Events::empty();
        if readiness.read_ready {
            events |= Events::IN;
        }
        if readiness.write_ready {
            events |= Events::OUT;
        }
        if !events.is_empty() {
            entry.notify_pollables(events);
        }
    }
}

struct BrokerHandleEntry<Platform: RawSyncPrimitivesProvider> {
    pollables: Vec<Weak<Pollee<Platform>>>,
}

impl<Platform: RawSyncPrimitivesProvider> BrokerHandleEntry<Platform> {
    fn new() -> Self {
        Self {
            pollables: Vec::new(),
        }
    }

    fn register_pollable(&mut self, pollee: &Arc<Pollee<Platform>>) {
        self.pollables.push(Arc::downgrade(pollee));
    }

    fn unregister_pollable(&mut self, pollee: &Arc<Pollee<Platform>>) {
        self.pollables.retain(|registered| {
            registered
                .upgrade()
                .is_some_and(|registered| !Arc::ptr_eq(&registered, pollee))
        });
    }

    fn prune_stale_pollables(&mut self) {
        self.pollables
            .retain(|registered| registered.strong_count() > 0);
    }

    fn notify_pollables(&self, events: Events)
    where
        Platform: TimeProvider,
    {
        for registered in &self.pollables {
            if let Some(pollee) = registered.upgrade() {
                pollee.notify_observers(events);
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.pollables.is_empty()
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
