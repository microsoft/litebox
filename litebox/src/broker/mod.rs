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
use litebox_broker_protocol::event::{ConsumeEventResponse, EventConsumeMode};
use litebox_broker_protocol::readiness::ReadinessFlags;

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
    ) -> core::result::Result<ReadinessFlags, BrokerControlError>;

    fn add_event(
        &self,
        handle: ObjectHandle,
        value: u64,
    ) -> core::result::Result<ReadinessFlags, BrokerControlError>;

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
            if entry.pollables.is_empty() {
                handles.remove(&handle);
            }
        }
    }

    pub(crate) fn notify_readiness(&self, handle: ObjectHandle, readiness: ReadinessFlags)
    where
        Platform: TimeProvider,
    {
        let events = readiness_events(readiness);
        if events.is_empty() {
            return;
        }
        let pollables = {
            let mut handles = self.handles.lock();
            let Some(entry) = handles.get_mut(&handle) else {
                return;
            };
            entry.prune_stale_pollables();
            let pollables = entry
                .pollables
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>();
            if entry.pollables.is_empty() {
                handles.remove(&handle);
            }
            pollables
        };
        for pollee in pollables {
            pollee.notify_observers(events);
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
    ) -> core::result::Result<ReadinessFlags, BrokerControlError> {
        Ok(self.local.lock().wait_event(handle)?)
    }

    fn add_event(
        &self,
        handle: ObjectHandle,
        value: u64,
    ) -> core::result::Result<ReadinessFlags, BrokerControlError> {
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

pub(crate) fn readiness_events(readiness: ReadinessFlags) -> Events {
    let mut events = Events::empty();
    events.set(Events::IN, readiness.0 & ReadinessFlags::READ.0 != 0);
    events.set(Events::OUT, readiness.0 & ReadinessFlags::WRITE.0 != 0);
    events.set(Events::HUP, readiness.0 & ReadinessFlags::HANGUP.0 != 0);
    events.set(Events::ERR, readiness.0 & ReadinessFlags::ERROR.0 != 0);
    events
}
