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

    fn fail_connection(&self);
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

    fn notify_all(&self, events: Events)
    where
        Platform: TimeProvider,
    {
        let pollables = {
            let mut pollables = Vec::new();
            self.handles.lock().retain(|_, entry| {
                entry.prune_stale_pollables();
                pollables.extend(entry.pollables.iter().filter_map(Weak::upgrade));
                !entry.pollables.is_empty()
            });
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
    local: Mutex<Platform, Option<BrokerLocal<Channel>>>,
    handles: Arc<BrokerHandleRegistry<Platform>>,
}

impl<Platform, Channel> BrokerLocalControl<Platform, Channel>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
    Channel: LocalControlChannel + Send,
{
    pub(crate) fn new(
        local: BrokerLocal<Channel>,
        handles: Arc<BrokerHandleRegistry<Platform>>,
    ) -> Self {
        Self {
            local: Mutex::new(Some(local)),
            handles,
        }
    }

    fn request<T>(
        &self,
        request: impl FnOnce(
            &mut BrokerLocal<Channel>,
        ) -> litebox_broker_local::Result<T, Channel::Error>,
    ) -> core::result::Result<T, BrokerControlError> {
        let (result, failed_connection) = {
            let mut local = self.local.lock();
            let Some(connection) = local.as_mut() else {
                return Err(BrokerControlError::Transport);
            };
            let result = request(connection).map_err(BrokerControlError::from);
            let failed_connection = if matches!(result.as_ref(), Err(BrokerControlError::Transport))
            {
                local.take()
            } else {
                None
            };
            (result, failed_connection)
        };
        if let Some(connection) = failed_connection {
            drop(connection);
            self.handles.notify_all(Events::ERR);
        }
        result
    }
}

impl<Platform, Channel> BrokerControl for BrokerLocalControl<Platform, Channel>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
    Channel: LocalControlChannel + Send,
{
    fn create_event_with_count(
        &self,
        initial_count: u64,
    ) -> core::result::Result<ObjectHandle, BrokerControlError> {
        self.request(|local| local.create_event_with_count(initial_count))
    }

    fn wait_event(
        &self,
        handle: ObjectHandle,
    ) -> core::result::Result<ReadinessFlags, BrokerControlError> {
        self.request(|local| local.wait_event(handle))
    }

    fn add_event(
        &self,
        handle: ObjectHandle,
        value: u64,
    ) -> core::result::Result<ReadinessFlags, BrokerControlError> {
        self.request(|local| local.add_event(handle, value))
    }

    fn consume_event(
        &self,
        handle: ObjectHandle,
        mode: EventConsumeMode,
    ) -> core::result::Result<ConsumeEventResponse, BrokerControlError> {
        self.request(|local| local.consume_event(handle, mode))
    }

    fn close_object(&self, handle: ObjectHandle) -> core::result::Result<(), BrokerControlError> {
        self.request(|local| local.close_object(handle))
    }

    fn fail_connection(&self) {
        let connection = self.local.lock().take();
        if let Some(connection) = connection {
            drop(connection);
            self.handles.notify_all(Events::ERR);
        }
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
