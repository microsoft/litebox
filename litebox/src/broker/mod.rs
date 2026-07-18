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
use litebox_broker_protocol::pipe::CreatePipeResponse;
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

    fn check_readiness(
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

    fn create_pipe(
        &self,
        capacity: u64,
        atomic_write_size: u64,
    ) -> core::result::Result<CreatePipeResponse, BrokerControlError>;

    fn read_pipe(
        &self,
        handle: ObjectHandle,
        length: u32,
    ) -> core::result::Result<Vec<u8>, BrokerControlError>;

    fn write_pipe(
        &self,
        handle: ObjectHandle,
        data: &[u8],
    ) -> core::result::Result<usize, BrokerControlError>;

    fn close_object(&self, handle: ObjectHandle) -> core::result::Result<(), BrokerControlError>;

    fn fail_connection(&self);
}

pub(crate) struct BrokerPollableRegistry<Platform: RawSyncPrimitivesProvider> {
    pollables: Mutex<Platform, HashMap<ObjectHandle, Weak<Pollee<Platform>>>>,
}

impl<Platform: RawSyncPrimitivesProvider> BrokerPollableRegistry<Platform> {
    pub(crate) fn new() -> Self {
        Self {
            pollables: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn register_pollable(&self, handle: ObjectHandle, pollee: &Arc<Pollee<Platform>>) {
        let previous = self.pollables.lock().insert(handle, Arc::downgrade(pollee));
        assert!(
            previous.is_none(),
            "broker handle already has a registered pollable"
        );
    }

    pub(crate) fn unregister_pollable(&self, handle: ObjectHandle) {
        self.pollables.lock().remove(&handle);
    }

    pub(crate) fn notify_readiness(&self, handle: ObjectHandle, readiness: ReadinessFlags)
    where
        Platform: TimeProvider,
    {
        let events = readiness_events(readiness);
        if events.is_empty() {
            return;
        }
        let pollee = {
            let mut pollables = self.pollables.lock();
            let pollee = pollables.get(&handle).and_then(Weak::upgrade);
            if pollee.is_none() {
                pollables.remove(&handle);
            }
            pollee
        };
        if let Some(pollee) = pollee {
            pollee.notify_observers(events);
        }
    }

    fn notify_all(&self, events: Events)
    where
        Platform: TimeProvider,
    {
        let pollables = {
            let mut pollables = Vec::new();
            self.pollables.lock().retain(|_, registered| {
                let Some(pollee) = registered.upgrade() else {
                    return false;
                };
                pollables.push(pollee);
                true
            });
            pollables
        };
        for pollee in pollables {
            pollee.notify_observers(events);
        }
    }
}

pub(crate) struct BrokerLocalControl<
    Platform: RawSyncPrimitivesProvider,
    Channel: LocalControlChannel + Send,
> {
    local: Mutex<Platform, Option<BrokerLocal<Channel>>>,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
}

impl<Platform, Channel> BrokerLocalControl<Platform, Channel>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
    Channel: LocalControlChannel + Send,
{
    pub(crate) fn new(
        local: BrokerLocal<Channel>,
        pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    ) -> Self {
        Self {
            local: Mutex::new(Some(local)),
            pollable_registry,
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
            self.pollable_registry.notify_all(Events::ERR);
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

    fn check_readiness(
        &self,
        handle: ObjectHandle,
    ) -> core::result::Result<ReadinessFlags, BrokerControlError> {
        self.request(|local| local.check_readiness(handle))
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

    fn create_pipe(
        &self,
        capacity: u64,
        atomic_write_size: u64,
    ) -> core::result::Result<CreatePipeResponse, BrokerControlError> {
        self.request(|local| local.create_pipe(capacity, atomic_write_size))
    }

    fn read_pipe(
        &self,
        handle: ObjectHandle,
        length: u32,
    ) -> core::result::Result<Vec<u8>, BrokerControlError> {
        self.request(|local| local.read_pipe(handle, length))
    }

    fn write_pipe(
        &self,
        handle: ObjectHandle,
        data: &[u8],
    ) -> core::result::Result<usize, BrokerControlError> {
        self.request(|local| local.write_pipe(handle, data))
    }

    fn close_object(&self, handle: ObjectHandle) -> core::result::Result<(), BrokerControlError> {
        self.request(|local| local.close_object(handle))
    }

    fn fail_connection(&self) {
        let connection = self.local.lock().take();
        if let Some(connection) = connection {
            drop(connection);
            self.pollable_registry.notify_all(Events::ERR);
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
