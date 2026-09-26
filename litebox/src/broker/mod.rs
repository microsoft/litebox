// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};

use hashbrown::HashMap;
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::event::{ConsumeEventResponse, EventConsumeMode};
use litebox_broker_protocol::pipe::{CreatePipeResponse, MAX_PIPE_TRANSFER_SIZE};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_transport::channel::LocalCallChannel;

use crate::event::{Events, polling::Pollee};
use crate::platform::TimeProvider;
use crate::sync::{Mutex, RawSyncPrimitivesProvider};

pub(crate) mod error;
mod shared_buffer;
use error::BrokerControlError;
use shared_buffer::{SlotAllocator, SlotLease};

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
    Channel: LocalCallChannel + Send + Sync,
> {
    local: Mutex<Platform, Option<Arc<BrokerLocal<Channel>>>>,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    slot_allocator: SlotAllocator<Platform>,
}

impl<Platform, Channel> BrokerLocalControl<Platform, Channel>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
    Channel: LocalCallChannel + Send + Sync,
{
    pub(crate) fn new(
        local: BrokerLocal<Channel>,
        pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    ) -> Self {
        Self {
            local: Mutex::new(Some(Arc::new(local))),
            pollable_registry,
            slot_allocator: SlotAllocator::new(),
        }
    }

    fn request<T>(
        &self,
        request: impl FnOnce(&BrokerLocal<Channel>) -> litebox_broker_local::Result<T, Channel::Error>,
    ) -> core::result::Result<T, BrokerControlError> {
        let connection = {
            let local = self.local.lock();
            let Some(connection) = local.as_ref() else {
                return Err(BrokerControlError::AssociationFailed);
            };
            Arc::clone(connection)
        };
        let result = request(&connection).map_err(BrokerControlError::from);
        if matches!(result.as_ref(), Err(BrokerControlError::AssociationFailed)) {
            self.fail_association();
        }
        result
    }

    fn acquire_shared_buffer(
        &self,
        length: u32,
    ) -> core::result::Result<SlotLease<'_, Platform>, BrokerControlError> {
        self.slot_allocator.acquire(length).map_err(|_| {
            self.fail_association();
            BrokerControlError::AssociationFailed
        })
    }

    fn fail_association(&self) {
        self.slot_allocator.fail();
        if self.local.lock().take().is_some() {
            self.pollable_registry.notify_all(Events::ERR);
        }
    }
}

impl<Platform, Channel> BrokerControl for BrokerLocalControl<Platform, Channel>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
    Channel: LocalCallChannel + Send + Sync,
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
        if length > MAX_PIPE_TRANSFER_SIZE {
            return Err(BrokerControlError::Broker(ErrorCode::ResourceExhausted));
        }
        let mut data = Vec::new();
        data.try_reserve_exact(length as usize)
            .map_err(|_| BrokerControlError::Broker(ErrorCode::OutOfMemory))?;
        data.resize(length as usize, 0);
        let lease = self.acquire_shared_buffer(length)?;
        let read = self.request(|local| local.read_pipe(handle, lease.descriptor(), &mut data))?;
        data.truncate(read);
        Ok(data)
    }

    fn write_pipe(
        &self,
        handle: ObjectHandle,
        data: &[u8],
    ) -> core::result::Result<usize, BrokerControlError> {
        if data.len() > MAX_PIPE_TRANSFER_SIZE as usize {
            return Err(BrokerControlError::Broker(ErrorCode::ResourceExhausted));
        }
        let length = u32::try_from(data.len())
            .expect("validated shared pipe transfer length must fit in u32");
        let lease = self.acquire_shared_buffer(length)?;
        self.request(|local| local.write_pipe(handle, lease.descriptor(), data))
    }

    fn close_object(&self, handle: ObjectHandle) -> core::result::Result<(), BrokerControlError> {
        self.request(|local| local.close_object(handle))
    }

    fn fail_connection(&self) {
        self.fail_association();
    }
}

pub(crate) fn readiness_events(readiness: ReadinessFlags) -> Events {
    let mut events = Events::empty();
    events.set(Events::IN, readiness.contains(ReadinessFlags::READ));
    events.set(Events::OUT, readiness.contains(ReadinessFlags::WRITE));
    events.set(Events::HUP, readiness.contains(ReadinessFlags::HANGUP));
    events.set(Events::ERR, readiness.contains(ReadinessFlags::ERROR));
    events
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::convert::Infallible;
    use std::sync::{Arc as StdArc, Condvar as StdCondvar, Mutex as StdMutex, mpsc};
    use std::time::Duration;

    use litebox_broker_protocol::BROKER_PROTOCOL_VERSION;
    use litebox_broker_protocol::message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerOperation, BrokerRequest,
        BrokerResponse, BrokerResult, PipeRequest, PipeResponse,
    };
    use litebox_broker_protocol::pipe::{ReadPipeResponse, WritePipeResponse};
    use litebox_broker_protocol::shared_buffer::{
        SHARED_BUFFER_POOL_SIZE, SHARED_BUFFER_SLOT_SIZE, SharedBufferDescriptor,
    };
    use litebox_broker_transport::channel::{LocalCallChannel, LocalSetupChannel};
    use litebox_broker_transport::shared_memory::{SharedMemory, SharedMemoryError};

    use crate::platform::mock::MockPlatform;

    #[test]
    fn concurrent_pipe_writes_use_distinct_shared_buffer_leases() {
        let memory = TestSharedMemory::new();
        let (observed_sender, observed_receiver) = mpsc::sync_channel(2);
        let release = StdArc::new((StdMutex::new(false), StdCondvar::new()));
        let channel = ConcurrentPipeChannel {
            memory: memory.clone(),
            observed_sender,
            release: StdArc::clone(&release),
        };
        let (local, ()) = BrokerLocal::negotiate(channel, |channel| {
            Ok((channel, Arc::new(memory) as Arc<dyn SharedMemory>, ()))
        })
        .unwrap();
        let control = Arc::new(BrokerLocalControl::<MockPlatform, _>::new(
            local,
            Arc::new(BrokerPollableRegistry::new()),
        ));
        let first_control = Arc::clone(&control);
        let first = std::thread::spawn(move || first_control.write_pipe(ObjectHandle(1), b"first"));
        let second_control = Arc::clone(&control);
        let second =
            std::thread::spawn(move || second_control.write_pipe(ObjectHandle(2), b"second"));

        let first_observed = observed_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        let second_observed = observed_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert_ne!(
            first_observed.0.slot_index, second_observed.0.slot_index,
            "simultaneous payload calls reused one slot"
        );
        let mut payloads = [first_observed.1, second_observed.1];
        payloads.sort();
        assert_eq!(payloads, [b"first".to_vec(), b"second".to_vec()]);

        let (released, available) = &*release;
        *released.lock().unwrap() = true;
        available.notify_all();
        assert_eq!(first.join().unwrap().unwrap(), 5);
        assert_eq!(second.join().unwrap().unwrap(), 6);
    }

    #[test]
    fn concurrent_pipe_reads_retain_distinct_shared_buffer_data() {
        let memory = TestSharedMemory::new();
        let (observed_sender, observed_receiver) = mpsc::sync_channel(2);
        let release = StdArc::new((StdMutex::new(false), StdCondvar::new()));
        let channel = ConcurrentPipeReadChannel {
            memory: memory.clone(),
            observed_sender,
            release: StdArc::clone(&release),
        };
        let (local, ()) = BrokerLocal::negotiate(channel, |channel| {
            Ok((channel, Arc::new(memory) as Arc<dyn SharedMemory>, ()))
        })
        .unwrap();
        let control = Arc::new(BrokerLocalControl::<MockPlatform, _>::new(
            local,
            Arc::new(BrokerPollableRegistry::new()),
        ));
        let first_control = Arc::clone(&control);
        let first = std::thread::spawn(move || first_control.read_pipe(ObjectHandle(1), 3));
        let second_control = Arc::clone(&control);
        let second = std::thread::spawn(move || second_control.read_pipe(ObjectHandle(2), 3));

        let first_buffer = observed_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        let second_buffer = observed_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert_ne!(
            first_buffer.slot_index, second_buffer.slot_index,
            "simultaneous payload calls reused one slot"
        );

        let (released, available) = &*release;
        *released.lock().unwrap() = true;
        available.notify_all();
        assert_eq!(first.join().unwrap().unwrap(), [1; 3]);
        assert_eq!(second.join().unwrap().unwrap(), [2; 3]);
    }

    #[derive(Clone)]
    struct TestSharedMemory(StdArc<StdMutex<std::vec::Vec<u8>>>);

    impl TestSharedMemory {
        fn new() -> Self {
            Self(StdArc::new(StdMutex::new(std::vec![
                0;
                SHARED_BUFFER_POOL_SIZE
            ])))
        }
    }

    impl SharedMemory for TestSharedMemory {
        fn len(&self) -> usize {
            self.0.lock().unwrap().len()
        }

        fn read(
            &self,
            offset: usize,
            destination: &mut [u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(destination.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(
                memory
                    .get(offset..end)
                    .ok_or(SharedMemoryError::InvalidRange)?,
            );
            Ok(())
        }

        fn write(
            &self,
            offset: usize,
            source: &[u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let mut memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(source.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            memory
                .get_mut(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?
                .copy_from_slice(source);
            Ok(())
        }
    }

    struct ConcurrentPipeChannel {
        memory: TestSharedMemory,
        observed_sender: mpsc::SyncSender<(SharedBufferDescriptor, std::vec::Vec<u8>)>,
        release: StdArc<(StdMutex<bool>, StdCondvar)>,
    }

    struct ConcurrentPipeReadChannel {
        memory: TestSharedMemory,
        observed_sender: mpsc::SyncSender<SharedBufferDescriptor>,
        release: StdArc<(StdMutex<bool>, StdCondvar)>,
    }

    impl LocalSetupChannel for ConcurrentPipeChannel {
        type Error = Infallible;

        fn send_handshake_request(
            &mut self,
            request: &BrokerHandshakeRequest,
        ) -> core::result::Result<(), Self::Error> {
            assert_eq!(request.protocol_version, BROKER_PROTOCOL_VERSION);
            Ok(())
        }

        fn recv_handshake_response(
            &mut self,
        ) -> core::result::Result<Option<BrokerHandshakeResponse>, Self::Error> {
            Ok(Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }))
        }
    }

    impl LocalCallChannel for ConcurrentPipeChannel {
        type Error = Infallible;

        fn call(
            &self,
            request: BrokerRequest,
        ) -> core::result::Result<BrokerResponse, Self::Error> {
            let BrokerOperation::Pipe(PipeRequest::Write(write)) = request.operation else {
                panic!("unexpected broker request");
            };
            let mut payload = std::vec![0; write.buffer.length as usize];
            self.memory
                .read(
                    write.buffer.slot_index.0 as usize * SHARED_BUFFER_SLOT_SIZE as usize,
                    &mut payload,
                )
                .unwrap();
            self.observed_sender.send((write.buffer, payload)).unwrap();
            let (released, available) = &*self.release;
            let mut released = released.lock().unwrap();
            while !*released {
                released = available.wait(released).unwrap();
            }
            Ok(BrokerResponse {
                request_id: request.request_id,
                result: BrokerResult::Pipe(PipeResponse::Write(WritePipeResponse {
                    written: write.buffer.length,
                })),
            })
        }
    }

    impl LocalSetupChannel for ConcurrentPipeReadChannel {
        type Error = Infallible;

        fn send_handshake_request(
            &mut self,
            request: &BrokerHandshakeRequest,
        ) -> core::result::Result<(), Self::Error> {
            assert_eq!(request.protocol_version, BROKER_PROTOCOL_VERSION);
            Ok(())
        }

        fn recv_handshake_response(
            &mut self,
        ) -> core::result::Result<Option<BrokerHandshakeResponse>, Self::Error> {
            Ok(Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }))
        }
    }

    impl LocalCallChannel for ConcurrentPipeReadChannel {
        type Error = Infallible;

        fn call(
            &self,
            request: BrokerRequest,
        ) -> core::result::Result<BrokerResponse, Self::Error> {
            let BrokerOperation::Pipe(PipeRequest::Read(read)) = request.operation else {
                panic!("unexpected broker request");
            };
            let payload = std::vec![
                u8::try_from(read.handle.0).unwrap();
                read.buffer.length as usize
            ];
            self.memory
                .write(
                    read.buffer.slot_index.0 as usize * SHARED_BUFFER_SLOT_SIZE as usize,
                    &payload,
                )
                .unwrap();
            self.observed_sender.send(read.buffer).unwrap();
            let (released, available) = &*self.release;
            let mut released = released.lock().unwrap();
            while !*released {
                released = available.wait(released).unwrap();
            }
            Ok(BrokerResponse {
                request_id: request.request_id,
                result: BrokerResult::Pipe(PipeResponse::Read(ReadPipeResponse {
                    read: read.buffer.length,
                })),
            })
        }
    }
}
