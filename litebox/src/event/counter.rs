// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::event::ConsumeEventResponse;
pub use litebox_broker_protocol::event::EventConsumeMode as EventCounterReadMode;
use litebox_broker_protocol::readiness::ReadinessFlags;
use thiserror::Error;

use crate::{
    LiteBox,
    broker::{
        BrokerControl, BrokerPollableRegistry,
        error::{BrokerControlError, BrokerObjectError},
        readiness_events,
    },
    event::{
        Events, IOPollable, observer::Observer, polling::Pollee, polling::TryOpError,
        wait::WaitContext,
    },
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};

/// Errors returned by local-core event counters.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventCounterError {
    #[error("invalid event counter input")]
    InvalidInput,
    #[error("event counter operation would block")]
    WouldBlock,
    #[error("event counter resource exhausted")]
    ResourceExhausted,
    #[error("event counter permission denied")]
    PermissionDenied,
    #[error("event counter I/O failed")]
    Io,
    #[error("event counter backing authority unavailable")]
    Unavailable,
}

/// A local-core event counter object.
pub struct EventCounter<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform> EventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    /// Creates a local-core event counter.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued event request.
    pub fn new(litebox: &LiteBox<Platform>, initial_count: u64) -> Result<Self, EventCounterError> {
        let Some(broker) = litebox.broker_control() else {
            return Err(EventCounterError::Unavailable);
        };
        let handle = broker
            .create_event_with_count(initial_count)
            .map_err(BrokerObjectError::from)
            .map_err(EventCounterError::from)?;
        let pollable_registry = litebox.broker_pollable_registry();
        let pollee = Arc::new(Pollee::new());
        pollable_registry.register_pollable(handle, &pollee);
        Ok(Self {
            broker,
            handle,
            pollable_registry,
            pollee,
        })
    }

    /// Reads the event counter.
    pub fn read(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        mode: EventCounterReadMode,
    ) -> Result<u64, TryOpError<EventCounterError>> {
        self.pollee.wait(cx, nonblock, Events::IN, || {
            let response = self.consume(mode)?;
            if response.readiness.contains(ReadinessFlags::WRITE) {
                self.pollee.notify_observers(Events::OUT);
            }
            Ok(response.value)
        })
    }

    /// Writes readiness credits to the event counter.
    pub fn write(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        value: u64,
    ) -> Result<usize, TryOpError<EventCounterError>> {
        if value == u64::MAX {
            return Err(TryOpError::Other(EventCounterError::InvalidInput));
        }
        self.pollee.wait(cx, nonblock, Events::OUT, || {
            let readiness = self.add(value)?;
            if value != 0 && readiness.contains(ReadinessFlags::READ) {
                self.pollee.notify_observers(Events::IN);
            }
            Ok(core::mem::size_of::<u64>())
        })
    }

    fn consume(
        &self,
        mode: EventCounterReadMode,
    ) -> Result<ConsumeEventResponse, BrokerObjectError> {
        self.broker
            .consume_event(self.handle, mode)
            .map_err(|error| self.broker_request_error(error))
    }

    fn add(&self, value: u64) -> Result<ReadinessFlags, BrokerObjectError> {
        self.broker
            .add_event(self.handle, value)
            .map_err(|error| self.broker_request_error(error))
    }

    fn broker_request_error(&self, error: BrokerControlError) -> BrokerObjectError {
        let error = error.into();
        if error != BrokerObjectError::WouldBlock {
            self.pollee.notify_observers(Events::ERR);
        }
        error
    }
}

impl<Platform> Drop for EventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
    }
}

impl<Platform> IOPollable for EventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        let readiness = match self
            .broker
            .check_readiness(self.handle)
            .map_err(|error| self.broker_request_error(error))
        {
            Ok(readiness) => readiness,
            Err(BrokerObjectError::WouldBlock) => return Events::empty(),
            Err(_) => return Events::ERR,
        };
        readiness_events(readiness)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    use alloc::sync::Arc;
    use litebox_broker_local::BrokerLocal;
    use litebox_broker_protocol::error::ErrorCode;
    use litebox_broker_protocol::event::{CreateEventResponse, EventConsumption};
    use litebox_broker_protocol::message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerOperation,
        BrokerRequest, BrokerResponse, BrokerResult, EventRequest, EventResponse,
        ReadinessNotification,
    };
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_transport::channel::{LocalCallChannel, LocalSetupChannel};

    use super::*;
    use crate::LiteBox;
    use crate::event::wait::WaitState;
    use crate::platform::mock::MockPlatform;

    #[test]
    fn readiness_notification_wakes_blocked_read() {
        use std::time::{Duration, Instant};

        let platform = MockPlatform::new();
        let handle = ObjectHandle(7);
        let consume_attempts = Arc::new(AtomicUsize::new(0));
        let read_ready = Arc::new(AtomicBool::new(false));
        let request_count = Arc::new(AtomicUsize::new(0));
        let (local, ()) = BrokerLocal::negotiate(
            FakeLocalChannel {
                next_handle: AtomicU64::new(handle.0),
                consume_attempts: consume_attempts.clone(),
                read_ready: read_ready.clone(),
                request_count,
                fail_requests: Arc::new(AtomicBool::new(false)),
            },
            |channel| Ok((channel, Arc::new(NoopSharedMemory), ())),
        )
        .unwrap();
        let litebox = LiteBox::new_with_broker_local(platform, local);
        let counter = Arc::new(EventCounter::new(&litebox, 0).unwrap());

        let (result_sender, result_receiver) = std::sync::mpsc::channel();
        {
            let counter = counter.clone();
            std::thread::spawn(move || {
                result_sender
                    .send(counter.read(
                        &WaitState::new(platform).context(),
                        false,
                        EventCounterReadMode::One,
                    ))
                    .unwrap();
            });
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        // The second consume attempt happens after the waiter has registered its observer.
        while consume_attempts.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        read_ready.store(true, Ordering::SeqCst);
        litebox.dispatch_broker_notification(BrokerNotification::Readiness(
            ReadinessNotification {
                handle,
                readiness: ReadinessFlags::READ | ReadinessFlags::WRITE,
            },
        ));

        assert_eq!(
            result_receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap(),
            1
        );
    }

    #[test]
    fn broker_association_failure_wakes_blocked_read() {
        use std::time::{Duration, Instant};

        let platform = MockPlatform::new();
        let handle = ObjectHandle(7);
        let consume_attempts = Arc::new(AtomicUsize::new(0));
        let request_count = Arc::new(AtomicUsize::new(0));
        let (local, ()) = BrokerLocal::negotiate(
            FakeLocalChannel {
                next_handle: AtomicU64::new(handle.0),
                consume_attempts: Arc::clone(&consume_attempts),
                read_ready: Arc::new(AtomicBool::new(false)),
                request_count: Arc::clone(&request_count),
                fail_requests: Arc::new(AtomicBool::new(false)),
            },
            |channel| Ok((channel, Arc::new(NoopSharedMemory), ())),
        )
        .unwrap();
        let litebox = Arc::new(LiteBox::new_with_broker_local(platform, local));
        let counter = Arc::new(EventCounter::new(&litebox, 0).unwrap());

        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(1);
        let read_counter = Arc::clone(&counter);
        let reader = std::thread::spawn(move || {
            result_sender
                .send(read_counter.read(
                    &WaitState::new(platform).context(),
                    false,
                    EventCounterReadMode::One,
                ))
                .unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while consume_attempts.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }

        litebox.broker_failure_dispatcher()();

        assert!(matches!(
            result_receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap(),
            Err(TryOpError::Other(EventCounterError::Io))
        ));
        reader.join().unwrap();
        assert_eq!(request_count.load(Ordering::SeqCst), 3);
        assert_eq!(counter.check_io_events(), Events::ERR);
        assert_eq!(request_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn control_transport_failure_notifies_all_event_counters() {
        let platform = MockPlatform::new();
        let handle = ObjectHandle(7);
        let request_count = Arc::new(AtomicUsize::new(0));
        let fail_requests = Arc::new(AtomicBool::new(false));
        let (local, ()) = BrokerLocal::negotiate(
            FakeLocalChannel {
                next_handle: AtomicU64::new(handle.0),
                consume_attempts: Arc::new(AtomicUsize::new(0)),
                read_ready: Arc::new(AtomicBool::new(false)),
                request_count: Arc::clone(&request_count),
                fail_requests: Arc::clone(&fail_requests),
            },
            |channel| Ok((channel, Arc::new(NoopSharedMemory), ())),
        )
        .unwrap();
        let litebox = LiteBox::new_with_broker_local(platform, local);
        let first = EventCounter::new(&litebox, 0).unwrap();
        let second = EventCounter::new(&litebox, 0).unwrap();
        let first_observer = Arc::new(ErrorObserver(AtomicBool::new(false)));
        let first_observer_dyn: Arc<dyn Observer<Events>> = first_observer.clone();
        first.register_observer(Arc::downgrade(&first_observer_dyn), Events::ERR);
        let second_observer = Arc::new(ErrorObserver(AtomicBool::new(false)));
        let second_observer_dyn: Arc<dyn Observer<Events>> = second_observer.clone();
        second.register_observer(Arc::downgrade(&second_observer_dyn), Events::ERR);

        fail_requests.store(true, Ordering::SeqCst);

        assert_eq!(first.check_io_events(), Events::ERR);
        assert!(first_observer.0.load(Ordering::SeqCst));
        assert!(second_observer.0.load(Ordering::SeqCst));
        assert_eq!(request_count.load(Ordering::SeqCst), 3);
        assert_eq!(second.check_io_events(), Events::ERR);
        assert_eq!(request_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn broker_dispatchers_follow_objects_that_outlive_litebox() {
        let platform = MockPlatform::new();
        let handle = ObjectHandle(7);
        let request_count = Arc::new(AtomicUsize::new(0));
        let (local, ()) = BrokerLocal::negotiate(
            FakeLocalChannel {
                next_handle: AtomicU64::new(handle.0),
                consume_attempts: Arc::new(AtomicUsize::new(0)),
                read_ready: Arc::new(AtomicBool::new(false)),
                request_count: Arc::clone(&request_count),
                fail_requests: Arc::new(AtomicBool::new(false)),
            },
            |channel| Ok((channel, Arc::new(NoopSharedMemory), ())),
        )
        .unwrap();
        let litebox = LiteBox::new_with_broker_local(platform, local);
        let counter = EventCounter::new(&litebox, 0).unwrap();
        let read_observer = Arc::new(ReadObserver(AtomicBool::new(false)));
        let read_observer_dyn: Arc<dyn Observer<Events>> = read_observer.clone();
        counter.register_observer(Arc::downgrade(&read_observer_dyn), Events::IN);
        let litebox_weak = Arc::downgrade(&litebox.x);
        let dispatch_notification = litebox.broker_notification_dispatcher();
        let dispatch_failure = litebox.broker_failure_dispatcher();

        drop(litebox);

        assert!(litebox_weak.upgrade().is_none());
        dispatch_notification(BrokerNotification::Readiness(ReadinessNotification {
            handle,
            readiness: ReadinessFlags::READ,
        }));
        assert!(read_observer.0.load(Ordering::SeqCst));
        dispatch_failure();
        assert_eq!(counter.check_io_events(), Events::ERR);
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
    }

    struct ErrorObserver(AtomicBool);

    impl Observer<Events> for ErrorObserver {
        fn on_events(&self, events: &Events) {
            if events.contains(Events::ERR) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
    }

    struct ReadObserver(AtomicBool);

    impl Observer<Events> for ReadObserver {
        fn on_events(&self, events: &Events) {
            if events.contains(Events::IN) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
    }

    struct FakeLocalChannel {
        next_handle: AtomicU64,
        consume_attempts: Arc<AtomicUsize>,
        read_ready: Arc<AtomicBool>,
        request_count: Arc<AtomicUsize>,
        fail_requests: Arc<AtomicBool>,
    }

    struct NoopSharedMemory;

    impl litebox_broker_transport::shared_memory::SharedMemory for NoopSharedMemory {
        fn len(&self) -> usize {
            litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE
        }

        fn read(
            &self,
            _offset: usize,
            destination: &mut [u8],
        ) -> core::result::Result<(), litebox_broker_transport::shared_memory::SharedMemoryError>
        {
            destination.fill(0);
            Ok(())
        }

        fn write(
            &self,
            _offset: usize,
            _source: &[u8],
        ) -> core::result::Result<(), litebox_broker_transport::shared_memory::SharedMemoryError>
        {
            Ok(())
        }
    }

    impl LocalSetupChannel for FakeLocalChannel {
        type Error = ();

        fn send_handshake_request(
            &mut self,
            _request: &BrokerHandshakeRequest,
        ) -> core::result::Result<(), Self::Error> {
            Ok(())
        }

        fn recv_handshake_response(
            &mut self,
        ) -> core::result::Result<Option<BrokerHandshakeResponse>, Self::Error> {
            Ok(Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
            }))
        }
    }

    impl LocalCallChannel for FakeLocalChannel {
        type Error = ();

        fn call(
            &self,
            request: BrokerRequest,
        ) -> core::result::Result<BrokerResponse, Self::Error> {
            self.request_count.fetch_add(1, Ordering::SeqCst);
            if self.fail_requests.load(Ordering::SeqCst) {
                return Err(());
            }
            let result = match request.operation {
                BrokerOperation::Event(EventRequest::Create(_)) => {
                    let handle = ObjectHandle(self.next_handle.fetch_add(1, Ordering::SeqCst));
                    BrokerResult::Event(EventResponse::Create(CreateEventResponse { handle }))
                }
                BrokerOperation::Event(EventRequest::Consume(_)) => {
                    self.consume_attempts.fetch_add(1, Ordering::SeqCst);
                    if self.read_ready.swap(false, Ordering::SeqCst) {
                        BrokerResult::Event(EventResponse::Consume(EventConsumption {
                            value: 1,
                            readiness: ReadinessFlags::WRITE,
                        }))
                    } else {
                        BrokerResult::Error(ErrorCode::WouldBlock)
                    }
                }
                BrokerOperation::CloseObject(_) => BrokerResult::ObjectClosed,
                BrokerOperation::CheckReadiness(_) => {
                    BrokerResult::Readiness(ReadinessFlags::WRITE)
                }
                request @ (BrokerOperation::Event(_)
                | BrokerOperation::Pipe(_)
                | BrokerOperation::Socket(_)) => {
                    panic!("unexpected broker request: {request:?}")
                }
            };
            Ok(BrokerResponse {
                request_id: request.request_id,
                result,
            })
        }
    }
}
