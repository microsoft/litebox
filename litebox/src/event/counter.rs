// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use litebox_broker_protocol::ObjectHandle;
pub use litebox_broker_protocol::event::EventConsumeMode as EventCounterReadMode;
use litebox_broker_protocol::event::{ConsumeEventResponse, ReadinessState};
use thiserror::Error;

use crate::{
    LiteBox,
    broker::{
        BrokerControl, BrokerHandleRegistry,
        error::{BrokerControlError, BrokerObjectError},
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
    registry: Arc<BrokerHandleRegistry<Platform>>,
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
        let registry = litebox.broker_handle_registry();
        let pollee = Arc::new(Pollee::new());
        registry.register_pollable(handle, &pollee);
        Ok(Self {
            broker,
            handle,
            registry,
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
            if response.readiness.write_ready {
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
            if value != 0 && readiness.read_ready {
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

    fn add(&self, value: u64) -> Result<ReadinessState, BrokerObjectError> {
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
        self.registry.unregister_pollable(self.handle, &self.pollee);
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
            .wait_event(self.handle)
            .map_err(|error| self.broker_request_error(error))
        {
            Ok(readiness) => readiness,
            Err(BrokerObjectError::WouldBlock) => return Events::empty(),
            Err(_) => return Events::ERR,
        };
        let mut events = Events::empty();
        if readiness.read_ready {
            events |= Events::IN;
        }
        if readiness.write_ready {
            events |= Events::OUT;
        }
        events
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use alloc::sync::Arc;
    use litebox_broker_local::BrokerLocal;
    use litebox_broker_protocol::channel::LocalControlChannel;
    use litebox_broker_protocol::error::ErrorCode;
    use litebox_broker_protocol::event::{CreateEventResponse, EventConsumption, ReadinessState};
    use litebox_broker_protocol::message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerRequest,
        BrokerResponse, EventReadinessNotification, EventRequest, EventResponse,
    };

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
        let local = BrokerLocal::negotiate(FakeLocalControlChannel {
            handle,
            consume_attempts: consume_attempts.clone(),
            read_ready: read_ready.clone(),
            last_request: None,
        })
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
        litebox.dispatch_broker_notification(BrokerNotification::EventReadiness(
            EventReadinessNotification {
                handle,
                readiness: ReadinessState {
                    read_ready: true,
                    write_ready: true,
                },
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

    struct FakeLocalControlChannel {
        handle: ObjectHandle,
        consume_attempts: Arc<AtomicUsize>,
        read_ready: Arc<AtomicBool>,
        last_request: Option<BrokerRequest>,
    }

    impl LocalControlChannel for FakeLocalControlChannel {
        type Error = core::convert::Infallible;

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

        fn send_request(
            &mut self,
            request: &BrokerRequest,
        ) -> core::result::Result<(), Self::Error> {
            self.last_request = Some(request.clone());
            Ok(())
        }

        fn recv_response(&mut self) -> core::result::Result<Option<BrokerResponse>, Self::Error> {
            let response = match self.last_request.take().unwrap() {
                BrokerRequest::Event(EventRequest::Create(_)) => {
                    BrokerResponse::Event(EventResponse::Create(CreateEventResponse {
                        handle: self.handle,
                    }))
                }
                BrokerRequest::Event(EventRequest::Consume(request))
                    if request.handle == self.handle =>
                {
                    self.consume_attempts.fetch_add(1, Ordering::SeqCst);
                    if self.read_ready.swap(false, Ordering::SeqCst) {
                        BrokerResponse::Event(EventResponse::Consume(EventConsumption {
                            value: 1,
                            readiness: ReadinessState {
                                read_ready: false,
                                write_ready: true,
                            },
                        }))
                    } else {
                        BrokerResponse::Error(ErrorCode::WouldBlock)
                    }
                }
                BrokerRequest::CloseObject(handle) if handle == self.handle => {
                    BrokerResponse::ObjectClosed
                }
                request => panic!("unexpected broker request: {request:?}"),
            };
            Ok(Some(response))
        }
    }
}
