// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use litebox_broker_protocol::{
    AddEventRequest, ConsumeEventRequest, ConsumeEventResponse, CoreRequest, CoreResponse,
    CreateEventRequest, EventRequest, EventResponse, ObjectHandle, ReadinessState,
    WaitEventRequest, WaitOutcome,
};

use super::{
    BrokerControl, BrokerState,
    error::{BrokerObjectError, map_broker_object_result},
};
use crate::{
    event::{
        Events, IOPollable,
        counter::{EventCounter, EventCounterError, EventCounterReadMode},
        observer::Observer,
        polling::Pollee,
        polling::TryOpError,
        wait::WaitContext,
    },
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};

/// Broker-backed implementation of a local-core event counter.
pub(crate) struct BrokerEventCounter<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollee: Pollee<Platform>,
}

impl<Platform: RawSyncPrimitivesProvider> BrokerState<Platform> {
    pub(crate) fn create_event_counter(
        &self,
        initial_count: u64,
    ) -> Result<EventCounter<Platform>, EventCounterError>
    where
        Platform: TimeProvider,
    {
        let Some(control) = self.control.clone() else {
            return Err(EventCounterError::Unavailable);
        };
        BrokerEventCounter::new(control, initial_count).map(EventCounter::from_broker)
    }
}

impl<Platform> BrokerEventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn new(broker: Arc<dyn BrokerControl>, initial_count: u64) -> Result<Self, EventCounterError> {
        let response = request_event(
            &broker,
            EventRequest::Create(CreateEventRequest::new(initial_count)),
        )
        .map_err(EventCounterError::from)?;
        let EventResponse::Create(response) = response else {
            return Err(BrokerObjectError::UnexpectedResponse.into());
        };
        Ok(Self {
            broker,
            handle: response.handle,
            pollee: Pollee::new(),
        })
    }

    /// Returns whether blocking reads and writes are supported.
    pub(crate) fn supports_blocking_operations() -> bool {
        false
    }

    /// Reads the event counter.
    pub(crate) fn read(
        &self,
        _cx: &WaitContext<'_, Platform>,
        _nonblock: bool,
        mode: EventCounterReadMode,
    ) -> Result<u64, TryOpError<EventCounterError>> {
        let response = map_broker_object_result(self.consume(mode))?;
        if response.readiness.write_ready {
            self.pollee.notify_observers(Events::OUT);
        }
        Ok(response.value)
    }

    /// Writes readiness credits to the event counter.
    pub(crate) fn write(
        &self,
        _cx: &WaitContext<'_, Platform>,
        _nonblock: bool,
        value: u64,
    ) -> Result<usize, TryOpError<EventCounterError>> {
        if value == u64::MAX {
            return Err(TryOpError::Other(EventCounterError::InvalidInput));
        }
        let readiness = map_broker_object_result(self.add(value))?;
        if value != 0 && readiness.read_ready {
            self.pollee.notify_observers(Events::IN);
        }
        Ok(core::mem::size_of::<u64>())
    }

    fn consume(
        &self,
        mode: EventCounterReadMode,
    ) -> Result<ConsumeEventResponse, BrokerObjectError> {
        let response = self.request(EventRequest::Consume(ConsumeEventRequest::new(
            self.handle,
            to_protocol_consume_mode(mode),
        )))?;
        let EventResponse::Consume(response) = response else {
            return Err(BrokerObjectError::UnexpectedResponse);
        };
        Ok(response)
    }

    fn add(&self, value: u64) -> Result<ReadinessState, BrokerObjectError> {
        let response = self.request(EventRequest::Add(AddEventRequest::new(self.handle, value)))?;
        let EventResponse::Add(response) = response else {
            return Err(BrokerObjectError::UnexpectedResponse);
        };
        Ok(response.readiness)
    }

    fn readiness_state(&self) -> Result<ReadinessState, BrokerObjectError> {
        let response = self.request(EventRequest::Wait(WaitEventRequest::new(self.handle)))?;
        let EventResponse::Wait(response) = response else {
            return Err(BrokerObjectError::UnexpectedResponse);
        };
        Ok(match response.outcome {
            WaitOutcome::Ready(readiness) | WaitOutcome::WouldBlock(readiness) => readiness,
            _ => return Err(BrokerObjectError::UnexpectedResponse),
        })
    }

    fn request(&self, request: EventRequest) -> Result<EventResponse, BrokerObjectError> {
        request_event(&self.broker, request)
    }
}

impl<Platform> IOPollable for BrokerEventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        let Ok(readiness) = self.readiness_state() else {
            return Events::empty();
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

fn to_protocol_consume_mode(
    mode: EventCounterReadMode,
) -> litebox_broker_protocol::EventConsumeMode {
    match mode {
        EventCounterReadMode::All => litebox_broker_protocol::EventConsumeMode::All,
        EventCounterReadMode::One => litebox_broker_protocol::EventConsumeMode::One,
    }
}

fn request_event(
    broker: &Arc<dyn BrokerControl>,
    request: EventRequest,
) -> Result<EventResponse, BrokerObjectError> {
    let response = broker
        .request(CoreRequest::Event(request))
        .map_err(BrokerObjectError::from)?;
    match response {
        CoreResponse::Event(response) => Ok(response),
        _ => Err(BrokerObjectError::UnexpectedResponse),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::{collections::VecDeque, sync::Mutex};

    use litebox_broker_protocol::{
        AddEventResponse, ConsumeEventResponse, CoreRequest, CoreResponse, CreateEventResponse,
        EventResponse, ObjectHandle, ObjectReferenceGeneration, ObjectReferenceId, ReadinessState,
        WaitEventResponse,
    };

    use super::*;
    use crate::{
        BrokerControlError,
        event::{Events, IOPollable, observer::Observer, wait::WaitState},
        platform::mock::MockPlatform,
    };

    struct MockBrokerControl {
        responses: Mutex<VecDeque<CoreResponse>>,
    }

    impl MockBrokerControl {
        fn new(responses: impl IntoIterator<Item = CoreResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
            }
        }
    }

    impl BrokerControl for MockBrokerControl {
        fn request(
            &self,
            _request: CoreRequest,
        ) -> core::result::Result<CoreResponse, BrokerControlError> {
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(BrokerControlError::UnexpectedResponse)
        }
    }

    struct CountingObserver {
        notifications: AtomicUsize,
    }

    impl CountingObserver {
        fn new() -> Self {
            Self {
                notifications: AtomicUsize::new(0),
            }
        }

        fn notifications(&self) -> usize {
            self.notifications.load(Ordering::Relaxed)
        }
    }

    impl Observer<Events> for CountingObserver {
        fn on_events(&self, _events: &Events) {
            self.notifications.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn sample_handle() -> ObjectHandle {
        ObjectHandle::new(ObjectReferenceId::new(1), ObjectReferenceGeneration::new(1))
    }

    fn create_response() -> CoreResponse {
        CoreResponse::Event(EventResponse::Create(CreateEventResponse::new(
            sample_handle(),
        )))
    }

    fn add_response(read_ready: bool, write_ready: bool) -> CoreResponse {
        CoreResponse::Event(EventResponse::Add(AddEventResponse::new(
            ReadinessState::new(read_ready, write_ready, 1),
        )))
    }

    fn consume_response(value: u64, read_ready: bool, write_ready: bool) -> CoreResponse {
        CoreResponse::Event(EventResponse::Consume(ConsumeEventResponse::new(
            value,
            ReadinessState::new(read_ready, write_ready, 1),
        )))
    }

    fn event_counter(
        responses: impl IntoIterator<Item = CoreResponse>,
    ) -> BrokerEventCounter<MockPlatform> {
        BrokerEventCounter::new(Arc::new(MockBrokerControl::new(responses)), 0).unwrap()
    }

    fn observer() -> (Arc<CountingObserver>, Arc<dyn Observer<Events>>) {
        let observer = Arc::new(CountingObserver::new());
        let observer_dyn: Arc<dyn Observer<Events>> = observer.clone();
        (observer, observer_dyn)
    }

    #[test]
    fn create_maps_unexpected_response_shape() {
        let result = BrokerEventCounter::<MockPlatform>::new(
            Arc::new(MockBrokerControl::new([add_response(false, true)])),
            0,
        );

        assert!(matches!(result, Err(EventCounterError::UnexpectedResponse)));
    }

    #[test]
    fn zero_write_does_not_notify_read_observers() {
        let event = event_counter([create_response(), add_response(false, true)]);
        let (observer, observer_dyn) = observer();
        event.register_observer(Arc::downgrade(&observer_dyn), Events::IN);

        let wait = WaitState::new(MockPlatform::new());
        assert_eq!(event.write(&wait.context(), true, 0).unwrap(), 8);

        assert_eq!(observer.notifications(), 0);
    }

    #[test]
    fn nonzero_write_notifies_read_observers_when_broker_reports_ready() {
        let event = event_counter([create_response(), add_response(true, true)]);
        let (observer, observer_dyn) = observer();
        event.register_observer(Arc::downgrade(&observer_dyn), Events::IN);

        let wait = WaitState::new(MockPlatform::new());
        assert_eq!(event.write(&wait.context(), true, 1).unwrap(), 8);

        assert_eq!(observer.notifications(), 1);
    }

    #[test]
    fn read_does_not_notify_write_observers_without_broker_write_readiness() {
        let event = event_counter([create_response(), consume_response(1, false, false)]);
        let (observer, observer_dyn) = observer();
        event.register_observer(Arc::downgrade(&observer_dyn), Events::OUT);

        let wait = WaitState::new(MockPlatform::new());
        assert_eq!(
            event
                .read(&wait.context(), true, EventCounterReadMode::All)
                .unwrap(),
            1
        );

        assert_eq!(observer.notifications(), 0);
    }

    #[test]
    fn read_notifies_write_observers_when_broker_reports_write_ready() {
        let event = event_counter([create_response(), consume_response(1, false, true)]);
        let (observer, observer_dyn) = observer();
        event.register_observer(Arc::downgrade(&observer_dyn), Events::OUT);

        let wait = WaitState::new(MockPlatform::new());
        assert_eq!(
            event
                .read(&wait.context(), true, EventCounterReadMode::All)
                .unwrap(),
            1
        );

        assert_eq!(observer.notifications(), 1);
    }

    #[test]
    fn poll_uses_broker_read_and_write_readiness() {
        let event = event_counter([
            create_response(),
            CoreResponse::Event(EventResponse::Wait(WaitEventResponse::new(
                WaitOutcome::Ready(ReadinessState::new(true, false, 1)),
            ))),
            CoreResponse::Event(EventResponse::Wait(WaitEventResponse::new(
                WaitOutcome::WouldBlock(ReadinessState::new(false, true, 2)),
            ))),
        ]);

        assert_eq!(event.check_io_events(), Events::IN);
        assert_eq!(event.check_io_events(), Events::OUT);
    }
}
