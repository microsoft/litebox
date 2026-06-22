// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned event object operations.

use crate::session::{ObjectEntry, ObjectRights};
use crate::{BrokerError, BrokerSession, Result};
use litebox_broker_protocol::{
    EventConsumeMode, EventConsumption, ObjectHandle, ReadinessState, WaitOutcome,
};

pub(crate) const MAX_EVENT_COUNT: u64 = u64::MAX - 1;

/// Creates a broker-owned event object with initial readiness credits.
pub fn create(session: &BrokerSession, initial_count: u64) -> Result<ObjectHandle> {
    if initial_count > MAX_EVENT_COUNT {
        return Err(BrokerError::ResourceExhausted);
    }

    session.create_object_reference(ObjectEntry::Event(EventObject::new(initial_count)))
}

/// Checks whether an event wait would complete now.
///
/// Blocking is intentionally outside BrokerCore for the first proof of
/// concept. Userland or kernel deployments can block on deployment-specific
/// wait primitives after BrokerCore authorizes and reports readiness state.
pub fn wait(session: &BrokerSession, handle: ObjectHandle) -> Result<WaitOutcome> {
    let required_rights = ObjectRights::WAIT;
    session.with_authorized_object(
        handle,
        required_rights,
        |object, reference_rights| match object {
            ObjectEntry::Event(event) => {
                let readiness =
                    filter_readiness_for_rights(event.readiness_state(), reference_rights);
                Ok(if readiness.read_ready {
                    WaitOutcome::Ready(readiness)
                } else {
                    WaitOutcome::WouldBlock(readiness)
                })
            }
        },
    )
}

/// Adds readiness credits to a broker-owned event object.
pub fn add(session: &BrokerSession, handle: ObjectHandle, value: u64) -> Result<ReadinessState> {
    let required_rights = ObjectRights::WRITE;
    session.with_authorized_object_mut(handle, required_rights, |object, reference_rights| {
        match object {
            ObjectEntry::Event(event) => event
                .add(value)
                .map(|state| filter_readiness_for_rights(state, reference_rights)),
        }
    })
}

/// Consumes readiness credits from a broker-owned event object.
pub fn consume(
    session: &BrokerSession,
    handle: ObjectHandle,
    mode: EventConsumeMode,
) -> Result<EventConsumption> {
    let required_rights = ObjectRights::WAIT;
    session.with_authorized_object_mut(handle, required_rights, |object, reference_rights| {
        match object {
            ObjectEntry::Event(event) => event.consume(mode).map(|response| {
                EventConsumption::new(
                    response.value,
                    filter_readiness_for_rights(response.readiness, reference_rights),
                )
            }),
        }
    })
}

fn filter_readiness_for_rights(state: ReadinessState, rights: ObjectRights) -> ReadinessState {
    ReadinessState::new(
        rights.contains(ObjectRights::WAIT) && state.read_ready,
        rights.contains(ObjectRights::WRITE) && state.write_ready,
        state.generation,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EventObject {
    count: u64,
    readiness_generation: u64,
}

impl EventObject {
    const fn new(count: u64) -> Self {
        Self {
            count,
            readiness_generation: 0,
        }
    }

    const fn readiness_state(self) -> ReadinessState {
        ReadinessState::new(
            self.count > 0,
            self.count < MAX_EVENT_COUNT,
            self.readiness_generation,
        )
    }

    fn add(&mut self, value: u64) -> Result<ReadinessState> {
        let new_count = self
            .count
            .checked_add(value)
            .filter(|count| *count <= MAX_EVENT_COUNT)
            .ok_or(BrokerError::WouldBlock)?;
        let next_generation = self.next_generation()?;
        self.count = new_count;
        self.readiness_generation = next_generation;
        Ok(self.readiness_state())
    }

    fn consume(&mut self, mode: EventConsumeMode) -> Result<EventConsumption> {
        if self.count == 0 {
            return Err(BrokerError::WouldBlock);
        }

        let value = match mode {
            EventConsumeMode::All => self.count,
            EventConsumeMode::One => 1,
            _ => return Err(BrokerError::UnsupportedOperation),
        };
        let next_generation = self.next_generation()?;
        self.count -= value;
        self.readiness_generation = next_generation;
        Ok(EventConsumption::new(value, self.readiness_state()))
    }

    fn next_generation(&self) -> Result<u64> {
        self.readiness_generation
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ObjectRights;

    #[test]
    fn event_readiness_state_only_reports_authorized_directions() {
        let readiness = ReadinessState::new(true, true, 7);

        assert_eq!(
            filter_readiness_for_rights(readiness, ObjectRights::WAIT),
            ReadinessState::new(true, false, 7)
        );
        assert_eq!(
            filter_readiness_for_rights(readiness, ObjectRights::WRITE),
            ReadinessState::new(false, true, 7)
        );
    }

    #[test]
    fn add_event_does_not_mutate_count_when_generation_is_exhausted() {
        let mut event = EventObject {
            count: 1,
            readiness_generation: u64::MAX,
        };

        assert_eq!(event.add(1), Err(BrokerError::ResourceExhausted));
        assert_eq!(event.count, 1);
        assert_eq!(event.readiness_generation, u64::MAX);
    }

    #[test]
    fn consume_event_does_not_mutate_count_when_generation_is_exhausted() {
        let mut event = EventObject {
            count: 1,
            readiness_generation: u64::MAX,
        };

        assert_eq!(
            event.consume(EventConsumeMode::One),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(event.count, 1);
        assert_eq!(event.readiness_generation, u64::MAX);
    }
}
