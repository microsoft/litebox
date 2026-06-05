// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::object::{ObjectId, ObjectKind};
use crate::{BrokerAssociation, BrokerCore, BrokerError, ObjectRights, ObjectType, Result};
use litebox_broker_protocol::{
    EventConsumeMode, EventConsumption, ObjectHandle, ReadinessState, WaitOutcome,
};

const MAX_EVENT_COUNT: u64 = u64::MAX - 1;

impl BrokerCore {
    /// Creates a broker-owned event object.
    pub fn create_event(&mut self, association: &BrokerAssociation) -> Result<ObjectHandle> {
        self.create_event_with_count(association, 0)
    }

    /// Creates a broker-owned event object with initial readiness credits.
    pub fn create_event_with_count(
        &mut self,
        association: &BrokerAssociation,
        initial_count: u64,
    ) -> Result<ObjectHandle> {
        if initial_count > MAX_EVENT_COUNT {
            return Err(BrokerError::ResourceExhausted);
        }
        let rights = self.authorize_create_object(association, ObjectType::Event)?;

        self.insert_object_with_reference(
            association,
            ObjectKind::Event(EventObject::new(initial_count)),
            ObjectType::Event,
            rights,
        )
    }

    /// Checks whether an event wait would complete now.
    ///
    /// Blocking is intentionally outside BrokerCore for the first proof of
    /// concept. Userland or kernel deployments can block on deployment-specific
    /// wait primitives after BrokerCore authorizes and reports readiness state.
    pub fn wait_event(
        &mut self,
        association: &BrokerAssociation,
        handle: ObjectHandle,
    ) -> Result<WaitOutcome> {
        let authorized =
            self.authorize_use_object(association, handle, ObjectType::Event, ObjectRights::WAIT)?;
        let state = Self::filter_readiness_for_rights(
            self.event_state(authorized.object_id)?,
            authorized.rights,
        );
        Ok(if state.read_ready {
            WaitOutcome::Ready(state)
        } else {
            WaitOutcome::WouldBlock(state)
        })
    }

    /// Adds readiness credits to a broker-owned event object.
    pub fn add_event(
        &mut self,
        association: &BrokerAssociation,
        handle: ObjectHandle,
        value: u64,
    ) -> Result<ReadinessState> {
        let authorized =
            self.authorize_use_object(association, handle, ObjectType::Event, ObjectRights::WRITE)?;
        match &mut self.object_mut(authorized.object_id)?.kind {
            ObjectKind::Event(event) => event
                .add(value)
                .map(|state| Self::filter_readiness_for_rights(state, authorized.rights)),
        }
    }

    /// Consumes readiness credits from a broker-owned event object.
    pub fn consume_event(
        &mut self,
        association: &BrokerAssociation,
        handle: ObjectHandle,
        mode: EventConsumeMode,
    ) -> Result<EventConsumption> {
        let authorized =
            self.authorize_use_object(association, handle, ObjectType::Event, ObjectRights::WAIT)?;
        match &mut self.object_mut(authorized.object_id)?.kind {
            ObjectKind::Event(event) => event.consume(mode).map(|response| {
                EventConsumption::new(
                    response.value,
                    Self::filter_readiness_for_rights(response.readiness, authorized.rights),
                )
            }),
        }
    }

    fn filter_readiness_for_rights(state: ReadinessState, rights: ObjectRights) -> ReadinessState {
        ReadinessState::new(
            rights.contains(ObjectRights::WAIT) && state.read_ready,
            rights.contains(ObjectRights::WRITE) && state.write_ready,
            state.generation,
        )
    }

    fn event_state(&self, object_id: ObjectId) -> Result<ReadinessState> {
        match &self.object(object_id)?.kind {
            ObjectKind::Event(event) => Ok(event.readiness_state()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EventObject {
    count: u64,
    readiness_generation: u64,
}

impl EventObject {
    pub(crate) const fn new(count: u64) -> Self {
        Self {
            count,
            readiness_generation: 0,
        }
    }

    pub(crate) const fn readiness_state(self) -> ReadinessState {
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

    #[test]
    fn event_readiness_state_only_reports_authorized_directions() {
        let readiness = ReadinessState::new(true, true, 7);

        assert_eq!(
            BrokerCore::filter_readiness_for_rights(readiness, ObjectRights::WAIT),
            ReadinessState::new(true, false, 7)
        );
        assert_eq!(
            BrokerCore::filter_readiness_for_rights(readiness, ObjectRights::WRITE),
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
