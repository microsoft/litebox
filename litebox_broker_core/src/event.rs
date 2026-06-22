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
    session.with_authorized_object(handle, required_rights, |object| match object {
        ObjectEntry::Event(event) => {
            let readiness = ReadinessState::new(event.count > 0, event.count < MAX_EVENT_COUNT);
            Ok(if readiness.read_ready {
                WaitOutcome::Ready(readiness)
            } else {
                WaitOutcome::WouldBlock(readiness)
            })
        }
    })
}

/// Adds readiness credits to a broker-owned event object.
pub fn add(session: &BrokerSession, handle: ObjectHandle, value: u64) -> Result<ReadinessState> {
    let required_rights = ObjectRights::WRITE;
    session.with_authorized_object_mut(handle, required_rights, |object| match object {
        ObjectEntry::Event(event) => event.add(value),
    })
}

/// Consumes readiness credits from a broker-owned event object.
pub fn consume(
    session: &BrokerSession,
    handle: ObjectHandle,
    mode: EventConsumeMode,
) -> Result<EventConsumption> {
    let required_rights = ObjectRights::WAIT;
    session.with_authorized_object_mut(handle, required_rights, |object| match object {
        ObjectEntry::Event(event) => event.consume(mode),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EventObject {
    count: u64,
}

impl EventObject {
    const fn new(count: u64) -> Self {
        Self { count }
    }

    fn add(&mut self, value: u64) -> Result<ReadinessState> {
        self.count = self
            .count
            .checked_add(value)
            .filter(|count| *count <= MAX_EVENT_COUNT)
            .ok_or(BrokerError::WouldBlock)?;
        Ok(ReadinessState::new(
            self.count > 0,
            self.count < MAX_EVENT_COUNT,
        ))
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
        self.count -= value;
        Ok(EventConsumption::new(
            value,
            ReadinessState::new(self.count > 0, self.count < MAX_EVENT_COUNT),
        ))
    }
}
