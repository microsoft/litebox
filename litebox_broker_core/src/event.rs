// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned event object operations.

use crate::session::{ObjectEntry, ObjectRights};
use crate::{BrokerError, BrokerSession, Result};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::event::{EventConsumeMode, EventConsumption};
use litebox_broker_protocol::readiness::ReadinessFlags;

pub(crate) const MAX_EVENT_COUNT: u64 = u64::MAX - 1;

/// Creates a broker-owned event object with initial readiness credits.
pub fn create(session: &BrokerSession, initial_count: u64) -> Result<ObjectHandle> {
    if initial_count > MAX_EVENT_COUNT {
        return Err(BrokerError::ResourceExhausted);
    }

    session.create_object_reference(ObjectEntry::Event(EventObject::new(initial_count)))
}

/// Adds readiness credits to a broker-owned event object.
pub fn add(session: &BrokerSession, handle: ObjectHandle, value: u64) -> Result<ReadinessFlags> {
    let required_rights = ObjectRights::WRITE;
    session.with_authorized_object_mut(handle, required_rights, |object| match object {
        ObjectEntry::Event(event) => event.add(value),
        ObjectEntry::Pipe(_) => Err(BrokerError::InvalidRights),
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
        ObjectEntry::Pipe(_) => Err(BrokerError::InvalidRights),
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

    fn add(&mut self, value: u64) -> Result<ReadinessFlags> {
        self.count = self
            .count
            .checked_add(value)
            .filter(|count| *count <= MAX_EVENT_COUNT)
            .ok_or(BrokerError::WouldBlock)?;
        Ok(self.readiness())
    }

    fn consume(&mut self, mode: EventConsumeMode) -> Result<EventConsumption> {
        if self.count == 0 {
            return Err(BrokerError::WouldBlock);
        }

        let value = match mode {
            EventConsumeMode::All => self.count,
            EventConsumeMode::One => 1,
        };
        self.count -= value;
        Ok(EventConsumption {
            value,
            readiness: self.readiness(),
        })
    }

    pub(crate) fn readiness(self) -> ReadinessFlags {
        let mut readiness = ReadinessFlags::default();
        if self.count > 0 {
            readiness = readiness | ReadinessFlags::READ;
        }
        if self.count < MAX_EVENT_COUNT {
            readiness = readiness | ReadinessFlags::WRITE;
        }
        readiness
    }
}
