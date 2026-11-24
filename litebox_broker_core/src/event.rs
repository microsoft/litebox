// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned event object operations.

use crate::object::{ObjectEntry, ObjectRights, StatusFlags};
use crate::readiness::{ReadinessRegistration, ReadinessWatchers};
use crate::{BrokerError, BrokerProcess, Result};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::event::EventConsumption;
use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags, FileStatusFlags};
use litebox_broker_protocol::readiness::ReadinessFlags;
use spin::Mutex;
#[cfg(verus_keep_ghost)]
use vstd::prelude::old;
use vstd::prelude::verus_spec;

#[cfg(verus_keep_ghost)]
#[path = "event_spec.rs"]
pub mod verification;

pub(crate) const MAX_EVENT_COUNT: u64 = u64::MAX - 1;

#[cfg(test)]
pub(crate) fn create(
    process: &BrokerProcess,
    initial_count: u64,
    flags: FileOpenFlags,
) -> Result<ObjectHandle> {
    create_with_mode(process, initial_count, flags, false)
}

/// Creates a broker-owned event with initial readiness credits and a shared semaphore mode.
///
/// The event starts with the status flags `flags`, which must be within
/// [`FileOpenFlags::STATUS`].
pub fn create_with_mode(
    process: &BrokerProcess,
    initial_count: u64,
    flags: FileOpenFlags,
    semaphore: bool,
) -> Result<ObjectHandle> {
    let status = StatusFlags::new(flags)?;
    if initial_count > MAX_EVENT_COUNT {
        return Err(BrokerError::ResourceExhausted);
    }

    process.create_object_reference(ObjectEntry::Event(EventObject::new(
        initial_count,
        status,
        semaphore,
    )))
}

/// Adds readiness credits to a broker-owned event object.
///
/// Fails with `WouldBlock` if the count would exceed its maximum, or
/// `NonBlockingWouldBlock` if the event is also non-blocking.
pub fn add(process: &BrokerProcess, handle: ObjectHandle, value: u64) -> Result<ReadinessFlags> {
    let object = process.authorized_object(handle, ObjectRights::WRITE)?;
    let mut object = object.write();
    object.as_event_mut()?.add(value)
}

/// Consumes readiness credits from a broker-owned event object.
///
/// Fails with `WouldBlock` if the count is zero, or `NonBlockingWouldBlock`
/// if the event is also non-blocking.
pub fn consume(process: &BrokerProcess, handle: ObjectHandle) -> Result<EventConsumption> {
    let object = process.authorized_object(handle, ObjectRights::WAIT)?;
    let mut object = object.write();
    object.as_event_mut()?.consume()
}

impl ObjectEntry {
    #[verus_spec(result => ensures
        verification::event_projection(*old(self), *final(self), match result {
            Ok(value) => Ok((*value, *final(value))),
            Err(error) => Err(error),
        }),
    )]
    fn as_event_mut(&mut self) -> Result<&mut EventObject> {
        match self {
            Self::Event(event) => Ok(event),
            _ => Err(BrokerError::InvalidRights),
        }
    }
}

/// An event counter, whose references share its count, status flags, and semaphore mode.
pub(crate) struct EventObject {
    count: u64,
    status: StatusFlags,
    semaphore: bool,
    /// Registrations of references that other processes can change the
    /// count under.
    watchers: Mutex<ReadinessWatchers>,
}

impl EventObject {
    fn new(count: u64, status: StatusFlags, semaphore: bool) -> Self {
        Self {
            count,
            status,
            semaphore,
            watchers: Mutex::new(ReadinessWatchers::default()),
        }
    }

    fn add(&mut self, value: u64) -> Result<ReadinessFlags> {
        self.count = self
            .count
            .checked_add(value)
            .filter(|count| *count <= MAX_EVENT_COUNT)
            .ok_or(BrokerError::would_block(self.status.nonblocking()))?;
        let readiness = self.readiness();
        if value != 0 {
            self.watchers.get_mut().publish(readiness);
        }
        Ok(readiness)
    }

    fn consume(&mut self) -> Result<EventConsumption> {
        if self.count == 0 {
            return Err(BrokerError::would_block(self.status.nonblocking()));
        }

        let value = if self.semaphore { 1 } else { self.count };
        self.count -= value;
        let readiness = self.readiness();
        self.watchers.get_mut().publish(readiness);
        Ok(EventConsumption { value, readiness })
    }

    pub(crate) fn readiness(&self) -> ReadinessFlags {
        let mut readiness = ReadinessFlags::default();
        if self.count > 0 {
            readiness = readiness | ReadinessFlags::READ;
        }
        if self.count < MAX_EVENT_COUNT {
            readiness = readiness | ReadinessFlags::WRITE;
        }
        readiness
    }

    /// Publishes this event's later readiness changes through `registration`
    /// until every clone of `registration` drops.
    pub(crate) fn watch(&self, registration: &ReadinessRegistration) -> Result<()> {
        self.watchers.lock().watch(registration)
    }

    /// Returns the event's access mode and status flags.
    pub(crate) fn get_status_flags(&self) -> FileStatusFlags {
        self.status.get(FileAccessMode::ReadWrite)
    }

    /// Changes the status flags in `mask` to their values in `flags`.
    pub(crate) fn set_status_flags(&mut self, mask: FileOpenFlags, flags: FileOpenFlags) {
        self.status.set(mask, flags);
    }
}
