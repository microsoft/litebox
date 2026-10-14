// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Readiness queue protocol types.
//!
//! A readiness queue watches other broker objects and queues entries whose
//! watched readiness occurs, so one wait covers many objects. Every reference
//! to a queue shares its entries. An entry is identified by its target object
//! together with a caller-chosen key, so one object may be watched under
//! several keys.

use bitflags::bitflags;
use thiserror::Error;

use crate::ObjectHandle;
use crate::readiness::ReadinessFlags;
use crate::shared_buffer::SharedBufferSequence;

/// Maximum number of ready events one take-ready request returns.
pub const MAX_READINESS_QUEUE_EVENTS: u32 = 4096;

/// Encoded size in bytes of one [`ReadyEvent`] in a take-ready buffer.
pub const READY_EVENT_SIZE: u32 = 12;

bitflags! {
    /// How a readiness queue entry reports its watched readiness.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct ReadinessQueueEntryFlags: u8 {
        /// Report the entry once each time its target publishes watched
        /// readiness, rather than for as long as that readiness persists.
        const EDGE_TRIGGERED = 1 << 0;
        /// Disable the entry after it is reported once, until it is modified.
        const ONE_SHOT = 1 << 1;
    }
}

/// What a readiness queue entry watches and how it reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadinessQueueInterest {
    /// Target readiness to report. Other target readiness is ignored.
    pub readiness: ReadinessFlags,
    /// Reporting mode.
    pub flags: ReadinessQueueEntryFlags,
    /// Caller-chosen value returned with each of the entry's events.
    pub token: u64,
}

/// Response to a readiness queue create request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateReadinessQueueResponse {
    /// Created queue handle.
    pub handle: ObjectHandle,
}

/// Request to add an entry to a readiness queue.
///
/// Fails with [`ReadinessQueueError::AlreadyRegistered`] if the queue has an
/// entry for `target` and `key`. The broker returns `UnsupportedOperation` if
/// `target` has no readiness to watch or is itself a readiness queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddReadinessQueueEntryRequest {
    /// Queue handle.
    pub queue: ObjectHandle,
    /// Object to watch.
    pub target: ObjectHandle,
    /// Caller-chosen key distinguishing entries for the same object.
    pub key: u64,
    /// Watched readiness and reporting mode.
    pub interest: ReadinessQueueInterest,
}

/// Request to replace an entry's interest, re-enabling a disabled one-shot
/// entry.
///
/// Fails with [`ReadinessQueueError::NotRegistered`] if the queue has no entry
/// for `target` and `key`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModifyReadinessQueueEntryRequest {
    /// Queue handle.
    pub queue: ObjectHandle,
    /// Watched object.
    pub target: ObjectHandle,
    /// Key the entry was added with.
    pub key: u64,
    /// New watched readiness and reporting mode.
    pub interest: ReadinessQueueInterest,
}

/// Request to remove an entry from a readiness queue.
///
/// Fails with [`ReadinessQueueError::NotRegistered`] if the queue has no entry
/// for `target` and `key`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoveReadinessQueueEntryRequest {
    /// Queue handle.
    pub queue: ObjectHandle,
    /// Watched object.
    pub target: ObjectHandle,
    /// Key the entry was added with.
    pub key: u64,
}

/// Request to take ready events from a readiness queue without waiting.
///
/// The broker writes up to `buffer.length() / READY_EVENT_SIZE` encoded
/// [`ReadyEvent`]s to `buffer`. The buffer length must be a nonzero multiple
/// of [`READY_EVENT_SIZE`] holding at most [`MAX_READINESS_QUEUE_EVENTS`]
/// events. Waiters wait for the queue's `READ` readiness instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakeReadyRequest {
    /// Queue handle.
    pub queue: ObjectHandle,
    /// Destination for the encoded events.
    pub buffer: SharedBufferSequence,
}

/// Response to a take-ready request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakeReadyResponse {
    /// Number of events written to the request's buffer, possibly zero.
    pub count: u32,
}

/// One ready entry reported by a readiness queue.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadyEvent {
    /// The entry's token.
    pub token: u64,
    /// The entry's watched readiness that its target currently has.
    pub readiness: ReadinessFlags,
}

impl ReadyEvent {
    /// Returns this event's encoding in a take-ready buffer.
    #[must_use]
    pub fn encode(self) -> [u8; READY_EVENT_SIZE as usize] {
        let mut bytes = [0; READY_EVENT_SIZE as usize];
        bytes[..8].copy_from_slice(&self.token.to_le_bytes());
        bytes[8..].copy_from_slice(&self.readiness.0.to_le_bytes());
        bytes
    }

    /// Decodes an event from its encoding in a take-ready buffer.
    #[must_use]
    pub fn decode(bytes: &[u8; READY_EVENT_SIZE as usize]) -> Self {
        let mut token = [0; 8];
        token.copy_from_slice(&bytes[..8]);
        let mut readiness = [0; 4];
        readiness.copy_from_slice(&bytes[8..]);
        Self {
            token: u64::from_le_bytes(token),
            readiness: ReadinessFlags(u32::from_le_bytes(readiness)),
        }
    }
}

/// Readiness queue operation failure that is meaningful to the guest ABI.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadinessQueueError {
    #[error("the queue already has an entry for the object and key")]
    AlreadyRegistered,
    #[error("the queue has no entry for the object and key")]
    NotRegistered,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_event_encoding_round_trips() {
        let event = ReadyEvent {
            token: 0x0102_0304_0506_0708,
            readiness: ReadinessFlags::READ | ReadinessFlags::CLOSED,
        };
        let bytes = event.encode();
        assert_eq!(&bytes[..8], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(ReadyEvent::decode(&bytes), event);
    }
}
