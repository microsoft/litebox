// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Futexes in memory that several processes share.
//!
//! Memory that several processes map, such as a Linux `MAP_SHARED | MAP_ANONYMOUS` mapping that
//! native fork children inherit, is named by a [`SharedMemoryId`] that the broker issues to its
//! creator. The broker keeps no record of the memory: it keys futex wait queues by
//! [`SharedFutexKey`], so a wake in one process reaches waiters in every process that names the
//! same futex word.
//!
//! The broker signs each ID it issues and rejects keys whose IDs it did not sign. So a process
//! can only name memory whose ID it was given: memory it created, or that it inherited by copying
//! its creator's memory, as native fork does.
//!
//! Each waiting thread owns a futex waiter object. A wait arms it on a futex; a wake marks the
//! armed waiters it selects woken and publishes [`FUTEX_WAITER_WOKEN`] readiness for them.
//! Readiness is only a hint to disarm the waiter, which reports whether a wake selected it, and
//! resets it.

use crate::ObjectHandle;
use crate::readiness::ReadinessFlags;

/// Readiness of a futex waiter that a wake selected and that has not been disarmed since.
pub const FUTEX_WAITER_WOKEN: ReadinessFlags = ReadinessFlags::READ;

/// Size of a futex word in bytes, which its offset must be a multiple of.
pub const FUTEX_WORD_SIZE: u64 = 4;

/// Names memory shared by several processes.
///
/// Only the broker issues IDs, as [`IssueMemoryIdResponse`] describes, and no two of its IDs
/// are equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SharedMemoryId(
    /// The ID's value:
    /// | ---------------- | ------------- |
    /// | serial (64 bits) | tag (64 bits) |
    /// | ---------------- | ------------- |
    /// Serial: a value the broker uses for only one ID.
    /// Tag: the broker's signature of the serial.
    pub u128,
);

impl SharedMemoryId {
    /// Mask of the ID's tag.
    const TAG_MASK: u128 = u64::MAX as u128;

    /// Returns the ID made of `serial` and its `tag`.
    #[must_use]
    pub const fn new(serial: u64, tag: u64) -> Self {
        Self((serial as u128) << 64 | tag as u128)
    }

    /// Returns the serial of the ID.
    #[must_use]
    pub const fn serial(self) -> u64 {
        (self.0 >> 64) as u64
    }

    /// Returns the tag of the ID.
    #[must_use]
    pub const fn tag(self) -> u64 {
        (self.0 & Self::TAG_MASK) as u64
    }
}

/// Response to a request to issue a shared memory ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssueMemoryIdResponse {
    /// ID of the new memory, signed by the broker.
    pub memory: SharedMemoryId,
}

/// A futex word in shared memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SharedFutexKey {
    /// Memory holding the futex word.
    pub memory: SharedMemoryId,
    /// Byte offset of the futex word in the memory, a multiple of [`FUTEX_WORD_SIZE`].
    pub offset: u64,
}

/// Response to a futex waiter create request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateFutexWaiterResponse {
    /// Created futex waiter handle.
    pub handle: ObjectHandle,
}

/// Request to arm a futex waiter on a futex word in shared memory.
///
/// The broker does not read the futex word; the caller compares it after arming.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexArmRequest {
    /// Futex word to wait on.
    pub key: SharedFutexKey,
    /// Nonzero mask a wake's mask must intersect to select the waiter.
    pub bitset: u32,
    /// Futex waiter to arm, which must be idle: never armed, or disarmed since it was last armed.
    pub waiter: ObjectHandle,
}

/// Request to wake waiters on a futex word in shared memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexWakeRequest {
    /// Futex word whose waiters to wake.
    pub key: SharedFutexKey,
    /// Maximum number of waiters to wake.
    pub count: u32,
    /// Nonzero mask selecting the waiters whose masks intersect it.
    pub bitset: u32,
}

/// Response to a futex wake request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexWakeResponse {
    /// Number of waiters woken.
    pub woken: u32,
}

/// Request to disarm a futex waiter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexDisarmRequest {
    /// Futex waiter to disarm.
    pub waiter: ObjectHandle,
}

/// Response to a futex disarm request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexDisarmResponse {
    /// Whether a wake selected the waiter since it was armed.
    pub woken: bool,
}
