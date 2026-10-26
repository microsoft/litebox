// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Futexes in memory that several processes share.
//!
//! Memory that several processes map, such as a Linux `MAP_SHARED | MAP_ANONYMOUS` mapping that
//! native fork children inherit, is named by a [`SharedMemoryId`] that its creator picks from a
//! range the broker reserved for it. The broker keeps no record of the memory: it keys futex wait
//! queues by [`SharedFutexKey`], so a wake in one process reaches waiters in every process that
//! names the same futex word.
//!
//! Each waiting thread owns a futex waiter object. A wait arms it on a futex, a wake marks the
//! armed waiters it selects woken and publishes [`FUTEX_WAITER_WOKEN`] readiness for them, and
//! disarming the waiter reports whether it was woken. Readiness is only a hint to disarm;
//! the disarm response is authoritative.

use crate::ObjectHandle;
use crate::readiness::ReadinessFlags;

/// Readiness of a futex waiter that a wake selected and that has not been disarmed since.
pub const FUTEX_WAITER_WOKEN: ReadinessFlags = ReadinessFlags::READ;

/// Names memory shared by several processes.
///
/// The creator of the memory picks an ID that no other shared memory uses: one starting with a
/// prefix that the broker reserved for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SharedMemoryId(pub u128);

/// Response to a request to reserve shared memory IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReserveMemoryIdsResponse {
    /// Prefix that no other reservation returns, which reserves the IDs whose upper 64 bits it
    /// is.
    pub prefix: u64,
}

/// A futex word in shared memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SharedFutexKey {
    /// Memory holding the futex word.
    pub memory: SharedMemoryId,
    /// Byte offset of the futex word in the memory, a multiple of four.
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
/// The caller compares the futex word itself, after this request completes, and disarms the
/// waiter if the word no longer holds the expected value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexArmRequest {
    /// Futex word to wait on.
    pub key: SharedFutexKey,
    /// Nonzero mask a wake's mask must intersect to select the waiter.
    pub bitset: u32,
    /// Idle futex waiter to arm.
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
