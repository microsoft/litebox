// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned shared memory and the futexes on it.
//!
//! A shared memory object names memory that several processes map, such as a Linux
//! `MAP_SHARED | MAP_ANONYMOUS` mapping a native fork child inherits. The broker does not hold
//! the memory's contents; it only keys futex wait queues by object and byte offset, so a wake in
//! one process reaches waiters in every process that holds a reference to the object.
//!
//! Each waiting thread owns a futex waiter object. A wait arms it on a futex, a wake marks the
//! armed waiters it selects woken and publishes [`FUTEX_WAITER_WOKEN`] readiness for them, and
//! disarming the waiter reports whether it was woken. Readiness is only a hint to disarm;
//! the disarm response is authoritative.

use crate::ObjectHandle;
use crate::readiness::ReadinessFlags;

/// Readiness of a futex waiter that a wake selected and that has not been disarmed since.
pub const FUTEX_WAITER_WOKEN: ReadinessFlags = ReadinessFlags::READ;

/// Request to create a broker-owned shared memory object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateSharedMemoryRequest {
    /// Length of the memory in bytes, which bounds futex offsets.
    pub length: u64,
}

/// Response to a shared memory create request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateSharedMemoryResponse {
    /// Created shared memory handle.
    pub handle: ObjectHandle,
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
    /// Shared memory holding the futex word.
    pub memory: ObjectHandle,
    /// Byte offset of the futex word in the memory, a multiple of four.
    pub offset: u64,
    /// Nonzero mask a wake's mask must intersect to select the waiter.
    pub bitset: u32,
    /// Idle futex waiter to arm.
    pub waiter: ObjectHandle,
}

/// Request to wake waiters on a futex word in shared memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexWakeRequest {
    /// Shared memory holding the futex word.
    pub memory: ObjectHandle,
    /// Byte offset of the futex word in the memory, a multiple of four.
    pub offset: u64,
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
