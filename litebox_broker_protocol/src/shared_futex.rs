// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Futexes in memory that several processes share.
//!
//! Memory that several processes map, such as a Linux `MAP_SHARED | MAP_ANONYMOUS` mapping that
//! native fork children inherit, is named by a [`SharedMemoryId`] that its creator picks from a
//! block the broker reserved for it. The broker keeps no record of the memory: it keys futex wait
//! queues by [`SharedFutexKey`], so a wake in one process reaches waiters in every process that
//! names the same futex word. A process may only name the futexes of blocks it reserved, or that
//! the process that created it could name at the time, so that it can only reach memory it may
//! share. A process that creates another must therefore take its later IDs from a block it
//! reserves afterwards.
//!
//! Each waiting thread owns a futex waiter object. A wait arms it on a futex with a wrapping arm
//! generation, which differs from those of the waiter's recent arms; a wake marks the armed
//! waiters it selects woken and publishes [`futex_waiter_woken_readiness`] readiness for them,
//! which carries that generation. Disarming the waiter reports whether it was woken, and resets
//! it.
//!
//! Readiness that carries the generation of the current arm proves that a wake selected the
//! waiter, so the waiter may skip disarming and arm again. Any other readiness, such as one left
//! over from an earlier arm, is only a hint to disarm, whose response is authoritative.

use crate::ObjectHandle;
use crate::readiness::ReadinessFlags;

/// Readiness flag of a futex waiter that a wake selected and that has not been disarmed or armed
/// again since.
const FUTEX_WAITER_WOKEN: ReadinessFlags = ReadinessFlags::READ;

/// Number of distinct futex waiter arm generations, which wrap around.
pub const FUTEX_WAITER_GENERATIONS: u32 = 1 << 24;

/// Position of the arm generation in the readiness of a woken futex waiter.
const FUTEX_WAITER_GENERATION_SHIFT: u32 = 8;

/// Returns the readiness of a futex waiter that a wake selected while it was armed with
/// `generation`, which must be less than [`FUTEX_WAITER_GENERATIONS`].
#[must_use]
pub const fn futex_waiter_woken_readiness(generation: u32) -> ReadinessFlags {
    ReadinessFlags(FUTEX_WAITER_WOKEN.0 | generation << FUTEX_WAITER_GENERATION_SHIFT)
}

/// Returns the generation of the arm in which a wake selected a futex waiter with `readiness`,
/// or `None` if the readiness does not report a wake.
#[must_use]
pub const fn woken_futex_waiter_generation(readiness: ReadinessFlags) -> Option<u32> {
    if readiness.contains(FUTEX_WAITER_WOKEN) {
        Some(readiness.0 >> FUTEX_WAITER_GENERATION_SHIFT)
    } else {
        None
    }
}

/// Size of a futex word in bytes, which its offset must be a multiple of.
pub const FUTEX_WORD_SIZE: u64 = 4;

/// Names memory shared by several processes.
///
/// The creator of the memory picks an ID that no other shared memory uses from a block that the
/// broker reserved for it, as [`ReserveMemoryIdsResponse`] describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SharedMemoryId(
    /// The ID's value: a block's upper 64 bits, then a position in the block.
    pub u128,
);

impl SharedMemoryId {
    /// Returns the block the ID belongs to: its upper 64 bits.
    #[must_use]
    pub const fn block(self) -> u64 {
        (self.0 >> 64) as u64
    }

    /// Returns the ID `index` places after `self` in its block, wrapping within the block.
    #[must_use]
    pub fn nth_in_block(self, index: u64) -> Self {
        let position_mask = u128::from(u64::MAX);
        let position = self.0.wrapping_add(u128::from(index)) & position_mask;
        Self((self.0 & !position_mask) | position)
    }
}

/// Response to a request to reserve shared memory IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReserveMemoryIdsResponse {
    /// First ID of the reserved block: the 2^64 IDs that share its upper 64 bits, which no other
    /// reservation shares, and which only the reserving process and the processes it later
    /// creates may name.
    pub first: SharedMemoryId,
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
/// The caller compares the futex word itself, after this request completes, and disarms the
/// waiter if the word no longer holds the expected value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexArmRequest {
    /// Futex word to wait on.
    pub key: SharedFutexKey,
    /// Nonzero mask a wake's mask must intersect to select the waiter.
    pub bitset: u32,
    /// Futex waiter to arm, which is idle or was woken since it was last armed.
    pub waiter: ObjectHandle,
    /// Generation of this arm, less than [`FUTEX_WAITER_GENERATIONS`], which the waiter's
    /// [`futex_waiter_woken_readiness`] readiness carries if a wake selects it.
    pub generation: u32,
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

#[cfg(test)]
mod tests {
    use super::{
        FUTEX_WAITER_GENERATIONS, SharedMemoryId, futex_waiter_woken_readiness,
        woken_futex_waiter_generation,
    };
    use crate::readiness::ReadinessFlags;

    #[test]
    fn woken_readiness_carries_the_arm_generation() {
        for generation in [0, 1, FUTEX_WAITER_GENERATIONS - 1] {
            assert_eq!(
                woken_futex_waiter_generation(futex_waiter_woken_readiness(generation)),
                Some(generation)
            );
        }
        assert_eq!(
            woken_futex_waiter_generation(ReadinessFlags::default()),
            None
        );
    }

    #[test]
    fn ids_in_a_block_wrap_without_leaving_it() {
        let first = SharedMemoryId(7 << 64 | u128::from(u64::MAX - 1));
        assert_eq!(first.nth_in_block(0), first);
        assert_eq!(
            first.nth_in_block(1),
            SharedMemoryId(7 << 64 | u128::from(u64::MAX))
        );
        assert_eq!(first.nth_in_block(2), SharedMemoryId(7 << 64));
        assert_eq!(
            first.nth_in_block(u64::MAX),
            SharedMemoryId(7 << 64 | u128::from(u64::MAX - 2))
        );
    }
}
