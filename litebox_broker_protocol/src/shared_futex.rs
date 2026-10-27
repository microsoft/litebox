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
/// The creator of the memory picks an ID that no other shared memory uses from a block that the
/// broker reserved for it, as [`ReserveMemoryIdsResponse`] describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SharedMemoryId(
    /// The ID's value: from the most significant bits, the [reserver](Self::reserver) of its
    /// block (64 bits), the [block](Self::block)'s index among the reserver's blocks (32 bits),
    /// and the ID's position in the block (32 bits).
    pub u128,
);

impl SharedMemoryId {
    /// Mask of the ID's position in its block.
    const POSITION: u128 = u32::MAX as u128;

    /// Returns the first ID of the block with index `block` among those of `reserver`.
    #[must_use]
    pub const fn first_in_block(reserver: u64, block: u32) -> Self {
        Self((reserver as u128) << 64 | (block as u128) << 32)
    }

    /// Returns the ID of the process that reserved the ID's block, which no other process the
    /// broker creates shares.
    #[must_use]
    pub const fn reserver(self) -> u64 {
        (self.0 >> 64) as u64
    }

    /// Returns the index of the ID's block among those its [reserver](Self::reserver) reserved,
    /// in the order it reserved them.
    #[must_use]
    pub const fn block(self) -> u32 {
        ((self.0 >> 32) & Self::POSITION) as u32
    }

    /// Returns the ID after this one in its block, or `None` if this is the block's last.
    #[must_use]
    pub const fn next_in_block(self) -> Option<Self> {
        if self.0 & Self::POSITION == Self::POSITION {
            None
        } else {
            Some(Self(self.0 + 1))
        }
    }
}

/// Response to a request to reserve shared memory IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReserveMemoryIdsResponse {
    /// First ID of the reserved block, which the reserving process and the processes it creates
    /// from now on may name.
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

#[cfg(test)]
mod tests {
    use super::SharedMemoryId;

    #[test]
    fn ids_name_their_reserver_and_block_and_stay_in_it() {
        let first = SharedMemoryId::first_in_block(u64::MAX, u32::MAX);
        assert_eq!((first.reserver(), first.block()), (u64::MAX, u32::MAX));
        let second = first.next_in_block().unwrap();
        assert_eq!((second.reserver(), second.block()), (u64::MAX, u32::MAX));
        assert_ne!(second, first);
        let last = SharedMemoryId(first.0 | u128::from(u32::MAX));
        assert_eq!(last.block(), u32::MAX);
        assert_eq!(last.next_in_block(), None);
    }
}
