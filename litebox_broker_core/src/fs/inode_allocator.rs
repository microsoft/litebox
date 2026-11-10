// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::sync::atomic::{AtomicU64, Ordering};

use alloc::sync::Arc;

use super::NodeInfo;
use super::mount::MountPoints;

/// Hands out [`InodeAllocator`]s, each with its own device id, and keeps the registry of the points
/// of backends that mounts are attached at.
///
/// File services that can mount the same backend must share one, both to keep node identities
/// distinct and so that a mount point attached through one can't be removed or renamed through
/// another.
#[derive(Debug)]
pub struct InodeAllocators {
    next_device_id: AtomicU64,
    mount_points: Arc<MountPoints>,
}

impl InodeAllocators {
    /// Start handing out allocators, beginning at `first_device_id`.
    pub fn starting_at(first_device_id: u64) -> Self {
        Self {
            next_device_id: AtomicU64::new(first_device_id),
            mount_points: MountPoints::new(),
        }
    }

    /// The registry of mount points shared by every mount namespace created with these allocators.
    pub(crate) fn mount_points(&self) -> &Arc<MountPoints> {
        &self.mount_points
    }

    /// Hand out an allocator for one backend.
    #[must_use]
    pub fn next(&self) -> InodeAllocator {
        InodeAllocator::for_device(self.next_device_id.fetch_add(1, Ordering::Relaxed))
    }
}

/// Allocator for `(device_id, inode)` pairs scoped to one backend instance.
#[derive(Debug)]
pub struct InodeAllocator {
    device_id: u64,
    counter: AtomicU64,
}

impl InodeAllocator {
    /// Construct an allocator for a specific `device_id`.
    #[must_use]
    pub fn for_device(device_id: u64) -> Self {
        Self {
            device_id,
            counter: AtomicU64::new(1),
        }
    }

    /// Standalone allocator using the back-compat sentinel `device_id`.
    ///
    /// This should (eventually) disappear once we have better device ID allocation setup.
    #[must_use]
    pub fn standalone() -> Self {
        // `b"Stnd".hex()`
        const STANDALONE_DEVICE_ID: u64 = 0x53746e64;
        Self::for_device(STANDALONE_DEVICE_ID)
    }

    /// Allocate a fresh [`NodeInfo`] for a new entry on this backend.
    #[must_use]
    pub fn next(&self) -> NodeInfo {
        let ino = self.counter.fetch_add(1, Ordering::Relaxed);
        NodeInfo {
            dev: self.device_id(),
            ino,
            rdev: None,
        }
    }

    /// The device id this allocator hands out.
    #[must_use]
    pub fn device_id(&self) -> u64 {
        self.device_id
    }
}
