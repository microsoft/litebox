// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::sync::atomic::{AtomicU64, Ordering};

use super::NodeInfo;

/// Hands out [`InodeAllocator`]s, each with its own device id.
#[derive(Debug)]
pub struct InodeAllocators {
    next_device_id: AtomicU64,
}

impl InodeAllocators {
    /// Start handing out allocators, beginning at `first_device_id`.
    pub fn starting_at(first_device_id: u64) -> Self {
        Self {
            next_device_id: AtomicU64::new(first_device_id),
        }
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
    fn for_device(device_id: u64) -> Self {
        Self {
            device_id,
            counter: AtomicU64::new(1),
        }
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
