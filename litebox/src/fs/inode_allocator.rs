// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::sync::atomic::{AtomicU64, Ordering};

use super::NodeInfo;

/// Allocator for `(device_id, inode)` pairs scoped to one backend instance.
#[derive(Debug)]
pub struct InodeAllocator {
    device_id: u64,
    counter: AtomicU64,
}

impl InodeAllocator {
    /// Construct an allocator for a specific `device_id`. The composer hands
    /// out unique `device_id`s per mounted backend.
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

    /// Allocate a fresh `NodeInfo` for a new entry on this backend.
    #[must_use]
    pub fn next(&self) -> NodeInfo {
        let ino = self.counter.fetch_add(1, Ordering::Relaxed);
        NodeInfo {
            dev: self.device_id.try_into().unwrap(),
            ino: ino.try_into().unwrap(),
            rdev: None,
        }
    }
}
