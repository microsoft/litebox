// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Stub inotify implementation for LiteBox.
//!
//! This provides a minimal inotify implementation that allows applications to create
//! inotify instances and add/remove watches, but never generates any events. This is
//! sufficient for applications that use inotify optionally or with timeouts.

use core::sync::atomic::{AtomicU32, Ordering};

use alloc::{collections::BTreeMap, string::String, sync::Weak};
use litebox::{
    event::{
        Events, IOPollable,
        observer::Observer,
        polling::{Pollee, TryOpError},
        wait::WaitContext,
    },
    fs::OFlags,
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{InotifyInitFlags, errno::Errno};

/// Maximum number of watches per inotify instance.
/// Linux default is typically 8192 (via /proc/sys/fs/inotify/max_user_watches).
const MAX_WATCHES_PER_INSTANCE: usize = 8192;

/// Maximum pathname length (PATH_MAX on Linux).
const MAX_PATHNAME_LEN: usize = 4096;

/// An inotify file instance.
///
/// This is a stub implementation that stores watches but never generates events.
/// Applications that read from this fd will always get `EAGAIN` (nonblocking) or
/// block indefinitely (blocking mode).
pub(crate) struct InotifyFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    /// Next watch descriptor to allocate (starts at 1).
    /// Uses u32 to avoid signed overflow issues.
    next_wd: AtomicU32,
    /// Map of watch descriptors to watch entries.
    watches: litebox::sync::Mutex<Platform, BTreeMap<i32, WatchEntry>>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
    /// Pollee for epoll integration.
    pollee: Pollee<Platform>,
}

/// A watch entry that stores the path and mask for a watch.
#[allow(dead_code, reason = "stored for potential future use")]
struct WatchEntry {
    pathname: String,
    mask: u32,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> InotifyFile<Platform> {
    /// Create a new inotify instance with the given flags.
    pub(crate) fn new(flags: InotifyInitFlags) -> Self {
        let mut status = OFlags::RDONLY;
        status.set(
            OFlags::NONBLOCK,
            flags.contains(InotifyInitFlags::IN_NONBLOCK),
        );

        Self {
            // Watch descriptors start at 1 (like Linux)
            next_wd: AtomicU32::new(1),
            watches: litebox::sync::Mutex::new(BTreeMap::new()),
            status: AtomicU32::new(status.bits()),
            pollee: Pollee::new(),
        }
    }

    /// Add or modify a watch on the given path.
    ///
    /// Returns the watch descriptor on success.
    pub(crate) fn add_watch(&self, pathname: String, mask: u32) -> Result<i32, Errno> {
        // Validate mask - must have at least one event bit set
        // (Linux returns EINVAL if mask is 0)
        if mask == 0 {
            return Err(Errno::EINVAL);
        }

        // Validate pathname length (defense against memory exhaustion)
        if pathname.len() > MAX_PATHNAME_LEN {
            return Err(Errno::ENAMETOOLONG);
        }

        let mut watches = self.watches.lock();

        // Check if we already have a watch on this path
        // Linux would modify the existing watch, but for simplicity we just check for duplicates
        // by pathname. A full implementation would use inode comparison.
        for (wd, entry) in watches.iter_mut() {
            if entry.pathname == pathname {
                // Modify existing watch
                entry.mask = mask;
                return Ok(*wd);
            }
        }

        // Check watch count limit (defense against memory exhaustion)
        if watches.len() >= MAX_WATCHES_PER_INSTANCE {
            return Err(Errno::ENOSPC);
        }

        // Allocate new watch descriptor using compare-and-swap to prevent overflow
        let wd = self
            .next_wd
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                // i32::MAX as u32 is 2147483647, which is the max valid watch descriptor
                if current > i32::MAX as u32 {
                    None // Don't update, overflow would occur
                } else {
                    Some(current + 1)
                }
            })
            .map_err(|_| Errno::ENOSPC)?;

        // Safe cast: we validated wd <= i32::MAX above
        #[allow(clippy::cast_possible_wrap)]
        let wd = wd as i32;
        watches.insert(wd, WatchEntry { pathname, mask });
        Ok(wd)
    }

    /// Remove a watch by its descriptor.
    pub(crate) fn rm_watch(&self, wd: i32) -> Result<(), Errno> {
        let mut watches = self.watches.lock();
        if watches.remove(&wd).is_some() {
            Ok(())
        } else {
            Err(Errno::EINVAL)
        }
    }

    /// Read events from the inotify instance.
    ///
    /// This is a stub implementation that never has events available.
    /// - In nonblocking mode: returns EAGAIN immediately
    /// - In blocking mode: blocks indefinitely (until interrupted)
    #[expect(
        dead_code,
        reason = "API provided for future use; currently read() returns EAGAIN directly in file.rs"
    )]
    pub(crate) fn read(&self, cx: &WaitContext<'_, Platform>) -> Result<usize, Errno> {
        self.pollee
            .wait(
                cx,
                self.get_status().contains(OFlags::NONBLOCK),
                Events::IN,
                // Stub: always return TryAgain (no events available)
                || Err(TryOpError::<Errno>::TryAgain),
            )
            .map_err(Errno::from)
    }

    super::common_functions_for_file_status!();
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for InotifyFile<Platform> {
    fn check_io_events(&self) -> Events {
        // inotify is never readable since we never generate events
        Events::empty()
    }

    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }
}

#[cfg(test)]
mod tests {
    use litebox_common_linux::InotifyInitFlags;

    extern crate std;

    #[test]
    fn test_inotify_new() {
        let _task = crate::syscalls::tests::init_platform(None);

        let inotify = super::InotifyFile::<litebox_platform_multiplex::Platform>::new(
            InotifyInitFlags::empty(),
        );
        assert_eq!(
            inotify.next_wd.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_inotify_add_watch() {
        let _task = crate::syscalls::tests::init_platform(None);

        let inotify = super::InotifyFile::<litebox_platform_multiplex::Platform>::new(
            InotifyInitFlags::empty(),
        );

        // Add first watch
        let wd1 = inotify
            .add_watch("/tmp/test1".into(), 0x100)
            .expect("add_watch should succeed");
        assert_eq!(wd1, 1);

        // Add second watch
        let wd2 = inotify
            .add_watch("/tmp/test2".into(), 0x200)
            .expect("add_watch should succeed");
        assert_eq!(wd2, 2);

        // Modify first watch (same path)
        let wd1_again = inotify
            .add_watch("/tmp/test1".into(), 0x300)
            .expect("add_watch should succeed");
        assert_eq!(wd1_again, 1); // Should return existing wd
    }

    #[test]
    fn test_inotify_add_watch_invalid_mask() {
        let _task = crate::syscalls::tests::init_platform(None);

        let inotify = super::InotifyFile::<litebox_platform_multiplex::Platform>::new(
            InotifyInitFlags::empty(),
        );

        // Mask of 0 should fail
        let result = inotify.add_watch("/tmp/test".into(), 0);
        assert_eq!(result, Err(litebox_common_linux::errno::Errno::EINVAL));
    }

    #[test]
    fn test_inotify_add_watch_pathname_too_long() {
        let _task = crate::syscalls::tests::init_platform(None);

        let inotify = super::InotifyFile::<litebox_platform_multiplex::Platform>::new(
            InotifyInitFlags::empty(),
        );

        // Pathname too long should fail
        let long_path = "x".repeat(super::MAX_PATHNAME_LEN + 1);
        let result = inotify.add_watch(long_path, 0x100);
        assert_eq!(
            result,
            Err(litebox_common_linux::errno::Errno::ENAMETOOLONG)
        );
    }

    #[test]
    fn test_inotify_rm_watch() {
        let _task = crate::syscalls::tests::init_platform(None);

        let inotify = super::InotifyFile::<litebox_platform_multiplex::Platform>::new(
            InotifyInitFlags::empty(),
        );

        // Add a watch
        let wd = inotify
            .add_watch("/tmp/test".into(), 0x100)
            .expect("add_watch should succeed");

        // Remove the watch
        inotify.rm_watch(wd).expect("rm_watch should succeed");

        // Remove again should fail
        let result = inotify.rm_watch(wd);
        assert_eq!(result, Err(litebox_common_linux::errno::Errno::EINVAL));
    }

    #[test]
    fn test_inotify_rm_watch_invalid() {
        let _task = crate::syscalls::tests::init_platform(None);

        let inotify = super::InotifyFile::<litebox_platform_multiplex::Platform>::new(
            InotifyInitFlags::empty(),
        );

        // Remove non-existent watch
        let result = inotify.rm_watch(999);
        assert_eq!(result, Err(litebox_common_linux::errno::Errno::EINVAL));
    }
}
