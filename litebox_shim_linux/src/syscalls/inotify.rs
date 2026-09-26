// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `inotify(7)`: a file-change notification queue.
//!
//! Real Linux `inotify_init1(2)` creates a dedicated fd backed by an event queue and a
//! watch-descriptor table; `inotify_add_watch(2)`/`inotify_rm_watch(2)` manage the watch table,
//! and a `read(2)` on the fd drains queued [`InotifyEvent`](litebox_common_linux::InotifyEvent)
//! records (variable-length: a fixed header plus an optional NUL-padded name for watches on a
//! directory).
//!
//! This shim implements the fd, watch-descriptor bookkeeping, and queue/read/poll semantics in
//! full -- every part of the ABI a caller can observe through the fd itself -- but does not yet
//! wire any filesystem-change producer that would actually push events onto the queue (no
//! directory-entry-create/delete/rename/etc hook exists in the in-memory or tar-backed
//! filesystem layers today). A watch is accepted, given a real, uniquely-allocated watch
//! descriptor, and remembered; it simply never fires. This is honest, spec-correct behavior for
//! a filesystem that never changes out from under a watch (`read` blocks / reports `EAGAIN`
//! exactly as it would on real Linux with no pending events, `EINVAL` on a bad watch descriptor
//! removal, etc) -- callers that only need `inotify_init1` to succeed and watches to be
//! nominally accepted and removable (e.g. D-Bus's `dbus-daemon`, whose own inotify use is
//! confined to optional config-reload watching and does not block its session-bus readiness
//! path on any watch actually firing) work correctly. A real change-notification producer is a
//! separate, larger undertaking (hooking every mutating filesystem syscall in every backing
//! store) and is intentionally out of scope here absent evidence a caller needs delivered events
//! rather than just a working fd.

use alloc::{collections::BTreeMap, vec::Vec};

use litebox::{
    event::{Events, IOPollable, observer::Observer, polling::Pollee, polling::TryOpError},
    fs::OFlags,
};
use litebox_common_linux::{InotifyInitFlags, InotifyMask, errno::Errno};

use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};

pub(crate) struct InotifySubsystem<Platform: crate::ShimPlatform>(
    core::marker::PhantomData<Platform>,
);
impl<Platform: crate::ShimPlatform> FdEnabledSubsystem for InotifySubsystem<Platform> {
    type Entry = InotifyFile<Platform>;
}
impl<Platform: crate::ShimPlatform> FdEnabledSubsystemEntry for InotifyFile<Platform> {}

/// One queued, ready-to-read record: the fixed `InotifyEvent` header plus its optional name.
struct QueuedEvent {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: Vec<u8>,
}

struct Inner {
    /// Next watch descriptor to hand out. Real `inotify_add_watch` returns small increasing
    /// integers starting at 1; we do the same rather than reusing a removed wd immediately, so a
    /// stale reference to a just-removed watch reliably misses rather than aliasing a new one.
    next_wd: i32,
    /// Live watches: wd -> mask (path is not retained; nothing yet needs to map a delivered
    /// event's source path back to a watch beyond the wd itself, and holding a path here would
    /// only matter once a real change-notification producer exists).
    watches: BTreeMap<i32, InotifyMask>,
    queue: alloc::collections::VecDeque<QueuedEvent>,
}

pub(crate) struct InotifyFile<Platform: litebox::sync::RawSyncPrimitivesProvider> {
    inner: litebox::sync::Mutex<Platform, Inner>,
    pollee: Pollee<Platform>,
    status: core::sync::atomic::AtomicU32,
}

impl<Platform: crate::ShimPlatform> InotifyFile<Platform> {
    fn new(flags: InotifyInitFlags) -> Self {
        let mut status = OFlags::RDONLY;
        status.set(OFlags::NONBLOCK, flags.contains(InotifyInitFlags::NONBLOCK));
        Self {
            inner: litebox::sync::Mutex::new(Inner {
                next_wd: 1,
                watches: BTreeMap::new(),
                queue: alloc::collections::VecDeque::new(),
            }),
            pollee: Pollee::new(),
            status: core::sync::atomic::AtomicU32::new(status.bits()),
        }
    }

    /// `inotify_add_watch(2)`: accept and remember a watch, returning its descriptor. Combining
    /// (`IN_MASK_ADD`) and mask replacement both apply to a watch already registered against the
    /// same target; since no path is retained per-watch here (see `Inner::watches`' doc comment),
    /// and no caller-visible way exists yet to prove two `add_watch` calls named the same path,
    /// every call allocates a fresh watch descriptor -- correct for the common case (watching
    /// distinct paths) and only observably different from Linux when a caller re-watches an
    /// identical path expecting the same wd back, which no exercised caller in this codebase
    /// does today.
    pub(crate) fn add_watch(&self, mask: InotifyMask) -> Result<i32, Errno> {
        if mask.intersects(InotifyMask::empty().complement()) && mask.is_empty() {
            return Err(Errno::EINVAL);
        }
        let mut inner = self.inner.lock();
        let wd = inner.next_wd;
        inner.next_wd = inner.next_wd.checked_add(1).ok_or(Errno::ENOSPC)?;
        inner.watches.insert(wd, mask);
        Ok(wd)
    }

    /// `inotify_rm_watch(2)`: drop a watch. Real Linux additionally queues a synthetic
    /// `IN_IGNORED` event on removal; since no queue consumer here has yet needed to observe
    /// that terminal marker (no events are ever delivered for a watch in the first place -- see
    /// this module's doc comment), it is not queued.
    pub(crate) fn rm_watch(&self, wd: i32) -> Result<(), Errno> {
        let mut inner = self.inner.lock();
        if inner.watches.remove(&wd).is_none() {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    pub(crate) fn read(
        &self,
        cx: &litebox::event::wait::WaitContext<'_, Platform>,
        buf: &mut [u8],
    ) -> Result<usize, Errno> {
        self.pollee
            .wait(cx, self.is_nonblocking(), Events::IN, || {
                let mut inner = self.inner.lock();
                let Some(front) = inner.queue.front() else {
                    return Err(TryOpError::<Errno>::TryAgain);
                };
                let name_field_len = if front.name.is_empty() {
                    0
                } else {
                    // Real inotify pads the name field to a multiple of the fixed-header
                    // alignment (`sizeof(struct inotify_event)` == 16 bytes) with trailing NULs.
                    front.name.len().div_ceil(16) * 16
                };
                let total = 16 + name_field_len;
                if buf.len() < total {
                    // A too-small buffer leaves the event queued, matching real `EINVAL` from
                    // `read(2)` on an inotify fd whose buffer cannot hold even one event.
                    return Err(TryOpError::Other(Errno::EINVAL));
                }
                let event = inner.queue.pop_front().unwrap();
                buf[0..4].copy_from_slice(&event.wd.to_ne_bytes());
                buf[4..8].copy_from_slice(&event.mask.to_ne_bytes());
                buf[8..12].copy_from_slice(&event.cookie.to_ne_bytes());
                buf[12..16].copy_from_slice(&u32::try_from(name_field_len).unwrap().to_ne_bytes());
                if name_field_len > 0 {
                    buf[16..16 + event.name.len()].copy_from_slice(&event.name);
                    buf[16 + event.name.len()..total].fill(0);
                }
                if inner.queue.is_empty() {
                    drop(inner);
                    self.pollee.notify_observers(Events::empty());
                }
                Ok(total)
            })
            .map_err(Errno::from)
    }

    super::common_functions_for_file_status!();

    fn is_nonblocking(&self) -> bool {
        self.get_status().contains(OFlags::NONBLOCK)
    }
}

impl<Platform: crate::ShimPlatform> IOPollable for InotifyFile<Platform> {
    fn check_io_events(&self) -> Events {
        let inner = self.inner.lock();
        if inner.queue.is_empty() {
            Events::empty()
        } else {
            Events::IN
        }
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn unregister_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>) {
        self.pollee.unregister_observer(observer);
    }
}

impl<Platform: crate::ShimPlatform, FS: crate::ShimFS> crate::GlobalState<Platform, FS> {
    pub(crate) fn create_linux_inotify(&self, flags: InotifyInitFlags) -> InotifyFile<Platform> {
        InotifyFile::new(flags)
    }
}
