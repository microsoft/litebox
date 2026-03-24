// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::{convert::Infallible, sync::atomic::AtomicBool};

use alloc::{
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    sync::{Arc, Weak},
    vec::Vec,
};
use litebox::{
    event::{
        Events, IOPollable,
        observer::Observer,
        polling::{Pollee, TryOpError},
        wait::{WaitContext, WaitError, Waker},
    },
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd},
    fs::OFlags,
    utils::ReinterpretUnsignedExt,
};
use litebox_common_linux::{EpollEvent, EpollOp, errno::Errno};
use litebox_platform_multiplex::Platform;

use super::file::FilesState;
use crate::{GlobalState, ShimFS};

pub(crate) struct EpollSubsystem<FS: ShimFS>(core::marker::PhantomData<FS>);
impl<FS: ShimFS> FdEnabledSubsystem for EpollSubsystem<FS> {
    type Entry = EpollFile<FS>;
}
impl<FS: ShimFS> FdEnabledSubsystemEntry for EpollFile<FS> {}

bitflags::bitflags! {
    /// Linux's epoll flags.
    #[derive(Debug)]
    struct EpollFlags: u32 {
        const EXCLUSIVE      = (1 << 28);
        const WAKE_UP        = (1 << 29);
        const ONE_SHOT       = (1 << 30);
        const EDGE_TRIGGER   = (1 << 31);
    }
}

pub(crate) enum EpollDescriptor<FS: ShimFS> {
    Eventfd(Arc<TypedFd<super::eventfd::EventfdSubsystem>>),
    Epoll(Arc<TypedFd<super::epoll::EpollSubsystem<FS>>>),
    File(Arc<crate::FileFd<FS>>),
    Socket(Arc<super::net::SocketFd>),
    Pipe(Arc<litebox::pipes::PipeFd<Platform>>),
    Unix(Arc<TypedFd<crate::syscalls::unix::UnixSocketSubsystem<FS>>>),
}

impl<FS: ShimFS> EpollDescriptor<FS> {
    pub fn try_from(files: &FilesState<FS>, raw_fd: usize) -> Result<Self, Errno> {
        let rds = files.raw_descriptor_store.read();
        if let Ok(fd) = rds.fd_from_raw_integer::<FS>(raw_fd) {
            return Ok(EpollDescriptor::File(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<crate::Network<Platform>>(raw_fd) {
            return Ok(EpollDescriptor::Socket(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<litebox::pipes::Pipes<Platform>>(raw_fd) {
            return Ok(EpollDescriptor::Pipe(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<super::eventfd::EventfdSubsystem>(raw_fd) {
            return Ok(EpollDescriptor::Eventfd(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<EpollSubsystem<FS>>(raw_fd) {
            return Ok(EpollDescriptor::Epoll(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<super::unix::UnixSocketSubsystem<FS>>(raw_fd) {
            return Ok(EpollDescriptor::Unix(fd));
        }
        Err(Errno::EBADF)
    }
}

enum DescriptorRef<FS: ShimFS> {
    Eventfd(Weak<TypedFd<super::eventfd::EventfdSubsystem>>),
    Epoll(Weak<TypedFd<super::epoll::EpollSubsystem<FS>>>),
    File(Weak<crate::FileFd<FS>>),
    Socket(Weak<super::net::SocketFd>),
    Pipe(Weak<litebox::pipes::PipeFd<Platform>>),
    Unix(Weak<TypedFd<crate::syscalls::unix::UnixSocketSubsystem<FS>>>),
}

impl<FS: ShimFS> DescriptorRef<FS> {
    fn from(value: &EpollDescriptor<FS>) -> Self {
        match value {
            EpollDescriptor::Eventfd(file) => Self::Eventfd(Arc::downgrade(file)),
            EpollDescriptor::Epoll(file) => Self::Epoll(Arc::downgrade(file)),
            EpollDescriptor::File(file) => Self::File(Arc::downgrade(file)),
            EpollDescriptor::Socket(socket) => Self::Socket(Arc::downgrade(socket)),
            EpollDescriptor::Pipe(pipe) => Self::Pipe(Arc::downgrade(pipe)),
            EpollDescriptor::Unix(unix) => Self::Unix(Arc::downgrade(unix)),
        }
    }

    fn upgrade(&self) -> Option<EpollDescriptor<FS>> {
        match self {
            DescriptorRef::Eventfd(eventfd) => eventfd.upgrade().map(EpollDescriptor::Eventfd),
            DescriptorRef::Epoll(epoll) => epoll.upgrade().map(EpollDescriptor::Epoll),
            DescriptorRef::File(file) => file.upgrade().map(EpollDescriptor::File),
            DescriptorRef::Socket(socket) => socket.upgrade().map(EpollDescriptor::Socket),
            DescriptorRef::Pipe(pipe) => pipe.upgrade().map(EpollDescriptor::Pipe),
            DescriptorRef::Unix(unix) => unix.upgrade().map(EpollDescriptor::Unix),
        }
    }
}

impl<FS: ShimFS> EpollDescriptor<FS> {
    /// Returns the interesting events now and monitors their occurrence in the future if the
    /// observer is provided.
    fn poll(
        &self,
        global: &GlobalState<FS>,
        fs: &FS,
        mask: Events,
        observer: Option<Weak<dyn Observer<Events>>>,
    ) -> Option<Events> {
        let poll = |iop: &dyn IOPollable| {
            if let Some(observer) = observer {
                iop.register_observer(observer, mask);
            }
            iop.check_io_events() & (mask | Events::ALWAYS_POLLED)
        };
        match self {
            EpollDescriptor::Eventfd(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::Epoll(_file) => unimplemented!(),
            EpollDescriptor::File(file) => {
                // Check if the file supports async I/O polling (e.g., PTY master).
                if let Some(io_poll) = fs.get_io_pollable(file) {
                    let events = poll(&*io_poll);
                    return Some(events);
                }
                // Regular files: return dummy OUT events.
                Some(Events::OUT & mask)
            }
            EpollDescriptor::Socket(fd) => {
                let proxy = match global.get_proxy(fd) {
                    Ok(p) => p,
                    Err(e) => {
                        log_unsupported!("epoll poll with socket fd: {:?}", e);
                        return None;
                    }
                };
                Some(poll(&proxy))
            }
            EpollDescriptor::Pipe(fd) => global.pipes.with_iopollable(fd, poll).ok(),
            EpollDescriptor::Unix(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
        }
    }

    /// Returns `true` if this descriptor requires periodic host polling
    /// rather than observer-based notifications.
    fn needs_host_poll(&self, global: &GlobalState<FS>, fs: &FS) -> bool {
        match self {
            EpollDescriptor::Eventfd(fd) => global
                .litebox
                .descriptor_table()
                .entry_handle(fd)
                .is_some_and(|handle| handle.with_entry(|entry| entry.needs_host_poll())),
            EpollDescriptor::File(file) => fs
                .get_io_pollable(file)
                .is_some_and(|p| p.needs_host_poll()),
            _ => false,
        }
    }
}

pub(crate) struct EpollFile<FS: ShimFS> {
    interests: litebox::sync::Mutex<
        litebox_platform_multiplex::Platform,
        BTreeMap<EpollEntryKey, alloc::sync::Arc<EpollEntry<FS>>>,
    >,
    ready: Arc<ReadySet<FS>>,
    status: core::sync::atomic::AtomicU32,
    /// Set when the interest set contains descriptors that cannot register
    /// observers (e.g. host stdin). When true, `wait()` uses a capped timeout
    /// so it periodically re-polls these descriptors.
    needs_host_poll: core::sync::atomic::AtomicBool,
}

impl<FS: ShimFS> EpollFile<FS> {
    pub(crate) fn new() -> Self {
        EpollFile {
            interests: litebox::sync::Mutex::new(BTreeMap::new()),
            ready: Arc::new(ReadySet::new()),
            status: core::sync::atomic::AtomicU32::new(OFlags::RDWR.bits()),
            needs_host_poll: core::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(crate) fn wait(
        &self,
        global: &GlobalState<FS>,
        fs: &FS,
        cx: &WaitContext<'_, Platform>,
        maxevents: usize,
    ) -> Result<Vec<EpollEvent>, WaitError> {
        let mut events = Vec::new();

        if self
            .needs_host_poll
            .load(core::sync::atomic::Ordering::Relaxed)
        {
            // At least one descriptor requires periodic host polling (e.g.
            // stdin). Re-scan all interests with a short timeout to detect
            // host-side readiness changes, but also wait on the ready set so
            // observer-driven wakeups (e.g. eventfd) are not delayed until the
            // next poll tick.
            const POLL_INTERVAL: core::time::Duration = core::time::Duration::from_millis(50);
            loop {
                // Re-poll every interest — this calls check_io_events()
                // which queries the host for poll-only descriptors.
                self.rescan_interests(global, fs);

                self.ready.pop_multiple(global, fs, maxevents, &mut events);
                if !events.is_empty() {
                    return Ok(events);
                }

                // Check if the caller's deadline has already passed.
                if let Some(remaining) = cx.remaining_timeout() {
                    if remaining.is_zero() {
                        return Err(WaitError::TimedOut);
                    }
                } else if cx.deadline().is_some() {
                    // Deadline was set but remaining_timeout() returned None →
                    // deadline has passed.
                    return Err(WaitError::TimedOut);
                }

                // Sleep up to POLL_INTERVAL or until an observer fires or
                // the caller's deadline arrives, whichever is sooner.
                let poll_cx = cx.with_timeout(Some(POLL_INTERVAL));
                match self.ready.pollee.wait(&poll_cx, false, Events::IN, || {
                    self.ready.pop_multiple(global, fs, maxevents, &mut events);
                    if events.is_empty() {
                        return Err(TryOpError::<Infallible>::TryAgain);
                    }
                    Ok(())
                }) {
                    Ok(()) => return Ok(events),
                    Err(TryOpError::TryAgain) => unreachable!(),
                    Err(TryOpError::WaitError(WaitError::TimedOut)) => {
                        // If the caller's deadline has passed, propagate.
                        if cx
                            .deadline()
                            .is_some_and(|_| cx.remaining_timeout().is_none())
                        {
                            return Err(WaitError::TimedOut);
                        }
                        // Otherwise it was just our poll interval — continue.
                    }
                    Err(TryOpError::WaitError(WaitError::Interrupted)) => {
                        return Err(WaitError::Interrupted);
                    }
                    Err(TryOpError::Other(infallible)) => match infallible {},
                }
            }
        } else {
            match self.ready.pollee.wait(cx, false, Events::IN, || {
                self.ready.pop_multiple(global, fs, maxevents, &mut events);
                if events.is_empty() {
                    return Err(TryOpError::<Infallible>::TryAgain);
                }
                Ok(())
            }) {
                Ok(()) => Ok(events),
                Err(TryOpError::TryAgain) => unreachable!(),
                Err(TryOpError::WaitError(e)) => Err(e),
            }
        }
    }

    /// Re-scan all interests and push any that are ready to the ready set.
    fn rescan_interests(&self, global: &GlobalState<FS>, fs: &FS) {
        let interests = self.interests.lock();
        for entry in interests.values() {
            if entry.is_ready.load(core::sync::atomic::Ordering::Relaxed) {
                continue; // already in the ready set
            }
            if let Some((Some(_event), _)) = entry.poll(global, fs) {
                self.ready.push(entry);
            }
        }
    }

    pub(crate) fn epoll_ctl(
        &self,
        global: &GlobalState<FS>,
        fs: &FS,
        op: EpollOp,
        fd: u32,
        file: &EpollDescriptor<FS>,
        event: Option<EpollEvent>,
    ) -> Result<(), Errno> {
        match op {
            EpollOp::EpollCtlAdd => self.add_interest(global, fs, fd, file, event.unwrap()),
            EpollOp::EpollCtlMod => self.mod_interest(global, fs, fd, file, event.unwrap()),
            EpollOp::EpollCtlDel => {
                let mut interests = self.interests.lock();
                let _ = interests
                    .remove(&EpollEntryKey::new(fd, file))
                    .ok_or(Errno::ENOENT)?;
                Ok(())
            }
        }
    }

    fn add_interest(
        &self,
        global: &GlobalState<FS>,
        fs: &FS,
        fd: u32,
        file: &EpollDescriptor<FS>,
        event: EpollEvent,
    ) -> Result<(), Errno> {
        let mut interests = self.interests.lock();
        let key = EpollEntryKey::new(fd, file);
        if let Some(entry) = interests.get(&key)
            && entry.desc.upgrade().is_some()
        {
            return Err(Errno::EEXIST);
        }
        // we may have stale entry because we don't remove it immediately after the file is closed;
        // `insert` below will replace it with a new entry.

        let mask = Events::from_bits_truncate(event.events);
        let entry = EpollEntry::new(
            DescriptorRef::from(file),
            mask,
            EpollFlags::from_bits_truncate(event.events),
            event.data,
            self.ready.clone(),
        );
        let events = file
            .poll(global, fs, mask, Some(entry.weak_self.clone() as _))
            .ok_or(Errno::EBADF)?;
        // Add the new entry to the ready list if the file is ready
        if !events.is_empty() {
            self.ready.push(&entry);
        }
        if file.needs_host_poll(global, fs) {
            self.needs_host_poll
                .store(true, core::sync::atomic::Ordering::Relaxed);
        }
        interests.insert(key, entry);
        Ok(())
    }

    fn mod_interest(
        &self,
        global: &GlobalState<FS>,
        fs: &FS,
        fd: u32,
        file: &EpollDescriptor<FS>,
        event: EpollEvent,
    ) -> Result<(), Errno> {
        // EPOLLEXCLUSIVE is not allowed for a EPOLL_CTL_MOD operation
        let flags = EpollFlags::from_bits_truncate(event.events);
        if flags.contains(EpollFlags::EXCLUSIVE) {
            return Err(Errno::EINVAL);
        }

        let mut interests = self.interests.lock();
        let key = EpollEntryKey::new(fd, file);
        let entry = interests.get(&key).ok_or(Errno::ENOENT)?;
        if entry.desc.upgrade().is_none() {
            // The file descriptor is closed, remove the entry
            interests.remove(&key);
            return Err(Errno::ENOENT);
        }

        let mut inner = entry.inner.lock();
        if inner.flags.contains(EpollFlags::EXCLUSIVE) {
            // If EPOLLEXCLUSIVE has been set using epoll_ctl(), then a
            // subsequent EPOLL_CTL_MOD on the same epfd, fd pair yields an error.
            return Err(Errno::EINVAL);
        }

        let mask = Events::from_bits_truncate(event.events);
        inner.mask = mask;
        inner.flags = flags;
        inner.data = event.data;

        entry
            .is_enabled
            .store(true, core::sync::atomic::Ordering::Relaxed);
        let observer = entry.weak_self.clone();
        drop(inner);

        // re-register the observer with the new mask
        if let Some(events) = file.poll(global, fs, mask, Some(observer as _)) {
            if !events.is_empty() {
                // Add the updated entry to the ready list if the file is ready
                self.ready.push(entry);
            }

            Ok(())
        } else {
            // The file descriptor is closed, remove the entry
            interests.remove(&key);
            Err(Errno::ENOENT)
        }
    }

    super::common_functions_for_file_status!();
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct EpollEntryKey(u32, usize);
impl EpollEntryKey {
    fn new<FS: ShimFS>(fd: u32, desc: &EpollDescriptor<FS>) -> Self {
        let ptr = match desc {
            EpollDescriptor::Eventfd(file) => Arc::as_ptr(file).addr(),
            EpollDescriptor::Epoll(file) => Arc::as_ptr(file).addr(),
            EpollDescriptor::File(file) => Arc::as_ptr(file).addr(),
            EpollDescriptor::Socket(socket_fd) => Arc::as_ptr(socket_fd).addr(),
            EpollDescriptor::Pipe(pipe_fd) => Arc::as_ptr(pipe_fd).addr(),
            EpollDescriptor::Unix(unix) => Arc::as_ptr(unix).addr(),
        };
        Self(fd, ptr)
    }
}

struct EpollEntry<FS: ShimFS> {
    desc: DescriptorRef<FS>,
    inner: litebox::sync::Mutex<litebox_platform_multiplex::Platform, EpollEntryInner>,
    ready: Arc<ReadySet<FS>>,
    is_ready: AtomicBool,
    is_enabled: AtomicBool,
    weak_self: Weak<Self>,
}

struct EpollEntryInner {
    mask: Events,
    flags: EpollFlags,
    data: u64,
}

impl<FS: ShimFS> EpollEntry<FS> {
    fn new(
        desc: DescriptorRef<FS>,
        mask: Events,
        flags: EpollFlags,
        data: u64,
        ready: Arc<ReadySet<FS>>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|weak_self| EpollEntry {
            desc,
            inner: litebox::sync::Mutex::new(EpollEntryInner { mask, flags, data }),
            ready,
            is_ready: AtomicBool::new(false),
            is_enabled: AtomicBool::new(true),
            weak_self: weak_self.clone(),
        })
    }

    fn poll(&self, global: &GlobalState<FS>, fs: &FS) -> Option<(Option<EpollEvent>, bool)> {
        let file = self.desc.upgrade()?;
        let inner = self.inner.lock();

        if !self.is_enabled.load(core::sync::atomic::Ordering::Relaxed) {
            // the entry is disabled
            return None;
        }

        let events = file.poll(global, fs, inner.mask, None)?;
        if events.is_empty() {
            Some((None, false))
        } else {
            let event = Some(EpollEvent {
                events: events.bits(),
                data: inner.data,
            });

            // keep the entry in the ready list if it is not edge-triggered or one-shot
            let is_still_ready = event.is_some()
                && !inner
                    .flags
                    .intersects(EpollFlags::EDGE_TRIGGER | EpollFlags::ONE_SHOT);

            // disable the entry if it is one-shot
            if inner.flags.contains(EpollFlags::ONE_SHOT) {
                self.is_enabled
                    .store(false, core::sync::atomic::Ordering::Relaxed);
            }

            Some((event, is_still_ready))
        }
    }
}

impl<FS: ShimFS> Observer<Events> for EpollEntry<FS> {
    fn on_events(&self, _events: &Events) {
        self.ready.push(self);
    }
}

struct ReadySet<FS: ShimFS> {
    entries: litebox::sync::Mutex<
        litebox_platform_multiplex::Platform,
        VecDeque<alloc::sync::Weak<EpollEntry<FS>>>,
    >,
    pollee: Pollee<Platform>,
}

impl<FS: ShimFS> ReadySet<FS> {
    fn new() -> Self {
        Self {
            entries: litebox::sync::Mutex::new(VecDeque::new()),
            pollee: Pollee::new(),
        }
    }

    fn push(&self, entry: &EpollEntry<FS>) {
        if !entry.is_enabled.load(core::sync::atomic::Ordering::Relaxed) {
            // the entry is disabled
            return;
        }

        if !entry
            .is_ready
            .swap(true, core::sync::atomic::Ordering::Relaxed)
        {
            let mut entries = self.entries.lock();
            entries.push_back(entry.weak_self.clone());
        }

        self.pollee.notify_observers(Events::IN);
    }

    fn pop_multiple(
        &self,
        global: &GlobalState<FS>,
        fs: &FS,
        maxevents: usize,
        events: &mut Vec<EpollEvent>,
    ) {
        let mut nums = self.entries.lock().len();
        while nums > 0 {
            nums -= 1;
            if events.len() >= maxevents {
                break;
            }

            // Note the lock operation is performed inside the loop to avoid holding the lock while calling `poll()`.
            // e.g., `poll` on a socket requires lock on network, and a deadlock may happen if another thread
            // holds the network lock and tries to add an entry to the same epoll instance upon new events.
            let Some(weak_entry) = self.entries.lock().pop_front() else {
                // no more entries
                break;
            };

            let Some(entry) = weak_entry.upgrade() else {
                // the entry has been deleted
                continue;
            };
            entry
                .is_ready
                .store(false, core::sync::atomic::Ordering::Relaxed);

            let Some((event, is_still_ready)) = entry.poll(global, fs) else {
                // the entry is disabled or the associated file is closed
                continue;
            };

            if let Some(event) = event {
                events.push(event);
            }

            if is_still_ready {
                // if another event happened and already pushed the entry (i.e., marked it as ready)
                // while we were processing, we don't need to push it again.
                if !entry
                    .is_ready
                    .swap(true, core::sync::atomic::Ordering::Relaxed)
                {
                    self.entries.lock().push_back(weak_entry);
                }
            }
        }
    }
}

/// A poll set used for transient polling of a set of files. Designed for use
/// with the `poll` and `ppoll` syscalls.
pub(crate) struct PollSet {
    entries: Vec<PollEntry>,
}

struct PollEntry {
    fd: i32,
    mask: Events,
    revents: Events,
    observer: Option<Arc<PollEntryObserver>>,
}

#[derive(Clone)]
struct PollEntryObserver(Waker<Platform>);

impl PollSet {
    /// Returns a new empty `PollSet` with the given interest capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    /// Adds an fd to the poll set with the given event mask.
    ///
    /// If fd is negative, it is ignored during polling.
    pub fn add_fd(&mut self, fd: i32, mask: Events) {
        self.entries.push(PollEntry {
            fd,
            mask: mask | Events::ALWAYS_POLLED,
            revents: Events::empty(),
            observer: None,
        });
    }

    fn scan_once<FS: ShimFS>(
        &mut self,
        global: &GlobalState<FS>,
        files: &FilesState<FS>,
        waker: Option<&Waker<Platform>>,
    ) -> bool {
        let mut is_ready = false;
        for entry in &mut self.entries {
            entry.revents = if entry.fd < 0 {
                continue;
            } else if let Ok(poll_descriptor) =
                EpollDescriptor::try_from(files, entry.fd.reinterpret_as_unsigned() as usize)
            {
                let observer = if !is_ready && let Some(waker) = waker {
                    // TODO: a separate allocation is necessary here
                    // because registering an observer twice with two
                    // different event masks results in the last one
                    // replacing the first. If this is changed to
                    // instead combine the new event mask into the existing
                    // registration's mask, then we can use a single observer
                    // for all entries.
                    let observer = Arc::new(PollEntryObserver(waker.clone()));
                    let weak = Arc::downgrade(&observer);
                    entry.observer = Some(observer);
                    Some(weak as _)
                } else {
                    // The poll set is already ready, or we have already
                    // registered the observer for this entry.
                    None
                };
                // TODO: add machinery to unregister the observer to avoid leaks.
                poll_descriptor
                    .poll(global, &*files.fs, entry.mask, observer)
                    .unwrap_or(Events::NVAL)
            } else {
                Events::NVAL
            };
            if !entry.revents.is_empty() {
                is_ready = true;
            }
        }
        is_ready
    }

    /// Scans the poll set for ready fds once.
    pub fn scan<FS: ShimFS>(&mut self, global: &GlobalState<FS>, files: &FilesState<FS>) {
        self.scan_once(global, files, None);
    }

    /// Waits for any of the fds in the poll set to become ready.
    pub fn wait<FS: ShimFS>(
        &mut self,
        global: &GlobalState<FS>,
        cx: &WaitContext<'_, Platform>,
        files: &FilesState<FS>,
    ) -> Result<(), WaitError> {
        if self.scan_once(global, files, None) {
            return Ok(());
        }

        // Check if any entry needs host polling (e.g. stdin).
        let needs_host_poll = self.has_host_poll_fds(global, files);

        if needs_host_poll {
            const POLL_INTERVAL: core::time::Duration = core::time::Duration::from_millis(50);
            loop {
                if self.scan_once(global, files, None) {
                    return Ok(());
                }
                let poll_cx = cx.with_timeout(Some(POLL_INTERVAL));
                match poll_cx.sleep() {
                    WaitError::TimedOut => {
                        if cx
                            .deadline()
                            .is_some_and(|_| cx.remaining_timeout().is_none())
                        {
                            return Err(WaitError::TimedOut);
                        }
                    }
                    WaitError::Interrupted => return Err(WaitError::Interrupted),
                }
            }
        } else {
            let mut register = true;
            cx.wait_until(|| {
                if self.scan_once(global, files, register.then_some(cx.waker())) {
                    return true;
                }
                // Don't register observers again in the next iteration.
                register = false;
                false
            })
        }
    }

    /// Returns true if any entry in the poll set requires host polling.
    fn has_host_poll_fds<FS: ShimFS>(
        &self,
        global: &GlobalState<FS>,
        files: &FilesState<FS>,
    ) -> bool {
        for entry in &self.entries {
            if entry.fd < 0 {
                continue;
            }
            let raw_fd = entry.fd.reinterpret_as_unsigned() as usize;
            if let Ok(poll_descriptor) = EpollDescriptor::try_from(files, raw_fd)
                && poll_descriptor.needs_host_poll(global, &*files.fs)
            {
                return true;
            }
        }
        false
    }

    /// Returns the accumulated `revents` for each entry in the poll set.
    ///
    /// These are only valid after a call to `wait_or_timeout`.
    pub fn revents(&self) -> impl Iterator<Item = Events> + '_ {
        self.entries.iter().map(|entry| entry.revents)
    }

    /// Returns the accumulated `revents` and corresponding fds for each entry in the poll set.
    ///
    /// These are only valid after a call to `wait_or_timeout`.
    pub fn revents_with_fds(&self) -> impl Iterator<Item = (i32, Events)> + '_ {
        self.entries.iter().map(|entry| (entry.fd, entry.revents))
    }
}

impl Observer<Events> for PollEntryObserver {
    fn on_events(&self, _events: &Events) {
        self.0.wake();
    }
}

#[cfg(test)]
mod test {
    use core::sync::atomic::{AtomicBool, Ordering};
    use core::time::Duration;

    use alloc::sync::Arc;
    use litebox::event::Events;
    use litebox::event::wait::WaitState;
    use litebox::platform::RawConstPointer as _;
    use litebox::platform::TimeProvider as _;
    use litebox::utils::TruncateExt as _;
    use litebox_common_linux::{
        ClockId, EfdFlags, EpollEvent, ItimerSpec, TimerfdFlags, TimerfdTimerFlags,
    };
    use litebox_platform_multiplex::platform;

    use super::EpollFile;
    use crate::syscalls::file::FilesState;

    extern crate std;

    fn setup_epoll() -> (
        crate::Task<crate::DefaultFS>,
        EpollFile<crate::DefaultFS>,
        alloc::sync::Arc<crate::DefaultFS>,
    ) {
        let task = crate::syscalls::tests::init_platform(None);
        let fs = task.files.borrow().fs.clone();
        let epoll = EpollFile::new();
        (task, epoll, fs)
    }

    #[test]
    fn test_epoll_with_eventfd() {
        let (task, epoll, fs) = setup_epoll();
        let eventfd = crate::syscalls::eventfd::EventFile::new(0, EfdFlags::CLOEXEC);
        let typed = task
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<crate::syscalls::eventfd::EventfdSubsystem>(eventfd);
        let files = Arc::new(FilesState::new(task.files.borrow().fs.clone()));
        let Ok(raw_fd) = files.insert_raw_fd(typed) else {
            unreachable!()
        };
        let descriptor = super::EpollDescriptor::try_from(&files, raw_fd).unwrap();
        epoll
            .add_interest(
                &task.global,
                &*fs,
                10,
                &descriptor,
                EpollEvent {
                    events: Events::IN.bits(),
                    data: 0,
                },
            )
            .unwrap();

        // spawn a thread to write to the eventfd
        {
            let global = task.global.clone();
            let files = Arc::clone(&files);
            std::thread::spawn(move || {
                let typed = files
                    .raw_descriptor_store
                    .read()
                    .fd_from_raw_integer::<crate::syscalls::eventfd::EventfdSubsystem>(raw_fd)
                    .unwrap();
                let _ = global
                    .litebox
                    .descriptor_table()
                    .with_entry(&typed, |entry| {
                        entry.write(&WaitState::new(platform()).context(), 1)
                    });
            });
        }
        epoll
            .wait(
                &task.global,
                &*fs,
                &WaitState::new(platform()).context(),
                1024,
            )
            .unwrap();
    }

    #[test]
    fn test_epoll_with_timerfd() {
        let (task, epoll, fs) = setup_epoll();
        let timerfd = crate::syscalls::eventfd::EventFile::new_timer(
            platform(),
            platform().now(),
            ClockId::Monotonic,
            TimerfdFlags::empty(),
        );
        let typed = task
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<crate::syscalls::eventfd::EventfdSubsystem>(timerfd);
        let files = Arc::new(FilesState::new(task.files.borrow().fs.clone()));
        let Ok(raw_fd) = files.insert_raw_fd(typed) else {
            unreachable!()
        };
        let descriptor = super::EpollDescriptor::try_from(&files, raw_fd).unwrap();
        epoll
            .add_interest(
                &task.global,
                &*fs,
                11,
                &descriptor,
                EpollEvent {
                    events: Events::IN.bits(),
                    data: 0,
                },
            )
            .unwrap();
        task.global
            .litebox
            .descriptor_table()
            .with_entry(
                &files
                    .raw_descriptor_store
                    .read()
                    .fd_from_raw_integer::<crate::syscalls::eventfd::EventfdSubsystem>(raw_fd)
                    .unwrap(),
                |entry| {
                    entry.set_timer(
                        TimerfdTimerFlags::empty(),
                        ItimerSpec {
                            interval: Duration::ZERO.into(),
                            value: Duration::from_millis(1).into(),
                        },
                    )
                },
            )
            .unwrap()
            .unwrap();

        let events = epoll
            .wait(
                &task.global,
                &*fs,
                &WaitState::new(platform()).context(),
                1024,
            )
            .unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_epoll_with_eventfd_and_timerfd() {
        let (task, epoll, fs) = setup_epoll();

        let eventfd = crate::syscalls::eventfd::EventFile::new(0, EfdFlags::CLOEXEC);
        let eventfd = task
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<crate::syscalls::eventfd::EventfdSubsystem>(eventfd);

        let timerfd = crate::syscalls::eventfd::EventFile::new_timer(
            platform(),
            platform().now(),
            ClockId::Monotonic,
            TimerfdFlags::empty(),
        );
        let timerfd = task
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<crate::syscalls::eventfd::EventfdSubsystem>(timerfd);

        let files = Arc::new(FilesState::new(task.files.borrow().fs.clone()));
        let Ok(eventfd_raw) = files.insert_raw_fd(eventfd) else {
            unreachable!()
        };
        let Ok(timerfd_raw) = files.insert_raw_fd(timerfd) else {
            unreachable!()
        };

        let eventfd_desc = super::EpollDescriptor::try_from(&files, eventfd_raw).unwrap();
        epoll
            .add_interest(
                &task.global,
                &*fs,
                12,
                &eventfd_desc,
                EpollEvent {
                    events: Events::IN.bits(),
                    data: 12,
                },
            )
            .unwrap();

        let timerfd_desc = super::EpollDescriptor::try_from(&files, timerfd_raw).unwrap();
        epoll
            .add_interest(
                &task.global,
                &*fs,
                13,
                &timerfd_desc,
                EpollEvent {
                    events: Events::IN.bits(),
                    data: 13,
                },
            )
            .unwrap();

        {
            let global = task.global.clone();
            let files = Arc::clone(&files);
            std::thread::spawn(move || {
                std::thread::sleep(core::time::Duration::from_millis(10));
                let typed = files
                    .raw_descriptor_store
                    .read()
                    .fd_from_raw_integer::<crate::syscalls::eventfd::EventfdSubsystem>(eventfd_raw)
                    .unwrap();
                let _ = global
                    .litebox
                    .descriptor_table()
                    .with_entry(&typed, |entry| {
                        entry.write(&WaitState::new(platform()).context(), 1)
                    });
            });
        }

        let events = epoll
            .wait(
                &task.global,
                &*fs,
                &WaitState::new(platform())
                    .context()
                    .with_timeout(core::time::Duration::from_secs(1)),
                1024,
            )
            .unwrap();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        let data = event.data;
        let events_bits = event.events;
        assert_eq!(data, 12);
        assert_eq!(events_bits, Events::IN.bits());
    }

    #[test]
    fn test_epoll_with_host_poll_and_spurious_wakes() {
        let (task, epoll, fs) = setup_epoll();

        let eventfd = crate::syscalls::eventfd::EventFile::new(0, EfdFlags::CLOEXEC);
        let eventfd = task
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<crate::syscalls::eventfd::EventfdSubsystem>(eventfd);

        let timerfd = crate::syscalls::eventfd::EventFile::new_timer(
            platform(),
            platform().now(),
            ClockId::Monotonic,
            TimerfdFlags::empty(),
        );
        let timerfd = task
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<crate::syscalls::eventfd::EventfdSubsystem>(timerfd);

        let files = Arc::new(FilesState::new(task.files.borrow().fs.clone()));
        let Ok(eventfd_raw) = files.insert_raw_fd(eventfd) else {
            unreachable!()
        };
        let Ok(timerfd_raw) = files.insert_raw_fd(timerfd) else {
            unreachable!()
        };

        let eventfd_desc = super::EpollDescriptor::try_from(&files, eventfd_raw).unwrap();
        epoll
            .add_interest(
                &task.global,
                &*fs,
                12,
                &eventfd_desc,
                EpollEvent {
                    events: Events::IN.bits(),
                    data: 12,
                },
            )
            .unwrap();

        let timerfd_desc = super::EpollDescriptor::try_from(&files, timerfd_raw).unwrap();
        epoll
            .add_interest(
                &task.global,
                &*fs,
                13,
                &timerfd_desc,
                EpollEvent {
                    events: Events::IN.bits(),
                    data: 13,
                },
            )
            .unwrap();

        let wait_state = WaitState::new(platform());
        let waiter_waker = wait_state.context().waker().clone();
        let stop_spurious_wakes = Arc::new(AtomicBool::new(false));

        let spurious_waker = {
            let stop_spurious_wakes = Arc::clone(&stop_spurious_wakes);
            std::thread::spawn(move || {
                while !stop_spurious_wakes.load(Ordering::Relaxed) {
                    waiter_waker.wake();
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        };

        let writer = {
            let global = task.global.clone();
            let files = Arc::clone(&files);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                let typed = files
                    .raw_descriptor_store
                    .read()
                    .fd_from_raw_integer::<crate::syscalls::eventfd::EventfdSubsystem>(eventfd_raw)
                    .unwrap();
                let _ = global
                    .litebox
                    .descriptor_table()
                    .with_entry(&typed, |entry| {
                        entry.write(&WaitState::new(platform()).context(), 1)
                    });
            })
        };

        let events = epoll
            .wait(
                &task.global,
                &*fs,
                &wait_state
                    .context()
                    .with_timeout(Duration::from_millis(200)),
                1024,
            )
            .unwrap();

        stop_spurious_wakes.store(true, Ordering::Relaxed);
        spurious_waker.join().unwrap();
        writer.join().unwrap();

        assert_eq!(events.len(), 1);
        let event = &events[0];
        let data = event.data;
        let events_bits = event.events;
        assert_eq!(data, 12);
        assert_eq!(events_bits, Events::IN.bits());
    }

    #[test]
    fn test_sys_epoll_pwait_with_eventfd_and_timerfd() {
        let task = crate::syscalls::tests::init_platform(None);

        let epfd = task
            .sys_epoll_create(litebox_common_linux::EpollCreateFlags::empty())
            .expect("failed to create epoll");
        let epfd = i32::try_from(epfd).unwrap();

        let eventfd = task
            .sys_eventfd2(0, EfdFlags::empty())
            .expect("failed to create eventfd");
        let eventfd = i32::try_from(eventfd).unwrap();

        let timerfd = task
            .sys_timerfd_create(ClockId::Monotonic, TimerfdFlags::empty())
            .expect("failed to create timerfd");
        let timerfd = i32::try_from(timerfd).unwrap();

        let eventfd_event = litebox_common_linux::EpollEvent {
            events: Events::IN.bits(),
            data: 0x1111,
        };
        task.sys_epoll_ctl(
            epfd,
            litebox_common_linux::EpollOp::EpollCtlAdd,
            eventfd,
            crate::ConstPtr::from_usize((&raw const eventfd_event) as usize),
        )
        .expect("failed to add eventfd to epoll");

        let timerfd_event = litebox_common_linux::EpollEvent {
            events: Events::IN.bits(),
            data: 0x2222,
        };
        task.sys_epoll_ctl(
            epfd,
            litebox_common_linux::EpollOp::EpollCtlAdd,
            timerfd,
            crate::ConstPtr::from_usize((&raw const timerfd_event) as usize),
        )
        .expect("failed to add timerfd to epoll");

        task.spawn_clone_for_test(move |task| {
            std::thread::sleep(core::time::Duration::from_millis(10));
            let written = task
                .sys_write(eventfd, &1u64.to_le_bytes(), None)
                .expect("eventfd write failed");
            assert_eq!(written, 8);
        });

        let mut events = [litebox_common_linux::EpollEvent { events: 0, data: 0 }; 4];
        let ready = task
            .sys_epoll_pwait(
                epfd,
                crate::MutPtr::from_usize(events.as_mut_ptr() as usize),
                events.len().truncate(),
                litebox_common_linux::TimeParam::Milliseconds(1000),
                None,
                0,
            )
            .expect("epoll_pwait failed");

        assert_eq!(ready, 1);
        let event = &events[0];
        let data = event.data;
        let events_bits = event.events;
        assert_eq!(data, 0x1111);
        assert_eq!(events_bits, Events::IN.bits());
    }

    #[test]
    fn test_epoll_with_pipe() {
        let (task, epoll, fs) = setup_epoll();
        let (producer, consumer) =
            task.global
                .pipes
                .create_pipe(2, litebox::pipes::Flags::empty(), None);
        let consumer = Arc::new(consumer);
        let reader = super::EpollDescriptor::Pipe(Arc::clone(&consumer));
        epoll
            .add_interest(
                &task.global,
                &*fs,
                10,
                &reader,
                EpollEvent {
                    events: Events::IN.bits(),
                    data: 0,
                },
            )
            .unwrap();

        // spawn a thread to write to the pipe
        let global = task.global.clone();
        std::thread::spawn(move || {
            std::thread::sleep(core::time::Duration::from_millis(100));
            assert_eq!(
                global
                    .pipes
                    .write(&WaitState::new(platform()).context(), &producer, &[1, 2])
                    .unwrap(),
                2
            );
        });
        epoll
            .wait(
                &task.global,
                &*fs,
                &WaitState::new(platform()).context(),
                1024,
            )
            .unwrap();
        let mut buf = [0; 2];
        task.global
            .pipes
            .read(&WaitState::new(platform()).context(), &consumer, &mut buf)
            .unwrap();
        assert_eq!(buf, [1, 2]);
    }

    #[test]
    fn test_poll() {
        let task = crate::syscalls::tests::init_platform(None);

        let mut set = super::PollSet::with_capacity(0);
        let eventfd = crate::syscalls::eventfd::EventFile::new(0, EfdFlags::empty());

        let typed = task
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<crate::syscalls::eventfd::EventfdSubsystem>(eventfd);
        let no_fds = FilesState::new(task.files.borrow().fs.clone());
        let fds = Arc::new(FilesState::new(task.files.borrow().fs.clone()));
        let Ok(raw_fd) = fds.insert_raw_fd(typed) else {
            unreachable!()
        };
        let fd = i32::try_from(raw_fd).unwrap();
        set.add_fd(fd, Events::IN);

        let revents = |set: &super::PollSet| {
            let revents: std::vec::Vec<_> = set.revents().collect();
            assert_eq!(revents.len(), 1);
            revents[0]
        };

        set.wait(&task.global, &WaitState::new(platform()).context(), &no_fds)
            .unwrap();
        assert_eq!(revents(&set), Events::NVAL);

        {
            let typed = fds
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<crate::syscalls::eventfd::EventfdSubsystem>(raw_fd)
                .unwrap();
            task.global
                .litebox
                .descriptor_table()
                .with_entry(&typed, |entry| {
                    entry.write(&WaitState::new(platform()).context(), 1)
                });
        }
        set.wait(&task.global, &WaitState::new(platform()).context(), &fds)
            .unwrap();
        assert_eq!(revents(&set), Events::IN);

        {
            let typed = fds
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<crate::syscalls::eventfd::EventfdSubsystem>(raw_fd)
                .unwrap();
            task.global
                .litebox
                .descriptor_table()
                .with_entry(&typed, |entry| {
                    entry.read(&WaitState::new(platform()).context())
                });
        }
        set.wait(
            &task.global,
            &WaitState::new(platform())
                .context()
                .with_timeout(core::time::Duration::from_millis(100)),
            &fds,
        )
        .unwrap_err();
        assert!(revents(&set).is_empty());

        // spawn a thread to write to the eventfd
        let global = task.global.clone();
        let fds_for_thread = Arc::clone(&fds);
        std::thread::spawn(move || {
            let typed = fds_for_thread
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<crate::syscalls::eventfd::EventfdSubsystem>(raw_fd)
                .unwrap();
            let handle = global
                .litebox
                .descriptor_table()
                .entry_handle(&typed)
                .unwrap();
            let _ =
                handle.with_entry(|entry| entry.write(&WaitState::new(platform()).context(), 1));
        });

        set.wait(&task.global, &WaitState::new(platform()).context(), &fds)
            .unwrap();
        assert_eq!(revents(&set), Events::IN);
    }

    #[test]
    fn test_pselect() {
        let task = crate::syscalls::tests::init_platform(None);

        let (rfd_u, wfd_u) = task
            .sys_pipe2(litebox::fs::OFlags::empty())
            .expect("pipe2 failed");
        let rfd = i32::try_from(rfd_u).unwrap();
        let wfd = i32::try_from(wfd_u).unwrap();

        task.spawn_clone_for_test(move |task| {
            std::thread::sleep(core::time::Duration::from_millis(100));
            // write a byte
            let buf = [0x41u8];
            let written = task.sys_write(wfd, &buf, None).expect("write failed");
            assert_eq!(written, 1);
        });

        // prepare fd_set for read
        let mut rfds = bitvec::bitvec![0; rfd_u.next_multiple_of(64) as usize];
        rfds.set(rfd_u as usize, true);

        // Call pselect
        let ret = task
            .do_pselect(rfd_u + 1, Some(&mut rfds), None, None, None)
            .expect("pselect failed");
        assert!(ret > 0, "pselect should report ready");
        assert!(rfds.iter_ones().all(|fd| fd == rfd_u as usize));

        // read
        let mut out = [0u8; 8];
        let n = task.sys_read(rfd, &mut out, None).expect("read failed");
        assert_eq!(n, 1);
        assert_eq!(out[0], 0x41);

        let _ = task.sys_close(rfd);
        let _ = task.sys_close(wfd);
    }

    #[test]
    fn test_pselect_read_hup() {
        let task = crate::syscalls::tests::init_platform(None);

        let (rfd_u, wfd_u) = task
            .sys_pipe2(litebox::fs::OFlags::empty())
            .expect("pipe2 failed");
        let rfd = i32::try_from(rfd_u).unwrap();
        let wfd = i32::try_from(wfd_u).unwrap();

        task.spawn_clone_for_test(move |task| {
            std::thread::sleep(core::time::Duration::from_millis(100));
            task.sys_close(wfd).expect("close writer failed");
        });

        // prepare fd_set for read
        let mut rfds = bitvec::bitvec![0; rfd_u.next_multiple_of(64) as usize];
        rfds.set(rfd_u as usize, true);

        let ret = task
            .do_pselect(
                rfd_u + 1,
                Some(&mut rfds),
                None,
                None,
                Some(core::time::Duration::from_secs(60)),
            )
            .expect("pselect failed");

        // Expect pselect to indicate readiness (HUP should cause revents)
        assert!(ret > 0, "pselect should report ready for EOF/HUP");
        assert!(rfds.iter_ones().all(|fd| fd == rfd_u as usize));

        // read should return 0 (EOF)
        let mut out = [0u8; 8];
        let n = task.sys_read(rfd, &mut out, None).expect("read failed");
        assert_eq!(n, 0, "read should return 0 on EOF");

        let _ = task.sys_close(rfd);
    }

    #[test]
    fn test_pselect_invalid_fd() {
        let task = crate::syscalls::tests::init_platform(None);

        let invalid_fd_u = 100u32;

        // prepare fd_set for read
        let mut rfds = bitvec::bitvec![0; invalid_fd_u.next_multiple_of(64) as usize];
        rfds.set(invalid_fd_u as usize, true);

        let ret = task.do_pselect(
            invalid_fd_u + 1,
            Some(&mut rfds),
            None,
            None,
            Some(core::time::Duration::from_secs(1)),
        );

        // Expect pselect to return EBADF
        assert!(ret.is_err(), "pselect should fail for invalid fd");
        assert_eq!(
            ret.err().unwrap(),
            litebox_common_linux::errno::Errno::EBADF
        );
    }
}
