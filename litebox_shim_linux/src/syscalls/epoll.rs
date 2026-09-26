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
    fd::{
        EntryHandle, EntryIdentity, FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd,
        WeakEntryHandle,
    },
    utils::ReinterpretUnsignedExt,
};
use litebox_common_linux::{EpollEvent, EpollOp, errno::Errno};

use super::file::FilesState;
use crate::{GlobalState, ShimFS, ShimPlatform};

/// Serializes every nested-epoll `epoll_ctl(ADD)` across the whole process, mirroring real
/// Linux's `epmutex`. Cycle detection (walking the nested-epoll DAG) and the edge insertion it
/// guards have to happen as one atomic step: checking and inserting under separate locks lets two
/// concurrent adds that each individually look cycle-free still complete a cycle together (e.g.
/// thread 1 adds B into A, thread 2 concurrently adds A into B; neither sees the other's
/// not-yet-committed edge during its own check). A single global lock removes the race by only
/// ever allowing one such check-then-insert to be in flight anywhere in the process. It is not
/// taken for plain (non-nested) adds or for readiness polling, so the common case pays nothing
/// for it.
static EPOLL_NEST_LOCK: spin::Mutex<()> = spin::Mutex::new(());

pub(crate) struct EpollSubsystem<Platform: ShimPlatform, FS: ShimFS>(
    core::marker::PhantomData<(Platform, FS)>,
);
impl<Platform: ShimPlatform, FS: ShimFS> FdEnabledSubsystem for EpollSubsystem<Platform, FS> {
    type Entry = EpollFile<Platform, FS>;
}
impl<Platform: ShimPlatform, FS: ShimFS> FdEnabledSubsystemEntry for EpollFile<Platform, FS> {}

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

pub(crate) enum EpollDescriptor<Platform: ShimPlatform, FS: ShimFS> {
    Eventfd(WeakEntryHandle<Platform, super::eventfd::EventfdSubsystem<Platform>>),
    Epoll(WeakEntryHandle<Platform, super::epoll::EpollSubsystem<Platform, FS>>),
    File(WeakEntryHandle<Platform, FS>),
    Socket(WeakEntryHandle<Platform, crate::Network<Platform>>),
    Pipe(WeakEntryHandle<Platform, litebox::pipes::Pipes<Platform>>),
    Unix(WeakEntryHandle<Platform, crate::syscalls::unix::UnixSocketSubsystem<Platform, FS>>),
    Netlink(WeakEntryHandle<Platform, crate::syscalls::netlink::NetlinkSubsystem<Platform>>),
    Inotify(WeakEntryHandle<Platform, super::inotify::InotifySubsystem<Platform>>),
}

impl<Platform: ShimPlatform, FS: ShimFS> Clone for EpollDescriptor<Platform, FS> {
    fn clone(&self) -> Self {
        match self {
            Self::Eventfd(file) => Self::Eventfd(file.clone()),
            Self::Epoll(file) => Self::Epoll(file.clone()),
            Self::File(file) => Self::File(file.clone()),
            Self::Socket(socket) => Self::Socket(socket.clone()),
            Self::Pipe(pipe) => Self::Pipe(pipe.clone()),
            Self::Unix(unix) => Self::Unix(unix.clone()),
            Self::Netlink(netlink) => Self::Netlink(netlink.clone()),
            Self::Inotify(inotify) => Self::Inotify(inotify.clone()),
        }
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> EpollDescriptor<Platform, FS> {
    pub fn try_from(
        global: &GlobalState<Platform, FS>,
        files: &FilesState<Platform, FS>,
        raw_fd: usize,
    ) -> Result<Self, Errno> {
        let rds = files.raw_descriptor_store.read();
        if let Ok(fd) = rds.fd_from_raw_integer::<FS>(raw_fd) {
            let handle = global
                .litebox
                .descriptor_table()
                .entry_handle(&fd)
                .ok_or(Errno::EBADF)?;
            return Ok(Self::File(handle.downgrade()));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<crate::Network<Platform>>(raw_fd) {
            let handle = global
                .litebox
                .descriptor_table()
                .entry_handle(&fd)
                .ok_or(Errno::EBADF)?;
            return Ok(Self::Socket(handle.downgrade()));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<litebox::pipes::Pipes<Platform>>(raw_fd) {
            let handle = global
                .litebox
                .descriptor_table()
                .entry_handle(&fd)
                .ok_or(Errno::EBADF)?;
            return Ok(Self::Pipe(handle.downgrade()));
        }
        if let Ok(fd) =
            rds.fd_from_raw_integer::<super::eventfd::EventfdSubsystem<Platform>>(raw_fd)
        {
            let handle = global
                .litebox
                .descriptor_table()
                .entry_handle(&fd)
                .ok_or(Errno::EBADF)?;
            return Ok(Self::Eventfd(handle.downgrade()));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<EpollSubsystem<Platform, FS>>(raw_fd) {
            let handle = global
                .litebox
                .descriptor_table()
                .entry_handle(&fd)
                .ok_or(Errno::EBADF)?;
            return Ok(Self::Epoll(handle.downgrade()));
        }
        if let Ok(fd) =
            rds.fd_from_raw_integer::<super::unix::UnixSocketSubsystem<Platform, FS>>(raw_fd)
        {
            let handle = global
                .litebox
                .descriptor_table()
                .entry_handle(&fd)
                .ok_or(Errno::EBADF)?;
            return Ok(Self::Unix(handle.downgrade()));
        }
        if let Ok(fd) =
            rds.fd_from_raw_integer::<super::netlink::NetlinkSubsystem<Platform>>(raw_fd)
        {
            let handle = global
                .litebox
                .descriptor_table()
                .entry_handle(&fd)
                .ok_or(Errno::EBADF)?;
            return Ok(Self::Netlink(handle.downgrade()));
        }
        if let Ok(fd) =
            rds.fd_from_raw_integer::<super::inotify::InotifySubsystem<Platform>>(raw_fd)
        {
            let handle = global
                .litebox
                .descriptor_table()
                .entry_handle(&fd)
                .ok_or(Errno::EBADF)?;
            return Ok(Self::Inotify(handle.downgrade()));
        }
        Err(Errno::EBADF)
    }

    fn identity(&self) -> EntryIdentity {
        match self {
            Self::Eventfd(file) => file.identity(),
            Self::Epoll(file) => file.identity(),
            Self::File(file) => file.identity(),
            Self::Socket(socket) => socket.identity(),
            Self::Pipe(pipe) => pipe.identity(),
            Self::Unix(unix) => unix.identity(),
            Self::Netlink(netlink) => netlink.identity(),
            Self::Inotify(inotify) => inotify.identity(),
        }
    }

    fn is_alive(&self) -> bool {
        match self {
            Self::Eventfd(file) => file.upgrade().is_some(),
            Self::Epoll(file) => file.upgrade().is_some(),
            Self::File(file) => file.upgrade().is_some(),
            Self::Socket(socket) => socket.upgrade().is_some(),
            Self::Pipe(pipe) => pipe.upgrade().is_some(),
            Self::Unix(unix) => unix.upgrade().is_some(),
            Self::Netlink(netlink) => netlink.upgrade().is_some(),
            Self::Inotify(inotify) => inotify.upgrade().is_some(),
        }
    }

    pub(crate) fn is_epoll_identity(&self, identity: EntryIdentity) -> bool {
        matches!(self, Self::Epoll(epoll) if epoll.identity() == identity)
    }

    fn epoll_handle(&self) -> Option<EntryHandle<Platform, EpollSubsystem<Platform, FS>>> {
        match self {
            Self::Epoll(epoll) => epoll.upgrade(),
            _ => None,
        }
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> EpollDescriptor<Platform, FS> {
    /// Returns the interesting events now and monitors their occurrence in the future if the
    /// observer is provided.
    fn poll(
        &self,
        global: &GlobalState<Platform, FS>,
        mask: Events,
        observer: Option<Weak<dyn Observer<Events>>>,
    ) -> Option<Events> {
        // `/dev/input/event*` fds have real queue-backed readiness through the input registry
        // (X11/libinput poll these and only read after `IN` -- dummy always-ready would spin
        // them on empty reads). Register before checking the queue: an input record arriving
        // between a check and a later registration would otherwise leave Xorg asleep until the
        // next record, making every click or key appear one event late.
        if let EpollDescriptor::File(file) = self
            && let Some(file) = file.upgrade()
            && let Some(registry) = global.input_registry.as_ref()
            && let Ok(minor) = file.with_metadata(|meta: &super::file::InputEventMinor| meta.minor)
        {
            if let Some(observer) = observer {
                registry.register_observer(minor, observer, mask);
            }
            let events = registry.check_io_events(minor)?;
            return Some(events & (mask | Events::ALWAYS_POLLED));
        }
        let poll = |iop: &dyn IOPollable| {
            if let Some(observer) = observer {
                iop.register_observer(observer, mask);
            }
            iop.check_io_events() & (mask | Events::ALWAYS_POLLED)
        };
        match self {
            EpollDescriptor::Eventfd(fd) => {
                let handle = fd.upgrade()?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::Epoll(fd) => {
                let handle = fd.upgrade()?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::File(file) => {
                let file = file.upgrade()?;
                // Real files in general still get dummy "always ready" events -- only stdin has
                // a real, epoll-observable readiness signal (see `StdioProvider::stdin_pollable`
                // and `litebox::platform::StdinPump`); stdout/stderr writes to a real terminal
                // essentially never block in practice, so `Events::OUT` dummy readiness for them
                // remains a reasonable approximation.
                let events =
                    match file.with_metadata(|stream: &litebox::platform::StdioStream| *stream) {
                        Ok(litebox::platform::StdioStream::Stdin) => {
                            match global.platform.stdin_pollable() {
                                Some(pollable) => poll(pollable),
                                // Platform can't distinguish real readiness: fall back to the
                                // pre-existing dummy "always ready" behavior.
                                None => Events::IN,
                            }
                        }
                        Ok(
                            litebox::platform::StdioStream::Stdout
                            | litebox::platform::StdioStream::Stderr,
                        )
                        | Err(_) => Events::OUT,
                    };
                Some(events & mask)
            }
            EpollDescriptor::Socket(fd) => {
                let handle = fd.upgrade()?;
                let proxy = handle
                    .with_metadata(|proxy: &super::net::SocketProxy<Platform>| proxy.0.clone())
                    .ok()?;
                Some(poll(proxy.as_ref()))
            }
            EpollDescriptor::Pipe(fd) => {
                let handle = fd.upgrade()?;
                Some(global.pipes.with_iopollable_handle(&handle, poll))
            }
            EpollDescriptor::Unix(fd) => {
                let handle = fd.upgrade()?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::Netlink(fd) => {
                let handle = fd.upgrade()?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::Inotify(fd) => {
                let handle = fd.upgrade()?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
        }
    }

    /// Resolves where a transient observer must be removed before registering it.
    ///
    /// Most registrations live in the open file description and can be found again through this
    /// descriptor's weak handle. Input queues and stdin are different: their subjects outlive the
    /// filesystem entry. Remember those special routes now so closing the last descriptor while
    /// `poll` is asleep cannot strand a dead observer in a long-lived subject.
    fn transient_registration_target(
        &self,
        global: &GlobalState<Platform, FS>,
    ) -> PollRegistrationTarget<Platform, FS> {
        if let Self::File(file) = self
            && let Some(file) = file.upgrade()
        {
            if global.input_registry.is_some()
                && let Ok(minor) =
                    file.with_metadata(|meta: &super::file::InputEventMinor| meta.minor)
            {
                return PollRegistrationTarget::InputDevice(minor);
            }
            if let Ok(litebox::platform::StdioStream::Stdin) =
                file.with_metadata(|stream: &litebox::platform::StdioStream| *stream)
                && global.platform.stdin_pollable().is_some()
            {
                return PollRegistrationTarget::Stdin;
            }
        }
        PollRegistrationTarget::Descriptor(self.clone())
    }

    /// Removes a registration previously made by [`Self::poll`]. The descriptor only keeps weak
    /// open-file-description handles, so cleanup never extends the lifetime of the polled object.
    fn unregister_observer(
        &self,
        global: &GlobalState<Platform, FS>,
        observer: Weak<dyn Observer<Events>>,
    ) {
        // Input devices bypass the filesystem's dummy readiness path and register directly on the
        // queue owned by InputRegistry, so their cleanup must take that same path.
        if let EpollDescriptor::File(file) = self
            && let Some(file) = file.upgrade()
            && let Some(registry) = global.input_registry.as_ref()
            && let Ok(minor) = file.with_metadata(|meta: &super::file::InputEventMinor| meta.minor)
        {
            registry.unregister_observer(minor, observer);
            return;
        }

        let unregister = |iop: &dyn IOPollable| {
            iop.unregister_observer(observer.clone());
        };
        match self {
            EpollDescriptor::Eventfd(fd) => {
                if let Some(handle) = fd.upgrade() {
                    handle.with_entry(|entry| unregister(entry));
                }
            }
            EpollDescriptor::Epoll(fd) => {
                if let Some(handle) = fd.upgrade() {
                    handle.with_entry(|entry| unregister(entry));
                }
            }
            EpollDescriptor::File(file) => {
                let Some(file) = file.upgrade() else {
                    return;
                };
                if let Ok(litebox::platform::StdioStream::Stdin) =
                    file.with_metadata(|stream: &litebox::platform::StdioStream| *stream)
                    && let Some(pollable) = global.platform.stdin_pollable()
                {
                    unregister(pollable);
                }
            }
            EpollDescriptor::Socket(fd) => {
                let Some(handle) = fd.upgrade() else {
                    return;
                };
                if let Ok(proxy) = handle
                    .with_metadata(|proxy: &super::net::SocketProxy<Platform>| proxy.0.clone())
                {
                    unregister(proxy.as_ref());
                }
            }
            EpollDescriptor::Pipe(fd) => {
                if let Some(handle) = fd.upgrade() {
                    global.pipes.with_iopollable_handle(&handle, unregister);
                }
            }
            EpollDescriptor::Unix(fd) => {
                if let Some(handle) = fd.upgrade() {
                    handle.with_entry(|entry| unregister(entry));
                }
            }
            EpollDescriptor::Netlink(fd) => {
                if let Some(handle) = fd.upgrade() {
                    handle.with_entry(|entry| unregister(entry));
                }
            }
            EpollDescriptor::Inotify(fd) => {
                if let Some(handle) = fd.upgrade() {
                    handle.with_entry(|entry| unregister(entry));
                }
            }
        }
    }
}

pub(crate) struct EpollFile<Platform: ShimPlatform, FS: ShimFS> {
    interests: litebox::sync::Mutex<
        Platform,
        BTreeMap<EpollEntryKey, alloc::sync::Arc<EpollEntry<Platform, FS>>>,
    >,
    ready: Arc<ReadySet<Platform, FS>>,
    status: core::sync::atomic::AtomicU32,
}

impl<Platform: ShimPlatform, FS: ShimFS> EpollFile<Platform, FS> {
    pub(crate) fn new() -> Self {
        EpollFile {
            interests: litebox::sync::Mutex::new(BTreeMap::new()),
            ready: Arc::new(ReadySet::new()),
            status: core::sync::atomic::AtomicU32::new(0),
        }
    }

    pub(crate) fn wait(
        &self,
        global: &GlobalState<Platform, FS>,
        cx: &WaitContext<'_, Platform>,
        maxevents: usize,
    ) -> Result<Vec<EpollEvent>, WaitError> {
        let mut events = Vec::new();
        match self.ready.pollee.wait(cx, false, Events::IN, || {
            self.ready.pop_multiple(global, maxevents, &mut events);
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

    pub(crate) fn epoll_ctl(
        &self,
        global: &GlobalState<Platform, FS>,
        self_fd: &Arc<TypedFd<EpollSubsystem<Platform, FS>>>,
        op: EpollOp,
        fd: u32,
        file: &EpollDescriptor<Platform, FS>,
        event: Option<EpollEvent>,
    ) -> Result<(), Errno> {
        match op {
            EpollOp::EpollCtlAdd => self.add_interest(global, self_fd, fd, file, event.unwrap()),
            EpollOp::EpollCtlMod => {
                self.mod_interest(global, fd, file, event.ok_or(Errno::EINVAL)?)
            }
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
        global: &GlobalState<Platform, FS>,
        self_fd: &Arc<TypedFd<EpollSubsystem<Platform, FS>>>,
        fd: u32,
        file: &EpollDescriptor<Platform, FS>,
        event: EpollEvent,
    ) -> Result<(), Errno> {
        // A cycle can only be formed by nesting one epoll inside another, so only that case needs
        // the global lock; a plain fd add can't create one and stays as cheap as before. The guard
        // is held across both the cycle check and the insert below -- see `EPOLL_NEST_LOCK` for why
        // splitting those into separate critical sections would reopen the race this closes.
        let _nest_guard = matches!(file, EpollDescriptor::Epoll(_)).then(|| EPOLL_NEST_LOCK.lock());
        if let Some(inner_handle) = file.epoll_handle() {
            let self_handle = global
                .litebox
                .descriptor_table()
                .entry_handle(self_fd)
                .ok_or(Errno::EBADF)?;
            if self_handle.identity() == inner_handle.identity() {
                return Err(Errno::EINVAL);
            }
            if Self::nested_epoll_reaches(&self_handle, &inner_handle, 1)? {
                return Err(Errno::ELOOP);
            }
        }

        let mut interests = self.interests.lock();
        let key = EpollEntryKey::new(fd, file);
        if let Some(entry) = interests.get(&key)
            && entry.desc.is_alive()
        {
            return Err(Errno::EEXIST);
        }
        // we may have stale entry because we don't remove it immediately after the file is closed;
        // `insert` below will replace it with a new entry.

        let mask = Events::from_bits_truncate(event.events);
        let entry = EpollEntry::new(
            file.clone(),
            mask,
            EpollFlags::from_bits_truncate(event.events),
            event.data,
            self.ready.clone(),
        );
        let events = file
            .poll(global, mask, Some(entry.weak_self.clone() as _))
            .ok_or(Errno::EBADF)?;
        // Add the new entry to the ready list if the file is ready
        if !events.is_empty() {
            self.ready.push(&entry);
        }
        interests.insert(key, entry);
        Ok(())
    }

    /// Returns whether `self_fd` is reachable by following already-registered nested-epoll
    /// interests starting at `fd`, i.e. whether accepting `fd` as a new interest of `self_fd`
    /// would close a cycle.
    ///
    /// Must be called with `EPOLL_NEST_LOCK` held. Under that lock, every edge in the existing
    /// nested-epoll graph got there by passing this same check, so the graph is acyclic by
    /// induction going in -- the walk below can therefore only ever revisit `self_fd` itself
    /// (caught up front by open-file-description identity, before `self_fd`'s own entry is ever
    /// locked), never an intermediate node, so it can't re-lock an entry it is already holding on
    /// this call stack. Depth is also capped, mirroring real Linux's nesting limit, so a long
    /// acyclic chain can't blow the stack either.
    fn nested_epoll_reaches(
        self_fd: &EntryHandle<Platform, EpollSubsystem<Platform, FS>>,
        fd: &EntryHandle<Platform, EpollSubsystem<Platform, FS>>,
        depth: u32,
    ) -> Result<bool, Errno> {
        const MAX_NESTED_EPOLL_DEPTH: u32 = 5;
        if self_fd.identity() == fd.identity() {
            return Ok(true);
        }
        if depth > MAX_NESTED_EPOLL_DEPTH {
            return Err(Errno::ELOOP);
        }
        fd.with_entry(|entry: &Self| {
            for nested in entry.interests.lock().values() {
                if let Some(inner_fd) = nested.desc.epoll_handle()
                    && Self::nested_epoll_reaches(self_fd, &inner_fd, depth + 1)?
                {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    fn mod_interest(
        &self,
        global: &GlobalState<Platform, FS>,
        fd: u32,
        file: &EpollDescriptor<Platform, FS>,
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
        if !entry.desc.is_alive() {
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
        if let Some(events) = file.poll(global, mask, Some(observer as _)) {
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

impl<Platform: ShimPlatform, FS: ShimFS> IOPollable for EpollFile<Platform, FS> {
    fn check_io_events(&self) -> Events {
        if self.ready.entries.lock().is_empty() {
            Events::empty()
        } else {
            Events::IN
        }
    }

    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.ready.pollee.register_observer(observer, mask);
    }

    fn unregister_observer(&self, observer: Weak<dyn Observer<Events>>) {
        self.ready.pollee.unregister_observer(observer);
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct EpollEntryKey(u32, EntryIdentity);
impl EpollEntryKey {
    fn new<Platform: ShimPlatform, FS: ShimFS>(
        fd: u32,
        desc: &EpollDescriptor<Platform, FS>,
    ) -> Self {
        Self(fd, desc.identity())
    }
}

struct EpollEntry<Platform: ShimPlatform, FS: ShimFS> {
    desc: EpollDescriptor<Platform, FS>,
    inner: litebox::sync::Mutex<Platform, EpollEntryInner>,
    ready: Arc<ReadySet<Platform, FS>>,
    is_ready: AtomicBool,
    is_enabled: AtomicBool,
    weak_self: Weak<Self>,
}

struct EpollEntryInner {
    mask: Events,
    flags: EpollFlags,
    data: u64,
}

impl<Platform: ShimPlatform, FS: ShimFS> EpollEntry<Platform, FS> {
    fn new(
        desc: EpollDescriptor<Platform, FS>,
        mask: Events,
        flags: EpollFlags,
        data: u64,
        ready: Arc<ReadySet<Platform, FS>>,
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

    fn poll(&self, global: &GlobalState<Platform, FS>) -> Option<(Option<EpollEvent>, bool)> {
        let inner = self.inner.lock();

        if !self.is_enabled.load(core::sync::atomic::Ordering::Relaxed) {
            // the entry is disabled
            return None;
        }

        let events = self.desc.poll(global, inner.mask, None)?;
        if events.is_empty() {
            Some((None, false))
        } else {
            let event = Some(EpollEvent::new(events.bits(), inner.data));

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

impl<Platform: ShimPlatform, FS: ShimFS> Observer<Events> for EpollEntry<Platform, FS> {
    fn on_events(&self, _events: &Events) {
        self.ready.push(self);
    }
}

struct ReadySet<Platform: ShimPlatform, FS: ShimFS> {
    entries: litebox::sync::Mutex<Platform, VecDeque<alloc::sync::Weak<EpollEntry<Platform, FS>>>>,
    pollee: Pollee<Platform>,
}

impl<Platform: ShimPlatform, FS: ShimFS> ReadySet<Platform, FS> {
    fn new() -> Self {
        Self {
            entries: litebox::sync::Mutex::new(VecDeque::new()),
            pollee: Pollee::new(),
        }
    }

    fn push(&self, entry: &EpollEntry<Platform, FS>) {
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
        global: &GlobalState<Platform, FS>,
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

            let Some((event, is_still_ready)) = entry.poll(global) else {
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
pub(crate) struct PollSet<Platform: ShimPlatform> {
    entries: Vec<PollEntry<Platform>>,
}

struct PollEntry<Platform: ShimPlatform> {
    fd: i32,
    mask: Events,
    revents: Events,
    observer: Option<Arc<PollEntryObserver<Platform>>>,
}

struct PollEntryObserver<Platform: ShimPlatform>(Waker<Platform>);

enum PollRegistrationTarget<Platform: ShimPlatform, FS: ShimFS> {
    Descriptor(EpollDescriptor<Platform, FS>),
    InputDevice(usize),
    Stdin,
}

impl<Platform: ShimPlatform, FS: ShimFS> PollRegistrationTarget<Platform, FS> {
    fn unregister(self, global: &GlobalState<Platform, FS>, observer: Weak<dyn Observer<Events>>) {
        match self {
            Self::Descriptor(descriptor) => descriptor.unregister_observer(global, observer),
            Self::InputDevice(minor) => {
                if let Some(registry) = global.input_registry.as_ref() {
                    registry.unregister_observer(minor, observer);
                }
            }
            Self::Stdin => {
                if let Some(pollable) = global.platform.stdin_pollable() {
                    pollable.unregister_observer(observer);
                }
            }
        }
    }
}

struct PollRegistration<Platform: ShimPlatform, FS: ShimFS> {
    target: PollRegistrationTarget<Platform, FS>,
    observer: Weak<dyn Observer<Events>>,
}

impl<Platform: ShimPlatform> Clone for PollEntryObserver<Platform> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Platform: ShimPlatform> PollSet<Platform> {
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
        global: &GlobalState<Platform, FS>,
        files: &FilesState<Platform, FS>,
        waker: Option<&Waker<Platform>>,
        registrations: &mut Vec<PollRegistration<Platform, FS>>,
    ) -> bool {
        let mut is_ready = false;
        for entry in &mut self.entries {
            entry.revents = if entry.fd < 0 {
                continue;
            } else if let Ok(poll_descriptor) = EpollDescriptor::try_from(
                global,
                files,
                entry.fd.reinterpret_as_unsigned() as usize,
            ) {
                let observer: Option<Weak<dyn Observer<Events>>> =
                    if !is_ready && let Some(waker) = waker {
                        // A separate allocation is necessary here because registering an observer
                        // twice with two different event masks results in the last one replacing
                        // the first. If registration instead combines masks, this can become one
                        // observer shared by all entries.
                        let observer = Arc::new(PollEntryObserver(waker.clone()));
                        let weak = Arc::downgrade(&observer);
                        entry.observer = Some(observer);
                        Some(weak)
                    } else {
                        // The poll set is already ready, or this scan is only checking readiness.
                        None
                    };
                let registration_target = observer
                    .as_ref()
                    .map(|_| poll_descriptor.transient_registration_target(global));
                // poll(2) on a regular file or directory is always ready -- Linux's
                // `DEFAULT_POLLMASK` (IN | OUT | RDNORM | WRNORM) for any node without its own
                // `poll` op. Every other FS-backed node keeps its subsystem readiness: stdin's
                // pump, `/dev/input/event*` queues, and the OUT-only approximation for the rest,
                // so a queue-backed device never spins on empty reads. BusyBox's `read` builtin
                // polls its fd before every byte, so an FS-backed file that never reported IN
                // hung `read x < file` (and every `while read` loop over a file) forever.
                let always_ready_file = matches!(poll_descriptor, EpollDescriptor::File(_))
                    && files
                        .run_on_raw_fd(
                            entry.fd.reinterpret_as_unsigned() as usize,
                            |fd| {
                                files.fs.fd_file_status(fd).is_ok_and(|status| {
                                    matches!(
                                        status.file_type,
                                        litebox::fs::FileType::RegularFile
                                            | litebox::fs::FileType::Directory
                                    )
                                })
                            },
                            |_| false,
                            |_| false,
                            |_| false,
                            |_| false,
                            |_| false,
                            |_| false,
                        )
                        .unwrap_or(false);
                let events = if always_ready_file {
                    (Events::IN | Events::OUT) & entry.mask
                } else {
                    poll_descriptor
                        .poll(global, entry.mask, observer.clone())
                        .unwrap_or(Events::NVAL)
                };
                if let (Some(observer), Some(target)) = (observer, registration_target) {
                    registrations.push(PollRegistration { target, observer });
                }
                events
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
    pub fn scan<FS: ShimFS>(
        &mut self,
        global: &GlobalState<Platform, FS>,
        files: &FilesState<Platform, FS>,
    ) {
        let mut registrations = Vec::new();
        self.scan_once(global, files, None, &mut registrations);
        debug_assert!(registrations.is_empty());
    }

    /// Waits for any of the fds in the poll set to become ready.
    pub fn wait<FS: ShimFS>(
        &mut self,
        global: &GlobalState<Platform, FS>,
        cx: &WaitContext<'_, Platform>,
        files: &FilesState<Platform, FS>,
    ) -> Result<(), WaitError> {
        let mut registrations = Vec::new();
        if self.scan_once(global, files, None, &mut registrations) {
            return Ok(());
        }

        let mut register = true;
        let result = cx.wait_until(|| {
            if self.scan_once(
                global,
                files,
                register.then_some(cx.waker()),
                &mut registrations,
            ) {
                return true;
            }
            // Don't register observers again in the next iteration.
            register = false;
            false
        });

        // Every registration above belongs only to this wait. Remove it on readiness, timeout, or
        // interruption before dropping the strong observers, leaving permanent epoll interests
        // untouched.
        for registration in registrations.drain(..) {
            registration
                .target
                .unregister(global, registration.observer);
        }
        for entry in &mut self.entries {
            entry.observer = None;
        }
        result
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

impl<Platform: ShimPlatform> Observer<Events> for PollEntryObserver<Platform> {
    fn on_events(&self, _events: &Events) {
        self.0.wake();
    }
}

#[cfg(test)]
mod test {
    use crate::syscalls::tests::TestPlatform;
    use alloc::sync::Arc;
    use litebox::event::Events;
    use litebox::event::wait::WaitState;
    use litebox::fd::TypedFd;
    use litebox_common_linux::EpollEvent;
    use litebox_common_linux::errno::Errno;

    use super::{EpollFile, EpollSubsystem};
    use crate::syscalls::file::FilesState;

    extern crate std;

    fn platform() -> &'static TestPlatform {
        crate::syscalls::tests::test_platform(None)
    }

    type TestEpollFd = Arc<TypedFd<EpollSubsystem<TestPlatform, crate::DefaultFS<TestPlatform>>>>;

    fn new_epoll_fd(
        task: &crate::Task<TestPlatform, crate::DefaultFS<TestPlatform>>,
    ) -> TestEpollFd {
        Arc::new(
            task.global
                .litebox
                .descriptor_table_mut()
                .insert::<EpollSubsystem<TestPlatform, crate::DefaultFS<TestPlatform>>>(
                    EpollFile::new(),
                ),
        )
    }

    fn setup_epoll() -> (
        crate::Task<TestPlatform, crate::DefaultFS<TestPlatform>>,
        TestEpollFd,
    ) {
        let task = crate::syscalls::tests::init_platform(None);
        let epoll_fd = new_epoll_fd(&task);
        (task, epoll_fd)
    }

    #[test]
    fn test_epoll_with_pipe() {
        let (task, epoll_fd) = setup_epoll();
        let (producer, consumer) = task
            .global
            .pipes
            .create_pipe(2, litebox::pipes::Flags::empty(), None)
            .unwrap();
        let consumer = Arc::new(consumer);
        let reader = super::EpollDescriptor::Pipe(
            task.global
                .litebox
                .descriptor_table()
                .entry_handle(&consumer)
                .unwrap()
                .downgrade(),
        );
        let handle = task
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&epoll_fd)
            .unwrap();
        handle
            .with_entry(|epoll| {
                epoll.add_interest(
                    &task.global,
                    &epoll_fd,
                    10,
                    &reader,
                    EpollEvent::new(Events::IN.bits(), 0),
                )
            })
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
        handle
            .with_entry(|epoll| {
                epoll.wait(&task.global, &WaitState::new(platform()).context(), 1024)
            })
            .unwrap();
        let mut buf = [0; 2];
        task.global
            .pipes
            .read(&WaitState::new(platform()).context(), &consumer, &mut buf)
            .unwrap();
        assert_eq!(buf, [1, 2]);
    }

    #[test]
    fn test_epoll_ctl_mod_updates_registered_fd_instead_of_failing() {
        // Regression: `EPOLL_CTL_MOD` used to return `EINVAL` unconditionally.
        // libuv's `uv__io_poll` registers a watcher with `ADD`, and on the
        // `EEXIST` that a re-add returns it issues `MOD` to swap the event
        // mask; the stray `EINVAL` there made libuv `abort()` (guest SIGABRT),
        // which stalled every Node `http` loopback connection. `MOD` on a
        // registered fd must succeed; `MOD` on an unregistered fd is `ENOENT`,
        // never `EINVAL`.
        use litebox_common_linux::EpollOp;
        let (task, epoll_fd) = setup_epoll();
        let (_producer, consumer) = task
            .global
            .pipes
            .create_pipe(2, litebox::pipes::Flags::empty(), None)
            .unwrap();
        let consumer = Arc::new(consumer);
        let reader = super::EpollDescriptor::Pipe(
            task.global
                .litebox
                .descriptor_table()
                .entry_handle(&consumer)
                .unwrap()
                .downgrade(),
        );
        let handle = task
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&epoll_fd)
            .unwrap();

        // MOD before the fd is registered: not present, so ENOENT (not EINVAL).
        let before_add = handle.with_entry(|epoll| {
            epoll.epoll_ctl(
                &task.global,
                &epoll_fd,
                EpollOp::EpollCtlMod,
                10,
                &reader,
                Some(EpollEvent::new(Events::OUT.bits(), 0)),
            )
        });
        assert_eq!(before_add, Err(Errno::ENOENT));

        // ADD, then MOD to a fresh mask: the MOD must succeed.
        handle
            .with_entry(|epoll| {
                epoll.epoll_ctl(
                    &task.global,
                    &epoll_fd,
                    EpollOp::EpollCtlAdd,
                    10,
                    &reader,
                    Some(EpollEvent::new(Events::IN.bits(), 0)),
                )
            })
            .unwrap();
        handle
            .with_entry(|epoll| {
                epoll.epoll_ctl(
                    &task.global,
                    &epoll_fd,
                    EpollOp::EpollCtlMod,
                    10,
                    &reader,
                    Some(EpollEvent::new(Events::OUT.bits(), 5)),
                )
            })
            .expect("MOD on a registered fd must succeed, not return EINVAL");
    }

    #[test]
    fn test_epoll_nested() {
        let task = crate::syscalls::tests::init_platform(None);

        let inner_fd = new_epoll_fd(&task);
        let (producer, consumer) = task
            .global
            .pipes
            .create_pipe(2, litebox::pipes::Flags::empty(), None)
            .unwrap();
        let consumer = Arc::new(consumer);
        let reader = super::EpollDescriptor::Pipe(
            task.global
                .litebox
                .descriptor_table()
                .entry_handle(&consumer)
                .unwrap()
                .downgrade(),
        );
        let inner_handle = task
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&inner_fd)
            .unwrap();
        inner_handle
            .with_entry(|inner| {
                inner.add_interest(
                    &task.global,
                    &inner_fd,
                    20,
                    &reader,
                    EpollEvent::new(Events::IN.bits(), 0),
                )
            })
            .unwrap();

        let outer_fd = new_epoll_fd(&task);
        let nested = super::EpollDescriptor::Epoll(
            task.global
                .litebox
                .descriptor_table()
                .entry_handle(&inner_fd)
                .unwrap()
                .downgrade(),
        );
        let outer_handle = task
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&outer_fd)
            .unwrap();
        outer_handle
            .with_entry(|outer| {
                outer.add_interest(
                    &task.global,
                    &outer_fd,
                    10,
                    &nested,
                    EpollEvent::new(Events::IN.bits(), 42),
                )
            })
            .unwrap();

        // Writing to the pipe should make the inner epoll ready, which in turn should make the
        // outer epoll (which has the inner epoll nested inside it) ready.
        task.global
            .pipes
            .write(&WaitState::new(platform()).context(), &producer, &[1, 2])
            .unwrap();

        let events = outer_handle
            .with_entry(|outer| {
                outer.wait(&task.global, &WaitState::new(platform()).context(), 1024)
            })
            .unwrap();
        assert_eq!(events.len(), 1);
        let data = events[0].data;
        assert_eq!(data, 42);
    }

    #[test]
    fn test_epoll_nested_cycle_rejected() {
        let task = crate::syscalls::tests::init_platform(None);

        let a_fd = new_epoll_fd(&task);
        let b_fd = new_epoll_fd(&task);

        let a_handle = task
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&a_fd)
            .unwrap();
        a_handle
            .with_entry(|a| {
                a.add_interest(
                    &task.global,
                    &a_fd,
                    20,
                    &super::EpollDescriptor::Epoll(
                        task.global
                            .litebox
                            .descriptor_table()
                            .entry_handle(&b_fd)
                            .unwrap()
                            .downgrade(),
                    ),
                    EpollEvent::new(Events::IN.bits(), 0),
                )
            })
            .unwrap();

        // B adding A back would close a 2-fd cycle; this must be rejected synchronously with
        // ELOOP rather than being allowed to form (which would only surface as a hang later,
        // on the first event delivered into the cycle).
        let b_handle = task
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&b_fd)
            .unwrap();
        let result = b_handle.with_entry(|b| {
            b.add_interest(
                &task.global,
                &b_fd,
                10,
                &super::EpollDescriptor::Epoll(
                    task.global
                        .litebox
                        .descriptor_table()
                        .entry_handle(&a_fd)
                        .unwrap()
                        .downgrade(),
                ),
                EpollEvent::new(Events::IN.bits(), 0),
            )
        });
        assert_eq!(result, Err(Errno::ELOOP));
    }

    /// Reproduces, under real concurrency, the exact race a prior cycle-detection attempt
    /// missed: thread 1 adds B into A while thread 2 concurrently adds A into B. Checking for a
    /// cycle and committing the new edge are two different critical sections unless a single
    /// process-wide lock spans both, so each thread's check can run before the other's insert is
    /// visible -- both threads see an acyclic graph, both commit, and together they still close
    /// the cycle. Since A adding B and B adding A are reciprocal, the only two correct outcomes
    /// per iteration are "exactly one add wins, the other gets ELOOP" -- never both winning
    /// (that would be the cycle itself), never both losing, and never neither thread returning at
    /// all. A `Barrier` lines both threads up right before their `add_interest` call to maximize
    /// the chance of hitting the race, and `recv_timeout` bounds each attempt so a regression
    /// that reintroduces the deadlock fails this test quickly instead of hanging the run.
    #[test]
    fn test_epoll_nested_concurrent_add_never_forms_cycle() {
        let task = crate::syscalls::tests::init_platform(None);
        let global = task.global.clone();

        for iteration in 0..30u32 {
            let a_fd = new_epoll_fd(&task);
            let b_fd = new_epoll_fd(&task);
            let barrier = Arc::new(std::sync::Barrier::new(2));

            let (tx_a, rx_a) = std::sync::mpsc::channel();
            let g = global.clone();
            let (a, b) = (Arc::clone(&a_fd), Arc::clone(&b_fd));
            let bar = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let handle = g.litebox.descriptor_table().entry_handle(&a).unwrap();
                bar.wait();
                let result = handle.with_entry(|entry| {
                    entry.add_interest(
                        &g,
                        &a,
                        1000 + iteration,
                        &super::EpollDescriptor::Epoll(
                            g.litebox
                                .descriptor_table()
                                .entry_handle(&b)
                                .unwrap()
                                .downgrade(),
                        ),
                        EpollEvent::new(Events::IN.bits(), 0),
                    )
                });
                let _ = tx_a.send(result);
            });

            let (tx_b, rx_b) = std::sync::mpsc::channel();
            let g = global.clone();
            let (a, b) = (Arc::clone(&a_fd), Arc::clone(&b_fd));
            let bar = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let handle = g.litebox.descriptor_table().entry_handle(&b).unwrap();
                bar.wait();
                let result = handle.with_entry(|entry| {
                    entry.add_interest(
                        &g,
                        &b,
                        2000 + iteration,
                        &super::EpollDescriptor::Epoll(
                            g.litebox
                                .descriptor_table()
                                .entry_handle(&a)
                                .unwrap()
                                .downgrade(),
                        ),
                        EpollEvent::new(Events::IN.bits(), 0),
                    )
                });
                let _ = tx_b.send(result);
            });

            let timeout = core::time::Duration::from_secs(5);
            let Ok(result_a) = rx_a.recv_timeout(timeout) else {
                panic!(
                    "iteration {iteration}: thread adding B into A never returned -- \
                     a cycle likely formed and something is stuck on it"
                );
            };
            let Ok(result_b) = rx_b.recv_timeout(timeout) else {
                panic!(
                    "iteration {iteration}: thread adding A into B never returned -- \
                     a cycle likely formed and something is stuck on it"
                );
            };

            match (result_a, result_b) {
                (Ok(()), Err(Errno::ELOOP)) | (Err(Errno::ELOOP), Ok(())) => {}
                other => panic!(
                    "iteration {iteration}: expected exactly one add to win and the other to be \
                     rejected with ELOOP, got {other:?} instead"
                ),
            }
        }
    }

    #[test]
    fn test_poll() {
        let task = crate::syscalls::tests::init_platform(None);

        let mut set = super::PollSet::with_capacity(0);
        let (rfd_u, wfd_u) = task
            .sys_pipe2(litebox::fs::OFlags::empty())
            .expect("pipe2 failed");
        let rfd = i32::try_from(rfd_u).unwrap();
        let wfd = i32::try_from(wfd_u).unwrap();
        let no_fds = FilesState::new(task.files.borrow().fs.clone());
        let fds = task.files.borrow().clone();
        set.add_fd(rfd, Events::IN);

        let revents = |set: &super::PollSet<TestPlatform>| {
            let revents: std::vec::Vec<_> = set.revents().collect();
            assert_eq!(revents.len(), 1);
            revents[0]
        };

        set.wait(&task.global, &WaitState::new(platform()).context(), &no_fds)
            .unwrap();
        assert_eq!(revents(&set), Events::NVAL);

        task.sys_write(wfd, &[1], None).unwrap();
        set.wait(&task.global, &WaitState::new(platform()).context(), &fds)
            .unwrap();
        assert_eq!(revents(&set), Events::IN);

        let mut buf = [0; 1];
        assert_eq!(task.sys_read(rfd, &mut buf, None).unwrap(), 1);
        assert_eq!(buf, [1]);
        set.wait(
            &task.global,
            &WaitState::new(platform())
                .context()
                .with_timeout(core::time::Duration::from_millis(100)),
            &fds,
        )
        .unwrap_err();
        assert!(revents(&set).is_empty());

        task.spawn_clone_for_test(move |task| {
            std::thread::sleep(core::time::Duration::from_millis(100));
            assert_eq!(task.sys_write(wfd, &[1], None).unwrap(), 1);
        });

        set.wait(&task.global, &WaitState::new(platform()).context(), &fds)
            .unwrap();
        assert_eq!(revents(&set), Events::IN);

        let _ = task.sys_close(rfd);
        let _ = task.sys_close(wfd);
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
                Some(core::time::Duration::from_mins(1)),
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
