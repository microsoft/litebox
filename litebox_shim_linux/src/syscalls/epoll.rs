use core::{sync::atomic::AtomicBool, time::Duration};

use alloc::{
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    sync::{Arc, Weak},
    vec::Vec,
};
use litebox::{
    LiteBox,
    event::{Events, IOPollable, observer::Observer, polling::Pollee},
    platform::{Instant as _, RawMutex as _, RawMutexProvider as _, TimeProvider as _},
    utils::ReinterpretUnsignedExt,
};
use litebox_common_linux::{EpollEvent, EpollOp, errno::Errno};
use litebox_platform_multiplex::Platform;

use super::file::FilesState;
use crate::{Descriptor, StrongFd};

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

pub(crate) enum EpollDescriptor {
    Eventfd(Arc<super::eventfd::EventFile<Platform>>),
    Epoll(Arc<super::epoll::EpollFile>),
    File(Arc<crate::FileFd>),
    Socket(Arc<super::net::SocketFd>),
    Pipe(Arc<litebox::pipes::PipeFd<Platform>>),
}

impl EpollDescriptor {
    pub fn try_from(files: &FilesState, desc: &Descriptor) -> Result<Self, Errno> {
        match desc {
            Descriptor::LiteBoxRawFd(raw_fd) => match StrongFd::from_raw(files, *raw_fd)? {
                StrongFd::FileSystem(fd) => Ok(EpollDescriptor::File(fd)),
                StrongFd::Network(fd) => Ok(EpollDescriptor::Socket(fd)),
                StrongFd::Pipes(fd) => Ok(EpollDescriptor::Pipe(fd)),
            },
            Descriptor::Eventfd { file, .. } => Ok(EpollDescriptor::Eventfd(file.clone())),
            Descriptor::Epoll { file, .. } => Ok(EpollDescriptor::Epoll(file.clone())),
        }
    }
}

enum DescriptorRef {
    Eventfd(Weak<crate::syscalls::eventfd::EventFile<litebox_platform_multiplex::Platform>>),
    Epoll(Weak<super::epoll::EpollFile>),
    File(Weak<crate::FileFd>),
    Socket(Weak<super::net::SocketFd>),
    Pipe(Weak<litebox::pipes::PipeFd<Platform>>),
}

impl DescriptorRef {
    fn from(value: &EpollDescriptor) -> Self {
        match value {
            EpollDescriptor::Eventfd(file) => Self::Eventfd(Arc::downgrade(file)),
            EpollDescriptor::Epoll(file) => Self::Epoll(Arc::downgrade(file)),
            EpollDescriptor::File(file) => Self::File(Arc::downgrade(file)),
            EpollDescriptor::Socket(socket) => Self::Socket(Arc::downgrade(socket)),
            EpollDescriptor::Pipe(pipe) => Self::Pipe(Arc::downgrade(pipe)),
        }
    }

    fn upgrade(&self) -> Option<EpollDescriptor> {
        match self {
            DescriptorRef::Eventfd(eventfd) => eventfd.upgrade().map(EpollDescriptor::Eventfd),
            DescriptorRef::Epoll(epoll) => epoll.upgrade().map(EpollDescriptor::Epoll),
            DescriptorRef::File(file) => file.upgrade().map(EpollDescriptor::File),
            DescriptorRef::Socket(socket) => socket.upgrade().map(EpollDescriptor::Socket),
            DescriptorRef::Pipe(pipe) => pipe.upgrade().map(EpollDescriptor::Pipe),
        }
    }
}

impl EpollDescriptor {
    /// Returns the interesting events now and monitors their occurrence in the future if the
    /// observer is provided.
    fn poll(&self, mask: Events, observer: Option<Weak<dyn Observer<Events>>>) -> Option<Events> {
        let poll = |iop: &dyn IOPollable| {
            if let Some(observer) = observer {
                iop.register_observer(observer, mask);
            }
            iop.check_io_events() & (mask | Events::ALWAYS_POLLED)
        };
        let io_pollable: &dyn IOPollable = match self {
            EpollDescriptor::Eventfd(file) => file,
            EpollDescriptor::Epoll(_file) => unimplemented!(),
            EpollDescriptor::File(_file) => {
                // TODO: probably polling on stdio files, return dummy events for now
                return Some(Events::OUT & mask);
            }
            EpollDescriptor::Socket(fd) => {
                return crate::litebox_net().lock().with_iopollable(fd, poll);
            }
            EpollDescriptor::Pipe(fd) => {
                return crate::litebox_pipes().read().with_iopollable(fd, poll).ok();
            }
        };
        Some(poll(io_pollable))
    }
}

pub(crate) struct EpollFile {
    interests: litebox::sync::Mutex<
        litebox_platform_multiplex::Platform,
        BTreeMap<EpollEntryKey, alloc::sync::Arc<EpollEntry>>,
    >,
    ready: Arc<ReadySet>,
    status: core::sync::atomic::AtomicU32,
}

impl EpollFile {
    pub(crate) fn new(litebox: &LiteBox<Platform>) -> Self {
        EpollFile {
            interests: litebox.sync().new_mutex(BTreeMap::new()),
            ready: Arc::new(ReadySet::new(litebox)),
            status: core::sync::atomic::AtomicU32::new(0),
        }
    }

    pub(crate) fn wait(
        &self,
        maxevents: usize,
        timeout: Option<Duration>,
    ) -> Result<Vec<EpollEvent>, Errno> {
        let mut events = Vec::new();
        match self.ready.pollee.wait_or_timeout(
            timeout,
            || {
                self.ready.pop_multiple(maxevents, &mut events);
                if events.is_empty() {
                    return Err(litebox::event::polling::TryOpError::<Errno>::TryAgain);
                }
                Ok(())
            },
            || self.ready.check_io_events().contains(Events::IN),
        ) {
            Ok(()) | Err(litebox::event::polling::TryOpError::TimedOut) => {}
            Err(e) => return Err(e.into()),
        }
        Ok(events)
    }

    pub(crate) fn epoll_ctl(
        &self,
        op: EpollOp,
        fd: u32,
        file: &EpollDescriptor,
        event: Option<EpollEvent>,
    ) -> Result<(), Errno> {
        match op {
            EpollOp::EpollCtlAdd => self.add_interest(fd, file, event.unwrap()),
            EpollOp::EpollCtlMod => {
                log_unsupported!("epoll_ctl mod");
                Err(Errno::EINVAL)
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
        fd: u32,
        file: &EpollDescriptor,
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
            .poll(mask, Some(entry.weak_self.clone() as _))
            .ok_or(Errno::EBADF)?;
        // Add the new entry to the ready list if the file is ready
        if !events.is_empty() {
            self.ready.push(&entry);
        }
        interests.insert(key, entry);
        Ok(())
    }

    #[expect(dead_code, reason = "currently unused, but might want to use soon")]
    fn mod_interest(
        &self,
        fd: u32,
        file: &EpollDescriptor,
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
        if let Some(events) = file.poll(mask, Some(observer as _)) {
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
    fn new(fd: u32, desc: &EpollDescriptor) -> Self {
        let ptr = match desc {
            EpollDescriptor::Eventfd(file) => Arc::as_ptr(file).addr(),
            EpollDescriptor::Epoll(file) => Arc::as_ptr(file).addr(),
            EpollDescriptor::File(file) => Arc::as_ptr(file).addr(),
            EpollDescriptor::Socket(socket_fd) => Arc::as_ptr(socket_fd).addr(),
            EpollDescriptor::Pipe(pipe_fd) => Arc::as_ptr(pipe_fd).addr(),
        };
        Self(fd, ptr)
    }
}

struct EpollEntry {
    desc: DescriptorRef,
    inner: litebox::sync::Mutex<litebox_platform_multiplex::Platform, EpollEntryInner>,
    ready: Arc<ReadySet>,
    is_ready: AtomicBool,
    is_enabled: AtomicBool,
    weak_self: Weak<Self>,
}

struct EpollEntryInner {
    mask: Events,
    flags: EpollFlags,
    data: u64,
}

impl EpollEntry {
    fn new(
        desc: DescriptorRef,
        mask: Events,
        flags: EpollFlags,
        data: u64,
        ready: Arc<ReadySet>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|weak_self| EpollEntry {
            desc,
            inner: crate::litebox()
                .sync()
                .new_mutex(EpollEntryInner { mask, flags, data }),
            ready,
            is_ready: AtomicBool::new(false),
            is_enabled: AtomicBool::new(true),
            weak_self: weak_self.clone(),
        })
    }

    fn poll(&self) -> Option<(Option<EpollEvent>, bool)> {
        let file = self.desc.upgrade()?;
        let inner = self.inner.lock();

        if !self.is_enabled.load(core::sync::atomic::Ordering::Relaxed) {
            // the entry is disabled
            return None;
        }

        let events = file.poll(inner.mask, None)?;
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

impl Observer<Events> for EpollEntry {
    fn on_events(&self, _events: &Events) {
        self.ready.push(self);
    }
}

struct ReadySet {
    entries: litebox::sync::Mutex<
        litebox_platform_multiplex::Platform,
        VecDeque<alloc::sync::Weak<EpollEntry>>,
    >,
    pollee: Pollee<Platform>,
}

impl ReadySet {
    fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            entries: litebox.sync().new_mutex(VecDeque::new()),
            pollee: Pollee::new(litebox),
        }
    }

    fn push(&self, entry: &EpollEntry) {
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

    fn pop_multiple(&self, maxevents: usize, events: &mut Vec<EpollEvent>) {
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

            let Some((event, is_still_ready)) = entry.poll() else {
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

    fn check_io_events(&self) -> Events {
        if self.entries.lock().is_empty() {
            Events::empty()
        } else {
            Events::IN
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

struct PollEntryObserver(Arc<<Platform as litebox::platform::RawMutexProvider>::RawMutex>);

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

    /// Waits for any of the fds in the poll set to become ready, or until the
    /// timeout expires.
    pub fn wait_or_timeout(&mut self, files: &FilesState, timeout: Option<Duration>) {
        let platform = litebox_platform_multiplex::platform();
        let condvar = Arc::new(platform.new_raw_mutex());

        let start_time = platform.now();
        let mut register = true;
        let mut is_ready = timeout.is_some_and(|t| t.is_zero());
        loop {
            let fds = files.file_descriptors.read();
            for entry in &mut self.entries {
                entry.revents = if entry.fd < 0 {
                    continue;
                } else if let Some(file) = fds.get_fd(entry.fd.reinterpret_as_unsigned())
                    && let Ok(poll_descriptor) = EpollDescriptor::try_from(files, file)
                {
                    let observer = if is_ready || !register {
                        // The poll set is already ready, or we have already
                        // registered the observer for this entry.
                        None
                    } else {
                        // TODO: a separate allocation is necessary here
                        // because registering an observer twice with two
                        // different event masks results in the last one
                        // replacing the first. If this is changed to
                        // instead OR the new registration into the existing
                        // one, then we can use a single observer for all
                        // entries.
                        let observer = Arc::new(PollEntryObserver(condvar.clone()));
                        let weak = Arc::downgrade(&observer);
                        entry.observer = Some(observer);
                        Some(weak as _)
                    };
                    // TODO: add machinery to unregister the observer to avoid leaks.
                    poll_descriptor
                        .poll(entry.mask, observer)
                        .unwrap_or(Events::NVAL)
                } else {
                    Events::NVAL
                };
                if !entry.revents.is_empty() {
                    is_ready = true;
                    register = false;
                }
            }
            drop(fds);

            if is_ready {
                break;
            }

            // Don't register observers again in the next iteration.
            register = false;

            let remaining_time =
                timeout.map(|t| t.saturating_sub(platform.now().duration_since(&start_time)));
            if let Some(remaining_time) = remaining_time {
                if matches!(
                    condvar.block_or_timeout(0, remaining_time),
                    Ok(litebox::platform::UnblockedOrTimedOut::TimedOut),
                ) {
                    // Timed out. Loop around once more to check if any fds are
                    // ready, to match Linux behavior.
                    is_ready = true;
                }
            } else {
                let Ok(()) = condvar.block(0) else {
                    unreachable!()
                };
            }
            condvar
                .underlying_atomic()
                .store(0, core::sync::atomic::Ordering::Relaxed);
        }
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
        self.0
            .underlying_atomic()
            .store(1, core::sync::atomic::Ordering::Release);
        self.0.wake_one();
    }
}

#[cfg(test)]
mod test {
    use alloc::sync::Arc;
    use litebox::event::Events;
    use litebox::utils::ReinterpretUnsignedExt as _;
    use litebox_common_linux::{EfdFlags, EpollEvent};

    use super::EpollFile;
    use crate::syscalls::file::FilesState;
    use core::time::Duration;

    extern crate std;

    fn setup_epoll() -> EpollFile {
        let _task = crate::syscalls::tests::init_platform(None);

        EpollFile::new(crate::litebox())
    }

    #[test]
    fn test_epoll_with_eventfd() {
        let epoll = setup_epoll();
        let eventfd = Arc::new(crate::syscalls::eventfd::EventFile::new(
            0,
            EfdFlags::CLOEXEC,
            crate::litebox(),
        ));
        epoll
            .add_interest(
                10,
                &super::EpollDescriptor::Eventfd(eventfd.clone()),
                EpollEvent {
                    events: Events::IN.bits(),
                    data: 0,
                },
            )
            .unwrap();

        // spawn a thread to write to the eventfd
        let copied_eventfd = eventfd.clone();
        std::thread::spawn(move || {
            copied_eventfd.write(1).unwrap();
        });
        epoll.wait(1024, None).unwrap();
    }

    #[test]
    fn test_epoll_with_pipe() {
        let epoll = setup_epoll();
        let pipes = crate::litebox_pipes().read();
        let (producer, consumer) = pipes.create_pipe(2, litebox::pipes::Flags::empty(), None);
        let consumer = Arc::new(consumer);
        let reader = super::EpollDescriptor::Pipe(Arc::clone(&consumer));
        epoll
            .add_interest(
                10,
                &reader,
                EpollEvent {
                    events: Events::IN.bits(),
                    data: 0,
                },
            )
            .unwrap();

        // spawn a thread to write to the pipe
        std::thread::spawn(move || {
            std::thread::sleep(core::time::Duration::from_millis(100));
            assert_eq!(
                crate::litebox_pipes()
                    .read()
                    .write(&producer, &[1, 2])
                    .unwrap(),
                2
            );
        });
        epoll.wait(1024, None).unwrap();
        let mut buf = [0; 2];
        crate::litebox_pipes()
            .read()
            .read(&consumer, &mut buf)
            .unwrap();
        assert_eq!(buf, [1, 2]);
    }

    #[test]
    fn test_poll() {
        let _task = crate::syscalls::tests::init_platform(None);

        let mut set = super::PollSet::with_capacity(0);
        let eventfd = Arc::new(crate::syscalls::eventfd::EventFile::new(
            0,
            EfdFlags::empty(),
            crate::litebox(),
        ));

        let fd = 10i32;
        let descriptor = crate::Descriptor::Eventfd {
            file: eventfd.clone(),
            close_on_exec: core::sync::atomic::AtomicBool::new(false),
        };

        let no_fds = FilesState::new(crate::litebox());
        let fds = FilesState::new(crate::litebox());
        fds.file_descriptors
            .write()
            .insert_at(descriptor, fd.reinterpret_as_unsigned() as usize);
        set.add_fd(fd, Events::IN);

        let revents = |set: &super::PollSet| {
            let revents: std::vec::Vec<_> = set.revents().collect();
            assert_eq!(revents.len(), 1);
            revents[0]
        };

        set.wait_or_timeout(&no_fds, None);
        assert_eq!(revents(&set), Events::NVAL);

        eventfd.write(1).unwrap();
        set.wait_or_timeout(&fds, None);
        assert_eq!(revents(&set), Events::IN);

        eventfd.read().unwrap();
        set.wait_or_timeout(&fds, Some(Duration::from_millis(100)));
        assert!(revents(&set).is_empty());

        // spawn a thread to write to the eventfd
        let copied_eventfd = eventfd.clone();
        std::thread::spawn(move || {
            copied_eventfd.write(1).unwrap();
        });

        set.wait_or_timeout(&fds, None);
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
