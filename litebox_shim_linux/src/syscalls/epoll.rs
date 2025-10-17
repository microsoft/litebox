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

use crate::Descriptor;

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

enum DescriptorRef {
    PipeReader(Weak<litebox::pipes::ReadEnd<Platform, u8>>),
    PipeWriter(Weak<litebox::pipes::WriteEnd<Platform, u8>>),
    Eventfd(Weak<crate::syscalls::eventfd::EventFile<litebox_platform_multiplex::Platform>>),
    Socket(Weak<crate::syscalls::net::Socket>),
}

impl DescriptorRef {
    fn from(value: &Descriptor) -> Self {
        match value {
            Descriptor::PipeReader { consumer, .. } => {
                DescriptorRef::PipeReader(Arc::downgrade(consumer))
            }
            Descriptor::PipeWriter { producer, .. } => {
                DescriptorRef::PipeWriter(Arc::downgrade(producer))
            }
            Descriptor::Eventfd { file, .. } => DescriptorRef::Eventfd(Arc::downgrade(file)),
            Descriptor::Socket(socket) => DescriptorRef::Socket(Arc::downgrade(socket)),
            _ => todo!(),
        }
    }

    fn upgrade(&self) -> Option<Descriptor> {
        match self {
            DescriptorRef::PipeReader(pipe) => {
                pipe.upgrade().map(|consumer| Descriptor::PipeReader {
                    consumer,
                    close_on_exec: AtomicBool::new(false),
                })
            }
            DescriptorRef::PipeWriter(pipe) => {
                pipe.upgrade().map(|producer| Descriptor::PipeWriter {
                    producer,
                    close_on_exec: AtomicBool::new(false),
                })
            }
            DescriptorRef::Eventfd(eventfd) => eventfd.upgrade().map(|file| Descriptor::Eventfd {
                file,
                close_on_exec: AtomicBool::new(false),
            }),
            DescriptorRef::Socket(socket) => socket.upgrade().map(Descriptor::Socket),
            _ => todo!(),
        }
    }
}

impl Descriptor {
    /// Returns the interesting events now and monitors their occurrence in the future if the
    /// observer is provided.
    fn poll(&self, mask: Events, observer: Option<Weak<dyn Observer<Events>>>) -> Events {
        let io_pollable: &dyn IOPollable = match self {
            Descriptor::PipeReader { consumer, .. } => consumer,
            Descriptor::PipeWriter { producer, .. } => producer,
            Descriptor::Eventfd { file, .. } => file,
            Descriptor::Socket(socket) => socket,
            Descriptor::LiteBoxRawFd(fd) => return Events::OUT & mask, // TODO: handle properly
            Descriptor::Epoll { file, .. } => todo!(),
        };
        if let Some(observer) = observer {
            io_pollable.register_observer(observer, mask);
        }
        io_pollable.check_io_events() & (mask | Events::ALWAYS_POLLED)
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
        file: &Descriptor,
        event: Option<EpollEvent>,
    ) -> Result<(), Errno> {
        match op {
            EpollOp::EpollCtlAdd => self.add_interest(fd, file, event.unwrap()),
            EpollOp::EpollCtlMod => todo!(),
            EpollOp::EpollCtlDel => {
                let mut interests = self.interests.lock();
                let _ = interests
                    .remove(&EpollEntryKey::new(fd, file))
                    .ok_or(Errno::ENOENT)?;
                Ok(())
            }
        }
    }

    fn add_interest(&self, fd: u32, file: &Descriptor, event: EpollEvent) -> Result<(), Errno> {
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
        let events = file.poll(mask, Some(entry.weak_self.clone() as _));
        // Add the new entry to the ready list if the file is ready
        if !events.is_empty() {
            self.ready.push(&entry);
        }
        interests.insert(key, entry);
        Ok(())
    }

    fn mod_interest(&self, fd: u32, file: &Descriptor, event: EpollEvent) -> Result<(), Errno> {
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

        // re-register the observer with the new mask
        let events = file.poll(mask, Some(entry.weak_self.clone() as _));
        if !events.is_empty() {
            // Add the updated entry to the ready list if the file is ready
            self.ready.push(entry);
        }

        Ok(())
    }

    super::common_functions_for_file_status!();
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct EpollEntryKey(u32, *const ());
impl EpollEntryKey {
    fn new(fd: u32, desc: &Descriptor) -> Self {
        let ptr = match desc {
            Descriptor::LiteBoxRawFd(raw_fd) => *raw_fd as _,
            Descriptor::PipeReader { consumer, .. } => Arc::as_ptr(consumer).cast(),
            Descriptor::PipeWriter { producer, .. } => Arc::as_ptr(producer).cast(),
            Descriptor::Eventfd { file, .. } => Arc::as_ptr(file).cast(),
            Descriptor::Socket(socket) => Arc::as_ptr(socket).cast(),
            Descriptor::Epoll { .. } => todo!(),
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

        let events = file.poll(inner.mask, None);
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
    fn on_events(&self, events: &Events) {
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

        let mut entries = self.entries.lock();
        if !entry
            .is_ready
            .swap(true, core::sync::atomic::Ordering::Relaxed)
        {
            entries.push_back(entry.weak_self.clone());
        }
        drop(entries);

        self.pollee.notify_observers(Events::IN);
    }

    fn pop_multiple(&self, maxevents: usize, events: &mut Vec<EpollEvent>) {
        let mut entries = self.entries.lock();
        let mut nums = entries.len();
        while nums > 0 {
            nums -= 1;
            if events.len() >= maxevents {
                break;
            }

            let Some(weak_entry) = entries.pop_front() else {
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
                entry
                    .is_ready
                    .store(true, core::sync::atomic::Ordering::Relaxed);
                entries.push_back(weak_entry);
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

/// Trait for testing `PollSet`.
pub(crate) trait GetFd {
    fn get_fd(&self, n: i32) -> Option<&Descriptor>;
}

impl GetFd for litebox::sync::RwLockReadGuard<'_, Platform, crate::Descriptors> {
    fn get_fd(&self, n: i32) -> Option<&Descriptor> {
        (**self).get_fd(n.reinterpret_as_unsigned())
    }
}

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
    pub fn wait_or_timeout<T: GetFd>(
        &mut self,
        mut lock_fds: impl FnMut() -> T,
        timeout: Option<Duration>,
    ) {
        let platform = litebox_platform_multiplex::platform();
        let condvar = Arc::new(platform.new_raw_mutex());

        let start_time = platform.now();
        let mut register = true;
        let mut is_ready = timeout.is_some_and(|t| t.is_zero());
        loop {
            let mut fds = lock_fds();
            for entry in &mut self.entries {
                entry.revents = if entry.fd < 0 {
                    continue;
                } else if let Some(file) = fds.get_fd(entry.fd) {
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
                    file.poll(entry.mask, observer)
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
                condvar.block(0);
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
    fn on_events(&self, events: &Events) {
        self.0
            .underlying_atomic()
            .store(1, core::sync::atomic::Ordering::Release);
        self.0.wake_one();
    }
}

#[cfg(test)]
mod test {
    use alloc::sync::Arc;
    use litebox::{event::Events, fs::OFlags};
    use litebox_common_linux::{EfdFlags, EpollEvent};

    use crate::syscalls::file::{do_pselect, sys_close, sys_pipe2, sys_read};

    use super::EpollFile;
    use core::time::Duration;

    extern crate std;

    fn setup_epoll() -> EpollFile {
        crate::syscalls::tests::init_platform(None);

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
                &crate::Descriptor::Eventfd {
                    file: eventfd.clone(),
                    close_on_exec: core::sync::atomic::AtomicBool::new(false),
                },
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
        let (producer, consumer) =
            litebox::pipes::new_pipe::<_, u8>(crate::litebox(), 2, OFlags::empty(), None);
        let reader = crate::Descriptor::PipeReader {
            consumer,
            close_on_exec: core::sync::atomic::AtomicBool::new(false),
        };
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
            assert_eq!(producer.write(&[1, 2]).unwrap(), 2);
        });
        epoll.wait(1024, None).unwrap();
        let mut buf = [0; 2];
        let crate::Descriptor::PipeReader { consumer, .. } = reader else {
            unreachable!();
        };
        consumer.read(&mut buf).unwrap();
        assert_eq!(buf, [1, 2]);
    }

    #[test]
    fn test_poll() {
        #[derive(Copy, Clone)]
        struct Fds<'a>(i32, Option<&'a crate::Descriptor>);

        impl super::GetFd for Fds<'_> {
            fn get_fd(&self, n: i32) -> Option<&crate::Descriptor> {
                if n == self.0 { self.1 } else { None }
            }
        }

        struct FdsOnce<'a>(core::cell::Cell<Option<i32>>, Option<&'a crate::Descriptor>);

        impl super::GetFd for &FdsOnce<'_> {
            fn get_fd(&self, n: i32) -> Option<&crate::Descriptor> {
                if Some(n) == self.0.get() {
                    self.0.set(None);
                    self.1
                } else {
                    None
                }
            }
        }

        crate::syscalls::tests::init_platform(None);

        let mut set = super::PollSet::with_capacity(0);
        let eventfd = Arc::new(crate::syscalls::eventfd::EventFile::new(
            0,
            EfdFlags::empty(),
            crate::litebox(),
        ));

        let fd = 10;
        let descriptor = crate::Descriptor::Eventfd {
            file: eventfd.clone(),
            close_on_exec: core::sync::atomic::AtomicBool::new(false),
        };

        let no_fds = Fds(-1, None);
        let fds = Fds(fd, Some(&descriptor));
        set.add_fd(fd, Events::IN);

        let revents = |set: &super::PollSet| {
            let revents: std::vec::Vec<_> = set.revents().collect();
            assert_eq!(revents.len(), 1);
            revents[0]
        };

        set.wait_or_timeout(|| no_fds, None);
        assert_eq!(revents(&set), Events::NVAL);

        eventfd.write(1).unwrap();
        set.wait_or_timeout(|| fds, None);
        assert_eq!(revents(&set), Events::IN);

        eventfd.read().unwrap();
        set.wait_or_timeout(|| fds, Some(Duration::from_millis(100)));
        assert!(revents(&set).is_empty());

        let once = FdsOnce(Some(fd).into(), Some(&descriptor));
        set.wait_or_timeout(|| &once, Some(Duration::from_millis(100)));
        assert_eq!(revents(&set), Events::NVAL);

        // spawn a thread to write to the eventfd
        let copied_eventfd = eventfd.clone();
        std::thread::spawn(move || {
            copied_eventfd.write(1).unwrap();
        });

        set.wait_or_timeout(|| fds, None);
        assert_eq!(revents(&set), Events::IN);
    }

    #[test]
    fn test_pselect() {
        crate::syscalls::tests::init_platform(None);

        let (rfd_u, wfd_u) = sys_pipe2(litebox::fs::OFlags::empty()).expect("pipe2 failed");
        let rfd = i32::try_from(rfd_u).unwrap();
        let wfd = i32::try_from(wfd_u).unwrap();

        std::thread::spawn(move || {
            std::thread::sleep(core::time::Duration::from_millis(100));
            // write a byte
            let buf = [0x41u8];
            let written = super::super::file::sys_write(wfd, &buf, None).expect("write failed");
            assert_eq!(written, 1);
        });

        // prepare fd_set for read
        let mut rfds = litebox_common_linux::FdSet::default();
        rfds.clear();
        rfds.set(rfd_u);

        // Call pselect
        let ret = do_pselect(rfd_u + 1, Some(&mut rfds), None, None, None).expect("pselect failed");
        assert!(ret > 0, "pselect should report ready");
        assert!(rfds.iter().all(|fd| fd == rfd_u));

        // read
        let mut out = [0u8; 8];
        let n = sys_read(rfd, &mut out, None).expect("read failed");
        assert_eq!(n, 1);
        assert_eq!(out[0], 0x41);

        let _ = sys_close(rfd);
        let _ = sys_close(wfd);
    }

    #[test]
    fn test_pselect_read_hup() {
        crate::syscalls::tests::init_platform(None);

        let (rfd_u, wfd_u) = sys_pipe2(litebox::fs::OFlags::empty()).expect("pipe2 failed");
        let rfd = i32::try_from(rfd_u).unwrap();
        let wfd = i32::try_from(wfd_u).unwrap();

        std::thread::spawn(move || {
            std::thread::sleep(core::time::Duration::from_millis(100));
            sys_close(wfd).expect("close writer failed");
        });

        // prepare fd_set for read
        let mut rfds = litebox_common_linux::FdSet::default();
        rfds.clear();
        rfds.set(rfd_u);

        let ret = do_pselect(
            rfd_u + 1,
            Some(&mut rfds),
            None,
            None,
            Some(core::time::Duration::from_secs(60)),
        )
        .expect("pselect failed");

        // Expect pselect to indicate readiness (HUP should cause revents)
        assert!(ret > 0, "pselect should report ready for EOF/HUP");
        assert!(rfds.iter().all(|fd| fd == rfd_u));

        // read should return 0 (EOF)
        let mut out = [0u8; 8];
        let n = sys_read(rfd, &mut out, None).expect("read failed");
        assert_eq!(n, 0, "read should return 0 on EOF");

        let _ = sys_close(rfd);
    }
}
