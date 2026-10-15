// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! epoll instances (`epoll_create(2)`) backed by LiteBox readiness queues.

use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use litebox::{
    event::{
        Events, IOPollable,
        observer::Observer,
        polling::TryOpError,
        readiness_queue::{
            ReadinessInterest, ReadinessQueue, ReadinessQueueError, ReadinessTarget,
        },
        wait::{WaitContext, WaitError, Waker},
    },
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd},
    process::ProcessError,
    utils::ReinterpretUnsignedExt,
};
use litebox_broker_protocol::{
    ObjectHandle,
    readiness_queue::{MAX_READINESS_QUEUE_EVENTS, ReadinessQueueEntryFlags},
};
use litebox_common_linux::{EpollEvent, EpollOp, OFlags, errno::Errno};

use super::file::{FilesState, linux_status_flags, status_flags_change};
use crate::{GlobalState, ShimPlatform};

pub(crate) struct EpollSubsystem<Platform: ShimPlatform>(core::marker::PhantomData<Platform>);
impl<Platform: ShimPlatform> FdEnabledSubsystem for EpollSubsystem<Platform> {
    type Entry = EpollFile<Platform>;
}
impl<Platform: ShimPlatform> FdEnabledSubsystemEntry for EpollFile<Platform> {}

bitflags::bitflags! {
    /// Linux's epoll flags.
    #[derive(Clone, Copy, Debug)]
    struct EpollFlags: u32 {
        const EXCLUSIVE      = (1 << 28);
        const WAKE_UP        = (1 << 29);
        const ONE_SHOT       = (1 << 30);
        const EDGE_TRIGGER   = (1 << 31);
    }
}

pub(crate) enum EpollDescriptor<Platform: ShimPlatform> {
    Eventfd(Arc<TypedFd<super::eventfd::EventfdSubsystem<Platform>>>),
    Epoll(Arc<TypedFd<super::epoll::EpollSubsystem<Platform>>>),
    File(Arc<crate::FileFd>),
    Socket(Arc<super::net::SocketFd<Platform>>),
    Pipe(Arc<litebox::pipes::PipeFd<Platform>>),
    Unix(Arc<TypedFd<crate::syscalls::unix::UnixSocketSubsystem<Platform>>>),
    Timerfd(Arc<TypedFd<super::timerfd::TimerfdSubsystem<Platform>>>),
}

impl<Platform: ShimPlatform> EpollDescriptor<Platform> {
    pub fn try_from(files: &FilesState<Platform>, raw_fd: usize) -> Result<Self, Errno> {
        let rds = files.raw_descriptor_store.read();
        if let Ok(fd) = rds.fd_from_raw_integer::<litebox::fs::BrokerFile>(raw_fd) {
            return Ok(EpollDescriptor::File(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<crate::Network<Platform>>(raw_fd) {
            return Ok(EpollDescriptor::Socket(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<litebox::pipes::Pipes<Platform>>(raw_fd) {
            return Ok(EpollDescriptor::Pipe(fd));
        }
        if let Ok(fd) =
            rds.fd_from_raw_integer::<super::eventfd::EventfdSubsystem<Platform>>(raw_fd)
        {
            return Ok(EpollDescriptor::Eventfd(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<EpollSubsystem<Platform>>(raw_fd) {
            return Ok(EpollDescriptor::Epoll(fd));
        }
        if let Ok(fd) =
            rds.fd_from_raw_integer::<super::unix::UnixSocketSubsystem<Platform>>(raw_fd)
        {
            return Ok(EpollDescriptor::Unix(fd));
        }
        if let Ok(fd) =
            rds.fd_from_raw_integer::<super::timerfd::TimerfdSubsystem<Platform>>(raw_fd)
        {
            return Ok(EpollDescriptor::Timerfd(fd));
        }
        Err(Errno::EBADF)
    }

    /// Returns the interesting events now and monitors their occurrence in the future if the
    /// observer is provided.
    ///
    /// Returns `None` if the descriptor has been closed.
    fn poll(
        &self,
        global: &GlobalState<Platform>,
        mask: Events,
        observer: Option<Weak<dyn Observer<Events>>>,
    ) -> Option<Events> {
        let poll = |iop: &dyn IOPollable| {
            if let Some(observer) = observer {
                iop.register_observer(observer, mask);
            }
            iop.check_io_events() & (mask | Events::ALWAYS_POLLED)
        };
        // Like in-flight operations, polling releases the table lock before using (and dropping)
        // its entry handle, so it never finalizes an entry under the lock.
        macro_rules! poll_entry {
            ($fd:expr) => {{
                let handle = global.litebox.descriptor_table().entry_handle($fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }};
        }
        match self {
            EpollDescriptor::Eventfd(fd) => poll_entry!(fd),
            EpollDescriptor::Epoll(fd) => poll_entry!(fd),
            EpollDescriptor::File(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|file| poll(&global.litebox.broker_file_pollable(file))))
            }
            EpollDescriptor::Socket(fd) => {
                let proxy = global
                    .litebox
                    .descriptor_table()
                    .with_metadata(fd, |super::net::SocketProxy::<Platform>(proxy)| {
                        proxy.clone()
                    })
                    .ok()?;
                Some(poll(&proxy))
            }
            EpollDescriptor::Pipe(fd) => poll_entry!(fd),
            EpollDescriptor::Unix(fd) => poll_entry!(fd),
            EpollDescriptor::Timerfd(fd) => poll_entry!(fd),
        }
    }

    /// Runs `f` on the object this descriptor refers to, as a readiness queue target.
    ///
    /// Fails with `EPERM` for an epoll descriptor: epoll instances cannot be nested.
    fn with_target<R>(
        &self,
        global: &GlobalState<Platform>,
        f: impl FnOnce(&ReadinessTarget<'_, Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        match self {
            EpollDescriptor::File(fd) => f(&ReadinessTarget::File(fd)),
            EpollDescriptor::Pipe(fd) => f(&ReadinessTarget::Pipe(fd)),
            EpollDescriptor::Eventfd(fd) => {
                global.with_eventfd(fd, |file| f(&ReadinessTarget::EventCounter(file.counter())))
            }
            EpollDescriptor::Timerfd(fd) => {
                global.with_timerfd(fd, |file| f(&ReadinessTarget::Timer(file.timer())))
            }
            EpollDescriptor::Unix(fd) => global.with_unix_socket(fd, |socket| {
                f(&ReadinessTarget::UnixSocket(socket.unix_socket()))
            }),
            EpollDescriptor::Socket(fd) => {
                let proxy = global
                    .litebox
                    .descriptor_table()
                    .with_metadata(fd, |super::net::SocketProxy::<Platform>(proxy)| {
                        proxy.clone()
                    })
                    .map_err(|_| Errno::EBADF)?;
                f(&ReadinessTarget::NetworkSocket(&proxy))
            }
            EpollDescriptor::Epoll(_) => Err(Errno::EPERM),
        }
    }
}

/// An epoll instance, whose interest list and status flags its readiness queue owns, so
/// processes that share it through `fork` share one interest list.
///
/// Interests are keyed by their target's open file description and the descriptor number they
/// were added under, like Linux. Unlike Linux, epoll instances cannot be nested, `EPOLLPRI` is
/// never reported, `EPOLLWAKEUP` is ignored, and `EPOLLEXCLUSIVE` only affects argument
/// validation.
pub(crate) struct EpollFile<Platform: ShimPlatform> {
    queue: Arc<ReadinessQueue<Platform>>,
}

impl<Platform: ShimPlatform> EpollFile<Platform> {
    pub(crate) fn new(global: &GlobalState<Platform>) -> Result<Self, Errno> {
        // Exhaustion means ENOSPC only for epoll_ctl's watch limit.
        let queue = ReadinessQueue::new(&global.litebox).map_err(|error| match error {
            ReadinessQueueError::ResourceExhausted => Errno::ENOMEM,
            error => error.into(),
        })?;
        Ok(Self {
            queue: Arc::new(queue),
        })
    }

    pub(crate) fn queue(&self) -> &Arc<ReadinessQueue<Platform>> {
        &self.queue
    }

    /// Takes up to `maxevents` ready events, waiting for one if there are none.
    ///
    /// Returns no events if `cx` times out.
    pub(crate) fn wait(
        &self,
        cx: &WaitContext<'_, Platform>,
        maxevents: usize,
    ) -> Result<Vec<EpollEvent>, Errno> {
        // Allocate up front, since waiting consumes the events it takes.
        let mut events = Vec::new();
        events
            .try_reserve_exact(maxevents.min(MAX_READINESS_QUEUE_EVENTS as usize))
            .map_err(|_| Errno::ENOMEM)?;
        match self.queue.wait(cx, maxevents) {
            Ok(entries) => {
                events.extend(
                    entries
                        .into_iter()
                        .map(|entry| EpollEvent::new(entry.events.bits(), entry.token)),
                );
                Ok(events)
            }
            Err(TryOpError::WaitError(WaitError::TimedOut)) => Ok(Vec::new()),
            Err(TryOpError::WaitError(WaitError::Interrupted)) => Err(Errno::EINTR),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn epoll_ctl(
        &self,
        global: &GlobalState<Platform>,
        op: EpollOp,
        fd: u32,
        file: &EpollDescriptor<Platform>,
        event: Option<EpollEvent>,
    ) -> Result<(), Errno> {
        let key = u64::from(fd);
        match op {
            EpollOp::EpollCtlAdd => {
                let interest = readiness_interest(op, event.unwrap())?;
                file.with_target(global, |target| {
                    Ok(self.queue.add(&global.litebox, target, key, interest)?)
                })
            }
            EpollOp::EpollCtlMod => {
                let interest = readiness_interest(op, event.unwrap())?;
                file.with_target(global, |target| {
                    Ok(self.queue.modify(&global.litebox, target, key, interest)?)
                })
            }
            EpollOp::EpollCtlDel => file.with_target(global, |target| {
                Ok(self.queue.remove(&global.litebox, target, key)?)
            }),
        }
    }

    /// Returns the access mode and status flags of the epoll instance.
    pub(crate) fn get_status_flags(&self) -> Result<OFlags, Errno> {
        linux_status_flags(self.queue.get_status_flags()?)
    }

    /// Changes the status flags in `mask` of the epoll instance to their values in `flags`,
    /// ignoring flags other than `O_NONBLOCK` and `O_APPEND`.
    pub(crate) fn set_status_flags(&self, mask: OFlags, flags: OFlags) -> Result<(), Errno> {
        let (mask, flags) = status_flags_change(mask, flags);
        self.queue.set_status_flags(mask, flags)?;
        Ok(())
    }
}

/// Converts the event of an `EPOLL_CTL_ADD` or `EPOLL_CTL_MOD` into a readiness queue interest.
fn readiness_interest(op: EpollOp, event: EpollEvent) -> Result<ReadinessInterest, Errno> {
    let flags = EpollFlags::from_bits_retain(event.events);
    if flags.contains(EpollFlags::EXCLUSIVE) {
        // Like Linux, `EPOLLEXCLUSIVE` is allowed only when adding, and only together with
        // `EPOLLIN`, `EPOLLOUT`, `EPOLLERR`, `EPOLLHUP`, `EPOLLWAKEUP`, and `EPOLLET`.
        let allowed = (Events::IN | Events::OUT | Events::ERR | Events::HUP).bits()
            | (EpollFlags::EXCLUSIVE | EpollFlags::WAKE_UP | EpollFlags::EDGE_TRIGGER).bits();
        if op != EpollOp::EpollCtlAdd || event.events & !allowed != 0 {
            return Err(Errno::EINVAL);
        }
    }
    let mut entry_flags = ReadinessQueueEntryFlags::empty();
    if flags.contains(EpollFlags::EDGE_TRIGGER) {
        entry_flags |= ReadinessQueueEntryFlags::EDGE_TRIGGERED;
    }
    if flags.contains(EpollFlags::ONE_SHOT) {
        entry_flags |= ReadinessQueueEntryFlags::ONE_SHOT;
    }
    // Like Linux, errors and hangups are always reported.
    let events = Events::from_bits_truncate(event.events)
        & (Events::IN | Events::OUT | Events::RDHUP)
        | Events::ERR
        | Events::HUP;
    Ok(ReadinessInterest {
        events,
        flags: entry_flags,
        token: event.data,
    })
}

impl<Platform: ShimPlatform> IOPollable for EpollFile<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.queue.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        self.queue.check_io_events()
    }
}

impl<Platform: ShimPlatform> GlobalState<Platform> {
    /// Runs `f` on the epoll instance at `fd`, without holding the descriptor table.
    pub(crate) fn with_epoll<R>(
        &self,
        fd: &TypedFd<EpollSubsystem<Platform>>,
        f: impl FnOnce(&EpollFile<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let handle = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(f)
    }

    /// Adopts an epoll instance this process inherited from its parent as `handle`.
    pub(crate) fn adopt_inherited_epoll(
        &self,
        handle: ObjectHandle,
    ) -> Result<TypedFd<EpollSubsystem<Platform>>, ProcessError> {
        let queue = self.litebox.adopt_inherited_readiness_queue(handle)?;
        Ok(self
            .litebox
            .descriptor_table_mut()
            .insert::<EpollSubsystem<Platform>>(EpollFile {
                queue: Arc::new(queue),
            }))
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

impl<Platform: ShimPlatform> Clone for PollEntryObserver<Platform> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Platform: ShimPlatform> PollSet<Platform> {
    /// Returns a new empty `PollSet` with the given interest capacity.
    pub fn with_capacity(capacity: usize) -> Option<Self> {
        let mut entries = Vec::new();
        entries.try_reserve_exact(capacity).ok()?;
        Some(Self { entries })
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

    fn scan_once(
        &mut self,
        global: &GlobalState<Platform>,
        files: &FilesState<Platform>,
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
                    .poll(global, entry.mask, observer)
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
    pub fn scan(&mut self, global: &GlobalState<Platform>, files: &FilesState<Platform>) {
        self.scan_once(global, files, None);
    }

    /// Waits for any of the fds in the poll set to become ready.
    pub fn wait(
        &mut self,
        global: &GlobalState<Platform>,
        cx: &WaitContext<'_, Platform>,
        files: &FilesState<Platform>,
    ) -> Result<(), WaitError> {
        if self.scan_once(global, files, None) {
            return Ok(());
        }

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
    use crate::{Task, UserPtr, UserPtrMut};
    use litebox::event::Events;
    use litebox::event::wait::WaitState;
    use litebox_common_linux::{EpollCreateFlags, EpollEvent, EpollOp, OFlags, errno::Errno};

    use crate::syscalls::file::FilesState;

    extern crate std;

    fn platform() -> &'static TestPlatform {
        crate::syscalls::tests::test_platform()
    }

    fn epoll_create(task: &Task<TestPlatform>) -> i32 {
        i32::try_from(task.sys_epoll_create(EpollCreateFlags::empty()).unwrap()).unwrap()
    }

    fn epoll_ctl(
        task: &Task<TestPlatform>,
        epfd: i32,
        op: EpollOp,
        fd: i32,
        events: u32,
    ) -> Result<(), Errno> {
        let event = EpollEvent::new(events, u64::try_from(fd).unwrap());
        task.sys_epoll_ctl(epfd, op, fd, UserPtr::from_usize(&raw const event as usize))
    }

    /// Returns the `(data, events)` of each event an `epoll_wait` with `timeout` reports.
    fn epoll_wait(task: &Task<TestPlatform>, epfd: i32, timeout: i32) -> std::vec::Vec<(u64, u32)> {
        let mut events = [EpollEvent::new(0, 0); 4];
        let ready = task
            .sys_epoll_pwait(
                epfd,
                UserPtrMut::from_usize(events.as_mut_ptr() as usize),
                4,
                timeout,
                None,
                0,
            )
            .unwrap();
        events[..ready]
            .iter()
            .map(|event| (event.data, event.events))
            .collect()
    }

    #[test]
    fn test_epoll_with_pipe() {
        let task = crate::syscalls::tests::init_platform();
        let epfd = epoll_create(&task);
        let (rfd, wfd) = task.sys_pipe2(OFlags::empty()).unwrap();
        let rfd = i32::try_from(rfd).unwrap();
        let wfd = i32::try_from(wfd).unwrap();
        epoll_ctl(&task, epfd, EpollOp::EpollCtlAdd, rfd, Events::IN.bits()).unwrap();
        assert_eq!(epoll_wait(&task, epfd, 0), []);

        let writer = task.spawn_clone_for_test(move |task| {
            std::thread::sleep(core::time::Duration::from_millis(100));
            assert_eq!(task.sys_write(wfd, &[1, 2], None).unwrap(), 2);
        });
        assert_eq!(
            epoll_wait(&task, epfd, -1),
            [(u64::try_from(rfd).unwrap(), Events::IN.bits())]
        );
        let mut buf = [0; 2];
        assert_eq!(task.sys_read(rfd, &mut buf, None).unwrap(), 2);
        assert_eq!(buf, [1, 2]);
        writer.join().unwrap();
        assert_eq!(epoll_wait(&task, epfd, 0), []);

        // Closing the write end hangs up the read end, which is always reported.
        task.sys_close(wfd).unwrap();
        assert_eq!(
            epoll_wait(&task, epfd, 0),
            [(u64::try_from(rfd).unwrap(), Events::HUP.bits())]
        );
    }

    #[test]
    fn test_poll() {
        let task = crate::syscalls::tests::init_platform();

        let mut set = super::PollSet::with_capacity(0).unwrap();
        let (rfd_u, wfd_u) = task
            .sys_pipe2(litebox_common_linux::OFlags::empty())
            .expect("pipe2 failed");
        let rfd = i32::try_from(rfd_u).unwrap();
        let wfd = i32::try_from(wfd_u).unwrap();
        let no_fds = FilesState::new();
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

        let writer = task.spawn_clone_for_test(move |task| {
            std::thread::sleep(core::time::Duration::from_millis(100));
            assert_eq!(task.sys_write(wfd, &[1], None).unwrap(), 1);
        });

        set.wait(&task.global, &WaitState::new(platform()).context(), &fds)
            .unwrap();
        assert_eq!(revents(&set), Events::IN);

        let _ = task.sys_close(rfd);
        let _ = task.sys_close(wfd);
        writer.join().unwrap();
    }

    #[test]
    fn test_pselect() {
        let task = crate::syscalls::tests::init_platform();

        let (rfd_u, wfd_u) = task
            .sys_pipe2(litebox_common_linux::OFlags::empty())
            .expect("pipe2 failed");
        let rfd = i32::try_from(rfd_u).unwrap();
        let wfd = i32::try_from(wfd_u).unwrap();

        let writer = task.spawn_clone_for_test(move |task| {
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
        writer.join().unwrap();
    }

    #[test]
    fn test_pselect_read_hup() {
        let task = crate::syscalls::tests::init_platform();

        let (rfd_u, wfd_u) = task
            .sys_pipe2(litebox_common_linux::OFlags::empty())
            .expect("pipe2 failed");
        let rfd = i32::try_from(rfd_u).unwrap();
        let wfd = i32::try_from(wfd_u).unwrap();

        let closer = task.spawn_clone_for_test(move |task| {
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
        closer.join().unwrap();
    }

    #[test]
    fn test_pselect_invalid_fd() {
        let task = crate::syscalls::tests::init_platform();

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
