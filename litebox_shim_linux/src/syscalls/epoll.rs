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
        DescriptorObjectId, EntryHandle, FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd,
        WeakEntryHandle,
    },
    fs::OFlags,
    utils::ReinterpretUnsignedExt,
};
use litebox_common_linux::{EpollEvent, EpollOp, errno::Errno};
use litebox_platform_multiplex::Platform;

use super::file::FilesState;
use crate::{GlobalState, ShimFS};

pub(crate) struct EpollSubsystem<FS: ShimFS>(core::marker::PhantomData<FS>);
impl<FS: ShimFS> FdEnabledSubsystem for EpollSubsystem<FS> {
    const KIND: litebox::fd::SubsystemKind = litebox::fd::SubsystemKind::Epoll;

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

const MAX_NESTED_EPOLL_DEPTH: usize = 5;
const MAX_SOCKET_SETTLE_POLLS: usize = 16;

pub(crate) enum EpollDescriptor<FS: ShimFS> {
    Eventfd(Arc<TypedFd<super::eventfd::EventfdSubsystem>>),
    Signalfd(Arc<TypedFd<super::signalfd::SignalfdSubsystem>>),
    Inotify(Arc<TypedFd<super::inotify::InotifySubsystem>>),
    BrokerInetListener(Arc<TypedFd<super::broker_inet_listener::BrokerInetListenerSubsystem>>),
    BrokerInetDgram(Arc<TypedFd<super::broker_inet_dgram::BrokerInetDgramSubsystem>>),
    BrokerInetRaw(Arc<TypedFd<super::broker_inet_raw::BrokerInetRawSubsystem>>),
    Epoll(EntryHandle<Platform, super::epoll::EpollSubsystem<FS>>),
    File(Arc<crate::FileFd<FS>>),
    #[cfg(feature = "worker_local_inet")]
    Socket(Arc<super::net::SocketFd>),
    Unix(Arc<TypedFd<crate::syscalls::unix::UnixSocketSubsystem<FS>>>),
    HostPassthroughFd(Arc<TypedFd<super::host_passthrough_fd::HostPassthroughFd>>),
    BrokerPipe(Arc<TypedFd<super::broker_pipe::BrokerPipeSubsystem>>),
    BrokerPty(Arc<TypedFd<super::broker_pty::BrokerPtySubsystem>>),
    BrokerSocketPair(Arc<TypedFd<super::broker_socketpair::BrokerSocketPairSubsystem>>),
    BrokerTcpConn(Arc<TypedFd<super::broker_tcp_conn::BrokerTcpConnSubsystem>>),
    BrokerUnixStream(Arc<TypedFd<super::broker_unix_stream::BrokerUnixStreamSubsystem>>),
}

impl<FS: ShimFS> EpollDescriptor<FS> {
    #[deny(clippy::wildcard_enum_match_arm)]
    pub fn try_from(
        global: &GlobalState<FS>,
        files: &FilesState<FS>,
        raw_fd: usize,
    ) -> Result<Self, Errno> {
        files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
            crate::RawFdRef::Fs(fd) => Ok(EpollDescriptor::File(Arc::clone(fd))),
            #[cfg(feature = "worker_local_inet")]
            crate::RawFdRef::Net(fd) => Ok(EpollDescriptor::Socket(Arc::clone(fd))),
            crate::RawFdRef::Eventfd(fd) => Ok(EpollDescriptor::Eventfd(Arc::clone(fd))),
            crate::RawFdRef::Epoll(fd) => {
                let handle = global
                    .litebox
                    .descriptor_table()
                    .entry_handle(fd)
                    .ok_or(Errno::EBADF)?;
                Ok(EpollDescriptor::Epoll(handle))
            }
            crate::RawFdRef::Unix(fd) => Ok(EpollDescriptor::Unix(Arc::clone(fd))),
            crate::RawFdRef::HostPassthroughFd(fd) => {
                Ok(EpollDescriptor::HostPassthroughFd(Arc::clone(fd)))
            }
            crate::RawFdRef::BrokerPipe(fd) => Ok(EpollDescriptor::BrokerPipe(Arc::clone(fd))),
            crate::RawFdRef::BrokerSocketPair(fd) => {
                Ok(EpollDescriptor::BrokerSocketPair(Arc::clone(fd)))
            }
            crate::RawFdRef::BrokerTcpConn(fd) => {
                Ok(EpollDescriptor::BrokerTcpConn(Arc::clone(fd)))
            }
            crate::RawFdRef::BrokerPty(fd) => Ok(EpollDescriptor::BrokerPty(Arc::clone(fd))),
            crate::RawFdRef::Signalfd(fd) => Ok(EpollDescriptor::Signalfd(Arc::clone(fd))),
            crate::RawFdRef::Inotify(fd) => Ok(EpollDescriptor::Inotify(Arc::clone(fd))),
            crate::RawFdRef::BrokerInetListener(fd) => {
                Ok(EpollDescriptor::BrokerInetListener(Arc::clone(fd)))
            }
            crate::RawFdRef::BrokerInetDgram(fd) => {
                Ok(EpollDescriptor::BrokerInetDgram(Arc::clone(fd)))
            }
            crate::RawFdRef::BrokerSocketDgram(_) => Err(Errno::EBADF),
            crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::EBADF),
            crate::RawFdRef::BrokerUnixStream(fd) => {
                Ok(EpollDescriptor::BrokerUnixStream(Arc::clone(fd)))
            }
            crate::RawFdRef::BrokerInetRaw(fd) => {
                Ok(EpollDescriptor::BrokerInetRaw(Arc::clone(fd)))
            }
        })?
    }
}

enum DescriptorRef<FS: ShimFS> {
    Eventfd(Weak<TypedFd<super::eventfd::EventfdSubsystem>>),
    Signalfd(Weak<TypedFd<super::signalfd::SignalfdSubsystem>>),
    Inotify(Weak<TypedFd<super::inotify::InotifySubsystem>>),
    BrokerInetListener(Weak<TypedFd<super::broker_inet_listener::BrokerInetListenerSubsystem>>),
    BrokerInetDgram(Weak<TypedFd<super::broker_inet_dgram::BrokerInetDgramSubsystem>>),
    BrokerInetRaw(Weak<TypedFd<super::broker_inet_raw::BrokerInetRawSubsystem>>),
    Epoll(WeakEntryHandle<Platform, super::epoll::EpollSubsystem<FS>>),
    File(Weak<crate::FileFd<FS>>),
    #[cfg(feature = "worker_local_inet")]
    Socket(Weak<super::net::SocketFd>),
    Unix(Weak<TypedFd<crate::syscalls::unix::UnixSocketSubsystem<FS>>>),
    HostPassthroughFd(Weak<TypedFd<super::host_passthrough_fd::HostPassthroughFd>>),
    BrokerPipe(Weak<TypedFd<super::broker_pipe::BrokerPipeSubsystem>>),
    BrokerPty(Weak<TypedFd<super::broker_pty::BrokerPtySubsystem>>),
    BrokerSocketPair(Weak<TypedFd<super::broker_socketpair::BrokerSocketPairSubsystem>>),
    BrokerTcpConn(Weak<TypedFd<super::broker_tcp_conn::BrokerTcpConnSubsystem>>),
    BrokerUnixStream(Weak<TypedFd<super::broker_unix_stream::BrokerUnixStreamSubsystem>>),
}

impl<FS: ShimFS> DescriptorRef<FS> {
    fn from(value: &EpollDescriptor<FS>) -> Self {
        match value {
            EpollDescriptor::Eventfd(file) => Self::Eventfd(Arc::downgrade(file)),
            EpollDescriptor::Signalfd(file) => Self::Signalfd(Arc::downgrade(file)),
            EpollDescriptor::Inotify(file) => Self::Inotify(Arc::downgrade(file)),
            EpollDescriptor::BrokerInetListener(file) => {
                Self::BrokerInetListener(Arc::downgrade(file))
            }
            EpollDescriptor::BrokerInetDgram(file) => Self::BrokerInetDgram(Arc::downgrade(file)),
            EpollDescriptor::BrokerInetRaw(file) => Self::BrokerInetRaw(Arc::downgrade(file)),
            EpollDescriptor::Epoll(file) => Self::Epoll(file.downgrade()),
            EpollDescriptor::File(file) => Self::File(Arc::downgrade(file)),
            #[cfg(feature = "worker_local_inet")]
            EpollDescriptor::Socket(socket) => Self::Socket(Arc::downgrade(socket)),
            EpollDescriptor::Unix(unix) => Self::Unix(Arc::downgrade(unix)),
            EpollDescriptor::HostPassthroughFd(hp) => Self::HostPassthroughFd(Arc::downgrade(hp)),
            EpollDescriptor::BrokerPipe(bp) => Self::BrokerPipe(Arc::downgrade(bp)),
            EpollDescriptor::BrokerPty(pty) => Self::BrokerPty(Arc::downgrade(pty)),
            EpollDescriptor::BrokerSocketPair(sp) => Self::BrokerSocketPair(Arc::downgrade(sp)),
            EpollDescriptor::BrokerTcpConn(tcp) => Self::BrokerTcpConn(Arc::downgrade(tcp)),
            EpollDescriptor::BrokerUnixStream(us) => Self::BrokerUnixStream(Arc::downgrade(us)),
        }
    }

    fn upgrade(&self) -> Option<EpollDescriptor<FS>> {
        match self {
            DescriptorRef::Eventfd(eventfd) => eventfd.upgrade().map(EpollDescriptor::Eventfd),
            DescriptorRef::Signalfd(signalfd) => signalfd.upgrade().map(EpollDescriptor::Signalfd),
            DescriptorRef::Inotify(inotify) => inotify.upgrade().map(EpollDescriptor::Inotify),
            DescriptorRef::BrokerInetListener(listener) => {
                listener.upgrade().map(EpollDescriptor::BrokerInetListener)
            }
            DescriptorRef::BrokerInetDgram(dgram) => {
                dgram.upgrade().map(EpollDescriptor::BrokerInetDgram)
            }
            DescriptorRef::BrokerInetRaw(raw) => raw.upgrade().map(EpollDescriptor::BrokerInetRaw),
            DescriptorRef::Epoll(epoll) => epoll.upgrade().map(EpollDescriptor::Epoll),
            DescriptorRef::File(file) => file.upgrade().map(EpollDescriptor::File),
            #[cfg(feature = "worker_local_inet")]
            DescriptorRef::Socket(socket) => socket.upgrade().map(EpollDescriptor::Socket),
            DescriptorRef::Unix(unix) => unix.upgrade().map(EpollDescriptor::Unix),
            DescriptorRef::HostPassthroughFd(hp) => {
                hp.upgrade().map(EpollDescriptor::HostPassthroughFd)
            }
            DescriptorRef::BrokerPipe(bp) => bp.upgrade().map(EpollDescriptor::BrokerPipe),
            DescriptorRef::BrokerPty(pty) => pty.upgrade().map(EpollDescriptor::BrokerPty),
            DescriptorRef::BrokerSocketPair(sp) => {
                sp.upgrade().map(EpollDescriptor::BrokerSocketPair)
            }
            DescriptorRef::BrokerTcpConn(tcp) => tcp.upgrade().map(EpollDescriptor::BrokerTcpConn),
            DescriptorRef::BrokerUnixStream(us) => {
                us.upgrade().map(EpollDescriptor::BrokerUnixStream)
            }
        }
    }

    fn type_name(&self) -> &'static str {
        match self {
            DescriptorRef::Eventfd(_) => "Eventfd",
            DescriptorRef::Signalfd(_) => "Signalfd",
            DescriptorRef::Inotify(_) => "Inotify",
            DescriptorRef::BrokerInetListener(_) => "BrokerInetListener",
            DescriptorRef::BrokerInetDgram(_) => "BrokerInetDgram",
            DescriptorRef::BrokerInetRaw(_) => "BrokerInetRaw",
            DescriptorRef::Epoll(_) => "Epoll",
            DescriptorRef::File(_) => "File",
            #[cfg(feature = "worker_local_inet")]
            DescriptorRef::Socket(_) => "Socket",
            DescriptorRef::Unix(_) => "Unix",
            DescriptorRef::HostPassthroughFd(_) => "HostPassthroughFd",
            DescriptorRef::BrokerPipe(_) => "BrokerPipe",
            DescriptorRef::BrokerPty(_) => "BrokerPty",
            DescriptorRef::BrokerSocketPair(_) => "BrokerSocketPair",
            DescriptorRef::BrokerTcpConn(_) => "BrokerTcpConn",
            DescriptorRef::BrokerUnixStream(_) => "BrokerUnixStream",
        }
    }

    fn needs_network_drive(&self) -> bool {
        match self {
            #[cfg(feature = "worker_local_inet")]
            DescriptorRef::Socket(socket) => socket.upgrade().is_some(),
            DescriptorRef::BrokerTcpConn(tcp_conn) => tcp_conn.upgrade().is_some(),
            DescriptorRef::BrokerInetDgram(dgram) => dgram.upgrade().is_some(),
            DescriptorRef::Eventfd(_)
            | DescriptorRef::Signalfd(_)
            | DescriptorRef::Inotify(_)
            | DescriptorRef::BrokerInetListener(_)
            | DescriptorRef::BrokerInetRaw(_)
            | DescriptorRef::Epoll(_)
            | DescriptorRef::File(_)
            | DescriptorRef::Unix(_)
            | DescriptorRef::HostPassthroughFd(_)
            | DescriptorRef::BrokerPipe(_)
            | DescriptorRef::BrokerPty(_)
            | DescriptorRef::BrokerSocketPair(_)
            | DescriptorRef::BrokerUnixStream(_) => false,
        }
    }

    fn edge_dedup_mask(&self) -> Events {
        // Broker-held inet sockets re-assert their FULL current readiness on
        // every broker notification (the broker tracks level state, not edges).
        // For an EPOLLET interest the worker-local epoll must therefore compute
        // edges itself across ALL sticky bits — not just OUT. A half-closed TCP
        // conn (sticky RDHUP|IN), an idle readable conn (sticky IN with an
        // unread response), or a writable conn (sticky OUT) otherwise re-fires
        // on every wait and the reactor spins — the VS Code agent-host hang on
        // its update.code.visualstudio.com connections (sticky IN|OUT|RDHUP).
        const BROKER_INET_STICKY: Events = Events::from_bits_truncate(
            Events::IN.bits()
                | Events::PRI.bits()
                | Events::OUT.bits()
                | Events::ERR.bits()
                | Events::HUP.bits()
                | Events::RDHUP.bits(),
        );
        const BROKER_LOCAL_EDGE_TRACKED: Events =
            Events::from_bits_truncate(Events::IN.bits() | Events::OUT.bits());
        match self {
            DescriptorRef::BrokerInetDgram(_)
            | DescriptorRef::BrokerTcpConn(_)
            | DescriptorRef::BrokerInetListener(_)
            | DescriptorRef::BrokerInetRaw(_) => BROKER_INET_STICKY,
            DescriptorRef::Eventfd(_) => BROKER_LOCAL_EDGE_TRACKED,
            DescriptorRef::Signalfd(_)
            | DescriptorRef::Inotify(_)
            | DescriptorRef::Epoll(_)
            | DescriptorRef::File(_)
            | DescriptorRef::HostPassthroughFd(_)
            | DescriptorRef::BrokerPty(_)
            | DescriptorRef::Unix(_) => Events::empty(),
            DescriptorRef::BrokerPipe(_)
            | DescriptorRef::BrokerSocketPair(_)
            | DescriptorRef::BrokerUnixStream(_) => BROKER_LOCAL_EDGE_TRACKED,
            #[cfg(feature = "worker_local_inet")]
            DescriptorRef::Socket(_) => Events::empty(),
        }
    }
}

impl<FS: ShimFS> EpollDescriptor<FS> {
    fn edge_reset_generations(&self, global: &GlobalState<FS>) -> EdgeResetGenerations {
        match self {
            EpollDescriptor::Eventfd(fd) => global
                .litebox
                .descriptor_table()
                .entry_handle(fd)
                .map_or_else(EdgeResetGenerations::default, |handle| {
                    handle.with_entry(|entry| EdgeResetGenerations {
                        read: entry.read_edge_reset_generation(),
                        write: entry.write_edge_reset_generation(),
                    })
                }),
            EpollDescriptor::BrokerTcpConn(fd) => global
                .litebox
                .descriptor_table()
                .entry_handle(fd)
                .map_or_else(EdgeResetGenerations::default, |handle| {
                    handle.with_entry(|entry| EdgeResetGenerations {
                        read: entry.read_edge_reset_generation(),
                        write: entry.write_edge_reset_generation(),
                    })
                }),
            EpollDescriptor::BrokerPipe(fd) => global
                .litebox
                .descriptor_table()
                .entry_handle(fd)
                .map_or_else(EdgeResetGenerations::default, |handle| {
                    handle.with_entry(|entry| EdgeResetGenerations {
                        read: entry.read_edge_reset_generation(),
                        write: entry.write_edge_reset_generation(),
                    })
                }),
            EpollDescriptor::BrokerSocketPair(fd) => global
                .litebox
                .descriptor_table()
                .entry_handle(fd)
                .map_or_else(EdgeResetGenerations::default, |handle| {
                    handle.with_entry(|entry| EdgeResetGenerations {
                        read: entry.read_edge_reset_generation(),
                        write: entry.write_edge_reset_generation(),
                    })
                }),
            EpollDescriptor::BrokerUnixStream(fd) => global
                .litebox
                .descriptor_table()
                .entry_handle(fd)
                .map_or_else(EdgeResetGenerations::default, |handle| {
                    handle.with_entry(|entry| EdgeResetGenerations {
                        read: entry.read_edge_reset_generation(),
                        write: entry.write_edge_reset_generation(),
                    })
                }),
            EpollDescriptor::Signalfd(_)
            | EpollDescriptor::Inotify(_)
            | EpollDescriptor::BrokerInetListener(_)
            | EpollDescriptor::BrokerInetDgram(_)
            | EpollDescriptor::BrokerInetRaw(_)
            | EpollDescriptor::Epoll(_)
            | EpollDescriptor::File(_)
            | EpollDescriptor::Unix(_)
            | EpollDescriptor::HostPassthroughFd(_)
            | EpollDescriptor::BrokerPty(_) => EdgeResetGenerations::default(),
            #[cfg(feature = "worker_local_inet")]
            EpollDescriptor::Socket(_) => EdgeResetGenerations::default(),
        }
    }

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
            if let Some(observer) = observer.clone() {
                iop.register_observer(observer, mask);
            }
            iop.check_io_events() & (mask | Events::ALWAYS_POLLED)
        };
        match self {
            EpollDescriptor::Eventfd(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::Signalfd(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::Inotify(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::BrokerInetListener(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::BrokerInetDgram(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::BrokerInetRaw(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::Epoll(handle) => Some(handle.with_entry(|entry| {
                if let Some(observer) = observer {
                    entry.register_observer(observer, mask);
                }
                entry.rescan_interests(global, fs);
                entry.check_io_events() & (mask | Events::ALWAYS_POLLED)
            })),
            EpollDescriptor::File(file) => {
                // Check if the file supports async I/O polling (e.g., PTY master).
                let descriptors = global.litebox.descriptor_table();
                if let Some(io_poll) = fs.get_io_pollable(file, &*descriptors) {
                    let events = poll(&*io_poll);
                    return Some(events);
                }
                // Regular files and stdio: always considered both readable
                // and writable, matching Linux kernel behaviour.
                Some((Events::IN | Events::OUT) & mask)
            }
            #[cfg(feature = "worker_local_inet")]
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
            EpollDescriptor::Unix(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::HostPassthroughFd(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::BrokerPipe(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::BrokerPty(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::BrokerSocketPair(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::BrokerTcpConn(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::BrokerUnixStream(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
        }
    }

    /// Returns `true` if this descriptor requires periodic host polling
    /// rather than observer-based notifications.
    fn needs_host_poll(&self, global: &GlobalState<FS>, fs: &FS) -> bool {
        match self {
            EpollDescriptor::Signalfd(_) => false,
            EpollDescriptor::Inotify(_) => false,
            EpollDescriptor::BrokerInetListener(_) => true,
            EpollDescriptor::BrokerInetDgram(_) => false,
            EpollDescriptor::BrokerInetRaw(_) => false,
            EpollDescriptor::Eventfd(fd) => global
                .litebox
                .descriptor_table()
                .entry_handle(fd)
                .is_some_and(|handle| {
                    handle.with_entry(super::eventfd::EventFile::needs_host_poll)
                }),
            EpollDescriptor::Epoll(handle) => {
                handle.with_entry(|entry| entry.compute_needs_host_poll(global, fs))
            }
            EpollDescriptor::File(file) => fs
                .get_io_pollable(file, &*global.litebox.descriptor_table())
                .is_some_and(|p| p.needs_host_poll()),
            EpollDescriptor::HostPassthroughFd(_) => true,
            EpollDescriptor::BrokerPipe(_) => false,
            EpollDescriptor::BrokerPty(_) => false,
            EpollDescriptor::BrokerSocketPair(_) => false,
            // Broker TCP connect completion is produced by a broker-side helper
            // thread. Notifications are still the fast path, but epoll must also
            // periodically re-query the broker so a missed/lost wake cannot leave
            // a nonblocking connect stuck in EINPROGRESS until user timeout.
            EpollDescriptor::BrokerTcpConn(_) => true,
            EpollDescriptor::BrokerUnixStream(_) => false,
            #[cfg(feature = "worker_local_inet")]
            EpollDescriptor::Socket(_) => false,
            EpollDescriptor::Unix(fd) => global
                .litebox
                .descriptor_table()
                .entry_handle(fd)
                .is_some_and(|handle| handle.with_entry(super::unix::UnixSocket::needs_host_poll)),
        }
    }
}

pub(crate) struct EpollFile<FS: ShimFS> {
    interests: litebox::sync::Mutex<
        litebox_platform_multiplex::Platform,
        BTreeMap<EpollEntryKey, alloc::sync::Arc<EpollEntry<FS>>>,
    >,
    parents: litebox::sync::Mutex<
        litebox_platform_multiplex::Platform,
        Vec<WeakEntryHandle<Platform, super::epoll::EpollSubsystem<FS>>>,
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
            parents: litebox::sync::Mutex::new(Vec::new()),
            ready: Arc::new(ReadySet::new()),
            status: core::sync::atomic::AtomicU32::new(OFlags::RDWR.bits()),
            needs_host_poll: core::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Snapshot the current interest list for cross-binary-type exec
    /// migration (see `exec_on_remote_host` in `process.rs`). Returns
    /// `(parent_raw_fd, events_bits, user_data)` for every interest
    /// whose target descriptor is still live. The events bits combine
    /// the [`Events`] mask and the [`EpollFlags`] (EDGE_TRIGGER /
    /// ONE_SHOT / EXCLUSIVE / WAKE_UP), matching the wire format the
    /// guest originally passed to `epoll_ctl(EPOLL_CTL_ADD)`.
    ///
    /// The remote worker re-creates these interests by calling
    /// `EpollFile::add_interest` after every other bridge fd has been
    /// installed at its matching slot — the parent's `fd` is preserved
    /// across the exec boundary by the slot-preserving bridge install
    /// path.
    pub fn snapshot_interests(&self) -> Vec<(u32, u32, u64)> {
        let interests = self.interests.lock();
        let mut out: Vec<(u32, u32, u64)> = Vec::with_capacity(interests.len());
        for (key, entry) in interests.iter() {
            if entry.desc.upgrade().is_none() {
                continue;
            }
            let inner = entry.inner.lock();
            let events_bits = inner.mask.bits() | inner.flags.bits();
            out.push((key.0, events_bits, inner.data));
        }
        out
    }

    pub(crate) fn wait(
        &self,
        global: &GlobalState<FS>,
        fs: &FS,
        cx: &WaitContext<'_, Platform>,
        maxevents: usize,
    ) -> Result<Vec<EpollEvent>, WaitError> {
        enum WaitOutcome {
            Ready,
            RecheckMode,
        }

        let mut events = Vec::new();
        loop {
            self.drive_network_for_socket_interests(global);
            if self.compute_needs_host_poll(global, fs) {
                // At least one descriptor requires periodic host polling (e.g.
                // stdin). Re-scan all interests with a short timeout to detect
                // host-side readiness changes, but also wait on the ready set so
                // observer-driven wakeups (e.g. eventfd) are not delayed until the
                // next poll tick.
                const POLL_INTERVAL: core::time::Duration = core::time::Duration::from_millis(50);
                loop {
                    self.refresh_ready_interests(global, fs);

                    self.ready.pop_multiple(global, fs, maxevents, &mut events);
                    if !events.is_empty() {
                        self.collect_additional_socket_events(global, fs, maxevents, &mut events);
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
                            // PE.14: before honoring EINTR, do one more
                            // pass to collect events that may have become
                            // ready concurrently with the signal. Matches
                            // Linux's epoll_wait semantics: if events are
                            // available, return them; only EINTR if not.
                            self.refresh_ready_interests(global, fs);
                            self.ready.pop_multiple(global, fs, maxevents, &mut events);
                            if !events.is_empty() {
                                self.collect_additional_socket_events(
                                    global,
                                    fs,
                                    maxevents,
                                    &mut events,
                                );
                                return Ok(events);
                            }
                            return Err(WaitError::Interrupted);
                        }
                        Err(TryOpError::Other(infallible)) => match infallible {},
                    }
                }
            } else {
                match self.ready.pollee.wait(cx, false, Events::IN, || {
                    self.drive_network_for_socket_interests(global);
                    self.ready.pop_multiple(global, fs, maxevents, &mut events);
                    if !events.is_empty() {
                        self.collect_additional_socket_events(global, fs, maxevents, &mut events);
                        return Ok(WaitOutcome::Ready);
                    }
                    if self.compute_needs_host_poll(global, fs) {
                        return Ok(WaitOutcome::RecheckMode);
                    }
                    Err(TryOpError::<Infallible>::TryAgain)
                }) {
                    Ok(WaitOutcome::Ready) => return Ok(events),
                    Ok(WaitOutcome::RecheckMode) => {}
                    Err(TryOpError::TryAgain) => unreachable!(),
                    Err(TryOpError::WaitError(WaitError::Interrupted)) => {
                        // PE.14: before honoring EINTR, do one more pass
                        // to collect events that may have become ready
                        // concurrently with the signal.
                        self.drive_network_for_socket_interests(global);
                        self.ready.pop_multiple(global, fs, maxevents, &mut events);
                        if !events.is_empty() {
                            self.collect_additional_socket_events(
                                global,
                                fs,
                                maxevents,
                                &mut events,
                            );
                            return Ok(events);
                        }
                        return Err(WaitError::Interrupted);
                    }
                    Err(TryOpError::WaitError(e)) => return Err(e),
                    Err(TryOpError::Other(infallible)) => match infallible {},
                }
            }
        }
    }

    fn refresh_ready_interests(&self, global: &GlobalState<FS>, fs: &FS) {
        self.drive_network_for_socket_interests(global);
        self.rescan_interests(global, fs);
    }

    fn collect_additional_socket_events(
        &self,
        global: &GlobalState<FS>,
        fs: &FS,
        maxevents: usize,
        events: &mut Vec<EpollEvent>,
    ) {
        let target = self.network_drive_interest_count().min(maxevents);
        if target <= 1 || events.len() >= target {
            return;
        }
        for _ in 0..MAX_SOCKET_SETTLE_POLLS {
            if events.len() >= target {
                return;
            }
            self.drive_network_for_socket_interests(global);
            self.append_ready_socket_events(global, fs, maxevents, events);
        }
    }

    fn append_ready_socket_events(
        &self,
        global: &GlobalState<FS>,
        fs: &FS,
        maxevents: usize,
        events: &mut Vec<EpollEvent>,
    ) {
        let entries = {
            let interests = self.interests.lock();
            interests.values().cloned().collect::<Vec<_>>()
        };
        for entry in entries {
            if events.len() >= maxevents {
                return;
            }
            if !entry.desc.needs_network_drive() {
                continue;
            }
            if let Some((Some(event), _)) = entry.poll(global, fs, false, true)
                && !events.iter().any(|existing| existing.data == event.data)
            {
                events.push(event);
            }
        }
    }

    fn drive_network_for_socket_interests(&self, global: &GlobalState<FS>) {
        if crate::WORKER_LOCAL_INET && self.has_socket_interests() {
            Self::drive_network_until_idle(global);
        }
    }

    fn has_socket_interests(&self) -> bool {
        self.network_drive_interest_count() != 0
    }

    fn network_drive_interest_count(&self) -> usize {
        let interests = self.interests.lock();
        interests
            .values()
            .filter(|entry| entry.desc.needs_network_drive())
            .count()
    }

    fn drive_network_until_idle(global: &GlobalState<FS>) {
        const MAX_NETWORK_YIELDS: usize = 4;
        for _ in 0..MAX_NETWORK_YIELDS {
            Self::drive_network_poll_loop(global);
            litebox_platform_multiplex::platform().wake_network_worker();
            // SAFETY: sched_yield has no memory-safety preconditions and lets peer
            // worker threads run echo/readiness work before this epoll wait returns.
            unsafe { ::syscalls::raw::syscall0(::syscalls::Sysno::sched_yield) };
        }
        Self::drive_network_poll_loop(global);
    }

    fn drive_network_poll_loop(global: &GlobalState<FS>) {
        #[cfg(feature = "worker_local_inet")]
        {
            const MAX_NETWORK_POLLS: usize = 8;
            for _ in 0..MAX_NETWORK_POLLS {
                let advice = global.net.lock().perform_platform_interaction();
                if !advice.call_again_immediately() {
                    break;
                }
            }
        }
        #[cfg(not(feature = "worker_local_inet"))]
        {
            let _ = global;
        }
    }

    /// Re-scan all interests and push any that are ready to the ready set.
    fn rescan_interests(&self, global: &GlobalState<FS>, fs: &FS) {
        let entries = {
            let interests = self.interests.lock();
            interests.values().cloned().collect::<Vec<_>>()
        };
        for entry in entries {
            match entry.poll(global, fs, false, false) {
                Some((Some(_event), _)) => self.ready.push(&entry),
                Some((None, _)) | None => {
                    entry
                        .is_ready
                        .store(false, core::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    }

    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.ready.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        if self.ready.has_ready_entries() {
            Events::IN
        } else {
            Events::empty()
        }
    }

    fn compute_needs_host_poll(&self, global: &GlobalState<FS>, fs: &FS) -> bool {
        if self.requires_host_poll() {
            return true;
        }
        let interests = self.interests.lock();
        interests.values().any(|entry| {
            entry
                .desc
                .upgrade()
                .is_some_and(|file| file.needs_host_poll(global, fs))
        })
    }

    fn requires_host_poll(&self) -> bool {
        self.needs_host_poll
            .load(core::sync::atomic::Ordering::Relaxed)
    }

    fn directly_contains_epoll(&self, _global: &GlobalState<FS>, target: *const Self) -> bool {
        let interests = self.interests.lock();
        interests.values().any(|entry| {
            let Some(EpollDescriptor::Epoll(epoll)) = entry.desc.upgrade() else {
                return false;
            };
            epoll.with_entry(|nested| core::ptr::eq(nested, target))
        })
    }

    #[allow(clippy::only_used_in_recursion)]
    fn contains_epoll(&self, global: &GlobalState<FS>, target: *const Self) -> bool {
        if core::ptr::eq(self, target) {
            return true;
        }
        let interests = self.interests.lock();
        for entry in interests.values() {
            let Some(EpollDescriptor::Epoll(epoll)) = entry.desc.upgrade() else {
                continue;
            };
            if epoll.with_entry(|nested| nested.contains_epoll(global, target)) {
                return true;
            }
        }
        false
    }

    #[allow(clippy::only_used_in_recursion)]
    fn max_descendant_epoll_depth(&self, global: &GlobalState<FS>) -> usize {
        let interests = self.interests.lock();
        let mut max_depth = 1;
        for entry in interests.values() {
            let Some(EpollDescriptor::Epoll(epoll)) = entry.desc.upgrade() else {
                continue;
            };
            let depth = epoll.with_entry(|nested| nested.max_descendant_epoll_depth(global));
            max_depth = max_depth.max(1 + depth);
        }
        max_depth
    }

    fn max_ancestor_epoll_depth(&self, global: &GlobalState<FS>) -> usize {
        let parents = self.parents.lock().clone();
        let self_ptr: *const _ = self;
        let mut max_depth = 1;
        for handle in parents {
            let Some(handle) = handle.upgrade() else {
                continue;
            };
            let depth = handle.with_entry(|candidate| {
                if core::ptr::eq(candidate, self)
                    || !candidate.directly_contains_epoll(global, self_ptr)
                {
                    return 0;
                }
                candidate.max_ancestor_epoll_depth(global) + 1
            });
            max_depth = max_depth.max(depth);
        }
        max_depth
    }

    fn find_entry_handle(
        &self,
        global: &GlobalState<FS>,
    ) -> Option<EntryHandle<Platform, super::epoll::EpollSubsystem<FS>>> {
        global
            .litebox
            .descriptor_table()
            .entry_handles::<super::epoll::EpollSubsystem<FS>>()
            .find(|handle| handle.with_entry(|candidate| core::ptr::eq(candidate, self)))
    }

    fn add_parent(&self, parent: &EntryHandle<Platform, super::epoll::EpollSubsystem<FS>>) {
        self.parents.lock().push(parent.downgrade());
    }

    fn remove_parent_by_id(&self, parent_id: DescriptorObjectId) {
        let mut parents = self.parents.lock();
        if let Some(idx) = parents
            .iter()
            .position(|weak| weak.object_id() == parent_id)
        {
            parents.remove(idx);
        }
    }

    pub(crate) fn detach_nested_children_by_parent_id(&self, parent_id: DescriptorObjectId) {
        let entries = {
            let interests = self.interests.lock();
            interests.values().cloned().collect::<Vec<_>>()
        };
        for entry in entries {
            let Some(EpollDescriptor::Epoll(child)) = entry.desc.upgrade() else {
                continue;
            };
            child.with_entry(|nested| nested.remove_parent_by_id(parent_id));
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
                let _epoll_graph_guard = matches!(file, EpollDescriptor::Epoll(_))
                    .then(|| global.epoll_graph_lock.lock());
                let parent_handle = matches!(file, EpollDescriptor::Epoll(_))
                    .then(|| self.find_entry_handle(global))
                    .flatten();
                let mut interests = self.interests.lock();
                let removed = interests
                    .remove(&EpollEntryKey::new(fd, file))
                    .ok_or(Errno::ENOENT)?;
                drop(interests);
                if let (Some(parent_handle), Some(EpollDescriptor::Epoll(child))) =
                    (parent_handle.as_ref(), removed.desc.upgrade())
                {
                    child.with_entry(|entry| {
                        entry.remove_parent_by_id(parent_handle.object_id());
                    });
                }
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
        let _epoll_graph_guard =
            matches!(file, EpollDescriptor::Epoll(_)).then(|| global.epoll_graph_lock.lock());
        let parent_handle = matches!(file, EpollDescriptor::Epoll(_))
            .then(|| self.find_entry_handle(global))
            .flatten();
        let flags = EpollFlags::from_bits_truncate(event.events);
        if let EpollDescriptor::Epoll(epoll) = file {
            if flags.contains(EpollFlags::EXCLUSIVE) {
                return Err(Errno::EINVAL);
            }
            epoll.with_entry(|entry| {
                if core::ptr::eq(entry, self) {
                    return Err(Errno::EINVAL);
                }
                if entry.contains_epoll(global, core::ptr::from_ref(self)) {
                    return Err(Errno::ELOOP);
                }
                let new_depth = self.max_ancestor_epoll_depth(global)
                    + entry.max_descendant_epoll_depth(global);
                if new_depth > MAX_NESTED_EPOLL_DEPTH {
                    return Err(Errno::ELOOP);
                }
                Ok(())
            })?;
        }

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
            flags,
            event.data,
            self.ready.clone(),
        );
        let events = file
            .poll(global, fs, mask, Some(entry.weak_self.clone() as _))
            .ok_or(Errno::EBADF)?;
        let edge_reset_generations = file.edge_reset_generations(global);
        // Add the new entry to the ready list if the file is ready
        let initial_event = {
            let mut inner = entry.inner.lock();
            EpollEntry::<FS>::event_from_polled_events(
                &mut inner,
                events,
                edge_reset_generations,
                false,
                false,
                entry.edge_dedup_mask,
                &entry.is_enabled,
            )
            .is_some_and(|(event, _)| event.is_some())
        };
        if initial_event {
            self.ready.push(&entry);
        }
        let is_host_poll = file.needs_host_poll(global, fs);
        if is_host_poll
            && !self
                .needs_host_poll
                .swap(true, core::sync::atomic::Ordering::Relaxed)
        {
            self.ready.pollee.notify_observers(Events::IN);
        }
        interests.insert(key, entry);
        drop(interests);
        if let (Some(parent_handle), EpollDescriptor::Epoll(child)) = (parent_handle.as_ref(), file)
        {
            child.with_entry(|entry| entry.add_parent(parent_handle));
        }
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
        inner.last_delivered_events = Events::empty();
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
struct EpollEntryKey(u32, DescriptorObjectId);
impl EpollEntryKey {
    fn new<FS: ShimFS>(fd: u32, desc: &EpollDescriptor<FS>) -> Self {
        let object_id = match desc {
            EpollDescriptor::Eventfd(file) => file.object_id(),
            EpollDescriptor::Signalfd(file) => file.object_id(),
            EpollDescriptor::Inotify(file) => file.object_id(),
            EpollDescriptor::BrokerInetListener(file) => file.object_id(),
            EpollDescriptor::BrokerInetDgram(file) => file.object_id(),
            EpollDescriptor::BrokerInetRaw(file) => file.object_id(),
            EpollDescriptor::Epoll(file) => file.object_id(),
            EpollDescriptor::File(file) => file.object_id(),
            #[cfg(feature = "worker_local_inet")]
            EpollDescriptor::Socket(socket_fd) => socket_fd.object_id(),
            EpollDescriptor::Unix(unix) => unix.object_id(),
            EpollDescriptor::HostPassthroughFd(hp) => hp.object_id(),
            EpollDescriptor::BrokerPipe(bp) => bp.object_id(),
            EpollDescriptor::BrokerPty(pty) => pty.object_id(),
            EpollDescriptor::BrokerSocketPair(sp) => sp.object_id(),
            EpollDescriptor::BrokerTcpConn(tcp) => tcp.object_id(),
            EpollDescriptor::BrokerUnixStream(us) => us.object_id(),
        };
        Self(fd, object_id)
    }
}

struct EpollEntry<FS: ShimFS> {
    desc: DescriptorRef<FS>,
    inner: litebox::sync::Mutex<litebox_platform_multiplex::Platform, EpollEntryInner>,
    ready: Arc<ReadySet<FS>>,
    is_ready: AtomicBool,
    is_enabled: AtomicBool,
    edge_dedup_mask: Events,
    weak_self: Weak<Self>,
}

struct EpollEntryInner {
    mask: Events,
    flags: EpollFlags,
    data: u64,
    last_delivered_events: Events,
    last_edge_reset_generations: EdgeResetGenerations,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct EdgeResetGenerations {
    read: u64,
    write: u64,
}

impl<FS: ShimFS> EpollEntry<FS> {
    fn new(
        desc: DescriptorRef<FS>,
        mask: Events,
        flags: EpollFlags,
        data: u64,
        ready: Arc<ReadySet<FS>>,
    ) -> Arc<Self> {
        let edge_dedup_mask = desc.edge_dedup_mask();
        Arc::new_cyclic(|weak_self| EpollEntry {
            desc,
            inner: litebox::sync::Mutex::new(EpollEntryInner {
                mask,
                flags,
                data,
                last_delivered_events: Events::empty(),
                last_edge_reset_generations: EdgeResetGenerations::default(),
            }),
            ready,
            is_ready: AtomicBool::new(false),
            is_enabled: AtomicBool::new(true),
            edge_dedup_mask,
            weak_self: weak_self.clone(),
        })
    }

    /// Poll the entry for events.
    ///
    /// When `disable_oneshot` is true (used by `pop_multiple()` during event
    /// delivery), ONESHOT entries are disabled atomically under the `inner` lock
    /// before returning. This prevents both:
    /// - Double-delivery: another `pop_multiple()` thread cannot see the entry
    ///   as enabled between poll and disable.
    /// - MOD clobber: `mod_interest()` also operates under `inner`, so a
    ///   concurrent re-arm either completes before poll (and the disable
    ///   correctly fires for this delivery) or after (re-enabling the entry).
    ///
    /// When `disable_oneshot` is false (used by `rescan_interests()`), ONESHOT
    /// entries remain enabled so `push()` can add them to the ready set.
    fn poll(
        &self,
        global: &GlobalState<FS>,
        fs: &FS,
        disable_oneshot: bool,
        deliver: bool,
    ) -> Option<(Option<EpollEvent>, bool)> {
        let file = self.desc.upgrade()?;
        let mut inner = self.inner.lock();

        if !self.is_enabled.load(core::sync::atomic::Ordering::Relaxed) {
            // the entry is disabled
            return None;
        }

        let events = file.poll(global, fs, inner.mask, None)?;
        let edge_reset_generations = file.edge_reset_generations(global);
        Self::event_from_polled_events(
            &mut inner,
            events,
            edge_reset_generations,
            disable_oneshot,
            deliver,
            self.edge_dedup_mask,
            &self.is_enabled,
        )
    }

    fn event_from_polled_events(
        inner: &mut EpollEntryInner,
        events: Events,
        edge_reset_generations: EdgeResetGenerations,
        disable_oneshot: bool,
        deliver: bool,
        edge_dedup_mask: Events,
        is_enabled: &AtomicBool,
    ) -> Option<(Option<EpollEvent>, bool)> {
        if events.is_empty() {
            if inner.flags.contains(EpollFlags::EDGE_TRIGGER) && !edge_dedup_mask.is_empty() {
                inner.last_delivered_events = Events::empty();
                inner.last_edge_reset_generations = edge_reset_generations;
            }
            return Some((None, false));
        }

        if inner.flags.contains(EpollFlags::EDGE_TRIGGER) && !edge_dedup_mask.is_empty() {
            if edge_reset_generations != inner.last_edge_reset_generations {
                let mut reset_events = Events::empty();
                if edge_reset_generations.read != inner.last_edge_reset_generations.read {
                    reset_events |= Events::IN | Events::PRI;
                }
                if edge_reset_generations.write != inner.last_edge_reset_generations.write {
                    reset_events |= Events::OUT;
                }
                inner.last_delivered_events &= !reset_events;
                inner.last_edge_reset_generations = edge_reset_generations;
            }
            let dedup_events = events & edge_dedup_mask;
            let newly_ready = dedup_events & !inner.last_delivered_events;
            if newly_ready.is_empty() {
                inner.last_delivered_events = dedup_events;
                if (events & !edge_dedup_mask).is_empty() {
                    return Some((None, false));
                }
            } else if deliver {
                inner.last_delivered_events = dedup_events;
            }
        }

        let event = Some(EpollEvent {
            events: events.bits(),
            data: inner.data,
        });

        // keep the entry in the ready list if it is not edge-triggered or one-shot
        let is_still_ready = !inner
            .flags
            .intersects(EpollFlags::EDGE_TRIGGER | EpollFlags::ONE_SHOT);

        // Disable ONESHOT entries atomically under the inner lock when
        // delivering events (pop_multiple path). This is NOT done in the
        // rescan_interests path — disabling here would cause push() to
        // reject the entry, silently dropping the event.
        if disable_oneshot && inner.flags.contains(EpollFlags::ONE_SHOT) {
            is_enabled.store(false, core::sync::atomic::Ordering::Relaxed);
        }

        Some((event, is_still_ready))
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

    fn has_ready_entries(&self) -> bool {
        self.entries.lock().iter().any(|weak_entry| {
            weak_entry.upgrade().is_some_and(|entry| {
                entry.is_enabled.load(core::sync::atomic::Ordering::Relaxed)
                    && entry.is_ready.load(core::sync::atomic::Ordering::Relaxed)
            })
        })
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

            let Some((event, is_still_ready)) = entry.poll(global, fs, true, true) else {
                // the entry is disabled or the associated file is closed
                continue;
            };

            if let Some(event) = event {
                events.push(event);
                // ONESHOT disable already happened atomically inside poll()
                // under the inner lock, preventing both MOD-clobber races and
                // double-delivery by concurrent pop_multiple() threads.
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

fn should_settle_socket_rdhup(mask: Events, revents: Events) -> bool {
    mask.contains(Events::RDHUP)
        && revents.contains(Events::IN)
        && !revents.intersects(Events::RDHUP | Events::HUP)
}

impl PollSet {
    /// Returns a new empty `PollSet` with the given interest capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    /// Returns true if no fds have been added.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
        if crate::WORKER_LOCAL_INET && self.has_socket_entries(global, files) {
            EpollFile::<FS>::drive_network_until_idle(global);
        }

        let mut is_ready = false;
        for entry in &mut self.entries {
            entry.revents = if entry.fd < 0 {
                continue;
            } else if let Ok(poll_descriptor) = EpollDescriptor::try_from(
                global,
                files,
                entry.fd.reinterpret_as_unsigned() as usize,
            ) {
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
                #[cfg(feature = "worker_local_inet")]
                let is_socket = matches!(poll_descriptor, EpollDescriptor::Socket(_));
                #[cfg(not(feature = "worker_local_inet"))]
                let is_socket = false;
                let mut revents = poll_descriptor
                    .poll(global, &*files.fs, entry.mask, observer)
                    .unwrap_or(Events::NVAL);
                if is_socket && should_settle_socket_rdhup(entry.mask, revents) {
                    for _ in 0..MAX_SOCKET_SETTLE_POLLS {
                        EpollFile::<FS>::drive_network_until_idle(global);
                        revents = poll_descriptor
                            .poll(global, &*files.fs, entry.mask, None)
                            .unwrap_or(Events::NVAL);
                        if !should_settle_socket_rdhup(entry.mask, revents) {
                            break;
                        }
                    }
                }
                revents
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
                    WaitError::Interrupted => {
                        // PE.14: before honoring EINTR, do one more scan
                        // for ready entries. Matches Linux's poll/ppoll
                        // semantics: events available concurrent with a
                        // signal are returned first.
                        if self.scan_once(global, files, None) {
                            return Ok(());
                        }
                        return Err(WaitError::Interrupted);
                    }
                }
            }
        } else {
            let mut register = true;
            let res = cx.wait_until(|| {
                if self.scan_once(global, files, register.then_some(cx.waker())) {
                    return true;
                }
                // Don't register observers again in the next iteration.
                register = false;
                false
            });
            // PE.14: even on Interrupted, check once more if any entry
            // became ready (between observer fire and signal arrival).
            match res {
                Err(WaitError::Interrupted) => {
                    if self.scan_once(global, files, None) {
                        Ok(())
                    } else {
                        Err(WaitError::Interrupted)
                    }
                }
                other => other,
            }
        }
    }

    fn has_socket_entries<FS: ShimFS>(
        &self,
        global: &GlobalState<FS>,
        files: &FilesState<FS>,
    ) -> bool {
        self.entries.iter().any(|entry| {
            if entry.fd < 0 {
                return false;
            }
            let raw_fd = entry.fd.reinterpret_as_unsigned() as usize;
            match EpollDescriptor::try_from(global, files, raw_fd) {
                #[cfg(feature = "worker_local_inet")]
                Ok(EpollDescriptor::Socket(_)) => true,
                Ok(EpollDescriptor::BrokerTcpConn(_)) => true,
                _ => false,
            }
        })
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
            if let Ok(poll_descriptor) = EpollDescriptor::try_from(global, files, raw_fd)
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
    use litebox::utils::TruncateExt as _;
    use litebox_common_linux::{ClockId, EfdFlags, EpollEvent, TimerfdFlags};
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

    fn new_mock_eventfd(
        count: u64,
        flags: EfdFlags,
    ) -> crate::syscalls::eventfd::EventFile<litebox_platform_multiplex::Platform> {
        crate::syscalls::eventfd::test_support::new_mock_broker_eventfd(count, flags).2
    }

    fn new_mock_timerfd(
        flags: TimerfdFlags,
    ) -> (
        Arc<
            litebox_common_linux::cwfd::broker_timerfd_provider::test_util::TestBrokerTimerfdProvider,
        >,
        u64,
        crate::syscalls::eventfd::EventFile<litebox_platform_multiplex::Platform>,
    ){
        crate::syscalls::eventfd::test_support::new_mock_broker_timerfd(flags)
    }

    #[test]
    fn test_epoll_with_eventfd() {
        let (task, epoll, fs) = setup_epoll();
        let eventfd = new_mock_eventfd(0, EfdFlags::CLOEXEC);
        let typed = task
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<crate::syscalls::eventfd::EventfdSubsystem>(eventfd);
        let files = Arc::new(FilesState::new(task.files.borrow().fs.clone()));
        let Ok(raw_fd) = files.insert_raw_fd(typed) else {
            unreachable!()
        };
        let descriptor = super::EpollDescriptor::try_from(&task.global, &files, raw_fd).unwrap();
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
        let (timer_provider, timer_handle, timerfd) = new_mock_timerfd(TimerfdFlags::empty());
        let typed = task
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<crate::syscalls::eventfd::EventfdSubsystem>(timerfd);
        let files = Arc::new(FilesState::new(task.files.borrow().fs.clone()));
        let Ok(raw_fd) = files.insert_raw_fd(typed) else {
            unreachable!()
        };
        let descriptor = super::EpollDescriptor::try_from(&task.global, &files, raw_fd).unwrap();
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
        timer_provider
            .fire_timerfd(timer_handle, 1)
            .expect("failed to fire mock timerfd");

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
    fn test_nested_epoll_wait_switches_to_host_poll_after_child_update() {
        let task = crate::syscalls::tests::init_platform(None);
        let fs = task.files.borrow().fs.clone();

        let outer = super::EpollFile::new();
        let outer_typed = task
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<super::EpollSubsystem<crate::DefaultFS>>(outer);
        let outer_handle = task
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&outer_typed)
            .unwrap();

        let middle = super::EpollFile::new();
        let middle_typed = task
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<super::EpollSubsystem<crate::DefaultFS>>(middle);
        let middle_handle = task
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&middle_typed)
            .unwrap();

        let inner = super::EpollFile::new();
        let inner_typed = task
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<super::EpollSubsystem<crate::DefaultFS>>(inner);
        let inner_handle = task
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&inner_typed)
            .unwrap();

        let files = Arc::new(FilesState::new(task.files.borrow().fs.clone()));
        let Ok(outer_raw) = files.insert_raw_fd(outer_typed) else {
            unreachable!()
        };
        let Ok(middle_raw) = files.insert_raw_fd(middle_typed) else {
            unreachable!()
        };
        let Ok(inner_raw) = files.insert_raw_fd(inner_typed) else {
            unreachable!()
        };

        let middle_desc =
            super::EpollDescriptor::try_from(&task.global, &files, middle_raw).unwrap();
        outer_handle
            .with_entry(|entry| {
                entry.add_interest(
                    &task.global,
                    &*fs,
                    1,
                    &middle_desc,
                    EpollEvent {
                        events: Events::IN.bits(),
                        data: 0x1111,
                    },
                )
            })
            .unwrap();

        let inner_desc = super::EpollDescriptor::try_from(&task.global, &files, inner_raw).unwrap();
        middle_handle
            .with_entry(|entry| {
                entry.add_interest(
                    &task.global,
                    &*fs,
                    2,
                    &inner_desc,
                    EpollEvent {
                        events: Events::IN.bits(),
                        data: 0x2222,
                    },
                )
            })
            .unwrap();

        {
            let global = task.global.clone();
            let files = Arc::clone(&files);
            let fs = fs.clone();
            let inner_handle = inner_handle.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                let (timer_provider, timer_broker_handle, timerfd) =
                    crate::syscalls::eventfd::test_support::new_mock_broker_timerfd(
                        TimerfdFlags::empty(),
                    );
                let typed = global
                    .litebox
                    .descriptor_table_mut()
                    .insert::<crate::syscalls::eventfd::EventfdSubsystem>(timerfd);
                let timer_entry_handle = global
                    .litebox
                    .descriptor_table()
                    .entry_handle(&typed)
                    .unwrap();
                let Ok(timer_raw) = files.insert_raw_fd(typed) else {
                    unreachable!()
                };
                let timer_desc =
                    super::EpollDescriptor::try_from(&global, &files, timer_raw).unwrap();
                inner_handle
                    .with_entry(|entry| {
                        entry.add_interest(
                            &global,
                            &*fs,
                            3,
                            &timer_desc,
                            EpollEvent {
                                events: Events::IN.bits(),
                                data: 0x3333,
                            },
                        )
                    })
                    .unwrap();
                let _ = timer_entry_handle;
                timer_provider
                    .fire_timerfd(timer_broker_handle, 1)
                    .expect("failed to fire mock timerfd");
            });
        }

        let wait_state = WaitState::new(platform());
        let wait_cx = wait_state
            .context()
            .with_timeout(Some(Duration::from_secs(1)));
        let events = outer_handle
            .with_entry(|entry| entry.wait(&task.global, &*fs, &wait_cx, 4))
            .unwrap();
        assert_eq!(events.len(), 1);
        let data = events[0].data;
        let bits = events[0].events;
        assert_eq!(data, 0x1111);
        assert_ne!(bits & Events::IN.bits(), 0);

        let _ = outer_raw;
    }

    #[test]
    fn test_epoll_with_eventfd_and_timerfd() {
        let (task, epoll, fs) = setup_epoll();

        let eventfd = new_mock_eventfd(0, EfdFlags::CLOEXEC);
        let eventfd = task
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<crate::syscalls::eventfd::EventfdSubsystem>(eventfd);

        let (_, _, timerfd) = new_mock_timerfd(TimerfdFlags::empty());
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

        let eventfd_desc =
            super::EpollDescriptor::try_from(&task.global, &files, eventfd_raw).unwrap();
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

        let timerfd_desc =
            super::EpollDescriptor::try_from(&task.global, &files, timerfd_raw).unwrap();
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

        let eventfd = new_mock_eventfd(0, EfdFlags::CLOEXEC);
        let eventfd = task
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<crate::syscalls::eventfd::EventfdSubsystem>(eventfd);

        let (_, _, timerfd) = new_mock_timerfd(TimerfdFlags::empty());
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

        let eventfd_desc =
            super::EpollDescriptor::try_from(&task.global, &files, eventfd_raw).unwrap();
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

        let timerfd_desc =
            super::EpollDescriptor::try_from(&task.global, &files, timerfd_raw).unwrap();
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
        let provider: Arc<
            dyn litebox_common_linux::broker_eventfd_provider::BrokerEventfdProvider,
        > = Arc::new(crate::syscalls::eventfd::test_support::TestBrokerEventfdProvider::new());
        let _ = crate::syscalls::eventfd::set_broker_eventfd_provider(provider);
        let timer_provider: Arc<
            dyn litebox_common_linux::cwfd::broker_timerfd_provider::BrokerTimerfdProvider,
        > = Arc::new(
            litebox_common_linux::cwfd::broker_timerfd_provider::test_util::TestBrokerTimerfdProvider::new(),
        );
        let _ = crate::syscalls::eventfd::set_broker_timerfd_provider(timer_provider);

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
    fn test_poll() {
        let task = crate::syscalls::tests::init_platform(None);

        let mut set = super::PollSet::with_capacity(0);
        let eventfd = new_mock_eventfd(0, EfdFlags::empty());

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
