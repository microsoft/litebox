// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The bridge's host sockets on Linux: Unix streams, which the thread waits
//! for with `epoll`, woken through an eventfd.
//!
//! Each OS module provides these items, with these signatures; the core uses
//! no others.

use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use litebox_broker_platform_linux_userland::{LinuxInstant, LinuxTimeProvider};
use litebox_platform::time::TimeProvider as _;
use rustix::event::{EventfdFlags, PollFd, PollFlags, Timespec, epoll, eventfd, poll};
use rustix::io::{Errno, ioctl_fionread, read, write};
use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, SocketAddrUnix, SocketFlags, SocketType, accept_with,
    bind, connect, listen, recv, send, shutdown, socket_with, sockopt,
};

use super::{LISTENER_TOKEN, MAX_EVENTS, Readiness, WAKE_TOKEN};

/// The bridge's monotonic clock.
pub(super) type Instant = LinuxInstant;

pub(super) fn now() -> Instant {
    LinuxTimeProvider.now()
}

/// How a guest's close shuts the stream down before dropping the host's
/// unread data.
pub(super) const CLOSE_SHUTDOWN: Shutdown = Shutdown::Both;

/// The longest Unix socket path, without its NUL.
pub(super) const MAX_SOCKET_PATH: usize = 108;

/// What the thread waits for on each stream; edge-triggered, as every event
/// leads to a poll, which reads each connection's state afresh.
const STREAM_EVENTS: epoll::EventFlags = epoll::EventFlags::IN
    .union(epoll::EventFlags::OUT)
    .union(epoll::EventFlags::RDHUP)
    .union(epoll::EventFlags::ET);

/// `PATH`, as the bridge bound it: removed when dropped if still that socket
/// (see the [bridge's](super) access control).
pub(super) struct BoundPath {
    path: PathBuf,
    /// Its device and inode, right after the bind.
    identity: (u64, u64),
}

impl BoundPath {
    fn identify(path: &Path) -> IoResult<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "replaced right after the bind",
            ));
        }
        Ok(Self {
            path: path.to_owned(),
            identity: (metadata.dev(), metadata.ino()),
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BoundPath {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && (metadata.dev(), metadata.ino()) == self.identity
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// A nonblocking listening socket.
pub(super) struct Listener(OwnedFd);

impl Listener {
    /// Listens at `path`, which must not exist.
    pub(super) fn bind(path: &Path, backlog: i32) -> IoResult<(Self, BoundPath)> {
        let address = SocketAddrUnix::new(path)?;
        let listener = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )?;
        bind(&listener, &address)?;
        // Removes `path` from here on, if setup fails.
        let bound = BoundPath::identify(path)?;
        listen(&listener, backlog)?;
        Ok((Self(listener), bound))
    }

    /// The next client's stream; `WouldBlock` if none waits.
    pub(super) fn accept(&mut self) -> IoResult<Stream> {
        let stream = accept_with(&self.0, SocketFlags::NONBLOCK | SocketFlags::CLOEXEC)?;
        Ok(Stream(stream))
    }
}

/// A nonblocking connected stream.
pub(super) struct Stream(OwnedFd);

impl Stream {
    /// Connects to `path`; the stream, and whether the connect is still in
    /// progress, which it never is here: a Unix stream connects at once, or
    /// fails (`EAGAIN` if the listener's backlog is full).
    pub(super) fn connect(path: &Path) -> IoResult<(Self, bool)> {
        let address = SocketAddrUnix::new(path)?;
        let stream = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )?;
        connect(&stream, &address)?;
        Ok((Self(stream), false))
    }

    /// Reads into `buffer`: `Ok(0)` at EOF, `WouldBlock` if nothing waits.
    pub(super) fn recv(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        let (len, _) = retry(|| recv(&self.0, &mut *buffer, RecvFlags::DONTWAIT))?;
        Ok(len)
    }

    /// As [`Stream::recv`], leaving the data to read.
    pub(super) fn peek(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        let (len, _) =
            retry(|| recv(&self.0, &mut *buffer, RecvFlags::PEEK | RecvFlags::DONTWAIT))?;
        Ok(len)
    }

    /// Writes from `bytes`, `WouldBlock` if there is no room; a peer gone
    /// fails it, without `SIGPIPE`.
    pub(super) fn send(&mut self, bytes: &[u8]) -> IoResult<usize> {
        Ok(retry(|| {
            send(&self.0, bytes, SendFlags::NOSIGNAL | SendFlags::DONTWAIT)
        })?)
    }

    /// Shuts the stream down `how`; a stream that failed already is ended.
    pub(super) fn shutdown(&self, how: Shutdown) {
        let how = match how {
            Shutdown::Read => rustix::net::Shutdown::Read,
            Shutdown::Write => rustix::net::Shutdown::Write,
            Shutdown::Both => rustix::net::Shutdown::Both,
        };
        let _ = shutdown(&self.0, how);
    }

    /// Whether data waits to be read.
    pub(super) fn has_data(&self) -> bool {
        ioctl_fionread(&self.0).is_ok_and(|len| len > 0)
    }

    /// The stream's readiness now; a failure to poll is an end.
    pub(super) fn poll_now(&mut self) -> Readiness {
        let mut fds = [PollFd::new(
            &self.0,
            PollFlags::IN | PollFlags::OUT | PollFlags::RDHUP,
        )];
        let now = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let flags = match retry(|| poll(&mut fds, Some(&now))) {
            Ok(_) => fds[0].revents(),
            Err(_) => PollFlags::ERR,
        };
        Readiness {
            ended: flags.intersects(PollFlags::RDHUP | PollFlags::HUP | PollFlags::ERR),
            writable: flags.contains(PollFlags::OUT),
        }
    }

    /// Whether the stream's end goes unwatched, which it never does: `epoll`
    /// reports it whether or not data waits.
    #[expect(clippy::unused_self, reason = "the Windows module's signature")]
    pub(super) fn end_unwatched(&self) -> bool {
        false
    }
}

/// What the thread waits for, and its wakeup; the bridge's.
pub(super) struct Poller {
    epoll: OwnedFd,
    wake: OwnedFd,
}

/// The thread's side of a [`Poller`].
pub(super) struct Waiter {
    epoll: OwnedFd,
    wake: OwnedFd,
}

impl Poller {
    pub(super) fn new() -> IoResult<(Self, Waiter)> {
        let epoll = epoll::create(epoll::CreateFlags::CLOEXEC)?;
        let wake = eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)?;
        epoll::add(
            &epoll,
            &wake,
            epoll::EventData::new_u64(WAKE_TOKEN),
            epoll::EventFlags::IN,
        )?;
        let waiter = Waiter {
            epoll: epoll.try_clone()?,
            wake: wake.try_clone()?,
        };
        Ok((Self { epoll, wake }, waiter))
    }

    /// Reports `stream`'s events as `token`: data, room, and its end, which
    /// includes, if `connecting`, its connect's completion.
    pub(super) fn add_stream(
        &self,
        stream: &mut Stream,
        token: u64,
        _connecting: bool,
    ) -> IoResult<()> {
        // Every stream the bridge reads comes here first. Urgent (`MSG_OOB`)
        // data is read inline, as `FIONREAD`, which `status` relies on,
        // counts it.
        sockopt::set_socket_oobinline(&stream.0, true)?;
        epoll::add(
            &self.epoll,
            &stream.0,
            epoll::EventData::new_u64(token),
            STREAM_EVENTS,
        )?;
        Ok(())
    }

    /// Reports `listener`'s clients as [`LISTENER_TOKEN`], while any waits.
    pub(super) fn watch_listener(&self, listener: &mut Listener) -> IoResult<()> {
        epoll::add(
            &self.epoll,
            &listener.0,
            epoll::EventData::new_u64(LISTENER_TOKEN),
            epoll::EventFlags::IN,
        )?;
        Ok(())
    }

    pub(super) fn unwatch_listener(&self, listener: &mut Listener) -> IoResult<()> {
        epoll::delete(&self.epoll, &listener.0)?;
        Ok(())
    }

    /// Keeps reporting `listener`'s waiting clients after accepts stopped
    /// short of `WouldBlock`, as a level-triggered listener does already.
    #[expect(
        clippy::unnecessary_wraps,
        clippy::unused_self,
        reason = "the Windows module's signature"
    )]
    pub(super) fn rearm_listener(&self, _listener: &mut Listener) -> IoResult<()> {
        Ok(())
    }

    /// Ends the thread's wait, now or at its next.
    pub(super) fn wake(&self) -> IoResult<()> {
        let value = 1_u64.to_ne_bytes();
        match retry(|| write(&self.wake, &value)) {
            Ok(length) if length == value.len() => Ok(()),
            Ok(_) => Err(Error::new(
                ErrorKind::WriteZero,
                "eventfd wake was truncated",
            )),
            // A saturated counter is readable already.
            Err(Errno::AGAIN) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

impl Waiter {
    /// Waits for events or a wake until `timeout` (`None`: forever), or an
    /// interrupt; `tokens` are then the listener's and streams' events.
    pub(super) fn wait(
        &mut self,
        tokens: &mut Vec<u64>,
        timeout: Option<Duration>,
    ) -> IoResult<()> {
        tokens.clear();
        // Past `Timespec`'s range: forever.
        let timeout = timeout.and_then(|timeout| Timespec::try_from(timeout).ok());
        // Here, not in the waiter, which moves to the thread: rustix's events
        // are not `Send`.
        let mut events = [epoll::Event {
            flags: epoll::EventFlags::empty(),
            data: epoll::EventData::new_u64(0),
        }; MAX_EVENTS];
        let len = match epoll::wait(&self.epoll, &mut events, timeout.as_ref()) {
            Ok(len) => len,
            Err(Errno::INTR) => 0,
            Err(error) => return Err(error.into()),
        };
        for event in &events[..len] {
            match event.data.u64() {
                WAKE_TOKEN => self.drain()?,
                token => tokens.push(token),
            }
        }
        Ok(())
    }

    fn drain(&self) -> IoResult<()> {
        let mut value = [0; size_of::<u64>()];
        match retry(|| read(&self.wake, &mut value)) {
            Ok(length) if length == value.len() => Ok(()),
            Ok(_) => Err(Errno::IO.into()),
            Err(Errno::AGAIN) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn retry<T>(mut f: impl FnMut() -> rustix::io::Result<T>) -> rustix::io::Result<T> {
    loop {
        match f() {
            Err(Errno::INTR) => {}
            result => return result,
        }
    }
}
