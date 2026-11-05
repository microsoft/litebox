// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The bridge's host sockets on macOS: Unix streams, which the thread waits
//! for with kqueue, woken through an `EVFILT_USER` event. The items are the
//! Linux module's.
//!
//! macOS creates sockets without atomic close-on-exec, so each opens under
//! the broker's spawn fence (see [`open_under_spawn_fence`]), and sends never
//! raise `SIGPIPE`, as each passes `MSG_NOSIGNAL`. Unix streams carry
//! no urgent data on macOS (`MSG_OOB` fails), so `FIONREAD` counts all of
//! it.

use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::Shutdown;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use litebox_broker_platform_macos_userland::{MacosInstant, MacosTimeProvider};
use litebox_platform::time::TimeProvider as _;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::{Errno, FdFlags, fcntl_setfd, ioctl_fionbio, ioctl_fionread};
use rustix::net::{
    AddressFamily, RecvFlags, SocketAddrUnix, SocketType, accept, bind, connect, listen, recv,
    shutdown, socket,
};

use super::{LISTENER_TOKEN, MAX_EVENTS, Readiness, WAKE_TOKEN};

/// The bridge's monotonic clock.
pub(super) type Instant = MacosInstant;

pub(super) fn now() -> Instant {
    MacosTimeProvider.now()
}

/// How a guest's close shuts the stream down before dropping the host's
/// unread data.
pub(super) const CLOSE_SHUTDOWN: Shutdown = Shutdown::Both;

/// The longest Unix socket path, without its NUL: `sun_path` holds 104 bytes.
pub(super) const MAX_SOCKET_PATH: usize = 103;

/// The `EVFILT_USER` identifier of the poller's wakes.
const WAKE_IDENT: usize = 0;

/// The longest timeout `kevent` takes, in seconds (2^31 - 1); it fails
/// longer ones with `EINVAL`.
const MAX_WAIT_SECONDS: u64 = 0x7fff_ffff;

/// `PATH`, as the bridge bound it: removed when dropped if still that socket
/// (see the [bridge's](super) access control). As the Linux module's.
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

/// Runs `open`, which makes a descriptor, then marks it close-on-exec, with
/// no runner spawn in between, which would inherit it; then makes it
/// nonblocking.
fn open_under_spawn_fence(open: impl FnOnce() -> Result<OwnedFd, Errno>) -> IoResult<OwnedFd> {
    let fd = crate::runner::without_concurrent_spawn(|| {
        let fd = open()?;
        fcntl_setfd(&fd, FdFlags::CLOEXEC)?;
        Ok::<_, Errno>(fd)
    })?;
    ioctl_fionbio(&fd, true)?;
    Ok(fd)
}

/// A new nonblocking, close-on-exec Unix stream socket.
fn unix_stream() -> IoResult<OwnedFd> {
    open_under_spawn_fence(|| socket(AddressFamily::UNIX, SocketType::STREAM, None))
}

/// A nonblocking listening socket.
pub(super) struct Listener(OwnedFd);

impl Listener {
    /// Listens at `path`, which must not exist.
    pub(super) fn bind(path: &Path, backlog: i32) -> IoResult<(Self, BoundPath)> {
        let address = SocketAddrUnix::new(path)?;
        let listener = unix_stream()?;
        bind(&listener, &address)?;
        // Removes `path` from here on, if setup fails.
        let bound = BoundPath::identify(path)?;
        listen(&listener, backlog)?;
        Ok((Self(listener), bound))
    }

    /// The next client's stream; `WouldBlock` if none waits.
    pub(super) fn accept(&mut self) -> IoResult<Stream> {
        // Nonblocking explicitly, though macOS copies it from the listener.
        Ok(Stream(open_under_spawn_fence(|| {
            retry(|| accept(&self.0))
        })?))
    }
}

/// A nonblocking connected stream.
pub(super) struct Stream(OwnedFd);

impl Stream {
    /// Connects to `path`; the stream, and whether the connect is still in
    /// progress, which it never is here: a Unix stream connects at once, or
    /// fails (`ECONNREFUSED` if the listener's backlog is full).
    pub(super) fn connect(path: &Path) -> IoResult<(Self, bool)> {
        let address = SocketAddrUnix::new(path)?;
        let stream = Self(unix_stream()?);
        connect(&stream.0, &address)?;
        Ok((stream, false))
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
    ///
    /// Through libc, as rustix offers no `MSG_NOSIGNAL` on macOS; not
    /// `SO_NOSIGPIPE`, which macOS refuses to set on an accepted stream whose
    /// client has gone, turning a client gone before its accept into a failed
    /// accept.
    pub(super) fn send(&mut self, bytes: &[u8]) -> IoResult<usize> {
        let sent = retry(|| {
            // SAFETY: `bytes` is readable for its length during the call,
            // which only reads it.
            let sent = unsafe {
                libc::send(
                    self.0.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                )
            };
            usize::try_from(sent)
                .map_err(|_| Errno::from_io_error(&Error::last_os_error()).unwrap_or(Errno::IO))
        })?;
        Ok(sent)
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
    ///
    /// macOS has no `POLLRDHUP`: it reports `POLLHUP` once either side of
    /// the stream is shut down for sending, the peer's or this one's. The
    /// bridge shuts a stream down for sending only once its connection
    /// ended, or as it closes it, so `POLLHUP` is the peer's end.
    pub(super) fn poll_now(&mut self) -> Readiness {
        let mut fds = [PollFd::new(&self.0, PollFlags::IN | PollFlags::OUT)];
        let now = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let flags = match retry(|| poll(&mut fds, Some(&now))) {
            Ok(_) => fds[0].revents(),
            Err(_) => PollFlags::ERR,
        };
        Readiness {
            ended: flags.intersects(PollFlags::HUP | PollFlags::ERR),
            writable: flags.contains(PollFlags::OUT),
        }
    }

    /// Whether the stream's end goes unwatched, which it never does: kqueue
    /// reports it (`EV_EOF`) whether or not data waits.
    #[expect(clippy::unused_self, reason = "the Windows module's signature")]
    pub(super) fn end_unwatched(&self) -> bool {
        false
    }
}

/// What the thread waits for, and its wakeup; the bridge's.
///
/// A kqueue drops a descriptor's filters as the descriptor closes, with any
/// events not yet reported, so a dropped stream needs no deregistration. A
/// descriptor number reused by a later stream is registered under that
/// stream's new token, and tokens are never reused, so no event is taken for
/// another stream's.
pub(super) struct Poller {
    kqueue: Arc<OwnedFd>,
}

/// The thread's side of a [`Poller`].
pub(super) struct Waiter {
    kqueue: Arc<OwnedFd>,
}

impl Poller {
    /// macOS opens a kqueue close-on-exec, and never lets a child inherit
    /// it, so it needs no spawn fence.
    pub(super) fn new() -> IoResult<(Self, Waiter)> {
        // SAFETY: `kqueue` takes no arguments.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(Error::last_os_error());
        }
        // SAFETY: `kqueue` returned a new descriptor that nothing else owns.
        let kqueue = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
        apply_changes(
            &kqueue,
            &mut [change(
                WAKE_IDENT,
                libc::EVFILT_USER,
                libc::EV_ADD | libc::EV_CLEAR,
                0,
                WAKE_TOKEN,
            )?],
        )?;
        let waiter = Waiter {
            kqueue: kqueue.clone(),
        };
        Ok((Self { kqueue }, waiter))
    }

    /// Reports `stream`'s events as `token`: data, room, and its end, which
    /// includes, if `connecting`, its connect's completion.
    ///
    /// Edge-triggered (`EV_CLEAR`), as every event leads to a poll, which
    /// reads each connection's state afresh.
    pub(super) fn add_stream(
        &self,
        stream: &mut Stream,
        token: u64,
        _connecting: bool,
    ) -> IoResult<()> {
        let ident = ident(&stream.0);
        let flags = libc::EV_ADD | libc::EV_CLEAR;
        apply_changes(
            &self.kqueue,
            &mut [
                change(ident, libc::EVFILT_READ, flags, 0, token)?,
                change(ident, libc::EVFILT_WRITE, flags, 0, token)?,
            ],
        )
    }

    /// Reports `listener`'s clients as [`LISTENER_TOKEN`], while any waits.
    pub(super) fn watch_listener(&self, listener: &mut Listener) -> IoResult<()> {
        apply_changes(
            &self.kqueue,
            &mut [change(
                ident(&listener.0),
                libc::EVFILT_READ,
                libc::EV_ADD,
                0,
                LISTENER_TOKEN,
            )?],
        )
    }

    pub(super) fn unwatch_listener(&self, listener: &mut Listener) -> IoResult<()> {
        apply_changes(
            &self.kqueue,
            &mut [change(
                ident(&listener.0),
                libc::EVFILT_READ,
                libc::EV_DELETE,
                0,
                LISTENER_TOKEN,
            )?],
        )
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
        apply_changes(
            &self.kqueue,
            &mut [change(
                WAKE_IDENT,
                libc::EVFILT_USER,
                0,
                libc::NOTE_TRIGGER,
                WAKE_TOKEN,
            )?],
        )
    }
}

impl Waiter {
    /// Waits for events or a wake until `timeout` (`None`: forever), or an
    /// interrupt; `tokens` are then the listener's and streams' events, each
    /// once.
    ///
    /// The wake's `EV_CLEAR` resets it once reported.
    pub(super) fn wait(
        &mut self,
        tokens: &mut Vec<u64>,
        timeout: Option<Duration>,
    ) -> IoResult<()> {
        tokens.clear();
        // Past `kevent`'s range: forever.
        let timeout = timeout
            .filter(|timeout| timeout.as_secs() <= MAX_WAIT_SECONDS)
            .map(|timeout| libc::timespec {
                tv_sec: libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX),
                tv_nsec: libc::c_long::from(timeout.subsec_nanos()),
            });
        let timeout_ptr = timeout.as_ref().map_or(ptr::null(), ptr::from_ref);
        // Here, not in the waiter, which moves to the thread: raw pointers
        // in `udata` are not `Send`.
        let mut events = [empty_event(); MAX_EVENTS];
        let capacity = libc::c_int::try_from(events.len()).map_err(|_| Errno::INVAL)?;
        // SAFETY: `events` outlives the call, which writes at most
        // `capacity` events, its length, to it; `timeout`, if any, outlives
        // the call too.
        let len = unsafe {
            libc::kevent(
                self.kqueue.as_raw_fd(),
                ptr::null(),
                0,
                events.as_mut_ptr(),
                capacity,
                timeout_ptr,
            )
        };
        let len = if let Ok(len) = usize::try_from(len) {
            len
        } else {
            let error = Error::last_os_error();
            if error.kind() != ErrorKind::Interrupted {
                return Err(error);
            }
            0
        };
        for event in &events[..len] {
            match event.udata.addr() as u64 {
                WAKE_TOKEN => {}
                // A stream reports its read and write filters separately.
                token if !tokens.contains(&token) => tokens.push(token),
                _ => {}
            }
        }
        Ok(())
    }
}

/// Applies `changes`, each with `EV_RECEIPT`, and fails with the first
/// change's error.
fn apply_changes(kqueue: &OwnedFd, changes: &mut [libc::kevent]) -> IoResult<()> {
    for change in changes.iter_mut() {
        change.flags |= libc::EV_RECEIPT;
    }
    let count = libc::c_int::try_from(changes.len()).map_err(|_| Errno::INVAL)?;
    let changes_ptr = changes.as_mut_ptr();
    let now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        // SAFETY: `changes` outlives the call, which reads `count` changes
        // from it and, each change asking for a receipt, writes as many
        // receipts back to it; `now` outlives the call.
        let result = unsafe {
            libc::kevent(
                kqueue.as_raw_fd(),
                changes_ptr,
                count,
                changes_ptr,
                count,
                &raw const now,
            )
        };
        if result >= 0 {
            break;
        }
        let error = Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error);
        }
    }
    for receipt in changes.iter() {
        // A receipt reports success as error 0.
        if receipt.flags & libc::EV_ERROR != 0 && receipt.data != 0 {
            let error = i32::try_from(receipt.data).map_err(|_| Errno::INVAL)?;
            return Err(Error::from_raw_os_error(error));
        }
    }
    Ok(())
}

/// A kqueue change for `ident` and `filter`, reporting events as `token`,
/// which the event's pointer-sized user data holds.
fn change(
    ident: usize,
    filter: i16,
    flags: u16,
    filter_flags: u32,
    token: u64,
) -> IoResult<libc::kevent> {
    let token = usize::try_from(token).map_err(|_| Error::from(ErrorKind::InvalidInput))?;
    Ok(libc::kevent {
        ident,
        filter,
        flags,
        fflags: filter_flags,
        data: 0,
        // An integer the kernel stores and returns, never a pointer.
        udata: ptr::without_provenance_mut(token),
    })
}

fn empty_event() -> libc::kevent {
    libc::kevent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: ptr::null_mut(),
    }
}

/// `fd`'s kqueue identifier: its descriptor, which is never negative.
#[allow(clippy::cast_sign_loss)]
fn ident(fd: &OwnedFd) -> usize {
    fd.as_raw_fd() as usize
}

fn retry<T>(mut f: impl FnMut() -> rustix::io::Result<T>) -> rustix::io::Result<T> {
    loop {
        match f() {
            Err(Errno::INTR) => {}
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    //! What the macOS module provides beyond what the bridge's tests show.

    use super::*;

    const NO_TOKENS: [u64; 0] = [];

    /// A connected pair: the bridge's stream, and the peer's, both through
    /// this module, and the listener's bound path.
    fn pair() -> (Stream, Stream, Listener, BoundPath, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let (mut listener, bound) = Listener::bind(&dir.path().join("pair"), 1).unwrap();
        let (peer, pending) = Stream::connect(bound.path()).unwrap();
        assert!(!pending);
        let stream = listener.accept().unwrap();
        (stream, peer, listener, bound, dir)
    }

    fn assert_nonblocking_and_close_on_exec(fd: &OwnedFd) {
        assert!(
            rustix::io::fcntl_getfd(fd)
                .unwrap()
                .contains(FdFlags::CLOEXEC)
        );
        assert!(
            rustix::fs::fcntl_getfl(fd)
                .unwrap()
                .contains(rustix::fs::OFlags::NONBLOCK)
        );
    }

    #[test]
    fn sockets_are_nonblocking_and_close_on_exec() {
        let (stream, peer, listener, _bound, _dir) = pair();
        for fd in [&stream.0, &peer.0, &listener.0] {
            assert_nonblocking_and_close_on_exec(fd);
        }
    }

    /// A peer gone fails a send with `EPIPE`. Rust's runtime ignores
    /// `SIGPIPE`, so this does not show that the send raises none.
    #[test]
    fn sends_to_a_closed_peer_fail_with_broken_pipe() {
        let (mut stream, peer, _listener, _bound, _dir) = pair();
        drop(peer);
        let error = stream.send(b"x").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::BrokenPipe);
    }

    /// macOS has no `POLLRDHUP`: the peer's end of sending alone is an end.
    #[test]
    fn a_peer_s_write_shutdown_is_an_end() {
        let (mut stream, peer, _listener, _bound, _dir) = pair();
        assert!(!stream.poll_now().ended);
        assert!(stream.poll_now().writable);
        peer.shutdown(Shutdown::Write);
        assert!(stream.poll_now().ended);
    }

    #[test]
    fn a_full_listener_backlog_refuses_connects() {
        let (_stream, _peer, _listener, bound, _dir) = pair();
        // Backlog 1: one connect queues, the next is refused at once.
        let mut queued = Vec::new();
        let refused = loop {
            match Stream::connect(bound.path()) {
                Ok((stream, pending)) => {
                    assert!(!pending);
                    queued.push(stream);
                    assert!(queued.len() < 16, "never refused");
                }
                Err(error) => break error,
            }
        };
        assert_eq!(refused.kind(), ErrorKind::ConnectionRefused);
    }

    /// An end with data unread is reported, as `end_unwatched` assumes.
    #[test]
    fn ends_are_reported_while_data_waits() {
        let (mut stream, mut peer, _listener, _bound, _dir) = pair();
        let (poller, mut waiter) = Poller::new().unwrap();
        poller.add_stream(&mut stream, 7, false).unwrap();
        let mut tokens = Vec::new();
        // Room, once.
        waiter.wait(&mut tokens, Some(Duration::ZERO)).unwrap();
        assert_eq!(tokens, [7]);
        waiter.wait(&mut tokens, Some(Duration::ZERO)).unwrap();
        assert_eq!(tokens, NO_TOKENS);
        peer.send(b"data").unwrap();
        waiter
            .wait(&mut tokens, Some(Duration::from_secs(10)))
            .unwrap();
        assert_eq!(tokens, [7]);
        peer.shutdown(Shutdown::Write);
        waiter
            .wait(&mut tokens, Some(Duration::from_secs(10)))
            .unwrap();
        assert_eq!(tokens, [7]);
        assert!(stream.has_data());
    }

    #[test]
    fn wakes_are_reported_once_and_not_as_tokens() {
        let (poller, mut waiter) = Poller::new().unwrap();
        let mut tokens = vec![9];
        poller.wake().unwrap();
        poller.wake().unwrap();
        let start = std::time::Instant::now();
        waiter
            .wait(&mut tokens, Some(Duration::from_secs(10)))
            .unwrap();
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_eq!(tokens, NO_TOKENS);
        let start = std::time::Instant::now();
        waiter
            .wait(&mut tokens, Some(Duration::from_millis(20)))
            .unwrap();
        assert!(start.elapsed() >= Duration::from_millis(20));
    }

    /// `kevent` fails a timeout past `MAX_WAIT_SECONDS`; such a wait is
    /// forever, until a wake.
    #[test]
    fn waits_past_kevent_s_range_are_forever() {
        let (poller, mut waiter) = Poller::new().unwrap();
        let mut tokens = Vec::new();
        for timeout in [
            Duration::from_secs(MAX_WAIT_SECONDS),
            Duration::from_secs(MAX_WAIT_SECONDS + 1),
            Duration::MAX,
        ] {
            poller.wake().unwrap();
            waiter.wait(&mut tokens, Some(timeout)).unwrap();
            assert_eq!(tokens, NO_TOKENS);
        }
    }

    #[test]
    fn the_listener_is_level_triggered_until_unwatched() {
        let dir = tempfile::tempdir().unwrap();
        let (mut listener, bound) = Listener::bind(&dir.path().join("l"), 4).unwrap();
        let (poller, mut waiter) = Poller::new().unwrap();
        poller.watch_listener(&mut listener).unwrap();
        let _client = Stream::connect(bound.path()).unwrap();
        let mut tokens = Vec::new();
        for _ in 0..2 {
            waiter
                .wait(&mut tokens, Some(Duration::from_secs(10)))
                .unwrap();
            assert_eq!(tokens, [LISTENER_TOKEN]);
        }
        poller.unwatch_listener(&mut listener).unwrap();
        waiter.wait(&mut tokens, Some(Duration::ZERO)).unwrap();
        assert_eq!(tokens, NO_TOKENS);
        poller.watch_listener(&mut listener).unwrap();
        waiter.wait(&mut tokens, Some(Duration::ZERO)).unwrap();
        assert_eq!(tokens, [LISTENER_TOKEN]);
        listener.accept().unwrap();
        waiter.wait(&mut tokens, Some(Duration::ZERO)).unwrap();
        assert_eq!(tokens, NO_TOKENS);
    }
}
