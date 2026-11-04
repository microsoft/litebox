// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The bridge's host sockets on Windows: Unix (`AF_UNIX`) streams, which the
//! thread waits for with mio (AFD polls on an I/O completion port), woken
//! through a [`Waker`]. The items are the Linux module's.
//!
//! mio wraps the sockets as TCP ones: never make TCP-only calls on them.
//! It reports each kind of readiness once, until the socket is rearmed, and
//! a rearm reports a lasting state (unread data, an end) again at once. A
//! report due before a rearm may still come after it and disarm the socket
//! again, so a stream rearms after each read, when a send would block, and
//! at each [`Stream::poll_now`], which the provider makes of every stream
//! after every wakeup. It watches only for what has not happened yet: data
//! while none waits, room while there is none, and nothing once ended. mio
//! watches for the end only with data, so while data waits, the end goes
//! unwatched, and the thread polls for it (see [`Stream::end_unwatched`]).

use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::Shutdown;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{AsRawHandle as _, AsRawSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use litebox_broker_platform_windows_userland::{WindowsInstant, WindowsTimeProvider};
use litebox_platform::time::TimeProvider as _;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Registry, Token, Waker};
use socket2::{Domain, SockAddr, SockRef, Type};
use windows_sys::Win32::Networking::WinSock::{
    FIONREAD, MSG_PEEK, POLLERR, POLLHUP, POLLRDNORM, POLLWRNORM, SOCKET, SOCKET_ERROR,
    WSAGetLastError, WSAPOLLFD, WSAPoll, ioctlsocket, recv, send,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FileAttributeTagInfo, FileDispositionInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, SetFileInformationByHandle,
};

use super::{LISTENER_TOKEN, MAX_EVENTS, Readiness, WAKE_TOKEN};
use crate::fine_timer::FineTimer;

/// The bridge's monotonic clock.
pub(super) type Instant = WindowsInstant;

pub(super) fn now() -> Instant {
    WindowsTimeProvider.now()
}

/// How a guest's close shuts the stream down before dropping the host's
/// unread data: sending only, as receives fail once both are shut down,
/// which would leave the data to reset the host.
pub(super) const CLOSE_SHUTDOWN: Shutdown = Shutdown::Write;

/// The longest Unix socket path, in bytes: socket2 needs a NUL within
/// `SOCKADDR_UN`'s 108.
pub(super) const MAX_SOCKET_PATH: usize = 107;

/// The reparse tag of a Unix socket's file (`IO_REPARSE_TAG_AF_UNIX`).
const IO_REPARSE_TAG_AF_UNIX: u32 = 0x8000_0023;

#[allow(clippy::cast_possible_truncation)]
const TAG_INFO_LENGTH: u32 = size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32;

#[allow(clippy::cast_possible_truncation)]
const DISPOSITION_INFO_LENGTH: u32 = size_of::<FILE_DISPOSITION_INFO>() as u32;

/// `PATH`, as the bridge bound it: deleted when dropped if still that socket
/// (see the [bridge's](super) access control).
pub(super) struct BoundPath {
    path: PathBuf,
    /// Its volume's serial number and its file index, right after the bind.
    identity: (u32, u64),
}

impl BoundPath {
    fn identify(path: &Path) -> IoResult<Self> {
        let identity = socket_identity(&open_entry(path)?)?
            .ok_or_else(|| Error::new(ErrorKind::AlreadyExists, "replaced right after the bind"))?;
        Ok(Self {
            path: path.to_owned(),
            identity,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BoundPath {
    /// Deletes through a handle to the file it identified, so it never
    /// deletes another.
    fn drop(&mut self) {
        if let Ok(file) = open_entry(&self.path)
            && socket_identity(&file).is_ok_and(|identity| identity == Some(self.identity))
        {
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            // SAFETY: `disposition` outlives the call, which reads only its
            // `DISPOSITION_INFO_LENGTH` bytes; `file` keeps the handle open.
            // The entry goes once every handle to it is closed.
            unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle(),
                    FileDispositionInfo,
                    (&raw const disposition).cast(),
                    DISPOSITION_INFO_LENGTH,
                );
            }
        }
    }
}

/// Opens the entry at `path` itself, not a reparse point's target, to read
/// its attributes or delete it.
fn open_entry(path: &Path) -> IoResult<File> {
    OpenOptions::new()
        .access_mode(DELETE | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

/// The identity of `file`, if a Unix socket's.
fn socket_identity(file: &File) -> IoResult<Option<(u32, u64)>> {
    let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: `tag` outlives the call, which writes at most
    // `TAG_INFO_LENGTH` bytes, its size, into it; `file` keeps the handle
    // open.
    let tagged = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&raw mut tag).cast(),
            TAG_INFO_LENGTH,
        )
    };
    if tagged == 0 {
        return Err(Error::last_os_error());
    }
    // The tag is defined only for a reparse point.
    if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        || tag.ReparseTag != IO_REPARSE_TAG_AF_UNIX
    {
        return Ok(None);
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `information` outlives the call, which writes only it; `file`
    // keeps the handle open.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) } == 0 {
        return Err(Error::last_os_error());
    }
    let index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok(Some((information.dwVolumeSerialNumber, index)))
}

/// A nonblocking listening socket.
pub(super) struct Listener(TcpListener);

impl Listener {
    /// Listens at `path`, which must not exist.
    pub(super) fn bind(path: &Path, backlog: i32) -> IoResult<(Self, BoundPath)> {
        let address = SockAddr::unix(path)?;
        let listener = socket2::Socket::new(Domain::UNIX, Type::STREAM, None)?;
        listener.set_nonblocking(true)?;
        listener.bind(&address)?;
        // Removes `path` from here on, if setup fails.
        let bound = BoundPath::identify(path)?;
        listener.listen(backlog)?;
        Ok((Self(TcpListener::from_std(listener.into())), bound))
    }

    /// The next client's stream; `WouldBlock` if none waits.
    pub(super) fn accept(&mut self) -> IoResult<Stream> {
        // Not mio's: it fails to parse a Unix socket's address, dropping the
        // client.
        let (stream, _) = SockRef::from(&self.0).accept()?;
        stream.set_nonblocking(true)?;
        Ok(Stream::new(stream))
    }
}

/// A nonblocking connected stream.
pub(super) struct Stream {
    source: TcpStream,
    /// The registry and token it is watched with, once it is.
    registration: Option<(Registry, Token)>,
    /// No room, as the last poll or a send that would block found, or the
    /// connect is in progress: watched for room too, until a poll finds some
    /// or the stream's end.
    write_blocked: bool,
    /// See [`Stream::end_unwatched`].
    end_unwatched: bool,
}

impl Stream {
    fn new(socket: socket2::Socket) -> Self {
        Self {
            source: TcpStream::from_std(socket.into()),
            registration: None,
            write_blocked: false,
            end_unwatched: false,
        }
    }

    /// Connects to `path`; the stream, and whether the connect is still in
    /// progress, which it is here even to a listener with room.
    pub(super) fn connect(path: &Path) -> IoResult<(Self, bool)> {
        let address = SockAddr::unix(path)?;
        let stream = socket2::Socket::new(Domain::UNIX, Type::STREAM, None)?;
        stream.set_nonblocking(true)?;
        let pending = match stream.connect(&address) {
            Ok(()) => false,
            Err(error) if error.kind() == ErrorKind::WouldBlock => true,
            Err(error) => return Err(error),
        };
        Ok((Self::new(stream), pending))
    }

    /// Reads into `buffer`: `Ok(0)` at EOF, `WouldBlock` if nothing waits.
    pub(super) fn recv(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        let received = self.receive(buffer, 0);
        match &received {
            Ok(len) if *len > 0 => self.rearm(),
            Err(error) if error.kind() == ErrorKind::WouldBlock => self.rearm(),
            // An end or a failure lasts: a rearm would report it at once.
            _ => {}
        }
        received
    }

    /// As [`Stream::recv`], leaving the data to read.
    pub(super) fn peek(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        let peeked = self.receive(buffer, MSG_PEEK);
        if peeked
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::WouldBlock)
        {
            self.rearm();
        }
        peeked
    }

    /// Writes from `bytes`, `WouldBlock` if there is no room; a peer gone
    /// fails it, without a signal.
    pub(super) fn send(&mut self, bytes: &[u8]) -> IoResult<usize> {
        // Winsock takes an `i32` length; a send may take fewer bytes anyway.
        let len = i32::try_from(bytes.len()).unwrap_or(i32::MAX);
        // SAFETY: `bytes` outlives the call, which reads at most `len` of
        // them and is not overlapped.
        let sent = unsafe { send(raw_socket(&self.source), bytes.as_ptr(), len, 0) };
        if sent == SOCKET_ERROR {
            let error = last_error();
            if error.kind() == ErrorKind::WouldBlock {
                self.write_blocked = true;
                self.rearm();
            }
            return Err(error);
        }
        Ok(usize::try_from(sent).unwrap_or_default())
    }

    /// Shuts the stream down `how`; a stream that failed already is ended.
    pub(super) fn shutdown(&self, how: Shutdown) {
        let _ = SockRef::from(&self.source).shutdown(how);
    }

    /// Whether data waits to be read.
    pub(super) fn has_data(&self) -> bool {
        let mut queued = 0_u32;
        // SAFETY: `queued` outlives the call, which writes only it.
        let result = unsafe { ioctlsocket(raw_socket(&self.source), FIONREAD, &raw mut queued) };
        result != SOCKET_ERROR && queued > 0
    }

    /// The stream's readiness now, rearming it for what it does not show yet
    /// (see the module docs); a failure to poll is an end.
    pub(super) fn poll_now(&mut self) -> Readiness {
        // Winsock reports a failed connect only to a poll for data.
        let mut sockets = [WSAPOLLFD {
            fd: raw_socket(&self.source),
            events: POLLRDNORM | POLLWRNORM,
            revents: 0,
        }];
        // SAFETY: `sockets` outlives the call, which polls without waiting
        // and writes only the entries' `revents`.
        let flags = if unsafe { WSAPoll(sockets.as_mut_ptr(), 1, 0) } == SOCKET_ERROR {
            POLLERR
        } else {
            sockets[0].revents
        };
        let readiness = Readiness {
            ended: flags & (POLLHUP | POLLERR) != 0,
            writable: flags & POLLWRNORM != 0,
        };
        // A send that succeeds may leave no room, which only a poll then
        // finds.
        self.write_blocked = !readiness.writable && !readiness.ended;
        if !readiness.ended {
            self.rearm();
        }
        readiness
    }

    /// Receives into `buffer` with `flags`.
    fn receive(&self, buffer: &mut [u8], flags: i32) -> IoResult<usize> {
        // Winsock takes an `i32` length; a receive may return fewer bytes
        // anyway.
        let len = i32::try_from(buffer.len()).unwrap_or(i32::MAX);
        // SAFETY: `buffer` outlives the call, which writes at most `len` of
        // its bytes and is not overlapped.
        let received = unsafe { recv(raw_socket(&self.source), buffer.as_mut_ptr(), len, flags) };
        if received == SOCKET_ERROR {
            return Err(last_error());
        }
        Ok(usize::try_from(received).unwrap_or_default())
    }

    /// Has mio report the stream's next change: data or its end, unless data
    /// waits, which a rearm would report at once, and room while there is
    /// none. A failed rearm loses events until the next one.
    fn rearm(&mut self) {
        let has_data = self.has_data();
        // Watching for the end is watching for data too.
        self.end_unwatched = has_data;
        let interest = match (has_data, self.write_blocked) {
            (false, false) => Interest::READABLE,
            (false, true) => Interest::READABLE | Interest::WRITABLE,
            (true, true) => Interest::WRITABLE,
            // Readable and writable already.
            (true, false) => return,
        };
        if let Some((registry, token)) = &self.registration {
            let _ = registry.reregister(&mut self.source, *token, interest);
        }
    }

    /// Whether the stream's end may go unwatched: data waits, which watching
    /// for the end would report at once. The thread must then poll for the
    /// end.
    pub(super) fn end_unwatched(&self) -> bool {
        self.end_unwatched
    }
}

/// What the thread waits for, and its wakeup; the bridge's.
pub(super) struct Poller {
    registry: Registry,
    /// Wakes the waiter under [`WAKE_TOKEN`].
    waker: Waker,
}

/// The thread's side of a [`Poller`].
pub(super) struct Waiter {
    poll: Poll,
    events: Events,
    /// Keeps the provider's quick retries from stretching to the default
    /// timer resolution.
    fine_timer: FineTimer,
}

impl Poller {
    pub(super) fn new() -> IoResult<(Self, Waiter)> {
        let poll = Poll::new()?;
        let registry = poll.registry().try_clone()?;
        let waker = Waker::new(&registry, token(WAKE_TOKEN)?)?;
        let waiter = Waiter {
            poll,
            events: Events::with_capacity(MAX_EVENTS),
            fine_timer: FineTimer::new(),
        };
        Ok((Self { registry, waker }, waiter))
    }

    /// Reports `stream`'s events as `token`: data and its end, and, if
    /// `connecting`, its connect's completion.
    pub(super) fn add_stream(
        &self,
        stream: &mut Stream,
        token: u64,
        connecting: bool,
    ) -> IoResult<()> {
        let token = self::token(token)?;
        let registry = self.registry.try_clone()?;
        stream.write_blocked = connecting;
        let interest = if connecting {
            Interest::READABLE | Interest::WRITABLE
        } else {
            Interest::READABLE
        };
        self.registry
            .register(&mut stream.source, token, interest)?;
        stream.registration = Some((registry, token));
        Ok(())
    }

    /// Reports `listener`'s clients as [`LISTENER_TOKEN`], once, until
    /// rearmed.
    pub(super) fn watch_listener(&self, listener: &mut Listener) -> IoResult<()> {
        self.registry
            .register(&mut listener.0, token(LISTENER_TOKEN)?, Interest::READABLE)
    }

    pub(super) fn unwatch_listener(&self, listener: &mut Listener) -> IoResult<()> {
        self.registry.deregister(&mut listener.0)
    }

    /// Keeps reporting `listener`'s waiting clients after accepts stopped,
    /// as a level-triggered listener would.
    pub(super) fn rearm_listener(&self, listener: &mut Listener) -> IoResult<()> {
        self.registry
            .reregister(&mut listener.0, token(LISTENER_TOKEN)?, Interest::READABLE)
    }

    /// Ends the thread's wait, now or at its next.
    pub(super) fn wake(&self) -> IoResult<()> {
        self.waker.wake()
    }
}

impl Waiter {
    /// Waits for events or a wake until `timeout` (`None`: forever), or an
    /// interrupt; `tokens` are then the listener's and streams' events.
    ///
    /// Each wake is a completion that reporting [`WAKE_TOKEN`] dequeues.
    pub(super) fn wait(
        &mut self,
        tokens: &mut Vec<u64>,
        timeout: Option<Duration>,
    ) -> IoResult<()> {
        tokens.clear();
        self.fine_timer.adjust(timeout);
        match self.poll.poll(&mut self.events, timeout) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
        tokens.extend(
            self.events
                .iter()
                .map(|event| event.token().0 as u64)
                .filter(|&token| token != WAKE_TOKEN),
        );
        Ok(())
    }
}

#[allow(clippy::cast_possible_truncation)]
fn raw_socket(socket: &impl AsRawSocket) -> SOCKET {
    // A `SOCKET` is pointer-sized, which on x86_64 holds every raw socket.
    socket.as_raw_socket() as SOCKET
}

/// The calling thread's last Winsock error.
fn last_error() -> Error {
    // SAFETY: `WSAGetLastError` takes no arguments and only reads the calling
    // thread's last error.
    Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

fn token(token: u64) -> IoResult<Token> {
    usize::try_from(token)
        .map(Token)
        .map_err(|_| Error::from(ErrorKind::InvalidInput))
}
