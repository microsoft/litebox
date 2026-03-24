// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Cross-platform socket compatibility layer.
//!
//! Uses `std` types (`TcpStream`, `UnixStream`, `TcpListener`) wherever
//! possible.  Raw FFI is limited to operations with no `std` equivalent:
//! `poll`, `MSG_PEEK` recv, non-blocking connect, and `getsockopt(SO_ERROR)`.

use std::io::{self, Read, Write};
use std::net::{TcpStream, UdpSocket};

// ---------------------------------------------------------------------------
// Platform-specific raw socket type (needed only for poll)
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub type RawSock = std::os::unix::io::RawFd;

#[cfg(windows)]
pub type RawSock = usize; // SOCKET

// ---------------------------------------------------------------------------
// AsRawSock — unified raw-socket accessor
// ---------------------------------------------------------------------------

/// Trait for obtaining the platform raw socket descriptor from any std socket.
pub trait AsRawSock {
    fn as_raw_sock(&self) -> RawSock;
}

macro_rules! impl_as_raw_sock {
    ($ty:ty) => {
        impl AsRawSock for $ty {
            fn as_raw_sock(&self) -> RawSock {
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    self.as_raw_fd()
                }
                #[cfg(windows)]
                {
                    use std::os::windows::io::AsRawSocket;
                    self.as_raw_socket() as RawSock
                }
            }
        }
    };
}

impl_as_raw_sock!(TcpStream);
impl_as_raw_sock!(std::net::TcpListener);
impl_as_raw_sock!(UdpSocket);

// ---------------------------------------------------------------------------
// IpcStream — owned, cross-platform IPC/TCP socket
// ---------------------------------------------------------------------------

/// Owned stream socket.
///
/// Wraps a stream socket on all platforms and implements `Read + Write` via
/// `std`.
pub enum IpcStream {
    /// TCP stream (cross-platform).
    Tcp(TcpStream),
    /// Unix domain stream.
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    /// Windows AF_UNIX stream socket, owned through `TcpStream`.
    #[cfg(windows)]
    Unix(TcpStream),
}

impl IpcStream {
    /// Construct from a `TcpStream` (cross-platform).
    pub fn from_tcp_stream(stream: TcpStream) -> Self {
        Self::Tcp(stream)
    }

    /// Construct from an already-owned file descriptor (Unix only).
    #[cfg(unix)]
    pub fn from_owned_fd(fd: std::os::unix::io::OwnedFd) -> Self {
        Self::Unix(std::os::unix::net::UnixStream::from(fd))
    }

    /// Set the socket to non-blocking mode.
    pub fn set_nonblocking(&self, nonblock: bool) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.set_nonblocking(nonblock),
            #[cfg(unix)]
            Self::Unix(s) => s.set_nonblocking(nonblock),
            #[cfg(windows)]
            Self::Unix(s) => s.set_nonblocking(nonblock),
        }
    }

    /// Raw socket descriptor for use with [`poll_fds`].
    pub fn raw(&self) -> RawSock {
        match self {
            Self::Tcp(s) => s.as_raw_sock(),
            #[cfg(unix)]
            Self::Unix(s) => {
                use std::os::unix::io::AsRawFd;
                s.as_raw_fd()
            }
            #[cfg(windows)]
            Self::Unix(s) => s.as_raw_sock(),
        }
    }

    /// Peek at incoming data without consuming it (`MSG_PEEK`).
    ///
    /// Returns bytes peeked, or `Err` on failure.  On would-block the
    /// returned byte count is 0.
    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        let normalize = |result: io::Result<usize>| match result {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(0),
            other => other,
        };
        match self {
            Self::Tcp(s) => normalize(s.peek(buf)),
            #[cfg(unix)]
            Self::Unix(s) => {
                use std::os::unix::io::AsRawFd;
                // SAFETY: `s` is a valid open Unix socket, and `buf` points to
                // `buf.len()` bytes of writable memory. `MSG_PEEK` reads data
                // without consuming it.
                let ret = unsafe {
                    libc::recv(
                        s.as_raw_fd(),
                        buf.as_mut_ptr().cast::<libc::c_void>(),
                        buf.len(),
                        libc::MSG_PEEK,
                    )
                };
                normalize(if ret < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(ret as usize)
                })
            }
            #[cfg(windows)]
            Self::Unix(s) => normalize(s.peek(buf)),
        }
    }
}

impl Read for IpcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            Self::Unix(s) => s.read(buf),
            #[cfg(windows)]
            Self::Unix(s) => s.read(buf),
        }
    }
}

impl Write for IpcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            Self::Unix(s) => s.write(buf),
            #[cfg(windows)]
            Self::Unix(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            #[cfg(unix)]
            Self::Unix(s) => s.flush(),
            #[cfg(windows)]
            Self::Unix(s) => s.flush(),
        }
    }
}

impl AsRawSock for IpcStream {
    fn as_raw_sock(&self) -> RawSock {
        self.raw()
    }
}

#[cfg(unix)]
impl std::os::unix::io::AsRawFd for IpcStream {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        match self {
            Self::Tcp(s) => std::os::unix::io::AsRawFd::as_raw_fd(s),
            Self::Unix(s) => std::os::unix::io::AsRawFd::as_raw_fd(s),
        }
    }
}

// ---------------------------------------------------------------------------
// IPC listener — UnixListener on Unix, TcpListener on Windows
// ---------------------------------------------------------------------------

/// Cross-platform IPC listener.
///
/// On Unix: wraps a `UnixListener` (Unix domain socket).
/// On Windows: wraps either a loopback TCP listener or a raw AF_UNIX socket
/// listener.
pub struct IpcListener {
    #[cfg(unix)]
    inner: std::os::unix::net::UnixListener,
    #[cfg(windows)]
    inner: WindowsIpcListener,
}

#[cfg(windows)]
enum WindowsIpcListener {
    Tcp(std::net::TcpListener),
    Unix(UnixSocketListener),
}

#[cfg(windows)]
struct UnixSocketListener {
    socket: RawSock,
    path: std::path::PathBuf,
}

#[cfg(windows)]
impl Drop for UnixSocketListener {
    fn drop(&mut self) {
        unsafe {
            win::closesocket(self.socket);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(windows)]
impl UnixSocketListener {
    fn accept(&self) -> io::Result<Option<IpcStream>> {
        use std::os::windows::io::FromRawSocket;

        let socket =
            unsafe { win::accept(self.socket, std::ptr::null_mut(), std::ptr::null_mut()) };
        if socket == win::INVALID_SOCKET {
            let err = unsafe { win::WSAGetLastError() };
            if err == win::WSAEWOULDBLOCK {
                return Ok(None);
            }
            return Err(io::Error::from_raw_os_error(err));
        }

        let stream = unsafe { TcpStream::from_raw_socket(socket as _) };
        stream.set_nonblocking(true)?;
        Ok(Some(IpcStream::Unix(stream)))
    }
}

impl IpcListener {
    /// Accept a connection.  Returns `Ok(None)` on would-block, `Ok(Some(..))` on
    /// success, or `Err(..)` on a real listener error (fd exhaustion, etc.).
    pub fn accept(&self) -> io::Result<Option<IpcStream>> {
        #[cfg(unix)]
        {
            match self.inner.accept() {
                Ok((stream, _)) => Ok(Some(IpcStream::Unix(stream))),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(e),
            }
        }
        #[cfg(windows)]
        {
            match &self.inner {
                WindowsIpcListener::Tcp(listener) => match listener.accept() {
                    Ok((stream, _)) => Ok(Some(IpcStream::Tcp(stream))),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
                    Err(e) => Err(e),
                },
                WindowsIpcListener::Unix(listener) => listener.accept(),
            }
        }
    }

    /// Raw socket for polling.
    pub fn raw(&self) -> RawSock {
        #[cfg(unix)]
        {
            self.inner.as_raw_sock()
        }
        #[cfg(windows)]
        {
            match &self.inner {
                WindowsIpcListener::Tcp(listener) => listener.as_raw_sock(),
                WindowsIpcListener::Unix(listener) => listener.socket,
            }
        }
    }
}

impl AsRawSock for IpcListener {
    fn as_raw_sock(&self) -> RawSock {
        self.raw()
    }
}

#[cfg(unix)]
impl_as_raw_sock!(std::os::unix::net::UnixListener);

#[cfg(unix)]
impl IpcListener {
    /// Bind to a Unix domain socket path.
    pub fn bind_unix(path: &std::path::Path) -> io::Result<Self> {
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        let listener = std::os::unix::net::UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        Ok(Self { inner: listener })
    }
}

#[cfg(windows)]
impl IpcListener {
    /// Bind to either a TCP loopback address or an AF_UNIX socket path.
    ///
    /// Only `127.0.0.1` and `[::1]` are accepted for TCP — the IPC listener
    /// must not be reachable off-host.
    pub fn bind_endpoint(endpoint: &str) -> io::Result<Self> {
        if let Ok(sock_addr) = endpoint.parse::<std::net::SocketAddr>() {
            if !sock_addr.ip().is_loopback() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "IPC listener must bind to loopback (127.0.0.1 / [::1]), got {endpoint}"
                    ),
                ));
            }
            let listener = std::net::TcpListener::bind(sock_addr)?;
            listener.set_nonblocking(true)?;
            return Ok(Self {
                inner: WindowsIpcListener::Tcp(listener),
            });
        }

        Self::bind_unix(endpoint)
    }

    fn bind_unix(path: &str) -> io::Result<Self> {
        let socket_path = std::path::Path::new(path);
        if socket_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("AF_UNIX socket path already exists: {path}"),
            ));
        }

        let (addr, addr_len) = win::sockaddr_un_from_path(path)?;
        let socket = unsafe {
            win::wsa_ensure_init();
            let socket = win::socket(i32::from(win::AF_UNIX), win::SOCK_STREAM, 0);
            if socket == win::INVALID_SOCKET {
                let err = win::WSAGetLastError();
                return Err(if err == win::WSAEAFNOSUPPORT {
                    io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Windows AF_UNIX is not available on this system",
                    )
                } else {
                    io::Error::from_raw_os_error(err)
                });
            }
            socket
        };

        let bind_ret = unsafe { win::bind(socket, (&raw const addr).cast(), addr_len) };
        if bind_ret != 0 {
            unsafe {
                win::closesocket(socket);
            }
            return Err(io::Error::from_raw_os_error(unsafe {
                win::WSAGetLastError()
            }));
        }
        let mut nonblock = 1;
        let nonblock_ret = unsafe { win::ioctlsocket(socket, win::FIONBIO as i32, &mut nonblock) };
        if nonblock_ret != 0 {
            unsafe {
                win::closesocket(socket);
            }
            let _ = std::fs::remove_file(socket_path);
            return Err(io::Error::from_raw_os_error(unsafe {
                win::WSAGetLastError()
            }));
        }
        let listen_ret = unsafe { win::listen(socket, 128) };
        if listen_ret != 0 {
            unsafe {
                win::closesocket(socket);
            }
            let _ = std::fs::remove_file(socket_path);
            return Err(io::Error::from_raw_os_error(unsafe {
                win::WSAGetLastError()
            }));
        }
        Ok(Self {
            inner: WindowsIpcListener::Unix(UnixSocketListener {
                socket,
                path: socket_path.to_path_buf(),
            }),
        })
    }
}

// ---------------------------------------------------------------------------
// Poll support (no std equivalent)
// ---------------------------------------------------------------------------

/// Portable poll file-descriptor entry.
#[repr(C)]
pub struct PollFd {
    pub fd: RawSock,
    pub events: i16,
    pub revents: i16,
}

// POSIX and WinSock use different bitmask values for poll events.
#[cfg(unix)]
pub const POLLIN: i16 = 0x0001;
#[cfg(unix)]
pub const POLLOUT: i16 = 0x0004;
#[cfg(unix)]
pub const POLLERR: i16 = 0x0008;
#[cfg(unix)]
pub const POLLHUP: i16 = 0x0010;

#[cfg(windows)]
pub const POLLIN: i16 = 0x0300; // POLLRDNORM | POLLRDBAND
#[cfg(windows)]
pub const POLLOUT: i16 = 0x0010; // POLLWRNORM
#[cfg(windows)]
pub const POLLERR: i16 = 0x0001;
#[cfg(windows)]
pub const POLLHUP: i16 = 0x0002;

/// Poll a set of sockets for readiness.
///
/// `timeout_ms`: negative = block forever, 0 = non-blocking, positive = ms.
pub fn poll_fds(fds: &mut [PollFd], timeout_ms: i32) -> i32 {
    #[cfg(unix)]
    {
        let ptr = fds.as_mut_ptr().cast::<libc::pollfd>();
        let nfds = fds.len() as libc::nfds_t;
        unsafe { libc::poll(ptr, nfds, timeout_ms) }
    }
    #[cfg(windows)]
    {
        let ptr = fds.as_mut_ptr().cast::<win::WSAPOLLFD>();
        let nfds = fds.len() as u32;
        unsafe { win::WSAPoll(ptr, nfds, timeout_ms) }
    }
}

/// Poll with sub-millisecond timeout (uses ppoll on Unix, WSAPoll on Windows).
pub fn poll_fds_timeout(fds: &mut [PollFd], timeout: std::time::Duration) -> i32 {
    #[cfg(unix)]
    {
        let ts = libc::timespec {
            tv_sec: timeout.as_secs() as libc::time_t,
            #[allow(clippy::cast_possible_wrap)]
            tv_nsec: timeout.subsec_nanos() as libc::c_long,
        };
        let ptr = fds.as_mut_ptr().cast::<libc::pollfd>();
        let nfds = fds.len() as libc::nfds_t;
        unsafe { libc::ppoll(ptr, nfds, &ts, std::ptr::null()) }
    }
    #[cfg(windows)]
    {
        // WSAPoll only supports millisecond resolution; round up so
        // sub-millisecond timeouts don't degrade into non-blocking polls.
        let ms = timeout.as_millis();
        #[allow(clippy::cast_possible_truncation)]
        let ms = if ms == 0 && !timeout.is_zero() {
            1
        } else {
            ms as i32
        };
        poll_fds(fds, ms)
    }
}

// ---------------------------------------------------------------------------
// Non-blocking recv / send on raw sockets
//
// Used by the IPC device (smoltcp Device trait) where only a RawSock is
// available.  Higher-level code should prefer IpcStream's Read/Write impls.
// ---------------------------------------------------------------------------

/// Flags for recv.
pub const MSG_PEEK: i32 = {
    #[cfg(unix)]
    {
        libc::MSG_PEEK
    }
    #[cfg(windows)]
    {
        0x2
    }
};

/// Non-blocking receive on a raw socket.  Returns bytes read, 0 for EOF, or
/// negative on error.
pub fn recv_nb(fd: RawSock, buf: &mut [u8], extra_flags: i32) -> isize {
    #[cfg(unix)]
    unsafe {
        libc::recv(
            fd,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
            extra_flags | libc::MSG_DONTWAIT,
        )
    }
    #[cfg(windows)]
    unsafe {
        #[allow(clippy::cast_possible_truncation)]
        let len = buf.len().min(i32::MAX as usize) as i32;
        let ret = win::recv(fd, buf.as_mut_ptr().cast(), len, extra_flags);
        ret as isize
    }
}

/// Non-blocking send on a raw socket.  Returns bytes sent or negative on
/// error.
pub fn send_nb(fd: RawSock, buf: &[u8], extra_flags: i32) -> isize {
    #[cfg(unix)]
    unsafe {
        libc::send(
            fd,
            buf.as_ptr().cast::<libc::c_void>(),
            buf.len(),
            extra_flags | libc::MSG_NOSIGNAL,
        )
    }
    #[cfg(windows)]
    unsafe {
        #[allow(clippy::cast_possible_truncation)]
        let len = buf.len().min(i32::MAX as usize) as i32;
        let ret = win::send(fd, buf.as_ptr().cast(), len, extra_flags);
        ret as isize
    }
}

/// Get the last socket error code.
pub fn last_socket_error() -> i32 {
    #[cfg(unix)]
    unsafe {
        *libc::__errno_location()
    }
    #[cfg(windows)]
    unsafe {
        win::WSAGetLastError()
    }
}

/// Check if the error code means "would block".
pub fn is_would_block(err: i32) -> bool {
    #[cfg(unix)]
    {
        err == libc::EAGAIN || err == libc::EWOULDBLOCK
    }
    #[cfg(windows)]
    {
        err == win::WSAEWOULDBLOCK
    }
}

// ---------------------------------------------------------------------------
// Non-blocking TCP connect (no std equivalent)
// ---------------------------------------------------------------------------

/// Start a non-blocking TCP connect.  Returns an `IpcStream::Tcp` wrapping
/// the connecting socket.
///
/// The caller must poll for `POLLOUT` and call [`check_connect`] to determine
/// when the connection completes.
pub fn start_nonblocking_connect(dest: &std::net::SocketAddr) -> Result<IpcStream, std::io::Error> {
    let std::net::SocketAddr::V4(v4) = dest else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only IPv4 supported",
        ));
    };

    #[cfg(unix)]
    {
        use std::os::unix::io::FromRawFd;
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let octets = v4.ip().octets();
        let sa = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: v4.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(octets),
            },
            sin_zero: [0; 8],
        };
        let ret = unsafe {
            libc::connect(
                fd,
                (&raw const sa).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno != libc::EINPROGRESS {
                unsafe { libc::close(fd) };
                return Err(io::Error::from_raw_os_error(errno));
            }
        }
        // Wrap the raw TCP fd in a std TcpStream for ownership + Read/Write.
        let tcp = unsafe { TcpStream::from_raw_fd(fd) };
        Ok(IpcStream::Tcp(tcp))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::FromRawSocket;
        unsafe {
            win::wsa_ensure_init();
            let s = win::socket(i32::from(win::AF_INET), win::SOCK_STREAM, 0);
            if s == win::INVALID_SOCKET {
                return Err(io::Error::from_raw_os_error(win::WSAGetLastError()));
            }
            let mut nonblock: u32 = 1;
            win::ioctlsocket(s, win::FIONBIO as i32, &mut nonblock);

            let octets = v4.ip().octets();
            let sa = win::SOCKADDR_IN {
                sin_family: win::AF_INET,
                sin_port: v4.port().to_be(),
                sin_addr: u32::from_ne_bytes(octets),
                sin_zero: [0; 8],
            };
            let ret = win::connect(
                s,
                (&sa as *const win::SOCKADDR_IN).cast(),
                std::mem::size_of::<win::SOCKADDR_IN>() as i32,
            );
            if ret != 0 {
                let err = win::WSAGetLastError();
                if err != win::WSAEWOULDBLOCK {
                    win::closesocket(s);
                    return Err(io::Error::from_raw_os_error(err));
                }
            }
            let tcp = TcpStream::from_raw_socket(s as u64);
            Ok(IpcStream::Tcp(tcp))
        }
    }
}

/// Check if a pending non-blocking connect has completed.
///
/// Returns `Some(Ok(()))` if connected, `Some(Err(e))` on failure,
/// `None` if still in progress.
pub fn check_connect(ipc: &IpcStream) -> Option<Result<(), io::Error>> {
    let fd = ipc.raw();
    let mut pfd = PollFd {
        fd,
        events: POLLOUT,
        revents: 0,
    };
    poll_fds(std::slice::from_mut(&mut pfd), 0);
    if pfd.revents & (POLLOUT | POLLERR | POLLHUP) == 0 {
        return None; // Still connecting.
    }

    // Read SO_ERROR to distinguish success from failure.
    #[cfg(unix)]
    {
        let mut err: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut err).cast::<libc::c_void>(),
                &raw mut len,
            );
        }
        if err != 0 {
            Some(Err(io::Error::from_raw_os_error(err)))
        } else {
            Some(Ok(()))
        }
    }
    #[cfg(windows)]
    unsafe {
        let mut err: i32 = 0;
        let mut len: i32 = i32::try_from(std::mem::size_of::<i32>()).expect("i32 size fits in i32");
        win::getsockopt(
            fd,
            win::SOL_SOCKET.cast_signed(),
            win::SO_ERROR.cast_signed(),
            (&raw mut err).cast(),
            &raw mut len,
        );
        if err != 0 {
            Some(Err(io::Error::from_raw_os_error(err)))
        } else {
            Some(Ok(()))
        }
    }
}

/// Convert an `IpcStream` into a blocking `TcpStream`.
///
/// Used for 9P local service connections where the stream is known to be TCP.
pub fn into_blocking_tcp_stream(ipc: IpcStream) -> TcpStream {
    match ipc {
        IpcStream::Tcp(s) => {
            let _ = s.set_nonblocking(false);
            s
        }
        #[cfg(unix)]
        IpcStream::Unix(s) => {
            // The local-service path always uses loopback TCP pairs,
            // so this branch is unreachable in practice.  Convert via fd
            // as a safety net.
            use std::os::unix::io::{FromRawFd, IntoRawFd};
            let fd = s.into_raw_fd();
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
            }
            unsafe { TcpStream::from_raw_fd(fd) }
        }
        #[cfg(windows)]
        IpcStream::Unix(s) => {
            let _ = s.set_nonblocking(false);
            s
        }
    }
}

// ---------------------------------------------------------------------------
// Windows WinSock FFI (poll, non-blocking connect, getsockopt, recv/send)
// ---------------------------------------------------------------------------

#[cfg(windows)]
#[allow(
    non_camel_case_types,
    non_snake_case,
    dead_code,
    clippy::upper_case_acronyms
)]
mod win {
    use std::{io, sync::Once};

    pub const AF_INET: u16 = 2;
    pub const AF_UNIX: u16 = 1;
    pub const SOCK_STREAM: i32 = 1;
    pub const INVALID_SOCKET: usize = !0;
    pub const FIONBIO: u32 = 0x8004_667E;
    pub const SOL_SOCKET: u32 = 0xFFFF;
    pub const SO_ERROR: u32 = 0x1007;
    pub const WSAEAFNOSUPPORT: i32 = 10047;
    pub const WSAEWOULDBLOCK: i32 = 10035;

    #[repr(C)]
    pub struct WSADATA {
        pub wVersion: u16,
        pub wHighVersion: u16,
        pub iMaxSockets: u16,
        pub iMaxUdpDg: u16,
        pub lpVendorInfo: *mut u8,
        pub szDescription: [u8; 257],
        pub szSystemStatus: [u8; 129],
    }

    #[repr(C)]
    pub struct SOCKADDR_IN {
        pub sin_family: u16,
        pub sin_port: u16,
        pub sin_addr: u32,
        pub sin_zero: [u8; 8],
    }

    #[repr(C)]
    pub struct SOCKADDR_UN {
        pub sun_family: u16,
        pub sun_path: [u8; 108],
    }

    #[repr(C)]
    pub struct WSAPOLLFD {
        pub fd: usize, // SOCKET
        pub events: i16,
        pub revents: i16,
    }

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        pub fn WSAStartup(wVersionRequested: u16, lpWSAData: *mut WSADATA) -> i32;
        pub fn WSAGetLastError() -> i32;
        pub fn WSAPoll(fdArray: *mut WSAPOLLFD, fds: u32, timeout: i32) -> i32;
        pub fn socket(af: i32, r#type: i32, protocol: i32) -> usize;
        pub fn closesocket(s: usize) -> i32;
        pub fn connect(s: usize, name: *const u8, namelen: i32) -> i32;
        pub fn bind(s: usize, name: *const u8, namelen: i32) -> i32;
        pub fn listen(s: usize, backlog: i32) -> i32;
        pub fn accept(s: usize, addr: *mut u8, addrlen: *mut i32) -> usize;
        pub fn recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32;
        pub fn send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32;
        pub fn ioctlsocket(s: usize, cmd: i32, argp: *mut u32) -> i32;
        pub fn getsockopt(
            s: usize,
            level: i32,
            optname: i32,
            optval: *mut u8,
            optlen: *mut i32,
        ) -> i32;
    }

    static WSA_INIT: Once = Once::new();

    /// Ensure Winsock is initialized (idempotent).
    pub fn wsa_ensure_init() {
        WSA_INIT.call_once(|| unsafe {
            let mut data = std::mem::zeroed::<WSADATA>();
            WSAStartup(0x0202, &raw mut data);
        });
    }

    pub fn sockaddr_un_from_path(path: &str) -> io::Result<(SOCKADDR_UN, i32)> {
        let path_bytes = path.as_bytes();
        if path_bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AF_UNIX path cannot be empty",
            ));
        }
        if path_bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AF_UNIX path cannot contain NUL bytes",
            ));
        }
        if path_bytes.len() >= 108 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "AF_UNIX path too long ({} bytes, max 107)",
                    path_bytes.len()
                ),
            ));
        }

        let mut addr = SOCKADDR_UN {
            sun_family: AF_UNIX,
            sun_path: [0; 108],
        };
        addr.sun_path[..path_bytes.len()].copy_from_slice(path_bytes);
        let addr_len =
            i32::try_from(std::mem::size_of::<u16>() + path_bytes.len() + 1).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "AF_UNIX path length overflow")
            })?;
        Ok((addr, addr_len))
    }
}
