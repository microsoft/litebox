// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The Windows host: sockets through socket2 and Winsock, and events from
//! mio, which polls sockets through AFD and wakes through its completion
//! port. Where Winsock falls short of the host contract, the code that makes
//! up the difference says how.

use std::cell::Cell;
use std::fmt;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4};
use std::os::windows::io::AsRawSocket;
use std::process::{Child, Command};
use std::ptr::{self, NonNull};
use std::sync::{PoisonError, RwLock};
use std::time::Duration;

use litebox_broker_core::BrokerError;
use litebox_broker_protocol::socket::MAX_UDP_DATAGRAM_SIZE;
use mio::net::{TcpListener, TcpStream, UdpSocket};
use mio::{Poll, Registry, Token, Waker};
use socket2::{Domain, Protocol, SockAddr, SockRef, Type};
use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, CMSGHDR, FIONREAD, IN_ADDR, IN_ADDR_0, IN_PKTINFO, IP_PKTINFO, IPPROTO_IP,
    LPFN_WSARECVMSG, MSG_BCAST, MSG_MCAST, MSG_PEEK, POLLERR, POLLRDNORM, POLLWRNORM,
    SIO_GET_EXTENSION_FUNCTION_POINTER, SIO_UDP_CONNRESET, SIO_UDP_NETRESET, SO_CONNECT_TIME,
    SO_EXCLUSIVEADDRUSE, SOCKADDR_IN, SOCKET, SOCKET_ERROR, SOL_SOCKET, WSA_NOT_ENOUGH_MEMORY,
    WSABUF, WSAEACCES, WSAEADDRINUSE, WSAEADDRNOTAVAIL, WSAEAFNOSUPPORT, WSAEALREADY,
    WSAECONNABORTED, WSAECONNREFUSED, WSAECONNRESET, WSAEHOSTUNREACH, WSAEINPROGRESS, WSAEINTR,
    WSAEINVAL, WSAEISCONN, WSAEMFILE, WSAEMSGSIZE, WSAENETRESET, WSAENETUNREACH, WSAENOBUFS,
    WSAENOTCONN, WSAEOPNOTSUPP, WSAESHUTDOWN, WSAETIMEDOUT, WSAEWOULDBLOCK, WSAGetLastError,
    WSAID_WSARECVMSG, WSAIoctl, WSAMSG, WSAPOLLFD, WSAPoll, WSARecv, WSARecvFrom, WSASend,
    WSASendMsg, WSASendTo, getsockopt, ioctlsocket, setsockopt,
};
use windows_sys::core::GUID;

use super::{
    Host, HostErrno, HostEventBuffer, HostPoller, HostSocket, HostWaiter, Interest, LISTEN_BACKLOG,
    ReceiveMode, SocketEvents, WAKE_TOKEN,
};
use crate::fine_timer::FineTimer;
use crate::socket::direct::{MAX_RAW_PARTS, RawParts};

/// The Windows host.
pub(crate) enum Windows {}

impl Host for Windows {
    type Errno = Errno;
    type Socket = Socket;
    type Poller = Poller;
    type Waiter = Waiter;
    type EventBuffer = EventBuffer;

    fn spawn(command: &mut Command) -> IoResult<Child> {
        let _no_accept = INHERITABLE.write().unwrap_or_else(PoisonError::into_inner);
        command.spawn()
    }
}

/// Held shared from an accept until the accepted socket is non-inheritable (`accept` cannot create
/// it so), and exclusively to start a runner, which would inherit the socket meanwhile.
static INHERITABLE: RwLock<()> = RwLock::new(());

/// The length of the longest datagram a UDP socket receives.
const MAX_DATAGRAM_LENGTH: usize = MAX_UDP_DATAGRAM_SIZE as usize;

/// The most errors of sends past a connected socket's peer that a receive
/// drops before it fails with `AGAIN`. Tests use a bound they can exceed
/// within Windows's global limit of about 100 ICMP errors per quarter second.
const MAX_DROPPED_DATAGRAM_ERRORS: usize = if cfg!(test) { 4 } else { 64 };

/// A Winsock error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Errno(i32);

impl HostErrno for Errno {
    const INTR: Self = Self(WSAEINTR);
    const AGAIN: Self = Self(WSAEWOULDBLOCK);
    /// A TCP connect started, which Winsock reports as [`Self::AGAIN`].
    const INPROGRESS: Self = Self(WSAEINPROGRESS);
    const ALREADY: Self = Self(WSAEALREADY);
    const ISCONN: Self = Self(WSAEISCONN);
    const NOTCONN: Self = Self(WSAENOTCONN);
    const PIPE: Self = Self(WSAESHUTDOWN);
    const ADDRINUSE: Self = Self(WSAEADDRINUSE);
    const ADDRNOTAVAIL: Self = Self(WSAEADDRNOTAVAIL);
    const CONNREFUSED: Self = Self(WSAECONNREFUSED);
    const CONNRESET: Self = Self(WSAECONNRESET);
    const CONNABORTED: Self = Self(WSAECONNABORTED);
    const NETUNREACH: Self = Self(WSAENETUNREACH);
    const HOSTUNREACH: Self = Self(WSAEHOSTUNREACH);
    const TIMEDOUT: Self = Self(WSAETIMEDOUT);
    const INVAL: Self = Self(WSAEINVAL);
    const ACCES: Self = Self(WSAEACCES);

    fn broker_resource_error(self) -> Option<BrokerError> {
        match self {
            Self::NOMEM | Self::OUTOFMEMORY => Some(BrokerError::OutOfMemory),
            Self::MFILE | Self::NOBUFS => Some(BrokerError::ResourceExhausted),
            _ => None,
        }
    }
}

impl Errno {
    const NOMEM: Self = Self(WSA_NOT_ENOUGH_MEMORY);
    const NOBUFS: Self = Self(WSAENOBUFS);
    const AFNOSUPPORT: Self = Self(WSAEAFNOSUPPORT);
    const NETRESET: Self = Self(WSAENETRESET);
    /// A datagram is longer than a receive's output.
    const MSGSIZE: Self = Self(WSAEMSGSIZE);
    const MFILE: Self = Self(WSAEMFILE);
    const OPNOTSUPP: Self = Self(WSAEOPNOTSUPP);
    /// `ERROR_OUTOFMEMORY`, which some calls report instead of
    /// [`Self::NOMEM`].
    const OUTOFMEMORY: Self = Self(14);

    /// Returns the error of the calling thread's last failed Winsock call.
    fn last() -> Self {
        // SAFETY: `WSAGetLastError` takes no arguments and only reads the
        // calling thread's last error.
        Self(unsafe { WSAGetLastError() })
    }
}

impl From<Error> for Errno {
    fn from(error: Error) -> Self {
        if let Some(code) = error.raw_os_error() {
            return Self(code);
        }
        match error.kind() {
            ErrorKind::WouldBlock => Self::AGAIN,
            ErrorKind::Interrupted => Self::INTR,
            ErrorKind::OutOfMemory => Self::NOMEM,
            _ => Self::INVAL,
        }
    }
}

impl From<Errno> for Error {
    fn from(error: Errno) -> Self {
        Self::from_raw_os_error(error.0)
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Error::from_raw_os_error(self.0), formatter)
    }
}

/// A nonblocking, non-inheritable IPv4 host socket.
pub(crate) struct Socket {
    source: Source,
    /// Whether the poller watches the socket.
    registered: bool,
    /// The read side is shut down. Winsock is not told, because it resets a
    /// connection that receives data after a read shutdown, at once if data
    /// is queued, discarding it.
    read_shutdown: Cell<bool>,
    /// A TCP connect started without completing at once.
    connecting: Cell<bool>,
    /// The peer of a UDP socket's last connect that succeeded. Winsock
    /// reports the destination of a failed reconnect as the peer, though the
    /// socket keeps its old one.
    udp_peer: Cell<Option<SocketAddrV4>>,
    /// Winsock's `WSARecvMsg`, once [`HostSocket::report_destinations`] looked it up.
    receive_message: Cell<LPFN_WSARECVMSG>,
}

enum Source {
    Tcp(TcpStream),
    Udp(UdpSocket),
    Listener(TcpListener),
}

impl Socket {
    fn new(source: Source) -> Self {
        Self {
            source,
            registered: false,
            read_shutdown: Cell::new(false),
            connecting: Cell::new(false),
            udp_peer: Cell::new(None),
            receive_message: Cell::new(None),
        }
    }

    fn raw(&self) -> SOCKET {
        match &self.source {
            Source::Tcp(socket) => raw_socket(socket),
            Source::Udp(socket) => raw_socket(socket),
            Source::Listener(socket) => raw_socket(socket),
        }
    }

    fn socket(&self) -> SockRef<'_> {
        match &self.source {
            Source::Tcp(socket) => SockRef::from(socket),
            Source::Udp(socket) => SockRef::from(socket),
            Source::Listener(socket) => SockRef::from(socket),
        }
    }

    fn source_mut(&mut self) -> &mut dyn mio::event::Source {
        match &mut self.source {
            Source::Tcp(socket) => socket,
            Source::Udp(socket) => socket,
            Source::Listener(socket) => socket,
        }
    }

    fn is_tcp(&self) -> bool {
        matches!(self.source, Source::Tcp(_))
    }

    /// Reports whether an ICMP error that Winsock reports from `source`
    /// concerns a destination other than a connected socket's peer, as one
    /// that a send past the peer causes does.
    fn reports_another_destination(&self, source: Option<SocketAddrV4>) -> bool {
        matches!((self.udp_peer(), source), (Some(peer), Some(source)) if peer != source)
    }

    /// Returns a UDP socket's peer, which, unlike Winsock, keeps the one
    /// that a failed reconnect keeps.
    fn udp_peer(&self) -> Option<SocketAddrV4> {
        self.udp_peer.get()
    }

    /// Takes the datagram or ICMP error at the head of a UDP socket.
    fn take_head(&self) -> Result<usize, Errno> {
        let buffers = [WSABUF {
            len: 0,
            buf: NonNull::dangling().as_ptr(),
        }];
        receive_into(self.raw(), &buffers, false, None)
    }

    /// Receives a datagram, returning Winsock's error, and sets `source` to
    /// its source, or an ICMP error's, if IPv4.
    fn receive_datagram_once(
        &self,
        output: RawParts<'_>,
        peek: bool,
        source: &mut Option<SocketAddrV4>,
    ) -> Result<usize, Errno> {
        if output.len() >= MAX_DATAGRAM_LENGTH {
            let (buffers, count) = wsabufs(output)?;
            return receive_into(self.raw(), &buffers[..count], peek, Some(source));
        }
        // Winsock fails a receive into a shorter output rather than
        // truncating the datagram and reporting its length.
        let mut staging = Vec::new();
        staging
            .try_reserve_exact(MAX_DATAGRAM_LENGTH)
            .map_err(|_| Errno::NOMEM)?;
        staging.resize(MAX_DATAGRAM_LENGTH, 0);
        let buffers = [wsabuf(staging.as_mut_ptr(), staging.len())?];
        let received = receive_into(self.raw(), &buffers, peek, Some(source))?;
        output.copy_from_slice(&staging[..received.min(output.len())]);
        Ok(received)
    }

    /// Reports whether Winsock reports a TCP connection failed.
    fn error_polled(&self) -> Result<bool, Errno> {
        // Winsock reports a failed connect only to a poll for data.
        let mut sockets = [WSAPOLLFD {
            fd: self.raw(),
            events: POLLRDNORM | POLLWRNORM,
            revents: 0,
        }];
        // SAFETY: `sockets` outlives the call, which polls without waiting
        // and writes only the entries' `revents`.
        if unsafe { WSAPoll(sockets.as_mut_ptr(), 1, 0) } == SOCKET_ERROR {
            return Err(Errno::last());
        }
        Ok(sockets[0].revents & POLLERR != 0)
    }

    /// Returns the error of a failed TCP connection.
    fn connection_error(&self) -> Result<Errno, Errno> {
        if let Some(error) = self.socket().take_error()? {
            return Ok(stream_error_code(error.into()));
        }
        // Winsock reports a reset to receives rather than in `SO_ERROR`.
        let (buffers, count) = wsabufs(RawParts::EMPTY)?;
        match receive_into(self.raw(), &buffers[..count], true, None) {
            Err(error) if error != Errno::AGAIN => Ok(stream_error_code(error)),
            _ => Ok(Errno::CONNRESET),
        }
    }

    /// Maps the error of a TCP call to the result the host contract has it
    /// report; a receive ends the stream where the contract has it.
    fn stream_error(&self, error: Errno, receiving: bool) -> Result<usize, Errno> {
        match error {
            // A read shutdown ends the stream once the queued data is read.
            Errno::AGAIN if receiving && self.read_shutdown.get() => Ok(0),
            Errno::AGAIN => {
                self.rearm();
                Err(Errno::AGAIN)
            }
            // Winsock fails calls on a pending or failed connect, where the
            // contract has them block or report the failure.
            Errno::NOTCONN if self.connecting.get() => {
                Err(self.take_error()?.unwrap_or(Errno::AGAIN))
            }
            error => Err(stream_error_code(error)),
        }
    }

    /// Has mio report the stream's readiness again, so that the provider
    /// learns of each arrival that follows a read emptying the receive
    /// queue, and of the readiness of a call that would block.
    fn rearm(&self) {
        if let Source::Tcp(stream) = &self.source {
            // `try_io` rearms the socket when its closure would block. Failing
            // to rearm loses events, which the next call that would block
            // rearms again.
            let _ = stream.try_io(|| Err::<(), _>(Error::from(ErrorKind::WouldBlock)));
        }
    }
}

impl HostSocket for Socket {
    type Errno = Errno;

    fn tcp() -> Result<Self, Errno> {
        let socket = open(Type::STREAM, Protocol::TCP)?;
        Ok(Self::new(Source::Tcp(TcpStream::from_std(socket.into()))))
    }

    fn udp() -> Result<Self, Errno> {
        let socket = open(Type::DGRAM, Protocol::UDP)?;
        // The socket reports ICMP errors only while connected, and never a
        // time exceeded, which Winsock would report as a network reset
        // whether connected or not.
        report_icmp_errors(raw_socket(&socket), SIO_UDP_CONNRESET, false)?;
        report_icmp_errors(raw_socket(&socket), SIO_UDP_NETRESET, false)?;
        Ok(Self::new(Source::Udp(UdpSocket::from_std(socket.into()))))
    }

    fn owns_address(address: Ipv4Addr) -> Result<bool, Errno> {
        if address.is_unspecified() || address.is_multicast() || address.is_broadcast() {
            return Ok(false);
        }
        match Self::udp()?.bind(SocketAddrV4::new(address, 0)) {
            Ok(()) => Ok(true),
            Err(Errno::ADDRNOTAVAIL) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// With `SO_EXCLUSIVEADDRUSE`, without which a socket bound to a specific address could share
    /// a wildcard one's port. Connections accepted on the port keep it from being bound again
    /// until they end.
    fn tcp_listening(address: SocketAddrV4) -> Result<Self, Errno> {
        let socket = open(Type::STREAM, Protocol::TCP)?;
        use_exclusively(raw_socket(&socket))?;
        socket.bind(&SockAddr::from(address))?;
        let listener = Self::new(Source::Listener(TcpListener::from_std(socket.into())));
        listener.listen(LISTEN_BACKLOG)?;
        Ok(listener)
    }

    /// Winsock keeps a listener's first backlog: listening again succeeds without changing it.
    ///
    /// A stream that listens stays one for mio, which would drop its watch if it became a
    /// listener, and reports a connection to accept on a watched stream as readable, as it does
    /// on a listener; [`Self::accept`] accepts on either.
    fn listen(&self, backlog: u32) -> Result<(), Errno> {
        Ok(self
            .socket()
            .listen(i32::try_from(backlog).unwrap_or(i32::MAX))?)
    }

    /// mio's accept rearms the listener when it would block, as `try_io` does a stream that
    /// listens. Unlike `socket`, `accept` cannot make a socket non-inheritable, so runners would
    /// get it if it stayed so.
    fn accept(&self) -> Result<(Self, SocketAddrV4), Errno> {
        let _accepting = INHERITABLE.read().unwrap_or_else(PoisonError::into_inner);
        let (stream, peer) = match &self.source {
            Source::Listener(listener) => listener.accept()?,
            Source::Tcp(stream) => {
                // Winsock gives the accepted socket the listener's nonblocking mode, as mio's
                // accept relies on.
                let (socket, peer) = stream.try_io(|| SockRef::from(stream).accept())?;
                let peer = peer.as_socket().ok_or(Errno::AFNOSUPPORT)?;
                (TcpStream::from_std(socket.into()), peer)
            }
            Source::Udp(_) => return Err(Errno::INVAL),
        };
        let SocketAddr::V4(peer) = peer else {
            return Err(Errno::INVAL);
        };
        let handle = raw_socket(&stream) as HANDLE;
        // SAFETY: The call changes only the flags of the handle that `stream` owns.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(Error::last_os_error().into());
        }
        Ok((Self::new(Source::Tcp(stream)), peer))
    }

    fn bind(&self, address: SocketAddrV4) -> Result<(), Errno> {
        Ok(self.socket().bind(&SockAddr::from(address))?)
    }

    fn bind_exclusively(&self, address: SocketAddrV4) -> Result<(), Errno> {
        use_exclusively(self.raw())?;
        self.bind(address)
    }

    /// Winsock's `SO_REUSEADDR` lets a socket take a port that another holds, so the bind is
    /// exclusive. Winsock reports some conflicts with an exclusive bind, as well as ports the
    /// host reserves, as `WSAEACCES`, so the bind reports that as [`HostErrno::ADDRINUSE`].
    fn bind_as_guest(&self, address: SocketAddrV4, _reuse_address: bool) -> Result<(), Errno> {
        match self.bind_exclusively(address) {
            Err(Errno::ACCES) => Err(Errno::ADDRINUSE),
            result => result,
        }
    }

    /// Winsock retries a refused TCP connect for about 2 seconds before it
    /// fails, and refuses a connection request once the listener's accept
    /// queue is full.
    fn connect(&self, address: SocketAddrV4) -> Result<(), Errno> {
        if !self.is_tcp() {
            report_icmp_errors(self.raw(), SIO_UDP_CONNRESET, true)?;
        }
        match self.socket().connect(&SockAddr::from(address)) {
            Ok(()) => {
                if !self.is_tcp() {
                    self.udp_peer.set(Some(address));
                }
                Ok(())
            }
            Err(error) => match Errno::from(error) {
                Errno::AGAIN if self.is_tcp() => {
                    self.connecting.set(true);
                    Err(Errno::INPROGRESS)
                }
                error => {
                    if !self.is_tcp() && self.udp_peer().is_none() {
                        // An unconnected socket reports no ICMP errors, and
                        // a failed connect leaves it unconnected. Best effort:
                        // failing only reports them, and the same call just
                        // succeeded.
                        let _ = report_icmp_errors(self.raw(), SIO_UDP_CONNRESET, false);
                    }
                    Err(error)
                }
            },
        }
    }

    fn local_address(&self) -> Result<SocketAddrV4, Errno> {
        match self.socket().local_addr() {
            Ok(address) => address.as_socket_ipv4().ok_or(Errno::AFNOSUPPORT),
            // Winsock fails on an unbound socket, whose local address is the
            // wildcard.
            Err(error) => match Errno::from(error) {
                Errno::INVAL => Ok(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                error => Err(error),
            },
        }
    }

    fn shutdown(&self, how: Shutdown) -> Result<(), Errno> {
        let socket = self.socket();
        socket.peer_addr()?;
        if how != Shutdown::Read {
            socket.shutdown(Shutdown::Write)?;
        }
        if how != Shutdown::Write {
            self.read_shutdown.set(true);
        }
        Ok(())
    }

    /// Winsock cannot stop a listener or a connect in progress but by closing the socket, which
    /// releases its port.
    fn disconnect(&self) -> Result<(), Errno> {
        Err(Errno::OPNOTSUPP)
    }

    /// A UDP send reports an ICMP error only once the event thread has taken
    /// it, so a send right after one arrives can still succeed.
    fn send(&self, data: RawParts<'_>, destination: Option<SocketAddrV4>) -> Result<usize, Errno> {
        let result = send_parts(self.raw(), data, destination);
        if self.is_tcp() {
            result.or_else(|error| self.stream_error(error, false))
        } else {
            result.map_err(datagram_error)
        }
    }

    /// Winsock selects even a connected socket's source for each destination.
    fn send_as_unconnected(
        &self,
        data: RawParts<'_>,
        destination: SocketAddrV4,
    ) -> Result<usize, Errno> {
        self.send(data, Some(destination))
    }

    fn send_from(
        &self,
        data: RawParts<'_>,
        destination: SocketAddrV4,
        source: Ipv4Addr,
    ) -> Result<usize, Errno> {
        if source.is_unspecified() {
            return self.send(data, Some(destination));
        }
        let (mut buffers, count) = wsabufs(data)?;
        let mut address = sockaddr_in(destination);
        let mut control = PacketInfo::new(source);
        let message = WSAMSG {
            name: ptr::from_mut(&mut address).cast(),
            namelen: SOCKADDR_IN_LENGTH,
            lpBuffers: buffers.as_mut_ptr(),
            dwBufferCount: u32::try_from(count).map_err(|_| Errno::INVAL)?,
            Control: wsabuf(ptr::from_mut(&mut control).cast(), size_of::<PacketInfo>())?,
            dwFlags: 0,
        };
        let mut sent = 0_u32;
        // SAFETY: The message refers to `address`, `buffers` and `control`, which outlive the
        // call, as does `sent`; the call is not overlapped. Each of the first `count` buffers
        // covers raw bytes that are readable for the call and that Winsock reads without Rust
        // references to them.
        let result = unsafe {
            WSASendMsg(
                self.raw(),
                &raw const message,
                0,
                &raw mut sent,
                ptr::null_mut(),
                None,
            )
        };
        if result == SOCKET_ERROR {
            return Err(datagram_error(Errno::last()));
        }
        usize::try_from(sent).map_err(|_| Errno::INVAL)
    }

    fn report_destinations(&self) -> Result<(), Errno> {
        let on = 1_u32;
        // SAFETY: `on` outlives the call, which reads only it.
        let set = unsafe {
            setsockopt(
                self.raw(),
                IPPROTO_IP,
                IP_PKTINFO,
                (&raw const on).cast(),
                U32_LENGTH,
            )
        };
        if set == SOCKET_ERROR {
            return Err(Errno::last());
        }
        self.receive_message
            .set(receive_message_function(self.raw()));
        Ok(())
    }

    /// Winsock reports the address a datagram was sent to, from which a reply cannot leave if it
    /// is a broadcast or multicast one.
    fn peek_destination(&self) -> Ipv4Addr {
        let Some(receive_message) = self.receive_message.get() else {
            return Ipv4Addr::UNSPECIFIED;
        };
        let mut byte = 0_u8;
        let mut buffer = WSABUF {
            len: 1,
            buf: &raw mut byte,
        };
        let mut control = PacketInfo::new(Ipv4Addr::UNSPECIFIED);
        let mut message = WSAMSG {
            name: ptr::null_mut(),
            namelen: 0,
            lpBuffers: &raw mut buffer,
            dwBufferCount: 1,
            Control: WSABUF {
                len: PACKET_INFO_LENGTH,
                buf: ptr::from_mut(&mut control).cast(),
            },
            dwFlags: PEEK,
        };
        let mut received = 0_u32;
        // SAFETY: The message refers to `buffer`, which covers `byte`, and to `control`, which
        // outlive the call, as does `received`; the call is not overlapped.
        let result = unsafe {
            receive_message(
                self.raw(),
                &raw mut message,
                &raw mut received,
                ptr::null_mut(),
                None,
            )
        };
        // A datagram longer than the byte fails the peek, which still reports its control data.
        let reported = (result != SOCKET_ERROR || Errno::last() == Errno::MSGSIZE)
            && message.Control.len != 0
            && (control.header.cmsg_level, control.header.cmsg_type) == (IPPROTO_IP, IP_PKTINFO);
        // SAFETY: Every field of the address union is plain bytes, so any value of it is a valid
        // `S_addr`.
        let address = Ipv4Addr::from(unsafe { control.info.ipi_addr.S_un.S_addr }.to_ne_bytes());
        // Not a broadcast's, even to a subnet, or a multicast's.
        if !reported || message.dwFlags & (MSG_BCAST | MSG_MCAST) != 0 || address.is_multicast() {
            return Ipv4Addr::UNSPECIFIED;
        }
        address
    }

    fn receive(&self, output: RawParts<'_>, mode: ReceiveMode) -> Result<usize, Errno> {
        let (buffers, count) = wsabufs(output)?;
        match receive_into(self.raw(), &buffers[..count], mode.is_peek(), None) {
            Ok(received) => {
                if mode == ReceiveMode::Read && received != 0 && self.queued_bytes() == Ok(0) {
                    self.rearm();
                }
                Ok(received)
            }
            Err(error) => self.stream_error(error, true),
        }
    }

    /// An ICMP error it reports, it takes, even with `peek`. Fails with
    /// `AGAIN`, possibly with entries still queued, once it drops
    /// [`MAX_DROPPED_DATAGRAM_ERRORS`] errors of sends past a connected
    /// socket's peer; [`Self::discard_datagram`] empties a queue.
    fn receive_datagram(
        &self,
        output: RawParts<'_>,
        peek: bool,
    ) -> Result<(usize, Option<SocketAddrV4>), Errno> {
        // Bound the work that a flood of ICMP errors causes.
        for _ in 0..MAX_DROPPED_DATAGRAM_ERRORS {
            let mut source = None;
            match self.receive_datagram_once(output, peek, &mut source) {
                Ok(received) => return Ok((received, source)),
                Err(Errno::CONNRESET) => {
                    // A receive takes the error it reports, even a peek.
                    if peek {
                        let _ = self.take_head();
                    }
                    if !self.reports_another_destination(source) {
                        return Err(datagram_error(Errno::CONNRESET));
                    }
                }
                Err(error) => return Err(datagram_error(error)),
            }
        }
        Err(Errno::AGAIN)
    }

    /// Unlike [`Self::receive_datagram`], it discards the errors of sends
    /// past a connected socket's peer one at a time.
    fn discard_datagram(&self) -> Result<(), Errno> {
        match self.take_head() {
            // A receive that does not peek discards a datagram longer than
            // its output.
            Ok(_) | Err(Errno::MSGSIZE) => Ok(()),
            Err(error) => Err(datagram_error(error)),
        }
    }

    fn queued_bytes(&self) -> Result<usize, Errno> {
        let mut queued = 0_u32;
        // SAFETY: `queued` outlives the call, which writes only it.
        if unsafe { ioctlsocket(self.raw(), FIONREAD, &raw mut queued) } == SOCKET_ERROR {
            return Err(Errno::last());
        }
        usize::try_from(queued).map_err(|_| Errno::INVAL)
    }

    fn stream_readable(&self) -> Result<bool, Errno> {
        let mut sockets = [WSAPOLLFD {
            fd: self.raw(),
            events: POLLRDNORM,
            revents: 0,
        }];
        // SAFETY: `sockets` outlives the call, which polls without waiting
        // and writes only the entries' `revents`.
        if unsafe { WSAPoll(sockets.as_mut_ptr(), 1, 0) } == SOCKET_ERROR {
            return Err(Errno::last());
        }
        Ok(sockets[0].revents & POLLRDNORM != 0)
    }

    #[cfg(test)]
    fn head_datagram_length(&self) -> Result<usize, Errno> {
        // On a datagram socket, `FIONREAD` reports every queued datagram.
        match self.receive_datagram_once(RawParts::EMPTY, true, &mut None) {
            Ok(length) => Ok(length),
            Err(Errno::AGAIN) => Ok(0),
            Err(error) => Err(datagram_error(error)),
        }
    }

    /// A failed TCP connection reports its error every time, and Winsock
    /// discards the data not yet received when it resets one.
    fn take_error(&self) -> Result<Option<Errno>, Errno> {
        if !self.is_tcp() {
            return Ok(self
                .socket()
                .take_error()?
                .map(|error| datagram_error(error.into())));
        }
        if !self.error_polled()? {
            return Ok(None);
        }
        self.connection_error().map(Some)
    }

    fn error_pending(&self) -> Result<bool, Errno> {
        if !self.is_tcp() {
            // Winsock queues a UDP socket's ICMP errors among its datagrams,
            // for receives to report, so the poller reports them as readable
            // rather than as an error; see `REPORTS_UNWATCHED_ERRORS`.
            return Ok(false);
        }
        self.error_polled()
    }

    fn connect_pending(&self) -> Result<bool, Errno> {
        if !self.connecting.get() || self.error_pending()? {
            return Ok(false);
        }
        // Winsock reports the peer of a pending connect, so this asks how
        // long the socket has been connected, which is all ones until then.
        let mut seconds = 0_u32;
        let mut length = U32_LENGTH;
        // SAFETY: `seconds` and `length` outlive the call, which writes at
        // most `length` bytes to `seconds` and then writes only `length`.
        let result = unsafe {
            getsockopt(
                self.raw(),
                SOL_SOCKET,
                SO_CONNECT_TIME,
                (&raw mut seconds).cast(),
                &raw mut length,
            )
        };
        if result == SOCKET_ERROR {
            return Err(Errno::last());
        }
        Ok(seconds == u32::MAX)
    }

    fn set_no_delay(&self, value: bool) -> Result<(), Errno> {
        Ok(self.socket().set_tcp_nodelay(value)?)
    }

    #[cfg(test)]
    fn no_delay(&self) -> Result<bool, Errno> {
        Ok(self.socket().tcp_nodelay()?)
    }

    fn set_keep_alive(&self, value: bool) -> Result<(), Errno> {
        Ok(self.socket().set_keepalive(value)?)
    }

    #[cfg(test)]
    fn keep_alive(&self) -> Result<bool, Errno> {
        Ok(self.socket().keepalive()?)
    }

    fn set_linger_zero(&self) -> Result<(), Errno> {
        Ok(self.socket().set_linger(Some(Duration::ZERO))?)
    }

    /// [`Self::bind_as_guest`] binds exclusively whatever the guest asks.
    fn set_reuse_address(&self, _value: bool) -> Result<(), Errno> {
        Ok(())
    }

    fn reuse_address(&self) -> Result<bool, Errno> {
        Ok(self.socket().reuse_address()?)
    }

    fn set_receive_buffer_size(&self, size: usize) -> Result<(), Errno> {
        Ok(self.socket().set_recv_buffer_size(size)?)
    }

    fn receive_buffer_size(&self) -> Result<usize, Errno> {
        Ok(self.socket().recv_buffer_size()?)
    }
}

/// Opens a nonblocking, non-inheritable IPv4 socket.
fn open(socket_type: Type, protocol: Protocol) -> Result<socket2::Socket, Errno> {
    let socket = socket2::Socket::new(Domain::IPV4, socket_type, Some(protocol))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[allow(clippy::cast_possible_truncation)]
fn raw_socket(socket: &impl AsRawSocket) -> SOCKET {
    // A `SOCKET` is pointer-sized, which on x86_64 holds every raw socket.
    socket.as_raw_socket() as SOCKET
}

/// Keeps every other socket off `socket`'s port, whichever address either binds.
fn use_exclusively(socket: SOCKET) -> Result<(), Errno> {
    let on = 1_u32;
    // SAFETY: `on` outlives the call, which reads only it.
    let set = unsafe {
        setsockopt(
            socket,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&raw const on).cast(),
            U32_LENGTH,
        )
    };
    if set == SOCKET_ERROR {
        return Err(Errno::last());
    }
    Ok(())
}

/// Sets whether a UDP socket reports the ICMP errors its datagrams cause
/// that `control` covers: [`SIO_UDP_CONNRESET`] covers port unreachable
/// messages, and [`SIO_UDP_NETRESET`] time exceeded messages.
fn report_icmp_errors(socket: SOCKET, control: u32, report: bool) -> Result<(), Errno> {
    let value = i32::from(report);
    let mut returned = 0_u32;
    // SAFETY: `value` and `returned` outlive the call, which reads only
    // `value` and writes only `returned`, and the call is not overlapped.
    let result = unsafe {
        WSAIoctl(
            socket,
            control,
            ptr::from_ref(&value).cast(),
            I32_LENGTH,
            ptr::null_mut(),
            0,
            &raw mut returned,
            ptr::null_mut(),
            None,
        )
    };
    if result == SOCKET_ERROR {
        return Err(Errno::last());
    }
    Ok(())
}

/// Maps a TCP call's error code to the one the host contract has it report.
const fn stream_error_code(error: Errno) -> Errno {
    match error {
        // Winsock reports a keep-alive failure this way only to a call in
        // progress, which a nonblocking call never is. Later calls see it,
        // and a retransmission timeout, as a reset, which nothing tells
        // apart from one reliably: `SIO_TCP_INFO` counts the timeouts of the
        // connection's whole life, including those it recovered from.
        Errno::NETRESET => Errno::TIMEDOUT,
        // Winsock reports some resets, such as one that follows the peer's
        // end of stream, as an abort.
        Errno::CONNABORTED => Errno::CONNRESET,
        error => error,
    }
}

/// Maps a UDP call's error code to the one the host contract has it report.
const fn datagram_error(error: Errno) -> Errno {
    match error {
        // Winsock reports an ICMP port unreachable as a reset.
        Errno::CONNRESET => Errno::CONNREFUSED,
        error => error,
    }
}

/// Watches host sockets with mio; a [`Waiter`] collects their events.
pub(crate) struct Poller {
    registry: Registry,
    /// Wakes the waiter under [`WAKE_TOKEN`].
    waker: Waker,
}

/// Collects a [`Poller`]'s events on the event thread.
pub(crate) struct Waiter {
    poll: Poll,
    fine_timer: FineTimer,
}

impl HostPoller for Poller {
    type Errno = Errno;
    type Socket = Socket;
    type Waiter = Waiter;

    /// mio reports each kind of readiness once until the socket is rearmed,
    /// so it does not report data that arrives while earlier data is queued.
    const REPORTS_EVERY_ARRIVAL: bool = false;

    /// Winsock queues a UDP socket's ICMP errors among its datagrams, so
    /// only a socket watched for reads reports them.
    const REPORTS_UNWATCHED_ERRORS: bool = false;

    fn new() -> IoResult<(Self, Waiter)> {
        let poll = Poll::new()?;
        let registry = poll.registry().try_clone()?;
        let waker = Waker::new(&registry, Token(token(WAKE_TOKEN)?))?;
        let waiter = Waiter {
            poll,
            fine_timer: FineTimer::new(),
        };
        Ok((Self { registry, waker }, waiter))
    }

    fn add(&self, socket: &mut Socket, token: u64, interest: Interest) -> Result<(), Errno> {
        self.watch(socket, token, interest)
    }

    fn modify(&self, socket: &mut Socket, token: u64, interest: Interest) -> Result<(), Errno> {
        self.watch(socket, token, interest)
    }

    fn delete(&self, socket: &mut Socket) {
        if socket.registered {
            let _ = self.registry.deregister(socket.source_mut());
            socket.registered = false;
        }
    }

    fn wake(&self) -> IoResult<()> {
        self.waker.wake()
    }
}

impl Poller {
    fn watch(&self, socket: &mut Socket, token: u64, interest: Interest) -> Result<(), Errno> {
        let token = Token(self::token(token)?);
        let interest = match interest {
            Interest::Stream
            | Interest::Oneshot {
                read: true,
                write: true,
            } => Some(mio::Interest::READABLE | mio::Interest::WRITABLE),
            Interest::Oneshot { read: true, .. } => Some(mio::Interest::READABLE),
            Interest::Oneshot { write: true, .. } => Some(mio::Interest::WRITABLE),
            // mio cannot watch a socket for nothing, and not watching it
            // keeps errors from raising events, which `Interest::Oneshot`
            // allows.
            Interest::Oneshot { .. } => None,
        };
        let registered = socket.registered;
        let source = socket.source_mut();
        match (interest, registered) {
            (Some(interest), false) => self.registry.register(source, token, interest)?,
            (Some(interest), true) => self.registry.reregister(source, token, interest)?,
            (None, true) => self.registry.deregister(source)?,
            (None, false) => {}
        }
        socket.registered = interest.is_some();
        Ok(())
    }
}

impl HostWaiter for Waiter {
    type Errno = Errno;
    type EventBuffer = EventBuffer;

    /// Each wake is a completion that reporting [`WAKE_TOKEN`] dequeues.
    ///
    /// A [`FineTimer`] keeps the provider's quick retries from stretching to
    /// the default timer resolution.
    fn wait(&mut self, events: &mut EventBuffer, timeout: Duration) -> Result<(), Errno> {
        self.fine_timer.adjust(Some(timeout));
        Ok(self.poll.poll(&mut events.0, Some(timeout))?)
    }
}

/// Room for the events one wait reports.
pub(crate) struct EventBuffer(mio::Events);

impl HostEventBuffer for EventBuffer {
    /// mio aborts if the allocation fails, so this never returns `None`.
    fn with_capacity(capacity: usize) -> Option<Self> {
        Some(Self(mio::Events::with_capacity(capacity)))
    }

    fn iter(&self) -> impl Iterator<Item = (u64, SocketEvents)> + '_ {
        self.0
            .iter()
            .map(|event| (event.token().0 as u64, host_events(event)))
    }
}

fn host_events(event: &mio::event::Event) -> SocketEvents {
    let mut events = SocketEvents::empty();
    if event.is_readable() {
        events |= SocketEvents::READABLE;
    }
    if event.is_writable() {
        events |= SocketEvents::WRITABLE;
    }
    if event.is_read_closed() {
        events |= SocketEvents::READ_CLOSED;
    }
    // mio reports a reset or a failed connect as closing the write side,
    // which the provider takes as a hang-up with an error.
    if event.is_write_closed() {
        events |= SocketEvents::HANGUP | SocketEvents::ERROR;
    }
    if event.is_error() {
        events |= SocketEvents::ERROR;
    }
    events
}

fn token(token: u64) -> Result<usize, Errno> {
    usize::try_from(token).map_err(|_| Errno::INVAL)
}

/// Sends `data` on `socket` with one system call, to `destination` if set,
/// and returns how many bytes it sent.
fn send_parts(
    socket: SOCKET,
    data: RawParts<'_>,
    destination: Option<SocketAddrV4>,
) -> Result<usize, Errno> {
    let (buffers, count) = wsabufs(data)?;
    let count = u32::try_from(count).map_err(|_| Errno::INVAL)?;
    let mut sent = 0_u32;
    let result = if let Some(destination) = destination {
        let address = sockaddr_in(destination);
        // SAFETY: `buffers`, `sent` and `address` outlive the call, which is
        // not overlapped. Each of the first `count` buffers covers raw bytes
        // that are readable for the call and that Winsock reads without Rust
        // references to them.
        unsafe {
            WSASendTo(
                socket,
                buffers.as_ptr(),
                count,
                &raw mut sent,
                0,
                ptr::from_ref(&address).cast(),
                SOCKADDR_IN_LENGTH,
                ptr::null_mut(),
                None,
            )
        }
    } else {
        // SAFETY: `buffers` and `sent` outlive the call, which is not
        // overlapped. Each of the first `count` buffers covers raw bytes that
        // are readable for the call and that Winsock reads without Rust
        // references to them.
        unsafe {
            WSASend(
                socket,
                buffers.as_ptr(),
                count,
                &raw mut sent,
                0,
                ptr::null_mut(),
                None,
            )
        }
    };
    if result == SOCKET_ERROR {
        return Err(Errno::last());
    }
    usize::try_from(sent).map_err(|_| Errno::INVAL)
}

/// Receives into `buffers` from `socket` with one system call, leaving the
/// data queued with `peek`, and returns how many bytes it received.
///
/// With `source`, it also sets that to the source address, if IPv4, which
/// Winsock reports for an ICMP error too.
fn receive_into(
    socket: SOCKET,
    buffers: &[WSABUF],
    peek: bool,
    source: Option<&mut Option<SocketAddrV4>>,
) -> Result<usize, Errno> {
    let count = u32::try_from(buffers.len()).map_err(|_| Errno::INVAL)?;
    let mut flags = if peek { PEEK } else { 0 };
    let mut received = 0_u32;
    let mut address = SOCKADDR_IN {
        sin_family: 0,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 { S_addr: 0 },
        },
        sin_zero: [0; 8],
    };
    let mut address_length = SOCKADDR_IN_LENGTH;
    let result = if source.is_some() {
        // SAFETY: `buffers`, `received`, `flags`, `address` and
        // `address_length` outlive the call, which is not overlapped and
        // writes at most `address_length` bytes of `address`. Each buffer
        // covers raw bytes that are writable for the call and that Winsock
        // fills without Rust references to them.
        unsafe {
            WSARecvFrom(
                socket,
                buffers.as_ptr(),
                count,
                &raw mut received,
                &raw mut flags,
                ptr::from_mut(&mut address).cast(),
                &raw mut address_length,
                ptr::null_mut(),
                None,
            )
        }
    } else {
        // SAFETY: `buffers`, `received` and `flags` outlive the call, which
        // is not overlapped. Each buffer covers raw bytes that are writable
        // for the call and that Winsock fills without Rust references to
        // them.
        unsafe {
            WSARecv(
                socket,
                buffers.as_ptr(),
                count,
                &raw mut received,
                &raw mut flags,
                ptr::null_mut(),
                None,
            )
        }
    };
    let result = if result == SOCKET_ERROR {
        Err(Errno::last())
    } else {
        usize::try_from(received).map_err(|_| Errno::INVAL)
    };
    if let Some(source) = source {
        *source =
            (address_length == SOCKADDR_IN_LENGTH && address.sin_family == AF_INET).then(|| {
                // SAFETY: Every field of the address union is plain bytes, so
                // any value of it is a valid `S_addr`.
                let host = unsafe { address.sin_addr.S_un.S_addr };
                SocketAddrV4::new(
                    Ipv4Addr::from(host.to_ne_bytes()),
                    u16::from_be(address.sin_port),
                )
            });
    }
    result
}

/// An `IP_PKTINFO` control message. Sent, it sets a datagram's source address;
/// received, it reports the address the datagram was sent to.
#[repr(C)]
struct PacketInfo {
    header: CMSGHDR,
    info: IN_PKTINFO,
}

// Winsock finds a control message's data at the aligned end of its header.
const _: () = assert!(
    core::mem::offset_of!(PacketInfo, info)
        == size_of::<CMSGHDR>().next_multiple_of(size_of::<usize>())
);

impl PacketInfo {
    fn new(address: Ipv4Addr) -> Self {
        Self {
            header: CMSGHDR {
                cmsg_len: size_of::<Self>(),
                cmsg_level: IPPROTO_IP,
                cmsg_type: IP_PKTINFO,
            },
            info: IN_PKTINFO {
                ipi_addr: sockaddr_in(SocketAddrV4::new(address, 0)).sin_addr,
                ipi_ifindex: 0,
            },
        }
    }
}

/// Returns Winsock's `WSARecvMsg` for `socket`, which only `WSAIoctl` provides.
fn receive_message_function(socket: SOCKET) -> LPFN_WSARECVMSG {
    let (guid, mut function, mut returned) = (WSAID_WSARECVMSG, None, 0_u32);
    // SAFETY: `guid`, `function` and `returned` outlive the call, which is not overlapped and
    // writes only `function` and `returned`.
    let result = unsafe {
        WSAIoctl(
            socket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            (&raw const guid).cast(),
            GUID_LENGTH,
            (&raw mut function).cast(),
            FUNCTION_LENGTH,
            &raw mut returned,
            ptr::null_mut(),
            None,
        )
    };
    (result != SOCKET_ERROR).then_some(function).flatten()
}

/// Returns a buffer for each of `parts`, or one empty buffer if there are
/// none, followed by empty ones, and how many it filled in.
fn wsabufs(parts: RawParts<'_>) -> Result<([WSABUF; MAX_RAW_PARTS], usize), Errno> {
    let mut buffers = [wsabuf(NonNull::dangling().as_ptr(), 0)?; MAX_RAW_PARTS];
    for (buffer, part) in buffers.iter_mut().zip(parts.parts()) {
        *buffer = wsabuf(part.as_ptr(), part.len())?;
    }
    Ok((buffers, parts.parts().len().max(1)))
}

fn wsabuf(bytes: *mut u8, length: usize) -> Result<WSABUF, Errno> {
    Ok(WSABUF {
        len: u32::try_from(length).map_err(|_| Errno::INVAL)?,
        buf: bytes,
    })
}

#[allow(clippy::cast_sign_loss)]
const PEEK: u32 = MSG_PEEK as u32;

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
const SOCKADDR_IN_LENGTH: i32 = size_of::<SOCKADDR_IN>() as i32;

#[allow(clippy::cast_possible_truncation)]
const I32_LENGTH: u32 = size_of::<i32>() as u32;

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
const U32_LENGTH: i32 = size_of::<u32>() as i32;

#[allow(clippy::cast_possible_truncation)]
const PACKET_INFO_LENGTH: u32 = size_of::<PacketInfo>() as u32;

#[allow(clippy::cast_possible_truncation)]
const GUID_LENGTH: u32 = size_of::<GUID>() as u32;

#[allow(clippy::cast_possible_truncation)]
const FUNCTION_LENGTH: u32 = size_of::<LPFN_WSARECVMSG>() as u32;

fn sockaddr_in(address: SocketAddrV4) -> SOCKADDR_IN {
    SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: address.port().to_be(),
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(address.ip().octets()),
            },
        },
        sin_zero: [0; 8],
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use super::{
        Errno, EventBuffer, HostErrno as _, HostEventBuffer as _, HostPoller as _, HostSocket as _,
        HostWaiter as _, Poller, ReceiveMode, Socket,
    };
    use crate::fine_timer::DEFAULT_TIMER_PERIOD;
    use crate::socket::direct::RawParts;
    use dev_test_support::net::refusing_udp_address;
    use litebox_broker_core::BrokerError;
    use litebox_platform::buffer::RawBytes;

    #[test]
    fn resource_errors_map_to_broker_errors() {
        let cases = [
            (Errno::NOMEM, Some(BrokerError::OutOfMemory)),
            (Errno::OUTOFMEMORY, Some(BrokerError::OutOfMemory)),
            (Errno::NOBUFS, Some(BrokerError::ResourceExhausted)),
            (Errno::MFILE, Some(BrokerError::ResourceExhausted)),
            (Errno::CONNRESET, None),
        ];
        for (error, expected) in cases {
            assert_eq!(error.broker_resource_error(), expected, "{error}");
        }
    }

    /// Winsock reports a reset that follows the peer's end of stream, which
    /// discards the data not yet read, as an abort, which is reported as a
    /// reset to whichever call sees it first.
    #[test]
    fn a_reset_after_the_peers_end_of_stream_is_reported_as_a_reset() {
        /// The call that sees the reset first.
        #[derive(Clone, Copy, Debug)]
        enum First {
            Peek,
            Read,
            Send,
            TakeError,
            /// A call that failed as on a pending connect just before the
            /// connection completed and was reset.
            CallBeforeConnect,
        }
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let std::net::SocketAddr::V4(address) = listener.local_addr().unwrap() else {
            unreachable!()
        };
        let mut byte = [0_u8; 1];
        let byte = [RawBytes::from(&mut byte[..])];
        let byte = RawParts::from(&byte);
        let mut data = [0_u8; 8];
        let data = [RawBytes::from(&mut data[..])];
        let data = RawParts::from(&data);
        // Returns a socket whose peer sent 4 bytes, which the socket did not
        // read, and ended its stream, and then reset the connection when the
        // socket sent to it.
        let reset_after_end = || {
            let socket = Socket::tcp().unwrap();
            assert_eq!(socket.connect(address), Err(Errno::INPROGRESS));
            let mut peer = listener.accept().unwrap().0;
            peer.write_all(b"data").unwrap();
            drop(peer);
            let deadline = Instant::now() + Duration::from_secs(5);
            // A zero-length receive returns 0 once data is queued.
            loop {
                match socket.receive(RawParts::EMPTY, ReceiveMode::Read) {
                    Ok(0) => break,
                    Err(Errno::AGAIN) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    result => panic!("{result:?}"),
                }
            }
            loop {
                match socket.send(byte, None) {
                    Ok(1) => break,
                    Err(Errno::AGAIN) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    result => panic!("{result:?}"),
                }
            }
            while socket.error_pending() != Ok(true) {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
            socket
        };

        for first in [
            First::Peek,
            First::Read,
            First::Send,
            First::TakeError,
            First::CallBeforeConnect,
        ] {
            let socket = reset_after_end();
            let reported = match first {
                First::Peek => socket.receive(data, ReceiveMode::Peek).err(),
                First::Read => socket.receive(data, ReceiveMode::Read).err(),
                First::Send => socket.send(byte, None).err(),
                First::TakeError => socket.take_error().unwrap(),
                First::CallBeforeConnect => socket.stream_error(Errno::NOTCONN, false).err(),
            };
            assert_eq!(reported, Some(Errno::CONNRESET), "{first:?}");
        }
    }

    /// A failed reconnect leaves a UDP socket with its peer, whose ICMP
    /// errors it keeps reporting, though Winsock then reports the failed
    /// destination as the peer.
    #[test]
    fn a_failed_reconnect_keeps_the_peers_icmp_errors() {
        let (_refusing, peer) = refusing_udp_address();
        let socket = Socket::udp().unwrap();
        socket.connect(peer).unwrap();
        let unconnectable = std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 9);
        assert!(socket.connect(unconnectable).is_err());
        assert_eq!(socket.send(RawParts::EMPTY, None), Ok(0));
        let deadline = Instant::now() + Duration::from_secs(30);
        let received = loop {
            match socket.receive_datagram(RawParts::EMPTY, false) {
                Err(Errno::AGAIN) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                received => break received,
            }
        };
        assert_eq!(received, Err(Errno::CONNREFUSED));
    }

    #[test]
    fn timed_waits_end_soon_after_their_timeout() {
        const WAITS: u32 = 20;
        let (_poller, mut waiter) = Poller::new().unwrap();
        let mut events = EventBuffer::with_capacity(1).unwrap();
        let start = Instant::now();
        for _ in 0..WAITS {
            waiter.wait(&mut events, Duration::from_millis(1)).unwrap();
        }
        // At the default timer resolution, each wait takes 15.6ms.
        let elapsed = start.elapsed();
        assert!(elapsed < WAITS * Duration::from_millis(8), "{elapsed:?}");
    }

    /// A wait the default timer resolution barely stretches restores the
    /// resolution a shorter wait raised.
    #[test]
    fn a_long_wait_restores_the_default_timer_resolution() {
        let (_poller, mut waiter) = Poller::new().unwrap();
        let mut events = EventBuffer::with_capacity(1).unwrap();
        waiter.wait(&mut events, Duration::from_millis(1)).unwrap();
        assert!(waiter.fine_timer.is_raised());
        waiter.wait(&mut events, DEFAULT_TIMER_PERIOD).unwrap();
        assert!(!waiter.fine_timer.is_raised());
    }
}
