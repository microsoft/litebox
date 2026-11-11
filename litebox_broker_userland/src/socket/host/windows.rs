// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The Windows host: sockets through socket2 and Winsock, and events from
//! mio, which polls sockets through AFD and wakes through its completion
//! port. Where Winsock falls short of the host contract, the code that makes
//! up the difference says how.

use std::cell::Cell;
use std::fmt;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::marker::PhantomData;
use std::mem::offset_of;
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4};
use std::os::windows::io::AsRawSocket;
use std::ptr::{self, NonNull};
use std::slice;
use std::time::Duration;

use litebox_broker_core::BrokerError;
use litebox_broker_protocol::socket::MAX_UDP_DATAGRAM_SIZE;
use mio::net::{TcpListener, TcpStream, UdpSocket};
use mio::{Poll, Registry, Token, Waker};
use socket2::{Domain, Protocol, SockAddr, SockRef, Type};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, FALSE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetCurrentThreadCompartmentId, GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID,
    MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    SetCurrentThreadCompartmentId, TCP_TABLE_OWNER_PID_LISTENER,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_IF_COMPARTMENT_ID;
use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, FIONREAD, IN_ADDR, IN_ADDR_0, MSG_PEEK, POLLERR, POLLRDNORM,
    POLLWRNORM, SIO_UDP_CONNRESET, SIO_UDP_NETRESET, SO_CONNECT_TIME, SO_EXCLUSIVEADDRUSE,
    SOCKADDR_IN, SOCKET, SOCKET_ERROR, SOL_SOCKET, WSA_NOT_ENOUGH_MEMORY, WSABUF, WSAEADDRINUSE,
    WSAEADDRNOTAVAIL, WSAEAFNOSUPPORT, WSAEALREADY, WSAECONNABORTED, WSAECONNREFUSED,
    WSAECONNRESET, WSAEHOSTUNREACH, WSAEINPROGRESS, WSAEINTR, WSAEINVAL, WSAEISCONN, WSAEMFILE,
    WSAEMSGSIZE, WSAENETRESET, WSAENETUNREACH, WSAENOBUFS, WSAENOTCONN, WSAESHUTDOWN, WSAETIMEDOUT,
    WSAEWOULDBLOCK, WSAGetLastError, WSAIoctl, WSAPOLLFD, WSAPoll, WSARecv, WSARecvFrom, WSASend,
    WSASendTo, getsockopt, ioctlsocket, setsockopt,
};

use super::{
    Host, HostErrno, HostEventBuffer, HostPoller, HostSocket, HostWaiter, Interest, ReceiveMode,
    SocketEvents, WAKE_TOKEN,
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
}

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

/// The network compartment sockets are opened in: one of the host's, such
/// as a container's HCN namespace, or, with none, the calling thread's.
///
/// Windows opens a socket in its creating thread's compartment, which the
/// socket keeps. Opening one in another compartment moves the thread there
/// for the call, then back.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Network {
    compartment: Option<NET_IF_COMPARTMENT_ID>,
}

impl Network {
    /// Selects the network compartment `compartment`, or the calling
    /// thread's; fails if this thread cannot enter it.
    pub(crate) fn new(compartment: Option<u32>) -> IoResult<Self> {
        let network = Self { compartment };
        drop(network.enter().map_err(|error| {
            error.with_context(format_args!(
                "cannot enter network compartment {}",
                compartment.unwrap_or_default()
            ))
        })?);
        Ok(network)
    }

    /// Moves the calling thread to the network's compartment until the
    /// returned guard drops.
    fn enter(self) -> Result<CompartmentGuard, Errno> {
        let Some(compartment) = self.compartment else {
            return Ok(CompartmentGuard::new(None));
        };
        // SAFETY: takes no arguments and reads only the calling thread's
        // compartment.
        let previous = unsafe { GetCurrentThreadCompartmentId() };
        if previous == compartment {
            return Ok(CompartmentGuard::new(None));
        }
        // SAFETY: takes only an integer and changes only the calling
        // thread's compartment.
        match unsafe { SetCurrentThreadCompartmentId(compartment) } {
            NO_ERROR => Ok(CompartmentGuard::new(Some(previous))),
            error => Err(Errno(error.cast_signed())),
        }
    }
}

/// Returns the calling thread to its previous network compartment. It
/// stays on the thread whose compartment it restores.
struct CompartmentGuard {
    previous: Option<NET_IF_COMPARTMENT_ID>,
    _thread: PhantomData<*const ()>,
}

impl CompartmentGuard {
    fn new(previous: Option<NET_IF_COMPARTMENT_ID>) -> Self {
        Self {
            previous,
            _thread: PhantomData,
        }
    }
}

impl Drop for CompartmentGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous {
            // SAFETY: as in `Network::enter`.
            let restored = unsafe { SetCurrentThreadCompartmentId(previous) };
            if restored != NO_ERROR {
                // The thread would open its later sockets, and those of the
                // broker's own network, in the other compartment.
                std::eprintln!(
                    "cannot return to network compartment {previous}: {}",
                    Errno(restored.cast_signed())
                );
                std::process::abort();
            }
        }
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
    type Network = Network;

    fn tcp(network: Network) -> Result<Self, Errno> {
        let socket = open(network, Type::STREAM, Protocol::TCP)?;
        Ok(Self::new(Source::Tcp(TcpStream::from_std(socket.into()))))
    }

    /// Windows' `SO_REUSEADDR` would let another socket take the address,
    /// so the listener takes it exclusively, which sockets in `TIME_WAIT` do
    /// not prevent. Winsock still lets an exclusive listener take the
    /// clients of a wildcard listener on its port, so the listener looks for
    /// one; see [`wildcard_listener_holds_port`].
    fn tcp_listener(network: Network, address: SocketAddrV4, backlog: u32) -> Result<Self, Errno> {
        let socket = open(network, Type::STREAM, Protocol::TCP)?;
        let raw = raw_socket(&socket);
        let exclusive = 1_i32;
        let value = ptr::from_ref(&exclusive).cast();
        // SAFETY: `raw` is the handle that `socket` owns, and both it and
        // `exclusive` outlive the call, which reads `I32_LENGTH` bytes from
        // `value`.
        let set = unsafe {
            setsockopt(
                raw,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                value,
                I32_LENGTH.cast_signed(),
            )
        };
        if set == SOCKET_ERROR {
            return Err(Errno::last());
        }
        socket.bind(&SockAddr::from(address))?;
        socket.listen(i32::try_from(backlog).unwrap_or(i32::MAX))?;
        // The port bound, which `address` leaves to the host if it is 0.
        let bound = socket.local_addr()?.as_socket_ipv4().ok_or(Errno::INVAL)?;
        // Looked for once listening, so that one that listened first is found.
        let compartment = network.enter()?;
        let taken = wildcard_listener_holds_port(bound)?;
        drop(compartment);
        if taken {
            return Err(Errno::ADDRINUSE);
        }
        Ok(Self::new(Source::Listener(TcpListener::from_std(
            socket.into(),
        ))))
    }

    /// Winsock reports a connection reset before it was accepted as a
    /// reset rather than an abort.
    fn accept(&self) -> Result<Self, Errno> {
        let Source::Listener(listener) = &self.source else {
            return Err(Errno::INVAL);
        };
        match listener.accept() {
            Ok((stream, _)) => Ok(Self::new(Source::Tcp(stream))),
            Err(error) => match Errno::from(error) {
                Errno::CONNRESET => Err(Errno::CONNABORTED),
                error => Err(error),
            },
        }
    }

    fn udp(network: Network) -> Result<Self, Errno> {
        let socket = open(network, Type::DGRAM, Protocol::UDP)?;
        // The socket reports ICMP errors only while connected, and never a
        // time exceeded, which Winsock would report as a network reset
        // whether connected or not.
        report_icmp_errors(raw_socket(&socket), SIO_UDP_CONNRESET, false)?;
        report_icmp_errors(raw_socket(&socket), SIO_UDP_NETRESET, false)?;
        Ok(Self::new(Source::Udp(UdpSocket::from_std(socket.into()))))
    }

    fn bind(&self, address: SocketAddrV4) -> Result<(), Errno> {
        Ok(self.socket().bind(&SockAddr::from(address))?)
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

    fn set_receive_buffer_size(&self, size: usize) -> Result<(), Errno> {
        Ok(self.socket().set_recv_buffer_size(size)?)
    }

    fn receive_buffer_size(&self) -> Result<usize, Errno> {
        Ok(self.socket().recv_buffer_size()?)
    }
}

/// Opens a nonblocking, non-inheritable IPv4 socket in `network`.
fn open(network: Network, socket_type: Type, protocol: Protocol) -> Result<socket2::Socket, Errno> {
    let compartment = network.enter()?;
    let socket = socket2::Socket::new(Domain::IPV4, socket_type, Some(protocol))?;
    drop(compartment);
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Whether another socket in the calling thread's compartment listens on
/// `address`'s port at every address, IPv4 or IPv6, that would take clients
/// of `address`: Winsock lets an exclusive listener on `address` take them,
/// where Linux refuses its bind. The table does not tell an IPv6-only
/// wildcard listener, which Linux allows beside `address` and which takes no
/// IPv4 clients, from a dual-stack one, so any IPv6 wildcard listener counts.
fn wildcard_listener_holds_port(address: SocketAddrV4) -> Result<bool, Errno> {
    let port = address.port();
    // An IPv4 wildcard address itself is bound exclusively, which a wildcard
    // listener on it refuses.
    if !address.ip().is_unspecified()
        && any_tcp_listener(|row: &MIB_TCPROW_OWNER_PID| {
            row.dwLocalAddr == 0 && table_port(row.dwLocalPort) == port
        })?
    {
        return Ok(true);
    }
    any_tcp_listener(|row: &MIB_TCP6ROW_OWNER_PID| {
        row.ucLocalAddr == [0; 16] && table_port(row.dwLocalPort) == port
    })
}

/// A row of a table of TCP listeners that `GetExtendedTcpTable` returns.
///
/// # Safety
///
/// Any bytes are a valid `Self`. The table of [`Self::FAMILY`]'s listeners
/// holds its rows as `Self`s, [`Self::ROWS_OFFSET`] bytes into it, after its
/// `u32` count of them.
unsafe trait TcpListenerRow: Copy {
    const FAMILY: ADDRESS_FAMILY;
    const ROWS_OFFSET: usize;
}

// SAFETY: the row holds only `u32`s, and `MIB_TCPTABLE_OWNER_PID`, the
// table of IPv4 listeners with `TCP_TABLE_OWNER_PID_LISTENER`, holds it.
unsafe impl TcpListenerRow for MIB_TCPROW_OWNER_PID {
    const FAMILY: ADDRESS_FAMILY = AF_INET;
    const ROWS_OFFSET: usize = offset_of!(MIB_TCPTABLE_OWNER_PID, table);
}

// SAFETY: the row holds only `u32`s and byte arrays, and
// `MIB_TCP6TABLE_OWNER_PID`, the table of IPv6 listeners with
// `TCP_TABLE_OWNER_PID_LISTENER`, holds it.
unsafe impl TcpListenerRow for MIB_TCP6ROW_OWNER_PID {
    const FAMILY: ADDRESS_FAMILY = AF_INET6;
    const ROWS_OFFSET: usize = offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
}

/// Whether a row of the calling thread's compartment's table of `Row`'s
/// family's TCP listeners matches `matches`.
fn any_tcp_listener<Row: TcpListenerRow>(matches: impl Fn(&Row) -> bool) -> Result<bool, Errno> {
    // The table lies in words, which align it for any row with no wider
    // alignment, at an offset aligned for its rows.
    const {
        assert!(align_of::<Row>() <= align_of::<u32>());
        assert!(Row::ROWS_OFFSET.is_multiple_of(align_of::<Row>()));
    }
    let mut table = Vec::<u32>::new();
    // Listeners may come between the call that sizes the table and the next.
    for _ in 0..4 {
        let mut size = u32::try_from(size_of_val(table.as_slice())).unwrap_or(u32::MAX);
        let output = if table.is_empty() {
            ptr::null_mut()
        } else {
            table.as_mut_ptr().cast()
        };
        // SAFETY: `output` is null with `size` 0, or `table`'s `size`
        // writable bytes, and `size` outlives the call, which writes at most
        // `size` bytes to `output` and updates `size`.
        let result = unsafe {
            GetExtendedTcpTable(
                output,
                &raw mut size,
                FALSE,
                u32::from(Row::FAMILY),
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        match result {
            NO_ERROR => {
                let Some(&count) = table.first() else {
                    return Ok(false);
                };
                let count = usize::try_from(count).map_err(|_| Errno::INVAL)?;
                let end = count
                    .checked_mul(size_of::<Row>())
                    .and_then(|length| length.checked_add(Row::ROWS_OFFSET))
                    .ok_or(Errno::INVAL)?;
                if end > size_of_val(table.as_slice()) {
                    return Err(Errno::INVAL);
                }
                // SAFETY: the `count` rows, which the call wrote, lie within
                // `table`, aligned for `Row` (asserted above), and any bytes
                // are a valid `Row`, as `TcpListenerRow` requires.
                let rows = unsafe {
                    slice::from_raw_parts(
                        table
                            .as_ptr()
                            .cast::<u8>()
                            .add(Row::ROWS_OFFSET)
                            .cast::<Row>(),
                        count,
                    )
                };
                return Ok(rows.iter().any(matches));
            }
            ERROR_INSUFFICIENT_BUFFER => {
                let words = usize::try_from(size.div_ceil(4)).map_err(|_| Errno::NOMEM)?;
                table
                    .try_reserve_exact(words.saturating_sub(table.len()))
                    .map_err(|_| Errno::NOMEM)?;
                table.resize(words, 0);
            }
            error => return Err(Errno(error.cast_signed())),
        }
    }
    Err(Errno::NOBUFS)
}

/// Returns the port of a TCP table's row, which holds it in network byte
/// order in its first two bytes.
fn table_port(field: u32) -> u16 {
    let [high, low, ..] = field.to_ne_bytes();
    u16::from_be_bytes([high, low])
}

#[allow(clippy::cast_possible_truncation)]
fn raw_socket(socket: &impl AsRawSocket) -> SOCKET {
    // A `SOCKET` is pointer-sized, which on x86_64 holds every raw socket.
    socket.as_raw_socket() as SOCKET
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
        HostWaiter as _, Network, Poller, ReceiveMode, Socket,
    };
    use crate::fine_timer::DEFAULT_TIMER_PERIOD;
    use crate::socket::direct::RawParts;
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
            let socket = Socket::tcp(Network::default()).unwrap();
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
        let closed = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let std::net::SocketAddr::V4(peer) = closed.local_addr().unwrap() else {
            unreachable!()
        };
        drop(closed);
        let socket = Socket::udp(Network::default()).unwrap();
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
