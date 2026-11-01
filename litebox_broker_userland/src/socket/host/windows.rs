// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The Windows host: sockets through socket2 and Winsock, and events from
//! mio, which polls sockets through AFD and wakes through its completion
//! port.
//!
//! The provider expects Linux socket semantics, so this module emulates them
//! where Winsock differs:
//! - mio reports each kind of readiness once until the socket is rearmed. A
//!   TCP call that would block rearms it, and so does a read that empties
//!   the receive queue, after which Linux reports the next arrival. Other
//!   arrivals go unreported; see [`REPORTS_EVERY_ARRIVAL`].
//! - Winsock resets a connection that receives data after a read shutdown,
//!   or at once if data is queued, so a read shutdown is recorded here, and
//!   receives end the stream once the queued data is read. Linux resets a
//!   connection shut down in both directions that receives data, so once
//!   such a connection's queued data is read, Winsock is told of the read
//!   shutdown too. Until then, data that arrives is still delivered.
//! - Winsock reports a connection's error on every call, and Linux only
//!   once, after which receives end the stream and sends fail with
//!   [`Errno::PIPE`]. Winsock also still shuts down a failed connection,
//!   which Linux has closed.
//! - Winsock reports a connection that a keep-alive or retransmission
//!   timeout ends as reset, so it fails here with [`Errno::CONNRESET`],
//!   where Linux reports [`Errno::TIMEDOUT`]. Nothing tells the two apart
//!   reliably: `SIO_TCP_INFO` counts the timeouts of the connection's whole
//!   life, including those it recovered from.
//! - Winsock retries a refused TCP connect for about 2 seconds, and Linux
//!   reports the refusal at once. A loopback connect sends its SYN only
//!   once, so it fails at once when refused, and times out after 3 seconds
//!   when unanswered. Winsock also refuses a connection request once the
//!   listener's accept queue is full, which Linux drops to be retried until
//!   the queue drains, so such a loopback connect fails at once too.
//! - Winsock fails a datagram receive into a shorter output instead of
//!   truncating the datagram and reporting its length, so short receives go
//!   through a staging buffer.
//! - As on Linux, only a connected UDP socket reports ICMP errors, and none
//!   reports an ICMP time exceeded. Winsock reports only port unreachable,
//!   so the other errors Linux reports, such as protocol unreachable,
//!   administratively prohibited or fragmentation needed, go unreported.
//!   Winsock queues each error behind the datagrams that arrived first, so
//!   a receive reports one only after those datagrams, where Linux reports
//!   it first. A receive that reports one, even a peek, takes it and the
//!   errors queued right behind it, as Linux keeps only one. A receive drops
//!   the errors of sends past a connected socket's peer, which Linux does
//!   not report. Only a socket watched for reads reports them; see
//!   [`REPORTS_UNWATCHED_ERRORS`]. A send reports one only once the event
//!   thread has taken it, so a send right after one arrives can still
//!   succeed.
//! - Windows rounds a wait's timeout up to its timer resolution, 15.6ms by
//!   default, where Linux waits about as long as asked. So the event
//!   thread's waits raise this process's resolution while they have a
//!   timeout; see [`Waiter::wait`].

use std::fmt;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4};
use std::os::windows::io::AsRawSocket;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

use litebox_broker_core::BrokerError;
use litebox_broker_protocol::socket::{MAX_UDP_DATAGRAM_SIZE, SocketError};
use mio::net::{TcpStream, UdpSocket};
use mio::{Poll, Registry, Token, Waker};
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type};
use windows_sys::Win32::Media::{TIMERR_NOERROR, timeBeginPeriod, timeEndPeriod};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, FIONREAD, IN_ADDR, IN_ADDR_0, MSG_PEEK, POLLERR, POLLRDNORM, POLLWRNORM,
    SIO_TCP_INITIAL_RTO, SIO_UDP_CONNRESET, SIO_UDP_NETRESET, SO_CONNECT_TIME, SOCKADDR_IN, SOCKET,
    SOCKET_ERROR, SOL_SOCKET, TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS, TCP_INITIAL_RTO_PARAMETERS,
    WSA_NOT_ENOUGH_MEMORY, WSABUF, WSAEADDRINUSE, WSAEADDRNOTAVAIL, WSAEAFNOSUPPORT, WSAEALREADY,
    WSAECONNABORTED, WSAECONNREFUSED, WSAECONNRESET, WSAEHOSTUNREACH, WSAEINPROGRESS, WSAEINTR,
    WSAEINVAL, WSAEISCONN, WSAEMFILE, WSAEMSGSIZE, WSAENETRESET, WSAENETUNREACH, WSAENOBUFS,
    WSAENOTCONN, WSAESHUTDOWN, WSAETIMEDOUT, WSAEWOULDBLOCK, WSAGetLastError, WSAIoctl, WSAPOLLFD,
    WSAPoll, WSARecv, WSARecvFrom, WSASend, WSASendTo, getsockopt, ioctlsocket,
};

use super::{HostEvents, Interest, ReceiveMode, WAKE_TOKEN};
use crate::socket::direct::{MAX_RAW_PARTS, RawParts};

/// mio reports each kind of readiness once until the socket is rearmed, so
/// it does not report data that arrives while earlier data is queued.
pub(crate) const REPORTS_EVERY_ARRIVAL: bool = false;

/// Winsock queues a UDP socket's ICMP errors among its datagrams, so only a
/// socket watched for reads reports them.
pub(crate) const REPORTS_UNWATCHED_ERRORS: bool = false;

/// The length of the longest datagram a UDP socket receives.
const MAX_DATAGRAM_LENGTH: usize = MAX_UDP_DATAGRAM_SIZE as usize;

/// The most queued ICMP errors that a receive merges into the one it
/// reports, or drops before it reports a datagram; later receives and sends
/// drop the rest of a merged run. Tests use a bound they can exceed within
/// Windows's global limit of about 100 ICMP errors per quarter second.
const MAX_MERGED_DATAGRAM_ERRORS: usize = if cfg!(test) { 4 } else { 64 };

/// How long a loopback TCP connect waits for its only SYN to be answered;
/// Winsock waits no longer than this.
const SYN_TIMEOUT_MILLISECONDS: u16 = 3000;

/// A Winsock error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Errno(i32);

impl Errno {
    pub(crate) const INTR: Self = Self(WSAEINTR);
    pub(crate) const AGAIN: Self = Self(WSAEWOULDBLOCK);
    /// A TCP connect started, which Winsock reports as [`Self::AGAIN`].
    pub(crate) const INPROGRESS: Self = Self(WSAEINPROGRESS);
    pub(crate) const ALREADY: Self = Self(WSAEALREADY);
    pub(crate) const ISCONN: Self = Self(WSAEISCONN);
    pub(crate) const NOTCONN: Self = Self(WSAENOTCONN);
    /// The stream can no longer send, which Linux reports as `EPIPE`.
    pub(crate) const PIPE: Self = Self(WSAESHUTDOWN);
    pub(crate) const ADDRINUSE: Self = Self(WSAEADDRINUSE);
    pub(crate) const ADDRNOTAVAIL: Self = Self(WSAEADDRNOTAVAIL);
    pub(crate) const AFNOSUPPORT: Self = Self(WSAEAFNOSUPPORT);
    pub(crate) const CONNREFUSED: Self = Self(WSAECONNREFUSED);
    pub(crate) const CONNRESET: Self = Self(WSAECONNRESET);
    pub(crate) const CONNABORTED: Self = Self(WSAECONNABORTED);
    pub(crate) const NETRESET: Self = Self(WSAENETRESET);
    pub(crate) const NETUNREACH: Self = Self(WSAENETUNREACH);
    pub(crate) const HOSTUNREACH: Self = Self(WSAEHOSTUNREACH);
    pub(crate) const TIMEDOUT: Self = Self(WSAETIMEDOUT);
    pub(crate) const INVAL: Self = Self(WSAEINVAL);
    /// A datagram is longer than a receive's output.
    const MSGSIZE: Self = Self(WSAEMSGSIZE);
    pub(crate) const MFILE: Self = Self(WSAEMFILE);
    pub(crate) const NOBUFS: Self = Self(WSAENOBUFS);
    pub(crate) const NOMEM: Self = Self(WSA_NOT_ENOUGH_MEMORY);
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
pub(crate) struct HostSocket {
    source: Source,
    /// Whether the poller watches the socket.
    registered: bool,
    /// The read side is shut down. Winsock is not told, because it resets a
    /// connection that receives data after a read shutdown, until the write
    /// side is also shut down; see [`Self::shut_down_drained_receive`].
    read_shutdown: AtomicBool,
    /// The write side is shut down.
    write_shutdown: AtomicBool,
    /// Winsock was told of the read shutdown.
    receive_shut_down: AtomicBool,
    /// A TCP connect started without completing at once.
    connecting: AtomicBool,
    /// The TCP connection's error was reported.
    error_reported: AtomicBool,
    /// An error Winsock cannot raise itself, which the socket reports next,
    /// or 0.
    stashed_error: AtomicI32,
    /// A receive reported a run of a UDP socket's queued ICMP errors
    /// without taking all of them, so receives and sends drop the rest of
    /// the run.
    merging_errors: AtomicBool,
}

enum Source {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

impl HostSocket {
    /// Opens a TCP socket.
    pub(crate) fn tcp() -> Result<Self, Errno> {
        let socket = open(Type::STREAM, Protocol::TCP)?;
        Ok(Self::new(Source::Tcp(TcpStream::from_std(socket.into()))))
    }

    /// Opens a UDP socket.
    pub(crate) fn udp() -> Result<Self, Errno> {
        let socket = open(Type::DGRAM, Protocol::UDP)?;
        // Linux reports ICMP errors only to connected UDP sockets, and an
        // ICMP time exceeded, which Winsock reports as a network reset, to
        // none.
        report_icmp_errors(raw_socket(&socket), SIO_UDP_CONNRESET, false)?;
        report_icmp_errors(raw_socket(&socket), SIO_UDP_NETRESET, false)?;
        Ok(Self::new(Source::Udp(UdpSocket::from_std(socket.into()))))
    }

    fn new(source: Source) -> Self {
        Self {
            source,
            registered: false,
            read_shutdown: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false),
            receive_shut_down: AtomicBool::new(false),
            connecting: AtomicBool::new(false),
            error_reported: AtomicBool::new(false),
            stashed_error: AtomicI32::new(0),
            merging_errors: AtomicBool::new(false),
        }
    }

    fn raw(&self) -> SOCKET {
        match &self.source {
            Source::Tcp(socket) => raw_socket(socket),
            Source::Udp(socket) => raw_socket(socket),
        }
    }

    fn socket(&self) -> SockRef<'_> {
        match &self.source {
            Source::Tcp(socket) => SockRef::from(socket),
            Source::Udp(socket) => SockRef::from(socket),
        }
    }

    fn source_mut(&mut self) -> &mut dyn mio::event::Source {
        match &mut self.source {
            Source::Tcp(socket) => socket,
            Source::Udp(socket) => socket,
        }
    }

    fn is_tcp(&self) -> bool {
        matches!(self.source, Source::Tcp(_))
    }

    pub(crate) fn bind(&self, address: SocketAddrV4) -> Result<(), Errno> {
        Ok(self.socket().bind(&SockAddr::from(address))?)
    }

    /// Connects to `address`, or starts connecting a TCP socket, which fails
    /// with [`Errno::INPROGRESS`].
    pub(crate) fn connect(&self, address: SocketAddrV4) -> Result<(), Errno> {
        if !self.is_tcp() {
            report_icmp_errors(self.raw(), SIO_UDP_CONNRESET, true)?;
        } else if address.ip().is_loopback() {
            // Best effort: failing only delays reporting a refusal, and it
            // fails on a socket that is connecting or connected, whose
            // connect fails anyway.
            let _ = stop_syn_retries(self.raw());
        }
        match self.socket().connect(&SockAddr::from(address)) {
            Ok(()) => Ok(()),
            Err(error) => match Errno::from(error) {
                Errno::AGAIN if self.is_tcp() => {
                    self.connecting.store(true, Ordering::Relaxed);
                    Err(Errno::INPROGRESS)
                }
                error => {
                    if !self.is_tcp() && self.socket().peer_addr().is_err() {
                        // Linux reports no ICMP errors to the unconnected
                        // socket a failed connect leaves. Best effort:
                        // failing only reports them, and the same call just
                        // succeeded.
                        let _ = report_icmp_errors(self.raw(), SIO_UDP_CONNRESET, false);
                    }
                    Err(error)
                }
            },
        }
    }

    pub(crate) fn local_address(&self) -> Result<SocketAddrV4, Errno> {
        match self.socket().local_addr() {
            Ok(address) => address.as_socket_ipv4().ok_or(Errno::AFNOSUPPORT),
            // Winsock fails on an unbound socket, which Linux reports bound
            // to the wildcard address.
            Err(error) => match Errno::from(error) {
                Errno::INVAL => Ok(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                error => Err(error),
            },
        }
    }

    pub(crate) fn shutdown(&self, how: Shutdown) -> Result<(), Errno> {
        let socket = self.socket();
        // Linux aborts a pending connect that is shut down, which then
        // reports a reset.
        if self.connect_pending()? {
            socket.set_linger(Some(Duration::ZERO))?;
            self.stashed_error
                .store(Errno::CONNRESET.0, Ordering::Relaxed);
            return Ok(());
        }
        socket.peer_addr()?;
        // Winsock still shuts down a failed connection, which Linux has
        // closed.
        if self.error_reported.load(Ordering::Relaxed) || self.error_pending()? {
            return Err(Errno::NOTCONN);
        }
        if how != Shutdown::Read {
            socket.shutdown(Shutdown::Write)?;
            self.write_shutdown.store(true, Ordering::Relaxed);
        }
        if how != Shutdown::Write {
            self.read_shutdown.store(true, Ordering::Relaxed);
        }
        self.shut_down_drained_receive();
        Ok(())
    }

    /// Tells Winsock of the read shutdown of a TCP connection shut down in
    /// both directions once its receive queue is empty, so that data that
    /// arrives resets the connection, as on Linux.
    ///
    /// Winsock would reset the connection at once if data were queued, which
    /// would discard data that arrived before the shutdown. Data that
    /// arrives after the check resets the connection, as it does on Linux.
    fn shut_down_drained_receive(&self) {
        if !self.read_shutdown.load(Ordering::Relaxed)
            || !self.write_shutdown.load(Ordering::Relaxed)
            || self.receive_shut_down.load(Ordering::Relaxed)
            || self.queued_bytes() != Ok(0)
        {
            return;
        }
        // Best effort: failing only leaves later data delivered, and it fails
        // only on a failed connection, which receives no more data.
        if self.socket().shutdown(Shutdown::Read).is_ok() {
            self.receive_shut_down.store(true, Ordering::Relaxed);
        }
    }

    /// Sends `data` with one system call, to `destination` if set, and
    /// returns how many bytes it sent.
    ///
    /// A UDP socket fails with `AGAIN`, sending nothing, while it drops what
    /// remains queued of a run of ICMP errors whose first it reported; see
    /// [`Self::drop_merged_errors`].
    pub(crate) fn send(
        &self,
        data: RawParts<'_>,
        destination: Option<SocketAddrV4>,
    ) -> Result<usize, Errno> {
        if !self.is_tcp() && !self.drop_merged_errors() {
            return Err(Errno::AGAIN);
        }
        let result = send_parts(self.raw(), data, destination);
        if self.is_tcp() {
            result.or_else(|error| self.stream_error(error, false))
        } else {
            result.map_err(datagram_error)
        }
    }

    /// Sends the datagram `data` to `destination` with one system call from
    /// the source address an unconnected socket would use, and returns how
    /// many bytes it sent.
    ///
    /// Winsock selects even a connected socket's source for each destination.
    pub(crate) fn send_as_unconnected(
        &self,
        data: RawParts<'_>,
        destination: SocketAddrV4,
    ) -> Result<usize, Errno> {
        self.send(data, Some(destination))
    }

    /// Receives stream data into `output` with one system call.
    pub(crate) fn receive(&self, output: RawParts<'_>, mode: ReceiveMode) -> Result<usize, Errno> {
        let (buffers, count) = wsabufs(output)?;
        match receive_into(self.raw(), &buffers[..count], mode.is_peek(), None) {
            Ok(received) => {
                if mode == ReceiveMode::Read && received != 0 && self.queued_bytes() == Ok(0) {
                    self.rearm();
                    self.shut_down_drained_receive();
                }
                Ok(received)
            }
            Err(error) => self.stream_error(error, true),
        }
    }

    /// Receives the datagram at the head of the socket into `output`,
    /// leaving it queued with `peek`.
    ///
    /// Returns the datagram's full length, even if `output` is shorter, and
    /// its source, if IPv4. Fails with `AGAIN`, possibly with entries still
    /// queued, once it drops [`MAX_MERGED_DATAGRAM_ERRORS`] errors of sends
    /// past a connected socket's peer, or of a run whose first it reported;
    /// [`Self::discard_datagram`] empties a queue.
    pub(crate) fn receive_datagram(
        &self,
        output: RawParts<'_>,
        peek: bool,
    ) -> Result<(usize, Option<SocketAddrV4>), Errno> {
        // Bound the work that a flood of ICMP errors causes.
        for _ in 0..MAX_MERGED_DATAGRAM_ERRORS {
            let mut source = None;
            match self.receive_datagram_once(output, peek, &mut source) {
                Ok(received) => {
                    self.merging_errors.store(false, Ordering::Relaxed);
                    return Ok((received, source));
                }
                Err(Errno::CONNRESET)
                    if self.merging_errors.load(Ordering::Relaxed)
                        || self.reports_another_destination(source) =>
                {
                    if peek {
                        let _ = self.take_head();
                    }
                }
                Err(Errno::CONNRESET) => {
                    self.take_queued_errors(peek);
                    return Err(datagram_error(Errno::CONNRESET));
                }
                Err(error) => {
                    if error != Errno::INTR {
                        self.merging_errors.store(false, Ordering::Relaxed);
                    }
                    return Err(datagram_error(error));
                }
            }
        }
        // A run of errors may end at the bound.
        if self.merging_errors.load(Ordering::Relaxed) && !self.error_queued() {
            self.merging_errors.store(false, Ordering::Relaxed);
        }
        Err(Errno::AGAIN)
    }

    /// Reports whether an ICMP error that Winsock reports from `source`
    /// concerns a destination other than a connected socket's peer, as one
    /// that a send past the peer causes does. Linux reports no such error.
    fn reports_another_destination(&self, source: Option<SocketAddrV4>) -> bool {
        let peer = self.socket().peer_addr().ok();
        matches!((peer.as_ref().and_then(SockAddr::as_socket_ipv4), source),
            (Some(peer), Some(source)) if peer != source)
    }

    /// Discards the datagram or ICMP error at the head of a UDP socket.
    ///
    /// Fails with the error it discards, or with `AGAIN` if neither is
    /// queued. Unlike [`Self::receive_datagram`], it discards the errors of
    /// sends past a connected socket's peer one at a time.
    pub(crate) fn discard_datagram(&self) -> Result<(), Errno> {
        let result = self.take_head();
        if !matches!(result, Err(Errno::CONNRESET | Errno::INTR)) {
            self.merging_errors.store(false, Ordering::Relaxed);
        }
        match result {
            // A receive that does not peek discards a datagram longer than
            // its output.
            Ok(_) | Err(Errno::MSGSIZE) => Ok(()),
            Err(error) => Err(datagram_error(error)),
        }
    }

    /// Takes the datagram or ICMP error at the head of a UDP socket.
    fn take_head(&self) -> Result<usize, Errno> {
        let buffers = [WSABUF {
            len: 0,
            buf: NonNull::dangling().as_ptr(),
        }];
        receive_into(self.raw(), &buffers, false, None)
    }

    /// Takes the ICMP errors queued at the head of a UDP socket after a
    /// receive reported the first, which a peek left queued.
    ///
    /// Winsock queues each error among the datagrams, where Linux keeps one
    /// pending error, which a peek takes too. If more errors remain queued,
    /// later receives drop them.
    fn take_queued_errors(&self, peeked: bool) {
        if peeked {
            let _ = self.take_head();
        }
        // Bound the work that a flood of ICMP errors causes.
        for _ in 0..MAX_MERGED_DATAGRAM_ERRORS {
            if !self.error_queued() {
                return;
            }
            let _ = self.take_head();
        }
        self.merging_errors
            .store(self.error_queued(), Ordering::Relaxed);
    }

    /// Drops what remains queued of a run of ICMP errors that a receive
    /// reported, before a UDP send, and reports whether the run ended.
    ///
    /// Callers send only once the run's error is taken. Linux merged the
    /// errors queued before then into that error, and reports the error of a
    /// later send, so a send waits for the run to end, lest its error join
    /// the run or the rest of the run be reported as another.
    fn drop_merged_errors(&self) -> bool {
        if !self.merging_errors.load(Ordering::Relaxed) {
            return true;
        }
        // Bound the work that a flood of ICMP errors causes.
        for _ in 0..MAX_MERGED_DATAGRAM_ERRORS {
            if !self.error_queued() {
                break;
            }
            let _ = self.take_head();
        }
        let ended = !self.error_queued();
        self.merging_errors.store(!ended, Ordering::Relaxed);
        ended
    }

    /// Reports whether an ICMP error is at the head of a UDP socket.
    fn error_queued(&self) -> bool {
        let buffers = [WSABUF {
            len: 0,
            buf: NonNull::dangling().as_ptr(),
        }];
        // A zero-length peek of a datagram fails with `WSAEMSGSIZE` and
        // leaves it queued.
        receive_into(self.raw(), &buffers, true, None) == Err(Errno::CONNRESET)
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

    /// Returns how many bytes a stream receive could take now.
    pub(crate) fn queued_bytes(&self) -> Result<usize, Errno> {
        let mut queued = 0_u32;
        // SAFETY: `queued` outlives the call, which writes only it.
        if unsafe { ioctlsocket(self.raw(), FIONREAD, &raw mut queued) } == SOCKET_ERROR {
            return Err(Errno::last());
        }
        usize::try_from(queued).map_err(|_| Errno::INVAL)
    }

    /// Returns the length of the datagram at the head of a UDP socket, or 0
    /// if none is queued.
    #[cfg(test)]
    pub(crate) fn head_datagram_length(&self) -> Result<usize, Errno> {
        // On a datagram socket, `FIONREAD` reports every queued datagram.
        match self.receive_datagram_once(RawParts::EMPTY, true, &mut None) {
            Ok(length) => Ok(length),
            Err(Errno::AGAIN) => Ok(0),
            Err(error) => Err(datagram_error(error)),
        }
    }

    /// Takes the socket's pending error, if any.
    pub(crate) fn take_error(&self) -> Result<Option<Errno>, Errno> {
        let stashed = self.stashed_error.swap(0, Ordering::Relaxed);
        if stashed != 0 {
            self.error_reported.store(true, Ordering::Relaxed);
            return Ok(Some(Errno(stashed)));
        }
        if !self.is_tcp() {
            return Ok(self
                .socket()
                .take_error()?
                .map(|error| datagram_error(error.into())));
        }
        if self.error_reported.load(Ordering::Relaxed) || !self.error_polled()? {
            return Ok(None);
        }
        let error = self.connection_error()?;
        self.error_reported.store(true, Ordering::Relaxed);
        Ok(Some(error))
    }

    /// Reports whether the socket has a pending error, without taking it.
    pub(crate) fn error_pending(&self) -> Result<bool, Errno> {
        if self.stashed_error.load(Ordering::Relaxed) != 0 {
            return Ok(true);
        }
        if !self.is_tcp() || self.error_reported.load(Ordering::Relaxed) {
            return Ok(false);
        }
        self.error_polled()
    }

    /// Reports whether a TCP connect is still in progress.
    fn connect_pending(&self) -> Result<bool, Errno> {
        if !self.connecting.load(Ordering::Relaxed)
            || self.error_reported.load(Ordering::Relaxed)
            || self.error_pending()?
        {
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
            return Ok(self.stream_error_code(error.into()));
        }
        // Winsock reports a reset to receives rather than in `SO_ERROR`.
        let (buffers, count) = wsabufs(RawParts::EMPTY)?;
        match receive_into(self.raw(), &buffers[..count], true, None) {
            Err(error) if error != Errno::AGAIN => Ok(self.stream_error_code(error)),
            _ => Ok(Errno::CONNRESET),
        }
    }

    /// Maps a TCP call's error to the one Linux reports.
    fn stream_error_code(&self, error: Errno) -> Errno {
        match error {
            // Winsock reports a keep-alive failure this way only to a call
            // in progress, which a nonblocking call never is, and to later
            // calls as a reset; see the module docs.
            Errno::NETRESET => Errno::TIMEDOUT,
            // Winsock reports the reset of data that arrives after a read
            // shutdown as an abort, and Linux as a reset.
            Errno::CONNABORTED if self.receive_shut_down.load(Ordering::Relaxed) => {
                Errno::CONNRESET
            }
            error => error,
        }
    }

    /// Maps the error of a TCP call to the result Linux reports; a receive
    /// ends the stream where Linux's would.
    fn stream_error(&self, error: Errno, receiving: bool) -> Result<usize, Errno> {
        let error = match error {
            Errno::AGAIN if receiving && self.read_shutdown.load(Ordering::Relaxed) => {
                self.shut_down_drained_receive();
                return Ok(0);
            }
            // Winsock fails receives once told of the read shutdown.
            Errno::PIPE if receiving && self.receive_shut_down.load(Ordering::Relaxed) => {
                return Ok(0);
            }
            Errno::AGAIN => {
                self.rearm();
                return Err(Errno::AGAIN);
            }
            // Winsock fails calls on a pending or failed connect, where Linux
            // would block or report the failure.
            Errno::NOTCONN if self.connecting.load(Ordering::Relaxed) => match self.take_error()? {
                Some(error) => return Err(error),
                None if !self.error_reported.load(Ordering::Relaxed) => return Err(Errno::AGAIN),
                // Already reported, which the check below handles.
                None => Errno::CONNRESET,
            },
            error => self.stream_error_code(error),
        };
        if is_connection_error(error) && self.error_reported.swap(true, Ordering::Relaxed) {
            return if receiving { Ok(0) } else { Err(Errno::PIPE) };
        }
        Err(error)
    }

    /// Has mio report the stream's readiness again, as Linux reports each
    /// change in it.
    fn rearm(&self) {
        if let Source::Tcp(stream) = &self.source {
            // `try_io` rearms the socket when its closure would block. Failing
            // to rearm loses events, which the next call that would block
            // rearms again.
            let _ = stream.try_io(|| Err::<(), _>(Error::from(ErrorKind::WouldBlock)));
        }
    }

    pub(crate) fn set_no_delay(&self, value: bool) -> Result<(), Errno> {
        Ok(self.socket().set_tcp_nodelay(value)?)
    }

    #[cfg(test)]
    pub(crate) fn no_delay(&self) -> Result<bool, Errno> {
        Ok(self.socket().tcp_nodelay()?)
    }

    pub(crate) fn set_keep_alive(&self, value: bool) -> Result<(), Errno> {
        Ok(self.socket().set_keepalive(value)?)
    }

    #[cfg(test)]
    pub(crate) fn keep_alive(&self) -> Result<bool, Errno> {
        Ok(self.socket().keepalive()?)
    }

    /// Makes closing the socket reset its connection instead of finishing
    /// it.
    pub(crate) fn set_linger_zero(&self) -> Result<(), Errno> {
        Ok(self.socket().set_linger(Some(Duration::ZERO))?)
    }

    pub(crate) fn set_receive_buffer_size(&self, size: usize) -> Result<(), Errno> {
        Ok(self.socket().set_recv_buffer_size(size)?)
    }

    pub(crate) fn receive_buffer_size(&self) -> Result<usize, Errno> {
        Ok(self.socket().recv_buffer_size()?)
    }
}

/// Opens a nonblocking, non-inheritable IPv4 socket.
fn open(socket_type: Type, protocol: Protocol) -> Result<Socket, Errno> {
    let socket = Socket::new(Domain::IPV4, socket_type, Some(protocol))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
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

/// Has a TCP socket send its connect's SYN only once, so a refused connect
/// fails at once, as on Linux, rather than after about 2 seconds of retries.
///
/// Winsock retries a refused SYN as it does a lost one, so this also stops
/// those retries. Only loopback connects use this, which lose no SYNs. A
/// connect to a listener that never answers times out after 3 seconds, the
/// longest initial timeout Winsock allows, rather than 21. And Winsock
/// refuses a connection request once the listener's accept queue is full,
/// where Linux drops it to be retried, so a connect to such a listener is
/// refused at once rather than retried until the queue drains.
fn stop_syn_retries(socket: SOCKET) -> Result<(), Errno> {
    let parameters = TCP_INITIAL_RTO_PARAMETERS {
        Rtt: SYN_TIMEOUT_MILLISECONDS,
        // The field is a byte, which holds the constant's low byte.
        #[allow(clippy::cast_possible_truncation)]
        MaxSynRetransmissions: TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS as u8,
    };
    let mut returned = 0_u32;
    // SAFETY: `parameters` and `returned` outlive the call, which reads only
    // `parameters` and writes only `returned`, and the call is not
    // overlapped.
    let result = unsafe {
        WSAIoctl(
            socket,
            SIO_TCP_INITIAL_RTO,
            ptr::from_ref(&parameters).cast(),
            TCP_INITIAL_RTO_PARAMETERS_LENGTH,
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

/// Maps a UDP call's error to the one Linux reports.
const fn datagram_error(error: Errno) -> Errno {
    match error {
        // Winsock reports an ICMP port unreachable as a reset.
        Errno::CONNRESET => Errno::CONNREFUSED,
        error => error,
    }
}

/// Whether `error` reports that a TCP connection failed.
const fn is_connection_error(error: Errno) -> bool {
    matches!(
        error,
        Errno::CONNREFUSED
            | Errno::CONNRESET
            | Errno::CONNABORTED
            | Errno::TIMEDOUT
            | Errno::NETUNREACH
            | Errno::HOSTUNREACH
    )
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
    /// Whether the waiter raised the process's timer resolution to
    /// [`FINE_TIMER_PERIOD_MS`].
    fine_timer: bool,
}

/// The timer resolution, in milliseconds, of a wait with a timeout.
const FINE_TIMER_PERIOD_MS: u32 = 1;

impl Poller {
    pub(crate) fn new() -> IoResult<(Self, Waiter)> {
        let poll = Poll::new()?;
        let registry = poll.registry().try_clone()?;
        let waker = Waker::new(&registry, Token(token(WAKE_TOKEN)?))?;
        let waiter = Waiter {
            poll,
            fine_timer: false,
        };
        Ok((Self { registry, waker }, waiter))
    }

    /// Watches `socket` for `interest`, reporting its events under `token`.
    pub(crate) fn add(
        &self,
        socket: &mut HostSocket,
        token: u64,
        interest: Interest,
    ) -> Result<(), Errno> {
        self.watch(socket, token, interest)
    }

    /// Replaces the interest a watched `socket` is watched for.
    pub(crate) fn modify(
        &self,
        socket: &mut HostSocket,
        token: u64,
        interest: Interest,
    ) -> Result<(), Errno> {
        self.watch(socket, token, interest)
    }

    fn watch(&self, socket: &mut HostSocket, token: u64, interest: Interest) -> Result<(), Errno> {
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
            // keeps errors from raising events, which Linux allows.
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

    /// Stops watching `socket` before it closes.
    pub(crate) fn delete(&self, socket: &mut HostSocket) {
        if socket.registered {
            let _ = self.registry.deregister(socket.source_mut());
            socket.registered = false;
        }
    }

    /// Wakes the waiter, which reports an event under [`WAKE_TOKEN`].
    pub(crate) fn wake(&self) -> IoResult<()> {
        self.waker.wake()
    }
}

impl Waiter {
    /// Waits for events, at most `timeout` if set, and replaces `events`
    /// with them.
    ///
    /// Windows rounds a timeout up to the process's timer resolution, 15.6ms
    /// by default, and the provider sets one only to retry events soon. So
    /// while waits have a timeout, the waiter raises the resolution to
    /// [`FINE_TIMER_PERIOD_MS`], and restores it at the first wait without
    /// one. Since Windows 10 2004, this affects only this process.
    pub(crate) fn wait(
        &mut self,
        events: &mut Events,
        timeout: Option<Duration>,
    ) -> Result<(), Errno> {
        self.set_fine_timer(timeout.is_some());
        Ok(self.poll.poll(&mut events.0, timeout)?)
    }

    fn set_fine_timer(&mut self, fine: bool) {
        if fine == self.fine_timer {
            return;
        }
        // SAFETY: Both functions take only an integer, and the waiter ends
        // only a period it began.
        let result = unsafe {
            if fine {
                timeBeginPeriod(FINE_TIMER_PERIOD_MS)
            } else {
                timeEndPeriod(FINE_TIMER_PERIOD_MS)
            }
        };
        // If raising the resolution fails, retries are only slower.
        if result == TIMERR_NOERROR {
            self.fine_timer = fine;
        }
    }

    /// Consumes the wakes a [`WAKE_TOKEN`] event reported.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    pub(crate) fn drain_wake(&self) -> Result<(), Errno> {
        // Each wake is a completion that the wait already consumed.
        Ok(())
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        self.set_fine_timer(false);
    }
}

/// Room for the events one [`Waiter::wait`] reports.
pub(crate) struct Events(mio::Events);

impl Events {
    /// Allocates room for `capacity` events.
    ///
    /// mio aborts if the allocation fails, so this never returns `None`.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn with_capacity(capacity: usize) -> Option<Self> {
        Some(Self(mio::Events::with_capacity(capacity)))
    }

    /// Returns the token and events of each event the last wait reported.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (u64, HostEvents)> + '_ {
        self.0
            .iter()
            .map(|event| (event.token().0 as u64, host_events(event)))
    }
}

fn host_events(event: &mio::event::Event) -> HostEvents {
    let mut events = HostEvents::empty();
    if event.is_readable() {
        events |= HostEvents::READABLE;
    }
    if event.is_writable() {
        events |= HostEvents::WRITABLE;
    }
    if event.is_read_closed() {
        events |= HostEvents::READ_CLOSED;
    }
    // mio reports a reset or a failed connect as closing the write side,
    // which Linux reports as a hang-up with an error.
    if event.is_write_closed() {
        events |= HostEvents::HANGUP | HostEvents::ERROR;
    }
    if event.is_error() {
        events |= HostEvents::ERROR;
    }
    events
}

fn token(token: u64) -> Result<usize, Errno> {
    usize::try_from(token).map_err(|_| Errno::INVAL)
}

/// Maps a socket operation's error to the error the guest observes.
pub(crate) const fn socket_error_from_errno(error: Errno) -> SocketError {
    match error {
        Errno::CONNREFUSED => SocketError::ConnectionRefused,
        Errno::CONNRESET | Errno::PIPE => SocketError::ConnectionReset,
        Errno::CONNABORTED => SocketError::ConnectionAborted,
        Errno::NETUNREACH => SocketError::NetworkUnreachable,
        Errno::HOSTUNREACH => SocketError::HostUnreachable,
        Errno::TIMEDOUT => SocketError::TimedOut,
        Errno::ADDRINUSE => SocketError::AddressInUse,
        Errno::ADDRNOTAVAIL => SocketError::AddressNotAvailable,
        Errno::NOTCONN => SocketError::NotConnected,
        Errno::INVAL => SocketError::InvalidArgument,
        _ => SocketError::Other,
    }
}

/// Maps an error that reports the host out of a resource to the broker's.
pub(crate) const fn broker_resource_error_from_errno(error: Errno) -> Option<BrokerError> {
    match error {
        Errno::NOMEM | Errno::OUTOFMEMORY => Some(BrokerError::OutOfMemory),
        Errno::MFILE | Errno::NOBUFS => Some(BrokerError::ResourceExhausted),
        _ => None,
    }
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

#[allow(clippy::cast_possible_truncation)]
const TCP_INITIAL_RTO_PARAMETERS_LENGTH: u32 = size_of::<TCP_INITIAL_RTO_PARAMETERS>() as u32;

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
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use super::{Errno, Events, HostSocket, MAX_MERGED_DATAGRAM_ERRORS, Poller};
    use crate::socket::direct::RawParts;

    /// A send after a connected UDP socket reported a long run of ICMP errors
    /// drops the rest of the run, which Linux merges into the error it
    /// reported, and waits for the run to end, but the send's own error
    /// starts another run.
    #[test]
    fn a_send_after_a_reported_icmp_error_run_ends_the_run() {
        let closed = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let std::net::SocketAddr::V4(peer) = closed.local_addr().unwrap() else {
            unreachable!()
        };
        drop(closed);
        let socket = HostSocket::udp().unwrap();
        socket.connect(peer).unwrap();
        // Reports the first of `errors` errors and merges as many more as a
        // receive does.
        let report_long_run = |errors| {
            for _ in 0..errors {
                assert_eq!(socket.send(RawParts::EMPTY, None), Ok(0));
            }
            std::thread::sleep(Duration::from_millis(100));
            assert_eq!(
                socket.receive_datagram(RawParts::EMPTY, false),
                Err(Errno::CONNREFUSED)
            );
        };

        // A send drops what it can of the rest, and the next drops the rest.
        report_long_run(3 * MAX_MERGED_DATAGRAM_ERRORS + 1);
        let reopened = std::net::UdpSocket::bind(peer).unwrap();
        reopened
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        assert_eq!(socket.send(RawParts::EMPTY, None), Err(Errno::AGAIN));
        assert_eq!(socket.send(RawParts::EMPTY, None), Ok(0));
        assert_eq!(reopened.recv(&mut [0; 1]).unwrap(), 0);
        assert_eq!(
            socket.receive_datagram(RawParts::EMPTY, false),
            Err(Errno::AGAIN)
        );
        drop(reopened);

        report_long_run(2 * MAX_MERGED_DATAGRAM_ERRORS + 1);
        assert_eq!(socket.send(RawParts::EMPTY, None), Ok(0));
        std::thread::sleep(Duration::from_millis(100));
        let mut results = Vec::new();
        for _ in 0..=2 * MAX_MERGED_DATAGRAM_ERRORS {
            let result = socket.receive_datagram(RawParts::EMPTY, false);
            results.push(result);
            if result != Err(Errno::AGAIN) {
                break;
            }
        }
        assert_eq!(
            results.last(),
            Some(&Err(Errno::CONNREFUSED)),
            "{results:?}"
        );
    }

    #[test]
    fn timed_waits_end_soon_after_their_timeout() {
        const WAITS: u32 = 20;
        let (_poller, mut waiter) = Poller::new().unwrap();
        let mut events = Events::with_capacity(1).unwrap();
        let start = Instant::now();
        for _ in 0..WAITS {
            waiter
                .wait(&mut events, Some(Duration::from_millis(1)))
                .unwrap();
        }
        // At the default timer resolution, each wait takes 15.6ms.
        let elapsed = start.elapsed();
        assert!(elapsed < WAITS * Duration::from_millis(8), "{elapsed:?}");
    }
}
