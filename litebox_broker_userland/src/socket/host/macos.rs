// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The macOS host: sockets through rustix and libc, and events from kqueue,
//! woken through an `EVFILT_USER` event.
//!
//! Where macOS sockets fall short of the host contract, the code that makes
//! up the difference says how:
//! - Sockets open without atomic close-on-exec, so they open under the
//!   broker's spawn fence; see [`Socket::open`].
//! - Nothing reports a pending `SO_ERROR` without taking it, so a socket
//!   caches the error it takes until a call reports it; see
//!   [`Socket::pending_error`].
//! - A send after a connection failed reports `EPIPE`, and one on a pending
//!   connect `ENOTCONN`; see [`Socket::stream_send_error`].
//! - A read shutdown discards queued data, so it is not given to the host;
//!   see [`Socket::read_shutdown`].
//! - A receive with `MSG_TRUNC` returns the copied length, so a datagram's
//!   full length comes from `SO_NREAD`; see [`HostSocket::receive_datagram`].
//! - A connected UDP socket refuses a send that names its peer, a receive
//!   into no buffers fails, and one into no bytes returns at once even with
//!   nothing queued; see [`Socket::receive_datagram_parts`].
//! - A UDP socket's send buffer limits its datagrams; see
//!   [`HostSocket::udp`].
//! - A peek that reports a UDP socket's error leaves it pending.
//! - A connected UDP socket refuses to send elsewhere, so a helper socket on
//!   its port sends past its peer; see [`HostSocket::send_as_unconnected`].
//! - kqueue reports the read and write sides as separate events, so a wait
//!   merges a socket's events and derives a hang-up; see
//!   [`HostEventBuffer::iter`].

use core::fmt;
use std::cell::Cell;
use std::io::{Error, Result as IoResult};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd as _, OwnedFd, RawFd};
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use litebox_broker_core::BrokerError;
use rustix::io::{Errno as RustixErrno, FdFlags, fcntl_setfd, ioctl_fionbio, ioctl_fionread};
use rustix::net::{
    AddressFamily, Protocol, Shutdown as HostShutdown, SocketType, bind, connect, getpeername,
    getsockname, ipproto, shutdown, socket, sockopt,
};

use super::{
    Host, HostErrno, HostEventBuffer, HostPoller, HostSocket, HostWaiter, Interest, ReceiveMode,
    SocketEvents, WAKE_TOKEN,
};
use crate::socket::direct::{MAX_RAW_PARTS, RawParts};

/// The macOS host.
pub(crate) enum Macos {}

impl Host for Macos {
    type Errno = Errno;
    type Socket = Socket;
    type Poller = Poller;
    type Waiter = Waiter;
    type EventBuffer = EventBuffer;
}

/// A macOS error code.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Errno(RustixErrno);

impl HostErrno for Errno {
    const INTR: Self = Self(RustixErrno::INTR);
    const AGAIN: Self = Self(RustixErrno::AGAIN);
    const INPROGRESS: Self = Self(RustixErrno::INPROGRESS);
    const ALREADY: Self = Self(RustixErrno::ALREADY);
    const ISCONN: Self = Self(RustixErrno::ISCONN);
    const NOTCONN: Self = Self(RustixErrno::NOTCONN);
    const PIPE: Self = Self(RustixErrno::PIPE);
    const ADDRINUSE: Self = Self(RustixErrno::ADDRINUSE);
    const ADDRNOTAVAIL: Self = Self(RustixErrno::ADDRNOTAVAIL);
    const CONNREFUSED: Self = Self(RustixErrno::CONNREFUSED);
    const CONNRESET: Self = Self(RustixErrno::CONNRESET);
    const CONNABORTED: Self = Self(RustixErrno::CONNABORTED);
    const NETUNREACH: Self = Self(RustixErrno::NETUNREACH);
    const HOSTUNREACH: Self = Self(RustixErrno::HOSTUNREACH);
    const TIMEDOUT: Self = Self(RustixErrno::TIMEDOUT);
    const INVAL: Self = Self(RustixErrno::INVAL);

    fn broker_resource_error(self) -> Option<BrokerError> {
        match self.0 {
            RustixErrno::NOMEM => Some(BrokerError::OutOfMemory),
            RustixErrno::MFILE | RustixErrno::NFILE | RustixErrno::NOBUFS | RustixErrno::NOSPC => {
                Some(BrokerError::ResourceExhausted)
            }
            _ => None,
        }
    }
}

impl From<Errno> for Error {
    fn from(error: Errno) -> Self {
        error.0.into()
    }
}

impl fmt::Debug for Errno {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, formatter)
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

/// A nonblocking, close-on-exec IPv4 host socket.
pub(crate) struct Socket {
    fd: OwnedFd,
    tcp: bool,
    /// The error that a call took from `SO_ERROR` without reporting it, which
    /// the next call that would report the socket's error reports instead.
    /// macOS reports a pending error only by taking it.
    error: Cell<Option<Errno>>,
    /// The TCP socket's read side is shut down. macOS is not told, because
    /// it discards queued data on a read shutdown.
    read_shutdown: Cell<bool>,
    /// The UDP socket that sends past a connected socket's peer, bound to its
    /// port; see [`HostSocket::send_as_unconnected`].
    unconnected_sender: Cell<Option<OwnedFd>>,
    /// The peer of a connected UDP socket. macOS refuses a send that names a
    /// connected socket's destination, even its peer.
    udp_peer: Cell<Option<SocketAddrV4>>,
}

impl Socket {
    /// Opens a socket with no runner spawn in between, which would inherit
    /// it: macOS sets neither close-on-exec nor nonblocking atomically.
    fn open(socket_type: SocketType, protocol: Protocol) -> Result<Self, Errno> {
        let fd = open_fd(socket_type, protocol)?;
        Ok(Self {
            fd,
            tcp: socket_type == SocketType::STREAM,
            error: Cell::new(None),
            read_shutdown: Cell::new(false),
            unconnected_sender: Cell::new(None),
            udp_peer: Cell::new(None),
        })
    }

    /// Takes the socket's pending error: the cached one, or else the one in
    /// `SO_ERROR`.
    fn pending_error(&self) -> Result<Option<Errno>, Errno> {
        if let Some(error) = self.error.take() {
            return Ok(Some(error));
        }
        take_socket_error(&self.fd)
    }

    /// Maps the error of a TCP send to the one the host contract has it
    /// report. macOS fails a send on a failed connection with `EPIPE`, and
    /// one on a pending connect with `ENOTCONN`, leaving the connection's
    /// error in `SO_ERROR`.
    fn stream_send_error(&self, error: Errno) -> Errno {
        match error {
            Errno::PIPE | Errno::NOTCONN => {
                if let Ok(Some(failure)) = self.pending_error() {
                    return failure;
                }
                if error == Errno::NOTCONN && self.connect_pending() == Ok(true) {
                    return Errno::AGAIN;
                }
                error
            }
            error => error,
        }
    }

    /// Returns the length of the datagram at the head of a UDP socket, or 0
    /// if none is queued.
    fn head_length(&self) -> Result<usize, Errno> {
        let length = get_option(&self.fd, libc::SOL_SOCKET, libc::SO_NREAD)?;
        usize::try_from(length).map_err(|_| Errno(RustixErrno::OVERFLOW))
    }

    /// Receives a datagram as [`receive_parts`] does. A peek that fails with
    /// the socket's error takes it, which macOS leaves pending.
    ///
    /// macOS returns nothing at once for a receive into no bytes, even with
    /// nothing queued, so one that reports no source fails with `AGAIN`.
    fn receive_datagram_parts(
        &self,
        output: RawParts<'_>,
        flags: libc::c_int,
    ) -> Result<(usize, Option<SocketAddrV4>), Errno> {
        match receive_parts(&self.fd, output, flags) {
            Ok((0, None)) if output.len() == 0 => Err(Errno::AGAIN),
            Ok(received) => Ok(received),
            Err(error) => {
                if flags & libc::MSG_PEEK != 0 && error != Errno::AGAIN && error != Errno::INTR {
                    // The error is reported either way; failing to take it
                    // can only report it again.
                    let _ = take_socket_error(&self.fd);
                }
                Err(error)
            }
        }
    }

    /// Opens the socket that sends past a connected UDP socket's peer: one
    /// bound to the socket's port on the wildcard address, so that the route
    /// selects its source address. `SO_REUSEPORT` lets it share the port. It
    /// receives what a connected socket would drop, and drops it at once
    /// with its minimal receive buffer.
    ///
    /// The connected socket keeps `SO_REUSEPORT` for the rest of its life, so
    /// meanwhile another process of the same user that also sets it can bind
    /// the port.
    fn open_unconnected_sender(&self) -> Result<OwnedFd, Errno> {
        let port = self.local_address()?.port();
        sockopt::set_socket_reuseport(&self.fd, true).map_err(Errno)?;
        let sender = open_fd(SocketType::DGRAM, ipproto::UDP)?;
        sockopt::set_socket_reuseport(&sender, true).map_err(Errno)?;
        sockopt::set_socket_recv_buffer_size(&sender, 1).map_err(Errno)?;
        sockopt::set_socket_send_buffer_size(&sender, MAX_DATAGRAM_LENGTH).map_err(Errno)?;
        bind(&sender, &SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).map_err(Errno)?;
        Ok(sender)
    }
}

/// Opens a nonblocking, close-on-exec IPv4 socket under the broker's spawn
/// fence.
fn open_fd(socket_type: SocketType, protocol: Protocol) -> Result<OwnedFd, Errno> {
    crate::runner::without_concurrent_spawn(|| {
        let fd = socket(AddressFamily::INET, socket_type, Some(protocol)).map_err(Errno)?;
        fcntl_setfd(&fd, FdFlags::CLOEXEC).map_err(Errno)?;
        Ok(fd)
    })
    .and_then(|fd| {
        ioctl_fionbio(&fd, true).map_err(Errno)?;
        Ok(fd)
    })
}

impl HostSocket for Socket {
    type Errno = Errno;

    fn tcp() -> Result<Self, Errno> {
        Self::open(SocketType::STREAM, ipproto::TCP)
    }

    /// macOS limits a datagram to the socket's send buffer, by default
    /// `net.inet.udp.maxdgram` (9216) bytes, so the buffer is raised to hold
    /// the longest one.
    fn udp() -> Result<Self, Errno> {
        let socket = Self::open(SocketType::DGRAM, ipproto::UDP)?;
        sockopt::set_socket_send_buffer_size(&socket.fd, MAX_DATAGRAM_LENGTH).map_err(Errno)?;
        Ok(socket)
    }

    fn bind(&self, address: SocketAddrV4) -> Result<(), Errno> {
        bind(&self.fd, &address).map_err(Errno)
    }

    /// A UDP socket whose reconnect fails is left unconnected.
    fn connect(&self, address: SocketAddrV4) -> Result<(), Errno> {
        let result = connect(&self.fd, &address).map_err(Errno);
        if !self.tcp {
            self.udp_peer.set(result.is_ok().then_some(address));
        }
        result
    }

    fn local_address(&self) -> Result<SocketAddrV4, Errno> {
        SocketAddrV4::try_from(getsockname(&self.fd).map_err(Errno)?)
            .map_err(|_| Errno(RustixErrno::AFNOSUPPORT))
    }

    fn shutdown(&self, how: Shutdown) -> Result<(), Errno> {
        if how == Shutdown::Read {
            getpeername(&self.fd).map_err(Errno)?;
        } else {
            shutdown(&self.fd, HostShutdown::Write).map_err(Errno)?;
        }
        if how != Shutdown::Write {
            self.read_shutdown.set(true);
        }
        Ok(())
    }

    /// A send reports the cached error first, as one would report the error
    /// in `SO_ERROR`.
    fn send(&self, data: RawParts<'_>, destination: Option<SocketAddrV4>) -> Result<usize, Errno> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        let destination =
            destination.filter(|destination| self.udp_peer.get() != Some(*destination));
        send_parts(&self.fd, data, destination).map_err(|error| {
            if self.tcp {
                self.stream_send_error(error)
            } else {
                error
            }
        })
    }

    /// The helper socket that sends is unconnected, so it causes no ICMP
    /// errors that the socket reports.
    fn send_as_unconnected(
        &self,
        data: RawParts<'_>,
        destination: SocketAddrV4,
    ) -> Result<usize, Errno> {
        let sender = match self.unconnected_sender.take() {
            Some(sender) => sender,
            None => self.open_unconnected_sender()?,
        };
        let sent = send_parts(&sender, data, Some(destination));
        self.unconnected_sender.set(Some(sender));
        sent
    }

    /// Queued data is received before the connection's error, as on macOS
    /// and Linux. The cached error is reported where macOS would have
    /// reported it, and so ends the stream once it took it.
    fn receive(&self, output: RawParts<'_>, mode: ReceiveMode) -> Result<usize, Errno> {
        // A peek for the whole output fails while less is queued, unlike
        // Linux's, which returns what is queued. The provider asks for it
        // only once enough is queued or no more can arrive.
        let flags = if mode.is_peek() { libc::MSG_PEEK } else { 0 };
        let received = receive_parts(&self.fd, output, flags).map(|(received, _)| received);
        match received {
            Ok(received) if received != 0 || output.len() == 0 => Ok(received),
            Ok(_) => match self.error.take() {
                Some(cached) => Err(cached),
                None => Ok(0),
            },
            Err(error) => match self.error.take() {
                Some(cached) => Err(cached),
                // A read shutdown ends the stream once the queued data is read.
                None if error == Errno::AGAIN && self.read_shutdown.get() => Ok(0),
                None => Err(error),
            },
        }
    }

    /// The cached error is reported first, as on Linux. A peek that reports
    /// an error takes it, which macOS leaves pending.
    ///
    /// The full length of a datagram longer than `output` is the length
    /// `SO_NREAD` reports of the head while a peek holds it there; the
    /// socket has a single reader, so only a datagram that arrives at an
    /// empty queue changes its head.
    fn receive_datagram(
        &self,
        output: RawParts<'_>,
        peek: bool,
    ) -> Result<(usize, Option<SocketAddrV4>), Errno> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        if output.len() >= MAX_DATAGRAM_LENGTH {
            let flags = if peek { libc::MSG_PEEK } else { 0 };
            return self.receive_datagram_parts(output, flags);
        }
        if peek {
            let (received, source) = self.receive_datagram_parts(output, libc::MSG_PEEK)?;
            return Ok((self.head_length()?.max(received), source));
        }
        let mut head_length = self.head_length()?;
        if head_length == 0 {
            // The queue is empty, or its head is: a peek holds a datagram
            // that arrives now at the head while its length is read.
            self.receive_datagram_parts(RawParts::EMPTY, libc::MSG_PEEK)?;
            head_length = self.head_length()?;
        }
        let (received, source) = self.receive_datagram_parts(output, 0)?;
        Ok((head_length.max(received), source))
    }

    fn discard_datagram(&self) -> Result<(), Errno> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        self.receive_datagram_parts(RawParts::EMPTY, 0).map(drop)
    }

    fn queued_bytes(&self) -> Result<usize, Errno> {
        usize::try_from(ioctl_fionread(&self.fd).map_err(Errno)?)
            .map_err(|_| Errno(RustixErrno::OVERFLOW))
    }

    #[cfg(test)]
    fn head_datagram_length(&self) -> Result<usize, Errno> {
        // On a datagram socket, `FIONREAD` reports every queued datagram and
        // its source address.
        self.head_length()
    }

    /// macOS records a TCP socket's error only when its connection fails.
    fn take_error(&self) -> Result<Option<Errno>, Errno> {
        self.pending_error()
    }

    /// Takes the error from `SO_ERROR` into the socket's cache.
    fn error_pending(&self) -> Result<bool, Errno> {
        let error = self.pending_error()?;
        self.error.set(error);
        Ok(error.is_some())
    }

    /// macOS reports no peer for a pending connect, nor for a failed one, so
    /// this asks for the connection's state.
    fn connect_pending(&self) -> Result<bool, Errno> {
        // SAFETY: Every field of `tcp_connection_info` is an integer, for
        // which zero is valid.
        let mut info: libc::tcp_connection_info = unsafe { core::mem::zeroed() };
        let mut length = socklen::<libc::tcp_connection_info>();
        // SAFETY: `info` and `length` outlive the call, which writes at most
        // `length` bytes to `info`, whose integer fields any bytes are valid
        // for, and then writes only `length`.
        let result = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_CONNECTION_INFO,
                (&raw mut info).cast(),
                &raw mut length,
            )
        };
        if result != 0 {
            return Err(last_errno());
        }
        Ok(info.tcpi_state == TCPS_SYN_SENT)
    }

    fn set_no_delay(&self, value: bool) -> Result<(), Errno> {
        sockopt::set_tcp_nodelay(&self.fd, value).map_err(Errno)
    }

    #[cfg(test)]
    fn no_delay(&self) -> Result<bool, Errno> {
        sockopt::tcp_nodelay(&self.fd).map_err(Errno)
    }

    fn set_keep_alive(&self, value: bool) -> Result<(), Errno> {
        sockopt::set_socket_keepalive(&self.fd, value).map_err(Errno)
    }

    #[cfg(test)]
    fn keep_alive(&self) -> Result<bool, Errno> {
        sockopt::socket_keepalive(&self.fd).map_err(Errno)
    }

    fn set_linger_zero(&self) -> Result<(), Errno> {
        sockopt::set_socket_linger(&self.fd, Some(Duration::ZERO)).map_err(Errno)
    }

    fn set_receive_buffer_size(&self, size: usize) -> Result<(), Errno> {
        sockopt::set_socket_recv_buffer_size(&self.fd, size).map_err(Errno)
    }

    fn receive_buffer_size(&self) -> Result<usize, Errno> {
        sockopt::socket_recv_buffer_size(&self.fd).map_err(Errno)
    }
}

/// The length of the longest datagram a UDP socket receives.
const MAX_DATAGRAM_LENGTH: usize = litebox_broker_protocol::socket::MAX_UDP_DATAGRAM_SIZE as usize;

/// `TCPS_SYN_SENT` from Darwin's `netinet/tcp_fsm.h`: a connect is in
/// progress.
const TCPS_SYN_SENT: u8 = 2;

/// Takes the error in `socket`'s `SO_ERROR`.
fn take_socket_error(socket: &OwnedFd) -> Result<Option<Errno>, Errno> {
    let error = get_option(socket, libc::SOL_SOCKET, libc::SO_ERROR)?;
    Ok((error != 0).then(|| Errno(RustixErrno::from_raw_os_error(error))))
}

/// Reads the integer socket option `name` at `level`.
fn get_option(
    socket: &OwnedFd,
    level: libc::c_int,
    name: libc::c_int,
) -> Result<libc::c_int, Errno> {
    let mut value: libc::c_int = 0;
    let mut length = socklen::<libc::c_int>();
    // SAFETY: `value` and `length` outlive the call, which writes at most
    // `length` bytes to `value`, an integer that any bytes are valid for, and
    // then writes only `length`.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&raw mut value).cast(),
            &raw mut length,
        )
    };
    if result != 0 {
        return Err(last_errno());
    }
    Ok(value)
}

/// Watches host sockets with kqueue; a [`Waiter`] collects their events.
pub(crate) struct Poller {
    kqueue: Arc<OwnedFd>,
}

/// Collects a [`Poller`]'s events on the event thread.
pub(crate) struct Waiter {
    kqueue: Arc<OwnedFd>,
}

/// The `EVFILT_USER` identifier of a poller's wakes.
const WAKE_IDENT: usize = 0;

impl HostPoller for Poller {
    type Errno = Errno;
    type Socket = Socket;
    type Waiter = Waiter;

    /// A read filter with `EV_CLEAR` reports each arrival of data.
    const REPORTS_EVERY_ARRIVAL: bool = true;

    /// kqueue reports a socket's error only through the read and write
    /// filters.
    const REPORTS_UNWATCHED_ERRORS: bool = false;

    /// macOS does not let a child process inherit a kqueue, so it needs no
    /// close-on-exec.
    fn new() -> IoResult<(Self, Waiter)> {
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
                libc::EV_ADD | libc::EV_CLEAR | libc::EV_RECEIPT,
                0,
                WAKE_TOKEN,
            )],
        )?;
        Ok((
            Self {
                kqueue: Arc::clone(&kqueue),
            },
            Waiter { kqueue },
        ))
    }

    fn add(&self, socket: &mut Socket, token: u64, interest: Interest) -> Result<(), Errno> {
        self.watch(socket, token, interest)
    }

    fn modify(&self, socket: &mut Socket, token: u64, interest: Interest) -> Result<(), Errno> {
        self.watch(socket, token, interest)
    }

    fn delete(&self, socket: &mut Socket) {
        let ident = fd_ident(socket.fd.as_raw_fd());
        let flags = libc::EV_DELETE | libc::EV_RECEIPT;
        // A filter that was never added fails alone, as does every filter of
        // a socket that is about to close anyway.
        let _ = apply_changes(
            &self.kqueue,
            &mut [
                change(ident, libc::EVFILT_READ, flags, 0, 0),
                change(ident, libc::EVFILT_WRITE, flags, 0, 0),
            ],
        );
    }

    fn wake(&self) -> IoResult<()> {
        apply_changes(
            &self.kqueue,
            &mut [change(
                WAKE_IDENT,
                libc::EVFILT_USER,
                libc::EV_RECEIPT,
                libc::NOTE_TRIGGER,
                WAKE_TOKEN,
            )],
        )
        .map_err(Error::from)
    }
}

impl Poller {
    /// Sets the read and write filters of `socket` for `interest`.
    ///
    /// A filter `interest` does not request is added disabled. A filter keeps
    /// the mode it was added with, so it is always given one: `EV_CLEAR`,
    /// which reports each change once, for a stream, and `EV_DISPATCH`,
    /// which disables the filter once it reports, for a oneshot interest.
    /// Enabling a filter reports an event already present.
    fn watch(&self, socket: &Socket, token: u64, interest: Interest) -> Result<(), Errno> {
        let (read, write, mode) = match interest {
            Interest::Stream => (true, true, libc::EV_CLEAR),
            Interest::Oneshot { read, write } => (read, write, libc::EV_DISPATCH),
        };
        let flags = |enabled: bool| {
            let state = if enabled {
                libc::EV_ENABLE
            } else {
                libc::EV_DISABLE
            };
            libc::EV_ADD | libc::EV_RECEIPT | mode | state
        };
        let ident = fd_ident(socket.fd.as_raw_fd());
        apply_changes(
            &self.kqueue,
            &mut [
                change(ident, libc::EVFILT_READ, flags(read), 0, token),
                change(ident, libc::EVFILT_WRITE, flags(write), 0, token),
            ],
        )
    }
}

/// Applies `changes`, each with `EV_RECEIPT`, and returns the first error.
fn apply_changes(kqueue: &OwnedFd, changes: &mut [libc::kevent]) -> Result<(), Errno> {
    let count = libc::c_int::try_from(changes.len()).map_err(|_| Errno::INVAL)?;
    let results = changes.as_mut_ptr();
    let now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        // SAFETY: `changes` outlives the call, which reads `count` changes
        // from it and, each change asking for a receipt, writes as many
        // receipts back to it, and `now` outlives the call.
        let result = unsafe {
            libc::kevent(
                kqueue.as_raw_fd(),
                results,
                count,
                results,
                count,
                &raw const now,
            )
        };
        if result >= 0 {
            break;
        }
        let error = last_errno();
        if error != Errno::INTR {
            return Err(error);
        }
    }
    for receipt in changes.iter() {
        // A receipt reports success as error 0.
        if receipt.flags & libc::EV_ERROR != 0 && receipt.data != 0 {
            let error = i32::try_from(receipt.data).map_err(|_| Errno::INVAL)?;
            return Err(Errno(RustixErrno::from_raw_os_error(error)));
        }
    }
    Ok(())
}

/// Returns a kqueue change for `ident` and `filter`, reporting events
/// under `token`.
fn change(ident: usize, filter: i16, flags: u16, filter_flags: u32, token: u64) -> libc::kevent {
    // A token is stored in the event's pointer-sized user data, which on
    // macOS holds every `u64`.
    #[allow(clippy::cast_possible_truncation)]
    let udata = ptr::without_provenance_mut(token as usize);
    libc::kevent {
        ident,
        filter,
        flags,
        fflags: filter_flags,
        data: 0,
        udata,
    }
}

#[allow(clippy::cast_sign_loss)]
fn fd_ident(fd: RawFd) -> usize {
    // A descriptor is never negative.
    fd as usize
}

impl HostWaiter for Waiter {
    type Errno = Errno;
    type EventBuffer = EventBuffer;

    /// The wake event's `EV_CLEAR` resets it once reported.
    fn wait(&mut self, events: &mut EventBuffer, timeout: Duration) -> Result<(), Errno> {
        let timeout = libc::timespec {
            tv_sec: libc::time_t::try_from(timeout.as_secs()).map_err(|_| Errno::INVAL)?,
            tv_nsec: libc::c_long::from(timeout.subsec_nanos()),
        };
        events.merged.clear();
        let capacity = libc::c_int::try_from(events.raw.len()).map_err(|_| Errno::INVAL)?;
        // SAFETY: `events.raw` outlives the call, which writes at most
        // `capacity` events to it, and `timeout` outlives the call.
        let count = unsafe {
            libc::kevent(
                self.kqueue.as_raw_fd(),
                ptr::null(),
                0,
                events.raw.as_mut_ptr(),
                capacity,
                &raw const timeout,
            )
        };
        let count = usize::try_from(count).map_err(|_| last_errno())?;
        events.merge(count);
        Ok(())
    }
}

/// Room for the events one wait reports.
pub(crate) struct EventBuffer {
    /// The kernel's events, one per filter.
    raw: Vec<libc::kevent>,
    /// The events of the last wait, one per token.
    merged: Vec<(u64, SocketEvents)>,
}

impl HostEventBuffer for EventBuffer {
    fn with_capacity(capacity: usize) -> Option<Self> {
        let mut raw = Vec::new();
        raw.try_reserve_exact(capacity).ok()?;
        raw.resize(capacity, change(0, 0, 0, 0, 0));
        let mut merged = Vec::new();
        merged.try_reserve_exact(capacity).ok()?;
        Some(Self { raw, merged })
    }

    /// A socket's read and write events are merged. Its connection is
    /// closed in both directions, as Linux reports a hang-up, when both
    /// filters report the end of their side in one wait, or when either
    /// reports an error with it, which a connection's failure raises. A
    /// hang-up also reports an error, since a call may have taken the error
    /// the filters would have reported; the provider drops it unless an
    /// error is pending.
    ///
    /// A write filter reports a write shutdown's end once, so the peer's
    /// later end of stream is reported without a hang-up; the provider
    /// derives the closed connection from its own write shutdown.
    fn iter(&self) -> impl Iterator<Item = (u64, SocketEvents)> + '_ {
        self.merged.iter().copied()
    }
}

impl EventBuffer {
    /// Merges the first `count` raw events into one event per token.
    fn merge(&mut self, count: usize) {
        let raw = &mut self.raw[..count];
        raw.sort_unstable_by_key(|event| event.udata.addr());
        for group in raw.chunk_by(|left, right| left.udata == right.udata) {
            let mut events = SocketEvents::empty();
            let (mut read_closed, mut write_closed, mut failed) = (false, false, false);
            for event in group {
                let eof = event.flags & libc::EV_EOF != 0;
                failed |= eof && event.fflags != 0;
                match event.filter {
                    libc::EVFILT_READ => {
                        events |= SocketEvents::READABLE;
                        if eof {
                            events |= SocketEvents::READ_CLOSED;
                            read_closed = true;
                        } else if event.data == 0 {
                            // A read event without data or an end reports a
                            // pending error, or a zero-length datagram.
                            events |= SocketEvents::ERROR;
                        }
                    }
                    libc::EVFILT_WRITE => {
                        events |= SocketEvents::WRITABLE;
                        write_closed |= eof;
                    }
                    _ => {}
                }
            }
            if (read_closed && write_closed) || failed {
                events |= SocketEvents::HANGUP | SocketEvents::ERROR;
            }
            self.merged.push((group[0].udata.addr() as u64, events));
        }
    }
}

/// Sends `data` on `socket` with one system call, to `destination` if set,
/// and returns how many bytes it sent.
///
/// Bytes in at most one part go with `sendto`, which costs less per call
/// than `sendmsg`.
fn send_parts(
    socket: &OwnedFd,
    data: RawParts<'_>,
    destination: Option<SocketAddrV4>,
) -> Result<usize, Errno> {
    let socket = socket.as_raw_fd();
    let flags = libc::MSG_NOSIGNAL;
    let mut address = destination.map(sockaddr_in);
    let (name, name_length) = match address.as_mut() {
        Some(address) => (ptr::from_mut(address), socklen::<libc::sockaddr_in>()),
        None => (ptr::null_mut(), 0),
    };
    let sent = if let Some((bytes, length)) = contiguous(data) {
        // SAFETY: `address` outlives the call, and the `length` bytes at
        // `bytes` are raw bytes that are readable for the call and that the
        // kernel reads without Rust references to them.
        unsafe { libc::sendto(socket, bytes, length, flags, name.cast(), name_length) }
    } else {
        let mut iovecs = iovecs(data);
        let message = libc::msghdr {
            msg_name: name.cast(),
            msg_namelen: name_length,
            msg_iov: iovecs.as_mut_ptr(),
            msg_iovlen: iovec_count(data)?,
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        // SAFETY: The message refers to `address` and `iovecs`, which outlive
        // the call. Each iovec covers raw bytes that are readable for the call
        // and that the kernel reads without Rust references to them.
        unsafe { libc::sendmsg(socket, &raw const message, flags) }
    };
    usize::try_from(sent).map_err(|_| last_errno())
}

/// Receives into `output` from `socket` with one system call.
///
/// Returns how many bytes it received and the source address, if the socket
/// reports an IPv4 one.
fn receive_parts(
    socket: &OwnedFd,
    output: RawParts<'_>,
    flags: libc::c_int,
) -> Result<(usize, Option<SocketAddrV4>), Errno> {
    let mut address = sockaddr_in(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let mut iovecs = iovecs(output);
    let mut message = libc::msghdr {
        msg_name: ptr::from_mut(&mut address).cast(),
        msg_namelen: socklen::<libc::sockaddr_in>(),
        msg_iov: iovecs.as_mut_ptr(),
        msg_iovlen: iovec_count(output)?,
        msg_control: ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    // SAFETY: The message refers to `address` and `iovecs`, which outlive the
    // call. Each iovec covers raw bytes that are writable for the call and
    // that the kernel fills without Rust references to them.
    let received = unsafe { libc::recvmsg(socket.as_raw_fd(), &raw mut message, flags) };
    let received = usize::try_from(received).map_err(|_| last_errno())?;
    let source = (message.msg_namelen == socklen::<libc::sockaddr_in>()
        && address.sin_family == AF_INET)
        .then(|| {
            SocketAddrV4::new(
                Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(address.sin_port),
            )
        });
    Ok((received, source))
}

/// Returns an iovec for each of `parts`, followed by empty ones.
fn iovecs(parts: RawParts<'_>) -> [libc::iovec; MAX_RAW_PARTS] {
    let mut iovecs = [libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    }; MAX_RAW_PARTS];
    for (iovec, part) in iovecs.iter_mut().zip(parts.parts()) {
        *iovec = libc::iovec {
            iov_base: part.as_ptr().cast(),
            iov_len: part.len(),
        };
    }
    iovecs
}

/// Returns how many of [`iovecs`]' iovecs cover `parts`: at least one,
/// since macOS fails a receive into none.
fn iovec_count(parts: RawParts<'_>) -> Result<libc::c_int, Errno> {
    libc::c_int::try_from(parts.parts().len().max(1)).map_err(|_| Errno::INVAL)
}

/// Returns the address and length of `parts`' bytes, if they are in at most
/// one part.
fn contiguous(parts: RawParts<'_>) -> Option<(*mut libc::c_void, usize)> {
    match parts.parts() {
        [] => Some((ptr::null_mut(), 0)),
        [part] => Some((part.as_ptr().cast(), part.len())),
        _ => None,
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
const AF_INET: libc::sa_family_t = libc::AF_INET as libc::sa_family_t;

#[allow(clippy::cast_possible_truncation)]
const fn socklen<T>() -> libc::socklen_t {
    size_of::<T>() as libc::socklen_t
}

fn sockaddr_in(address: SocketAddrV4) -> libc::sockaddr_in {
    #[allow(clippy::cast_possible_truncation)]
    libc::sockaddr_in {
        sin_len: size_of::<libc::sockaddr_in>() as u8,
        sin_family: AF_INET,
        sin_port: address.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

/// Returns the error of the last failed system call.
fn last_errno() -> Errno {
    Errno(RustixErrno::from_raw_os_error(
        Error::last_os_error().raw_os_error().unwrap_or(0),
    ))
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::time::{Duration, Instant};

    use litebox_broker_core::BrokerError;
    use litebox_platform::buffer::RawBytes;
    use rustix::io::Errno as RustixErrno;

    use super::{
        Errno, EventBuffer, HostErrno as _, HostEventBuffer as _, HostPoller as _, HostSocket as _,
        HostWaiter as _, Interest, Poller, ReceiveMode, Socket, SocketAddrV4, SocketEvents,
        WAKE_TOKEN, Waiter,
    };
    use crate::socket::direct::RawParts;

    const TIMEOUT: Duration = Duration::from_secs(10);
    const TOKEN: u64 = 7;

    fn v4(address: SocketAddr) -> SocketAddrV4 {
        let SocketAddr::V4(address) = address else {
            unreachable!()
        };
        address
    }

    /// Returns a loopback address on which nothing listens.
    fn closed_address() -> SocketAddrV4 {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        v4(socket.local_addr().unwrap())
    }

    /// Waits until `waiter` reports events for [`TOKEN`] that contain
    /// `expected`, and returns them merged.
    fn wait_for(waiter: &mut Waiter, expected: SocketEvents) -> SocketEvents {
        let mut buffer = EventBuffer::with_capacity(8).unwrap();
        let mut seen = SocketEvents::empty();
        let deadline = Instant::now() + TIMEOUT;
        while !seen.contains(expected) {
            assert!(Instant::now() < deadline, "saw only {seen:?}");
            waiter.wait(&mut buffer, Duration::from_millis(50)).unwrap();
            for (token, events) in buffer.iter() {
                if token == TOKEN {
                    seen |= events;
                }
            }
        }
        seen
    }

    /// Returns a connected TCP socket and its peer.
    fn connected_tcp() -> (Socket, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = Socket::tcp().unwrap();
        match socket.connect(v4(listener.local_addr().unwrap())) {
            Ok(()) | Err(Errno::INPROGRESS) => {}
            Err(error) => panic!("{error}"),
        }
        let peer = listener.accept().unwrap().0;
        let deadline = Instant::now() + TIMEOUT;
        while socket.connect_pending().unwrap() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        (socket, peer)
    }

    #[test]
    fn resource_errors_map_to_broker_errors() {
        let cases = [
            (RustixErrno::NOMEM, Some(BrokerError::OutOfMemory)),
            (RustixErrno::NOBUFS, Some(BrokerError::ResourceExhausted)),
            (RustixErrno::MFILE, Some(BrokerError::ResourceExhausted)),
            (RustixErrno::CONNRESET, None),
        ];
        for (error, expected) in cases {
            assert_eq!(Errno(error).broker_resource_error(), expected, "{error}");
        }
    }

    #[test]
    fn sockets_are_nonblocking_and_close_on_exec() {
        for socket in [Socket::tcp().unwrap(), Socket::udp().unwrap()] {
            let fd = &socket.fd;
            assert!(
                rustix::io::fcntl_getfd(fd)
                    .unwrap()
                    .contains(rustix::io::FdFlags::CLOEXEC)
            );
            assert!(
                rustix::fs::fcntl_getfl(fd)
                    .unwrap()
                    .contains(rustix::fs::OFlags::NONBLOCK)
            );
        }
    }

    /// A refused connect stays pending while only `error_pending` saw its
    /// error, and is reported once.
    #[test]
    fn error_pending_keeps_a_refused_connects_error() {
        let socket = Socket::tcp().unwrap();
        match socket.connect(closed_address()) {
            Err(Errno::INPROGRESS) => {}
            result => panic!("{result:?}"),
        }
        let deadline = Instant::now() + TIMEOUT;
        while !socket.error_pending().unwrap() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(socket.error_pending().unwrap());
        assert!(!socket.connect_pending().unwrap());
        assert_eq!(socket.take_error(), Ok(Some(Errno::CONNREFUSED)));
        assert_eq!(socket.take_error(), Ok(None));
        assert!(!socket.error_pending().unwrap());
    }

    /// A send reports a failed connection's error, which macOS reports as a
    /// broken pipe, and one on a pending connect would block.
    #[test]
    fn sends_report_connect_state_as_the_contract_does() {
        let mut byte = [0_u8; 1];
        let byte = [RawBytes::from(&mut byte[..])];
        let byte = RawParts::from(&byte);

        let socket = Socket::tcp().unwrap();
        let _ = socket.connect(closed_address());
        let deadline = Instant::now() + TIMEOUT;
        let error = loop {
            match socket.send(byte, None) {
                Err(Errno::AGAIN) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                result => break result,
            }
        };
        assert_eq!(error, Err(Errno::CONNREFUSED));
        assert_eq!(socket.take_error(), Ok(None));

        let (socket, peer) = connected_tcp();
        rustix::net::sockopt::set_socket_linger(&peer, Some(Duration::ZERO)).unwrap();
        drop(peer);
        while !socket.error_pending().unwrap() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(socket.send(byte, None), Err(Errno::CONNRESET));
        assert_eq!(socket.send(byte, None), Err(Errno::PIPE));
    }

    /// A read shutdown keeps the queued data and data that arrives later
    /// readable, and then ends the stream.
    #[test]
    fn a_read_shutdown_keeps_queued_data() {
        let (socket, mut peer) = connected_tcp();
        peer.write_all(b"data").unwrap();
        let deadline = Instant::now() + TIMEOUT;
        while socket.queued_bytes().unwrap() < 4 {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        socket.shutdown(std::net::Shutdown::Read).unwrap();
        let mut data = [0_u8; 8];
        let output = [RawBytes::from(&mut data[..])];
        let output = RawParts::from(&output);
        assert_eq!(socket.receive(output, ReceiveMode::Read), Ok(4));
        assert_eq!(socket.receive(output, ReceiveMode::Read), Ok(0));
        // The write side still works.
        let mut byte = *b"x";
        let byte = [RawBytes::from(&mut byte[..])];
        assert_eq!(socket.send(RawParts::from(&byte), None), Ok(1));
        let mut received = [0_u8; 1];
        peer.read_exact(&mut received).unwrap();
    }

    /// A hang-up is reported when the connection fails, not when only the
    /// local side ends its stream or only the peer does.
    #[test]
    fn a_hang_up_needs_both_directions_closed() {
        let (poller, mut waiter) = Poller::new().unwrap();
        let (mut socket, _peer) = connected_tcp();
        poller.add(&mut socket, TOKEN, Interest::Stream).unwrap();
        wait_for(&mut waiter, SocketEvents::WRITABLE);
        socket.shutdown(std::net::Shutdown::Write).unwrap();
        let events = wait_for(&mut waiter, SocketEvents::WRITABLE);
        assert!(!events.contains(SocketEvents::HANGUP), "{events:?}");

        let (mut socket, peer) = connected_tcp();
        poller.add(&mut socket, TOKEN, Interest::Stream).unwrap();
        wait_for(&mut waiter, SocketEvents::WRITABLE);
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        let events = wait_for(&mut waiter, SocketEvents::READ_CLOSED);
        assert!(!events.contains(SocketEvents::HANGUP), "{events:?}");
        rustix::net::sockopt::set_socket_linger(&peer, Some(Duration::ZERO)).unwrap();
        drop(peer);
        let events = wait_for(&mut waiter, SocketEvents::HANGUP);
        assert!(events.contains(SocketEvents::ERROR), "{events:?}");
        assert!(socket.error_pending().unwrap());
        assert_eq!(socket.take_error(), Ok(Some(Errno::CONNRESET)));
    }

    /// A refused connect is reported as writable with a hang-up and error,
    /// and a connect stays pending until the host completes it.
    #[test]
    fn connect_completion_is_reported() {
        let (poller, mut waiter) = Poller::new().unwrap();
        let mut socket = Socket::tcp().unwrap();
        poller.add(&mut socket, TOKEN, Interest::Stream).unwrap();
        let _ = socket.connect(closed_address());
        let events = wait_for(&mut waiter, SocketEvents::HANGUP | SocketEvents::ERROR);
        assert!(events.contains(SocketEvents::WRITABLE), "{events:?}");
        assert!(!socket.connect_pending().unwrap());
        assert_eq!(socket.take_error(), Ok(Some(Errno::CONNREFUSED)));
    }

    #[test]
    fn wakes_are_reported_once() {
        let (poller, mut waiter) = Poller::new().unwrap();
        let mut buffer = EventBuffer::with_capacity(4).unwrap();
        poller.wake().unwrap();
        poller.wake().unwrap();
        waiter.wait(&mut buffer, TIMEOUT).unwrap();
        let tokens: Vec<_> = buffer.iter().map(|(token, _)| token).collect();
        assert_eq!(tokens, [WAKE_TOKEN]);
        waiter.wait(&mut buffer, Duration::from_millis(10)).unwrap();
        assert_eq!(buffer.iter().count(), 0);
    }

    /// A oneshot interest reports an event once, and again once set again
    /// while the event is still present.
    #[test]
    fn oneshot_interest_reports_once_per_setting() {
        let (poller, mut waiter) = Poller::new().unwrap();
        let mut socket = Socket::udp().unwrap();
        socket
            .bind(SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0))
            .unwrap();
        let address = socket.local_address().unwrap();
        let read = Interest::Oneshot {
            read: true,
            write: false,
        };
        poller.add(&mut socket, TOKEN, read).unwrap();
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .send_to(b"data", address)
            .unwrap();
        let events = wait_for(&mut waiter, SocketEvents::READABLE);
        assert!(!events.contains(SocketEvents::WRITABLE), "{events:?}");
        let mut buffer = EventBuffer::with_capacity(4).unwrap();
        waiter.wait(&mut buffer, Duration::from_millis(20)).unwrap();
        assert_eq!(buffer.iter().count(), 0);
        poller.modify(&mut socket, TOKEN, read).unwrap();
        wait_for(&mut waiter, SocketEvents::READABLE);
    }

    /// A receive reports a datagram's full length, even into a shorter
    /// output, and a zero-length datagram as one.
    #[test]
    fn datagram_receives_report_the_full_length() {
        let socket = Socket::udp().unwrap();
        socket
            .bind(SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0))
            .unwrap();
        let address = socket.local_address().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let source = v4(sender.local_addr().unwrap());
        assert_eq!(
            socket.receive_datagram(RawParts::EMPTY, true),
            Err(Errno::AGAIN)
        );
        assert_eq!(socket.discard_datagram(), Err(Errno::AGAIN));
        sender.send_to(&[1; 10], address).unwrap();
        sender.send_to(&[2; 20], address).unwrap();
        sender.send_to(&[], address).unwrap();
        let deadline = Instant::now() + TIMEOUT;
        while socket.head_datagram_length().unwrap() == 0 {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut data = [0_u8; 4];
        let output = [RawBytes::from(&mut data[..])];
        let output = RawParts::from(&output);
        assert_eq!(
            socket.receive_datagram(output, true),
            Ok((10, Some(source)))
        );
        assert_eq!(
            socket.receive_datagram(output, false),
            Ok((10, Some(source)))
        );
        assert_eq!(
            socket.receive_datagram(RawParts::EMPTY, false),
            Ok((20, Some(source)))
        );
        // Loopback queues datagrams as they are sent.
        assert_eq!(
            socket.receive_datagram(output, false),
            Ok((0, Some(source)))
        );
        assert_eq!(socket.receive_datagram(output, false), Err(Errno::AGAIN));
        assert_eq!(data, [1; 4]);
    }

    /// A connected UDP socket's ICMP error is reported as an event, stays
    /// pending through `error_pending`, and a peek that reports it takes it.
    #[test]
    fn udp_errors_are_reported_once() {
        let (poller, mut waiter) = Poller::new().unwrap();
        let mut socket = Socket::udp().unwrap();
        socket.connect(closed_address()).unwrap();
        poller
            .add(
                &mut socket,
                TOKEN,
                Interest::Oneshot {
                    read: true,
                    write: false,
                },
            )
            .unwrap();
        assert_eq!(socket.send(RawParts::EMPTY, None), Ok(0));
        wait_for(&mut waiter, SocketEvents::ERROR);
        assert!(socket.error_pending().unwrap());
        assert!(socket.error_pending().unwrap());
        assert_eq!(
            socket.receive_datagram(RawParts::EMPTY, true),
            Err(Errno::CONNREFUSED)
        );
        assert!(!socket.error_pending().unwrap());
        assert_eq!(
            socket.receive_datagram(RawParts::EMPTY, true),
            Err(Errno::AGAIN)
        );

        // Without `error_pending`, a peek takes the error that macOS leaves.
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(socket.send(RawParts::EMPTY, None), Ok(0));
        let deadline = Instant::now() + TIMEOUT;
        let reported = loop {
            match socket.receive_datagram(RawParts::EMPTY, true) {
                Err(Errno::AGAIN) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                result => break result,
            }
        };
        assert_eq!(reported, Err(Errno::CONNREFUSED));
        assert_eq!(socket.take_error(), Ok(None));
    }

    /// A connected UDP socket sends past its peer from its own port, keeps
    /// receiving its peer's datagrams, and receives no others.
    #[test]
    fn sends_past_the_peer_keep_the_connection() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let other = UdpSocket::bind("127.0.0.1:0").unwrap();
        other.set_read_timeout(Some(TIMEOUT)).unwrap();
        let socket = Socket::udp().unwrap();
        socket
            .bind(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0))
            .unwrap();
        socket.connect(v4(peer.local_addr().unwrap())).unwrap();
        let local = socket.local_address().unwrap();
        let mut data = *b"past";
        let input = [RawBytes::from(&mut data[..])];
        let input = RawParts::from(&input);
        for _ in 0..2 {
            assert_eq!(
                socket.send_as_unconnected(input, v4(other.local_addr().unwrap())),
                Ok(4)
            );
            let mut received = [0_u8; 8];
            let (length, source) = other.recv_from(&mut received).unwrap();
            assert_eq!(&received[..length], b"past");
            assert_eq!(v4(source).port(), local.port());
        }
        assert_eq!(
            socket.send(input, Some(v4(peer.local_addr().unwrap()))),
            Ok(4)
        );

        other.send_to(b"stray", source_of(local)).unwrap();
        peer.send_to(b"peer", source_of(local)).unwrap();
        let mut received = [0_u8; 8];
        let output = [RawBytes::from(&mut received[..])];
        let output = RawParts::from(&output);
        let deadline = Instant::now() + TIMEOUT;
        let result = loop {
            match socket.receive_datagram(output, false) {
                Err(Errno::AGAIN) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                result => break result,
            }
        };
        assert_eq!(result, Ok((4, Some(v4(peer.local_addr().unwrap())))));
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(socket.receive_datagram(output, false), Err(Errno::AGAIN));
    }

    fn source_of(local: SocketAddrV4) -> SocketAddrV4 {
        SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, local.port())
    }
}
