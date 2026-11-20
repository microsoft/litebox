// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The host network stack under the socket provider.
//!
//! The provider uses a host only through the traits here, which state what
//! it relies on:
//! - [`Host`], a host's family of types;
//! - [`HostErrno`], the host's error codes;
//! - [`HostSocket`], a nonblocking IPv4 TCP or UDP socket;
//! - [`HostPoller`], which watches host sockets for [`Interest`]s, and
//!   [`HostWaiter`] and [`HostEventBuffer`], with which the event thread
//!   collects the [`SocketEvents`] they raise and the poller's wakes.
//!
//! Each host module implements them for its own types, and [`Native`] is the
//! host this build runs on, whose types the provider names through the
//! aliases here. The provider's logic is thus the same on every host. Where
//! a host's own sockets fall short of the contract, its module makes up the
//! difference and documents how.
//!
//! Hosts may differ where the contract is silent, for instance in the error
//! that ends a connection, in how long a refused connect takes to fail, in
//! what data a read shutdown lets arrive, in which ICMP errors a UDP socket
//! reports and whether it merges those that arrive before one is taken, or
//! in whether a UDP socket keeps its source address when it reconnects.
//! The shims above the broker present the guest's own semantics.

use core::fmt;
use core::ops::{BitOr, BitOrAssign};
use std::io::Result as IoResult;
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4};
use std::process::{Child, Command};
use std::time::Duration;

use litebox_broker_core::BrokerError;

use super::direct::RawParts;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;

/// The host this build runs on.
#[cfg(target_os = "linux")]
pub(crate) type Native = linux::Linux;
/// The host this build runs on.
#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) type Native = windows::Windows;

/// The [`Native`] host's error code.
pub(crate) type Errno = <Native as Host>::Errno;
/// The [`Native`] host's socket.
pub(crate) type Socket = <Native as Host>::Socket;
/// The [`Native`] host's poller.
pub(crate) type Poller = <Native as Host>::Poller;
/// The [`Native`] host's waiter.
pub(crate) type Waiter = <Native as Host>::Waiter;
/// The [`Native`] host's event buffer.
pub(crate) type EventBuffer = <Native as Host>::EventBuffer;

/// A host network stack: the types through which the provider uses it.
pub(crate) trait Host {
    type Errno: HostErrno;
    type Socket: HostSocket<Errno = Self::Errno>;
    type Poller: HostPoller<Errno = Self::Errno, Socket = Self::Socket, Waiter = Self::Waiter>;
    type Waiter: HostWaiter<Errno = Self::Errno, EventBuffer = Self::EventBuffer>;
    type EventBuffer: HostEventBuffer;

    /// Starts `command`, a runner, which must inherit no socket that a published port accepts.
    fn spawn(command: &mut Command) -> IoResult<Child>;
}

/// A host error code. Hosts name their errors after POSIX's; these are the
/// ones the provider tells apart.
pub(crate) trait HostErrno:
    Copy + Eq + fmt::Debug + fmt::Display + Send + Sync + 'static
{
    const INTR: Self;
    const AGAIN: Self;
    /// A TCP connect started.
    const INPROGRESS: Self;
    const ALREADY: Self;
    const ISCONN: Self;
    const NOTCONN: Self;
    /// The stream can no longer send. Only a send reports it; elsewhere a
    /// reset is reported as [`Self::CONNRESET`].
    const PIPE: Self;
    const ADDRINUSE: Self;
    const ADDRNOTAVAIL: Self;
    const CONNREFUSED: Self;
    const CONNRESET: Self;
    const CONNABORTED: Self;
    const NETUNREACH: Self;
    const HOSTUNREACH: Self;
    const TIMEDOUT: Self;
    const INVAL: Self;
    /// The host withholds what the call asks for from the broker's privileges.
    const ACCES: Self;

    /// Maps an error that reports the host out of a resource to the broker's.
    fn broker_resource_error(self) -> Option<BrokerError>;
}

/// A nonblocking IPv4 TCP or UDP host socket.
///
/// # TCP errors
///
/// A receive or send on a pending connect fails with [`HostErrno::AGAIN`],
/// as one that would block does, and one on a connect that failed, with its
/// error not yet taken, reports that error. Neither reports
/// [`HostErrno::PIPE`] or [`HostErrno::CONNRESET`]. Those report, whether to
/// a call or to [`Self::take_error`], the reset of a connection that the
/// peer took part in, which the provider counts as established even if, as
/// in a simultaneous open, it was reset before it was.
///
/// A failed connection reports its error to a call or to
/// [`Self::take_error`], possibly to more than one. The provider records the
/// first report, ends receives after it, and aborts a pending connect that
/// the guest shuts down.
///
/// # UDP errors
///
/// A UDP socket reports ICMP errors only while connected, and only those its
/// datagrams to its peer cause, a port unreachable as
/// [`HostErrno::CONNREFUSED`]. It reports each at most once: a receive that
/// reports one, even a peek, takes it, and so may a send. The rule is the
/// broker's own, whether or not a host's sockets follow it natively. An
/// error that the poller reports on a UDP socket as [`SocketEvents::ERROR`]
/// stays until a call or [`Self::take_error`] takes it, and
/// [`Self::error_pending`] reports it until then.
pub(crate) trait HostSocket: Sized + Send {
    type Errno: HostErrno;

    /// Opens a TCP socket.
    fn tcp() -> Result<Self, Self::Errno>;

    /// Opens a UDP socket.
    fn udp() -> Result<Self, Self::Errno>;

    /// Opens a TCP socket listening at `address` with room for [`LISTEN_BACKLOG`] connections,
    /// which keeps every other socket off the port.
    fn tcp_listening(address: SocketAddrV4) -> Result<Self, Self::Errno>;

    /// Listens with room for `backlog` connections; a listener keeps those pending. A TCP socket
    /// that the poller watches stays watched under its token, and reports a connection to accept
    /// as [`SocketEvents::READABLE`].
    fn listen(&self, backlog: u32) -> Result<(), Self::Errno>;

    /// Accepts a listener's connection and its peer, or fails with [`HostErrno::AGAIN`].
    fn accept(&self) -> Result<(Self, SocketAddrV4), Self::Errno>;

    fn bind(&self, address: SocketAddrV4) -> Result<(), Self::Errno>;

    /// Binds the socket so that no other shares its port, whichever address either binds.
    fn bind_exclusively(&self, address: SocketAddrV4) -> Result<(), Self::Errno>;

    /// Binds a TCP socket at `address` for a mirrored guest socket. With `reuse_address`, it
    /// shares the address as far as the host's `SO_REUSEADDR` lets sockets that do not listen
    /// share one; a host on which that would let other sockets take the port binds exclusively
    /// whatever `reuse_address` says.
    ///
    /// Fails with [`HostErrno::ADDRINUSE`] if another socket holds the address, and with
    /// [`HostErrno::ACCES`] only if the host withholds the address from the broker's
    /// privileges, as Linux does a privileged port.
    fn bind_as_guest(&self, address: SocketAddrV4, reuse_address: bool) -> Result<(), Self::Errno>;

    /// Gets a preferred source address without sending traffic. This is a hint, not an
    /// ownership check: policy routing can allow TCP while denying the UDP route used here.
    fn preferred_source_for(destination: SocketAddrV4) -> Result<Option<Ipv4Addr>, Self::Errno> {
        let hint = || {
            let socket = Self::udp()?;
            loop {
                match socket.connect(destination) {
                    Err(error) if error == <Self::Errno as HostErrno>::INTR => continue,
                    result => result?,
                }
                return socket.local_address();
            }
        };
        match hint() {
            Ok(source) => Ok(Some(*source.ip())),
            Err(error) if error.broker_resource_error().is_some() => Err(error),
            Err(error) => {
                // This probe chooses only a source for an already-authorized in-memory stream.
                litebox_util_log::debug!("No UDP source hint for {destination}: {error}");
                Ok(None)
            }
        }
    }

    /// Whether this namespace owns the unicast address, independent of flow routing.
    fn owns_address(address: Ipv4Addr) -> Result<bool, Self::Errno>;

    /// Connects to `address`, or starts connecting a TCP socket, which fails
    /// with [`HostErrno::INPROGRESS`].
    fn connect(&self, address: SocketAddrV4) -> Result<(), Self::Errno>;

    /// Returns the socket's local address, which for an unbound socket is
    /// the wildcard address.
    fn local_address(&self) -> Result<SocketAddrV4, Self::Errno>;

    /// Shuts the socket down in the directions `how` names.
    ///
    /// Fails only on a socket that is not connected or whose connection
    /// failed, and then leaves the failure's error to be reported. A read
    /// shutdown discards no queued data: receives return it before they end
    /// the stream.
    fn shutdown(&self, how: Shutdown) -> Result<(), Self::Errno>;

    /// Disconnects a TCP socket in place, whatever its state, as Linux's `connect` to
    /// `AF_UNSPEC` does: a listener stops listening and resets the connections it did not
    /// accept, and a connect in progress stops, without a reset. The socket stays bound at a
    /// port it was bound at explicitly, rather than one the host chose, but not at its address
    /// if that was the wildcard and a connect chose another.
    ///
    /// Fails on a host that cannot disconnect a socket in place.
    fn disconnect(&self) -> Result<(), Self::Errno>;

    /// Sends `data` with one system call, to `destination` if set, and
    /// returns how many bytes it sent.
    fn send(
        &self,
        data: RawParts<'_>,
        destination: Option<SocketAddrV4>,
    ) -> Result<usize, Self::Errno>;

    /// Sends the datagram `data` to `destination` with one system call from
    /// the source address an unconnected socket would use, and returns how
    /// many bytes it sent.
    fn send_as_unconnected(
        &self,
        data: RawParts<'_>,
        destination: SocketAddrV4,
    ) -> Result<usize, Self::Errno>;

    /// Sends the datagram `data` to `destination` from the local address `source`, or with the
    /// unspecified one from the address the route selects.
    fn send_from(
        &self,
        data: RawParts<'_>,
        destination: SocketAddrV4,
        source: Ipv4Addr,
    ) -> Result<usize, Self::Errno>;

    /// Makes [`Self::peek_destination`] report datagrams that arrive from now on.
    fn report_destinations(&self) -> Result<(), Self::Errno>;

    /// The local address to reply to the head datagram from, usually the one it was sent to; the
    /// unspecified one, for the route to choose, if unknown.
    fn peek_destination(&self) -> Ipv4Addr;

    /// Receives stream data into `output` with one system call.
    ///
    /// A reset that discarded data not yet received is reported as an
    /// error, never as the end of the stream.
    fn receive(&self, output: RawParts<'_>, mode: ReceiveMode) -> Result<usize, Self::Errno>;

    /// Receives the datagram at the head of the socket into `output`,
    /// leaving it queued with `peek`.
    ///
    /// Returns the datagram's full length, even if `output` is shorter, and
    /// its source, if IPv4. May fail with [`HostErrno::AGAIN`] while
    /// datagrams are still queued, which the poller then reports; see
    /// [`Interest::Oneshot`].
    fn receive_datagram(
        &self,
        output: RawParts<'_>,
        peek: bool,
    ) -> Result<(usize, Option<SocketAddrV4>), Self::Errno>;

    /// Discards the datagram or error at the head of a UDP socket.
    ///
    /// Fails with the error it discards, or with [`HostErrno::AGAIN`] if
    /// neither is queued.
    fn discard_datagram(&self) -> Result<(), Self::Errno>;

    /// Returns how many bytes a stream receive could take now.
    fn queued_bytes(&self) -> Result<usize, Self::Errno>;

    /// Reports whether a stream receive would return data or the end of the
    /// stream now, as a poll for ordinary data does; on a listener, whether a
    /// connection is waiting.
    ///
    /// Unlike [`Self::queued_bytes`], which Linux stops at the urgent mark,
    /// this counts the ordinary data behind urgent data, which a receive skips
    /// the urgent byte to return.
    fn stream_readable(&self) -> Result<bool, Self::Errno>;

    /// Returns the length of the datagram at the head of a UDP socket, or 0
    /// if none is queued.
    #[cfg(test)]
    fn head_datagram_length(&self) -> Result<usize, Self::Errno>;

    /// Takes the socket's pending error, if any. A TCP socket's error is
    /// taken only while [`Self::error_pending`] reports it, so not one the
    /// host records without raising it.
    fn take_error(&self) -> Result<Option<Self::Errno>, Self::Errno>;

    /// Reports whether the socket has a pending error, without taking it. A
    /// failed TCP connection's error is pending while a call or
    /// [`Self::take_error`] would report it.
    fn error_pending(&self) -> Result<bool, Self::Errno>;

    /// Reports whether a TCP connect is still in progress.
    fn connect_pending(&self) -> Result<bool, Self::Errno>;

    /// Sets whether a TCP socket sends small segments without delay.
    ///
    /// A new TCP socket takes this option, but a host may refuse it while a
    /// connect is pending or after a connection failed; the provider gives
    /// it to the socket again once it connects.
    fn set_no_delay(&self, value: bool) -> Result<(), Self::Errno>;

    #[cfg(test)]
    fn no_delay(&self) -> Result<bool, Self::Errno>;

    /// Sets whether a TCP socket probes an idle connection.
    ///
    /// A new TCP socket takes this option, but a host may refuse it while a
    /// connect is pending or after a connection failed; the provider gives
    /// it to the socket again once it connects.
    fn set_keep_alive(&self, value: bool) -> Result<(), Self::Errno>;

    #[cfg(test)]
    fn keep_alive(&self) -> Result<bool, Self::Errno>;

    /// Makes closing the socket reset its connection instead of finishing
    /// it.
    fn set_linger_zero(&self) -> Result<(), Self::Errno>;

    /// Changes whether a bound TCP socket shares its address, as
    /// [`Self::bind_as_guest`] binds it, for the binds and listens that follow. A host that
    /// binds a guest's socket exclusively whatever it asks ignores the change.
    fn set_reuse_address(&self, value: bool) -> Result<(), Self::Errno>;

    /// Reports whether a TCP socket shares its address, as [`Self::set_reuse_address`] last
    /// set it, or as a connection a listener accepted took it from the listener when the host
    /// connected it.
    fn reuse_address(&self) -> Result<bool, Self::Errno>;

    fn set_receive_buffer_size(&self, size: usize) -> Result<(), Self::Errno>;

    fn receive_buffer_size(&self) -> Result<usize, Self::Errno>;
}

/// Watches host sockets for [`Interest`]s; its [`HostWaiter`] collects the
/// [`SocketEvents`] they raise.
///
/// A TCP connect in progress is reported [`SocketEvents::WRITABLE`] once it
/// completes, and a TCP socket's only pending error, which the poller
/// reports as [`SocketEvents::ERROR`], is the failure of its connection.
pub(crate) trait HostPoller: Sized + Send + Sync {
    type Errno;
    type Socket;
    type Waiter;

    /// Whether a stream socket watched for [`Interest::Stream`] reports each
    /// arrival of data, even while earlier data is queued. Otherwise it
    /// reports only the first, and the provider polls for the data a peek
    /// waits for.
    const REPORTS_EVERY_ARRIVAL: bool;

    /// Whether a UDP socket watched for neither event reports its errors.
    /// Otherwise the provider watches a UDP socket shut for reading for
    /// reads, discarding what arrives, to see its errors.
    const REPORTS_UNWATCHED_ERRORS: bool;

    /// Creates a poller and the waiter that collects its events.
    fn new() -> IoResult<(Self, Self::Waiter)>;

    /// Watches `socket` for `interest`, reporting its events under `token`.
    fn add(
        &self,
        socket: &mut Self::Socket,
        token: u64,
        interest: Interest,
    ) -> Result<(), Self::Errno>;

    /// Replaces the interest a watched `socket` is watched for.
    fn modify(
        &self,
        socket: &mut Self::Socket,
        token: u64,
        interest: Interest,
    ) -> Result<(), Self::Errno>;

    /// Stops watching `socket` before it closes.
    fn delete(&self, socket: &mut Self::Socket);

    /// Wakes the waiter, which reports an event under [`WAKE_TOKEN`].
    fn wake(&self) -> IoResult<()>;
}

/// Collects a [`HostPoller`]'s events on the event thread.
pub(crate) trait HostWaiter: Send {
    type Errno;
    type EventBuffer;

    /// Waits at most `timeout` for events, and replaces `events` with them.
    ///
    /// A wait consumes the wakes it reports, so each wake after it is
    /// reported by a later wait.
    fn wait(
        &mut self,
        events: &mut Self::EventBuffer,
        timeout: Duration,
    ) -> Result<(), Self::Errno>;
}

/// Room for the events one [`HostWaiter::wait`] reports.
///
/// It need not be `Send`, so the event thread allocates its own.
pub(crate) trait HostEventBuffer: Sized {
    /// Allocates room for `capacity` events, or returns `None` if the
    /// allocation fails.
    fn with_capacity(capacity: usize) -> Option<Self>;

    /// Returns the token and events of each event the last wait reported.
    fn iter(&self) -> impl Iterator<Item = (u64, SocketEvents)> + '_;
}

/// The backlog a host listener starts with, which Winsock keeps whatever the guest's listen asks.
pub(crate) const LISTEN_BACKLOG: u32 = 128;

/// Poller token reserved for the poller's own wakes.
pub(crate) const WAKE_TOKEN: u64 = 0;

/// The events a host socket raised.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SocketEvents(u8);

impl SocketEvents {
    /// A receive would not block.
    pub(crate) const READABLE: Self = Self(1 << 0);
    /// A send would not block.
    pub(crate) const WRITABLE: Self = Self(1 << 1);
    /// The peer finished sending.
    pub(crate) const READ_CLOSED: Self = Self(1 << 2);
    /// The connection is closed in both directions.
    pub(crate) const HANGUP: Self = Self(1 << 3);
    /// The socket has a pending error.
    pub(crate) const ERROR: Self = Self(1 << 4);

    pub(crate) const fn empty() -> Self {
        Self(0)
    }

    /// Whether every event in `other` is set.
    pub(crate) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether any event in `other` is set.
    pub(crate) const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub(crate) fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }
}

impl BitOr for SocketEvents {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl BitOrAssign for SocketEvents {
    fn bitor_assign(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// The events a poller reports for a host socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Interest {
    /// Every change in a stream's readiness, once per change.
    Stream,
    /// Each requested event once present. After reporting one, the socket
    /// need report nothing more until its interest is set again, though it
    /// may still report the other. Setting the interest reports an event
    /// already present as well as one that follows. Errors may be reported
    /// even if neither event is requested.
    Oneshot { read: bool, write: bool },
}

/// How a stream receive treats the data it receives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiveMode {
    /// Dequeue the data.
    Read,
    /// Leave the data queued.
    Peek,
    /// Leave the data queued, asking the host for the whole output.
    PeekAll,
}

impl ReceiveMode {
    /// Whether the data stays queued.
    pub(crate) const fn is_peek(self) -> bool {
        matches!(self, Self::Peek | Self::PeekAll)
    }
}
