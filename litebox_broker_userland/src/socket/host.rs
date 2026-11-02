// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The host network stack under the socket provider.
//!
//! A host module provides:
//! - `HostSocket`, a nonblocking IPv4 TCP or UDP socket, with the
//!   operations the provider performs on it;
//! - `Poller`, which watches host sockets for [`Interest`]s, and `Waiter`
//!   and `Events`, with which the event thread collects the [`HostEvents`]
//!   they raise and the wakes that `Poller::wake` sends under
//!   [`WAKE_TOKEN`];
//! - `Errno`, the host's error codes, with the constants the provider
//!   matches on, and the functions that map them to broker errors;
//! - `REPORTS_EVERY_ARRIVAL`, whether a stream socket watched for
//!   [`Interest::Stream`] reports each arrival of data, even while earlier
//!   data is queued. Otherwise it reports only the first, and the provider
//!   polls for the data a peek waits for;
//! - `REPORTS_UNWATCHED_ERRORS`, whether a UDP socket watched for neither
//!   event reports its errors. Otherwise the provider watches a UDP socket
//!   shut for reading for reads, discarding what arrives, to see its errors.
//!
//! The types in this module are host-neutral, so the provider's logic is
//! the same on every host.
//!
//! # Contract
//!
//! The provider relies on every host's sockets to behave as follows. Where a
//! host's own sockets fall short, its module makes up the difference and
//! documents how.
//! - A receive or send on a pending TCP connect fails with `Errno::AGAIN`,
//!   as one that would block does, and one on a connect that failed, with
//!   its error not yet taken, reports that error. Neither reports
//!   `Errno::PIPE` or `Errno::CONNRESET`, which only a connection that was
//!   established reports, whether to a call or to `take_error`.
//! - A failed TCP connection reports its error to a call or to
//!   `take_error`, possibly to more than one. `error_pending` reports it
//!   while any of them would, and `connect_pending` reports whether a
//!   connect is still in progress. The provider records the first report,
//!   ends receives after it, and aborts a pending connect that the guest
//!   shuts down. A shutdown fails only on a socket that is not connected or
//!   whose connection failed, and leaves the failure's error for those
//!   reports.
//! - Only a send reports `Errno::PIPE`, meaning that the stream can no
//!   longer send; elsewhere a reset is reported as `Errno::CONNRESET`.
//! - A reset that discarded data not yet received is reported as an error,
//!   never as the end of the stream.
//! - A read shutdown discards no queued data: receives return it before
//!   they end the stream.
//! - A new TCP socket takes the no-delay and keep-alive options. A host may
//!   refuse them while a connect is pending or after a connection failed;
//!   the provider gives them to the socket again once it connects.
//! - An unbound socket's local address is the wildcard address.
//! - A datagram receive returns the datagram's full length, even if its
//!   output is shorter. It may fail with `Errno::AGAIN` while datagrams are
//!   still queued, which the poller then reports; see [`Interest::Oneshot`].
//! - A UDP socket reports ICMP errors only while connected, and only those
//!   its datagrams to its peer cause. It reports each at most once: a
//!   receive that reports one, even a peek, takes it, and so may a send.
//!   The rule is the broker's own, whether or not a host's sockets follow
//!   it natively. An error that the poller reports on a UDP socket as
//!   [`HostEvents::ERROR`] stays until a call or `take_error` takes it, and
//!   `error_pending` reports it until then.
//!
//! Hosts may differ where the contract is silent, for instance in the error
//! that ends a connection, in how long a refused connect takes to fail, in
//! what data a read shutdown lets arrive, in which ICMP errors a UDP socket
//! reports and whether it merges those that arrive before one is taken, or
//! in whether a UDP socket keeps its source address when it reconnects.
//! The shims above the broker present the guest's own semantics.

use core::ops::{BitOr, BitOrAssign};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::*;
#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;
#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) use windows::*;

/// Poller token reserved for the poller's own wakes.
pub(crate) const WAKE_TOKEN: u64 = 0;

/// The events a host socket raised.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HostEvents(u8);

impl HostEvents {
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

impl BitOr for HostEvents {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl BitOrAssign for HostEvents {
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
