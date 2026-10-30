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
    /// The first of the requested events, after which the socket reports
    /// nothing until its interest is set again. Errors may be reported even
    /// if neither event is requested.
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
