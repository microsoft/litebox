// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted AF_UNIX SOCK_STREAM socketpair
//! operations.
//!
//! Each endpoint is its own broker state-registry entry; the shim
//! refers to a specific endpoint by handle, so endpoint identity is
//! not on the wire for `read_socketpair`, `write_socketpair`, subscribe,
//! dup, or release. The shim still tracks endpoint identity internally
//! for `fork_snapshot_handle()` so the receiving worker can
//! reconstruct the correct capability after fork+exec.

use crate::cwfd::broker_subscribable::BrokerSubscribable;

#[doc(inline)]
pub use crate::cwfd::broker_subscribable::{BrokerEventCallback, BrokerOpError};

/// Endpoint identity for a broker-hosted socketpair end. Used
/// shim-side for serializing/parsing fork-snapshot metadata so the
/// receiver knows which broker handle corresponds to which side. The
/// broker itself doesn't see this — each endpoint has its own broker
/// state-registry handle and operations are routed by handle alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerSocketPairEndpoint {
    A,
    B,
}

impl BrokerSocketPairEndpoint {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }
}

/// Object-safe provider used by the shim to talk to broker-hosted
/// AF_UNIX SOCK_STREAM socketpairs. Phase F.
pub trait BrokerSocketPairProvider: BrokerSubscribable {
    /// Creates a new socketpair in the broker and returns both
    /// endpoints' handles as `(endpoint_a_handle, endpoint_b_handle)`.
    /// Each handle is its own state-registry entry with refcount = 1.
    fn create_socketpair(
        &self,
        capacity: u64,
        atomic_write_size: u64,
    ) -> Result<(u64, u64), BrokerOpError>;

    /// Reads up to `max_len` bytes from the socketpair endpoint
    /// addressed by `handle`. Returns the bytes that have arrived
    /// from the peer. Zero-length result = EOF (peer closed and no
    /// more data buffered).
    fn read_socketpair(
        &self,
        handle: u64,
        max_len: u64,
    ) -> Result<alloc::vec::Vec<u8>, BrokerOpError>;

    /// Writes `bytes` to the socketpair endpoint addressed by `handle`.
    /// Returns the number of bytes accepted (may be partial for
    /// non-atomic writes). `BrokerOpError::InvalidValue` indicates
    /// peer-closed (EPIPE).
    fn write_socketpair(&self, handle: u64, bytes: &[u8]) -> Result<usize, BrokerOpError>;

    /// Applies `shutdown(SHUT_WR)` to the socketpair endpoint addressed
    /// by `handle`, making the peer observe EOF after buffered data is
    /// drained while preserving the peer's ability to write back.
    fn shutdown_socketpair_write(&self, handle: u64) -> Result<(), BrokerOpError>;
}
