// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted pipe operations.
//!
//! Each pipe end is its own broker state-registry entry; the shim
//! refers to a specific end by handle, so direction is not on the
//! wire for `read_pipe`, `write_pipe`, subscribe/unsubscribe, dup, or
//! release. The shim still tracks direction internally for
//! read-vs-write capability gating (a fd installed for the read end
//! returns EBADF on `write` calls).

use crate::cwfd::broker_subscribable::BrokerSubscribable;

#[doc(inline)]
pub use crate::cwfd::broker_subscribable::{BrokerEventCallback, BrokerOpError};

/// Direction of a broker-hosted pipe endpoint. Used shim-side for
/// read-vs-write capability gating and for serializing/parsing
/// `--broker-fd-bridge` specs across `exec_on_remote_host` (so the
/// receiver knows which slot's BrokerPipeFd is for reading vs
/// writing). The broker itself doesn't see this — each end has its
/// own broker handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerPipeEnd {
    Read,
    Write,
}

impl BrokerPipeEnd {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::Write => 1,
        }
    }
}

/// Object-safe provider used by the shim to talk to broker-hosted pipes.
pub trait BrokerPipeProvider: BrokerSubscribable {
    /// Creates a new pipe in the broker and returns both ends'
    /// handles as `(read_handle, write_handle)`. Each handle is its
    /// own state-registry entry with refcount = 1.
    fn create_pipe(
        &self,
        capacity: u64,
        atomic_write_size: u64,
    ) -> Result<(u64, u64), BrokerOpError>;

    /// Reads up to `max_len` bytes from the pipe addressed by the
    /// read end's `handle`. `handle` MUST be a read-end handle;
    /// passing a write-end handle returns `InvalidValue` from the
    /// broker.
    fn read_pipe(&self, handle: u64, max_len: u64) -> Result<alloc::vec::Vec<u8>, BrokerOpError>;

    /// Writes `bytes` to the pipe addressed by the write end's
    /// `handle`. Returns the number of bytes accepted (may be less
    /// than `bytes.len()` for non-atomic writes). `handle` MUST be a
    /// write-end handle.
    fn write_pipe(&self, handle: u64, bytes: &[u8]) -> Result<usize, BrokerOpError>;
}
