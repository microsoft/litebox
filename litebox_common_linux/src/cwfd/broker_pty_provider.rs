// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted PTY operations.
//!
//! Phase E mirrors the eventfd provider pattern instead of extending the
//! eventfd trait: PTY has a distinct data plane (read/write byte streams) and a
//! multiplexed ioctl control plane, but shares lifecycle and subscription
//! operations through `BrokerSubscribable`.

use crate::cwfd::broker_subscribable::BrokerSubscribable;
use crate::cwfd::fd_token_protocol::PtyIoctlOp;

#[doc(inline)]
pub use crate::cwfd::broker_subscribable::{BrokerEventCallback, BrokerOpError};

/// Result of creating a broker-owned PTY pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrokerPtyPair {
    pub master_handle: u64,
    pub slave_handle: u64,
    pub pty_id: u32,
}

pub trait BrokerPtyProvider: BrokerSubscribable {
    fn create_pty(&self) -> Result<BrokerPtyPair, BrokerOpError>;
    fn open_pty_slave(&self, pty_id: u32) -> Result<u64, BrokerOpError>;
    fn read_pty(&self, handle: u64, max_len: u32) -> Result<alloc::vec::Vec<u8>, BrokerOpError>;
    fn write_pty(&self, handle: u64, data: &[u8]) -> Result<u32, BrokerOpError>;
    fn ioctl_pty(
        &self,
        handle: u64,
        op: PtyIoctlOp,
        payload: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, BrokerOpError>;
}
