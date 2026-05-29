// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted raw IPv4 socket operations.

use crate::cwfd::broker_subscribable::BrokerSubscribable;

#[doc(inline)]
pub use crate::cwfd::broker_subscribable::{BrokerEventCallback, BrokerOpError};

/// Object-safe provider used by the shim to talk to broker-hosted raw sockets.
pub trait BrokerInetRawProvider: BrokerSubscribable {
    /// Creates a broker-hosted raw socket placeholder for `family` and `protocol`.
    fn create(&self, family: u8, protocol: u8) -> Result<u64, BrokerOpError>;

    /// Sends one raw packet to `sockaddr`, returning the number of bytes written.
    fn send_to(&self, handle: u64, sockaddr: &[u8], bytes: &[u8]) -> Result<usize, BrokerOpError>;

    /// Receives one raw packet, returning `(peer_sockaddr, bytes)`.
    fn recv_from(&self, handle: u64, max_len: u64) -> Result<([u8; 28], alloc::vec::Vec<u8>), BrokerOpError>;

    /// Returns current poll/epoll-style readiness bits.
    fn poll_raw_events(&self, handle: u64) -> Result<u32, BrokerOpError>;
}
