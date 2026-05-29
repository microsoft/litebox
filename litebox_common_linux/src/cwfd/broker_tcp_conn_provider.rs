// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted connected TCP socket operations.

use crate::cwfd::broker_subscribable::BrokerSubscribable;

#[doc(inline)]
pub use crate::cwfd::broker_subscribable::{BrokerEventCallback, BrokerOpError};

/// Object-safe provider used by the shim to talk to broker-hosted connected TCP sockets.
pub trait BrokerTcpConnProvider: BrokerSubscribable {
    /// Creates a broker-hosted TCP connection placeholder for `family` (0=v4, 1=v6).
    fn create(&self, family: u8) -> Result<u64, BrokerOpError>;

    /// Initiates or completes an outbound connect for a broker-hosted TCP connection.
    fn connect(&self, handle: u64, sockaddr: &[u8], timeout_ms: u32) -> Result<(), BrokerOpError>;

    /// Returns the broker-held socket's local address.
    fn getsockname(&self, handle: u64) -> Result<[u8; 28], BrokerOpError>;

    /// Returns the broker-held socket's peer address.
    fn getpeername(&self, handle: u64) -> Result<[u8; 28], BrokerOpError>;

    /// Reads up to `max_len` bytes. A zero-length success means EOF.
    fn read_tcp_conn(
        &self,
        handle: u64,
        max_len: u64,
    ) -> Result<alloc::vec::Vec<u8>, BrokerOpError>;

    /// Writes bytes to the connection. `InvalidValue` maps to `EPIPE`.
    fn write_tcp_conn(&self, handle: u64, bytes: &[u8]) -> Result<usize, BrokerOpError>;

    /// Applies `shutdown(2)` to the broker-held stream.
    fn shutdown_tcp_conn(&self, handle: u64, read: bool, write: bool) -> Result<(), BrokerOpError>;

    /// Returns current poll/epoll-style readiness bits, including `RDHUP` when available.
    fn poll_tcp_conn_events(&self, handle: u64) -> Result<u32, BrokerOpError>;
}
