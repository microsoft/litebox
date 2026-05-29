// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted UDP datagram socket operations.

use crate::cwfd::broker_subscribable::BrokerSubscribable;

#[doc(inline)]
pub use crate::cwfd::broker_subscribable::{BrokerEventCallback, BrokerOpError};

/// Object-safe provider used by the shim to talk to broker-hosted UDP sockets.
pub trait BrokerInetDgramProvider: BrokerSubscribable {
    /// Creates a broker-hosted UDP socket placeholder for `family` (0=v4, 1=v6).
    fn create(&self, family: u8) -> Result<u64, BrokerOpError>;

    /// Binds a broker-hosted UDP socket and returns the actual bound address.
    fn bind(&self, handle: u64, sockaddr: &[u8]) -> Result<[u8; 28], BrokerOpError>;

    /// Connects UDP default send target and receive filter.
    fn connect(&self, handle: u64, sockaddr: &[u8]) -> Result<(), BrokerOpError>;

    /// Sends a datagram. An all-zero sockaddr selects the connected peer.
    fn sendto(&self, handle: u64, sockaddr: &[u8], payload: &[u8]) -> Result<usize, BrokerOpError>;

    /// Receives one datagram and returns `(peer_sockaddr, payload, flags)`.
    fn recvfrom(
        &self,
        handle: u64,
        max_len: u32,
    ) -> Result<([u8; 28], alloc::vec::Vec<u8>, u32), BrokerOpError>;

    /// Applies UDP shutdown semantics to the broker-held socket.
    fn shutdown(&self, handle: u64, how: u8) -> Result<(), BrokerOpError>;

    /// Returns the broker-held socket's local address.
    fn getsockname(&self, handle: u64) -> Result<[u8; 28], BrokerOpError>;

    /// Returns the broker-held socket's connected peer address.
    fn getpeername(&self, handle: u64) -> Result<[u8; 28], BrokerOpError>;

    /// Passes a socket option write through to the broker-held host fd.
    fn setsockopt(
        &self,
        handle: u64,
        level: i32,
        name: i32,
        value: &[u8],
    ) -> Result<(), BrokerOpError>;

    /// Reads a socket option from the broker-held host fd.
    fn getsockopt(
        &self,
        handle: u64,
        level: i32,
        name: i32,
        max_len: u32,
    ) -> Result<alloc::vec::Vec<u8>, BrokerOpError>;

    /// Returns current poll/epoll-style readiness bits.
    fn query_events(&self, handle: u64) -> Result<u32, BrokerOpError>;
}
