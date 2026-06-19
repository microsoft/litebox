// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted AF_UNIX SOCK_SEQPACKET sockets.
//!
//! The broker owns the seqpacket endpoint, its bind/connect state, and its
//! receive queue so the socket survives delayed-fork-restore across workers.
//! `SCM_RIGHTS` fd tokens are represented per packet; `SCM_CREDENTIALS` is
//! still deliberately out of scope because it has authentication implications.

use crate::cwfd::{broker_subscribable::BrokerSubscribable, fd_transfer_frame::PassedToken};

#[doc(inline)]
pub use crate::cwfd::broker_subscribable::{BrokerEventCallback, BrokerOpError};

/// Object-safe provider used by the shim to talk to broker-hosted AF_UNIX
/// seqpacket sockets.
pub trait BrokerSocketSeqPacketProvider: BrokerSubscribable {
    /// Creates an unbound broker-hosted AF_UNIX SOCK_SEQPACKET socket.
    fn create(&self) -> Result<u64, BrokerOpError>;

    /// Binds `handle` to an encoded Unix address and returns the bound address.
    fn bind(&self, handle: u64, addr: &[u8]) -> Result<alloc::vec::Vec<u8>, BrokerOpError>;

    /// Creates a connected broker-hosted AF_UNIX SOCK_SEQPACKET socketpair.
    fn create_socketpair(&self) -> Result<(u64, u64), BrokerOpError>;

    /// Marks a bound socket as a listener.
    fn listen(&self, handle: u64, backlog: u32) -> Result<(), BrokerOpError>;

    /// Accepts one pending connection and returns the accepted endpoint handle.
    fn accept(&self, handle: u64) -> Result<u64, BrokerOpError>;

    /// Connects to a listening Unix address.
    fn connect(&self, handle: u64, addr: &[u8]) -> Result<(), BrokerOpError>;

    /// Sends one packet to the connected peer. `tokens` carries SCM_RIGHTS
    /// broker handles atomically with `payload`.
    fn send(
        &self,
        handle: u64,
        payload: &[u8],
        tokens: &[PassedToken],
    ) -> Result<usize, BrokerOpError>;

    /// Receives one packet and returns `(payload, flags, tokens)`.
    fn recv(
        &self,
        handle: u64,
        max_len: u32,
    ) -> Result<(alloc::vec::Vec<u8>, u32, alloc::vec::Vec<PassedToken>), BrokerOpError>;

    /// Applies `shutdown(2)` semantics (`0=RD`, `1=WR`, `2=RDWR`).
    fn shutdown(&self, handle: u64, how: u8) -> Result<(), BrokerOpError>;

    /// Returns the socket's local address.
    fn getsockname(&self, handle: u64) -> Result<alloc::vec::Vec<u8>, BrokerOpError>;

    /// Returns the socket's connected peer address.
    fn getpeername(&self, handle: u64) -> Result<alloc::vec::Vec<u8>, BrokerOpError>;

    /// Returns current poll/epoll-style readiness bits.
    fn query_events(&self, handle: u64) -> Result<u32, BrokerOpError>;
}
