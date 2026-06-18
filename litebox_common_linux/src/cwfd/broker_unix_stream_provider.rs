// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted AF_UNIX SOCK_STREAM (named) sockets.
//!
//! The broker owns the named listener (path registry, accept backlog) and the
//! connected stream endpoints (byte buffers) so named unix streams survive
//! delayed-fork-restore and cross worker boundaries natively — replacing the
//! legacy shim-local `UnixSocketSubsystem` that bridged cross-worker connections
//! over a broker TCP connection with sidecar metadata files.
//!
//! `SCM_RIGHTS` is framed inline in the byte stream by the shim (the same
//! `FdTransferReader` mechanism the broker socketpair uses); the broker carries
//! the framed bytes opaquely, so it is not represented in this provider.

use crate::cwfd::broker_subscribable::BrokerSubscribable;

#[doc(inline)]
pub use crate::cwfd::broker_subscribable::{BrokerEventCallback, BrokerOpError};

/// Object-safe provider used by the shim to talk to broker-hosted AF_UNIX
/// named SOCK_STREAM sockets.
pub trait BrokerUnixStreamProvider: BrokerSubscribable {
    /// Creates an unbound, unconnected broker-hosted AF_UNIX SOCK_STREAM socket.
    fn create(&self) -> Result<u64, BrokerOpError>;

    /// Binds `handle` to an encoded Unix address and returns the bound address.
    fn bind(&self, handle: u64, addr: &[u8]) -> Result<alloc::vec::Vec<u8>, BrokerOpError>;

    /// Marks a bound socket as a listener.
    fn listen(&self, handle: u64, backlog: u32) -> Result<(), BrokerOpError>;

    /// Accepts one pending connection and returns the accepted endpoint handle.
    fn accept(&self, handle: u64) -> Result<u64, BrokerOpError>;

    /// Connects to a listening Unix address.
    fn connect(&self, handle: u64, addr: &[u8]) -> Result<(), BrokerOpError>;

    /// Writes `payload` to the connected peer's stream; returns bytes written.
    fn send(&self, handle: u64, payload: &[u8]) -> Result<usize, BrokerOpError>;

    /// Reads up to `max_len` bytes from the stream (no packet boundary).
    fn recv(&self, handle: u64, max_len: u32) -> Result<alloc::vec::Vec<u8>, BrokerOpError>;

    /// Applies `shutdown(2)` semantics (`0=RD`, `1=WR`, `2=RDWR`).
    fn shutdown(&self, handle: u64, how: u8) -> Result<(), BrokerOpError>;

    /// Returns the socket's local address.
    fn getsockname(&self, handle: u64) -> Result<alloc::vec::Vec<u8>, BrokerOpError>;

    /// Returns the socket's connected peer address.
    fn getpeername(&self, handle: u64) -> Result<alloc::vec::Vec<u8>, BrokerOpError>;

    /// Returns current poll/epoll-style readiness bits.
    fn query_events(&self, handle: u64) -> Result<u32, BrokerOpError>;
}
