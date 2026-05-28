// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted TCP listener operations.

use crate::cwfd::broker_subscribable::BrokerSubscribable;

#[doc(inline)]
pub use crate::cwfd::broker_subscribable::{BrokerEventCallback, BrokerOpError};

/// Trait abstraction over broker-hosted inet listener state.
pub trait BrokerInetListenerProvider: BrokerSubscribable {
    /// Creates a broker-hosted TCP listener placeholder for `family` (0=v4, 1=v6).
    fn create(&self, family: u8) -> Result<u64, BrokerOpError>;

    /// Binds a broker-hosted listener and returns the actual bound address.
    fn bind(&self, handle: u64, sockaddr: &[u8]) -> Result<[u8; 28], BrokerOpError>;

    /// Marks a broker-hosted listener as listening with the requested backlog.
    fn listen(&self, handle: u64, backlog: u32) -> Result<(), BrokerOpError>;

    /// Accepts one queued connection, returning `(conn_handle, peer_addr)`.
    fn accept(&self, handle: u64) -> Result<(u64, [u8; 28]), BrokerOpError>;
}
