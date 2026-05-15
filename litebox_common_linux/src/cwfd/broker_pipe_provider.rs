// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted pipe operations.

use crate::cwfd::broker_subscribable::BrokerSubscribable;

#[doc(inline)]
pub use crate::cwfd::broker_subscribable::{BrokerEventCallback, BrokerOpError};

/// Direction of a broker-hosted pipe endpoint.
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
    fn create_pipe(&self, capacity: u64, atomic_write_size: u64) -> Result<u64, BrokerOpError>;
    fn read_pipe(&self, handle: u64, max_len: u64) -> Result<alloc::vec::Vec<u8>, BrokerOpError>;
    fn write_pipe(&self, handle: u64, bytes: &[u8]) -> Result<usize, BrokerOpError>;
    fn incref_pipe_end(&self, handle: u64, end: BrokerPipeEnd) -> Result<(), BrokerOpError>;
    fn close_pipe_end(&self, handle: u64, end: BrokerPipeEnd);

    /// Direction-aware unsubscribe. Required for pipes because their
    /// subscription ids span both `read_subject` and `write_subject`,
    /// and the kind-agnostic [`BrokerSubscribable::unsubscribe`] would
    /// silently strip the wrong subject (the broker checks
    /// `read_subject` first).
    fn unsubscribe_pipe_end(&self, handle: u64, end: BrokerPipeEnd, subscription_id: u64);

    /// Subscribe to broker pipe events for a specific end of the pipe.
    ///
    /// The generic `BrokerSubscribable::subscribe` impl cannot carry
    /// per-end direction. Callers that need correct read-vs-write event
    /// routing MUST use this method instead.
    ///
    /// Returns the broker-assigned subscription id (same as
    /// `BrokerSubscribable::subscribe`).
    fn subscribe_pipe_end(
        &self,
        handle: u64,
        end: BrokerPipeEnd,
        events_mask: u32,
        callback: alloc::sync::Arc<dyn BrokerEventCallback>,
    ) -> Result<u64, BrokerOpError>;
}
