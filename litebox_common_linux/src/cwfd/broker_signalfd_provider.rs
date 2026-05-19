// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted signalfd operations.

use alloc::vec::Vec;

use crate::cwfd::broker_subscribable::BrokerSubscribable;

#[doc(inline)]
pub use crate::cwfd::broker_subscribable::{BrokerEventCallback, BrokerOpError};

/// Trait abstraction over broker-hosted signalfd state.
pub trait BrokerSignalfdProvider: BrokerSubscribable {
    /// Creates a broker-hosted signalfd watching the supplied 128-bit signal mask.
    fn create_signalfd(&self, sigmask_lo: u64, sigmask_hi: u64) -> Result<u64, BrokerOpError>;

    /// Reads one `signalfd_siginfo` payload, or `None` if the fd would block.
    fn read_siginfo(&self, handle: u64) -> Result<Option<Vec<u8>>, BrokerOpError>;

    /// Pushes one shim-synthesized `signalfd_siginfo` payload into the signalfd queue.
    fn push_siginfo(&self, handle: u64, payload: &[u8]) -> Result<(), BrokerOpError>;
}
