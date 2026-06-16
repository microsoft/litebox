// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted timerfd operations.

use crate::cwfd::broker_subscribable::BrokerSubscribable;

#[doc(inline)]
pub use crate::cwfd::broker_subscribable::{BrokerEventCallback, BrokerOpError};

/// Plain no_std representation of Linux `itimerspec`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BrokerTimerfdSpec {
    pub interval_sec: u64,
    pub interval_nsec: u64,
    pub value_sec: u64,
    pub value_nsec: u64,
}

/// Trait abstraction over broker-hosted timerfd state.
pub trait BrokerTimerfdProvider: BrokerSubscribable {
    /// Creates a broker-hosted timerfd for `clockid` and raw timerfd `flags`.
    fn create_timerfd(&self, clockid: i32, flags: u32) -> Result<u64, BrokerOpError>;

    /// Arms or disarms a broker-hosted timerfd with raw `timerfd_settime` flags.
    fn settime_timerfd(
        &self,
        handle: u64,
        new_value: BrokerTimerfdSpec,
        flags: u32,
    ) -> Result<(), BrokerOpError>;

    /// Returns the remaining time and interval for a broker-hosted timerfd.
    fn gettime_timerfd(&self, handle: u64) -> Result<BrokerTimerfdSpec, BrokerOpError>;

    /// Reads and clears the accumulated expiration count.
    fn read_timerfd(&self, handle: u64) -> Result<u64, BrokerOpError>;
}
