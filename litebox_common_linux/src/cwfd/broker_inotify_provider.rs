// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted inotify operations.

use alloc::vec::Vec;

use crate::cwfd::broker_subscribable::BrokerSubscribable;

#[doc(inline)]
pub use crate::cwfd::broker_subscribable::{BrokerEventCallback, BrokerOpError};

/// Trait abstraction over broker-hosted inotify state.
pub trait BrokerInotifyProvider: BrokerSubscribable {
    /// Creates a broker-hosted inotify instance.
    fn inotify_init1(&self, flags: u32) -> Result<u64, BrokerOpError>;

    /// Adds or updates an inotify watch and returns its watch descriptor.
    fn inotify_add_watch(&self, handle: u64, path: &str, mask: u32) -> Result<i32, BrokerOpError>;

    /// Removes an inotify watch descriptor.
    fn inotify_rm_watch(&self, handle: u64, wd: i32) -> Result<(), BrokerOpError>;

    /// Reads queued Linux `inotify_event` records, or `None` if the fd would block.
    fn inotify_read(&self, handle: u64, max_len: u32) -> Result<Option<Vec<u8>>, BrokerOpError>;
}
