// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted process-group signal delivery.

use alloc::sync::Arc;

use crate::cwfd::broker_subscribable::BrokerOpError;

pub trait BrokerPgrpSignalCallback: Send + Sync {
    fn on_signal(&self, pgid: i32, signum: i32, siginfo: &[u8]);
}

pub trait BrokerPgrpSignalProvider: Send + Sync {
    fn subscribe_pgrp_signal(
        &self,
        pgid: u32,
        signal_mask: u32,
        callback: Arc<dyn BrokerPgrpSignalCallback>,
    ) -> Result<u64, BrokerOpError>;

    fn unsubscribe_pgrp_signal(&self, pgid: u32, subscription_id: u64);

    fn deliver_pgrp_signal(&self, pgid: u32, signum: u32) -> Result<(), BrokerOpError>;
}
