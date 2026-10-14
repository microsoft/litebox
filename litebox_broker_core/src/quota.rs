// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Resource counts charged both broker-wide and to one process.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{BrokerError, Result};

/// One resource charged to a broker-wide count and a per-process count until
/// it drops.
pub(crate) struct QuotaReservation {
    global: Arc<AtomicUsize>,
    process: Arc<AtomicUsize>,
}

impl QuotaReservation {
    /// Charges one resource to `global` and `process`, failing with
    /// `ResourceExhausted` if either would exceed its limit.
    pub(crate) fn new(
        global: &Arc<AtomicUsize>,
        global_limit: usize,
        process: &Arc<AtomicUsize>,
        process_limit: usize,
    ) -> Result<Self> {
        reserve(global, global_limit)?;
        if let Err(error) = reserve(process, process_limit) {
            global.fetch_sub(1, Ordering::Relaxed);
            return Err(error);
        }
        Ok(Self {
            global: Arc::clone(global),
            process: Arc::clone(process),
        })
    }
}

impl Drop for QuotaReservation {
    fn drop(&mut self) {
        self.process.fetch_sub(1, Ordering::Relaxed);
        self.global.fetch_sub(1, Ordering::Relaxed);
    }
}

fn reserve(counter: &AtomicUsize, limit: usize) -> Result<()> {
    counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
            reserved.checked_add(1).filter(|next| *next <= limit)
        })
        .map(|_| ())
        .map_err(|_| BrokerError::ResourceExhausted)
}
