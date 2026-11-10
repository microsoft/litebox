// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Resource counts charged both broker-wide and to one process.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{BrokerError, Result};

/// One resource charged to a broker-wide count, a per-process count and
/// optionally a per-job count until it drops.
pub(crate) struct QuotaReservation {
    global: Arc<AtomicUsize>,
    process: Arc<AtomicUsize>,
    job: Option<Arc<AtomicUsize>>,
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
            job: None,
        })
    }

    /// Charges one resource as [`Self::new`] does and also to `job`, failing
    /// with `ResourceExhausted` if any count would exceed its limit.
    pub(crate) fn with_job(
        global: (&Arc<AtomicUsize>, usize),
        job: (&Arc<AtomicUsize>, usize),
        process: (&Arc<AtomicUsize>, usize),
    ) -> Result<Self> {
        let mut reservation = Self::new(global.0, global.1, process.0, process.1)?;
        reserve(job.0, job.1)?;
        reservation.job = Some(Arc::clone(job.0));
        Ok(reservation)
    }
}

impl Drop for QuotaReservation {
    fn drop(&mut self) {
        if let Some(job) = &self.job {
            job.fetch_sub(1, Ordering::Relaxed);
        }
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
