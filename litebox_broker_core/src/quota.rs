// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Resource usage counted broker-wide, per process and optionally per job.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{BrokerError, Result};

/// One resource, such as a socket or a PID namespace, counted until it drops
/// in how many resources of its kind the broker, its process and optionally
/// its job hold.
#[allow(
    clippy::struct_field_names,
    reason = "each field is one scope's usage of the same resource"
)]
pub(crate) struct QuotaReservation {
    /// How many resources of this kind the whole broker holds.
    broker_usage: Arc<AtomicUsize>,
    /// How many resources of this kind the owning process holds.
    process_usage: Arc<AtomicUsize>,
    /// How many resources of this kind the owning job holds, if counted.
    job_usage: Option<Arc<AtomicUsize>>,
}

impl QuotaReservation {
    /// Counts one resource in the usage of the broker, the process and, if
    /// given, the job, each passed as its usage and limit, failing with
    /// `ResourceExhausted` if any usage would exceed its limit.
    pub(crate) fn new(
        broker: (&Arc<AtomicUsize>, usize),
        process: (&Arc<AtomicUsize>, usize),
        job: Option<(&Arc<AtomicUsize>, usize)>,
    ) -> Result<Self> {
        let (broker_usage, broker_limit) = broker;
        let (process_usage, process_limit) = process;
        reserve(broker_usage, broker_limit)?;
        if let Err(error) = reserve(process_usage, process_limit) {
            broker_usage.fetch_sub(1, Ordering::Relaxed);
            return Err(error);
        }
        // From here on, dropping the reservation releases what it counted.
        let mut reservation = Self {
            broker_usage: Arc::clone(broker_usage),
            process_usage: Arc::clone(process_usage),
            job_usage: None,
        };
        if let Some((job_usage, job_limit)) = job {
            reserve(job_usage, job_limit)?;
            reservation.job_usage = Some(Arc::clone(job_usage));
        }
        Ok(reservation)
    }
}

impl Drop for QuotaReservation {
    fn drop(&mut self) {
        if let Some(job_usage) = &self.job_usage {
            job_usage.fetch_sub(1, Ordering::Relaxed);
        }
        self.process_usage.fetch_sub(1, Ordering::Relaxed);
        self.broker_usage.fetch_sub(1, Ordering::Relaxed);
    }
}

fn reserve(usage: &AtomicUsize, limit: usize) -> Result<()> {
    if try_increment(usage, limit) {
        Ok(())
    } else {
        Err(BrokerError::ResourceExhausted)
    }
}

/// Adds one to `counter` unless that would take it past `limit`, returning whether it did.
pub(crate) fn try_increment(counter: &AtomicUsize, limit: usize) -> bool {
    counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
            reserved.checked_add(1).filter(|next| *next <= limit)
        })
        .is_ok()
}
