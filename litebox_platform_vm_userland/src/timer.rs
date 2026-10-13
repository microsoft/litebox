// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform timers (`alarm`, `setitimer`), on the process's one kernel timer
//! ([`kcall::set_timer`]): unlike a userland host signal, the
//! kernel delivers it exactly at the deadline, so there is nothing to poll.
//! [`litebox::platform::SignalProvider::take_pending_signals`] runs whenever
//! the guest exits to the shim for any reason (including the delivered
//! interrupt itself), and reports whichever timers have since expired.
//!
//! One hardware deadline backs every live timer: creating or (re)arming one
//! re-arms the kernel to the earliest across all of them.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use litebox_common_linux::signal::Signal;
use litebox_platform::time::Instant as _;
use spin::Mutex;

use crate::{Instant, VmUserland, kcall, now};

const DISARMED: u64 = 0;

struct TimerState {
    signal: Signal,
    /// An [`Instant`]'s nanoseconds, or [`DISARMED`].
    deadline: AtomicU64,
}

/// Every live timer, so a new deadline can be the earliest across all of
/// them, and [`take_pending_signals`](litebox::platform::SignalProvider::take_pending_signals)
/// can find which expired.
static TIMERS: Mutex<Vec<Weak<TimerState>>> = Mutex::new(Vec::new());

/// A one-shot timer that raises its signal when its deadline passes.
pub struct Timer(Arc<TimerState>);

impl litebox::platform::TimerHandle for Timer {
    fn set_timer(&self, duration: Duration) {
        let deadline = if duration.is_zero() {
            DISARMED
        } else {
            now()
                .checked_add(duration)
                .map_or(u64::MAX, Instant::as_nanos)
                .max(DISARMED + 1)
        };
        self.0.deadline.store(deadline, Ordering::Relaxed);
        rearm();
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.0.deadline.store(DISARMED, Ordering::Relaxed);
        rearm();
    }
}

impl litebox::platform::TimerProvider for VmUserland {
    type TimerHandle = Timer;
    type Signal = Signal;

    fn create_timer(&self, signal: Signal) -> Result<Timer, litebox::platform::TimerCreationError> {
        let timer = Arc::new(TimerState {
            signal,
            deadline: AtomicU64::new(DISARMED),
        });
        TIMERS.lock().push(Arc::downgrade(&timer));
        Ok(Timer(timer))
    }
}

/// The signals of expired timers, which it disarms (their kernel deadline
/// already fired, or they were never armed to begin with).
impl litebox::platform::SignalProvider for VmUserland {
    type Signal = Signal;

    fn take_pending_signals(&self, mut f: impl FnMut(Signal)) {
        let now = now().as_nanos();
        let mut due = Vec::new();
        let mut rearm_needed = false;
        TIMERS.lock().retain(|timer| {
            let Some(timer) = timer.upgrade() else {
                return false;
            };
            let deadline = timer.deadline.load(Ordering::Relaxed);
            if deadline != DISARMED && deadline <= now {
                timer.deadline.store(DISARMED, Ordering::Relaxed);
                due.push(timer.signal);
                rearm_needed = true;
            }
            true
        });
        // Not under the timers' lock, which `Timer::set_timer`/`drop` take.
        due.into_iter().for_each(&mut f);
        if rearm_needed {
            rearm();
        }
    }
}

/// The earliest live timer's deadline, if any.
pub(crate) fn next_deadline() -> Option<Instant> {
    TIMERS
        .lock()
        .iter()
        .filter_map(
            |timer| match timer.upgrade()?.deadline.load(Ordering::Relaxed) {
                DISARMED => None,
                deadline => Some(deadline),
            },
        )
        .min()
        .map(Instant::from_nanos)
}

/// Sets the process's kernel timer to the earliest live timer, or cancels it
/// if none is armed.
fn rearm() {
    kcall::set_timer(next_deadline()).unwrap_or_else(|status| panic!("set_timer: {status:?}"));
}
