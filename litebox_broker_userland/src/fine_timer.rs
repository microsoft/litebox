// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The process's timer resolution, raised for waits with short timeouts.

use std::time::Duration;

use windows_sys::Win32::Media::{TIMERR_NOERROR, timeBeginPeriod, timeEndPeriod};

/// The timer resolution, in milliseconds, of a wait with a short timeout.
const FINE_TIMER_PERIOD_MS: u32 = 1;
/// The timer resolution Windows uses unless a process raises it.
pub(crate) const DEFAULT_TIMER_PERIOD: Duration = Duration::from_micros(15_625);

/// Windows rounds a wait's timeout up to the process's timer resolution,
/// [`DEFAULT_TIMER_PERIOD`] by default, which would stretch short waits (e.g.,
/// a provider's quick retries). So while a waiter's waits have a shorter
/// timeout, it raises the resolution to [`FINE_TIMER_PERIOD_MS`], and restores
/// it at the first longer wait or when dropped. Since Windows 10 2004, this
/// affects only this process.
pub(crate) struct FineTimer {
    /// Whether this raised the resolution.
    raised: bool,
}

impl FineTimer {
    pub(crate) fn new() -> Self {
        Self { raised: false }
    }

    /// Raises the resolution for a wait with `timeout` shorter than
    /// [`DEFAULT_TIMER_PERIOD`], else restores it; `None` waits forever.
    pub(crate) fn adjust(&mut self, timeout: Option<Duration>) {
        self.set(timeout.is_some_and(|timeout| timeout < DEFAULT_TIMER_PERIOD));
    }

    #[cfg(test)]
    pub(crate) fn is_raised(&self) -> bool {
        self.raised
    }

    fn set(&mut self, raised: bool) {
        if raised == self.raised {
            return;
        }
        // SAFETY: Both functions take only an integer, and this ends only a
        // period it began.
        let result = unsafe {
            if raised {
                timeBeginPeriod(FINE_TIMER_PERIOD_MS)
            } else {
                timeEndPeriod(FINE_TIMER_PERIOD_MS)
            }
        };
        // If raising the resolution fails, short waits are only longer.
        if result == TIMERR_NOERROR {
            self.raised = raised;
        }
    }
}

impl Drop for FineTimer {
    fn drop(&mut self) {
        self.set(false);
    }
}
