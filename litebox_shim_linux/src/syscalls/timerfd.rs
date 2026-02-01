// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Timer file descriptor for notification

use core::sync::atomic::AtomicU32;
use core::time::Duration;

use litebox::{
    event::{
        Events, IOPollable,
        observer::Observer,
        polling::{Pollee, TryOpError},
        wait::WaitContext,
    },
    fs::OFlags,
    platform::{Instant as _, TimeProvider},
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{ClockId, TfdFlags, TfdSetTimeFlags, errno::Errno};

/// A timer file descriptor that can be used for event notification.
///
/// When the timer expires, it becomes readable and returns the number of
/// expirations since the last read.
pub(crate) struct TimerFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    /// The clock type used by this timer.
    /// Currently stored for future use - proper CLOCK_REALTIME vs CLOCK_MONOTONIC
    /// differentiation would require this field.
    #[allow(dead_code)]
    clockid: ClockId,
    /// Current expiration count (number of times the timer has fired)
    ticks: litebox::sync::Mutex<Platform, u64>,
    /// Timer interval (for periodic timers). Duration::ZERO means one-shot.
    interval: litebox::sync::Mutex<Platform, Duration>,
    /// When the timer should next fire (absolute time from boot)
    /// None means timer is disarmed
    expiration: litebox::sync::Mutex<Platform, Option<<Platform as TimeProvider>::Instant>>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
    /// Pollee for poll/epoll support
    pollee: Pollee<Platform>,
    /// Platform reference for time operations
    platform: &'static Platform,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> TimerFile<Platform> {
    pub(crate) fn new(platform: &'static Platform, clockid: ClockId, flags: TfdFlags) -> Self {
        let mut status = OFlags::RDONLY;
        status.set(OFlags::NONBLOCK, flags.contains(TfdFlags::TFD_NONBLOCK));

        Self {
            clockid,
            ticks: litebox::sync::Mutex::new(0),
            interval: litebox::sync::Mutex::new(Duration::ZERO),
            expiration: litebox::sync::Mutex::new(None),
            status: AtomicU32::new(status.bits()),
            pollee: Pollee::new(),
            platform,
        }
    }

    /// Check if the timer has expired and update tick count if needed
    #[allow(clippy::collapsible_if)]
    fn check_and_update_expiration(&self) {
        let now = self.platform.now();
        let mut expiration = self.expiration.lock();
        let mut ticks = self.ticks.lock();
        let interval = *self.interval.lock();

        if let Some(exp) = *expiration {
            if now >= exp {
                // Timer has expired at least once
                *ticks += 1;

                if interval == Duration::ZERO {
                    // One-shot timer - disarm
                    *expiration = None;
                } else {
                    // Periodic timer - calculate how many times it expired and reschedule
                    let elapsed = now.duration_since(&exp);
                    let additional_ticks = elapsed.as_nanos() / interval.as_nanos().max(1);
                    // Truncation is intentional: u128 ticks would overflow u64 counter anyway
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        *ticks += additional_ticks as u64;
                    }

                    // Set next expiration using saturating arithmetic to avoid overflow
                    // Clamp multiplier to u32::MAX to prevent overflow in duration multiplication
                    #[allow(clippy::cast_possible_truncation)]
                    let multiplier = (additional_ticks + 1).min(u128::from(u32::MAX)) as u32;
                    let total_elapsed = interval.saturating_mul(multiplier);
                    let next = exp.checked_add(total_elapsed).unwrap_or(now);
                    *expiration = Some(next);
                }

                // Notify poll waiters
                drop(ticks);
                drop(expiration);
                self.pollee.notify_observers(Events::IN);
            }
        }
    }

    fn try_read(&self) -> Result<u64, TryOpError<Errno>> {
        self.check_and_update_expiration();

        let mut ticks = self.ticks.lock();
        if *ticks == 0 {
            return Err(TryOpError::TryAgain);
        }

        let res = *ticks;
        *ticks = 0;
        Ok(res)
    }

    pub(crate) fn read(&self, cx: &WaitContext<'_, Platform>) -> Result<u64, Errno> {
        // Check timer status before potentially blocking
        self.check_and_update_expiration();

        self.pollee
            .wait(
                cx,
                self.get_status().contains(OFlags::NONBLOCK),
                Events::IN,
                || self.try_read(),
            )
            .map_err(Errno::from)
    }

    /// Set the timer's expiration time and interval.
    /// Returns the old (remaining, interval) values.
    pub(crate) fn set_time(
        &self,
        _flags: TfdSetTimeFlags,
        new_value: Duration,
        new_interval: Duration,
    ) -> (Duration, Duration) {
        let mut expiration = self.expiration.lock();
        let mut interval = self.interval.lock();
        let mut ticks = self.ticks.lock();

        // Calculate old remaining time
        let old_remaining = if let Some(exp) = *expiration {
            let now = self.platform.now();
            if now >= exp {
                Duration::ZERO
            } else {
                exp.checked_duration_since(&now).unwrap_or(Duration::ZERO)
            }
        } else {
            Duration::ZERO
        };
        let old_interval = *interval;

        // Clear ticks on settime
        *ticks = 0;

        // Set new values
        *interval = new_interval;

        if new_value == Duration::ZERO {
            // Disarm the timer
            *expiration = None;
        } else {
            // Note: TFD_TIMER_ABSTIME is rejected earlier in sys_timerfd_settime,
            // so we only handle relative time here
            let now = self.platform.now();
            let exp_time = now.checked_add(new_value).unwrap_or(now);
            *expiration = Some(exp_time);
        }

        (old_remaining, old_interval)
    }

    /// Get the timer's current remaining time and interval.
    pub(crate) fn get_time(&self) -> (Duration, Duration) {
        self.check_and_update_expiration();

        let expiration = self.expiration.lock();
        let interval = self.interval.lock();

        let remaining = if let Some(exp) = *expiration {
            let now = self.platform.now();
            if now >= exp {
                Duration::ZERO
            } else {
                exp.checked_duration_since(&now).unwrap_or(Duration::ZERO)
            }
        } else {
            Duration::ZERO
        };

        (remaining, *interval)
    }

    super::common_functions_for_file_status!();
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for TimerFile<Platform> {
    fn check_io_events(&self) -> Events {
        self.check_and_update_expiration();

        let ticks = self.ticks.lock();
        if *ticks != 0 {
            Events::IN
        } else {
            Events::empty()
        }
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }
}

#[cfg(test)]
mod tests {
    use litebox::event::wait::WaitState;
    use litebox_common_linux::{ClockId, TfdFlags, TfdSetTimeFlags, errno::Errno};
    use litebox_platform_multiplex::platform;

    extern crate std;

    #[test]
    fn test_timerfd_oneshot() {
        let _task = crate::syscalls::tests::init_platform(None);
        let platform = platform();

        let timerfd = alloc::sync::Arc::new(super::TimerFile::new(
            platform,
            ClockId::Monotonic,
            TfdFlags::TFD_NONBLOCK,
        ));

        // Set a 10ms one-shot timer
        timerfd.set_time(
            TfdSetTimeFlags::empty(),
            core::time::Duration::from_millis(10),
            core::time::Duration::ZERO,
        );

        // Should not be readable yet
        let result = timerfd.read(&WaitState::new(platform).context());
        assert_eq!(result, Err(Errno::EAGAIN));

        // Wait for the timer to expire
        std::thread::sleep(core::time::Duration::from_millis(20));

        // Should be readable now
        let result = timerfd.read(&WaitState::new(platform).context());
        assert!(result.is_ok());
        assert!(result.unwrap() >= 1);

        // Should not be readable again (one-shot)
        let result = timerfd.read(&WaitState::new(platform).context());
        assert_eq!(result, Err(Errno::EAGAIN));
    }

    #[test]
    fn test_timerfd_disarm() {
        let _task = crate::syscalls::tests::init_platform(None);
        let platform = platform();

        let timerfd = alloc::sync::Arc::new(super::TimerFile::new(
            platform,
            ClockId::Monotonic,
            TfdFlags::TFD_NONBLOCK,
        ));

        // Set a timer
        timerfd.set_time(
            TfdSetTimeFlags::empty(),
            core::time::Duration::from_secs(10),
            core::time::Duration::ZERO,
        );

        // Get time should show remaining > 0
        let (remaining, _interval) = timerfd.get_time();
        assert!(remaining > core::time::Duration::ZERO);

        // Disarm by setting to zero
        timerfd.set_time(
            TfdSetTimeFlags::empty(),
            core::time::Duration::ZERO,
            core::time::Duration::ZERO,
        );

        // Get time should show zero
        let (remaining, interval) = timerfd.get_time();
        assert_eq!(remaining, core::time::Duration::ZERO);
        assert_eq!(interval, core::time::Duration::ZERO);
    }
}
