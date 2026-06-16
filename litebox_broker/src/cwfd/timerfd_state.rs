// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted timerfd state.
//!
//! The broker has no central timed wait/dispatch loop today. This state
//! therefore exposes [`TimerfdState::fire_due`] as the precise hook that
//! future broker polling code must call when its next deadline is reached.

use core::any::Any;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use litebox_common_linux::broker_timerfd_provider::BrokerTimerfdSpec;
use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_frame::NOTIFY_EVENT_IN;
use litebox_common_linux::notification_ring::NotificationSender;

use crate::state_registry::StateObject;
use crate::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

const NSEC_PER_SEC: u64 = 1_000_000_000;
const SETTIME_ALLOWED_FLAGS: u32 =
    libc::TFD_TIMER_ABSTIME as u32 | libc::TFD_TIMER_CANCEL_ON_SET as u32;
const CREATE_ALLOWED_FLAGS: u32 = libc::TFD_CLOEXEC as u32 | libc::TFD_NONBLOCK as u32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TimerfdError {
    #[error("timerfd op would block")]
    WouldBlock,
    #[error("invalid timerfd value")]
    InvalidValue,
}

#[derive(Debug)]
pub struct TimerfdState {
    inner: Mutex<TimerfdInner>,
    subscriptions: SubscriptionList,
}

#[derive(Debug)]
struct TimerfdInner {
    clockid: i32,
    interval: Duration,
    next_deadline: Option<Instant>,
    accumulated: u64,
}

impl TimerfdState {
    pub fn new(clockid: i32, flags: u32) -> Result<Arc<Self>, TimerfdError> {
        if !matches!(clockid, libc::CLOCK_MONOTONIC | libc::CLOCK_REALTIME)
            || flags & !CREATE_ALLOWED_FLAGS != 0
        {
            return Err(TimerfdError::InvalidValue);
        }
        Ok(Arc::new(Self {
            inner: Mutex::new(TimerfdInner {
                clockid,
                interval: Duration::ZERO,
                next_deadline: None,
                accumulated: 0,
            }),
            subscriptions: SubscriptionList::new(),
        }))
    }

    pub fn settime(&self, new_value: BrokerTimerfdSpec, flags: u32) -> Result<(), TimerfdError> {
        if flags & !SETTIME_ALLOWED_FLAGS != 0 || flags & libc::TFD_TIMER_CANCEL_ON_SET as u32 != 0
        {
            return Err(TimerfdError::InvalidValue);
        }
        let interval = duration_from_parts(new_value.interval_sec, new_value.interval_nsec)?;
        let value = duration_from_parts(new_value.value_sec, new_value.value_nsec)?;
        let mut inner = self.inner.lock().expect("TimerfdState poisoned");
        refresh_locked(&mut inner, Instant::now());
        inner.interval = interval;
        inner.accumulated = 0;
        inner.next_deadline = compute_deadline(inner.clockid, value, flags)?;
        Ok(())
    }

    pub fn gettime(&self) -> BrokerTimerfdSpec {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("TimerfdState poisoned");
        refresh_locked(&mut inner, now);
        let remaining = inner
            .next_deadline
            .map(|deadline| deadline.saturating_duration_since(now))
            .unwrap_or(Duration::ZERO);
        spec_from_durations(inner.interval, remaining)
    }

    pub fn read(&self) -> Result<u64, TimerfdError> {
        let mut inner = self.inner.lock().expect("TimerfdState poisoned");
        refresh_locked(&mut inner, Instant::now());
        if inner.accumulated == 0 {
            return Err(TimerfdError::WouldBlock);
        }
        let expirations = inner.accumulated;
        inner.accumulated = 0;
        Ok(expirations)
    }

    pub fn current_events(&self) -> u32 {
        let mut inner = self.inner.lock().expect("TimerfdState poisoned");
        refresh_locked(&mut inner, Instant::now());
        if inner.accumulated > 0 {
            NOTIFY_EVENT_IN
        } else {
            0
        }
    }

    pub fn fire_due(&self, now: Instant) -> bool {
        let mut inner = self.inner.lock().expect("TimerfdState poisoned");
        let before = inner.accumulated;
        refresh_locked(&mut inner, now);
        let became_readable = before == 0 && inner.accumulated > 0;
        drop(inner);
        if became_readable {
            self.subscriptions.notify(NOTIFY_EVENT_IN);
        }
        became_readable
    }

    // TODO(broker-timerfd): call `fire_due(Instant::now())` from the broker's
    // future timed dispatch loop whenever this state's `next_deadline` is due,
    // and arrange for the loop to sleep until the earliest live timerfd
    // deadline. Without that hook, expirations are accumulated lazily by RPCs
    // (`read`, `gettime`, `query_events`) but subscribers are not woken exactly
    // at the deadline.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.inner
            .lock()
            .expect("TimerfdState poisoned")
            .next_deadline
    }

    pub fn subscribe(
        &self,
        subscription_id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError> {
        let now_events = self.current_events();
        self.subscriptions
            .add(subscription_id, events_mask, sender)?;
        let initial = now_events & events_mask;
        if initial != 0 {
            self.subscriptions.notify(initial);
        }
        Ok(())
    }

    pub fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        self.subscriptions.remove(subscription_id)
    }
}

fn compute_deadline(
    clockid: i32,
    value: Duration,
    flags: u32,
) -> Result<Option<Instant>, TimerfdError> {
    if value.is_zero() {
        return Ok(None);
    }
    let now = Instant::now();
    if flags & libc::TFD_TIMER_ABSTIME as u32 == 0 {
        return now
            .checked_add(value)
            .map(Some)
            .ok_or(TimerfdError::InvalidValue);
    }
    let remaining = match clockid {
        libc::CLOCK_REALTIME | libc::CLOCK_MONOTONIC => {
            value.saturating_sub(clock_now_duration(clockid)?)
        }
        _ => return Err(TimerfdError::InvalidValue),
    };
    now.checked_add(remaining)
        .map(Some)
        .ok_or(TimerfdError::InvalidValue)
}

fn refresh_locked(inner: &mut TimerfdInner, now: Instant) {
    let Some(deadline) = inner.next_deadline else {
        return;
    };
    if now < deadline {
        return;
    }
    inner.accumulated = inner.accumulated.saturating_add(1);
    if inner.interval.is_zero() {
        inner.next_deadline = None;
        return;
    }
    let elapsed_after_first = now.duration_since(deadline);
    let additional = elapsed_after_first.as_nanos() / inner.interval.as_nanos();
    let additional_u64 = u64::try_from(additional).unwrap_or(u64::MAX);
    inner.accumulated = inner.accumulated.saturating_add(additional_u64);
    let total = additional_u64.saturating_add(1);
    inner.next_deadline = duration_mul(inner.interval, total)
        .and_then(|delta| deadline.checked_add(delta))
        .or(Some(now));
}

fn duration_from_parts(sec: u64, nsec: u64) -> Result<Duration, TimerfdError> {
    if nsec >= NSEC_PER_SEC {
        return Err(TimerfdError::InvalidValue);
    }
    Ok(Duration::from_secs(sec) + Duration::from_nanos(nsec))
}

fn clock_now_duration(clockid: i32) -> Result<Duration, TimerfdError> {
    // SAFETY: `timespec` may be zero-initialized before passing a valid
    // mutable pointer to `clock_gettime`; `clockid` is validated by the caller.
    let mut ts = unsafe { core::mem::zeroed::<libc::timespec>() };
    // SAFETY: `ts` is a valid, writable `timespec` pointer.
    if unsafe { libc::clock_gettime(clockid, &mut ts) } != 0 {
        return Err(TimerfdError::InvalidValue);
    }
    let secs = u64::try_from(ts.tv_sec).map_err(|_| TimerfdError::InvalidValue)?;
    let nsecs = u64::try_from(ts.tv_nsec).map_err(|_| TimerfdError::InvalidValue)?;
    duration_from_parts(secs, nsecs)
}

fn spec_from_durations(interval: Duration, value: Duration) -> BrokerTimerfdSpec {
    BrokerTimerfdSpec {
        interval_sec: interval.as_secs(),
        interval_nsec: u64::from(interval.subsec_nanos()),
        value_sec: value.as_secs(),
        value_nsec: u64::from(value.subsec_nanos()),
    }
}

fn duration_mul(duration: Duration, count: u64) -> Option<Duration> {
    let nanos = duration.as_nanos().checked_mul(u128::from(count))?;
    let secs = nanos / u128::from(NSEC_PER_SEC);
    let sub_nanos = nanos % u128::from(NSEC_PER_SEC);
    let secs = u64::try_from(secs).ok()?;
    let sub_nanos = u64::try_from(sub_nanos).ok()?;
    Some(Duration::from_secs(secs) + Duration::from_nanos(sub_nanos))
}

impl StateObject for TimerfdState {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::Timerfd
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn subscribe(
        &self,
        subscription_id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError> {
        TimerfdState::subscribe(self, subscription_id, events_mask, sender)
    }

    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        TimerfdState::unsubscribe(self, subscription_id)
    }

    fn current_events(&self) -> u32 {
        TimerfdState::current_events(self)
    }

    fn try_flush_subscriptions(&self) {
        self.subscriptions.try_flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_linux::notification_ring::NotificationReceiver;
    use litebox_common_linux::shmem_ring::ShmemRingPair;

    fn make_pair() -> (Arc<Mutex<NotificationSender>>, NotificationReceiver) {
        let (pair, tx_fd, rx_fd) = ShmemRingPair::create().expect("ring create");
        let (broker_writer, _unused) = pair.into_parts();
        let (_unused, worker_reader) = ShmemRingPair::open(tx_fd, rx_fd).expect("ring open");
        (
            Arc::new(Mutex::new(NotificationSender::new(broker_writer))),
            NotificationReceiver::new(worker_reader),
        )
    }

    #[test]
    fn relative_oneshot_accumulates_on_read() {
        let timer = TimerfdState::new(libc::CLOCK_MONOTONIC, 0).unwrap();
        timer
            .settime(
                BrokerTimerfdSpec {
                    value_nsec: 1,
                    ..BrokerTimerfdSpec::default()
                },
                0,
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(timer.read().unwrap(), 1);
        assert!(matches!(timer.read(), Err(TimerfdError::WouldBlock)));
    }

    #[test]
    fn fire_due_notifies_subscriber() {
        let timer = TimerfdState::new(libc::CLOCK_MONOTONIC, 0).unwrap();
        timer
            .settime(
                BrokerTimerfdSpec {
                    value_sec: 60,
                    ..BrokerTimerfdSpec::default()
                },
                0,
            )
            .unwrap();
        let (sender, mut receiver) = make_pair();
        timer.subscribe(7, NOTIFY_EVENT_IN, sender).unwrap();
        let due = timer.next_deadline().unwrap();
        assert!(timer.fire_due(due));
        let frame = receiver.recv().unwrap();
        assert_eq!(frame.subscription_id(), 7);
        assert_eq!(frame.events(), NOTIFY_EVENT_IN);
        timer.unsubscribe(7).unwrap();
    }
}
