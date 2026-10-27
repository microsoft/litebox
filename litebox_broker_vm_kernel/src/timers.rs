// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker timers on the kernel clock. Alarms fire when the broker runs: on
//! each futex operation on the control ring and each poll of a blocked wait,
//! after the kernel halts until the earliest deadline
//! ([`KernelTimers::next_deadline`]), and when that deadline interrupts a
//! running process. A fired alarm publishes
//! its timer's readiness to its watchers (e.g., processes sharing the timer
//! across fork), through their associations' notification rings.
//!
//! Every armed timer interrupts the running process when due, whether or not
//! anything watches it: a fast periodic timer file interrupts even a busy
//! loop every period. The kernel reads when the broker must next run as the
//! broker publishes it ([`PublishedDeadline`]), without its locks.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use litebox_broker_core::readiness::SharedReadinessWatchers;
use litebox_broker_core::timer::{Alarm, TimerProvider};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_platform::time::TimeProvider as _;
use litebox_platform_vm_kernel::{Instant, VmKernel};
use spin::mutex::SpinMutex;

pub(crate) struct KernelTimers {
    platform: &'static VmKernel,
    /// Every alarm not yet dropped.
    alarms: SpinMutex<Vec<Weak<KernelAlarm>>>,
    /// Lowered as an alarm is set.
    published: Arc<PublishedDeadline>,
}

struct KernelAlarm {
    /// On the [`TimerProvider::now`] clock.
    deadline: SpinMutex<Option<Duration>>,
    watchers: SharedReadinessWatchers,
}

/// Dropping it cancels the alarm.
struct AlarmHandle {
    alarm: Arc<KernelAlarm>,
    published: Arc<PublishedDeadline>,
}

impl Alarm for AlarmHandle {
    fn set(&self, deadline: Option<Duration>) {
        *self.alarm.deadline.lock() = deadline;
        if let Some(deadline) = deadline {
            self.published.lower(instant(deadline));
        }
    }
}

/// When the broker must next run, as last published, for the kernel to read
/// without the broker's locks ([`Self::get`]): the earliest of its sources'
/// deadlines (see `Broker::publish_deadline`). Published anew where they may
/// have changed (as polls, serves and associations end), and lowered as an
/// alarm is set; a later publication may be too early (e.g., an alarm since
/// cancelled), which costs a poll, but never too late. Both under one lock,
/// so that a publication computed before an alarm was set never replaces its
/// lowering.
pub(crate) struct PublishedDeadline {
    /// In nanoseconds; `u64::MAX` for none.
    nanos: AtomicU64,
    /// Orders publications and lowerings.
    publishing: SpinMutex<()>,
}

impl PublishedDeadline {
    pub(crate) fn new() -> Self {
        Self {
            nanos: AtomicU64::new(u64::MAX),
            publishing: SpinMutex::new(()),
        }
    }

    /// The deadline published last, if any.
    pub(crate) fn get(&self) -> Option<Instant> {
        let nanos = self.nanos.load(Ordering::SeqCst);
        (nanos != u64::MAX).then(|| Instant::from_nanos(nanos))
    }

    /// Publishes the deadline `next` computes, reading the sources.
    pub(crate) fn publish(&self, next: impl FnOnce() -> Option<Instant>) {
        let _publishing = self.publishing.lock();
        let nanos = next().map_or(u64::MAX, Instant::as_nanos);
        self.nanos.store(nanos, Ordering::SeqCst);
    }

    /// Lowers the published deadline to `deadline`, if earlier.
    fn lower(&self, deadline: Instant) {
        let _publishing = self.publishing.lock();
        self.nanos.fetch_min(deadline.as_nanos(), Ordering::SeqCst);
    }
}

impl KernelTimers {
    /// Its alarms lower `published` as they are set.
    pub(crate) fn new(platform: &'static VmKernel, published: Arc<PublishedDeadline>) -> Self {
        Self {
            platform,
            alarms: SpinMutex::new(Vec::new()),
            published,
        }
    }

    /// Fires the alarms whose deadlines passed.
    pub(crate) fn fire(&self) {
        let now = self.now();
        let mut due = Vec::new();
        self.alarms.lock().retain(|alarm| {
            let Some(alarm) = alarm.upgrade() else {
                return false;
            };
            let mut deadline = alarm.deadline.lock();
            if deadline.is_some_and(|deadline| deadline <= now) {
                *deadline = None;
                drop(deadline);
                due.push(alarm);
            }
            true
        });
        // Not under the alarms' locks, which setting or dropping one takes.
        for alarm in due {
            alarm.watchers.publish(ReadinessFlags::READ);
        }
    }

    /// The earliest armed deadline.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        let mut alarms = self.alarms.lock();
        alarms.retain(|alarm| alarm.strong_count() != 0);
        let earliest = alarms
            .iter()
            .filter_map(|alarm| *alarm.upgrade()?.deadline.lock())
            .min()?;
        Some(instant(earliest))
    }
}

impl TimerProvider for KernelTimers {
    /// The kernel clock, since its origin.
    fn now(&self) -> Duration {
        Duration::from_nanos(self.platform.now().as_nanos())
    }

    fn create_alarm(
        &self,
        watchers: SharedReadinessWatchers,
    ) -> litebox_broker_core::Result<Box<dyn Alarm>> {
        let alarm = Arc::new(KernelAlarm {
            deadline: SpinMutex::new(None),
            watchers,
        });
        self.alarms.lock().push(Arc::downgrade(&alarm));
        Ok(Box::new(AlarmHandle {
            alarm,
            published: self.published.clone(),
        }))
    }
}

/// `time`, on [`KernelTimers::now`]'s clock, as an instant.
pub(crate) fn instant(time: Duration) -> Instant {
    Instant::from_nanos(u64::try_from(time.as_nanos()).unwrap_or(u64::MAX))
}

/// `deadline` and `other`'s earlier, either being `None` for none.
pub(crate) fn earliest(deadline: Option<Instant>, other: Option<Instant>) -> Option<Instant> {
    match (deadline, other) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
