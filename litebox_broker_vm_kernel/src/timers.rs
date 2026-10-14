// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker timers on the kernel clock. Alarms fire when the broker runs: on
//! each `BrokerEnter` and each poll of a blocked wait, after the kernel halts
//! until the earliest deadline ([`KernelTimers::next_deadline`]), and when
//! that deadline interrupts a running process. A fired alarm publishes
//! its timer's readiness to its watchers (e.g., processes sharing the timer
//! across fork), through their associations' notification rings.
//!
//! Every armed timer interrupts the running process when due, whether or not
//! anything watches it: a fast periodic timer file interrupts even a busy
//! loop every period.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
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
}

struct KernelAlarm {
    /// On the [`TimerProvider::now`] clock.
    deadline: SpinMutex<Option<Duration>>,
    watchers: SharedReadinessWatchers,
}

/// Dropping it cancels the alarm.
struct AlarmHandle(Arc<KernelAlarm>);

impl Alarm for AlarmHandle {
    fn set(&self, deadline: Option<Duration>) {
        *self.0.deadline.lock() = deadline;
    }
}

impl KernelTimers {
    pub(crate) fn new(platform: &'static VmKernel) -> Self {
        Self {
            platform,
            alarms: SpinMutex::new(Vec::new()),
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
        Some(Instant::from_nanos(
            u64::try_from(earliest.as_nanos()).unwrap_or(u64::MAX),
        ))
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
        Ok(Box::new(AlarmHandle(alarm)))
    }
}

/// `deadline` and `other`'s earlier, either being `None` for none.
pub(crate) fn earliest(deadline: Option<Instant>, other: Option<Instant>) -> Option<Instant> {
    match (deadline, other) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
