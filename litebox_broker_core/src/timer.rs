// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned timer object operations.
//!
//! A timer's expiration state is derived from its deadline and the provider's
//! monotonic clock whenever it is observed, so the provider only needs to wake
//! waiters once the next deadline passes.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::time::Duration;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::timer::TimerSpec;

use crate::object::{ObjectEntry, ObjectRights};
use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::{BrokerError, BrokerProcess, Result};

/// Trusted provider of the broker's monotonic clock and timer alarms.
pub trait TimerProvider: Send + Sync {
    /// Returns the current time on a monotonic clock with a fixed origin.
    fn now(&self) -> Duration;

    /// Creates a disarmed alarm for one timer.
    ///
    /// Whenever an armed alarm's deadline passes on [`Self::now`]'s clock, the
    /// provider must disarm it and call
    /// `readiness.republish(ReadinessFlags::READ)`. The provider must not hold
    /// locks that [`Alarm::set`] or dropping an alarm acquires while it
    /// republishes, and it may ignore publication errors.
    fn create_alarm(&self, readiness: ReadinessRegistration) -> Result<Box<dyn Alarm>>;
}

/// Provider-owned alarm of one timer, cancelled when dropped.
pub trait Alarm: Send + Sync {
    /// Replaces the pending deadline, or disarms the alarm if `deadline` is
    /// `None`.
    fn set(&self, deadline: Option<Duration>);
}

/// Timer provider for deployments without timers.
pub struct UnsupportedTimerProvider;

impl TimerProvider for UnsupportedTimerProvider {
    fn now(&self) -> Duration {
        Duration::ZERO
    }

    fn create_alarm(&self, _readiness: ReadinessRegistration) -> Result<Box<dyn Alarm>> {
        Err(BrokerError::UnsupportedOperation)
    }
}

/// Creates a disarmed broker-owned timer.
pub fn create(
    process: &BrokerProcess,
    readiness_sink: Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    let rights = process
        .core
        .policy
        .principal_object_rights(process.caller_credential)?;
    let reference = process.reserve_object_reference(rights)?;
    let readiness = ReadinessRegistration::new(reference.handle(), readiness_sink);
    let clock = Arc::clone(&process.core.timer_provider);
    let alarm = match clock.create_alarm(readiness.clone()) {
        Ok(alarm) => alarm,
        Err(error) => {
            // The provider may have retained its registration before failing.
            readiness.retire();
            return Err(error);
        }
    };
    reference.commit(ObjectEntry::Timer(TimerObject {
        clock,
        alarm,
        readiness,
        deadline: None,
        interval: Duration::ZERO,
    }))
}

/// Arms or disarms a timer, returning its previous schedule.
///
/// A nonzero `spec.value_ns` arms the timer relative to now; zero disarms it.
/// Unconsumed expirations are discarded.
pub fn set(process: &BrokerProcess, handle: ObjectHandle, spec: TimerSpec) -> Result<TimerSpec> {
    let object = process.authorized_object(handle, ObjectRights::WRITE)?;
    let mut object = object.write();
    Ok(object.as_timer_mut()?.set(spec))
}

/// Returns a timer's current schedule.
pub fn get(process: &BrokerProcess, handle: ObjectHandle) -> Result<TimerSpec> {
    let object = process.authorized_object(handle, ObjectRights::WAIT)?;
    let object = object.read();
    let timer = object.as_timer()?;
    Ok(timer.current(timer.clock.now()))
}

/// Consumes a timer's pending expirations, returning how many passed.
///
/// Returns `WouldBlock` if none has passed.
pub fn read(process: &BrokerProcess, handle: ObjectHandle) -> Result<u64> {
    let object = process.authorized_object(handle, ObjectRights::WAIT)?;
    let mut object = object.write();
    object.as_timer_mut()?.read()
}

impl ObjectEntry {
    fn as_timer(&self) -> Result<&TimerObject> {
        match self {
            Self::Timer(timer) => Ok(timer),
            _ => Err(BrokerError::InvalidRights),
        }
    }

    fn as_timer_mut(&mut self) -> Result<&mut TimerObject> {
        match self {
            Self::Timer(timer) => Ok(timer),
            _ => Err(BrokerError::InvalidRights),
        }
    }
}

pub(crate) struct TimerObject {
    clock: Arc<dyn TimerProvider>,
    alarm: Box<dyn Alarm>,
    readiness: ReadinessRegistration,
    /// Next unconsumed expiration, or `None` while disarmed.
    deadline: Option<Duration>,
    /// Period of subsequent expirations, or zero for a one-shot timer.
    interval: Duration,
}

impl TimerObject {
    pub(crate) fn readiness(&self) -> ReadinessFlags {
        if self.expirations(self.clock.now()) > 0 {
            ReadinessFlags::READ
        } else {
            ReadinessFlags::default()
        }
    }

    fn set(&mut self, spec: TimerSpec) -> TimerSpec {
        let now = self.clock.now();
        let previous = self.current(now);
        self.interval = Duration::from_nanos(spec.interval_ns);
        self.deadline =
            (spec.value_ns != 0).then(|| now.saturating_add(Duration::from_nanos(spec.value_ns)));
        self.alarm.set(self.deadline);
        previous
    }

    fn read(&mut self) -> Result<u64> {
        let now = self.clock.now();
        let expirations = self.expirations(now);
        if expirations == 0 {
            return Err(BrokerError::WouldBlock);
        }
        self.deadline = self.next_deadline(now);
        self.alarm.set(self.deadline);
        Ok(expirations)
    }

    fn current(&self, now: Duration) -> TimerSpec {
        let value = self
            .next_deadline(now)
            .map_or(Duration::ZERO, |deadline| deadline.saturating_sub(now));
        TimerSpec {
            value_ns: saturating_nanos(value),
            interval_ns: saturating_nanos(self.interval),
        }
    }

    /// Returns the number of expirations that passed by `now`.
    fn expirations(&self, now: Duration) -> u64 {
        match self.deadline {
            Some(deadline) if deadline <= now => {
                if self.interval.is_zero() {
                    1
                } else {
                    let periods =
                        now.saturating_sub(deadline).as_nanos() / self.interval.as_nanos();
                    u64::try_from(periods).map_or(u64::MAX, |periods| periods.saturating_add(1))
                }
            }
            _ => 0,
        }
    }

    /// Returns the first expiration after `now`, if any.
    fn next_deadline(&self, now: Duration) -> Option<Duration> {
        let deadline = self.deadline?;
        if deadline > now {
            return Some(deadline);
        }
        if self.interval.is_zero() {
            return None;
        }
        let interval = self.interval.as_nanos();
        let elapsed_in_period = now.saturating_sub(deadline).as_nanos() % interval;
        let remaining = u64::try_from(interval - elapsed_in_period)
            .expect("remainder of a u64-nanosecond interval fits in u64");
        Some(now.saturating_add(Duration::from_nanos(remaining)))
    }
}

impl Drop for TimerObject {
    fn drop(&mut self) {
        // The provider may still hold a registration clone mid-publication.
        self.readiness.retire();
    }
}

fn saturating_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::time::Duration;

    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::timer::TimerSpec;

    use crate::readiness::tests::TestReadinessSink;
    use crate::test_support::{ManualTimerProvider, TestBrokerCoreBuilder};
    use crate::{BrokerError, BrokerProcess, CallerCredential, ObjectRights, PolicyEngine};

    fn spec(value_ns: u64, interval_ns: u64) -> TimerSpec {
        TimerSpec {
            value_ns,
            interval_ns,
        }
    }

    fn process(builder: TestBrokerCoreBuilder) -> Arc<BrokerProcess> {
        builder
            .build()
            .unwrap()
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap()
    }

    fn builder(rights: ObjectRights) -> TestBrokerCoreBuilder {
        TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(rights))
    }

    #[test]
    fn timer_expirations_are_derived_from_the_clock() {
        let clock = Arc::new(ManualTimerProvider::default());
        let process = process(builder(ObjectRights::all()).with_timer_provider(clock.clone()));
        let sink = Arc::new(TestReadinessSink::default());
        let handle = super::create(&process, sink.clone()).unwrap();
        let republished = || sink.republished.lock().unwrap().clone();

        assert_eq!(super::get(&process, handle), Ok(spec(0, 0)));
        assert_eq!(super::read(&process, handle), Err(BrokerError::WouldBlock));

        // One-shot: expires once, then stays disarmed.
        assert_eq!(super::set(&process, handle, spec(100, 0)), Ok(spec(0, 0)));
        clock.advance(Duration::from_nanos(40));
        assert_eq!(super::get(&process, handle), Ok(spec(60, 0)));
        assert_eq!(
            process.check_readiness(handle),
            Ok(ReadinessFlags::default())
        );
        assert!(republished().is_empty());
        clock.advance(Duration::from_nanos(60));
        assert_eq!(republished(), [(handle, ReadinessFlags::READ)]);
        assert_eq!(process.check_readiness(handle), Ok(ReadinessFlags::READ));
        assert_eq!(super::get(&process, handle), Ok(spec(0, 0)));
        assert_eq!(super::read(&process, handle), Ok(1));
        assert_eq!(super::read(&process, handle), Err(BrokerError::WouldBlock));
        assert_eq!(
            process.check_readiness(handle),
            Ok(ReadinessFlags::default())
        );
        clock.advance(Duration::from_nanos(1000));
        assert_eq!(republished().len(), 1);

        // Periodic: overruns accumulate until read, and the phase is kept.
        assert_eq!(super::set(&process, handle, spec(10, 30)), Ok(spec(0, 0)));
        clock.advance(Duration::from_nanos(75));
        assert_eq!(republished().len(), 2);
        assert_eq!(super::get(&process, handle), Ok(spec(25, 30)));
        assert_eq!(super::read(&process, handle), Ok(3));
        assert_eq!(super::get(&process, handle), Ok(spec(25, 30)));
        clock.advance(Duration::from_nanos(25));
        assert_eq!(republished().len(), 3);
        assert_eq!(super::get(&process, handle), Ok(spec(30, 30)));

        // Re-arming discards unconsumed expirations and reports the old schedule.
        assert_eq!(super::set(&process, handle, spec(50, 0)), Ok(spec(30, 30)));
        assert_eq!(super::read(&process, handle), Err(BrokerError::WouldBlock));
        assert_eq!(super::set(&process, handle, spec(0, 7)), Ok(spec(50, 0)));
        assert_eq!(super::get(&process, handle), Ok(spec(0, 7)));
        clock.advance(Duration::from_nanos(1000));
        assert_eq!(republished().len(), 3);

        process.close_object_reference(handle).unwrap();
        assert_eq!(*sink.retired.lock().unwrap(), [handle]);
        assert_eq!(clock.alarm_count(), 0);
    }

    #[test]
    fn timer_values_saturate_instead_of_overflowing() {
        let clock = Arc::new(ManualTimerProvider::default());
        let process = process(builder(ObjectRights::all()).with_timer_provider(clock.clone()));
        let handle = super::create(&process, Arc::new(TestReadinessSink::default())).unwrap();

        super::set(&process, handle, spec(u64::MAX, u64::MAX)).unwrap();
        assert_eq!(super::get(&process, handle), Ok(spec(u64::MAX, u64::MAX)));

        super::set(&process, handle, spec(1, 1)).unwrap();
        clock.advance(Duration::from_secs(u64::MAX / 2));
        assert_eq!(super::read(&process, handle), Ok(u64::MAX));
        assert_eq!(super::get(&process, handle), Ok(spec(1, 1)));
    }

    #[test]
    fn timer_creation_fails_without_a_provider() {
        let process = process(builder(ObjectRights::all()));
        let sink = Arc::new(TestReadinessSink::default());
        assert_eq!(
            super::create(&process, sink.clone()),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(sink.retired.lock().unwrap().len(), 1);
    }
}
