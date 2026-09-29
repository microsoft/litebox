// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Cross-platform timer provider backed by one alarm thread.

use std::collections::{BTreeSet, HashMap};
use std::io::Result as IoResult;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use litebox_broker_core::Result;
use litebox_broker_core::readiness::ReadinessRegistration;
use litebox_broker_core::timer::{Alarm, TimerProvider};
use litebox_broker_protocol::readiness::ReadinessFlags;

/// Timer provider that fires every broker timer alarm from a single thread.
pub(super) struct UserlandTimerProvider {
    scheduler: Arc<AlarmScheduler>,
}

/// Alarm queue shared by the provider, its alarms, and the alarm thread.
struct AlarmScheduler {
    origin: Instant,
    state: Mutex<SchedulerState>,
    /// Signaled when an alarm becomes the earliest pending deadline.
    wake: Condvar,
}

/// Mutable state of an [`AlarmScheduler`], guarded by its lock.
#[derive(Default)]
struct SchedulerState {
    /// Set once the provider is dropped to stop the alarm thread.
    stopped: bool,
    next_id: u64,
    /// Pending deadlines ordered by expiry.
    queue: BTreeSet<(Duration, u64)>,
    alarms: HashMap<u64, AlarmState>,
}

struct AlarmState {
    deadline: Option<Duration>,
    readiness: ReadinessRegistration,
}

impl UserlandTimerProvider {
    pub(super) fn new() -> IoResult<Self> {
        let scheduler = Arc::new(AlarmScheduler {
            origin: Instant::now(),
            state: Mutex::new(SchedulerState::default()),
            wake: Condvar::new(),
        });
        let thread_scheduler = Arc::clone(&scheduler);
        std::thread::Builder::new()
            .name("litebox-broker-timer".to_owned())
            .spawn(move || thread_scheduler.run())?;
        Ok(Self { scheduler })
    }
}

impl Drop for UserlandTimerProvider {
    fn drop(&mut self) {
        self.scheduler.lock().stopped = true;
        self.scheduler.wake.notify_one();
    }
}

impl TimerProvider for UserlandTimerProvider {
    fn now(&self) -> Duration {
        self.scheduler.now()
    }

    fn create_alarm(&self, readiness: ReadinessRegistration) -> Result<Box<dyn Alarm>> {
        let mut state = self.scheduler.lock();
        let id = state.next_id;
        state.next_id += 1;
        state.alarms.insert(
            id,
            AlarmState {
                deadline: None,
                readiness,
            },
        );
        Ok(Box::new(UserlandAlarm {
            scheduler: Arc::clone(&self.scheduler),
            id,
        }))
    }
}

impl AlarmScheduler {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn lock(&self) -> MutexGuard<'_, SchedulerState> {
        // Every critical section leaves the state consistent.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn run(&self) {
        let mut state = self.lock();
        while !state.stopped {
            let now = self.now();
            let mut fired = Vec::new();
            while let Some(&(deadline, id)) = state.queue.first()
                && deadline <= now
            {
                state.queue.pop_first();
                let alarm = state.alarms.get_mut(&id).expect("queued alarms are live");
                alarm.deadline = None;
                fired.push(alarm.readiness.clone());
            }
            if !fired.is_empty() {
                // Timer operations take this lock while holding the object lock
                // that readiness checks need.
                drop(state);
                for readiness in fired {
                    let _ = readiness.republish(ReadinessFlags::READ);
                }
                state = self.lock();
                continue;
            }
            state = match state.queue.first() {
                Some(&(deadline, _)) => {
                    self.wake
                        .wait_timeout(state, deadline.saturating_sub(now))
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
                None => self
                    .wake
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner),
            };
        }
    }
}

struct UserlandAlarm {
    scheduler: Arc<AlarmScheduler>,
    id: u64,
}

impl Alarm for UserlandAlarm {
    fn set(&self, deadline: Option<Duration>) {
        let mut state = self.scheduler.lock();
        let SchedulerState { queue, alarms, .. } = &mut *state;
        let alarm = alarms.get_mut(&self.id).expect("alarm is live");
        if let Some(previous) = core::mem::replace(&mut alarm.deadline, deadline) {
            queue.remove(&(previous, self.id));
        }
        if let Some(deadline) = deadline {
            queue.insert((deadline, self.id));
            if queue.first() == Some(&(deadline, self.id)) {
                self.scheduler.wake.notify_one();
            }
        }
    }
}

impl Drop for UserlandAlarm {
    fn drop(&mut self) {
        let alarm = {
            let mut state = self.scheduler.lock();
            let alarm = state.alarms.remove(&self.id).expect("alarm is live");
            if let Some(deadline) = alarm.deadline {
                state.queue.remove(&(deadline, self.id));
            }
            alarm
        };
        // Dropping the registration may retire it, so do so without the lock.
        drop(alarm);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::mpsc::{Sender, channel};
    use std::time::Duration;

    use litebox_broker_core::readiness::ReadinessSink;
    use litebox_broker_core::test_support::TestBrokerCoreBuilder;
    use litebox_broker_core::{
        BrokerError, CallerCredential, ObjectRights, PolicyEngine, Result, timer,
    };
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::timer::TimerSpec;

    use super::UserlandTimerProvider;

    #[test]
    fn dropping_provider_stops_alarm_thread() {
        let provider = UserlandTimerProvider::new().unwrap();
        let scheduler = Arc::downgrade(&provider.scheduler);
        drop(provider);
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while scheduler.strong_count() != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "alarm thread kept running"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    struct ChannelReadinessSink(std::sync::Mutex<Sender<(ObjectHandle, ReadinessFlags)>>);

    impl ReadinessSink for ChannelReadinessSink {
        fn max_tracked_objects(&self) -> usize {
            8
        }

        fn publish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
            let _ = self.0.lock().unwrap().send((handle, readiness));
            Ok(())
        }

        fn republish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
            self.publish(handle, readiness)
        }

        fn retire(&self, _handle: ObjectHandle) {}
    }

    #[test]
    fn alarms_fire_in_deadline_order_and_can_be_cancelled() {
        let process = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_timer_provider(Arc::new(UserlandTimerProvider::new().unwrap()))
        .build()
        .unwrap()
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
        let (sender, receiver) = channel();
        let sink = Arc::new(ChannelReadinessSink(std::sync::Mutex::new(sender)));
        let later = timer::create(&process, sink.clone()).unwrap();
        let cancelled = timer::create(&process, sink.clone()).unwrap();
        let sooner = timer::create(&process, sink).unwrap();
        let arm = |handle, delay: Duration| {
            let spec = TimerSpec {
                value_ns: u64::try_from(delay.as_nanos()).unwrap(),
                interval_ns: 0,
            };
            timer::set(&process, handle, spec).unwrap();
        };

        arm(cancelled, Duration::from_millis(200));
        process.close_object_reference(cancelled).unwrap();
        arm(sooner, Duration::from_millis(1));
        arm(later, Duration::from_millis(400));

        let timeout = Duration::from_secs(30);
        assert_eq!(
            receiver.recv_timeout(timeout),
            Ok((sooner, ReadinessFlags::READ))
        );
        assert_eq!(
            receiver.recv_timeout(timeout),
            Ok((later, ReadinessFlags::READ))
        );
        assert_eq!(timer::read(&process, sooner), Ok(1));
        assert_eq!(timer::read(&process, later), Ok(1));
        assert_eq!(timer::read(&process, later), Err(BrokerError::WouldBlock));
    }
}
