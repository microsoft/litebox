// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned platform timerfd authority.
//!
//! A broker timerfd delegates timekeeping to a host-owned Linux `timerfd`
//! descriptor. The broker core owns the object reference and readiness
//! registration; the host platform (via [`TimerProvider`]) owns the real
//! descriptor and publishes readiness when the timer expires, exactly like
//! broker sockets.

use alloc::sync::Arc;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::timer::{CreateTimerRequest, TimerSpec};
use spin::Once;

use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::session::{ObjectEntry, ObjectRights};
use crate::{BrokerError, BrokerSession, Result, SessionId};

/// Broker-wide timerfd provider supplied by the host platform.
///
/// The provider creates per-timer [`PlatformTimer`] resources and owns any
/// bookkeeping shared across a session's timers. Operations on an individual
/// timer belong to [`PlatformTimer`], not this shared provider.
pub trait TimerProvider: Send + Sync {
    /// Creates one host timerfd resource for an authenticated session.
    ///
    /// The returned timer must not retain authority beyond its `Arc` lifetime.
    fn create(
        &self,
        session_id: SessionId,
        request: CreateTimerRequest,
        readiness: ReadinessRegistration,
    ) -> Result<Arc<dyn PlatformTimer>>;

    /// Releases provider state associated with a session after its references close.
    fn close_session(&self, session_id: SessionId);
}

/// Outcome of draining a host timerfd.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerRead {
    /// Number of expirations drained (`>= 1` for a real expiration, `0` when
    /// the read was cancelled).
    pub expirations: u64,
    /// Set when a `CANCEL_ON_SET` timer was cancelled by a discontinuous clock
    /// change; the guest maps this to `ECANCELED`.
    pub cancelled: bool,
}

/// One host timerfd resource created by [`TimerProvider`].
///
/// The broker retains this resource in an `Arc`, allowing an operation already
/// in flight to finish after its object handle closes. Dropping the final `Arc`
/// releases the host descriptor.
pub trait PlatformTimer: Send + Sync {
    /// Arms or disarms the timer, returning the setting previously in effect.
    ///
    /// An all-zero `value` in `specification` disarms the timer. Unsupported
    /// `flags` are rejected with [`BrokerError::UnsupportedOperation`].
    fn set(&self, specification: TimerSpec, flags: u32) -> Result<TimerSpec>;

    /// Returns the time remaining until the next expiration and the interval.
    fn get(&self) -> Result<TimerSpec>;

    /// Drains and returns the accumulated expiration count.
    ///
    /// A timer that has not expired since the last read returns
    /// [`BrokerError::WouldBlock`]. A successful read always returns `>= 1`.
    fn read(&self) -> Result<TimerRead>;

    /// Returns the current readiness snapshot.
    fn readiness(&self) -> ReadinessFlags;
}

/// Placeholder provider for broker configurations that deliberately disable timers.
pub struct UnsupportedTimerProvider;

impl TimerProvider for UnsupportedTimerProvider {
    fn create(
        &self,
        _session_id: SessionId,
        _request: CreateTimerRequest,
        _readiness: ReadinessRegistration,
    ) -> Result<Arc<dyn PlatformTimer>> {
        Err(BrokerError::UnsupportedOperation)
    }

    fn close_session(&self, _session_id: SessionId) {}
}

/// Creates a broker-owned timerfd.
///
/// The total number of live timers is bounded by the shared object-reference
/// limit; timers do not carry a separate per-resource quota.
pub fn create(
    session: &BrokerSession,
    request: CreateTimerRequest,
    readiness_sink: Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    let rights = session
        .core
        .policy
        .principal_object_rights(session.caller_credential)?;
    let reference = session.reserve_object_reference(rights)?;
    let guard = Arc::new(TimerReservation);
    let readiness =
        ReadinessRegistration::new_with_retirement_guard(reference.handle(), readiness_sink, guard);
    let resource = Arc::new(TimerResource {
        platform_timer: Once::new(),
        readiness,
    });
    let platform_timer = match session.core.timer_provider.create(
        session.session_id,
        request,
        resource.readiness.clone(),
    ) {
        Ok(timerfd) => timerfd,
        Err(error) => {
            // The provider may have retained its registration before failing,
            // so retirement cannot rely on the local clone being the last one.
            resource.readiness.retire();
            return Err(error);
        }
    };
    resource.platform_timer.call_once(|| platform_timer);
    let handle = reference.commit(ObjectEntry::Timer(TimerObject::new(resource)))?;
    Ok(handle)
}

/// Arms or disarms a broker-owned timerfd, returning the previous setting.
pub fn set(
    session: &BrokerSession,
    handle: ObjectHandle,
    specification: TimerSpec,
    flags: u32,
) -> Result<(TimerSpec, ReadinessFlags)> {
    let resource = timer_resource(session, handle, ObjectRights::WRITE)?;
    let previous = resource.set(specification, flags)?;
    Ok((previous, resource.readiness()))
}

/// Returns a broker-owned timerfd's current setting.
pub fn get(session: &BrokerSession, handle: ObjectHandle) -> Result<TimerSpec> {
    let resource = timer_resource(session, handle, ObjectRights::WAIT)?;
    resource.get()
}

/// Drains a broker-owned timerfd's accumulated expiration count.
pub fn read(session: &BrokerSession, handle: ObjectHandle) -> Result<(TimerRead, ReadinessFlags)> {
    let resource = timer_resource(session, handle, ObjectRights::WAIT)?;
    let outcome = resource.read()?;
    Ok((outcome, resource.readiness()))
}

fn timer_resource(
    session: &BrokerSession,
    handle: ObjectHandle,
    required_rights: ObjectRights,
) -> Result<Arc<TimerResource>> {
    let object = session.authorized_object(handle, required_rights)?;
    let object = object.read();
    let ObjectEntry::Timer(timerfd) = &*object else {
        return Err(BrokerError::InvalidRights);
    };
    Ok(timerfd.resource())
}

/// A broker-owned timerfd reference.
pub(crate) struct TimerObject {
    resource: Arc<TimerResource>,
}

impl TimerObject {
    fn new(resource: Arc<TimerResource>) -> Self {
        Self { resource }
    }

    pub(crate) fn resource(&self) -> Arc<TimerResource> {
        Arc::clone(&self.resource)
    }
}

pub(crate) struct TimerResource {
    platform_timer: Once<Arc<dyn PlatformTimer>>,
    readiness: ReadinessRegistration,
}

impl TimerResource {
    fn platform_timer(&self) -> &dyn PlatformTimer {
        self.platform_timer
            .get()
            .expect("committed timerfd resources are initialized")
            .as_ref()
    }

    fn set(&self, specification: TimerSpec, flags: u32) -> Result<TimerSpec> {
        self.platform_timer().set(specification, flags)
    }

    fn get(&self) -> Result<TimerSpec> {
        self.platform_timer().get()
    }

    fn read(&self) -> Result<TimerRead> {
        self.platform_timer().read()
    }

    pub(crate) fn readiness(&self) -> ReadinessFlags {
        self.platform_timer().readiness()
    }
}

impl Drop for TimerResource {
    fn drop(&mut self) {
        self.readiness.retire();
    }
}

/// Retirement guard for a timerfd's readiness registration.
///
/// Timers are bounded by the shared object-reference limit rather than a
/// dedicated quota, so this guard carries no reservation state; it exists only
/// to satisfy the readiness registration's deferred-retirement contract.
struct TimerReservation;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::readiness::tests::TestReadinessSink;
    use crate::{BrokerCore, CallerCredential};
    use alloc::sync::Weak;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;

    const TEST_CLOCK_MONOTONIC: i32 = 1;

    fn create_request() -> CreateTimerRequest {
        CreateTimerRequest {
            clock_id: TEST_CLOCK_MONOTONIC,
        }
    }

    fn armed_spec() -> TimerSpec {
        TimerSpec {
            value_seconds: 0,
            value_nanoseconds: 500_000,
            interval_seconds: 0,
            interval_nanoseconds: 0,
        }
    }

    #[derive(Clone, Default)]
    pub(crate) struct TestTimerProvider {
        state: Arc<TestTimerState>,
    }

    #[derive(Default)]
    struct TestTimerState {
        creates: StdMutex<std::vec::Vec<(SessionId, CreateTimerRequest)>>,
        closed_sessions: StdMutex<std::vec::Vec<SessionId>>,
        dropped_timers: AtomicUsize,
        fail_create: core::sync::atomic::AtomicBool,
        live_timer: StdMutex<Option<Weak<TestPlatformTimer>>>,
    }

    impl TestTimerProvider {
        pub(crate) fn fail_next_create(&self) {
            self.state.fail_create.store(true, Ordering::Relaxed);
        }

        /// Simulates a host expiration on the most recently created live timer.
        fn fire_live(&self) {
            self.state
                .live_timer
                .lock()
                .unwrap()
                .as_ref()
                .and_then(Weak::upgrade)
                .expect("a live timer was created")
                .fire();
        }
    }

    impl TimerProvider for TestTimerProvider {
        fn create(
            &self,
            session_id: SessionId,
            request: CreateTimerRequest,
            readiness: ReadinessRegistration,
        ) -> Result<Arc<dyn PlatformTimer>> {
            self.state
                .creates
                .lock()
                .unwrap()
                .push((session_id, request));
            if self.state.fail_create.swap(false, Ordering::Relaxed) {
                return Err(BrokerError::OutOfMemory);
            }
            let timer = Arc::new(TestPlatformTimer {
                state: Arc::clone(&self.state),
                readiness,
                setting: StdMutex::new(TimerSpec::default()),
                pending: AtomicU64::new(0),
            });
            *self.state.live_timer.lock().unwrap() = Some(Arc::downgrade(&timer));
            Ok(timer)
        }

        fn close_session(&self, session_id: SessionId) {
            self.state.closed_sessions.lock().unwrap().push(session_id);
        }
    }

    struct TestPlatformTimer {
        state: Arc<TestTimerState>,
        readiness: ReadinessRegistration,
        setting: StdMutex<TimerSpec>,
        pending: AtomicU64,
    }

    impl TestPlatformTimer {
        /// Simulates a host expiration: accrues a count and publishes readiness.
        fn fire(&self) {
            self.pending.fetch_add(1, Ordering::Relaxed);
            self.readiness.publish(ReadinessFlags::READ).unwrap();
        }
    }

    impl PlatformTimer for TestPlatformTimer {
        fn set(&self, specification: TimerSpec, _flags: u32) -> Result<TimerSpec> {
            let mut setting = self.setting.lock().unwrap();
            let previous = *setting;
            *setting = specification;
            Ok(previous)
        }

        fn get(&self) -> Result<TimerSpec> {
            Ok(*self.setting.lock().unwrap())
        }

        fn read(&self) -> Result<TimerRead> {
            let pending = self.pending.swap(0, Ordering::Relaxed);
            if pending == 0 {
                return Err(BrokerError::WouldBlock);
            }
            Ok(TimerRead {
                expirations: pending,
                cancelled: false,
            })
        }

        fn readiness(&self) -> ReadinessFlags {
            if self.pending.load(Ordering::Relaxed) > 0 {
                ReadinessFlags::READ
            } else {
                ReadinessFlags::default()
            }
        }
    }

    impl Drop for TestPlatformTimer {
        fn drop(&mut self) {
            self.state.dropped_timers.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn check_timer_lifecycle(broker: &BrokerCore, provider: &TestTimerProvider) {
        check_failed_create_rolls_back(broker, provider);
        check_timer_operations(broker, provider);
        check_wrong_object_type_is_rejected(broker, provider);
    }

    fn check_failed_create_rolls_back(broker: &BrokerCore, provider: &TestTimerProvider) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        provider.fail_next_create();
        let sink = Arc::new(TestReadinessSink::default());
        assert_eq!(
            create(&session, create_request(), sink.clone()),
            Err(BrokerError::OutOfMemory)
        );
        assert_eq!(broker.pending_references.load(Ordering::Relaxed), 0);
    }

    fn check_timer_operations(broker: &BrokerCore, provider: &TestTimerProvider) {
        let dropped_before = provider.state.dropped_timers.load(Ordering::Relaxed);
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let sink = Arc::new(TestReadinessSink::default());
        let handle = create(&session, create_request(), sink.clone()).unwrap();

        // set returns the previous (zero) setting and re-arms.
        let (previous, _readiness) = set(&session, handle, armed_spec(), 0).unwrap();
        assert_eq!(previous, TimerSpec::default());
        assert_eq!(get(&session, handle).unwrap(), armed_spec());

        // A timer that has not expired reads as WouldBlock.
        assert_eq!(read(&session, handle), Err(BrokerError::WouldBlock));

        // Simulate a host expiration; readiness is published and the drained
        // count is reported.
        provider.fire_live();
        assert_eq!(
            session.check_readiness(handle).unwrap(),
            ReadinessFlags::READ
        );
        let (outcome, readiness) = read(&session, handle).unwrap();
        assert_eq!(outcome.expirations, 1);
        assert!(!outcome.cancelled);
        assert_eq!(readiness, ReadinessFlags::default());
        assert!(!sink.published.lock().unwrap().is_empty());

        session.close_object_reference(handle).unwrap();
        assert_eq!(
            provider.state.dropped_timers.load(Ordering::Relaxed),
            dropped_before + 1
        );
    }

    fn check_wrong_object_type_is_rejected(broker: &BrokerCore, _provider: &TestTimerProvider) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let event = crate::event::create(&session, 0).unwrap();
        assert_eq!(
            set(&session, event, armed_spec(), 0),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(get(&session, event), Err(BrokerError::InvalidRights));
        assert_eq!(read(&session, event), Err(BrokerError::InvalidRights));
        session.close_object_reference(event).unwrap();
    }
}
