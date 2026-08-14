// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Integration coverage for the broker timer reactor's readiness publishing.
//!
//! These tests run in their own binary so they can build a `BrokerCore` (a
//! process singleton) and drive the real Linux timer reactor end to end,
//! observing the readiness notifications it emits through a sink that mirrors
//! the broker notification ring's coalescing contract.

use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_core::{
    BrokerCore, BrokerCoreLimits, CallerCredential, ObjectRights, PolicyEngine,
};
use litebox_broker_platform_linux_userland::{LinuxSocketProvider, LinuxTimerProvider};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::timer::{CreateTimerRequest, TimerSpec};

const CLOCK_MONOTONIC: i32 = 1;
const RECV_TIMEOUT: Duration = Duration::from_secs(5);

/// A readiness sink that reproduces the broker notification ring's
/// value-equality coalescing.
///
/// The real ring (see `litebox_broker_host` readiness `record`, which drops a
/// `publish` when `entry.readiness == readiness && !force`) never delivers a
/// second wakeup for a value the local endpoint already knows. A `publish`
/// carrying the same flags as the last delivery is therefore dropped here,
/// while a `republish` is forced through. This is the exact gate that makes
/// finding #1 observable: after a drain leaves the level at READ, only a forced
/// re-publication can wake a parked reader for the next expiration.
struct CoalescingModelSink {
    last_delivered: Mutex<Option<ReadinessFlags>>,
    deliveries: Sender<ReadinessFlags>,
}

impl ReadinessSink for CoalescingModelSink {
    fn max_tracked_objects(&self) -> usize {
        64
    }

    fn publish(
        &self,
        _handle: ObjectHandle,
        readiness: ReadinessFlags,
    ) -> litebox_broker_core::Result<()> {
        let mut last = self.last_delivered.lock().unwrap();
        if *last != Some(readiness) {
            *last = Some(readiness);
            let _ = self.deliveries.send(readiness);
        }
        Ok(())
    }

    fn republish(
        &self,
        _handle: ObjectHandle,
        readiness: ReadinessFlags,
    ) -> litebox_broker_core::Result<()> {
        *self.last_delivered.lock().unwrap() = Some(readiness);
        let _ = self.deliveries.send(readiness);
        Ok(())
    }

    fn retire(&self, _handle: ObjectHandle) {}
}

/// Reproduces finding #1: an interval timer must wake a parked reader on every
/// expiration, not only the first.
///
/// A blocking reader parks until a readiness notification arrives. After the
/// first expiration wakes it and it drains the count, the timer's level returns
/// to READ on the next expiration without changing value. If the reactor only
/// `publish`es that unchanged READ, the ring coalesces it and the reader is
/// never woken again — an indefinite hang. The reactor must instead force the
/// wakeup, exactly as the socket reactor does for a readable-count change.
#[test]
fn interval_timer_wakes_reader_on_every_expiration() {
    let limits = BrokerCoreLimits::DEFAULT;
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all()),
        limits,
        Arc::new(LinuxSocketProvider::new(limits.max_sockets).unwrap()),
    )
    .unwrap()
    .with_timer_provider(Arc::new(
        LinuxTimerProvider::new(limits.max_references).unwrap(),
    ));

    let session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();

    let (deliveries_tx, deliveries) = channel();
    let sink = Arc::new(CoalescingModelSink {
        last_delivered: Mutex::new(None),
        deliveries: deliveries_tx,
    });

    let handle = litebox_broker_core::timer::create(
        &session,
        CreateTimerRequest {
            clock_id: CLOCK_MONOTONIC,
        },
        sink,
    )
    .unwrap();

    // Arm a 20ms interval timer.
    let spec = TimerSpec {
        value_seconds: 0,
        value_nanoseconds: 20_000_000,
        interval_seconds: 0,
        interval_nanoseconds: 20_000_000,
    };
    litebox_broker_core::timer::set(&session, handle, spec, 0).unwrap();

    // The first expiration wakes the reader.
    let first = deliveries
        .recv_timeout(RECV_TIMEOUT)
        .expect("first expiration must deliver a wakeup");
    assert!(first.contains(ReadinessFlags::READ));

    // Drain, as a woken blocking reader would. This resets the timer's snapshot
    // to empty without publishing that empty transition, so the ring's
    // coalescing state still reflects READ.
    let (outcome, _readiness) = litebox_broker_core::timer::read(&session, handle).unwrap();
    assert!(outcome.expirations >= 1);

    // The next expiration must wake the reader again. On the unfixed reactor the
    // re-`publish`ed READ coalesces and this times out — the hang a real
    // blocking read would suffer.
    let second = deliveries
        .recv_timeout(RECV_TIMEOUT)
        .expect("second expiration must deliver another wakeup");
    assert!(second.contains(ReadinessFlags::READ));

    session.close_object_reference(handle).unwrap();
}
