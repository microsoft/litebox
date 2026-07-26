// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Threaded readiness publication for the Linux-userland broker host.
//!
//! [`litebox_broker_host::readiness`] owns the portable coalescing state and
//! the publication loop but deliberately holds no wake primitive, so a
//! deployment supplies one. This module pairs that state with a condition
//! variable and the thread-facing API the broker host binary needs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};

use litebox_broker_host::readiness::{
    PublishOutcome, ReadinessPublishError, ReadinessPublisher, publish_readiness,
};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_transport::channel::HostNotificationChannel;

/// Readiness publication state plus the wake primitive its publisher parks on.
///
/// Backend readiness sources share this value and call [`publish`] and
/// [`retire`]; neither waits for notification transport capacity. Exactly one
/// thread calls [`run`], which owns the association notification channel for
/// the lifetime of the association.
///
/// [`publish`]: Self::publish
/// [`retire`]: Self::retire
/// [`run`]: Self::run
#[derive(Debug)]
pub struct ReadinessPublisherRuntime {
    publisher: ReadinessPublisher,
    signaled: Mutex<bool>,
    work_available: Condvar,
    running: AtomicBool,
}

impl Default for ReadinessPublisherRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadinessPublisherRuntime {
    /// Creates idle readiness publication state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            publisher: ReadinessPublisher::new(),
            signaled: Mutex::new(false),
            work_available: Condvar::new(),
            running: AtomicBool::new(false),
        }
    }

    /// Records the authoritative readiness of one broker object.
    ///
    /// Updates are coalesced per object, so a source may call this as often as
    /// its backend state changes. An update recorded after [`close`] is
    /// discarded rather than reported, because the association it would reach
    /// is already over. Returns an error only when the association already
    /// tracks the maximum number of objects.
    ///
    /// [`close`]: Self::close
    pub fn publish(
        &self,
        handle: ObjectHandle,
        readiness: ReadinessFlags,
    ) -> Result<(), ReadinessPublishError> {
        if self.publisher.publish(handle, readiness)? == PublishOutcome::Queued {
            self.signal();
        }
        Ok(())
    }

    /// Drops readiness state for an object whose backend resource is retired.
    pub fn retire(&self, handle: ObjectHandle) {
        self.publisher.retire(handle);
    }

    /// Publishes readiness notifications until the runtime is closed.
    ///
    /// The caller must be the only owner of `channel`. Sending blocks while the
    /// local endpoint leaves the notification transport full; that is confined
    /// to this thread by design, and association teardown fails the blocked
    /// send through the transport.
    ///
    /// # Panics
    ///
    /// Panics if publication has already run. Closure is terminal, so a runtime
    /// serves exactly one publisher, and a second one would park on a wake that
    /// only ever releases one waiter. That is a silent hang, so the second
    /// caller is rejected loudly instead. A returned error is terminal for the
    /// same reason: the portable loop leaves the failed update publishable, but
    /// no later publisher can send it, so this closes publication rather than
    /// leave sources recording into state nothing will drain. Resuming on a
    /// replacement channel means a new runtime, which starts empty, so the
    /// failed update is lost at this layer.
    pub fn run<Channel: HostNotificationChannel>(
        &self,
        channel: &mut Channel,
    ) -> Result<(), Channel::Error> {
        assert!(
            !self.running.swap(true, Ordering::Relaxed),
            "readiness publication must run exactly once per runtime"
        );
        let outcome = publish_readiness(&self.publisher, channel, || self.wait_for_work());
        if outcome.is_err() {
            self.publisher.close();
        }
        outcome
    }

    /// Closes publication and wakes a publisher parked for work so [`run`]
    /// returns.
    ///
    /// A publisher already inside a blocking send is not woken by this; the
    /// notification transport ends that send when the association fails or its
    /// peer closes.
    ///
    /// [`run`]: Self::run
    pub fn close(&self) {
        self.publisher.close();
        self.signal();
    }

    fn signal(&self) {
        *self
            .signaled
            .lock()
            .expect("broker readiness publisher mutex poisoned") = true;
        self.work_available.notify_one();
    }

    fn wait_for_work(&self) {
        let mut signaled = self
            .signaled
            .lock()
            .expect("broker readiness publisher mutex poisoned");
        while !*signaled {
            signaled = self
                .work_available
                .wait(signaled)
                .expect("broker readiness publisher mutex poisoned");
        }
        *signaled = false;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::time::Duration;

    use litebox_broker_protocol::message::{BrokerNotification, ReadinessNotification};

    use super::*;

    const HANDLE: ObjectHandle = ObjectHandle(3);
    const OTHER_HANDLE: ObjectHandle = ObjectHandle(5);
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    struct RecordingChannel {
        sent: Sender<ReadinessNotification>,
    }

    impl HostNotificationChannel for RecordingChannel {
        type Error = &'static str;

        fn send_notification(
            &mut self,
            notification: &BrokerNotification,
        ) -> Result<(), Self::Error> {
            let BrokerNotification::Readiness(readiness) = notification;
            self.sent.send(*readiness).map_err(|_| "receiver dropped")
        }
    }

    /// Runs a publisher on its own thread and reports its result through a
    /// channel, so a publisher that never ends fails a test on the deadline
    /// instead of hanging its join.
    fn spawn_publisher(
        runtime: &Arc<ReadinessPublisherRuntime>,
        sent: Sender<ReadinessNotification>,
    ) -> Receiver<Result<(), &'static str>> {
        let publishing = Arc::clone(runtime);
        let (finished, finish) = channel();
        std::thread::spawn(move || {
            let mut channel = RecordingChannel { sent };
            let _ = finished.send(publishing.run(&mut channel));
        });
        finish
    }

    fn expect_publication_ended(finish: &Receiver<Result<(), &'static str>>) {
        finish
            .recv_timeout(TEST_TIMEOUT)
            .expect("publication must end")
            .expect("publication must end without a channel error");
    }

    #[test]
    fn a_parked_publisher_wakes_for_a_later_readiness_update() {
        let runtime = Arc::new(ReadinessPublisherRuntime::new());
        let (sent, received) = channel();
        let finish = spawn_publisher(&runtime, sent);

        // The publisher parks first, so this update must wake it.
        std::thread::sleep(Duration::from_millis(20));
        runtime.publish(HANDLE, ReadinessFlags::READ).unwrap();

        assert_eq!(
            received.recv_timeout(TEST_TIMEOUT).unwrap(),
            ReadinessNotification {
                handle: HANDLE,
                readiness: ReadinessFlags::READ,
            }
        );
        runtime.close();
        expect_publication_ended(&finish);
    }

    use litebox_broker_host::readiness::MAX_TRACKED_READINESS_OBJECTS;

    struct FailingChannel;

    impl HostNotificationChannel for FailingChannel {
        type Error = &'static str;

        fn send_notification(
            &mut self,
            _notification: &BrokerNotification,
        ) -> Result<(), Self::Error> {
            Err("notification channel failed")
        }
    }

    #[test]
    fn a_failed_publication_closes_the_runtime() {
        let runtime = ReadinessPublisherRuntime::new();
        runtime.publish(HANDLE, ReadinessFlags::READ).unwrap();

        runtime.run(&mut FailingChannel).unwrap_err();

        // Publication cannot run again, so a closed runtime must discard later
        // updates rather than let sources fill tracking state to its limit.
        for handle in 0..=MAX_TRACKED_READINESS_OBJECTS as u64 {
            runtime
                .publish(ObjectHandle(handle), ReadinessFlags::READ)
                .unwrap();
        }
    }

    #[test]
    #[should_panic(expected = "exactly once")]
    fn publication_runs_at_most_once() {
        let runtime = ReadinessPublisherRuntime::new();
        let (sent, _received) = channel();
        let mut channel = RecordingChannel { sent };

        // Closure is terminal, so the first run returns at once and the second
        // would otherwise park on a wake that can never come.
        runtime.close();
        runtime.run(&mut channel).unwrap();

        let _ = runtime.run(&mut channel);
    }

    #[test]
    fn closing_wakes_a_publisher_waiting_for_work() {
        let runtime = Arc::new(ReadinessPublisherRuntime::new());
        let waiting = Arc::clone(&runtime);
        let (wake_sender, wakes) = channel();
        std::thread::spawn(move || {
            waiting.wait_for_work();
            let _ = wake_sender.send(());
        });

        // The latch is sticky, so this must end the wait whether it lands
        // before the waiter parks or after it, which is why the test needs no
        // rendezvous with a park it cannot observe.
        runtime.close();

        wakes
            .recv_timeout(TEST_TIMEOUT)
            .expect("closing must end a wait for work");
    }

    #[test]
    fn retired_objects_stop_being_published() {
        let runtime = Arc::new(ReadinessPublisherRuntime::new());
        let (sent, received) = channel();

        // The retired handle is queued ahead of the surviving one, so it would
        // arrive first if retirement had not dropped its queued update. The
        // publisher starts only once both calls have run, which keeps it from
        // draining the queue before retirement.
        runtime.publish(HANDLE, ReadinessFlags::READ).unwrap();
        runtime.retire(HANDLE);
        runtime.publish(OTHER_HANDLE, ReadinessFlags::READ).unwrap();

        let finish = spawn_publisher(&runtime, sent);

        assert_eq!(
            received.recv_timeout(TEST_TIMEOUT).unwrap(),
            ReadinessNotification {
                handle: OTHER_HANDLE,
                readiness: ReadinessFlags::READ,
            },
            "a retired object must not be published"
        );
        runtime.close();
        expect_publication_ended(&finish);
        assert!(received.try_iter().next().is_none());
    }
}
