// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An association's readiness, published to its (pinned) notification ring
//! at once, whichever process is current. What a full ring cannot take
//! stays pending until the next [`KernelReadiness::flush`].

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering, fence};
use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_core::{BrokerError, Result};
use litebox_broker_host::readiness::{
    MAX_TRACKED_READINESS_OBJECTS, ReadinessPublisher, publish_pending_readiness,
};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::message::BrokerNotification;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::wire;
use litebox_broker_transport::channel::HostNotificationChannel;
use litebox_broker_transport::control_ring::{
    ControlRingError, ControlRingProducer, ControlRingWriteStatus,
};
use litebox_platform_vm_kernel::cpu;
use spin::mutex::SpinMutex;

use crate::memory::PinnedControlRing;

type Producer = ControlRingProducer<PinnedControlRing>;

pub(crate) struct KernelReadiness {
    publisher: ReadinessPublisher,
    /// Until the handshake and after the association ends: `None`.
    notifications: SpinMutex<Option<Producer>>,
    /// The process corrupted its notification ring.
    failed: AtomicBool,
    /// A notification was written since [`Self::take_published`].
    published: AtomicBool,
    /// A thread of the process blocks in a wait that a notification would
    /// end (see `Association::set_notification_waiter`): a change to its ring
    /// notifies every CPU ([`cpu::notify_all`]).
    waiting: AtomicBool,
    /// How many console `WRITE` publications in progress wake the process; the
    /// others skip it.
    console_wakes: AtomicU32,
}

impl KernelReadiness {
    pub(crate) fn new() -> Self {
        Self {
            publisher: ReadinessPublisher::default(),
            notifications: SpinMutex::new(None),
            failed: AtomicBool::new(false),
            published: AtomicBool::new(false),
            waiting: AtomicBool::new(false),
            console_wakes: AtomicU32::new(0),
        }
    }

    /// A console `WRITE` publication that wakes the process starts (`true`)
    /// or ends.
    pub(crate) fn wake_for_console(&self, waking: bool) {
        if waking {
            self.console_wakes.fetch_add(1, Ordering::Relaxed);
        } else {
            self.console_wakes.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Whether a console `WRITE` publication in progress wakes the process.
    pub(crate) fn wakes_for_console(&self) -> bool {
        self.console_wakes.load(Ordering::Relaxed) != 0
    }

    /// Whether a republish of `readiness` is the console's `WRITE` publication
    /// (`publishing`, asked only for a `WRITE`), to a process it does not wake;
    /// a readiness queue's own `READ`, published inside it, is not.
    fn skips(&self, readiness: ReadinessFlags, publishing: impl FnOnce() -> bool) -> bool {
        readiness == ReadinessFlags::WRITE && publishing() && !self.wakes_for_console()
    }

    /// Whether a thread of the process blocks in a wait that a notification
    /// would end, for a write to its ring to notify every CPU. Ordered before
    /// the caller's reads of the ring (its poll of the wait), as
    /// [`Self::flush`] orders its writes before reading this: either the poll
    /// sees a write, or the write sees the waiter.
    pub(crate) fn set_waiting(&self, waiting: bool) {
        self.waiting.store(waiting, Ordering::SeqCst);
        fence(Ordering::SeqCst);
    }

    /// Starts publishing to the ring, including what is already pending.
    pub(crate) fn activate(&self, notifications: Producer) {
        *self.notifications.lock() = Some(notifications);
        self.flush();
    }

    /// Stops publishing, for good.
    pub(crate) fn close(&self) {
        self.publisher.close();
        *self.notifications.lock() = None;
    }

    /// Publishes what is pending, as far as the ring has room.
    pub(crate) fn flush(&self) {
        // Nothing publishes with this lock held: sending only writes the
        // ring, and interrupt handlers do not run sources.
        let mut notifications = self.notifications.lock();
        let Some(producer) = notifications.as_mut() else {
            return;
        };
        let mut ring = Ring {
            producer,
            written: false,
        };
        let result = publish_pending_readiness(&self.publisher, &mut ring);
        if ring.written {
            self.published.store(true, Ordering::Relaxed);
        }
        // See `set_waiting`.
        fence(Ordering::SeqCst);
        // For the CPUs to poll the waits again, wherever they run. (A process
        // with none, running on another CPU, sees `published` at its next
        // kernel entry.)
        if (ring.written || matches!(result, Err(RingError::Ring(_))))
            && self.waiting.load(Ordering::SeqCst)
        {
            cpu::notify_all();
        }
        match result {
            Ok(()) | Err(RingError::Full) => {}
            Err(RingError::Ring(error)) => {
                log::warn!("broker notification ring failed: {error:?}");
                *notifications = None;
                self.publisher.close();
                self.failed.store(true, Ordering::Relaxed);
            }
        }
    }

    /// Whether the process has yet to consume a notification written to its
    /// ring. Not on a ring it corrupted, which fails the association.
    pub(crate) fn unconsumed(&self) -> bool {
        self.notifications
            .lock()
            .as_ref()
            .is_some_and(|producer| producer.has_unconsumed().unwrap_or(false))
    }

    /// Whether a notification was written since the last call.
    pub(crate) fn take_published(&self) -> bool {
        self.published.swap(false, Ordering::Relaxed)
    }

    /// Whether the process corrupted its notification ring, which fails the
    /// association.
    pub(crate) fn failed(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }
}

enum RingError {
    Full,
    Ring(ControlRingError),
}

/// Never blocks: a full ring fails the send.
struct Ring<'a> {
    producer: &'a mut Producer,
    written: bool,
}

impl HostNotificationChannel for Ring<'_> {
    type Error = RingError;

    fn send_notification(
        &mut self,
        notification: &BrokerNotification,
    ) -> core::result::Result<(), RingError> {
        let frame = wire::encode_notification(notification.clone());
        match self.producer.try_write(&frame).map_err(RingError::Ring)? {
            ControlRingWriteStatus::Written => {
                self.written = true;
                Ok(())
            }
            ControlRingWriteStatus::Full { .. } => Err(RingError::Full),
        }
    }
}

impl ReadinessSink for KernelReadiness {
    fn max_tracked_objects(&self) -> usize {
        MAX_TRACKED_READINESS_OBJECTS
    }

    fn publish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
        self.publisher
            .publish(handle, readiness)
            .map_err(|_| BrokerError::ResourceExhausted)?;
        self.flush();
        Ok(())
    }

    fn republish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
        if self.skips(readiness, crate::serving::publishing_console) {
            return Ok(());
        }
        self.publisher
            .republish(handle, readiness)
            .map_err(|_| BrokerError::ResourceExhausted)?;
        self.flush();
        Ok(())
    }

    fn retire(&self, handle: ObjectHandle) {
        self.publisher.retire(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The console's publication skips a process it does not wake, and only
    /// that: not one it wakes, a `READ`, or another publication's `WRITE`.
    #[test]
    fn the_console_publication_skips_only_processes_it_does_not_wake() {
        let readiness = KernelReadiness::new();
        assert!(readiness.skips(ReadinessFlags::WRITE, || true), "unmarked");
        readiness.wake_for_console(true);
        assert!(!readiness.skips(ReadinessFlags::WRITE, || true), "marked");
        readiness.wake_for_console(false);
        assert!(!readiness.skips(ReadinessFlags::READ, || true), "a READ");
        assert!(
            !readiness.skips(ReadinessFlags::WRITE, || false),
            "not the console's"
        );
    }
}
