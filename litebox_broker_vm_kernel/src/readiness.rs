// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An association's readiness, published to its (pinned) notification ring
//! at once, whichever process is current. What a full ring cannot take
//! stays pending until the next [`KernelReadiness::flush`].

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
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
    /// end (see `Association::set_notification_waiter`).
    waiting: AtomicBool,
    /// The broker's: set when a waiting process's ring changes.
    woken: Arc<AtomicBool>,
}

impl KernelReadiness {
    pub(crate) fn new(woken: Arc<AtomicBool>) -> Self {
        Self {
            publisher: ReadinessPublisher::default(),
            notifications: SpinMutex::new(None),
            failed: AtomicBool::new(false),
            published: AtomicBool::new(false),
            waiting: AtomicBool::new(false),
            woken,
        }
    }

    /// Whether a thread of the process blocks in a wait that a notification
    /// would end, for a write to its ring to set the broker's `woken`.
    pub(crate) fn set_waiting(&self, waiting: bool) {
        self.waiting.store(waiting, Ordering::Relaxed);
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
        if (ring.written || matches!(result, Err(RingError::Ring(_))))
            && self.waiting.load(Ordering::Relaxed)
        {
            self.woken.store(true, Ordering::Relaxed);
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
