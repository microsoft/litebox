// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An association's readiness, published to its (pinned) notification ring
//! at once, whichever process is current. What a full ring cannot take
//! stays pending until the next [`KernelReadiness::flush`].

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

#[derive(Default)]
pub(crate) struct KernelReadiness {
    publisher: ReadinessPublisher,
    /// Until the handshake and after the association ends: `None`.
    notifications: SpinMutex<Option<Producer>>,
}

impl KernelReadiness {
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
        match publish_pending_readiness(&self.publisher, &mut Ring(producer)) {
            Ok(()) | Err(RingError::Full) => {}
            Err(RingError::Ring(error)) => {
                // The process corrupted its ring; its next broker entry fails
                // the association.
                log::warn!("broker notification ring failed: {error:?}");
                *notifications = None;
                self.publisher.close();
            }
        }
    }
}

enum RingError {
    Full,
    Ring(ControlRingError),
}

/// Never blocks: a full ring fails the send.
struct Ring<'a>(&'a mut Producer);

impl HostNotificationChannel for Ring<'_> {
    type Error = RingError;

    fn send_notification(
        &mut self,
        notification: &BrokerNotification,
    ) -> core::result::Result<(), RingError> {
        let frame = wire::encode_notification(notification.clone());
        match self.0.try_write(&frame).map_err(RingError::Ring)? {
            ControlRingWriteStatus::Written => Ok(()),
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
