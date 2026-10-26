// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host (broker-side) endpoints of an active control-ring association.

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::vec::Vec;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;

use litebox_broker_protocol::message::{BrokerNotification, BrokerRequest, BrokerResponse};
use litebox_broker_protocol::wire::{
    WireError, decode_request, encode_notification, encode_response,
};

use super::{AssociationStream, read_ready_token, ring_error, single_lane_layout, wire_error};
use crate::call_lane_pool::copy_error;
use crate::channel::{
    HostAssociationShutdown, HostCallLane, HostCallLaneSource, HostNotificationChannel, HostReceive,
};
use crate::control_ring::{
    ControlRing, ControlRingConsumer, ControlRingDemandStatus, ControlRingProducer,
    ControlRingReadError, ControlRingReadStatus, ControlRingWakeHandle, ControlRingWriteStatus,
    HostControlRingEndpoints, HostControlRingLane, HostLaneDemand, WaitableSharedMemory,
};
use crate::shared_memory::ControlRingMemory;

/// Source of the call lanes of an active host control-ring association, which
/// hands out each lane once the runner starts using it.
pub struct ControlRingHostCallLaneSource<Memory: ControlRingMemory> {
    /// Each lane, or `None` once handed out.
    lanes: Vec<Option<HostControlRingLane<Memory>>>,
    demand: HostLaneDemand<Memory>,
    association: Arc<HostAssociation<Memory>>,
}

/// One call lane of an active host control-ring association.
pub struct ControlRingHostCallLane<Memory: ControlRingMemory> {
    pub(super) lane: HostControlRingLane<Memory>,
    pub(super) association: Arc<HostAssociation<Memory>>,
}

/// Host notification sender of an active control-ring association.
pub struct ControlRingHostNotificationChannel<Memory: ControlRingMemory> {
    producer: ControlRingProducer<Memory>,
    association: Arc<HostAssociation<Memory>>,
}

/// RAII guard that interrupts all active host ring I/O when dropped.
pub struct ControlRingHostShutdown<Memory: WaitableSharedMemory<Error = Error>> {
    association: Arc<HostAssociation<Memory>>,
}

/// State shared by every activated host endpoint of one association: the setup
/// stream used for liveness and teardown, terminal status, and the wake
/// handles of every ring wait.
pub(super) struct HostAssociation<Memory: ControlRingMemory> {
    stream: Box<dyn AssociationStream>,
    status: Mutex<HostAssociationStatus>,
    wakes: Vec<ControlRingWakeHandle<Memory>>,
}

enum HostAssociationStatus {
    Live,
    PeerClosed,
    Failed(Arc<Error>),
}

/// The call-lane source, notification sender, and shutdown guard of an
/// activated host association.
type HostEndpoints<Memory> = (
    ControlRingHostCallLaneSource<Memory>,
    ControlRingHostNotificationChannel<Memory>,
    ControlRingHostShutdown<Memory>,
);

/// Activates the host endpoints of a negotiated association over `ring`,
/// retaining its setup `stream` for liveness and teardown.
///
/// Exchanges the ring layout's ready token with the runner over `stream`, then
/// starts a thread that ends the association once the stream ends. The ring
/// must have a layout of more than one lane.
pub fn activate_host<Memory: WaitableSharedMemory<Error = Error>>(
    ring: ControlRing<Memory>,
    mut stream: Box<dyn AssociationStream>,
) -> Result<HostEndpoints<Memory>, Error> {
    let ready_token = ring.layout().ready_token();
    let endpoints = ring.into_host();
    let wakes = endpoints.wake_handles();
    let HostControlRingEndpoints {
        lanes,
        lane_demand: Some(demand),
        notification_producer,
    } = endpoints
    else {
        return Err(single_lane_layout());
    };
    read_ready_token(&mut *stream, ready_token, "runner")?;
    stream.write_frame(ready_token)?;

    let association = Arc::new(HostAssociation {
        stream,
        status: Mutex::new(HostAssociationStatus::Live),
        wakes,
    });
    let monitor_association = Arc::clone(&association);
    thread::Builder::new()
        .name("litebox-runner-liveness".to_owned())
        .spawn(move || monitor_association.monitor())?;
    Ok((
        ControlRingHostCallLaneSource {
            lanes: lanes.into_iter().map(Some).collect(),
            demand,
            association: Arc::clone(&association),
        },
        ControlRingHostNotificationChannel {
            producer: notification_producer,
            association: Arc::clone(&association),
        },
        ControlRingHostShutdown { association },
    ))
}

impl<Memory: WaitableSharedMemory<Error = Error>> ControlRingHostShutdown<Memory> {
    /// Shuts down the active association without waiting for a ring lock.
    pub fn shutdown(&self) -> Result<(), Error> {
        self.association.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker host association shut down",
        ))
    }
}

impl<Memory: WaitableSharedMemory<Error = Error>> HostAssociationShutdown
    for ControlRingHostShutdown<Memory>
{
    type Error = Error;

    fn shutdown(&self) -> Result<(), Error> {
        Self::shutdown(self)
    }
}

impl<Memory: WaitableSharedMemory<Error = Error>> Drop for ControlRingHostShutdown<Memory> {
    fn drop(&mut self) {
        let _ = self.association.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker host association shutdown guard dropped",
        ));
    }
}

impl<Memory: WaitableSharedMemory<Error = Error>> ControlRingHostCallLaneSource<Memory> {
    /// Blocks until the runner starts using another lane and returns it.
    ///
    /// Once every lane is handed out, this blocks until the association ends.
    /// Returns `Ok(None)` once the runner closed the association.
    ///
    /// # Panics
    ///
    /// Panics if the lane demand hands out a lane more than once.
    pub fn next_lane(&mut self) -> Result<Option<ControlRingHostCallLane<Memory>>, Error> {
        loop {
            if let Some(ended) = self.association.ended() {
                return ended.map(|()| None);
            }
            match self.demand.try_next_lane() {
                Ok(ControlRingDemandStatus::Lane(index)) => {
                    let lane = self.lanes[index]
                        .take()
                        .expect("lane demand hands out each lane once");
                    return Ok(Some(ControlRingHostCallLane {
                        lane,
                        association: Arc::clone(&self.association),
                    }));
                }
                Ok(ControlRingDemandStatus::Satisfied { wake_count }) => {
                    if let Some(ended) = self.association.ended() {
                        return ended.map(|()| None);
                    }
                    if let Err(error) = self.demand.wait_for_demand(wake_count) {
                        return Err(self.association.fail_and_report(error));
                    }
                }
                Err(error) => return Err(self.association.fail_and_report(ring_error(error))),
            }
        }
    }
}

impl<Memory: WaitableSharedMemory<Error = Error>> HostCallLaneSource
    for ControlRingHostCallLaneSource<Memory>
{
    type Error = Error;
    type Lane = ControlRingHostCallLane<Memory>;

    fn next_lane(&mut self) -> Result<Option<ControlRingHostCallLane<Memory>>, Error> {
        Self::next_lane(self)
    }
}

impl<Memory: WaitableSharedMemory<Error = Error>> ControlRingHostCallLane<Memory> {
    /// Receives this lane's next broker request.
    pub fn recv_request(&mut self) -> Result<HostReceive<BrokerRequest>, Error> {
        let consumer = &mut self.lane.request_consumer;
        loop {
            if let Some(error) = self.association.current_failure() {
                return Err(error);
            }
            match consumer.try_read(decode_request) {
                Ok(ControlRingReadStatus::Message(request)) => {
                    self.association.acknowledge_request(consumer)?;
                    return Ok(HostReceive::Message(request));
                }
                Ok(ControlRingReadStatus::Empty { wake_count }) => {
                    if let Some(ended) = self.association.ended() {
                        return ended.map(|()| HostReceive::PeerClosed);
                    }
                    if let Err(error) = consumer.wait_for_message(wake_count) {
                        return Err(self.association.fail_and_report(error));
                    }
                }
                Err(ControlRingReadError::Decode(WireError::WrongMessagePhase)) => {
                    return Ok(HostReceive::ProtocolViolation);
                }
                Err(ControlRingReadError::Decode(error)) => {
                    return Err(self.association.fail_and_report(wire_error(error)));
                }
                Err(ControlRingReadError::Ring(error)) => {
                    return Err(self.association.fail_and_report(ring_error(error)));
                }
            }
        }
    }

    /// Serializes and sends the response to this lane's last request.
    pub fn send_response(&mut self, response: &BrokerResponse) -> Result<(), Error> {
        let frame = encode_response(response.clone());
        self.association
            .publish(&mut self.lane.response_producer, &frame)
    }
}

impl<Memory: WaitableSharedMemory<Error = Error>> HostCallLane for ControlRingHostCallLane<Memory> {
    type Error = Error;

    fn recv_request(&mut self) -> Result<HostReceive<BrokerRequest>, Error> {
        Self::recv_request(self)
    }

    fn send_response(&mut self, response: &BrokerResponse) -> Result<(), Error> {
        Self::send_response(self, response)
    }
}

impl<Memory: WaitableSharedMemory<Error = Error>> HostNotificationChannel
    for ControlRingHostNotificationChannel<Memory>
{
    type Error = Error;

    fn send_notification(&mut self, notification: &BrokerNotification) -> Result<(), Error> {
        let frame = encode_notification(notification.clone());
        self.association.publish(&mut self.producer, &frame)
    }
}

impl<Memory: WaitableSharedMemory<Error = Error>> HostAssociation<Memory> {
    /// Waits for the setup stream to end, then ends the association: as
    /// closed by the runner if the stream closed, or as failed if it failed.
    ///
    /// A stream ended by [`fail`](Self::fail) leaves the recorded failure.
    fn monitor(&self) {
        match self.stream.wait_for_close() {
            Ok(()) => self.peer_closed(),
            Err(error) => {
                let _ = self.fail(error);
            }
        }
    }

    pub(super) fn acknowledge_request(
        &self,
        consumer: &mut ControlRingConsumer<Memory>,
    ) -> Result<(), Error> {
        let result = {
            let status = self.status();
            if let HostAssociationStatus::Failed(error) = &*status {
                return Err(copy_error(error));
            }
            consumer
                .publish_head()
                .map_err(ring_error)
                .and_then(|()| consumer.wake_producer())
        };
        result.map_err(|error| self.fail_and_report(error))
    }

    pub(super) fn fail(&self, error: Error) -> Result<(), Error> {
        {
            let mut status = self.status();
            if matches!(*status, HostAssociationStatus::Live) {
                *status = HostAssociationStatus::Failed(Arc::new(error));
            }
        }
        self.wakes
            .iter()
            .map(ControlRingWakeHandle::interrupt_wait)
            .fold(Ok(()), Result::and)
            .and(self.stream.shutdown())
    }

    /// Fails the association with `error` and returns a copy of it to report.
    fn fail_and_report(&self, error: Error) -> Error {
        let report = copy_error(&error);
        let _ = self.fail(error);
        report
    }

    pub(super) fn peer_closed(&self) {
        {
            let mut status = self.status();
            if matches!(*status, HostAssociationStatus::Live) {
                *status = HostAssociationStatus::PeerClosed;
            }
        }
        for wake in &self.wakes {
            let _ = wake.interrupt_wait();
        }
    }

    /// Returns how the association ended, if it has: `Ok` if the runner
    /// closed it.
    fn ended(&self) -> Option<Result<(), Error>> {
        match &*self.status() {
            HostAssociationStatus::Live => None,
            HostAssociationStatus::PeerClosed => Some(Ok(())),
            HostAssociationStatus::Failed(error) => Some(Err(copy_error(error))),
        }
    }

    fn current_failure(&self) -> Option<Error> {
        match &*self.status() {
            HostAssociationStatus::Failed(error) => Some(copy_error(error)),
            HostAssociationStatus::Live | HostAssociationStatus::PeerClosed => None,
        }
    }

    /// Writes `frame` to `producer`, waiting while the ring is full.
    fn publish(
        &self,
        producer: &mut ControlRingProducer<Memory>,
        frame: &[u8],
    ) -> Result<(), Error> {
        loop {
            match self.try_publish(producer, frame)? {
                ControlRingWriteStatus::Written => return Ok(()),
                ControlRingWriteStatus::Full { wake_count } => {
                    if let Err(error) = producer.wait_for_capacity(wake_count) {
                        return Err(self.fail_and_report(error));
                    }
                }
            }
        }
    }

    fn try_publish(
        &self,
        producer: &mut ControlRingProducer<Memory>,
        frame: &[u8],
    ) -> Result<ControlRingWriteStatus, Error> {
        let result = {
            let status = self.status();
            match &*status {
                HostAssociationStatus::Live => {}
                HostAssociationStatus::PeerClosed => {
                    return Err(Error::new(
                        ErrorKind::BrokenPipe,
                        "runner closed the active broker association",
                    ));
                }
                HostAssociationStatus::Failed(error) => return Err(copy_error(error)),
            }
            producer
                .try_write(frame)
                .map_err(ring_error)
                .and_then(|write_status| {
                    if matches!(write_status, ControlRingWriteStatus::Written) {
                        producer.wake_consumer()?;
                    }
                    Ok(write_status)
                })
        };
        result.map_err(|error| self.fail_and_report(error))
    }

    fn status(&self) -> MutexGuard<'_, HostAssociationStatus> {
        self.status
            .lock()
            .expect("broker host association mutex poisoned")
    }
}
