// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local (LiteBox-side) endpoints of an active control-ring association.

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::vec::Vec;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use litebox_broker_protocol::message::{BrokerNotification, BrokerRequest, BrokerResponse};
use litebox_broker_protocol::wire::{decode_notification, decode_response, encode_request};

use super::{AssociationStream, read_ready_token, ring_error, single_lane_layout, wire_error};
use crate::call_lane_pool::{LaneClaim, LocalCallLanePool, copy_error};
use crate::channel::{LocalCallChannel, LocalNotificationChannel};
use crate::control_ring::{
    ControlRing, ControlRingConsumer, ControlRingReadError, ControlRingReadStatus,
    ControlRingWakeHandle, ControlRingWriteStatus, LocalControlRingEndpoints, LocalControlRingLane,
    LocalLaneDemand, WaitableSharedMemory,
};
use crate::shared_memory::ControlRingMemory;

/// Call-issuing endpoint of an active local control-ring association.
///
/// Dropping it ends the association as a local close.
pub struct ControlRingLocalCallChannel<Memory: WaitableSharedMemory<Error = Error>> {
    association: Arc<LocalAssociation<Memory>>,
}

/// Local notification receiver of an active control-ring association.
pub struct ControlRingLocalNotificationChannel<Memory: ControlRingMemory> {
    consumer: ControlRingConsumer<Memory>,
    association: Arc<LocalAssociation<Memory>>,
}

/// Independently owned handle for interrupting all local active-ring I/O.
pub struct ControlRingLocalShutdown<Memory: ControlRingMemory> {
    association: Arc<LocalAssociation<Memory>>,
}

/// State shared by every activated local endpoint of one association: the
/// call lanes and their demand, the setup stream used for liveness and
/// teardown, and the wake handles of every ring wait.
struct LocalAssociation<Memory: ControlRingMemory> {
    /// The call lanes, which also record the failure that ended the
    /// association.
    lanes: LocalCallLanePool<LocalControlRingLane<Memory>>,
    lane_demand: LocalLaneDemand<Memory>,
    stream: Box<dyn AssociationStream>,
    /// Whether the call channel was dropped, which ends the association as a
    /// local close rather than a failure.
    closed: AtomicBool,
    on_failure: Box<dyn Fn() + Send + Sync>,
    wakes: Vec<ControlRingWakeHandle<Memory>>,
}

/// The call channel, notification receiver, and shutdown handle of an
/// activated local association.
type LocalEndpoints<Memory> = (
    ControlRingLocalCallChannel<Memory>,
    ControlRingLocalNotificationChannel<Memory>,
    ControlRingLocalShutdown<Memory>,
);

/// Activates the local endpoints of a negotiated association over `ring`,
/// retaining its setup `stream` for liveness and teardown.
///
/// Exchanges the ring layout's ready token with the broker over `stream`, then
/// starts a thread that fails the association once the stream ends. The
/// association calls `on_failure` once, when it first fails or closes. The
/// ring must have a layout of more than one lane.
pub fn activate_local<Memory: WaitableSharedMemory<Error = Error>>(
    ring: ControlRing<Memory>,
    mut stream: Box<dyn AssociationStream>,
    on_failure: impl Fn() + Send + Sync + 'static,
) -> Result<LocalEndpoints<Memory>, Error> {
    let ready_token = ring.layout().ready_token();
    let endpoints = ring.into_local();
    let wakes = endpoints.wake_handles();
    let LocalControlRingEndpoints {
        lanes,
        lane_demand: Some(lane_demand),
        notification_consumer,
    } = endpoints
    else {
        return Err(single_lane_layout());
    };
    stream.write_frame(ready_token)?;
    read_ready_token(&mut *stream, ready_token, "broker")?;

    let association = Arc::new(LocalAssociation {
        lanes: LocalCallLanePool::new(lanes),
        lane_demand,
        stream,
        closed: AtomicBool::new(false),
        on_failure: Box::new(on_failure),
        wakes,
    });
    let monitor_association = Arc::clone(&association);
    let (started, wait_for_start) = std::sync::mpsc::sync_channel(1);
    if let Err(error) = thread::Builder::new()
        .name("litebox-broker-liveness".to_owned())
        .spawn(move || {
            let _ = started.send(());
            monitor_association.monitor();
        })
    {
        let _ = association.fail(error);
        return Err(Error::other("failed to start broker liveness monitor"));
    }
    // Wait until the monitor runs, past the runtime's own thread startup, which holds a
    // process-wide lock. A runner may clone itself as soon as this returns, and a clone that
    // inherited that lock held could never start a thread.
    let _ = wait_for_start.recv();

    Ok((
        ControlRingLocalCallChannel {
            association: Arc::clone(&association),
        },
        ControlRingLocalNotificationChannel {
            consumer: notification_consumer,
            association: Arc::clone(&association),
        },
        ControlRingLocalShutdown { association },
    ))
}

impl<Memory: WaitableSharedMemory<Error = Error>> ControlRingLocalShutdown<Memory> {
    /// Shuts down the active association, unblocking ring and stream waits.
    pub fn shutdown(&self) -> Result<(), Error> {
        self.association.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker local association shut down",
        ))
    }
}

impl<Memory: WaitableSharedMemory<Error = Error>> Drop for ControlRingLocalCallChannel<Memory> {
    fn drop(&mut self) {
        self.association.closed.store(true, Ordering::Release);
        let _ = self.association.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker local call channel dropped",
        ));
    }
}

impl<Memory: WaitableSharedMemory<Error = Error>> LocalCallChannel
    for ControlRingLocalCallChannel<Memory>
{
    type Error = Error;

    fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Error> {
        let association = &self.association;
        let mut lane = match association
            .lanes
            .claim(|lanes| association.demand_lanes(lanes))
        {
            Ok(lane) => lane,
            Err(error) => return Err(association.fail_and_report(error)),
        };
        let result = association.call_on_lane(&mut lane, request);
        // A failed call can leave its lane mid-exchange: fail the association
        // before freeing the lane, so no other call uses it.
        if let Err(error) = &result {
            let _ = association.fail(copy_error(error));
        }
        drop(lane);
        result
    }
}

impl<Memory: WaitableSharedMemory<Error = Error>> LocalNotificationChannel
    for ControlRingLocalNotificationChannel<Memory>
{
    type Error = Error;

    fn recv_notification(&mut self) -> Result<Option<BrokerNotification>, Error> {
        loop {
            if let Some(error) = self.association.lanes.current_failure() {
                return self.association.end_notifications(error);
            }
            match self.consumer.try_read(decode_notification) {
                Ok(ControlRingReadStatus::Message(notification)) => {
                    if let Err(error) = self
                        .association
                        .acknowledge_notification(&mut self.consumer)
                    {
                        return self.association.end_notifications(error);
                    }
                    return Ok(Some(notification));
                }
                Ok(ControlRingReadStatus::Empty { wake_count }) => {
                    if let Some(error) = self.association.lanes.current_failure() {
                        return self.association.end_notifications(error);
                    }
                    if let Err(error) = self.consumer.wait_for_message(wake_count) {
                        return Err(self.association.fail_and_report(error));
                    }
                }
                Err(ControlRingReadError::Ring(error)) => {
                    return Err(self.association.fail_and_report(ring_error(error)));
                }
                Err(ControlRingReadError::Decode(error)) => {
                    return Err(self.association.fail_and_report(wire_error(error)));
                }
            }
        }
    }
}

impl<Memory: WaitableSharedMemory<Error = Error>> LocalAssociation<Memory> {
    /// Waits for the setup stream to end, then fails the association.
    ///
    /// A stream ended by [`fail`](Self::fail) leaves the recorded failure.
    fn monitor(&self) {
        let error = match self.stream.wait_for_close() {
            Ok(()) => Error::new(
                ErrorKind::UnexpectedEof,
                "broker closed the active association",
            ),
            Err(error) => error,
        };
        let _ = self.fail(error);
    }

    /// Ends notification receipt once the association has ended with
    /// `failure`: cleanly if the local side closed it.
    fn end_notifications(&self, failure: Error) -> Result<Option<BrokerNotification>, Error> {
        if self.closed.load(Ordering::Acquire) {
            Ok(None)
        } else {
            Err(failure)
        }
    }

    fn acknowledge_notification(
        &self,
        consumer: &mut ControlRingConsumer<Memory>,
    ) -> Result<(), Error> {
        self.lanes
            .run_if_live(|| {
                consumer
                    .publish_head()
                    .map_err(ring_error)
                    .and_then(|()| consumer.wake_producer())
            })
            .map_err(|error| self.fail_and_report(error))
    }

    /// Raises the lane demand to `lanes` and wakes the broker to serve them.
    fn demand_lanes(&self, lanes: usize) -> Result<(), Error> {
        self.lane_demand.request(lanes).map_err(ring_error)?;
        self.lane_demand.wake_host()
    }

    /// Writes `request` to `lane` and reads the broker's response from it,
    /// releasing the lane once the call succeeds.
    fn call_on_lane(
        &self,
        lane: &mut LaneClaim<'_, LocalControlRingLane<Memory>>,
        request: BrokerRequest,
    ) -> Result<BrokerResponse, Error> {
        let request_id = request.request_id;
        let request_frame = encode_request(request);
        let producer = &mut lane.request_producer;
        loop {
            let write_status = self
                .lanes
                .run_if_live(|| producer.try_write(&request_frame).map_err(ring_error))?;
            match write_status {
                ControlRingWriteStatus::Written => break,
                ControlRingWriteStatus::Full { wake_count } => {
                    producer.wait_for_capacity(wake_count)?;
                }
            }
        }
        producer.wake_consumer()?;

        let consumer = &mut lane.response_consumer;
        let response = loop {
            match consumer.try_read(decode_response) {
                Ok(ControlRingReadStatus::Message(response)) => break response,
                Ok(ControlRingReadStatus::Empty { wake_count }) => {
                    if let Some(error) = self.lanes.current_failure() {
                        return Err(error);
                    }
                    consumer.wait_for_message(wake_count)?;
                }
                Err(ControlRingReadError::Ring(error)) => return Err(ring_error(error)),
                Err(ControlRingReadError::Decode(error)) => return Err(wire_error(error)),
            }
        };
        if response.request_id != request_id {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "broker answered a different request",
            ));
        }
        // Accepting the response with the lane's release excludes failure
        // recording, so no call succeeds once the association has failed.
        lane.release_if_live(|lane| {
            let consumer = &mut lane.response_consumer;
            consumer.publish_head().map_err(ring_error)?;
            consumer.wake_producer()
        })?;
        Ok(response)
    }

    fn fail(&self, error: Error) -> Result<(), Error> {
        let first_failure = self.lanes.record_failure(error);
        let wakes = self
            .wakes
            .iter()
            .map(ControlRingWakeHandle::interrupt_wait)
            .fold(Ok(()), Result::and);
        let shutdown_result = self.stream.shutdown();
        if first_failure {
            (self.on_failure)();
        }
        wakes.and(shutdown_result)
    }

    /// Fails the association with `error` and returns a copy of it to report.
    fn fail_and_report(&self, error: Error) -> Error {
        let report = copy_error(&error);
        let _ = self.fail(error);
        report
    }
}
