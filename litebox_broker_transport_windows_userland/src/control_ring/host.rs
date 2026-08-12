// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Error, ErrorKind, Result as IoResult};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use litebox_broker_protocol::message::{BrokerNotification, BrokerRequest, BrokerResponse};
use litebox_broker_protocol::wire::{
    WireError, decode_request, encode_notification, encode_response,
};
use litebox_broker_transport::channel::{HostNotificationChannel, HostReceive};
use litebox_broker_transport::control_ring::{
    CONTROL_RING_READY, ControlRing, ControlRingConsumer, ControlRingProducer,
    ControlRingReadError, ControlRingReadStatus, ControlRingWakeHandle, ControlRingWriteStatus,
};

use crate::named_pipe::WindowsNamedPipeStream;
use crate::setup::{
    copy_io_error, invalid_data, read_frame, read_pipe_until_cancelled, ring_error, wire_error,
    write_frame,
};
use crate::shared_memory::WindowsSharedMemory;

use super::{PipeLiveness, file_handle};

/// Request-reading endpoint of an active host control-ring association.
pub struct WindowsControlRingHostRequestSource {
    consumer: ControlRingConsumer<WindowsSharedMemory>,
    association: Arc<HostRingAssociation>,
}

/// Shared response-writing endpoint of an active host control-ring association.
#[derive(Clone)]
pub struct WindowsControlRingHostResponseSink {
    producer: Arc<Mutex<ControlRingProducer<WindowsSharedMemory>>>,
    association: Arc<HostRingAssociation>,
}

/// Host notification sender for a shared-ring Windows broker association.
pub struct WindowsControlRingHostNotificationChannel {
    producer: ControlRingProducer<WindowsSharedMemory>,
    association: Arc<HostRingAssociation>,
}

/// RAII guard that interrupts all active host ring I/O when dropped.
pub struct WindowsControlRingHostShutdown {
    association: Arc<HostRingAssociation>,
}

struct HostRingAssociation {
    status: Mutex<HostAssociationStatus>,
    liveness: PipeLiveness,
    request_wake: ControlRingWakeHandle<WindowsSharedMemory>,
    response_wake: ControlRingWakeHandle<WindowsSharedMemory>,
    notification_wake: ControlRingWakeHandle<WindowsSharedMemory>,
}

enum HostAssociationStatus {
    Live,
    PeerClosed,
    Failed(Arc<Error>),
}

pub(crate) fn activate_host(
    stream: WindowsNamedPipeStream,
    negotiated: bool,
    setup_deadline: Option<Instant>,
    ring: ControlRing<WindowsSharedMemory>,
) -> IoResult<(
    WindowsControlRingHostRequestSource,
    WindowsControlRingHostResponseSink,
    WindowsControlRingHostNotificationChannel,
    WindowsControlRingHostShutdown,
)> {
    if !negotiated {
        return Err(invalid_data(
            "broker host setup channel activated before negotiation completed",
        ));
    }
    let ready = read_frame(file_handle(&stream), setup_deadline)?.ok_or_else(|| {
        Error::new(
            ErrorKind::UnexpectedEof,
            "runner closed before control-ring setup acknowledgement",
        )
    })?;
    if ready != CONTROL_RING_READY {
        return Err(invalid_data(
            "runner sent an invalid control-ring setup acknowledgement",
        ));
    }
    write_frame(file_handle(&stream), CONTROL_RING_READY, setup_deadline)?;

    let litebox_broker_transport::control_ring::BrokerControlRingEndpoints {
        request_consumer,
        response_producer,
        notification_producer,
    } = ring.into_broker();
    let stream = Arc::new(stream);
    let association = Arc::new(HostRingAssociation {
        liveness: PipeLiveness::new(Arc::clone(&stream), true)?,
        status: Mutex::new(HostAssociationStatus::Live),
        request_wake: request_consumer.wake_handle(),
        response_wake: response_producer.wake_handle(),
        notification_wake: notification_producer.wake_handle(),
    });
    let monitor_association = Arc::clone(&association);
    thread::Builder::new()
        .name("litebox-runner-liveness".to_owned())
        .spawn(move || monitor_host_pipe(&stream, &monitor_association))?;
    Ok((
        WindowsControlRingHostRequestSource {
            consumer: request_consumer,
            association: Arc::clone(&association),
        },
        WindowsControlRingHostResponseSink {
            producer: Arc::new(Mutex::new(response_producer)),
            association: Arc::clone(&association),
        },
        WindowsControlRingHostNotificationChannel {
            producer: notification_producer,
            association: Arc::clone(&association),
        },
        WindowsControlRingHostShutdown { association },
    ))
}

impl WindowsControlRingHostShutdown {
    /// Shuts down the active association without waiting for a ring lock.
    pub fn shutdown(&self) -> IoResult<()> {
        self.association.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker host association shut down",
        ))
    }
}

impl Drop for WindowsControlRingHostShutdown {
    fn drop(&mut self) {
        let _ = self.association.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker host association shutdown guard dropped",
        ));
    }
}

impl WindowsControlRingHostRequestSource {
    /// Receives one active broker request.
    pub fn recv_request(&mut self) -> IoResult<HostReceive<BrokerRequest>> {
        loop {
            if let Some(error) = self.association.current_failure() {
                return Err(error);
            }
            match self.consumer.try_read(decode_request) {
                Ok(ControlRingReadStatus::Message(request)) => {
                    self.association.acknowledge_request(&mut self.consumer)?;
                    return Ok(HostReceive::Message(request));
                }
                Ok(ControlRingReadStatus::Empty { wait_epoch }) => {
                    if let Some(terminal) = self.association.request_terminal_result() {
                        return terminal;
                    }
                    if let Err(error) = self.consumer.wait_for_message(wait_epoch) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.association.fail(error);
                        return result;
                    }
                }
                Err(ControlRingReadError::Decode(WireError::WrongMessagePhase)) => {
                    return Ok(HostReceive::ProtocolViolation);
                }
                Err(ControlRingReadError::Decode(error)) => {
                    let error = wire_error(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.association.fail(error);
                    return result;
                }
                Err(ControlRingReadError::Ring(error)) => {
                    let error = ring_error(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.association.fail(error);
                    return result;
                }
            }
        }
    }
}

impl WindowsControlRingHostResponseSink {
    /// Serializes and sends one complete active broker response.
    pub fn send_response(&self, response: &BrokerResponse) -> IoResult<()> {
        let frame = encode_response(response.clone());
        let mut producer = self
            .producer
            .lock()
            .map_err(|_| Error::other("broker response writer mutex poisoned"))?;
        loop {
            match self.association.try_publish(&mut producer, &frame)? {
                ControlRingWriteStatus::Written => return Ok(()),
                ControlRingWriteStatus::Full { wait_epoch } => {
                    if let Err(error) = producer.wait_for_capacity(wait_epoch) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.association.fail(error);
                        return result;
                    }
                }
            }
        }
    }
}

impl HostNotificationChannel for WindowsControlRingHostNotificationChannel {
    type Error = Error;

    fn send_notification(&mut self, notification: &BrokerNotification) -> IoResult<()> {
        let frame = encode_notification(notification.clone());
        loop {
            match self.association.try_publish(&mut self.producer, &frame)? {
                ControlRingWriteStatus::Written => return Ok(()),
                ControlRingWriteStatus::Full { wait_epoch } => {
                    if let Err(error) = self.producer.wait_for_capacity(wait_epoch) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.association.fail(error);
                        return result;
                    }
                }
            }
        }
    }
}

impl HostRingAssociation {
    fn acknowledge_request(
        &self,
        consumer: &mut ControlRingConsumer<WindowsSharedMemory>,
    ) -> IoResult<()> {
        let result = {
            let status = self
                .status
                .lock()
                .expect("broker host association mutex poisoned");
            if let HostAssociationStatus::Failed(error) = &*status {
                return Err(copy_io_error(error));
            }
            consumer
                .publish_head()
                .map_err(ring_error)
                .and_then(|()| consumer.wake_producer())
        };
        if let Err(error) = result {
            let result = Err(copy_io_error(&error));
            let _ = self.fail(error);
            return result;
        }
        Ok(())
    }

    fn fail(&self, error: Error) -> IoResult<()> {
        {
            let mut status = self
                .status
                .lock()
                .expect("broker host association mutex poisoned");
            if matches!(*status, HostAssociationStatus::Live) {
                *status = HostAssociationStatus::Failed(Arc::new(error));
            }
        }
        self.interrupt_waits().and(self.liveness.shutdown())
    }

    fn peer_closed(&self) {
        {
            let mut status = self
                .status
                .lock()
                .expect("broker host association mutex poisoned");
            if matches!(*status, HostAssociationStatus::Live) {
                *status = HostAssociationStatus::PeerClosed;
            }
        }
        let _ = self.interrupt_waits();
        self.liveness.peer_closed();
    }

    fn interrupt_waits(&self) -> IoResult<()> {
        self.request_wake
            .interrupt_wait()
            .and(self.response_wake.interrupt_wait())
            .and(self.notification_wake.interrupt_wait())
    }

    fn request_terminal_result(&self) -> Option<IoResult<HostReceive<BrokerRequest>>> {
        match &*self
            .status
            .lock()
            .expect("broker host association mutex poisoned")
        {
            HostAssociationStatus::Live => None,
            HostAssociationStatus::PeerClosed => Some(Ok(HostReceive::PeerClosed)),
            HostAssociationStatus::Failed(error) => Some(Err(copy_io_error(error))),
        }
    }

    fn current_failure(&self) -> Option<Error> {
        match &*self
            .status
            .lock()
            .expect("broker host association mutex poisoned")
        {
            HostAssociationStatus::Failed(error) => Some(copy_io_error(error)),
            HostAssociationStatus::Live | HostAssociationStatus::PeerClosed => None,
        }
    }

    fn try_publish(
        &self,
        producer: &mut ControlRingProducer<WindowsSharedMemory>,
        frame: &[u8],
    ) -> IoResult<ControlRingWriteStatus> {
        let result = {
            let status = self
                .status
                .lock()
                .expect("broker host association mutex poisoned");
            match &*status {
                HostAssociationStatus::Live => {}
                HostAssociationStatus::PeerClosed => {
                    return Err(Error::new(
                        ErrorKind::BrokenPipe,
                        "runner closed the active broker association",
                    ));
                }
                HostAssociationStatus::Failed(error) => return Err(copy_io_error(error)),
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
        if let Err(error) = result {
            let result = Err(copy_io_error(&error));
            let _ = self.fail(error);
            return result;
        }
        result
    }
}

fn monitor_host_pipe(stream: &WindowsNamedPipeStream, association: &HostRingAssociation) {
    let mut byte = [0];
    match read_pipe_until_cancelled(
        file_handle(stream),
        &mut byte,
        association.liveness.shutdown_event.handle(),
    ) {
        Ok(0) => association.peer_closed(),
        Ok(_) => {
            let _ = association.fail(invalid_data(
                "runner sent unexpected active control-pipe data",
            ));
        }
        Err(error) if error.kind() == ErrorKind::ConnectionAborted => {}
        Err(error) => {
            let _ = association.fail(error);
        }
    }
}
