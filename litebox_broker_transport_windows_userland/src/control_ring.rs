// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Active Windows-userland broker endpoints over a shared control ring.

use std::io::{Error, ErrorKind, Result as IoResult};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use litebox_broker_protocol::message::{BrokerNotification, BrokerRequest, BrokerResponse};
use litebox_broker_protocol::wire::{
    WireError, decode_notification, decode_request, decode_response, encode_notification,
    encode_request, encode_response,
};
use litebox_broker_transport::channel::{
    HostNotificationChannel, HostReceive, LocalCallChannel, LocalNotificationChannel,
};
use litebox_broker_transport::control_ring::{
    CONTROL_RING_READY, ControlRing, ControlRingConsumer, ControlRingProducer,
    ControlRingReadError, ControlRingReadStatus, ControlRingWakeHandle, ControlRingWriteStatus,
};
use windows_sys::Win32::Foundation::ERROR_PIPE_NOT_CONNECTED;
use windows_sys::Win32::System::Pipes::DisconnectNamedPipe;

use crate::named_pipe::WindowsNamedPipeStream;
use crate::pending_calls::{PendingCalls, pending_calls_error};
use crate::setup::{
    OwnedEvent, copy_io_error, invalid_data, read_frame, read_pipe_until_cancelled, ring_error,
    wire_error, write_frame,
};
use crate::shared_memory::WindowsSharedMemory;

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

/// Call-issuing endpoint of an active local control-ring association.
pub struct WindowsControlRingLocalCallChannel {
    association: Arc<LocalRingAssociation>,
}

/// Local notification receiver for a shared-ring Windows broker association.
pub struct WindowsControlRingLocalNotificationChannel {
    consumer: ControlRingConsumer<WindowsSharedMemory>,
    association: Arc<LocalRingAssociation>,
}

struct LocalRingAssociation {
    request_producer: Mutex<ControlRingProducer<WindowsSharedMemory>>,
    pending_calls: Arc<PendingCalls>,
    liveness: PipeLiveness,
    request_wake: ControlRingWakeHandle<WindowsSharedMemory>,
    response_wake: ControlRingWakeHandle<WindowsSharedMemory>,
    notification_wake: ControlRingWakeHandle<WindowsSharedMemory>,
}

struct PipeLiveness {
    server: bool,
    shutdown_event: OwnedEvent,
    state: Mutex<PipeLivenessState>,
}

struct PipeLivenessState {
    stream: Option<Arc<WindowsNamedPipeStream>>,
    shutdown: bool,
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

pub(crate) fn activate_local(
    stream: WindowsNamedPipeStream,
    negotiated: bool,
    setup_deadline: Option<Instant>,
    ring: ControlRing<WindowsSharedMemory>,
) -> IoResult<(
    WindowsControlRingLocalCallChannel,
    WindowsControlRingLocalNotificationChannel,
)> {
    if !negotiated {
        return Err(invalid_data(
            "broker local setup channel activated before negotiation completed",
        ));
    }
    write_frame(file_handle(&stream), CONTROL_RING_READY, setup_deadline)?;
    let ready = read_frame(file_handle(&stream), setup_deadline)?.ok_or_else(|| {
        Error::new(
            ErrorKind::UnexpectedEof,
            "broker closed before control-ring setup acknowledgement",
        )
    })?;
    if ready != CONTROL_RING_READY {
        return Err(invalid_data(
            "broker sent an invalid control-ring setup acknowledgement",
        ));
    }

    let litebox_broker_transport::control_ring::LocalControlRingEndpoints {
        request_producer,
        response_consumer,
        notification_consumer,
    } = ring.into_local();
    let pending_calls = Arc::new(PendingCalls::new());
    let stream = Arc::new(stream);
    let association = Arc::new(LocalRingAssociation {
        liveness: PipeLiveness::new(Arc::clone(&stream), false)?,
        request_wake: request_producer.wake_handle(),
        request_producer: Mutex::new(request_producer),
        response_wake: response_consumer.wake_handle(),
        notification_wake: notification_consumer.wake_handle(),
        pending_calls,
    });
    let response_association = Arc::clone(&association);
    thread::Builder::new()
        .name("litebox-broker-responses".to_owned())
        .spawn(move || dispatch_responses(response_consumer, response_association))?;
    let monitor_association = Arc::clone(&association);
    thread::Builder::new()
        .name("litebox-broker-liveness".to_owned())
        .spawn(move || monitor_local_pipe(&stream, &monitor_association))?;
    Ok((
        WindowsControlRingLocalCallChannel {
            association: Arc::clone(&association),
        },
        WindowsControlRingLocalNotificationChannel {
            consumer: notification_consumer,
            association,
        },
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

impl LocalCallChannel for WindowsControlRingLocalCallChannel {
    type Error = Error;

    fn call(&self, request: BrokerRequest) -> IoResult<BrokerResponse> {
        let association = &self.association;
        let request_id = request.request_id;
        let pending_call = association
            .pending_calls
            .register(request_id)
            .map_err(pending_calls_error)?;
        let frame = encode_request(request);
        let write_result = {
            let mut producer = association
                .request_producer
                .lock()
                .map_err(|_| Error::other("broker request writer mutex poisoned"))?;
            loop {
                let status = association
                    .pending_calls
                    .run_if_live(|| producer.try_write(&frame).map_err(ring_error))
                    .map_err(pending_calls_error);
                match status {
                    Ok(ControlRingWriteStatus::Written) => {
                        break producer.wake_consumer();
                    }
                    Ok(ControlRingWriteStatus::Full { wait_epoch }) => {
                        if let Err(error) = producer.wait_for_capacity(wait_epoch) {
                            break Err(error);
                        }
                    }
                    Err(error) => break Err(error),
                }
            }
        };
        if let Err(error) = write_result {
            let _ = association.fail(error);
        }
        pending_call.wait().map_err(|error| copy_io_error(&error))
    }
}

impl Drop for WindowsControlRingLocalCallChannel {
    fn drop(&mut self) {
        let _ = self.association.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker local call channel dropped",
        ));
    }
}

impl LocalNotificationChannel for WindowsControlRingLocalNotificationChannel {
    type Error = Error;

    fn recv_notification(&mut self) -> IoResult<Option<BrokerNotification>> {
        loop {
            if let Some(error) = self.association.pending_calls.current_failure() {
                return Err(copy_io_error(&error));
            }
            match self.consumer.try_read(decode_notification) {
                Ok(ControlRingReadStatus::Message(notification)) => {
                    self.association
                        .acknowledge_notification(&mut self.consumer)?;
                    return Ok(Some(notification));
                }
                Ok(ControlRingReadStatus::Empty { wait_epoch }) => {
                    if let Some(error) = self.association.pending_calls.current_failure() {
                        return Err(copy_io_error(&error));
                    }
                    if let Err(error) = self.consumer.wait_for_message(wait_epoch) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.association.fail(error);
                        return result;
                    }
                }
                Err(ControlRingReadError::Ring(error)) => {
                    let error = ring_error(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.association.fail(error);
                    return result;
                }
                Err(ControlRingReadError::Decode(error)) => {
                    let error = wire_error(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.association.fail(error);
                    return result;
                }
            }
        }
    }
}

impl LocalRingAssociation {
    fn acknowledge_notification(
        &self,
        consumer: &mut ControlRingConsumer<WindowsSharedMemory>,
    ) -> IoResult<()> {
        self.acknowledge_consumer(consumer)
    }

    fn acknowledge_consumer(
        &self,
        consumer: &mut ControlRingConsumer<WindowsSharedMemory>,
    ) -> IoResult<()> {
        let result = self
            .pending_calls
            .run_if_live(|| {
                consumer
                    .publish_head()
                    .map_err(ring_error)
                    .and_then(|()| consumer.wake_producer())
            })
            .map_err(pending_calls_error);
        if let Err(error) = result {
            let result = Err(copy_io_error(&error));
            let _ = self.fail(error);
            return result;
        }
        Ok(())
    }

    fn fail(&self, error: Error) -> IoResult<()> {
        self.pending_calls.record_failure(Arc::new(error));
        self.request_wake
            .interrupt_wait()
            .and(self.response_wake.interrupt_wait())
            .and(self.notification_wake.interrupt_wait())
            .and(self.liveness.shutdown())
    }
}

fn dispatch_responses(
    mut consumer: ControlRingConsumer<WindowsSharedMemory>,
    association: Arc<LocalRingAssociation>,
) {
    loop {
        match consumer.try_read(decode_response) {
            Ok(ControlRingReadStatus::Message(response)) => {
                if let Err(error) = consumer
                    .publish_head()
                    .map_err(ring_error)
                    .and_then(|()| consumer.wake_producer())
                    .and_then(|()| {
                        association
                            .pending_calls
                            .complete(response)
                            .map_err(pending_calls_error)
                    })
                {
                    let _ = association.fail(error);
                    return;
                }
            }
            Ok(ControlRingReadStatus::Empty { wait_epoch }) => {
                if association.pending_calls.current_failure().is_some() {
                    return;
                }
                if let Err(error) = consumer.wait_for_message(wait_epoch) {
                    let _ = association.fail(error);
                    return;
                }
            }
            Err(ControlRingReadError::Ring(error)) => {
                let _ = association.fail(ring_error(error));
                return;
            }
            Err(ControlRingReadError::Decode(error)) => {
                let _ = association.fail(wire_error(error));
                return;
            }
        }
    }
}

impl PipeLiveness {
    fn new(stream: Arc<WindowsNamedPipeStream>, server: bool) -> IoResult<Self> {
        Ok(Self {
            server,
            shutdown_event: OwnedEvent::manual_reset()?,
            state: Mutex::new(PipeLivenessState {
                stream: Some(stream),
                shutdown: false,
            }),
        })
    }

    fn shutdown(&self) -> IoResult<()> {
        let stream = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| Error::other("broker pipe liveness mutex poisoned"))?;
            if state.shutdown {
                return Ok(());
            }
            state.shutdown = true;
            state.stream.take()
        };

        let mut first_error = self.shutdown_event.set().err();
        if self.server
            && let Some(stream) = &stream
        {
            // SAFETY: This is a duplicated server handle for the active named-pipe instance.
            if unsafe { DisconnectNamedPipe(file_handle(stream)) } == 0 {
                let error = Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_PIPE_NOT_CONNECTED.cast_signed())
                    && first_error.is_none()
                {
                    first_error = Some(error);
                }
            }
        }
        drop(stream);
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn peer_closed(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.shutdown = true;
            state.stream.take();
        }
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

fn monitor_local_pipe(stream: &WindowsNamedPipeStream, association: &LocalRingAssociation) {
    let mut byte = [0];
    let error = match read_pipe_until_cancelled(
        file_handle(stream),
        &mut byte,
        association.liveness.shutdown_event.handle(),
    ) {
        Ok(0) => Error::new(
            ErrorKind::UnexpectedEof,
            "broker closed the active association",
        ),
        Ok(_) => invalid_data("broker sent unexpected active control-pipe data"),
        Err(error) if error.kind() == ErrorKind::ConnectionAborted => return,
        Err(error) => error,
    };
    let _ = association.fail(error);
}

fn file_handle(stream: &WindowsNamedPipeStream) -> windows_sys::Win32::Foundation::HANDLE {
    stream.handle()
}
