// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host (broker-side) endpoints of a Windows broker association.

use std::io::{Error, ErrorKind, Result as IoResult};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerRequest,
    BrokerResponse,
};
use litebox_broker_protocol::wire::{
    WireError, decode_handshake_request, decode_request, encode_handshake_response,
    encode_notification, encode_response,
};
use litebox_broker_transport::channel::{
    HostAssociationShutdown, HostCallLane, HostCallLaneSource, HostNotificationChannel,
    HostReceive, HostSetupChannel, PeerCredential,
};
use litebox_broker_transport::control_ring::{
    ControlRing, ControlRingConsumer, ControlRingDemandStatus, ControlRingProducer,
    ControlRingReadError, ControlRingReadStatus, ControlRingWakeHandle, ControlRingWriteStatus,
    HostControlRingEndpoints, HostControlRingLane, HostLaneDemand,
};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::control_ring::PipeLiveness;
use crate::named_pipe::{TRANSFER_FRAME_TAG, WindowsNamedPipeStream};
use crate::process_image::WindowsProcessImage;
use crate::setup::{
    copy_io_error, invalid_data, read_frame, read_pipe_until_cancelled, ring_error, wire_error,
    write_frame,
};
use crate::shared_memory::{TransferredSharedMemory, WindowsSharedMemory};

/// Host-side broker setup channel over a Windows named pipe.
pub struct WindowsNamedPipeHostSetupChannel {
    stream: WindowsNamedPipeStream,
    peer_credential: PeerCredential,
    setup_deadline: Option<Instant>,
    negotiated: bool,
}

type BrokerLane = HostControlRingLane<WindowsSharedMemory>;

/// Source of the call lanes of an active host control-ring association, which
/// hands out each lane once the runner starts using it.
pub struct WindowsControlRingHostCallLaneSource {
    /// Each lane, or `None` once handed out.
    lanes: Vec<Option<BrokerLane>>,
    demand: HostLaneDemand<WindowsSharedMemory>,
    association: Arc<HostRingAssociation>,
}

/// One call lane of an active host control-ring association.
pub struct WindowsControlRingHostCallLane {
    lane: BrokerLane,
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

/// State shared by every activated host endpoint of one association: terminal
/// status, the pipe liveness used for teardown, and the wake handles of every
/// ring wait.
struct HostRingAssociation {
    status: Mutex<HostAssociationStatus>,
    liveness: PipeLiveness,
    wakes: Vec<ControlRingWakeHandle<WindowsSharedMemory>>,
}

enum HostAssociationStatus {
    Live,
    PeerClosed,
    Failed(Arc<Error>),
}

impl WindowsNamedPipeHostSetupChannel {
    /// Creates a host setup channel after the deployment has authenticated the client.
    pub const fn from_host_guaranteed(
        stream: WindowsNamedPipeStream,
        setup_deadline: Instant,
    ) -> Self {
        Self {
            stream,
            peer_credential: PeerCredential::HostGuaranteed,
            setup_deadline: Some(setup_deadline),
            negotiated: false,
        }
    }

    /// Duplicates one shared-memory object into the runner and sends its handle values.
    pub fn send_shared_memory(
        &mut self,
        memory: &WindowsSharedMemory,
        runner_process: HANDLE,
    ) -> IoResult<()> {
        let transfer = memory.duplicate_to_process(runner_process)?;
        write_frame(
            file_handle(&self.stream),
            &encode_transfer(&transfer)?,
            self.setup_deadline,
        )
    }

    /// Duplicates one shared-memory object into this process and sends its handle values.
    pub fn send_shared_memory_to_current_process(
        &mut self,
        memory: &WindowsSharedMemory,
    ) -> IoResult<()> {
        // SAFETY: GetCurrentProcess returns a pseudo-handle that remains valid
        // for the lifetime of this process and must not be closed.
        self.send_shared_memory(memory, unsafe { GetCurrentProcess() })
    }

    /// Duplicates a handle that can only read the image, if any, into its runner process and
    /// sends it.
    ///
    /// The broker must not write the image afterward. An empty image is sent as no image. The
    /// peer must call
    /// [`WindowsNamedPipeLocalSetupChannel::receive_process_image`](crate::named_pipe::WindowsNamedPipeLocalSetupChannel::receive_process_image)
    /// at the same setup step, even when there is no image.
    pub fn send_process_image(
        &mut self,
        image: Option<(&WindowsProcessImage, HANDLE)>,
    ) -> IoResult<()> {
        let transfer = match image.filter(|(image, _)| !image.is_empty()) {
            Some((image, runner_process)) => image.duplicate_to_process(runner_process)?,
            None => TransferredSharedMemory {
                length: 0,
                handles: Vec::new(),
            },
        };
        write_frame(
            file_handle(&self.stream),
            &encode_transfer(&transfer)?,
            self.setup_deadline,
        )
    }

    /// Activates host call-lane, notification, and shutdown control-ring endpoints.
    ///
    /// The ring must have a layout of more than one lane.
    pub fn into_active(
        self,
        ring: ControlRing<WindowsSharedMemory>,
    ) -> IoResult<(
        WindowsControlRingHostCallLaneSource,
        WindowsControlRingHostNotificationChannel,
        WindowsControlRingHostShutdown,
    )> {
        activate_host(self.stream, self.negotiated, self.setup_deadline, ring)
    }
}

impl HostSetupChannel for WindowsNamedPipeHostSetupChannel {
    type Error = Error;

    fn peer_credential(&self) -> IoResult<PeerCredential> {
        Ok(self.peer_credential)
    }

    fn recv_handshake_request(&mut self) -> IoResult<HostReceive<BrokerHandshakeRequest>> {
        let Some(frame) = read_frame(file_handle(&self.stream), self.setup_deadline)? else {
            return Ok(HostReceive::PeerClosed);
        };
        match decode_handshake_request(&frame) {
            Ok(request) => Ok(HostReceive::Message(request)),
            Err(WireError::WrongMessagePhase) => Ok(HostReceive::ProtocolViolation),
            Err(error) => Err(wire_error(error)),
        }
    }

    fn send_handshake_response(&mut self, response: &BrokerHandshakeResponse) -> IoResult<()> {
        write_frame(
            file_handle(&self.stream),
            &encode_handshake_response(response.clone()),
            self.setup_deadline,
        )?;
        self.negotiated = matches!(response, BrokerHandshakeResponse::Negotiated { .. });
        Ok(())
    }
}

/// Validates that a connected named-pipe client belongs to `expected_process_id`.
pub fn validate_client_process(
    stream: &WindowsNamedPipeStream,
    expected_process_id: u32,
) -> IoResult<()> {
    let mut process_id = 0;
    // SAFETY: `stream` is a connected named pipe and `process_id` is writable.
    if unsafe { GetNamedPipeClientProcessId(file_handle(stream), &raw mut process_id) } == 0 {
        return Err(Error::last_os_error());
    }
    if process_id != expected_process_id {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "named-pipe client is not the expected runner process",
        ));
    }
    Ok(())
}

fn activate_host(
    stream: WindowsNamedPipeStream,
    negotiated: bool,
    setup_deadline: Option<Instant>,
    ring: ControlRing<WindowsSharedMemory>,
) -> IoResult<(
    WindowsControlRingHostCallLaneSource,
    WindowsControlRingHostNotificationChannel,
    WindowsControlRingHostShutdown,
)> {
    if !negotiated {
        return Err(invalid_data(
            "broker host setup channel activated before negotiation completed",
        ));
    }
    let ready_token = ring.layout().ready_token();
    let endpoints = ring.into_host();
    let wakes = endpoints.wake_handles();
    let HostControlRingEndpoints {
        lanes,
        lane_demand: Some(demand),
        notification_producer,
    } = endpoints
    else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "broker control-ring layout has a single lane",
        ));
    };
    let ready = read_frame(file_handle(&stream), setup_deadline)?.ok_or_else(|| {
        Error::new(
            ErrorKind::UnexpectedEof,
            "runner closed before control-ring setup acknowledgement",
        )
    })?;
    if ready != ready_token {
        return Err(invalid_data(
            "runner sent an invalid control-ring setup acknowledgement",
        ));
    }
    write_frame(file_handle(&stream), ready_token, setup_deadline)?;

    let stream = Arc::new(stream);
    let association = Arc::new(HostRingAssociation {
        liveness: PipeLiveness::new(Arc::clone(&stream), true)?,
        status: Mutex::new(HostAssociationStatus::Live),
        wakes,
    });
    let monitor_association = Arc::clone(&association);
    thread::Builder::new()
        .name("litebox-runner-liveness".to_owned())
        .spawn(move || monitor_host_pipe(&stream, &monitor_association))?;
    Ok((
        WindowsControlRingHostCallLaneSource {
            lanes: lanes.into_iter().map(Some).collect(),
            demand,
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

impl HostAssociationShutdown for WindowsControlRingHostShutdown {
    type Error = Error;

    fn shutdown(&self) -> IoResult<()> {
        Self::shutdown(self)
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

impl WindowsControlRingHostCallLaneSource {
    /// Blocks until the runner starts using another lane and returns it.
    ///
    /// Once every lane is handed out, this blocks until the association ends.
    /// Returns `Ok(None)` once the runner closed the association.
    ///
    /// # Panics
    ///
    /// Panics if the lane demand hands out a lane more than once.
    pub fn next_lane(&mut self) -> IoResult<Option<WindowsControlRingHostCallLane>> {
        loop {
            if let Some(ended) = self.association.ended() {
                return ended.map(|()| None);
            }
            match self.demand.try_next_lane() {
                Ok(ControlRingDemandStatus::Lane(index)) => {
                    let lane = self.lanes[index]
                        .take()
                        .expect("lane demand hands out each lane once");
                    return Ok(Some(WindowsControlRingHostCallLane {
                        lane,
                        association: Arc::clone(&self.association),
                    }));
                }
                Ok(ControlRingDemandStatus::Satisfied { wake_count }) => {
                    if let Some(ended) = self.association.ended() {
                        return ended.map(|()| None);
                    }
                    if let Err(error) = self.demand.wait_for_demand(wake_count) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.association.fail(error);
                        return result;
                    }
                }
                Err(error) => {
                    let error = ring_error(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.association.fail(error);
                    return result;
                }
            }
        }
    }
}

impl HostCallLaneSource for WindowsControlRingHostCallLaneSource {
    type Error = Error;
    type Lane = WindowsControlRingHostCallLane;

    fn next_lane(&mut self) -> IoResult<Option<WindowsControlRingHostCallLane>> {
        Self::next_lane(self)
    }
}

impl WindowsControlRingHostCallLane {
    /// Receives this lane's next broker request.
    pub fn recv_request(&mut self) -> IoResult<HostReceive<BrokerRequest>> {
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

    /// Serializes and sends the response to this lane's last request.
    pub fn send_response(&mut self, response: &BrokerResponse) -> IoResult<()> {
        let frame = encode_response(response.clone());
        let producer = &mut self.lane.response_producer;
        loop {
            match self.association.try_publish(producer, &frame)? {
                ControlRingWriteStatus::Written => return Ok(()),
                ControlRingWriteStatus::Full { wake_count } => {
                    if let Err(error) = producer.wait_for_capacity(wake_count) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.association.fail(error);
                        return result;
                    }
                }
            }
        }
    }
}

impl HostCallLane for WindowsControlRingHostCallLane {
    type Error = Error;

    fn recv_request(&mut self) -> IoResult<HostReceive<BrokerRequest>> {
        Self::recv_request(self)
    }

    fn send_response(&mut self, response: &BrokerResponse) -> IoResult<()> {
        Self::send_response(self, response)
    }
}

impl HostNotificationChannel for WindowsControlRingHostNotificationChannel {
    type Error = Error;

    fn send_notification(&mut self, notification: &BrokerNotification) -> IoResult<()> {
        let frame = encode_notification(notification.clone());
        loop {
            match self.association.try_publish(&mut self.producer, &frame)? {
                ControlRingWriteStatus::Written => return Ok(()),
                ControlRingWriteStatus::Full { wake_count } => {
                    if let Err(error) = self.producer.wait_for_capacity(wake_count) {
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
        self.wakes
            .iter()
            .map(ControlRingWakeHandle::interrupt_wait)
            .fold(Ok(()), IoResult::and)
    }

    /// Returns how the association ended, if it has: `Ok` if the runner
    /// closed it.
    fn ended(&self) -> Option<IoResult<()>> {
        match &*self
            .status
            .lock()
            .expect("broker host association mutex poisoned")
        {
            HostAssociationStatus::Live => None,
            HostAssociationStatus::PeerClosed => Some(Ok(())),
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
        association.liveness.shutdown_handle(),
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

fn encode_transfer(transfer: &TransferredSharedMemory) -> IoResult<Vec<u8>> {
    let mut frame = Vec::with_capacity(13 + transfer.handles.len() * 8);
    frame.push(TRANSFER_FRAME_TAG);
    frame.extend_from_slice(
        &u64::try_from(transfer.length)
            .map_err(|_| invalid_data("shared-memory length is too large"))?
            .to_le_bytes(),
    );
    frame.extend_from_slice(
        &u32::try_from(transfer.handles.len())
            .map_err(|_| invalid_data("too many transferred handles"))?
            .to_le_bytes(),
    );
    for handle in &transfer.handles {
        frame.extend_from_slice(
            &u64::try_from(*handle)
                .map_err(|_| invalid_data("transferred handle is too large"))?
                .to_le_bytes(),
        );
    }
    Ok(frame)
}

fn file_handle(stream: &WindowsNamedPipeStream) -> HANDLE {
    stream.handle()
}
