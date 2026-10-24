// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local (runner-side) endpoints of a Windows broker association.

use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::os::windows::fs::OpenOptionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerRequest,
    BrokerResponse,
};
use litebox_broker_protocol::wire::{
    decode_handshake_response, decode_notification, decode_response, encode_handshake_request,
    encode_request,
};
use litebox_broker_transport::call_lane_pool::{LaneClaim, LocalCallLanePool};
use litebox_broker_transport::channel::{
    LocalCallChannel, LocalNotificationChannel, LocalSetupChannel,
};
use litebox_broker_transport::control_ring::{
    ControlRing, ControlRingConsumer, ControlRingLayout, ControlRingReadError,
    ControlRingReadStatus, ControlRingWakeHandle, ControlRingWriteStatus,
    LocalControlRingEndpoints, LocalControlRingLane, LocalLaneDemand,
};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED;

use crate::control_ring::PipeLiveness;
use crate::named_pipe::{TRANSFER_FRAME_TAG, WindowsNamedPipeStream};
use crate::process_image::WindowsReceivedProcessImage;
use crate::setup::{
    copy_io_error, invalid_data, read_frame, read_pipe_until_cancelled, ring_error, wire_error,
    write_frame,
};
use crate::shared_memory::{TransferredSharedMemory, WindowsSharedMemory};

const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(10);

/// Local-side broker setup channel over a Windows named pipe.
pub struct WindowsNamedPipeLocalSetupChannel {
    pub(crate) stream: WindowsNamedPipeStream,
    setup_deadline: Option<Instant>,
    negotiated: bool,
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

type LocalLane = LocalControlRingLane<WindowsSharedMemory>;

/// State shared by every activated local endpoint of one association: the
/// call lanes and their demand, the pipe liveness used for teardown, and the
/// wake handles of every ring wait.
struct LocalRingAssociation {
    lanes: LocalCallLanePool<LocalLane>,
    lane_demand: LocalLaneDemand<WindowsSharedMemory>,
    /// Whether the call channel was dropped, which ends the association as a
    /// local close rather than a failure.
    closed: AtomicBool,
    liveness: PipeLiveness,
    wakes: Vec<ControlRingWakeHandle<WindowsSharedMemory>>,
}

impl WindowsNamedPipeLocalSetupChannel {
    /// Connects to a broker setup pipe until `deadline` expires.
    pub fn connect_with_setup_deadline(name: &OsStr, deadline: Instant) -> IoResult<Self> {
        loop {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(FILE_FLAG_OVERLAPPED)
                .open(name)
            {
                Ok(stream) => {
                    return Ok(Self {
                        stream: WindowsNamedPipeStream::from_file(stream),
                        setup_deadline: Some(deadline),
                        negotiated: false,
                    });
                }
                Err(error) if Instant::now() < deadline => {
                    std::thread::sleep(
                        CONNECT_RETRY_DELAY.min(deadline.saturating_duration_since(Instant::now())),
                    );
                    let _ = error;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Receives and maps one shared-memory object duplicated into this process.
    pub fn receive_shared_memory(
        &mut self,
        expected_length: usize,
    ) -> IoResult<WindowsSharedMemory> {
        let frame =
            read_frame(file_handle(&self.stream), self.setup_deadline)?.ok_or_else(|| {
                Error::new(
                    ErrorKind::UnexpectedEof,
                    "broker closed before transferring shared memory",
                )
            })?;
        let transfer = decode_transfer(&frame)?;
        if transfer.length != expected_length {
            return Err(invalid_data("transferred shared-memory length mismatch"));
        }
        // SAFETY: The authenticated broker duplicated these handles into this process and encoded
        // their target-process values in the setup frame.
        unsafe { WindowsSharedMemory::from_transferred(transfer) }
    }

    /// Receives the shared control ring the broker duplicated into this process and maps it with
    /// `layout`.
    pub fn receive_control_ring(
        &mut self,
        layout: ControlRingLayout,
    ) -> IoResult<WindowsSharedMemory> {
        let frame =
            read_frame(file_handle(&self.stream), self.setup_deadline)?.ok_or_else(|| {
                Error::new(
                    ErrorKind::UnexpectedEof,
                    "broker closed before transferring control-ring memory",
                )
            })?;
        let transfer = decode_transfer(&frame)?;
        // SAFETY: The authenticated broker duplicated these handles into this process and encoded
        // their target-process values in the setup frame.
        unsafe { WindowsSharedMemory::control_ring_from_transferred(transfer, layout) }
    }

    /// Receives and maps the optional process image the broker sent with
    /// [`WindowsNamedPipeHostSetupChannel::send_process_image`](crate::named_pipe::WindowsNamedPipeHostSetupChannel::send_process_image).
    pub fn receive_process_image(&mut self) -> IoResult<Option<WindowsReceivedProcessImage>> {
        let frame =
            read_frame(file_handle(&self.stream), self.setup_deadline)?.ok_or_else(|| {
                Error::new(
                    ErrorKind::UnexpectedEof,
                    "broker closed before transferring the process image",
                )
            })?;
        let transfer = decode_transfer(&frame)?;
        // SAFETY: The authenticated broker duplicated these handles into this process and encoded
        // their target-process values in the setup frame.
        unsafe { WindowsReceivedProcessImage::from_transferred(transfer) }
    }

    /// Activates calls and notifications over the transferred shared control ring.
    ///
    /// The ring must have a layout of more than one lane.
    pub fn into_active(
        self,
        ring: ControlRing<WindowsSharedMemory>,
    ) -> IoResult<(
        WindowsControlRingLocalCallChannel,
        WindowsControlRingLocalNotificationChannel,
    )> {
        activate_local(self.stream, self.negotiated, self.setup_deadline, ring)
    }
}

impl LocalSetupChannel for WindowsNamedPipeLocalSetupChannel {
    type Error = Error;

    fn send_handshake_request(&mut self, request: &BrokerHandshakeRequest) -> IoResult<()> {
        write_frame(
            file_handle(&self.stream),
            &encode_handshake_request(request.clone()),
            self.setup_deadline,
        )
    }

    fn recv_handshake_response(&mut self) -> IoResult<Option<BrokerHandshakeResponse>> {
        let response = read_frame(file_handle(&self.stream), self.setup_deadline)?
            .map(|frame| decode_handshake_response(&frame).map_err(wire_error))
            .transpose()?;
        self.negotiated = matches!(response, Some(BrokerHandshakeResponse::Negotiated { .. }));
        Ok(response)
    }
}

fn activate_local(
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
    let ready_token = ring.layout().ready_token();
    let endpoints = ring.into_local();
    let wakes = endpoints.wake_handles();
    let LocalControlRingEndpoints {
        lanes,
        lane_demand: Some(lane_demand),
        notification_consumer,
    } = endpoints
    else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "broker control-ring layout has a single lane",
        ));
    };
    write_frame(file_handle(&stream), ready_token, setup_deadline)?;
    let ready = read_frame(file_handle(&stream), setup_deadline)?.ok_or_else(|| {
        Error::new(
            ErrorKind::UnexpectedEof,
            "broker closed before control-ring setup acknowledgement",
        )
    })?;
    if ready != ready_token {
        return Err(invalid_data(
            "broker sent an invalid control-ring setup acknowledgement",
        ));
    }

    let stream = Arc::new(stream);
    let association = Arc::new(LocalRingAssociation {
        lanes: LocalCallLanePool::new(lanes),
        lane_demand,
        closed: AtomicBool::new(false),
        liveness: PipeLiveness::new(Arc::clone(&stream), false)?,
        wakes,
    });
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

impl LocalCallChannel for WindowsControlRingLocalCallChannel {
    type Error = Error;

    fn call(&self, request: BrokerRequest) -> IoResult<BrokerResponse> {
        let association = &self.association;
        let mut lane = match association
            .lanes
            .claim(|lanes| association.demand_lanes(lanes))
        {
            Ok(lane) => lane,
            Err(error) => {
                let result = Err(copy_io_error(&error));
                let _ = association.fail(error);
                return result;
            }
        };
        let result = association.call_on_lane(&mut lane, request);
        // A failed call can leave its lane mid-exchange: fail the association
        // before freeing the lane, so no other call uses it.
        if let Err(error) = &result {
            let _ = association.fail(copy_io_error(error));
        }
        drop(lane);
        result
    }
}

impl Drop for WindowsControlRingLocalCallChannel {
    fn drop(&mut self) {
        self.association.closed.store(true, Ordering::Release);
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
                Ok(ControlRingReadStatus::Empty { wait_epoch }) => {
                    if let Some(error) = self.association.lanes.current_failure() {
                        return self.association.end_notifications(error);
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
    /// Ends notification receipt once the association has ended with
    /// `failure`: cleanly if the local side closed it.
    fn end_notifications(&self, failure: Error) -> IoResult<Option<BrokerNotification>> {
        if self.closed.load(Ordering::Acquire) {
            Ok(None)
        } else {
            Err(failure)
        }
    }

    fn acknowledge_notification(
        &self,
        consumer: &mut ControlRingConsumer<WindowsSharedMemory>,
    ) -> IoResult<()> {
        let result = self.lanes.run_if_live(|| {
            consumer
                .publish_head()
                .map_err(ring_error)
                .and_then(|()| consumer.wake_producer())
        });
        if let Err(error) = result {
            let result = Err(copy_io_error(&error));
            let _ = self.fail(error);
            return result;
        }
        Ok(())
    }

    /// Raises the lane demand to `lanes` and wakes the broker to serve them.
    fn demand_lanes(&self, lanes: usize) -> IoResult<()> {
        self.lane_demand.request(lanes).map_err(ring_error)?;
        self.lane_demand.wake_broker()
    }

    /// Writes `request` to `lane` and reads the broker's response from it,
    /// releasing the lane once the call succeeds.
    fn call_on_lane(
        &self,
        lane: &mut LaneClaim<'_, LocalLane>,
        request: BrokerRequest,
    ) -> IoResult<BrokerResponse> {
        let request_id = request.request_id;
        let request_frame = encode_request(request);
        let producer = &mut lane.request_producer;
        loop {
            let write_status = self
                .lanes
                .run_if_live(|| producer.try_write(&request_frame).map_err(ring_error))?;
            match write_status {
                ControlRingWriteStatus::Written => break,
                ControlRingWriteStatus::Full { wait_epoch } => {
                    producer.wait_for_capacity(wait_epoch)?;
                }
            }
        }
        producer.wake_consumer()?;

        let consumer = &mut lane.response_consumer;
        let response = loop {
            match consumer.try_read(decode_response) {
                Ok(ControlRingReadStatus::Message(response)) => break response,
                Ok(ControlRingReadStatus::Empty { wait_epoch }) => {
                    if let Some(error) = self.lanes.current_failure() {
                        return Err(error);
                    }
                    consumer.wait_for_message(wait_epoch)?;
                }
                Err(ControlRingReadError::Ring(error)) => return Err(ring_error(error)),
                Err(ControlRingReadError::Decode(error)) => return Err(wire_error(error)),
            }
        };
        if response.request_id != request_id {
            return Err(invalid_data("broker answered a different request"));
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

    fn fail(&self, error: Error) -> IoResult<()> {
        self.lanes.record_failure(error);
        self.wakes
            .iter()
            .map(ControlRingWakeHandle::interrupt_wait)
            .fold(Ok(()), IoResult::and)
            .and(self.liveness.shutdown())
    }
}

fn monitor_local_pipe(stream: &WindowsNamedPipeStream, association: &LocalRingAssociation) {
    let mut byte = [0];
    let error = match read_pipe_until_cancelled(
        file_handle(stream),
        &mut byte,
        association.liveness.shutdown_handle(),
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

fn decode_transfer(frame: &[u8]) -> IoResult<TransferredSharedMemory> {
    if frame.len() < 13 || frame[0] != TRANSFER_FRAME_TAG {
        return Err(invalid_data("invalid shared-memory transfer frame"));
    }
    let length = usize::try_from(u64::from_le_bytes(frame[1..9].try_into().unwrap()))
        .map_err(|_| invalid_data("transferred shared-memory length is too large"))?;
    let count = usize::try_from(u32::from_le_bytes(frame[9..13].try_into().unwrap()))
        .expect("u32 handle count fits usize");
    if frame.len()
        != 13
            + count
                .checked_mul(8)
                .ok_or_else(|| invalid_data("handle count overflow"))?
    {
        return Err(invalid_data("invalid shared-memory transfer frame length"));
    }
    let handles = frame[13..]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|bytes| {
            usize::try_from(u64::from_le_bytes(*bytes))
                .map_err(|_| invalid_data("transferred handle is too large"))
        })
        .collect::<IoResult<Vec<_>>>()?;
    Ok(TransferredSharedMemory { length, handles })
}

fn file_handle(stream: &WindowsNamedPipeStream) -> HANDLE {
    stream.handle()
}
