// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local (runner-side) endpoints of a Windows broker association.

use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::os::windows::fs::OpenOptionsExt;
use std::time::{Duration, Instant};

use litebox_broker_protocol::message::{BrokerHandshakeRequest, BrokerHandshakeResponse};
use litebox_broker_protocol::wire::{decode_handshake_response, encode_handshake_request};
use litebox_broker_transport::channel::LocalSetupChannel;
use litebox_broker_transport::control_ring::{ControlRing, ControlRingLayout};
use litebox_broker_transport::ring_association::{
    self, ControlRingLocalCallChannel, ControlRingLocalNotificationChannel,
};
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED;

use crate::control_ring::PipeAssociationStream;
use crate::named_pipe::{TRANSFER_FRAME_TAG, WindowsNamedPipeStream};
use crate::process_image::WindowsReceivedProcessImage;
use crate::setup::{invalid_data, wire_error};
use crate::shared_memory::{TransferredSharedMemory, WindowsSharedMemory};

const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(10);

/// Local-side broker setup channel over a Windows named pipe.
pub struct WindowsNamedPipeLocalSetupChannel {
    pub(crate) stream: WindowsNamedPipeStream,
    setup_deadline: Option<Instant>,
    negotiated: bool,
}

/// Call-issuing endpoint of an active local named-pipe association.
pub type WindowsControlRingLocalCallChannel = ControlRingLocalCallChannel<WindowsSharedMemory>;

/// Local notification receiver of an active named-pipe association.
pub type WindowsControlRingLocalNotificationChannel =
    ControlRingLocalNotificationChannel<WindowsSharedMemory>;

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
        let frame = self
            .stream
            .read_frame(self.setup_deadline)?
            .ok_or_else(|| {
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
        let frame = self
            .stream
            .read_frame(self.setup_deadline)?
            .ok_or_else(|| {
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
        let frame = self
            .stream
            .read_frame(self.setup_deadline)?
            .ok_or_else(|| {
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
        if !self.negotiated {
            return Err(invalid_data(
                "broker local setup channel activated before negotiation completed",
            ));
        }
        let stream = PipeAssociationStream::new(self.stream, false, self.setup_deadline)?;
        let (calls, notifications, _shutdown) =
            ring_association::activate_local(ring, Box::new(stream), || {})?;
        Ok((calls, notifications))
    }
}

impl LocalSetupChannel for WindowsNamedPipeLocalSetupChannel {
    type Error = Error;

    fn send_handshake_request(&mut self, request: &BrokerHandshakeRequest) -> IoResult<()> {
        self.stream.write_frame(
            &encode_handshake_request(request.clone()),
            self.setup_deadline,
        )
    }

    fn recv_handshake_response(&mut self) -> IoResult<Option<BrokerHandshakeResponse>> {
        let response = self
            .stream
            .read_frame(self.setup_deadline)?
            .map(|frame| decode_handshake_response(&frame).map_err(wire_error))
            .transpose()?;
        self.negotiated = matches!(response, Some(BrokerHandshakeResponse::Negotiated { .. }));
        Ok(response)
    }
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
