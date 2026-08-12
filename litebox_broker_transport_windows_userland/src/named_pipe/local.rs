// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::os::windows::fs::OpenOptionsExt;
use std::time::{Duration, Instant};

use litebox_broker_protocol::message::{BrokerHandshakeRequest, BrokerHandshakeResponse};
use litebox_broker_protocol::wire::{decode_handshake_response, encode_handshake_request};
use litebox_broker_transport::channel::LocalSetupChannel;
use litebox_broker_transport::control_ring::ControlRing;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED;

use crate::setup::{invalid_data, read_frame, wire_error, write_frame};
use crate::shared_memory::{TransferredSharedMemory, WindowsSharedMemory};

use super::{WindowsNamedPipeStream, file_handle};

const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(10);
const TRANSFER_FRAME_TAG: u8 = 0xa1;

/// Local-side broker setup channel over a Windows named pipe.
pub struct WindowsNamedPipeLocalSetupChannel {
    pub(super) stream: WindowsNamedPipeStream,
    setup_deadline: Option<Instant>,
    negotiated: bool,
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
                        stream: WindowsNamedPipeStream(stream),
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

    /// Receives and maps the shared control ring duplicated into this process.
    pub fn receive_control_ring(&mut self) -> IoResult<WindowsSharedMemory> {
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
        unsafe { WindowsSharedMemory::control_ring_from_transferred(transfer) }
    }

    /// Activates calls and notifications over the transferred shared control ring.
    pub fn into_active(
        self,
        ring: ControlRing<WindowsSharedMemory>,
    ) -> IoResult<(
        crate::control_ring::WindowsControlRingLocalCallChannel,
        crate::control_ring::WindowsControlRingLocalNotificationChannel,
    )> {
        crate::control_ring::activate_local(self.stream, self.negotiated, self.setup_deadline, ring)
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
        .chunks_exact(8)
        .map(|bytes| {
            usize::try_from(u64::from_le_bytes(bytes.try_into().unwrap()))
                .map_err(|_| invalid_data("transferred handle is too large"))
        })
        .collect::<IoResult<Vec<_>>>()?;
    Ok(TransferredSharedMemory { length, handles })
}
