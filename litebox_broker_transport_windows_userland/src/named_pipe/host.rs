// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Error, ErrorKind, Result as IoResult};
use std::time::Instant;

use litebox_broker_protocol::message::{BrokerHandshakeRequest, BrokerHandshakeResponse};
use litebox_broker_protocol::wire::{
    WireError, decode_handshake_request, encode_handshake_response,
};
use litebox_broker_transport::channel::{HostReceive, HostSetupChannel, PeerCredential};
use litebox_broker_transport::control_ring::ControlRing;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

use crate::setup::{invalid_data, read_frame, wire_error, write_frame};
use crate::shared_memory::{TransferredSharedMemory, WindowsSharedMemory};

use super::{WindowsNamedPipeStream, file_handle};

const TRANSFER_FRAME_TAG: u8 = 0xa1;

/// Host-side broker setup channel over a Windows named pipe.
pub struct WindowsNamedPipeHostSetupChannel {
    stream: WindowsNamedPipeStream,
    peer_credential: PeerCredential,
    setup_deadline: Option<Instant>,
    negotiated: bool,
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

    /// Activates host request, response, and notification control-ring endpoints.
    pub fn into_active(
        self,
        ring: ControlRing<WindowsSharedMemory>,
    ) -> IoResult<(
        crate::control_ring::WindowsControlRingHostRequestSource,
        crate::control_ring::WindowsControlRingHostResponseSink,
        crate::control_ring::WindowsControlRingHostNotificationChannel,
        crate::control_ring::WindowsControlRingHostShutdown,
    )> {
        crate::control_ring::activate_host(self.stream, self.negotiated, self.setup_deadline, ring)
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
