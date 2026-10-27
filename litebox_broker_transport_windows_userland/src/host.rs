// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host (broker-side) endpoints of a Windows broker association.

use std::io::{Error, ErrorKind, Result as IoResult};
use std::time::Instant;

use litebox_broker_protocol::message::{BrokerHandshakeRequest, BrokerHandshakeResponse};
use litebox_broker_protocol::wire::{
    WireError, decode_handshake_request, encode_handshake_response,
};
use litebox_broker_transport::channel::{HostReceive, HostSetupChannel, PeerCredential};
use litebox_broker_transport::control_ring::ControlRing;
use litebox_broker_transport::ring_association::{
    self, ControlRingHostCallLane, ControlRingHostCallLaneSource,
    ControlRingHostNotificationChannel, ControlRingHostShutdown,
};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::control_ring::PipeAssociationStream;
use crate::named_pipe::{TRANSFER_FRAME_TAG, WindowsNamedPipeStream};
use crate::process_image::WindowsProcessImage;
use crate::setup::{invalid_data, wire_error};
use crate::shared_memory::{TransferredSharedMemory, WindowsSharedMemory};

/// Host-side broker setup channel over a Windows named pipe.
pub struct WindowsNamedPipeHostSetupChannel {
    stream: WindowsNamedPipeStream,
    peer_credential: PeerCredential,
    setup_deadline: Option<Instant>,
    negotiated: bool,
}

/// Source of the call lanes of an active host named-pipe association, which
/// hands out each lane once the runner starts using it.
pub type WindowsControlRingHostCallLaneSource = ControlRingHostCallLaneSource<WindowsSharedMemory>;

/// One call lane of an active host named-pipe association.
pub type WindowsControlRingHostCallLane = ControlRingHostCallLane<WindowsSharedMemory>;

/// Host notification sender of an active named-pipe association.
pub type WindowsControlRingHostNotificationChannel =
    ControlRingHostNotificationChannel<WindowsSharedMemory>;

/// RAII guard that interrupts all active host ring I/O when dropped.
pub type WindowsControlRingHostShutdown = ControlRingHostShutdown<WindowsSharedMemory>;

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
        self.stream
            .write_frame(&encode_transfer(&transfer)?, self.setup_deadline)
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
        self.stream
            .write_frame(&encode_transfer(&transfer)?, self.setup_deadline)
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
        if !self.negotiated {
            return Err(invalid_data(
                "broker host setup channel activated before negotiation completed",
            ));
        }
        let stream = PipeAssociationStream::new(self.stream, true, self.setup_deadline)?;
        ring_association::activate_host(ring, Box::new(stream))
    }
}

impl HostSetupChannel for WindowsNamedPipeHostSetupChannel {
    type Error = Error;

    fn peer_credential(&self) -> IoResult<PeerCredential> {
        Ok(self.peer_credential)
    }

    fn recv_handshake_request(&mut self) -> IoResult<HostReceive<BrokerHandshakeRequest>> {
        let Some(frame) = self.stream.read_frame(self.setup_deadline)? else {
            return Ok(HostReceive::PeerClosed);
        };
        match decode_handshake_request(&frame) {
            Ok(request) => Ok(HostReceive::Message(request)),
            Err(WireError::WrongMessagePhase) => Ok(HostReceive::ProtocolViolation),
            Err(error) => Err(wire_error(error)),
        }
    }

    fn send_handshake_response(&mut self, response: &BrokerHandshakeResponse) -> IoResult<()> {
        self.stream.write_frame(
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
    if unsafe { GetNamedPipeClientProcessId(stream.handle(), &raw mut process_id) } == 0 {
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
