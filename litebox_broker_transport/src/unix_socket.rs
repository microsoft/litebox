// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix-domain-socket broker channel for hosted userland deployments.
//!
//! This module deliberately uses `std` because Unix-domain sockets and `std::io`
//! framing are hosted userland concerns. Portable broker interfaces live in the
//! no_std protocol, local, core, and host crates.

use std::io::{Error, ErrorKind, Read, Result as IoResult, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Instant;

use crate::shared_memory::MemfdSharedMemory;
use crate::unix_io::{
    refresh_read_deadline, refresh_write_deadline, with_read_deadline, with_write_deadline,
};
use litebox_broker_protocol::channel::{
    HostControlChannel, HostNotificationChannel, HostReceive, LocalControlChannel,
    LocalNotificationChannel, PeerCredential,
};
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerRequest,
    BrokerResponse,
};
use litebox_broker_protocol::wire::{
    WireError, decode_handshake_request, decode_handshake_response, decode_notification,
    decode_request, decode_response, encode_handshake_request, encode_handshake_response,
    encode_notification, encode_request, encode_response,
};

const MAX_FRAME_LEN: usize = 64 * 1024;

/// Validates that a connected Unix socket belongs to `expected_process_id`.
pub fn validate_peer_process(stream: &UnixStream, expected_process_id: u32) -> IoResult<()> {
    if peer_process_id(stream)? != expected_process_id {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "Unix socket peer is not the expected process",
        ));
    }
    Ok(())
}

/// Validates that two connected Unix sockets belong to the same process.
pub fn validate_same_peer_process(first: &UnixStream, second: &UnixStream) -> IoResult<()> {
    if peer_process_id(first)? != peer_process_id(second)? {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "Unix sockets belong to different peer processes",
        ));
    }
    Ok(())
}

fn peer_process_id(stream: &UnixStream) -> IoResult<u32> {
    let credentials = rustix::net::sockopt::socket_peercred(stream)?;
    u32::try_from(credentials.pid.as_raw_pid())
        .map_err(|_| invalid_data("Unix peer process ID is invalid"))
}

/// Local-side Unix-domain-socket control channel for the hosted userland POC.
pub struct UnixStreamLocalControlChannel {
    stream: UnixStream,
    setup_deadline: Option<Instant>,
}

/// Independently owned handle for interrupting local control-channel I/O.
pub struct UnixStreamLocalControlCancellation {
    stream: UnixStream,
}

impl UnixStreamLocalControlChannel {
    /// Creates a local control channel from an already-connected Unix stream.
    pub const fn from_connected(stream: UnixStream) -> Self {
        Self {
            stream,
            setup_deadline: None,
        }
    }

    /// Connects to a userland broker Unix socket.
    pub fn connect(path: impl AsRef<Path>) -> IoResult<Self> {
        UnixStream::connect(path).map(Self::from_connected)
    }

    /// Connects to a userland broker Unix socket with a deadline for setup I/O.
    ///
    /// TODO: `UnixStream` does not expose a connect timeout, so this
    /// deadline currently covers setup I/O after the initial connect
    /// succeeds, but not a blocking connect call.
    pub fn connect_with_setup_deadline(
        path: impl AsRef<Path>,
        deadline: Instant,
    ) -> IoResult<Self> {
        UnixStream::connect(path).map(|stream| Self {
            stream,
            setup_deadline: Some(deadline),
        })
    }

    /// Creates a handle that can interrupt pending control-channel I/O.
    pub fn cancellation_handle(&self) -> IoResult<UnixStreamLocalControlCancellation> {
        self.stream
            .try_clone()
            .map(|stream| UnixStreamLocalControlCancellation { stream })
    }

    /// Receives the memfd associated with this control channel.
    pub fn receive_memfd(
        &mut self,
        expected_len: usize,
        deadline: Option<Instant>,
    ) -> IoResult<MemfdSharedMemory> {
        crate::shared_memory::receive_memfd(&mut self.stream, expected_len, deadline)
    }
}

impl UnixStreamLocalControlCancellation {
    /// Shuts down the control stream, unblocking pending reads or writes.
    pub fn cancel(&self) -> IoResult<()> {
        match self.stream.shutdown(Shutdown::Both) {
            Err(error) if error.kind() == ErrorKind::NotConnected => Ok(()),
            result => result,
        }
    }
}

impl Drop for UnixStreamLocalControlChannel {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

/// Host-side Unix-domain-socket control channel for the hosted userland POC.
pub struct UnixStreamHostControlChannel {
    stream: UnixStream,
    peer_credential: PeerCredential,
    setup_deadline: Option<Instant>,
}

/// Local-side Unix-domain-socket notification channel for the hosted userland POC.
pub struct UnixStreamLocalNotificationChannel {
    stream: UnixStream,
}

/// Host-side Unix-domain-socket notification channel for the hosted userland POC.
pub struct UnixStreamHostNotificationChannel {
    stream: UnixStream,
}

impl UnixStreamHostControlChannel {
    /// Creates a host control channel from an accepted Unix stream.
    pub const fn from_accepted(stream: UnixStream) -> Self {
        Self {
            stream,
            peer_credential: PeerCredential::Unauthenticated,
            setup_deadline: None,
        }
    }

    /// Creates a host control channel after the deployment has authenticated
    /// and bound the accepted peer. `setup_deadline` bounds handshake I/O.
    pub const fn from_host_guaranteed(stream: UnixStream, setup_deadline: Instant) -> Self {
        Self {
            stream,
            peer_credential: PeerCredential::HostGuaranteed,
            setup_deadline: Some(setup_deadline),
        }
    }

    /// Sends the memfd associated with this control channel.
    pub fn send_memfd(
        &mut self,
        shared_memory: &MemfdSharedMemory,
        deadline: Option<Instant>,
    ) -> IoResult<()> {
        crate::shared_memory::send_memfd(&mut self.stream, shared_memory, deadline)
    }
}

impl UnixStreamLocalNotificationChannel {
    /// Creates a local notification channel from an already-connected Unix stream.
    pub const fn from_connected(stream: UnixStream) -> Self {
        Self { stream }
    }

    /// Connects to a userland broker Unix notification socket.
    pub fn connect(path: impl AsRef<Path>) -> IoResult<Self> {
        UnixStream::connect(path).map(Self::from_connected)
    }
}

impl UnixStreamHostNotificationChannel {
    /// Creates a host notification channel from an accepted Unix stream.
    pub const fn from_accepted(stream: UnixStream) -> Self {
        Self { stream }
    }
}

impl LocalControlChannel for UnixStreamLocalControlChannel {
    type Error = Error;

    fn send_handshake_request(&mut self, request: &BrokerHandshakeRequest) -> IoResult<()> {
        let frame = encode_handshake_request(request.clone());
        write_frame_with_deadline(&mut self.stream, &frame, self.setup_deadline)
    }

    fn recv_handshake_response(&mut self) -> IoResult<Option<BrokerHandshakeResponse>> {
        let frame = read_frame_with_deadline(&mut self.stream, self.setup_deadline)?;
        self.setup_deadline = None;
        match frame {
            Some(frame) => decode_handshake_response(&frame)
                .map(Some)
                .map_err(wire_error),
            None => Ok(None),
        }
    }

    fn send_request(&mut self, request: &BrokerRequest) -> IoResult<()> {
        let frame = encode_request(request.clone());
        write_frame_with_deadline(&mut self.stream, &frame, None)
    }

    fn recv_response(&mut self) -> IoResult<Option<BrokerResponse>> {
        match read_frame_with_deadline(&mut self.stream, None)? {
            Some(frame) => decode_response(&frame).map(Some).map_err(wire_error),
            None => Ok(None),
        }
    }
}

impl HostControlChannel for UnixStreamHostControlChannel {
    type Error = Error;

    fn peer_credential(&self) -> IoResult<PeerCredential> {
        Ok(self.peer_credential)
    }

    fn recv_handshake_request(&mut self) -> IoResult<HostReceive<BrokerHandshakeRequest>> {
        let Some(frame) = read_frame_with_deadline(&mut self.stream, self.setup_deadline)? else {
            return Ok(HostReceive::PeerClosed);
        };
        match decode_handshake_request(&frame) {
            Ok(request) => Ok(HostReceive::Message(request)),
            Err(WireError::WrongMessagePhase) => Ok(HostReceive::ProtocolViolation),
            Err(error) => Err(wire_error(error)),
        }
    }

    fn send_handshake_response(&mut self, response: &BrokerHandshakeResponse) -> IoResult<()> {
        write_frame_with_deadline(
            &mut self.stream,
            &encode_handshake_response(response.clone()),
            self.setup_deadline,
        )?;
        if matches!(response, BrokerHandshakeResponse::Negotiated { .. }) {
            self.setup_deadline = None;
        }
        Ok(())
    }

    fn recv_request(&mut self) -> IoResult<HostReceive<BrokerRequest>> {
        let Some(frame) = read_frame_with_deadline(&mut self.stream, None)? else {
            return Ok(HostReceive::PeerClosed);
        };
        match decode_request(&frame) {
            Ok(request) => Ok(HostReceive::Message(request)),
            Err(WireError::WrongMessagePhase) => Ok(HostReceive::ProtocolViolation),
            Err(error) => Err(wire_error(error)),
        }
    }

    fn send_response(&mut self, response: &BrokerResponse) -> IoResult<()> {
        write_frame_with_deadline(&mut self.stream, &encode_response(response.clone()), None)
    }
}

impl LocalNotificationChannel for UnixStreamLocalNotificationChannel {
    type Error = Error;

    fn recv_notification(&mut self) -> IoResult<Option<BrokerNotification>> {
        match read_frame_with_deadline(&mut self.stream, None)? {
            Some(frame) => decode_notification(&frame).map(Some).map_err(wire_error),
            None => Ok(None),
        }
    }
}

impl HostNotificationChannel for UnixStreamHostNotificationChannel {
    type Error = Error;

    fn send_notification(&mut self, notification: &BrokerNotification) -> IoResult<()> {
        write_frame_with_deadline(
            &mut self.stream,
            &encode_notification(notification.clone()),
            None,
        )
    }
}

fn read_frame_with_deadline(
    stream: &mut UnixStream,
    deadline: Option<Instant>,
) -> IoResult<Option<Vec<u8>>> {
    with_read_deadline(stream, deadline, |stream, deadline| {
        let mut len_buf = [0; 4];
        let mut read = 0;
        while read < len_buf.len() {
            refresh_read_deadline(stream, deadline)?;
            match stream.read(&mut len_buf[read..]) {
                Ok(0) if read == 0 => return Ok(None),
                Ok(0) => return Err(invalid_data("truncated broker frame length")),
                Ok(len) => read += len,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }

        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > MAX_FRAME_LEN {
            return Err(invalid_data("invalid broker frame length"));
        }

        let mut frame = vec![0; len];
        let mut read = 0;
        while read < frame.len() {
            refresh_read_deadline(stream, deadline)?;
            match stream.read(&mut frame[read..]) {
                Ok(0) => return Err(invalid_data("truncated broker frame")),
                Ok(len) => read += len,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(Some(frame))
    })
}

fn write_frame_with_deadline(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Option<Instant>,
) -> IoResult<()> {
    with_write_deadline(stream, deadline, |stream, deadline| {
        if frame.is_empty() || frame.len() > MAX_FRAME_LEN {
            return Err(invalid_data("invalid broker frame length"));
        }
        let len = u32::try_from(frame.len()).map_err(|_| invalid_data("broker frame too large"))?;
        write_all_with_deadline(stream, &len.to_le_bytes(), deadline)?;
        write_all_with_deadline(stream, frame, deadline)
    })
}

fn write_all_with_deadline(
    stream: &mut UnixStream,
    mut buffer: &[u8],
    deadline: Option<Instant>,
) -> IoResult<()> {
    while !buffer.is_empty() {
        refresh_write_deadline(stream, deadline)?;
        match stream.write(buffer) {
            Ok(0) => {
                return Err(Error::new(
                    ErrorKind::WriteZero,
                    "failed to write broker frame",
                ));
            }
            Ok(written) => buffer = &buffer[written..],
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn invalid_data(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

fn wire_error(error: WireError) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!("invalid broker wire message: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn linux_peer_validation_identifies_connected_process() {
        let (first, second) = UnixStream::pair().unwrap();

        validate_peer_process(&first, std::process::id()).unwrap();
        validate_same_peer_process(&first, &second).unwrap();
        let unexpected_process_id = std::process::id().checked_add(1).unwrap();
        assert_eq!(
            validate_peer_process(&first, unexpected_process_id)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn frame_round_trip() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        write_frame_with_deadline(&mut writer, &[1, 2, 3], None).unwrap();

        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap()
                .unwrap(),
            [1, 2, 3]
        );
    }

    #[test]
    fn clean_eof_before_frame_is_close() {
        let (writer, mut reader) = UnixStream::pair().unwrap();
        drop(writer);

        assert!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn malformed_frames_are_invalid() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&[1, 0]).unwrap();
        drop(writer);
        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&0u32.to_le_bytes()).unwrap();
        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer
            .write_all(&u32::try_from(MAX_FRAME_LEN + 1).unwrap().to_le_bytes())
            .unwrap();
        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&4u32.to_le_bytes()).unwrap();
        writer.write_all(&[1, 2]).unwrap();
        drop(writer);
        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn local_handshake_response_read_setup_deadline_is_wall_clock() {
        let (mut host_stream, local_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamLocalControlChannel {
            stream: local_stream,
            setup_deadline: Some(Instant::now() + Duration::from_millis(50)),
        };

        let reader = std::thread::spawn(move || channel.recv_handshake_response().unwrap_err());
        host_stream.write_all(&8u32.to_le_bytes()).unwrap();
        for _ in 0..8 {
            std::thread::sleep(Duration::from_millis(20));
            if host_stream.write_all(&[0]).is_err() {
                break;
            }
        }

        let error = reader.join().expect("timeout reader panicked");
        assert!(
            matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
            "unexpected timeout error kind: {error:?}"
        );
    }

    #[test]
    fn host_handshake_request_read_setup_deadline_is_wall_clock() {
        let (mut local_stream, host_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamHostControlChannel::from_host_guaranteed(
            host_stream,
            Instant::now() + Duration::from_millis(50),
        );

        let reader = std::thread::spawn(move || channel.recv_handshake_request().unwrap_err());
        local_stream.write_all(&8u32.to_le_bytes()).unwrap();
        for _ in 0..8 {
            std::thread::sleep(Duration::from_millis(20));
            if local_stream.write_all(&[0]).is_err() {
                break;
            }
        }

        let error = reader.join().expect("timeout reader panicked");
        assert!(
            matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
            "unexpected timeout error kind: {error:?}"
        );
    }

    #[test]
    fn negotiated_host_handshake_restores_active_timeouts() {
        let (mut local_stream, host_stream) = UnixStream::pair().unwrap();
        let active_read_timeout = Some(Duration::from_secs(2));
        let active_write_timeout = Some(Duration::from_secs(3));
        host_stream.set_read_timeout(active_read_timeout).unwrap();
        host_stream.set_write_timeout(active_write_timeout).unwrap();
        let mut channel = UnixStreamHostControlChannel::from_host_guaranteed(
            host_stream,
            Instant::now() + Duration::from_secs(1),
        );
        let request = BrokerHandshakeRequest {
            protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
        };

        write_frame_with_deadline(
            &mut local_stream,
            &encode_handshake_request(request.clone()),
            None,
        )
        .unwrap();
        assert_eq!(
            channel.recv_handshake_request().unwrap(),
            HostReceive::Message(request)
        );
        channel
            .send_handshake_response(&BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
            })
            .unwrap();

        assert_eq!(channel.setup_deadline, None);
        assert_eq!(channel.stream.read_timeout().unwrap(), active_read_timeout);
        assert_eq!(
            channel.stream.write_timeout().unwrap(),
            active_write_timeout
        );
    }

    #[test]
    fn local_control_cancellation_unblocks_response_read() {
        let (local_stream, _host_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamLocalControlChannel::from_connected(local_stream);
        let cancellation = channel.cancellation_handle().unwrap();
        let completed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (started_sender, started_receiver) = std::sync::mpsc::sync_channel(1);
        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(1);
        let reader_completed = completed.clone();
        let reader = std::thread::spawn(move || {
            started_sender.send(()).unwrap();
            result_sender.send(channel.recv_response()).unwrap();
            reader_completed.store(true, std::sync::atomic::Ordering::Release);
        });

        started_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(!completed.load(std::sync::atomic::Ordering::Acquire));
        cancellation.cancel().unwrap();

        assert!(result_receiver.recv_timeout(Duration::from_secs(1)).is_ok());
        reader.join().unwrap();
    }

    #[test]
    fn dropping_local_control_closes_connection_with_cancellation_clone() {
        let (local_stream, mut host_stream) = UnixStream::pair().unwrap();
        let channel = UnixStreamLocalControlChannel::from_connected(local_stream);
        let _cancellation = channel.cancellation_handle().unwrap();
        host_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        drop(channel);

        let mut byte = [0];
        assert_eq!(host_stream.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn host_reports_wrong_phase_request_frames_as_protocol_violations() {
        let (mut peer_stream, host_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamHostControlChannel::from_accepted(host_stream);
        write_frame_with_deadline(
            &mut peer_stream,
            &encode_request(BrokerRequest::Event(
                litebox_broker_protocol::message::EventRequest::Create(
                    litebox_broker_protocol::event::CreateEventRequest { initial_count: 0 },
                ),
            )),
            None,
        )
        .unwrap();
        assert_eq!(
            channel.recv_handshake_request().unwrap(),
            HostReceive::ProtocolViolation
        );

        let (mut peer_stream, host_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamHostControlChannel::from_accepted(host_stream);
        write_frame_with_deadline(
            &mut peer_stream,
            &encode_handshake_request(BrokerHandshakeRequest {
                protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
            }),
            None,
        )
        .unwrap();
        assert_eq!(
            channel.recv_request().unwrap(),
            HostReceive::ProtocolViolation
        );
    }

    #[test]
    fn notification_frame_round_trip() {
        let (local_stream, host_stream) = UnixStream::pair().unwrap();
        let mut local = UnixStreamLocalNotificationChannel::from_connected(local_stream);
        let mut host = UnixStreamHostNotificationChannel::from_accepted(host_stream);
        let notification = BrokerNotification::Readiness(
            litebox_broker_protocol::message::ReadinessNotification {
                handle: litebox_broker_protocol::ObjectHandle(7),
                readiness: litebox_broker_protocol::readiness::ReadinessFlags::READ,
            },
        );

        host.send_notification(&notification).unwrap();

        assert_eq!(local.recv_notification().unwrap(), Some(notification));
    }
}
