// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host (broker-side) endpoints of a Unix-domain-socket broker association.
//!
//! The matching local endpoints live in the sibling `local` module, and both
//! sides share the crate-private `setup` framing. Once negotiated, the
//! association runs on the shared [`ring_association`] endpoints over a POSIX
//! shared-memory control ring. Portable broker interfaces live in the no_std
//! protocol, transport, local, core, and host crates.

use std::io::{Error, ErrorKind, Result as IoResult};
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
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

use crate::setup::{
    UnixAssociationStream, invalid_data, read_setup_frame, wire_error, write_setup_frame,
};
use crate::shared_memory::MacosSharedMemory;

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

/// Returns the PID that `LOCAL_PEERPID` records for the peer of `stream`.
fn peer_process_id(stream: &UnixStream) -> IoResult<u32> {
    let expected_length = size_of::<libc::pid_t>();
    let mut process_id: libc::pid_t = 0;
    let mut actual_length =
        libc::socklen_t::try_from(expected_length).expect("pid_t size fits socklen_t");
    // SAFETY: `stream` supplies a live socket descriptor, `process_id` is
    // writable for `actual_length` bytes, and `actual_length` itself is a valid
    // writable socklen_t.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::from_mut(&mut process_id).cast(),
            &raw mut actual_length,
        )
    };
    if result != 0 {
        return Err(Error::last_os_error());
    }
    if actual_length as usize != expected_length {
        return Err(invalid_data("Unix peer process ID has an unexpected size"));
    }
    validate_peer_process_id(process_id)
}

fn validate_peer_process_id(process_id: i32) -> IoResult<u32> {
    match u32::try_from(process_id) {
        Ok(process_id) if process_id != 0 => Ok(process_id),
        _ => Err(Error::new(
            ErrorKind::PermissionDenied,
            "Unix socket peer process ID is unavailable",
        )),
    }
}

/// Host-side broker association setup channel over a Unix stream.
pub struct UnixStreamHostSetupChannel {
    stream: UnixStream,
    peer_credential: PeerCredential,
    setup_deadline: Option<Instant>,
    negotiated: bool,
}

/// Source of the call lanes of an active host Unix-socket association, which
/// hands out each lane once the runner starts using it.
pub type UnixControlRingHostCallLaneSource = ControlRingHostCallLaneSource<MacosSharedMemory>;

/// One call lane of an active host Unix-socket association.
pub type UnixControlRingHostCallLane = ControlRingHostCallLane<MacosSharedMemory>;

/// Host notification sender of an active Unix-socket association.
pub type UnixControlRingHostNotificationChannel =
    ControlRingHostNotificationChannel<MacosSharedMemory>;

/// RAII guard that interrupts all active host ring I/O when dropped.
pub type UnixControlRingHostShutdown = ControlRingHostShutdown<MacosSharedMemory>;

impl UnixStreamHostSetupChannel {
    /// Creates a host setup channel from an accepted Unix stream.
    pub const fn from_accepted(stream: UnixStream) -> Self {
        Self {
            stream,
            peer_credential: PeerCredential::Unauthenticated,
            setup_deadline: None,
            negotiated: false,
        }
    }

    /// Creates a host setup channel after the deployment has authenticated
    /// and bound the accepted peer. `setup_deadline` bounds handshake I/O.
    pub const fn from_host_guaranteed(stream: UnixStream, setup_deadline: Instant) -> Self {
        Self {
            stream,
            peer_credential: PeerCredential::HostGuaranteed,
            setup_deadline: Some(setup_deadline),
            negotiated: false,
        }
    }

    /// Sends one shared-memory resource during association setup.
    pub fn send_shared_memory(
        &mut self,
        shared_memory: &MacosSharedMemory,
        deadline: Option<Instant>,
    ) -> IoResult<()> {
        crate::shared_memory::send_shared_memory(&mut self.stream, shared_memory, deadline)
    }

    /// Consumes a negotiated setup channel into independently usable active
    /// call-lane, notification, and shutdown handles.
    ///
    /// The ring must have a layout of more than one lane.
    pub fn into_active(
        self,
        ring: ControlRing<MacosSharedMemory>,
    ) -> IoResult<(
        UnixControlRingHostCallLaneSource,
        UnixControlRingHostNotificationChannel,
        UnixControlRingHostShutdown,
    )> {
        if !self.negotiated {
            return Err(invalid_data(
                "broker host setup channel activated before negotiation completed",
            ));
        }
        let stream = UnixAssociationStream::new(self.stream, self.setup_deadline)?;
        ring_association::activate_host(ring, Box::new(stream))
    }
}

impl HostSetupChannel for UnixStreamHostSetupChannel {
    type Error = Error;

    fn peer_credential(&self) -> IoResult<PeerCredential> {
        Ok(self.peer_credential)
    }

    fn recv_handshake_request(&mut self) -> IoResult<HostReceive<BrokerHandshakeRequest>> {
        let Some(frame) = read_setup_frame(&mut self.stream, self.setup_deadline)? else {
            return Ok(HostReceive::PeerClosed);
        };
        match decode_handshake_request(&frame) {
            Ok(request) => Ok(HostReceive::Message(request)),
            Err(WireError::WrongMessagePhase) => Ok(HostReceive::ProtocolViolation),
            Err(error) => Err(wire_error(error)),
        }
    }

    fn send_handshake_response(&mut self, response: &BrokerHandshakeResponse) -> IoResult<()> {
        write_setup_frame(
            &mut self.stream,
            &encode_handshake_response(response.clone()),
            self.setup_deadline,
        )?;
        self.negotiated = matches!(response, BrokerHandshakeResponse::Negotiated { .. });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_protocol::message::{
        BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult,
    };
    use litebox_broker_protocol::wire::encode_request;
    use litebox_broker_protocol::{BROKER_PROTOCOL_VERSION, ObjectHandle, RequestId};
    use litebox_broker_transport::channel::{LocalCallChannel, LocalSetupChannel};
    use litebox_broker_transport::control_ring::{ControlRingLayout, LocalControlRingEndpoints};

    use crate::unix_socket::local::UnixStreamLocalSetupChannel;
    use std::io::Read;
    use std::os::fd::AsFd;
    use std::thread;
    use std::time::Duration;

    type Local = LocalControlRingEndpoints<MacosSharedMemory>;

    const LAYOUT: ControlRingLayout = ControlRingLayout::MULTI_LANE;

    fn ring_pair() -> (
        ControlRing<MacosSharedMemory>,
        ControlRing<MacosSharedMemory>,
    ) {
        let first = MacosSharedMemory::create_control_ring(LAYOUT).unwrap();
        let second = MacosSharedMemory::control_ring_from_received_fd(
            first.as_fd().try_clone_to_owned().unwrap(),
            LAYOUT,
        )
        .unwrap();
        (
            ControlRing::new(first, LAYOUT).unwrap(),
            ControlRing::new(second, LAYOUT).unwrap(),
        )
    }

    fn negotiated_host(stream: UnixStream) -> UnixStreamHostSetupChannel {
        UnixStreamHostSetupChannel {
            stream,
            peer_credential: PeerCredential::HostGuaranteed,
            setup_deadline: Some(Instant::now() + Duration::from_secs(2)),
            negotiated: true,
        }
    }

    /// Negotiates one real association over a socket pair, so the local half
    /// reaches its negotiated state through the same handshake production uses.
    fn negotiated_pair() -> (UnixStreamLocalSetupChannel, UnixStreamHostSetupChannel) {
        let (local_stream, host_stream) = UnixStream::pair().unwrap();
        let mut local = UnixStreamLocalSetupChannel::from_connected(local_stream);
        let mut host = UnixStreamHostSetupChannel::from_host_guaranteed(
            host_stream,
            Instant::now() + Duration::from_secs(2),
        );
        local
            .send_handshake_request(&BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            })
            .unwrap();
        assert!(matches!(
            host.recv_handshake_request().unwrap(),
            HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            })
        ));
        host.send_handshake_response(&BrokerHandshakeResponse::Negotiated {
            broker_protocol_version: BROKER_PROTOCOL_VERSION,
            process_id: litebox_broker_protocol::ProcessId(1),
            initial_thread_id: litebox_broker_protocol::ThreadId(2),
            startup: None,
        })
        .unwrap();
        assert!(matches!(
            local.recv_handshake_response().unwrap(),
            Some(BrokerHandshakeResponse::Negotiated { .. })
        ));
        (local, host)
    }

    fn activate_host() -> (
        UnixControlRingHostCallLaneSource,
        UnixControlRingHostShutdown,
        Local,
        UnixStream,
    ) {
        let (peer_stream, host_stream) = UnixStream::pair().unwrap();
        let mut ack_stream = peer_stream.try_clone().unwrap();
        let acknowledgement = thread::spawn(move || {
            write_setup_frame(&mut ack_stream, LAYOUT.ready_token(), None).unwrap();
            assert_eq!(
                read_setup_frame(&mut ack_stream, None).unwrap().unwrap(),
                LAYOUT.ready_token()
            );
        });
        let (local_ring, host_ring) = ring_pair();
        let channel = negotiated_host(host_stream);
        let (lanes, _notifications, shutdown) = channel.into_active(host_ring).unwrap();
        acknowledgement.join().unwrap();
        (lanes, shutdown, local_ring.into_local(), peer_stream)
    }

    fn request(id: u64) -> BrokerRequest {
        BrokerRequest {
            request_id: RequestId(id),
            operation: BrokerOperation::CloseObject(ObjectHandle(id)),
        }
    }

    fn response(id: RequestId) -> BrokerResponse {
        BrokerResponse {
            request_id: id,
            result: BrokerResult::ObjectClosed,
        }
    }

    #[test]
    fn macos_peer_validation_identifies_connected_process() {
        let (first, _second) = UnixStream::pair().unwrap();

        validate_peer_process(&first, std::process::id()).unwrap();
        let unexpected_process_id = std::process::id().checked_add(1).unwrap();
        assert_eq!(
            validate_peer_process(&first, unexpected_process_id)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn macos_peer_validation_rejects_unavailable_process_ids() {
        for process_id in [i32::MIN, -1, 0] {
            assert_eq!(
                validate_peer_process_id(process_id).unwrap_err().kind(),
                ErrorKind::PermissionDenied
            );
        }
        assert_eq!(validate_peer_process_id(1).unwrap(), 1);
    }

    #[test]
    fn two_way_ready_ack_activates_ring_transport() {
        let (local_setup, host) = negotiated_pair();
        let (local_ring, host_ring) = ring_pair();
        let host_active = thread::spawn(move || host.into_active(host_ring).unwrap());
        let (local, _local_notifications, _local_shutdown) =
            local_setup.into_active(local_ring, || {}).unwrap();
        let (mut lanes, _host_notifications, _shutdown) = host_active.join().unwrap();

        let caller = thread::spawn(move || local.call(request(7)));
        let mut lane = lanes.next_lane().unwrap().unwrap();
        let HostReceive::Message(received) = lane.recv_request().unwrap() else {
            panic!("expected ring request");
        };
        lane.send_response(&response(received.request_id)).unwrap();
        assert_eq!(caller.join().unwrap().unwrap().request_id, RequestId(7));
    }

    #[test]
    fn host_clean_close_wakes_request_and_lane_waits_as_peer_closed() {
        let (mut lanes, _shutdown, _local, peer) = activate_host();
        let mut lane = lanes.next_lane().unwrap().unwrap();
        let receiver = thread::spawn(move || lane.recv_request());
        let next = thread::spawn(move || lanes.next_lane());
        thread::sleep(Duration::from_millis(20));
        drop(peer);
        assert_eq!(receiver.join().unwrap().unwrap(), HostReceive::PeerClosed);
        assert!(next.join().unwrap().unwrap().is_none());
    }

    #[test]
    fn dropping_host_shutdown_guard_wakes_waits_and_closes_socket() {
        let (mut lanes, shutdown, _local, mut peer) = activate_host();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut lane = lanes.next_lane().unwrap().unwrap();
        let receiver = thread::spawn(move || lane.recv_request());
        let next = thread::spawn(move || lanes.next_lane());
        thread::sleep(Duration::from_millis(20));

        drop(shutdown);

        assert_eq!(
            receiver.join().unwrap().unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
        assert_eq!(
            next.join().unwrap().err().map(|error| error.kind()),
            Some(ErrorKind::ConnectionAborted)
        );
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn host_setup_rejects_active_frames_and_requires_negotiation() {
        let (mut peer_stream, host_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamHostSetupChannel::from_accepted(host_stream);
        write_setup_frame(&mut peer_stream, &encode_request(request(0)), None).unwrap();
        assert_eq!(
            channel.recv_handshake_request().unwrap(),
            HostReceive::ProtocolViolation
        );

        let (_peer_stream, host_stream) = UnixStream::pair().unwrap();
        let channel = UnixStreamHostSetupChannel::from_accepted(host_stream);
        let (ring, _) = ring_pair();
        let Err(error) = channel.into_active(ring) else {
            panic!("host control channel activated before negotiation");
        };
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn host_handshake_reports_peer_close_under_setup_deadline() {
        let (local_stream, host_stream) = UnixStream::pair().unwrap();
        let mut host = UnixStreamHostSetupChannel::from_host_guaranteed(
            host_stream,
            Instant::now() + Duration::from_secs(2),
        );
        drop(local_stream);
        assert_eq!(
            host.recv_handshake_request().unwrap(),
            HostReceive::PeerClosed
        );
    }
}
