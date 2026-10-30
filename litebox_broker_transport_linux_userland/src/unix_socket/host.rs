// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host (broker-side) endpoints of a Unix-domain-socket broker association.
//!
//! The matching local endpoints live in the sibling `local` module, and both
//! sides share the crate-private `setup` framing. Once negotiated, the
//! association runs on the shared [`ring_association`] endpoints over a memfd
//! control ring. Portable broker interfaces live in the no_std protocol,
//! transport, local, core, and host crates.

use std::io::{Error, ErrorKind, IoSliceMut, Result as IoResult};
use std::mem::size_of;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;

use rustix::io::Errno;
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};

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

use crate::memfd::{MemfdProcessImage, MemfdSharedMemory};
use crate::setup::{
    UnixAssociationStream, invalid_data, read_setup_frame, wire_error, write_setup_frame,
};

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

fn peer_process_id(stream: &UnixStream) -> IoResult<u32> {
    let expected_length = size_of::<libc::ucred>();
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut actual_length =
        libc::socklen_t::try_from(expected_length).expect("Linux ucred size fits socklen_t");
    // SAFETY: `stream` supplies a live socket descriptor, `credentials` is
    // writable for `actual_length` bytes, and `actual_length` itself is a valid
    // writable socklen_t.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut credentials).cast(),
            &raw mut actual_length,
        )
    };
    if result != 0 {
        return Err(Error::last_os_error());
    }
    if actual_length as usize != expected_length {
        return Err(invalid_data(
            "Unix peer credentials have an unexpected size",
        ));
    }
    validate_peer_process_id(credentials.pid)
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

/// Makes the kernel attach each sender's credentials to the data later received on `stream`,
/// for [`validate_sender_process`].
///
/// This must happen before the peer sends, since the kernel attaches credentials as data is sent.
/// Use it where [`validate_peer_process`] cannot identify the peer, such as on a socket pair
/// whose other end passes to a process that did not create it.
pub fn enable_sender_credentials(stream: &UnixStream) -> IoResult<()> {
    rustix::net::sockopt::set_socket_passcred(stream, true)?;
    Ok(())
}

/// Validates that `expected_process_id` sent the first data queued on `stream`, waiting for it
/// until `deadline`, without consuming it.
///
/// The kernel attaches the sender's credentials once [`enable_sender_credentials`] has been
/// called, and only a sender privileged over its PID namespace can claim another process's ID.
/// This then stops attaching them.
pub fn validate_sender_process(
    stream: &UnixStream,
    expected_process_id: u32,
    deadline: Instant,
) -> IoResult<()> {
    let sender = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::new(
                ErrorKind::TimedOut,
                "Unix socket peer sent nothing before the deadline",
            ));
        }
        stream.set_read_timeout(Some(remaining))?;
        let mut byte = [0];
        let mut io = [IoSliceMut::new(&mut byte)];
        let mut control_space =
            crate::control_space::<{ rustix::cmsg_space!(ScmCredentials(1)) }>();
        let mut control = RecvAncillaryBuffer::new(&mut control_space);
        match recvmsg(stream, &mut io, &mut control, RecvFlags::PEEK) {
            Ok(received) if received.bytes == 0 => {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "Unix socket peer closed before sending",
                ));
            }
            Ok(_) => {
                break control.drain().find_map(|message| match message {
                    RecvAncillaryMessage::ScmCredentials(credentials) => {
                        Some(credentials.pid.as_raw_pid())
                    }
                    _ => None,
                });
            }
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
                return Err(Error::new(
                    ErrorKind::TimedOut,
                    "Unix socket peer sent nothing before the deadline",
                ));
            }
            Err(error) => return Err(error.into()),
        }
    };
    stream.set_read_timeout(None)?;
    rustix::net::sockopt::set_socket_passcred(stream, false)?;
    let sender = sender.ok_or_else(|| {
        Error::new(
            ErrorKind::PermissionDenied,
            "Unix socket peer data carries no sender credentials",
        )
    })?;
    if validate_peer_process_id(sender)? != expected_process_id {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "Unix socket data was not sent by the expected process",
        ));
    }
    Ok(())
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
pub type UnixControlRingHostCallLaneSource = ControlRingHostCallLaneSource<MemfdSharedMemory>;

/// One call lane of an active host Unix-socket association.
pub type UnixControlRingHostCallLane = ControlRingHostCallLane<MemfdSharedMemory>;

/// Host notification sender of an active Unix-socket association.
pub type UnixControlRingHostNotificationChannel =
    ControlRingHostNotificationChannel<MemfdSharedMemory>;

/// RAII guard that interrupts all active host ring I/O when dropped.
pub type UnixControlRingHostShutdown = ControlRingHostShutdown<MemfdSharedMemory>;

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

    /// Sends a memfd during association setup.
    pub fn send_memfd(
        &mut self,
        shared_memory: &MemfdSharedMemory,
        deadline: Option<Instant>,
    ) -> IoResult<()> {
        crate::memfd::send_memfd(&mut self.stream, shared_memory, deadline)
    }

    /// Sends the runner's end of its shared-object socket during association setup, after the
    /// control ring. See [`crate::shared_objects`].
    pub fn send_shared_object_channel(
        &mut self,
        socket: BorrowedFd<'_>,
        deadline: Option<Instant>,
    ) -> IoResult<()> {
        crate::memfd::send_shared_object_channel(&mut self.stream, socket, deadline)
    }

    /// Sends the optional process image during association setup, after the
    /// shared-object socket.
    pub fn send_process_image(
        &mut self,
        image: Option<&MemfdProcessImage>,
        deadline: Option<Instant>,
    ) -> IoResult<()> {
        crate::memfd::send_process_image(&mut self.stream, image, deadline)
    }

    /// Consumes a negotiated setup channel into independently usable active
    /// call-lane, notification, and shutdown handles.
    ///
    /// The ring must have a layout of more than one lane.
    pub fn into_active(
        self,
        ring: ControlRing<MemfdSharedMemory>,
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
        BrokerNotification, BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult,
        ReadinessNotification,
    };
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::wire::{
        decode_response, encode_handshake_request, encode_request,
    };
    use litebox_broker_protocol::{BROKER_PROTOCOL_VERSION, ObjectHandle, RequestId};
    use litebox_broker_transport::channel::{
        HostNotificationChannel, LocalCallChannel, LocalNotificationChannel, LocalSetupChannel,
    };
    use litebox_broker_transport::control_ring::{
        CONTROL_RING_NOTIFICATION_SLOT_COUNT, ControlRingConsumer, ControlRingLayout,
        ControlRingProducer, ControlRingReadStatus, ControlRingWriteStatus,
        LocalControlRingEndpoints,
    };

    use crate::unix_socket::local::{
        UnixControlRingLocalCallChannel, UnixControlRingLocalNotificationChannel,
        UnixStreamLocalSetupChannel,
    };
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::thread;
    use std::time::Duration;

    type Producer = ControlRingProducer<MemfdSharedMemory>;
    type Consumer = ControlRingConsumer<MemfdSharedMemory>;
    type Local = LocalControlRingEndpoints<MemfdSharedMemory>;

    const LAYOUT: ControlRingLayout = ControlRingLayout::MULTI_LANE;

    fn ring_pair() -> (
        ControlRing<MemfdSharedMemory>,
        ControlRing<MemfdSharedMemory>,
    ) {
        let first = MemfdSharedMemory::create_control_ring(LAYOUT).unwrap();
        let second = MemfdSharedMemory::control_ring_from_received_fd(
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

    /// Activates a host association and takes its always-demanded first lane.
    fn activate_host_lane() -> (
        UnixControlRingHostCallLane,
        UnixControlRingHostShutdown,
        Local,
        UnixStream,
    ) {
        let (mut lanes, shutdown, local, peer) = activate_host();
        let lane = lanes.next_lane().unwrap().unwrap();
        (lane, shutdown, local, peer)
    }

    fn demand_lanes(local: &Local, lanes: usize) {
        let demand = local.lane_demand.as_ref().unwrap();
        demand.request(lanes).unwrap();
        demand.wake_host().unwrap();
    }

    fn notification_channel_pair() -> (
        UnixControlRingLocalCallChannel,
        UnixControlRingLocalNotificationChannel,
        UnixControlRingHostNotificationChannel,
        UnixControlRingHostShutdown,
    ) {
        let (local_setup, host_control) = negotiated_pair();
        let (local_ring, host_ring) = ring_pair();
        let host_active = thread::spawn(move || host_control.into_active(host_ring).unwrap());
        let (local_call, local_notifications, _local_shutdown) =
            local_setup.into_active(local_ring, || {}).unwrap();
        let (_lanes, host_notifications, shutdown) = host_active.join().unwrap();
        (
            local_call,
            local_notifications,
            host_notifications,
            shutdown,
        )
    }

    fn read_response(consumer: &mut Consumer) -> BrokerResponse {
        loop {
            match consumer.try_read(decode_response).unwrap() {
                ControlRingReadStatus::Message(response) => {
                    consumer.publish_head().unwrap();
                    consumer.wake_producer().unwrap();
                    return response;
                }
                ControlRingReadStatus::Empty { wake_count } => {
                    consumer.wait_for_message(wake_count).unwrap();
                }
            }
        }
    }

    fn write_payload(producer: &mut Producer, payload: &[u8]) {
        loop {
            match producer.try_write(payload).unwrap() {
                ControlRingWriteStatus::Written => {
                    producer.wake_consumer().unwrap();
                    return;
                }
                ControlRingWriteStatus::Full { wake_count } => {
                    producer.wait_for_capacity(wake_count).unwrap();
                }
            }
        }
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
    fn linux_peer_validation_identifies_connected_process() {
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
    fn linux_peer_validation_rejects_unavailable_process_ids() {
        for process_id in [i32::MIN, -1, 0] {
            assert_eq!(
                validate_peer_process_id(process_id).unwrap_err().kind(),
                ErrorKind::PermissionDenied
            );
        }
        assert_eq!(validate_peer_process_id(1).unwrap(), 1);
    }

    #[test]
    fn sender_validation_identifies_the_sender_rather_than_the_creator() {
        use std::process::{Command, Stdio};

        // Another process sends on the end this process created.
        let send_from_child = || {
            let (broker_end, runner_end) = UnixStream::pair().unwrap();
            enable_sender_credentials(&broker_end).unwrap();
            let mut child = Command::new("sh")
                .args(["-c", "echo x"])
                .stdout(Stdio::from(std::os::fd::OwnedFd::from(runner_end)))
                .spawn()
                .unwrap();
            assert!(child.wait().unwrap().success());
            (broker_end, child.id())
        };
        let deadline = || Instant::now() + Duration::from_secs(5);

        let (mut broker_end, sender) = send_from_child();
        validate_sender_process(&broker_end, sender, deadline()).unwrap();
        // Validation consumes nothing.
        let mut sent = String::new();
        broker_end.read_to_string(&mut sent).unwrap();
        assert_eq!(sent, "x\n");

        let (broker_end, _) = send_from_child();
        assert_eq!(
            validate_sender_process(&broker_end, std::process::id(), deadline())
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn sender_validation_fails_without_credentials_data_or_time() {
        let deadline = || Instant::now() + Duration::from_secs(5);
        let (broker_end, mut runner_end) = UnixStream::pair().unwrap();
        runner_end.write_all(b"x").unwrap();
        assert_eq!(
            validate_sender_process(&broker_end, std::process::id(), deadline())
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied,
            "data sent before credentials were enabled carries none"
        );

        let (broker_end, runner_end) = UnixStream::pair().unwrap();
        enable_sender_credentials(&broker_end).unwrap();
        drop(runner_end);
        assert_eq!(
            validate_sender_process(&broker_end, std::process::id(), deadline())
                .unwrap_err()
                .kind(),
            ErrorKind::UnexpectedEof
        );

        let (broker_end, _runner_end) = UnixStream::pair().unwrap();
        enable_sender_credentials(&broker_end).unwrap();
        assert_eq!(
            validate_sender_process(
                &broker_end,
                std::process::id(),
                Instant::now() + Duration::from_millis(10)
            )
            .unwrap_err()
            .kind(),
            ErrorKind::TimedOut
        );
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
    fn host_rejects_single_lane_layouts() {
        let layout = ControlRingLayout::SINGLE_LANE;
        let memory = MemfdSharedMemory::create_control_ring(layout).unwrap();
        let (_peer, host_stream) = UnixStream::pair().unwrap();
        let Err(error) =
            negotiated_host(host_stream).into_active(ControlRing::new(memory, layout).unwrap())
        else {
            panic!("a single-lane layout was activated");
        };
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn host_hands_out_lanes_on_demand_and_each_lane_serves_its_own_calls() {
        let (mut lanes, _shutdown, mut local, peer) = activate_host();
        let mut first = lanes.next_lane().unwrap().unwrap();
        let next = thread::spawn(move || lanes.next_lane().map(|lane| (lane, lanes)));
        thread::sleep(Duration::from_millis(20));
        assert!(!next.is_finished());
        demand_lanes(&local, 2);
        let (second, mut lanes) = next.join().unwrap().unwrap();
        let mut second = second.unwrap();

        for (index, lane) in [&mut first, &mut second].into_iter().enumerate() {
            let id = u64::try_from(index).unwrap();
            write_payload(
                &mut local.lanes[index].request_producer,
                &encode_request(request(id)),
            );
            let HostReceive::Message(received) = lane.recv_request().unwrap() else {
                panic!("expected ring request");
            };
            assert_eq!(received.request_id, RequestId(id));
            lane.send_response(&response(received.request_id)).unwrap();
        }
        for (index, lane) in local.lanes.iter_mut().take(2).enumerate() {
            assert_eq!(
                read_response(&mut lane.response_consumer).request_id,
                RequestId(u64::try_from(index).unwrap())
            );
        }

        // Each remaining lane is handed out once; then the source waits until
        // the peer closes.
        demand_lanes(&local, LAYOUT.lane_count());
        for _ in 2..LAYOUT.lane_count() {
            assert!(lanes.next_lane().unwrap().is_some());
        }
        let last = thread::spawn(move || lanes.next_lane());
        thread::sleep(Duration::from_millis(20));
        assert!(!last.is_finished());
        drop(peer);
        assert!(last.join().unwrap().unwrap().is_none());
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
    fn host_close_wakes_response_producer_blocked_on_full_lane() {
        let (mut lane, _shutdown, _local, peer) = activate_host_lane();
        lane.send_response(&response(RequestId(1))).unwrap();
        let blocked = thread::spawn(move || lane.send_response(&response(RequestId(2))));
        thread::sleep(Duration::from_millis(20));
        assert!(!blocked.is_finished());
        drop(peer);
        assert_eq!(
            blocked.join().unwrap().unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn host_reports_wrong_phase_ring_message_as_protocol_violation() {
        let (mut lane, _shutdown, mut local, _peer) = activate_host_lane();
        write_payload(
            &mut local.lanes[0].request_producer,
            &encode_handshake_request(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }),
        );
        assert_eq!(lane.recv_request().unwrap(), HostReceive::ProtocolViolation);
    }

    #[test]
    fn malformed_host_ring_request_is_fatal_invalid_data() {
        let (mut lane, _shutdown, mut local, _peer) = activate_host_lane();
        write_payload(&mut local.lanes[0].request_producer, &[u8::MAX]);
        assert_eq!(
            lane.recv_request().unwrap_err().kind(),
            ErrorKind::InvalidData
        );
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
    fn host_handshake_reads_use_absolute_setup_deadlines() {
        let (mut local_stream, host_stream) = UnixStream::pair().unwrap();
        let mut host = UnixStreamHostSetupChannel::from_host_guaranteed(
            host_stream,
            Instant::now() + Duration::from_millis(50),
        );
        let host_reader = thread::spawn(move || host.recv_handshake_request().unwrap_err());
        local_stream.write_all(&8u32.to_le_bytes()).unwrap();
        for _ in 0..8 {
            thread::sleep(Duration::from_millis(20));
            if local_stream.write_all(&[0]).is_err() {
                break;
            }
        }
        let error = host_reader.join().unwrap();
        assert!(
            matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
            "unexpected host timeout error: {error:?}"
        );
    }

    #[test]
    fn notification_ring_round_trips() {
        let (_control, mut local, mut host, _shutdown) = notification_channel_pair();
        let notification = BrokerNotification::Readiness(ReadinessNotification {
            handle: ObjectHandle(7),
            readiness: ReadinessFlags::READ,
        });

        let receiver = thread::spawn(move || local.recv_notification());
        thread::sleep(Duration::from_millis(20));
        host.send_notification(&notification).unwrap();

        assert_eq!(receiver.join().unwrap().unwrap(), Some(notification));
    }

    #[test]
    fn full_notification_ring_wakes_after_consumer_progress() {
        let (_control, mut local, mut host, _shutdown) = notification_channel_pair();
        let notification = BrokerNotification::Readiness(ReadinessNotification {
            handle: ObjectHandle(7),
            readiness: ReadinessFlags::READ,
        });
        for _ in 0..CONTROL_RING_NOTIFICATION_SLOT_COUNT {
            host.send_notification(&notification).unwrap();
        }

        let (started_sender, started_receiver) = std::sync::mpsc::sync_channel(1);
        let (done_sender, done_receiver) = std::sync::mpsc::sync_channel(1);
        let writer = thread::spawn(move || {
            started_sender.send(()).unwrap();
            host.send_notification(&notification).unwrap();
            done_sender.send(()).unwrap();
        });
        started_receiver.recv().unwrap();
        assert!(
            done_receiver
                .recv_timeout(Duration::from_millis(20))
                .is_err()
        );

        assert!(matches!(
            local.recv_notification().unwrap(),
            Some(BrokerNotification::Readiness(_))
        ));
        done_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        writer.join().unwrap();
    }

    #[test]
    fn association_shutdown_interrupts_notification_wait() {
        let (_control, mut local, _host, shutdown) = notification_channel_pair();
        let receiver = thread::spawn(move || local.recv_notification());

        shutdown.shutdown().unwrap();

        assert_eq!(
            receiver.join().unwrap().unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
    }
}
