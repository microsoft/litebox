// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host (broker-side) endpoints of a Unix-domain-socket broker association.
//!
//! The matching local endpoints live in the sibling `local` module, and both
//! sides share the crate-private `setup` framing. Once negotiated, the
//! association runs on the shared [`ring_association`] endpoints over a memfd
//! control ring. Portable broker interfaces live in the no_std protocol,
//! transport, local, core, and host crates.

use std::io::{Error, ErrorKind, Result as IoResult, Write as _};
use std::mem::size_of;
use std::os::fd::{AsRawFd, BorrowedFd};
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

use crate::memfd::{MemfdProcessImage, MemfdSharedMemory};
use crate::setup::{
    UnixAssociationStream, invalid_data, read_setup_frame, wire_error, write_setup_frame,
};
use crate::unix_io::{refresh_read_deadline, with_read_deadline};

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
/// for [`admit_sender_process`].
///
/// This must happen before the peer sends, since the kernel attaches credentials as data is sent.
/// Use it where [`validate_peer_process`] cannot identify the peer, such as on a socket pair
/// whose other end passes to a process that did not create it.
pub fn enable_sender_credentials(stream: &UnixStream) -> IoResult<()> {
    rustix::net::sockopt::set_socket_passcred(stream, true)?;
    Ok(())
}

/// Admits `expected_process_id` to send on `stream`, then waits until `deadline` for the first
/// data, without consuming it, failing with [`ErrorKind::PermissionDenied`] unless that process
/// sent it.
///
/// The kernel records only the number of each sender's process, so the caller must keep
/// `expected_process_id` from naming another process until this returns, such as by leaving it an
/// unreaped child. Data queued before then may have been sent while the number named another
/// process, so this fails with that kind if any is. Otherwise, it sends the admission byte, which
/// the peer awaits with [`wait_for_broker_admission`](super::wait_for_broker_admission) before
/// sending.
///
/// The kernel stops attaching credentials, which [`enable_sender_credentials`] requested, once
/// this returns.
pub fn admit_sender_process(
    stream: &mut UnixStream,
    expected_process_id: u32,
    deadline: Instant,
) -> IoResult<()> {
    let sender = ensure_nothing_queued(stream)
        .and_then(|()| stream.write_all(&[super::SENDER_ADMISSION]))
        .and_then(|()| with_read_deadline(stream, Some(deadline), wait_for_first_sender));
    let stopped = rustix::net::sockopt::set_socket_passcred(&*stream, false).map_err(Error::from);
    let sender = sender.and_then(|sender| stopped.map(|()| sender))?;
    if validate_peer_process_id(sender)? != expected_process_id {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "Unix socket data was not sent by the expected process",
        ));
    }
    Ok(())
}

fn ensure_nothing_queued(stream: &UnixStream) -> IoResult<()> {
    match peek_queued_data(stream, libc::MSG_DONTWAIT) {
        Ok(QueuedData::Sent { .. }) => Err(Error::new(
            ErrorKind::PermissionDenied,
            "Unix socket peer sent before it was admitted",
        )),
        Ok(QueuedData::Closed) => Err(peer_closed_before_sending()),
        Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(error),
    }
}

/// Returns the process ID the kernel recorded for the sender of the first data on `stream`,
/// waiting for it until `deadline`.
fn wait_for_first_sender(stream: &mut UnixStream, deadline: Option<Instant>) -> IoResult<i32> {
    loop {
        refresh_read_deadline(stream, deadline)?;
        match peek_queued_data(stream, 0) {
            Ok(QueuedData::Sent { sender }) => {
                return sender.ok_or_else(|| {
                    Error::new(
                        ErrorKind::PermissionDenied,
                        "Unix socket peer data carries no sender credentials",
                    )
                });
            }
            Ok(QueuedData::Closed) => return Err(peer_closed_before_sending()),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                return Err(Error::new(
                    ErrorKind::TimedOut,
                    "Unix socket peer sent nothing before the deadline",
                ));
            }
            Err(error) => return Err(error),
        }
    }
}

fn peer_closed_before_sending() -> Error {
    Error::new(
        ErrorKind::UnexpectedEof,
        "Unix socket peer closed before sending",
    )
}

/// What [`peek_queued_data`] found at the front of a stream.
enum QueuedData {
    /// The peer closed the stream without sending.
    Closed,
    /// Data, whose sender's process ID is the one the kernel attached, if any.
    Sent { sender: Option<libc::pid_t> },
}

/// Peeks at the first byte queued on `stream`, and the credentials the kernel attached to it,
/// without consuming it, waiting for it unless `flags` include `MSG_DONTWAIT`.
fn peek_queued_data(stream: &UnixStream, flags: libc::c_int) -> IoResult<QueuedData> {
    #[repr(C)]
    union ControlSpace {
        _alignment: libc::cmsghdr,
        bytes: [u8; 64],
    }

    let mut byte = 0u8;
    let mut io = libc::iovec {
        iov_base: (&raw mut byte).cast(),
        iov_len: 1,
    };
    let mut control = ControlSpace { bytes: [0; 64] };
    // SAFETY: A zeroed msghdr is a valid empty message header.
    let mut message = unsafe { core::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &raw mut io;
    message.msg_iovlen = 1;
    message.msg_control = (&raw mut control).cast();
    message.msg_controllen = size_of::<ControlSpace>();
    // SAFETY: `stream` supplies a live socket descriptor, and `message` describes `io`, writable
    // for one byte, and `control`, writable for `msg_controllen` bytes, both live for the call.
    let received = unsafe {
        libc::recvmsg(
            stream.as_raw_fd(),
            &raw mut message,
            flags | libc::MSG_PEEK | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if received < 0 {
        return Err(Error::last_os_error());
    }
    if received == 0 {
        return Ok(QueuedData::Closed);
    }
    let credentials_length = u32::try_from(size_of::<libc::ucred>())
        .expect("Linux ucred size fits a control message length");
    let mut sender = None;
    // SAFETY: recvmsg set `message.msg_control` and `msg_controllen` to the control data it wrote.
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
    while !header.is_null() {
        // SAFETY: CMSG_FIRSTHDR and CMSG_NXTHDR return only headers that lie entirely within the
        // control data, which `control` aligns for cmsghdr.
        let libc::cmsghdr {
            cmsg_len,
            cmsg_level,
            cmsg_type,
            ..
        } = unsafe { header.read() };
        // SAFETY: CMSG_LEN only computes a length.
        let minimum_length = unsafe { libc::CMSG_LEN(credentials_length) };
        if cmsg_level == libc::SOL_SOCKET
            && cmsg_type == libc::SCM_CREDENTIALS
            && u64::try_from(cmsg_len).is_ok_and(|length| length >= u64::from(minimum_length))
        {
            // SAFETY: The message's length covers a ucred payload, whose fields are plain integers
            // valid for any bytes.
            let credentials = unsafe {
                libc::CMSG_DATA(header)
                    .cast::<libc::ucred>()
                    .read_unaligned()
            };
            sender = Some(credentials.pid);
        }
        // SAFETY: `header` is a header within the control data `message` describes.
        header = unsafe { libc::CMSG_NXTHDR(&raw const message, header) };
    }
    Ok(QueuedData::Sent { sender })
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
    fn admission_identifies_the_sender_rather_than_the_creator() {
        use std::process::{Child, Command, Stdio};

        // Another process, which the broker keeps unreaped, sends on the end this process created
        // once it is admitted.
        let spawn_sender = || -> (UnixStream, Child) {
            let (broker_end, runner_end) = UnixStream::pair().unwrap();
            enable_sender_credentials(&broker_end).unwrap();
            let input = runner_end.try_clone().unwrap();
            let child = Command::new("sh")
                .args(["-c", "head -c 1 >/dev/null && echo x"])
                .stdin(Stdio::from(std::os::fd::OwnedFd::from(input)))
                .stdout(Stdio::from(std::os::fd::OwnedFd::from(runner_end)))
                .spawn()
                .unwrap();
            (broker_end, child)
        };
        let deadline = || Instant::now() + Duration::from_secs(5);

        let (mut broker_end, mut child) = spawn_sender();
        admit_sender_process(&mut broker_end, child.id(), deadline()).unwrap();
        assert!(child.wait().unwrap().success());
        // Admission consumes nothing the sender sent.
        let mut sent = String::new();
        broker_end.read_to_string(&mut sent).unwrap();
        assert_eq!(sent, "x\n");

        let (mut broker_end, mut child) = spawn_sender();
        assert_eq!(
            admit_sender_process(&mut broker_end, std::process::id(), deadline())
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn admission_fails_for_early_data_closure_or_silence() {
        let deadline = || Instant::now() + Duration::from_secs(5);
        let pair = || {
            let (broker_end, runner_end) = UnixStream::pair().unwrap();
            enable_sender_credentials(&broker_end).unwrap();
            (broker_end, runner_end)
        };
        let passes_credentials =
            |stream: &UnixStream| rustix::net::sockopt::socket_passcred(stream).unwrap();

        // Data sent before admission may come from a process that held the admitted ID earlier.
        let (mut broker_end, mut runner_end) = pair();
        runner_end.write_all(b"x").unwrap();
        assert_eq!(
            admit_sender_process(&mut broker_end, std::process::id(), deadline())
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert!(!passes_credentials(&broker_end));

        let (mut broker_end, runner_end) = pair();
        drop(runner_end);
        assert_eq!(
            admit_sender_process(&mut broker_end, std::process::id(), deadline())
                .unwrap_err()
                .kind(),
            ErrorKind::UnexpectedEof
        );

        let (mut broker_end, mut runner_end) = pair();
        assert_eq!(
            admit_sender_process(
                &mut broker_end,
                std::process::id(),
                Instant::now() + Duration::from_millis(10)
            )
            .unwrap_err()
            .kind(),
            ErrorKind::TimedOut
        );
        assert!(!passes_credentials(&broker_end));
        assert_eq!(broker_end.read_timeout().unwrap(), None);
        // The silent peer was admitted.
        let mut admission = [0];
        runner_end.read_exact(&mut admission).unwrap();
        assert_eq!(admission, [super::super::SENDER_ADMISSION]);
    }

    #[test]
    fn admitted_peers_wait_for_admission() {
        let (mut broker_end, runner_end) = UnixStream::pair().unwrap();
        enable_sender_credentials(&broker_end).unwrap();
        let sender = thread::spawn(move || {
            crate::unix_socket::wait_for_broker_admission(&runner_end).unwrap();
            (&runner_end).write_all(b"x").unwrap();
            runner_end
        });
        admit_sender_process(
            &mut broker_end,
            std::process::id(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        drop(sender.join().unwrap());

        let (broker_end, runner_end) = UnixStream::pair().unwrap();
        drop(broker_end);
        assert_eq!(
            crate::unix_socket::wait_for_broker_admission(&runner_end)
                .unwrap_err()
                .kind(),
            ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn credentials_of_data_sent_before_they_were_enabled_name_no_process() {
        let (broker_end, mut runner_end) = UnixStream::pair().unwrap();
        runner_end.write_all(b"x").unwrap();
        enable_sender_credentials(&broker_end).unwrap();
        // Linux: data queued before SO_PASSCRED was enabled carries SCM_CREDENTIALS with pid 0
        // and the overflow uid/gid (probed on 6.18), which must parse without naming a process.
        let QueuedData::Sent { sender } = peek_queued_data(&broker_end, 0).unwrap() else {
            panic!("data is queued");
        };
        assert!(matches!(sender, None | Some(0)), "{sender:?}");
        assert_eq!(
            validate_peer_process_id(sender.unwrap_or(0))
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
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
