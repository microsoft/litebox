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
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
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

use crate::control_message::ReceivedControl;
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

/// How the kernel identifies the senders of the data received on a [`SenderIdentifyingStream`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderIdentification {
    /// Each sender's pidfd, which keeps referring to that process after its ID is reused.
    /// Requires Linux 6.5.
    Pidfd,
    /// Only each sender's process ID, so the peer must wait for
    /// [`wait_for_broker_admission`](super::wait_for_broker_admission) before it sends.
    ProcessId,
}

/// The broker's end of a connected stream whose peer end passes to a process other than the one
/// that created it, on which the kernel identifies the sender of the data it receives.
///
/// Use it where [`validate_peer_process`] cannot identify the peer.
pub struct SenderIdentifyingStream {
    stream: UnixStream,
    identification: SenderIdentification,
}

impl SenderIdentifyingStream {
    /// Creates a connected pair, returning this end and the peer's, that identifies senders by
    /// pidfd where the kernel supports it and otherwise by process ID.
    pub fn pair() -> IoResult<(Self, UnixStream)> {
        match Self::pair_identified_by(SenderIdentification::Pidfd) {
            Err(error) if error.raw_os_error() == Some(libc::ENOPROTOOPT) => {
                Self::pair_identified_by(SenderIdentification::ProcessId)
            }
            result => result,
        }
    }

    /// Creates a connected pair, returning this end and the peer's, that identifies senders by
    /// `identification`, failing with `ENOPROTOOPT` if the kernel cannot identify them by pidfd.
    ///
    /// A pidfd keeps naming its sender after the sender's process ID is reused, so a peer whose
    /// senders are identified by pidfd is admitted at once.
    pub fn pair_identified_by(
        identification: SenderIdentification,
    ) -> IoResult<(Self, UnixStream)> {
        let (stream, peer) = UnixStream::pair()?;
        identify_senders(&stream, identification)?;
        if identification == SenderIdentification::Pidfd {
            (&stream).write_all(&[super::SENDER_ADMISSION])?;
        }
        Ok((
            Self {
                stream,
                identification,
            },
            peer,
        ))
    }

    /// Returns how the kernel identifies the senders on this stream.
    #[must_use]
    pub fn identification(&self) -> SenderIdentification {
        self.identification
    }

    /// Waits until `deadline` for the first data on this stream, without consuming it, and returns
    /// the stream, which no longer identifies senders, with a pidfd for the sender, failing with
    /// [`ErrorKind::PermissionDenied`] unless the sender had process ID `expected_process_id` when
    /// it sent.
    ///
    /// Where the kernel identifies senders only by process ID, it records just a number, so `pin`
    /// is called first. It must return a pidfd for `expected_process_id` and keep the ID from
    /// naming another process until this returns, such as by checking that it names an unreaped
    /// child. The peer is then admitted only if nothing was queued before, which may have been
    /// sent while the ID named another process, and the pinned pidfd is returned.
    ///
    /// Either pidfd refers to the sender even after it exits and its ID is reused, so the caller
    /// must check that it still refers to a process whose ID cannot be reused, such as a running
    /// child, to know that `expected_process_id` names the sender.
    pub fn verify_first_sender(
        self,
        expected_process_id: u32,
        deadline: Instant,
        pin: impl FnOnce() -> IoResult<OwnedFd>,
    ) -> IoResult<(UnixStream, OwnedFd)> {
        let Self {
            mut stream,
            identification,
        } = self;
        let pinned = match identification {
            SenderIdentification::Pidfd => None,
            SenderIdentification::ProcessId => {
                let pinned = pin()?;
                ensure_nothing_queued(&stream)?;
                (&stream).write_all(&[super::SENDER_ADMISSION])?;
                Some(pinned)
            }
        };
        let sender = with_read_deadline(&mut stream, Some(deadline), wait_for_first_sender)?;
        if identification == SenderIdentification::Pidfd {
            set_socket_passpidfd(&stream, false)?;
        }
        rustix::net::sockopt::set_socket_passcred(&stream, false)?;
        if validate_peer_process_id(sender.process_id)? != expected_process_id {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "Unix socket data was not sent by the expected process",
            ));
        }
        let pidfd = match pinned {
            Some(pinned) => pinned,
            None => sender_pidfd(sender.pidfd)?,
        };
        Ok((stream, pidfd))
    }
}

/// Makes the kernel identify each sender of the data later received on `stream` by
/// `identification`, failing with `ENOPROTOOPT` if the kernel cannot identify senders by pidfd.
///
/// This must happen before the peer sends, since the kernel records senders as data is sent.
fn identify_senders(stream: &UnixStream, identification: SenderIdentification) -> IoResult<()> {
    if identification == SenderIdentification::Pidfd {
        set_socket_passpidfd(stream, true)?;
    }
    rustix::net::sockopt::set_socket_passcred(stream, true)?;
    Ok(())
}

fn set_socket_passpidfd(stream: &UnixStream, enabled: bool) -> IoResult<()> {
    let value = libc::c_int::from(enabled);
    let length =
        libc::socklen_t::try_from(size_of::<libc::c_int>()).expect("Linux int size fits socklen_t");
    // SAFETY: `stream` supplies a live socket descriptor, and `value` is readable for `length`
    // bytes.
    let result = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSPIDFD,
            (&raw const value).cast(),
            length,
        )
    };
    if result != 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// Returns the sender's pidfd that the kernel attached to its data.
///
/// The kernel attaches an error in place of the pidfd when it cannot open one. If this process
/// was out of descriptors or memory, that error is returned as the broker's own failure. Any other
/// missing pidfd, such as for a sender that was already reaped, fails with
/// [`ErrorKind::PermissionDenied`].
fn sender_pidfd(pidfd: Option<IoResult<OwnedFd>>) -> IoResult<OwnedFd> {
    match pidfd {
        Some(Ok(pidfd)) => Ok(pidfd),
        Some(Err(error))
            if matches!(
                error.raw_os_error(),
                Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM)
            ) =>
        {
            Err(error)
        }
        Some(Err(_)) | None => Err(Error::new(
            ErrorKind::PermissionDenied,
            "Unix socket peer data carries no sender pidfd",
        )),
    }
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

/// The sender of the first data on a stream, as the kernel identified it.
struct Sender {
    process_id: libc::pid_t,
    /// Present if the stream identifies senders by pidfd.
    pidfd: Option<IoResult<OwnedFd>>,
}

/// Returns the sender of the first data on `stream`, waiting for it until `deadline`.
fn wait_for_first_sender(stream: &mut UnixStream, deadline: Option<Instant>) -> IoResult<Sender> {
    loop {
        refresh_read_deadline(stream, deadline)?;
        match peek_queued_data(stream, 0) {
            Ok(QueuedData::Sent { sender, pidfd }) => {
                let process_id = sender.ok_or_else(|| {
                    Error::new(
                        ErrorKind::PermissionDenied,
                        "Unix socket peer data carries no sender credentials",
                    )
                })?;
                return Ok(Sender { process_id, pidfd });
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
    /// Data, whose sender's process ID and pidfd are the ones the kernel attached, if any.
    Sent {
        sender: Option<libc::pid_t>,
        pidfd: Option<IoResult<OwnedFd>>,
    },
}

/// Peeks at the first byte queued on `stream`, and the credentials and pidfd the kernel attached to
/// it, without consuming it, waiting for it unless `flags` include `MSG_DONTWAIT`.
///
/// Fails with [`ErrorKind::PermissionDenied`] if the data carries descriptors or more control data
/// than fits. Even a peek installs descriptors in this process, so they are closed rather than
/// left to accumulate on every attempt.
fn peek_queued_data(stream: &UnixStream, flags: libc::c_int) -> IoResult<QueuedData> {
    #[repr(C)]
    union ControlSpace {
        _alignment: libc::cmsghdr,
        // Room for credentials and a pidfd, which take at most 56 bytes.
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
    // SAFETY: recvmsg just filled in `message`, whose control space is aligned for cmsghdr and
    // lives here, and installed the descriptors it carries in this process for this message alone.
    let control = unsafe { ReceivedControl::parse(&message) };
    if !control.descriptors.is_empty() {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "Unix socket peer data carries descriptors",
        ));
    }
    // The kernel drops what does not fit, possibly including the sender's pidfd.
    if control.truncated {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "Unix socket peer data carries more control data than expected",
        ));
    }
    Ok(QueuedData::Sent {
        sender: control.sender_process_id,
        pidfd: control.sender_pidfd,
    })
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
    use std::os::fd::{AsFd, FromRawFd as _};
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

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn pidfd_of(process_id: u32) -> IoResult<OwnedFd> {
        let pid = libc::pid_t::try_from(process_id).map_err(|_| ErrorKind::InvalidInput)?;
        // SAFETY: pidfd_open takes no pointers.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if pidfd < 0 {
            return Err(Error::last_os_error());
        }
        let pidfd = libc::c_int::try_from(pidfd).map_err(|_| ErrorKind::InvalidData)?;
        // SAFETY: pidfd_open returned a new descriptor that nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
    }

    /// Verifies the first sender on `stream`, pinning `expected_process_id` by a pidfd where the
    /// stream identifies senders by process ID.
    fn verify(
        stream: SenderIdentifyingStream,
        expected_process_id: u32,
        deadline: Instant,
    ) -> IoResult<(UnixStream, OwnedFd)> {
        stream.verify_first_sender(expected_process_id, deadline, || {
            pidfd_of(expected_process_id)
        })
    }

    fn process_id_pair() -> (SenderIdentifyingStream, UnixStream) {
        SenderIdentifyingStream::pair_identified_by(SenderIdentification::ProcessId).unwrap()
    }

    /// Returns a pair that identifies senders by pidfd, unless the kernel cannot.
    fn pidfd_pair() -> Option<(SenderIdentifyingStream, UnixStream)> {
        match SenderIdentifyingStream::pair_identified_by(SenderIdentification::Pidfd) {
            Ok(pair) => Some(pair),
            Err(error) if error.raw_os_error() == Some(libc::ENOPROTOOPT) => {
                eprintln!("skipping pidfd identification checks: the kernel lacks SO_PASSPIDFD");
                None
            }
            Err(error) => panic!("cannot identify senders by pidfd: {error}"),
        }
    }

    /// Spawns a child that, holding `runner_end`, sends `x\n` once admitted, then runs until
    /// killed if `linger`.
    fn spawn_sender(runner_end: UnixStream, linger: bool) -> std::process::Child {
        use std::process::{Command, Stdio};

        let script = if linger {
            "head -c 1 >/dev/null && echo x && exec sleep 30"
        } else {
            "head -c 1 >/dev/null && echo x"
        };
        let input = runner_end.try_clone().unwrap();
        Command::new("sh")
            .args(["-c", script])
            .stdin(Stdio::from(OwnedFd::from(input)))
            .stdout(Stdio::from(OwnedFd::from(runner_end)))
            .spawn()
            .unwrap()
    }

    fn passes_credentials(stream: &UnixStream) -> bool {
        rustix::net::sockopt::socket_passcred(stream).unwrap()
    }

    fn passes_pidfds(stream: &UnixStream) -> bool {
        let mut value: libc::c_int = 0;
        let mut length = libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap();
        // SAFETY: `stream` supplies a live socket descriptor, and `value` and `length` are
        // writable.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSPIDFD,
                (&raw mut value).cast(),
                &raw mut length,
            )
        };
        assert_eq!(result, 0, "{}", Error::last_os_error());
        value != 0
    }

    #[test]
    fn admission_identifies_the_sender_rather_than_the_creator() {
        // Another process, which the broker keeps unreaped, sends on the end this process created
        // once it is admitted.
        let (broker_end, runner_end) = process_id_pair();
        let mut child = spawn_sender(runner_end, false);
        let (mut stream, _pidfd) = verify(broker_end, child.id(), deadline()).unwrap();
        assert!(child.wait().unwrap().success());
        // Verification stops identifying senders, restores the read timeout, and consumes
        // nothing the sender sent.
        assert!(!passes_credentials(&stream));
        assert_eq!(stream.read_timeout().unwrap(), None);
        let mut sent = String::new();
        stream.read_to_string(&mut sent).unwrap();
        assert_eq!(sent, "x\n");

        let (broker_end, runner_end) = process_id_pair();
        let mut child = spawn_sender(runner_end, false);
        assert_eq!(
            verify(broker_end, std::process::id(), deadline())
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn admission_fails_for_early_data_closure_silence_or_a_failed_pin() {
        let own = std::process::id();

        // Data sent before admission may come from a process that held the admitted ID earlier.
        let (broker_end, mut runner_end) = process_id_pair();
        runner_end.write_all(b"x").unwrap();
        assert_eq!(
            verify(broker_end, own, deadline()).unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );

        // The peer closes before admission.
        let (broker_end, runner_end) = process_id_pair();
        drop(runner_end);
        assert_eq!(
            verify(broker_end, own, deadline()).unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );

        // The peer closes once admitted, without sending.
        let (broker_end, runner_end) = process_id_pair();
        let closer = thread::spawn(move || {
            crate::unix_socket::wait_for_broker_admission(&runner_end).unwrap();
        });
        assert_eq!(
            verify(broker_end, own, deadline()).unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
        closer.join().unwrap();

        // The admitted peer stays silent.
        let (broker_end, mut runner_end) = process_id_pair();
        assert_eq!(
            verify(broker_end, own, Instant::now() + Duration::from_millis(10))
                .unwrap_err()
                .kind(),
            ErrorKind::TimedOut
        );
        let mut admission = [0];
        runner_end.read_exact(&mut admission).unwrap();
        assert_eq!(admission, [super::super::SENDER_ADMISSION]);

        // A process that cannot be pinned is never admitted.
        let (broker_end, mut runner_end) = process_id_pair();
        assert_eq!(
            broker_end
                .verify_first_sender(own, deadline(), || Err(ErrorKind::PermissionDenied.into()))
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        let mut rest = Vec::new();
        runner_end.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"");
    }

    #[test]
    fn admitted_peers_wait_for_admission() {
        let (broker_end, runner_end) = process_id_pair();
        let sender = thread::spawn(move || {
            crate::unix_socket::wait_for_broker_admission(&runner_end).unwrap();
            (&runner_end).write_all(b"x").unwrap();
            runner_end
        });
        verify(broker_end, std::process::id(), deadline()).unwrap();
        drop(sender.join().unwrap());

        let (broker_end, runner_end) = UnixStream::pair().unwrap();
        drop(broker_end);
        assert_eq!(
            crate::unix_socket::wait_for_broker_admission(&runner_end)
                .unwrap_err()
                .kind(),
            ErrorKind::UnexpectedEof
        );

        let (mut broker_end, runner_end) = UnixStream::pair().unwrap();
        broker_end
            .write_all(&[super::super::SENDER_ADMISSION + 1])
            .unwrap();
        assert_eq!(
            crate::unix_socket::wait_for_broker_admission(&runner_end)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn admission_rejects_and_closes_descriptors_the_peer_sends() {
        use std::io::PipeReader;

        /// Sends one byte carrying the write end of a new pipe, returning the read end, which
        /// reaches end-of-file only once every copy of the write end is closed.
        fn send_descriptor(runner_end: &UnixStream) -> PipeReader {
            use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
            use std::io::IoSlice;

            let (pipe_read, pipe_write) = std::io::pipe().unwrap();
            let mut space = crate::control_space::<{ rustix::cmsg_space!(ScmRights(1)) }>();
            let mut control = SendAncillaryBuffer::new(&mut space);
            let descriptors = [pipe_write.as_fd()];
            assert!(control.push(SendAncillaryMessage::ScmRights(&descriptors)));
            rustix::net::sendmsg(
                runner_end,
                &[IoSlice::new(b"x")],
                &mut control,
                SendFlags::empty(),
            )
            .unwrap();
            pipe_read
        }

        /// Checks that peeking left no copy of the sent descriptor installed in this process,
        /// once rejection closed the broker's end and with it the in-flight copy.
        fn assert_closed(runner_end: UnixStream, mut pipe: PipeReader) {
            drop(runner_end);
            rustix::io::ioctl_fionbio(&pipe, true).unwrap();
            let mut rest = Vec::new();
            pipe.read_to_end(&mut rest).unwrap();
            assert_eq!(rest, b"");
        }

        // Queued before admission.
        let (broker_end, runner_end) = process_id_pair();
        let pipe = send_descriptor(&runner_end);
        assert_eq!(
            verify(broker_end, std::process::id(), deadline())
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_closed(runner_end, pipe);

        // Sent by the expected process as its first data once admitted.
        let (broker_end, runner_end) = process_id_pair();
        let sender = thread::spawn(move || {
            crate::unix_socket::wait_for_broker_admission(&runner_end).unwrap();
            let pipe = send_descriptor(&runner_end);
            (runner_end, pipe)
        });
        assert_eq!(
            verify(broker_end, std::process::id(), deadline())
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        let (runner_end, pipe) = sender.join().unwrap();
        assert_closed(runner_end, pipe);

        // Sent at once where senders are identified by pidfd.
        if let Some((broker_end, runner_end)) = pidfd_pair() {
            let pipe = send_descriptor(&runner_end);
            assert_eq!(
                verify(broker_end, std::process::id(), deadline())
                    .unwrap_err()
                    .kind(),
                ErrorKind::PermissionDenied
            );
            assert_closed(runner_end, pipe);
        }
    }

    #[test]
    fn pidfd_identification_admits_at_once_and_returns_the_senders_pidfd() {
        let Some((broker_end, runner_end)) = pidfd_pair() else {
            return;
        };
        let mut child = spawn_sender(runner_end, true);
        let (mut stream, pidfd) = broker_end
            .verify_first_sender(child.id(), deadline(), || {
                panic!("a sender identified by pidfd needs no pin")
            })
            .unwrap();
        assert!(!passes_credentials(&stream));
        assert!(!passes_pidfds(&stream));
        // The pidfd refers to the sender.
        child.kill().unwrap();
        // SAFETY: A zeroed siginfo_t is valid output storage for waitid.
        let mut info = unsafe { core::mem::zeroed::<libc::siginfo_t>() };
        // SAFETY: `info` is writable, and `pidfd` is a live pidfd. WNOWAIT leaves the child
        // unreaped for `child.wait`.
        let waited = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                libc::id_t::try_from(pidfd.as_raw_fd()).unwrap(),
                &raw mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(waited, 0);
        // SAFETY: waitid initialized `info`.
        assert_eq!(unsafe { info.si_pid() }, i32::try_from(child.id()).unwrap());
        child.wait().unwrap();
        // Verification consumes nothing the sender sent.
        let mut sent = String::new();
        stream.read_to_string(&mut sent).unwrap();
        assert_eq!(sent, "x\n");

        // A process other than the expected one sends.
        let (broker_end, mut runner_end) = pidfd_pair().unwrap();
        runner_end.write_all(b"x").unwrap();
        assert_eq!(
            verify(broker_end, std::process::id() + 1, deadline())
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );

        // Nobody sends.
        let (broker_end, _runner_end) = pidfd_pair().unwrap();
        assert_eq!(
            verify(
                broker_end,
                std::process::id(),
                Instant::now() + Duration::from_millis(10)
            )
            .unwrap_err()
            .kind(),
            ErrorKind::TimedOut
        );
    }

    #[test]
    fn pidfds_of_senders_reaped_before_verification_name_no_running_process() {
        let Some((broker_end, runner_end)) = pidfd_pair() else {
            return;
        };
        let mut child = spawn_sender(runner_end, false);
        let expected = child.id();
        assert!(child.wait().unwrap().success());
        // Linux: scm_pidfd_recv attaches a stale pidfd for a reaped sender from 6.18 and the
        // negative errno of pidfd_prepare (-EINVAL, or -ESRCH on 6.16) in its place before, which
        // must never be taken for a descriptor.
        match verify(broker_end, expected, deadline()) {
            Ok((_stream, pidfd)) => {
                // SAFETY: A zeroed siginfo_t is valid output storage for waitid.
                let mut info = unsafe { core::mem::zeroed::<libc::siginfo_t>() };
                // SAFETY: `info` is writable, and `pidfd` is a live pidfd.
                let waited = unsafe {
                    libc::waitid(
                        libc::P_PIDFD,
                        libc::id_t::try_from(pidfd.as_raw_fd()).unwrap(),
                        &raw mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                assert_eq!(waited, -1);
                assert_eq!(Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
            }
            Err(error) => assert_eq!(error.kind(), ErrorKind::PermissionDenied),
        }
    }

    #[test]
    fn credentials_of_data_sent_before_they_were_enabled_name_no_process() {
        let (broker_end, mut runner_end) = UnixStream::pair().unwrap();
        runner_end.write_all(b"x").unwrap();
        identify_senders(&broker_end, SenderIdentification::Pidfd)
            .or_else(|_| identify_senders(&broker_end, SenderIdentification::ProcessId))
            .unwrap();
        // Linux: data queued before SO_PASSCRED was enabled carries SCM_CREDENTIALS with pid 0
        // and the overflow uid/gid, and no SCM_PIDFD even with SO_PASSPIDFD (probed on 6.18),
        // which must parse without naming a process.
        let QueuedData::Sent { sender, pidfd } = peek_queued_data(&broker_end, 0).unwrap() else {
            panic!("data is queued");
        };
        assert!(matches!(sender, None | Some(0)), "{sender:?}");
        assert!(pidfd.is_none());
        assert_eq!(
            validate_peer_process_id(sender.unwrap_or(0))
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn missing_sender_pidfds_are_denied_unless_the_broker_ran_out_of_descriptors() {
        let kind = |error: libc::c_int| {
            sender_pidfd(Some(Err(Error::from_raw_os_error(error))))
                .unwrap_err()
                .kind()
        };
        assert_eq!(kind(libc::EINVAL), ErrorKind::PermissionDenied);
        assert_eq!(kind(libc::ESRCH), ErrorKind::PermissionDenied);
        assert_eq!(
            sender_pidfd(None).unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            sender_pidfd(Some(Err(Error::from_raw_os_error(libc::EMFILE))))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EMFILE)
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
