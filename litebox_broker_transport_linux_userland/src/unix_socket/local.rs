// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local (guest-side) endpoints of a Unix-domain-socket broker association.
//!
//! The matching host endpoints live in the sibling `host` module, and both
//! sides share the crate-private `setup` framing. Once negotiated, the
//! association runs on the shared [`ring_association`] endpoints over a memfd
//! control ring. Portable broker interfaces live in the no_std protocol,
//! transport, local, core, and host crates.

use std::io::{Error, ErrorKind, Result as IoResult};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::net::{
    AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with, sockopt,
};

use litebox_broker_protocol::message::{BrokerHandshakeRequest, BrokerHandshakeResponse};
use litebox_broker_protocol::wire::{decode_handshake_response, encode_handshake_request};
use litebox_broker_transport::channel::LocalSetupChannel;
use litebox_broker_transport::control_ring::{ControlRing, ControlRingLayout};
use litebox_broker_transport::ring_association::{
    self, ControlRingLocalCallChannel, ControlRingLocalNotificationChannel,
    ControlRingLocalShutdown,
};

use crate::memfd::MemfdSharedMemory;
use crate::setup::{
    UnixAssociationStream, invalid_data, read_setup_frame, wire_error, write_setup_frame,
};
use crate::unix_io::io_timeout_for_deadline;

const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(10);

/// Local-side broker association setup channel over a Unix stream.
pub struct UnixStreamLocalSetupChannel {
    stream: UnixStream,
    setup_deadline: Option<Instant>,
    negotiated: bool,
}

/// Call-issuing endpoint of an active local Unix-socket association.
pub type UnixControlRingLocalCallChannel = ControlRingLocalCallChannel<MemfdSharedMemory>;

/// Local notification receiver of an active Unix-socket association.
pub type UnixControlRingLocalNotificationChannel =
    ControlRingLocalNotificationChannel<MemfdSharedMemory>;

/// Independently owned handle for interrupting all local active-ring I/O.
pub struct UnixControlRingLocalShutdown {
    shutdown: ControlRingLocalShutdown<MemfdSharedMemory>,
    /// The socket descriptor that shutting down the association shuts down.
    stream: Arc<UnixStream>,
}

impl UnixStreamLocalSetupChannel {
    /// Creates a local setup channel from an already-connected Unix stream.
    pub const fn from_connected(stream: UnixStream) -> Self {
        Self {
            stream,
            setup_deadline: None,
            negotiated: false,
        }
    }

    /// Creates a local setup channel from an already-connected Unix stream, with an absolute
    /// deadline for setup I/O.
    pub const fn from_connected_with_setup_deadline(stream: UnixStream, deadline: Instant) -> Self {
        Self {
            stream,
            setup_deadline: Some(deadline),
            negotiated: false,
        }
    }

    /// Connects to a userland broker Unix socket.
    pub fn connect(path: impl AsRef<Path>) -> IoResult<Self> {
        UnixStream::connect(path).map(Self::from_connected)
    }

    /// Connects to a userland broker Unix socket with an absolute deadline for
    /// the connection and subsequent setup I/O.
    pub fn connect_with_setup_deadline(
        path: impl AsRef<Path>,
        deadline: Instant,
    ) -> IoResult<Self> {
        connect_with_deadline(path.as_ref(), deadline).map(|stream| Self {
            stream,
            setup_deadline: Some(deadline),
            negotiated: false,
        })
    }

    /// Receives one memfd offered by the broker during setup.
    pub fn receive_memfd(
        &mut self,
        expected_len: usize,
        deadline: Option<Instant>,
    ) -> IoResult<MemfdSharedMemory> {
        crate::memfd::receive_memfd(&mut self.stream, expected_len, deadline)
    }

    /// Receives the control-ring memfd with `layout` offered by the broker
    /// during setup.
    pub fn receive_control_ring(
        &mut self,
        layout: ControlRingLayout,
        deadline: Option<Instant>,
    ) -> IoResult<MemfdSharedMemory> {
        crate::memfd::receive_control_ring_memfd(&mut self.stream, layout, deadline)
    }

    /// Receives the optional process image offered by the broker during
    /// setup, after the control ring.
    pub fn receive_process_image(
        &mut self,
        deadline: Option<Instant>,
    ) -> IoResult<Option<OwnedFd>> {
        crate::memfd::receive_process_image(&mut self.stream, deadline)
    }

    /// Consumes a negotiated setup channel into independently usable active
    /// call, notification, and shutdown handles, starting the liveness
    /// monitor.
    ///
    /// The ring must be the control-ring memfd received during this
    /// setup exchange, with a layout of more than one lane.
    pub fn into_active(
        self,
        ring: ControlRing<MemfdSharedMemory>,
        on_failure: impl Fn() + Send + Sync + 'static,
    ) -> IoResult<(
        UnixControlRingLocalCallChannel,
        UnixControlRingLocalNotificationChannel,
        UnixControlRingLocalShutdown,
    )> {
        if !self.negotiated {
            return Err(invalid_data(
                "broker local setup channel activated before negotiation completed",
            ));
        }
        let stream = UnixAssociationStream::new(self.stream, self.setup_deadline)?;
        let shutdown_stream = stream.shutdown_stream();
        let (calls, notifications, shutdown) =
            ring_association::activate_local(ring, Box::new(stream), on_failure)?;
        Ok((
            calls,
            notifications,
            UnixControlRingLocalShutdown {
                shutdown,
                stream: shutdown_stream,
            },
        ))
    }
}

fn connect_with_deadline(path: &Path, deadline: Instant) -> IoResult<UnixStream> {
    io_timeout_for_deadline(deadline)?;
    let address = SocketAddrUnix::new(path)?;
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;

    loop {
        let remaining = io_timeout_for_deadline(deadline)?;
        match connect(&socket, &address) {
            Ok(()) | Err(Errno::ISCONN) => break,
            Err(Errno::INTR) => {}
            // Linux reports a full Unix-domain listen queue as EAGAIN without
            // starting a connection. Polling this socket would falsely report
            // it writable with no SO_ERROR, so retry connect instead.
            Err(Errno::AGAIN) => thread::sleep(CONNECT_RETRY_DELAY.min(remaining)),
            Err(Errno::INPROGRESS | Errno::ALREADY) => {
                wait_for_nonblocking_connect(&socket, deadline)?;
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }

    let stream = UnixStream::from(socket);
    stream.set_nonblocking(false)?;
    io_timeout_for_deadline(deadline)?;
    Ok(stream)
}

fn wait_for_nonblocking_connect(socket: &OwnedFd, deadline: Instant) -> IoResult<()> {
    loop {
        let remaining = io_timeout_for_deadline(deadline)?;
        let timeout = Timespec::try_from(remaining).map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                "broker setup deadline is too distant",
            )
        })?;
        let mut poll_fd = [PollFd::new(socket, PollFlags::OUT)];
        match poll(&mut poll_fd, Some(&timeout)) {
            Ok(0) | Err(Errno::INTR) => {}
            Ok(_) => match sockopt::socket_error(socket)? {
                Ok(()) => return Ok(()),
                Err(error) => return Err(error.into()),
            },
            Err(error) => return Err(error.into()),
        }
    }
}

impl UnixControlRingLocalShutdown {
    /// Shuts down the active association, unblocking ring and socket waits.
    pub fn shutdown(&self) -> IoResult<()> {
        self.shutdown.shutdown()
    }
}

/// Exposes the socket descriptor that [`shutdown`](Self::shutdown) shuts down.
impl AsFd for UnixControlRingLocalShutdown {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }
}

impl LocalSetupChannel for UnixStreamLocalSetupChannel {
    type Error = Error;

    fn send_handshake_request(&mut self, request: &BrokerHandshakeRequest) -> IoResult<()> {
        let frame = encode_handshake_request(request.clone());
        write_setup_frame(&mut self.stream, &frame, self.setup_deadline)
    }

    fn recv_handshake_response(&mut self) -> IoResult<Option<BrokerHandshakeResponse>> {
        let frame = read_setup_frame(&mut self.stream, self.setup_deadline)?;
        match frame {
            Some(frame) => {
                let response = decode_handshake_response(&frame).map_err(wire_error)?;
                self.negotiated = matches!(&response, BrokerHandshakeResponse::Negotiated { .. });
                Ok(Some(response))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod control_ring_tests {
    use super::*;
    use litebox_broker_protocol::message::{
        BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult,
    };
    use litebox_broker_protocol::wire::{
        decode_handshake_request, decode_request, encode_handshake_response, encode_response,
    };
    use litebox_broker_protocol::{ObjectHandle, RequestId};
    use litebox_broker_transport::call_lane_pool::LocalCallLanePool;
    use litebox_broker_transport::channel::{
        LocalCallChannel, LocalNotificationChannel, LocalSetupChannel,
    };
    use litebox_broker_transport::control_ring::{
        ControlRingConsumer, ControlRingDemandStatus, ControlRingProducer, ControlRingReadStatus,
        ControlRingWriteStatus, HostControlRingEndpoints,
    };
    use rustix::fs::{OFlags, fcntl_getfl};
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    type Producer = ControlRingProducer<MemfdSharedMemory>;
    type Consumer = ControlRingConsumer<MemfdSharedMemory>;
    type Broker = HostControlRingEndpoints<MemfdSharedMemory>;

    const LAYOUT: ControlRingLayout = ControlRingLayout::MULTI_LANE;

    struct TestSocketPath(PathBuf);

    impl TestSocketPath {
        fn new() -> Self {
            static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);
            Self(std::env::temp_dir().join(format!(
                "litebox-broker-connect-{}-{}",
                std::process::id(),
                NEXT_PATH.fetch_add(1, Ordering::Relaxed)
            )))
        }

        fn as_path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestSocketPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn saturated_listener() -> (TestSocketPath, UnixListener, Vec<std::os::fd::OwnedFd>) {
        let path = TestSocketPath::new();
        let listener = UnixListener::bind(path.as_path()).unwrap();
        rustix::net::listen(&listener, 0).unwrap();
        let address = SocketAddrUnix::new(path.as_path()).unwrap();
        let mut queued = Vec::new();
        for _ in 0..1024 {
            let socket = socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )
            .unwrap();
            match connect(&socket, &address) {
                Ok(()) => queued.push(socket),
                Err(Errno::AGAIN) => return (path, listener, queued),
                Err(error) => panic!("unexpected queue-filling connect error: {error}"),
            }
        }
        panic!("failed to saturate Unix listener queue");
    }

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

    fn negotiated_local(stream: UnixStream) -> UnixStreamLocalSetupChannel {
        UnixStreamLocalSetupChannel {
            stream,
            setup_deadline: Some(Instant::now() + Duration::from_secs(2)),
            negotiated: true,
        }
    }

    fn activate_local(
        on_failure: impl Fn() + Send + Sync + 'static,
    ) -> (
        UnixControlRingLocalCallChannel,
        UnixControlRingLocalNotificationChannel,
        UnixControlRingLocalShutdown,
        Broker,
        UnixStream,
    ) {
        let (local_stream, peer_stream) = UnixStream::pair().unwrap();
        let mut ack_stream = peer_stream.try_clone().unwrap();
        let acknowledgement = thread::spawn(move || {
            assert_eq!(
                read_setup_frame(&mut ack_stream, None).unwrap().unwrap(),
                LAYOUT.ready_token()
            );
            write_setup_frame(&mut ack_stream, LAYOUT.ready_token(), None).unwrap();
        });
        let (local_ring, broker_ring) = ring_pair();
        let setup = negotiated_local(local_stream);
        let (channel, notifications, shutdown) = setup.into_active(local_ring, on_failure).unwrap();
        acknowledgement.join().unwrap();
        (
            channel,
            notifications,
            shutdown,
            broker_ring.into_host(),
            peer_stream,
        )
    }

    fn read_request(consumer: &mut Consumer) -> BrokerRequest {
        loop {
            match consumer.try_read(decode_request).unwrap() {
                ControlRingReadStatus::Message(request) => {
                    consumer.publish_head().unwrap();
                    consumer.wake_producer().unwrap();
                    return request;
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
    fn local_setup_rejects_activation_before_negotiation() {
        let (local_stream, _host_stream) = UnixStream::pair().unwrap();
        let setup = UnixStreamLocalSetupChannel::from_connected(local_stream);
        let (ring, _) = ring_pair();
        let Err(error) = setup.into_active(ring, || {}) else {
            panic!("local setup channel activated before negotiation");
        };
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn local_setup_negotiates_then_activates_and_closes_on_drop() {
        let (local_stream, mut host_stream) = UnixStream::pair().unwrap();
        let mut setup = UnixStreamLocalSetupChannel::from_connected(local_stream);

        let handshake_request = BrokerHandshakeRequest {
            protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
        };
        setup.send_handshake_request(&handshake_request).unwrap();
        assert_eq!(
            decode_handshake_request(&read_setup_frame(&mut host_stream, None).unwrap().unwrap())
                .unwrap(),
            handshake_request
        );
        write_setup_frame(
            &mut host_stream,
            &encode_handshake_response(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
                process_id: litebox_broker_protocol::ProcessId(1),
                initial_thread_id: litebox_broker_protocol::ThreadId(2),
                startup: None,
            }),
            None,
        )
        .unwrap();
        assert!(matches!(
            setup.recv_handshake_response().unwrap(),
            Some(BrokerHandshakeResponse::Negotiated { .. })
        ));

        let acknowledgement = thread::spawn(move || {
            assert_eq!(
                read_setup_frame(&mut host_stream, None).unwrap().unwrap(),
                LAYOUT.ready_token()
            );
            write_setup_frame(&mut host_stream, LAYOUT.ready_token(), None).unwrap();
            host_stream
        });
        let (ring, _) = ring_pair();
        let (call_channel, _notifications, _shutdown) = setup.into_active(ring, || {}).unwrap();
        let mut host_stream = acknowledgement.join().unwrap();

        host_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        drop(call_channel);
        let mut byte = [0];
        assert_eq!(host_stream.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn single_lane_layouts_are_rejected() {
        let layout = ControlRingLayout::SINGLE_LANE;
        let memory = MemfdSharedMemory::create_control_ring(layout).unwrap();
        let (local_stream, _peer) = UnixStream::pair().unwrap();
        let Err(error) = negotiated_local(local_stream)
            .into_active(ControlRing::new(memory, layout).unwrap(), || {})
        else {
            panic!("a single-lane layout was activated");
        };
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn concurrent_calls_use_separate_lanes_without_socket_frames() {
        let (channel, _notifications, _shutdown, mut broker, mut peer) = activate_local(|| {});
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let channel = Arc::new(channel);
        let calls = [3, 7].map(|id| {
            let channel = Arc::clone(&channel);
            thread::spawn(move || channel.call(request(id)))
        });
        let demand = broker.lane_demand.as_mut().unwrap();
        assert_eq!(demand.try_next_lane(), Ok(ControlRingDemandStatus::Lane(0)));
        loop {
            match demand.try_next_lane().unwrap() {
                ControlRingDemandStatus::Lane(lane) => {
                    assert_eq!(lane, 1);
                    break;
                }
                ControlRingDemandStatus::Satisfied { wake_count } => {
                    demand.wait_for_demand(wake_count).unwrap();
                }
            }
        }
        let first = read_request(&mut broker.lanes[0].request_consumer);
        let second = read_request(&mut broker.lanes[1].request_consumer);

        // The later lane answers first; neither call waits for the other.
        write_payload(
            &mut broker.lanes[1].response_producer,
            &encode_response(response(second.request_id)),
        );
        write_payload(
            &mut broker.lanes[0].response_producer,
            &encode_response(response(first.request_id)),
        );
        for call in calls {
            assert!(call.join().unwrap().is_ok());
        }
        assert!(matches!(
            demand.try_next_lane(),
            Ok(ControlRingDemandStatus::Satisfied { .. })
        ));
        let mut byte = [0];
        assert!(matches!(
            peer.read(&mut byte).unwrap_err().kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut
        ));
    }

    #[test]
    fn sequential_calls_reuse_the_first_lane() {
        let (channel, _notifications, _shutdown, mut broker, _peer) = activate_local(|| {});
        let channel = Arc::new(channel);
        for id in 1..=3 {
            let caller = {
                let channel = Arc::clone(&channel);
                thread::spawn(move || channel.call(request(id)))
            };
            let lane = &mut broker.lanes[0];
            let request = read_request(&mut lane.request_consumer);
            assert_eq!(request.request_id, RequestId(id));
            write_payload(
                &mut lane.response_producer,
                &encode_response(response(request.request_id)),
            );
            assert_eq!(caller.join().unwrap().unwrap().request_id, RequestId(id));
        }
        let demand = broker.lane_demand.as_mut().unwrap();
        assert_eq!(demand.try_next_lane(), Ok(ControlRingDemandStatus::Lane(0)));
        assert!(matches!(
            demand.try_next_lane(),
            Ok(ControlRingDemandStatus::Satisfied { .. })
        ));
    }

    #[test]
    fn mismatched_and_malformed_responses_fail_closed() {
        for payload_kind in 0..3 {
            let failures = Arc::new(AtomicUsize::new(0));
            let callback_failures = Arc::clone(&failures);
            let (failure_reported, wait_for_failure) = mpsc::channel();
            let (channel, _notifications, _shutdown, mut broker, _peer) =
                activate_local(move || {
                    callback_failures.fetch_add(1, Ordering::SeqCst);
                    failure_reported.send(()).unwrap();
                });
            let channel = Arc::new(channel);
            let calls = [1, 2].map(|id| {
                let channel = Arc::clone(&channel);
                thread::spawn(move || channel.call(request(id)))
            });
            read_request(&mut broker.lanes[0].request_consumer);
            let other = read_request(&mut broker.lanes[1].request_consumer);

            let producer = &mut broker.lanes[0].response_producer;
            match payload_kind {
                0 => write_payload(producer, &encode_response(response(RequestId(99)))),
                1 => write_payload(producer, &encode_response(response(other.request_id))),
                _ => write_payload(producer, &[u8::MAX]),
            }

            for call in calls {
                assert!(call.join().unwrap().is_err());
            }
            wait_for_failure
                .recv_timeout(Duration::from_secs(1))
                .expect("failure callback was not invoked");
            assert_eq!(failures.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn local_socket_eof_and_shutdown_wake_waiting_calls() {
        for close_peer in [false, true] {
            let (channel, _notifications, shutdown, mut broker, peer) = activate_local(|| {});
            let channel = Arc::new(channel);
            let call = |id| {
                let channel = Arc::clone(&channel);
                thread::spawn(move || channel.call(request(id)))
            };
            let callers: Vec<_> = (0..LAYOUT.lane_count() as u64).map(call).collect();
            for lane in &mut broker.lanes {
                read_request(&mut lane.request_consumer);
            }
            // Every lane is held, so this call waits to claim one.
            let waiting = call(u64::MAX);
            thread::sleep(Duration::from_millis(10));
            if close_peer {
                drop(peer);
            } else {
                shutdown.shutdown().unwrap();
            }
            for caller in callers {
                assert!(caller.join().unwrap().is_err());
            }
            assert!(waiting.join().unwrap().is_err());
        }
    }

    #[test]
    fn dropping_the_call_channel_ends_notifications_cleanly() {
        let (channel, mut notifications, _shutdown, _broker, _peer) = activate_local(|| {});
        let receiver = thread::spawn(move || notifications.recv_notification());
        drop(channel);
        assert!(receiver.join().unwrap().unwrap().is_none());
    }

    #[test]
    fn ready_ack_uses_absolute_setup_deadline() {
        let (local_stream, _peer) = UnixStream::pair().unwrap();
        let (ring, _) = ring_pair();
        let local = UnixStreamLocalSetupChannel {
            stream: local_stream,
            setup_deadline: Some(Instant::now() + Duration::from_millis(30)),
            negotiated: true,
        };
        let Err(error) = local.into_active(ring, || {}) else {
            panic!("activation unexpectedly succeeded");
        };
        assert!(matches!(
            error.kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut
        ));
    }

    #[test]
    fn initial_connect_uses_absolute_setup_deadline() {
        let (path, listener, _queued) = saturated_listener();
        let deadline = Instant::now() + Duration::from_millis(50);
        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(0);
        let connector = thread::spawn(move || {
            result_sender
                .send(UnixStreamLocalSetupChannel::connect_with_setup_deadline(
                    path.as_path(),
                    deadline,
                ))
                .unwrap();
        });

        let result = match result_receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(result) => result,
            Err(error) => {
                // Release a queue slot so a regressed blocking connect can
                // finish instead of leaving the test process stuck.
                listener.accept().unwrap();
                let _ = result_receiver.recv_timeout(Duration::from_secs(1));
                connector.join().unwrap();
                panic!("connect did not honor its setup deadline: {error}");
            }
        };
        connector.join().unwrap();
        let Err(error) = result else {
            panic!("connect unexpectedly succeeded while the listen queue was full");
        };
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }

    #[test]
    fn initial_connect_retries_a_full_queue_and_restores_blocking_mode() {
        let (path, listener, _queued) = saturated_listener();
        let deadline = Instant::now() + Duration::from_secs(2);
        let connector = thread::spawn(move || {
            UnixStreamLocalSetupChannel::connect_with_setup_deadline(path.as_path(), deadline)
        });
        thread::sleep(Duration::from_millis(30));
        let _accepted = listener.accept().unwrap();

        let channel = connector.join().unwrap().unwrap();
        assert!(
            !fcntl_getfl(&channel.stream)
                .unwrap()
                .contains(OFlags::NONBLOCK)
        );
        assert_eq!(channel.setup_deadline, Some(deadline));
    }

    #[test]
    fn expired_setup_deadline_prevents_connect() {
        let path = TestSocketPath::new();
        let Err(error) = UnixStreamLocalSetupChannel::connect_with_setup_deadline(
            path.as_path(),
            Instant::now(),
        ) else {
            panic!("connect unexpectedly accepted an expired setup deadline");
        };
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }

    #[test]
    fn handshake_reads_use_absolute_setup_deadlines() {
        let (mut host_stream, local_stream) = UnixStream::pair().unwrap();
        let mut local = UnixStreamLocalSetupChannel {
            stream: local_stream,
            setup_deadline: Some(Instant::now() + Duration::from_millis(50)),
            negotiated: false,
        };
        let local_reader = thread::spawn(move || local.recv_handshake_response().unwrap_err());
        host_stream.write_all(&8u32.to_le_bytes()).unwrap();
        for _ in 0..8 {
            thread::sleep(Duration::from_millis(20));
            if host_stream.write_all(&[0]).is_err() {
                break;
            }
        }
        let error = local_reader.join().unwrap();
        assert!(
            matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
            "unexpected local timeout error: {error:?}"
        );
    }

    #[test]
    fn failure_recording_waits_for_in_progress_publication() {
        let pending = Arc::new(LocalCallLanePool::new(vec![()]));
        let publication_state = Arc::new(AtomicUsize::new(0));
        let (publication_started, wait_for_publication) = std::sync::mpsc::sync_channel(0);
        let (release_publication, publication_released) = std::sync::mpsc::sync_channel(0);
        let publisher_pending = Arc::clone(&pending);
        let publisher_state = Arc::clone(&publication_state);
        let publisher = thread::spawn(move || {
            publisher_pending
                .run_if_live(|| {
                    publisher_state.store(1, Ordering::Release);
                    publication_started.send(()).unwrap();
                    publication_released.recv().unwrap();
                    publisher_state.store(2, Ordering::Release);
                    Ok(())
                })
                .unwrap();
        });
        wait_for_publication.recv().unwrap();

        let (failure_started, wait_for_failure) = std::sync::mpsc::sync_channel(0);
        let (failure_recorded, wait_for_recording) = std::sync::mpsc::sync_channel(0);
        let failure_pending = Arc::clone(&pending);
        let failure_state = Arc::clone(&publication_state);
        let failure = thread::spawn(move || {
            failure_started.send(()).unwrap();
            failure_pending
                .record_failure(Error::new(ErrorKind::ConnectionAborted, "test failure"));
            assert_eq!(failure_state.load(Ordering::Acquire), 2);
            failure_recorded.send(()).unwrap();
        });
        wait_for_failure.recv().unwrap();
        assert!(matches!(
            wait_for_recording.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        release_publication.send(()).unwrap();
        publisher.join().unwrap();
        wait_for_recording
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        failure.join().unwrap();
        assert!(matches!(
            pending.claim(|_| Ok(())),
            Err(error) if error.kind() == ErrorKind::ConnectionAborted
        ));
    }
}
