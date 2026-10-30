// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local (guest-side) endpoints of a Unix-domain-socket broker association.
//!
//! The matching host endpoints live in the sibling `host` module, and both
//! sides share the crate-private `setup` framing. Once negotiated, the
//! association runs on the shared [`ring_association`] endpoints over a POSIX
//! shared-memory control ring. Portable broker interfaces live in the no_std
//! protocol, transport, local, core, and host crates.

use std::io::{Error, Result as IoResult};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use litebox_broker_protocol::message::{BrokerHandshakeRequest, BrokerHandshakeResponse};
use litebox_broker_protocol::wire::{decode_handshake_response, encode_handshake_request};
use litebox_broker_transport::channel::LocalSetupChannel;
use litebox_broker_transport::control_ring::{ControlRing, ControlRingLayout};
use litebox_broker_transport::ring_association::{
    self, ControlRingLocalCallChannel, ControlRingLocalNotificationChannel,
    ControlRingLocalShutdown,
};

use crate::setup::{
    UnixAssociationStream, invalid_data, read_setup_frame, wire_error, write_setup_frame,
};
use crate::shared_memory::MacosSharedMemory;
use crate::unix_io::io_timeout_for_deadline;

/// Local-side broker association setup channel over a Unix stream.
pub struct UnixStreamLocalSetupChannel {
    stream: UnixStream,
    setup_deadline: Option<Instant>,
    negotiated: bool,
}

/// Call-issuing endpoint of an active local Unix-socket association.
pub type UnixControlRingLocalCallChannel = ControlRingLocalCallChannel<MacosSharedMemory>;

/// Local notification receiver of an active Unix-socket association.
pub type UnixControlRingLocalNotificationChannel =
    ControlRingLocalNotificationChannel<MacosSharedMemory>;

/// Independently owned handle for interrupting all local active-ring I/O.
pub struct UnixControlRingLocalShutdown {
    shutdown: ControlRingLocalShutdown<MacosSharedMemory>,
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

    /// Connects to a userland broker Unix socket.
    pub fn connect(path: impl AsRef<Path>) -> IoResult<Self> {
        UnixStream::connect(path).map(Self::from_connected)
    }

    /// Connects to a userland broker Unix socket with an absolute deadline for
    /// the connection and subsequent setup I/O.
    ///
    /// A macOS Unix-domain `connect` never waits for the listener: it either
    /// joins the listen queue at once or fails, with `ECONNREFUSED` when the
    /// queue is full. So only an already expired deadline is checked here, and
    /// callers retry failed attempts until their deadline.
    pub fn connect_with_setup_deadline(
        path: impl AsRef<Path>,
        deadline: Instant,
    ) -> IoResult<Self> {
        io_timeout_for_deadline(deadline)?;
        UnixStream::connect(path).map(|stream| Self {
            stream,
            setup_deadline: Some(deadline),
            negotiated: false,
        })
    }

    /// Receives one byte-copy shared-memory resource offered by the broker
    /// during setup.
    pub fn receive_shared_memory(
        &mut self,
        expected_len: usize,
        deadline: Option<Instant>,
    ) -> IoResult<MacosSharedMemory> {
        crate::shared_memory::receive_shared_memory(&mut self.stream, expected_len, deadline)
    }

    /// Receives the control-ring shared memory with `layout` offered by the
    /// broker during setup.
    pub fn receive_control_ring(
        &mut self,
        layout: ControlRingLayout,
        deadline: Option<Instant>,
    ) -> IoResult<MacosSharedMemory> {
        crate::shared_memory::receive_control_ring(&mut self.stream, layout, deadline)
    }

    /// Consumes a negotiated setup channel into independently usable active
    /// call, notification, and shutdown handles, starting the liveness
    /// monitor.
    ///
    /// The ring must be the control-ring shared memory received during this
    /// setup exchange, with a layout of more than one lane.
    pub fn into_active(
        self,
        ring: ControlRing<MacosSharedMemory>,
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
    use litebox_broker_protocol::message::{BrokerOperation, BrokerRequest};
    use litebox_broker_protocol::wire::{
        decode_handshake_request, decode_request, encode_handshake_response,
    };
    use litebox_broker_protocol::{ObjectHandle, RequestId};
    use litebox_broker_transport::channel::{LocalCallChannel, LocalSetupChannel};
    use litebox_broker_transport::control_ring::{
        ControlRingConsumer, ControlRingReadStatus, HostControlRingEndpoints,
    };
    use rustix::fs::{OFlags, fcntl_getfl};
    use std::io::{ErrorKind, Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    type Consumer = ControlRingConsumer<MacosSharedMemory>;
    type Broker = HostControlRingEndpoints<MacosSharedMemory>;

    const LAYOUT: ControlRingLayout = ControlRingLayout::MULTI_LANE;

    /// A socket path in a fresh temporary directory, short enough for the
    /// 104-byte `sun_path` limit under the long macOS `$TMPDIR`.
    fn test_socket_path() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::Builder::new()
            .prefix("litebox-connect-")
            .tempdir()
            .unwrap();
        let path = directory.path().join("s");
        (directory, path)
    }

    /// Binds a listener at `path` and fills its listen queue.
    fn saturated_listener(path: &Path) -> (UnixListener, Vec<UnixStream>) {
        let listener = UnixListener::bind(path).unwrap();
        rustix::net::listen(&listener, 0).unwrap();
        let mut queued = Vec::new();
        for _ in 0..1024 {
            match UnixStream::connect(path) {
                Ok(stream) => queued.push(stream),
                Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
                    return (listener, queued);
                }
                Err(error) => panic!("unexpected queue-filling connect error: {error}"),
            }
        }
        panic!("failed to saturate Unix listener queue");
    }

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

    fn request(id: u64) -> BrokerRequest {
        BrokerRequest {
            request_id: RequestId(id),
            operation: BrokerOperation::CloseObject(ObjectHandle(id)),
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
    fn local_socket_eof_and_shutdown_wake_waiting_calls() {
        for close_peer in [false, true] {
            let (channel, _notifications, shutdown, mut broker, peer) = activate_local(|| {});
            let caller = thread::spawn(move || channel.call(request(1)));
            read_request(&mut broker.lanes[0].request_consumer);
            if close_peer {
                drop(peer);
            } else {
                shutdown.shutdown().unwrap();
            }
            assert!(caller.join().unwrap().is_err());
        }
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
    fn initial_connect_fails_promptly_on_a_full_queue_and_succeeds_once_drained() {
        let (_directory, path) = test_socket_path();
        let (listener, _queued) = saturated_listener(&path);
        let deadline = Instant::now() + Duration::from_secs(5);

        let start = Instant::now();
        let Err(error) = UnixStreamLocalSetupChannel::connect_with_setup_deadline(&path, deadline)
        else {
            panic!("connect unexpectedly succeeded while the listen queue was full");
        };
        assert_eq!(error.kind(), ErrorKind::ConnectionRefused);
        assert!(start.elapsed() < Duration::from_secs(1));

        let _accepted = listener.accept().unwrap();
        let channel =
            UnixStreamLocalSetupChannel::connect_with_setup_deadline(&path, deadline).unwrap();
        assert!(
            !fcntl_getfl(&channel.stream)
                .unwrap()
                .contains(OFlags::NONBLOCK)
        );
        assert_eq!(channel.setup_deadline, Some(deadline));
    }

    #[test]
    fn expired_setup_deadline_prevents_connect() {
        let (_directory, path) = test_socket_path();
        let _listener = UnixListener::bind(&path).unwrap();
        let Err(error) =
            UnixStreamLocalSetupChannel::connect_with_setup_deadline(&path, Instant::now())
        else {
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
}
