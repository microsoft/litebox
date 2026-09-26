// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local (guest-side) endpoints of a Unix-domain-socket broker association.
//!
//! The matching host endpoints live in the sibling `host` module, and both
//! sides share the crate-private `setup` framing. Portable broker interfaces
//! live in the no_std protocol, transport, local, core, and host crates.

use std::io::{Error, ErrorKind, Read, Result as IoResult};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use std::{collections::HashMap, thread};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::net::{
    AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with, sockopt,
};

use litebox_broker_protocol::RequestId;
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerRequest,
    BrokerResponse,
};
use litebox_broker_protocol::wire::{
    decode_handshake_response, decode_notification, decode_response, encode_handshake_request,
    encode_request,
};
use litebox_broker_transport::channel::{
    LocalCallChannel, LocalNotificationChannel, LocalSetupChannel,
};
use litebox_broker_transport::control_ring::{
    CONTROL_RING_READY, ControlRing, ControlRingConsumer, ControlRingProducer,
    ControlRingReadError, ControlRingReadStatus, ControlRingWakeHandle, ControlRingWriteStatus,
};

use crate::memfd::MemfdSharedMemory;
use crate::setup::{
    copy_io_error, invalid_data, read_setup_frame, ring_error, shutdown_socket, wire_error,
    write_setup_frame,
};
use crate::unix_io::io_timeout_for_deadline;

const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(10);

/// Maximum number of active calls waiting for broker responses.
pub const MAX_PENDING_CALLS: usize = 64;

/// Local-side broker association setup channel over a Unix stream.
pub struct UnixStreamLocalSetupChannel {
    stream: UnixStream,
    setup_deadline: Option<Instant>,
    negotiated: bool,
}

/// Call-issuing endpoint of an active local control-ring association.
pub struct UnixControlRingLocalCallChannel {
    association: Arc<LocalRingAssociation>,
}

/// Independently owned handle for interrupting all local active-ring I/O.
pub struct UnixControlRingLocalShutdown {
    association: Arc<LocalRingAssociation>,
}

/// State shared by every activated local endpoint of one association: the
/// request producer, the setup socket used for liveness and teardown, pending
/// call tracking, and the wake handles of all three ring directions.
struct LocalRingAssociation {
    request_producer: Mutex<ControlRingProducer<MemfdSharedMemory>>,
    control_stream: UnixStream,
    pending_calls: Arc<PendingCalls>,
    on_failure: Arc<dyn Fn() + Send + Sync>,
    request_wake: ControlRingWakeHandle<MemfdSharedMemory>,
    response_wake: ControlRingWakeHandle<MemfdSharedMemory>,
    notification_wake: ControlRingWakeHandle<MemfdSharedMemory>,
}

/// Local notification receiver for a shared-ring Unix broker association.
pub struct UnixControlRingLocalNotificationChannel {
    consumer: ControlRingConsumer<MemfdSharedMemory>,
    association: Arc<LocalRingAssociation>,
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

    /// Consumes a negotiated setup channel into independently usable active
    /// call, notification, and shutdown handles, starting the response
    /// dispatcher and liveness monitor.
    ///
    /// The ring must be the validated control-ring memfd received during this
    /// setup exchange.
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

        let mut setup_stream = self.stream;
        write_setup_frame(&mut setup_stream, CONTROL_RING_READY, self.setup_deadline)?;
        let Some(ready) = read_setup_frame(&mut setup_stream, self.setup_deadline)? else {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "broker closed before control-ring setup acknowledgement",
            ));
        };
        if ready != CONTROL_RING_READY {
            return Err(invalid_data(
                "broker sent an invalid control-ring setup acknowledgement",
            ));
        }

        let shutdown_stream = setup_stream.try_clone()?;
        let litebox_broker_transport::control_ring::LocalControlRingEndpoints {
            request_producer,
            response_consumer,
            notification_consumer,
        } = ring.into_local();
        let pending_calls = Arc::new(PendingCalls::new());
        let on_failure: Arc<dyn Fn() + Send + Sync> = Arc::new(on_failure);
        let association = Arc::new(LocalRingAssociation {
            request_wake: request_producer.wake_handle(),
            request_producer: Mutex::new(request_producer),
            control_stream: shutdown_stream,
            pending_calls: Arc::clone(&pending_calls),
            on_failure,
            response_wake: response_consumer.wake_handle(),
            notification_wake: notification_consumer.wake_handle(),
        });
        let response_association = Arc::clone(&association);
        if let Err(error) = thread::Builder::new()
            .name("litebox-broker-responses".to_owned())
            .spawn(move || {
                dispatch_responses(response_consumer, response_association);
            })
        {
            let _ = association.fail(error);
            return Err(Error::other("failed to start broker response dispatcher"));
        }
        let monitor_association = Arc::clone(&association);
        if let Err(error) = thread::Builder::new()
            .name("litebox-broker-liveness".to_owned())
            .spawn(move || {
                monitor_local_socket(&mut setup_stream, &monitor_association);
            })
        {
            let _ = association.fail(error);
            return Err(Error::other("failed to start broker liveness monitor"));
        }

        Ok((
            UnixControlRingLocalCallChannel {
                association: Arc::clone(&association),
            },
            UnixControlRingLocalNotificationChannel {
                consumer: notification_consumer,
                association: Arc::clone(&association),
            },
            UnixControlRingLocalShutdown { association },
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
        self.association.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker local association shut down",
        ))
    }
}

impl AsFd for UnixControlRingLocalShutdown {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.association.control_stream.as_fd()
    }
}

impl Drop for UnixControlRingLocalCallChannel {
    fn drop(&mut self) {
        let _ = self.association.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker local call channel dropped",
        ));
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

impl LocalCallChannel for UnixControlRingLocalCallChannel {
    type Error = Error;

    fn call(&self, request: BrokerRequest) -> IoResult<BrokerResponse> {
        let association = &self.association;
        let request_id = request.request_id;
        let pending_call = association.pending_calls.register(request_id)?;
        let request_frame = encode_request(request);

        let write_result = {
            let mut producer = association
                .request_producer
                .lock()
                .expect("broker request writer mutex poisoned");
            loop {
                let write_status = association
                    .pending_calls
                    .run_if_live(|| producer.try_write(&request_frame).map_err(ring_error));
                match write_status {
                    Ok(ControlRingWriteStatus::Written) => {
                        if let Err(error) = producer.wake_consumer() {
                            break Err(error);
                        }
                        break Ok(());
                    }
                    Ok(ControlRingWriteStatus::Full { wait_epoch }) => {
                        if let Err(error) = producer.wait_for_capacity(wait_epoch) {
                            break Err(error);
                        }
                    }
                    Err(error) => break Err(error),
                }
            }
        };
        if let Err(error) = write_result {
            let _ = association.fail(error);
        }

        pending_call.wait()
    }
}

impl LocalNotificationChannel for UnixControlRingLocalNotificationChannel {
    type Error = Error;

    fn recv_notification(&mut self) -> IoResult<Option<BrokerNotification>> {
        loop {
            if let Some(error) = self.association.pending_calls.current_failure() {
                return Err(copy_io_error(&error));
            }
            match self.consumer.try_read(decode_notification) {
                Ok(ControlRingReadStatus::Message(notification)) => {
                    self.association
                        .acknowledge_notification(&mut self.consumer)?;
                    return Ok(Some(notification));
                }
                Ok(ControlRingReadStatus::Empty { wait_epoch }) => {
                    if let Some(error) = self.association.pending_calls.current_failure() {
                        return Err(copy_io_error(&error));
                    }
                    if let Err(error) = self.consumer.wait_for_message(wait_epoch) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.association.fail(error);
                        return result;
                    }
                }
                Err(ControlRingReadError::Ring(error)) => {
                    let error = ring_error(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.association.fail(error);
                    return result;
                }
                Err(ControlRingReadError::Decode(error)) => {
                    let error = wire_error(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.association.fail(error);
                    return result;
                }
            }
        }
    }
}

struct PendingCalls {
    state: Mutex<PendingCallsState>,
    capacity_available: Condvar,
}

struct PendingCallsState {
    calls: HashMap<RequestId, Arc<PendingCall>>,
    failure: Option<Arc<Error>>,
}

struct PendingCall {
    result: Mutex<Option<PendingCallResult>>,
    result_ready: Condvar,
}

enum PendingCallResult {
    Response(BrokerResponse),
    Failure(Arc<Error>),
}

impl PendingCall {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            result_ready: Condvar::new(),
        }
    }

    fn resolve(&self, result: PendingCallResult) {
        let mut stored = self
            .result
            .lock()
            .expect("broker pending-call result mutex poisoned");
        assert!(stored.is_none(), "broker pending call already resolved");
        *stored = Some(result);
        self.result_ready.notify_one();
    }

    fn wait(&self) -> IoResult<BrokerResponse> {
        let mut result = self
            .result
            .lock()
            .expect("broker pending-call result mutex poisoned");
        loop {
            if let Some(result) = result.take() {
                return match result {
                    PendingCallResult::Response(response) => Ok(response),
                    PendingCallResult::Failure(error) => Err(copy_io_error(&error)),
                };
            }
            result = self
                .result_ready
                .wait(result)
                .expect("broker pending-call result mutex poisoned");
        }
    }
}

impl PendingCalls {
    fn new() -> Self {
        Self {
            state: Mutex::new(PendingCallsState {
                calls: HashMap::new(),
                failure: None,
            }),
            capacity_available: Condvar::new(),
        }
    }

    fn register(&self, request_id: RequestId) -> IoResult<Arc<PendingCall>> {
        let pending_call = Arc::new(PendingCall::new());
        let mut state = self.state.lock().expect("broker pending mutex poisoned");
        while state.calls.len() == MAX_PENDING_CALLS && state.failure.is_none() {
            state = self
                .capacity_available
                .wait(state)
                .expect("broker pending mutex poisoned");
        }
        if let Some(error) = state.failure.as_ref() {
            return Err(copy_io_error(error));
        }
        match state.calls.entry(request_id) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Arc::clone(&pending_call));
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(invalid_data("duplicate broker request ID"));
            }
        }
        Ok(pending_call)
    }

    fn complete(&self, response: BrokerResponse) -> IoResult<()> {
        let pending_call = {
            let mut state = self.state.lock().expect("broker pending mutex poisoned");
            if let Some(error) = state.failure.as_ref() {
                return Err(copy_io_error(error));
            }
            let Some(pending_call) = state.calls.remove(&response.request_id) else {
                return Err(invalid_data("broker returned an unknown response ID"));
            };
            self.capacity_available.notify_one();
            pending_call
        };
        pending_call.resolve(PendingCallResult::Response(response));
        Ok(())
    }

    fn record_failure(&self, error: Arc<Error>) -> bool {
        let pending_calls = {
            let mut state = self.state.lock().expect("broker pending mutex poisoned");
            if state.failure.is_some() {
                return false;
            }
            state.failure = Some(Arc::clone(&error));
            let pending_calls = core::mem::take(&mut state.calls);
            self.capacity_available.notify_all();
            pending_calls
        };
        for pending_call in pending_calls.into_values() {
            pending_call.resolve(PendingCallResult::Failure(Arc::clone(&error)));
        }
        true
    }

    fn current_failure(&self) -> Option<Arc<Error>> {
        self.state
            .lock()
            .expect("broker pending mutex poisoned")
            .failure
            .as_ref()
            .map(Arc::clone)
    }

    /// Runs a nonblocking publication while excluding failure recording.
    fn run_if_live<T>(&self, operation: impl FnOnce() -> IoResult<T>) -> IoResult<T> {
        let state = self.state.lock().expect("broker pending mutex poisoned");
        if let Some(error) = state.failure.as_ref() {
            return Err(copy_io_error(error));
        }
        operation()
    }
}

impl LocalRingAssociation {
    fn acknowledge_notification(
        &self,
        consumer: &mut ControlRingConsumer<MemfdSharedMemory>,
    ) -> IoResult<()> {
        let result = self.pending_calls.run_if_live(|| {
            consumer
                .publish_head()
                .map_err(ring_error)
                .and_then(|()| consumer.wake_producer())
        });
        if let Err(error) = result {
            let result = Err(copy_io_error(&error));
            let _ = self.fail(error);
            return result;
        }
        Ok(())
    }

    fn fail(&self, error: Error) -> IoResult<()> {
        let first_failure = self.pending_calls.record_failure(Arc::new(error));
        let request_wake = self.request_wake.interrupt_wait();
        let response_wake = self.response_wake.interrupt_wait();
        let notification_wake = self.notification_wake.interrupt_wait();
        let shutdown_result = shutdown_socket(&self.control_stream);
        if first_failure {
            (self.on_failure)();
        }
        request_wake
            .and(response_wake)
            .and(notification_wake)
            .and(shutdown_result)
    }
}

fn monitor_local_socket(stream: &mut UnixStream, association: &LocalRingAssociation) {
    let error = wait_for_socket_termination(stream, "broker");
    let _ = association.fail(error);
}

fn wait_for_socket_termination(stream: &mut UnixStream, peer: &'static str) -> Error {
    let mut byte = [0];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => {
                return Error::new(
                    ErrorKind::UnexpectedEof,
                    format!("{peer} closed the active broker association"),
                );
            }
            Ok(_) => {
                return invalid_data("peer sent unexpected active control-socket data");
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return error,
        }
    }
}

fn dispatch_responses(
    mut consumer: ControlRingConsumer<MemfdSharedMemory>,
    association: Arc<LocalRingAssociation>,
) {
    loop {
        match consumer.try_read(decode_response) {
            Ok(ControlRingReadStatus::Message(response)) => {
                if let Err(error) = consumer
                    .publish_head()
                    .map_err(ring_error)
                    .and_then(|()| consumer.wake_producer())
                    .and_then(|()| association.pending_calls.complete(response))
                {
                    let _ = association.fail(error);
                    return;
                }
            }
            Ok(ControlRingReadStatus::Empty { wait_epoch }) => {
                if association.pending_calls.current_failure().is_some() {
                    return;
                }
                if let Err(error) = consumer.wait_for_message(wait_epoch) {
                    let _ = association.fail(error);
                    return;
                }
            }
            Err(ControlRingReadError::Ring(error)) => {
                let _ = association.fail(ring_error(error));
                return;
            }
            Err(ControlRingReadError::Decode(error)) => {
                let _ = association.fail(wire_error(error));
                return;
            }
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
    use litebox_broker_transport::channel::{LocalCallChannel, LocalSetupChannel};
    use litebox_broker_transport::control_ring::CONTROL_RING_MEMORY_SIZE;
    use rustix::fs::{OFlags, fcntl_getfl};
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Barrier, mpsc};

    type Producer = ControlRingProducer<MemfdSharedMemory>;
    type Consumer = ControlRingConsumer<MemfdSharedMemory>;

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
        let first = MemfdSharedMemory::create(CONTROL_RING_MEMORY_SIZE).unwrap();
        let second = MemfdSharedMemory::from_received_fd(
            first.as_fd().try_clone_to_owned().unwrap(),
            CONTROL_RING_MEMORY_SIZE,
        )
        .unwrap();
        (
            ControlRing::new(first).unwrap(),
            ControlRing::new(second).unwrap(),
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
        UnixControlRingLocalShutdown,
        Producer,
        Consumer,
        UnixStream,
    ) {
        let (local_stream, peer_stream) = UnixStream::pair().unwrap();
        let mut ack_stream = peer_stream.try_clone().unwrap();
        let acknowledgement = thread::spawn(move || {
            assert_eq!(
                read_setup_frame(&mut ack_stream, None).unwrap().unwrap(),
                CONTROL_RING_READY
            );
            write_setup_frame(&mut ack_stream, CONTROL_RING_READY, None).unwrap();
        });
        let (local_ring, broker_ring) = ring_pair();
        let setup = negotiated_local(local_stream);
        let (channel, _notifications, shutdown) =
            setup.into_active(local_ring, on_failure).unwrap();
        acknowledgement.join().unwrap();
        let litebox_broker_transport::control_ring::BrokerControlRingEndpoints {
            request_consumer,
            response_producer,
            notification_producer: _,
        } = broker_ring.into_broker();
        (
            channel,
            shutdown,
            response_producer,
            request_consumer,
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
                ControlRingReadStatus::Empty { wait_epoch } => {
                    consumer.wait_for_message(wait_epoch).unwrap();
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
                ControlRingWriteStatus::Full { wait_epoch } => {
                    producer.wait_for_capacity(wait_epoch).unwrap();
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
                CONTROL_RING_READY
            );
            write_setup_frame(&mut host_stream, CONTROL_RING_READY, None).unwrap();
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
    fn local_matches_out_of_order_ring_responses_without_socket_frames() {
        let (channel, _shutdown, mut responses, mut requests, mut peer) = activate_local(|| {});
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let channel = Arc::new(channel);
        let calls = [3, 7].map(|id| {
            let channel = Arc::clone(&channel);
            thread::spawn(move || channel.call(request(id)))
        });
        let first = read_request(&mut requests);
        let second = read_request(&mut requests);

        write_payload(
            &mut responses,
            &encode_response(response(second.request_id)),
        );
        write_payload(&mut responses, &encode_response(response(first.request_id)));
        for call in calls {
            assert!(call.join().unwrap().is_ok());
        }
        let mut byte = [0];
        assert!(matches!(
            peer.read(&mut byte).unwrap_err().kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut
        ));
    }

    #[test]
    fn pending_capacity_blocks_before_sixty_fifth_publication() {
        let (channel, shutdown, mut responses, mut requests, _peer) = activate_local(|| {});
        let channel = Arc::new(channel);
        let start = Arc::new(Barrier::new(MAX_PENDING_CALLS + 2));
        let callers = (0..=MAX_PENDING_CALLS)
            .map(|id| {
                let channel = Arc::clone(&channel);
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    channel.call(request(id as u64))
                })
            })
            .collect::<Vec<_>>();
        start.wait();

        let mut published = Vec::new();
        for _ in 0..MAX_PENDING_CALLS {
            published.push(read_request(&mut requests).request_id);
        }
        write_payload(&mut responses, &encode_response(response(published[0])));
        let released = read_request(&mut requests).request_id;
        assert!(!published.contains(&released));

        shutdown.shutdown().unwrap();
        let completed = callers
            .into_iter()
            .map(|caller| usize::from(caller.join().unwrap().is_ok()))
            .sum::<usize>();
        assert_eq!(completed, 1);
    }

    #[test]
    fn unknown_duplicate_and_malformed_responses_fail_closed() {
        for payload_kind in 0..3 {
            let failures = Arc::new(AtomicUsize::new(0));
            let callback_failures = Arc::clone(&failures);
            let (failure_reported, wait_for_failure) = mpsc::channel();
            let (channel, _shutdown, mut responses, mut requests, _peer) =
                activate_local(move || {
                    callback_failures.fetch_add(1, Ordering::SeqCst);
                    failure_reported.send(()).unwrap();
                });
            let channel = Arc::new(channel);
            let calls = [1, 2].map(|id| {
                let channel = Arc::clone(&channel);
                thread::spawn(move || channel.call(request(id)))
            });
            read_request(&mut requests);
            read_request(&mut requests);

            match payload_kind {
                0 => write_payload(&mut responses, &encode_response(response(RequestId(99)))),
                1 => {
                    let duplicate = encode_response(response(RequestId(1)));
                    write_payload(&mut responses, &duplicate);
                    write_payload(&mut responses, &duplicate);
                }
                _ => write_payload(&mut responses, &[u8::MAX]),
            }

            let results = calls.map(|call| call.join().unwrap());
            let error_count = results.iter().filter(|result| result.is_err()).count();
            assert_eq!(error_count, if payload_kind == 1 { 1 } else { 2 });
            wait_for_failure
                .recv_timeout(Duration::from_secs(1))
                .expect("failure callback was not invoked");
            assert_eq!(failures.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn local_socket_eof_and_shutdown_wake_pending_calls() {
        for close_peer in [false, true] {
            let (channel, shutdown, _responses, mut requests, peer) = activate_local(|| {});
            let caller = thread::spawn(move || channel.call(request(1)));
            read_request(&mut requests);
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
    fn completed_call_wins_over_later_failure_and_failure_wins_before_completion() {
        let pending = PendingCalls::new();
        let completed = pending.register(RequestId(1)).unwrap();
        pending.complete(response(RequestId(1))).unwrap();
        pending.record_failure(Arc::new(Error::new(
            ErrorKind::ConnectionAborted,
            "test failure",
        )));
        assert_eq!(completed.wait().unwrap().request_id, RequestId(1));

        let pending = PendingCalls::new();
        let failed = pending.register(RequestId(2)).unwrap();
        pending.record_failure(Arc::new(Error::new(
            ErrorKind::ConnectionAborted,
            "test failure",
        )));
        assert!(pending.complete(response(RequestId(2))).is_err());
        assert_eq!(
            failed.wait().unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
    }

    #[test]
    fn failure_recording_waits_for_in_progress_publication() {
        let pending = Arc::new(PendingCalls::new());
        let pending_call = pending.register(RequestId(1)).unwrap();
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
            failure_pending.record_failure(Arc::new(Error::new(
                ErrorKind::ConnectionAborted,
                "test failure",
            )));
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
        assert_eq!(
            pending_call.wait().unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
    }

    #[test]
    fn duplicate_pending_registration_preserves_original() {
        let pending = PendingCalls::new();
        let original = pending.register(RequestId(1)).unwrap();
        let Err(error) = pending.register(RequestId(1)) else {
            panic!("duplicate registration unexpectedly succeeded");
        };
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        pending.complete(response(RequestId(1))).unwrap();
        assert_eq!(original.wait().unwrap().request_id, RequestId(1));
    }
}
