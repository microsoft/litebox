// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix-domain-socket broker channel for hosted userland deployments.
//!
//! This module deliberately uses `std` because Unix-domain sockets and `std::io`
//! framing are hosted userland concerns. Portable broker interfaces live in the
//! no_std protocol, local, core, and host crates.
//!
//! After setup, the authenticated socket is retained only for liveness and
//! cancellation. Active requests and responses use a shared control ring.

use std::io::{Error, ErrorKind, Read, Result as IoResult, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;
use std::{collections::HashMap, thread};

use crate::control_ring::{
    ControlRing, ControlRingConsumer, ControlRingError, ControlRingProducer, ControlRingReadError,
    ControlRingReadStatus, ControlRingWakeHandle, ControlRingWriteStatus,
};
use crate::shared_memory::MemfdSharedMemory;
use crate::unix_io::{
    refresh_read_deadline, refresh_write_deadline, with_read_deadline, with_write_deadline,
};
use litebox_broker_protocol::RequestId;
use litebox_broker_protocol::channel::{
    HostNotificationChannel, HostReceive, HostSetupChannel, LocalControlChannel,
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
const CONTROL_RING_READY: &[u8] = b"litebox-control-ring-ready-v1";
/// Maximum number of active calls waiting for broker responses.
pub const MAX_PENDING_CALLS: usize = 64;

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
    state: UnixStreamLocalControlState,
}

enum UnixStreamLocalControlState {
    Setup(UnixStreamLocalSetup),
    Active(UnixStreamLocalActive),
    Failed,
}

struct UnixStreamLocalSetup {
    stream: UnixStream,
    setup_deadline: Option<Instant>,
    negotiated: bool,
}

/// Independently owned handle for interrupting local control-channel I/O.
pub struct UnixStreamLocalControlCancellation {
    failure_coordinator: Arc<LocalActiveFailureCoordinator>,
}

struct UnixStreamLocalActive {
    request_producer: Mutex<crate::control_ring::ControlRingProducer<MemfdSharedMemory>>,
    failure_coordinator: Arc<LocalActiveFailureCoordinator>,
}

struct LocalActiveFailureCoordinator {
    stream: UnixStream,
    pending_calls: Arc<PendingCalls>,
    association_failure: Arc<dyn Fn() + Send + Sync>,
    request_wait: ControlRingWakeHandle<MemfdSharedMemory>,
    response_wait: ControlRingWakeHandle<MemfdSharedMemory>,
}

impl UnixStreamLocalControlChannel {
    /// Creates a local control channel from an already-connected Unix stream.
    pub const fn from_connected(stream: UnixStream) -> Self {
        Self {
            state: UnixStreamLocalControlState::Setup(UnixStreamLocalSetup {
                stream,
                setup_deadline: None,
                negotiated: false,
            }),
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
            state: UnixStreamLocalControlState::Setup(UnixStreamLocalSetup {
                stream,
                setup_deadline: Some(deadline),
                negotiated: false,
            }),
        })
    }

    /// Receives the memfd associated with this control channel.
    pub fn receive_memfd(
        &mut self,
        expected_len: usize,
        deadline: Option<Instant>,
    ) -> IoResult<MemfdSharedMemory> {
        let UnixStreamLocalControlState::Setup(setup) = &mut self.state else {
            return Err(invalid_data("broker control setup already completed"));
        };
        crate::shared_memory::receive_memfd(&mut setup.stream, expected_len, deadline)
    }

    /// Completes setup and starts the active control-ring response pump.
    ///
    /// The ring must be the validated control-ring memfd received during this
    /// setup exchange.
    pub fn activate(
        &mut self,
        ring: ControlRing<MemfdSharedMemory>,
        association_failure: impl Fn() + Send + Sync + 'static,
    ) -> IoResult<UnixStreamLocalControlCancellation> {
        let UnixStreamLocalControlState::Setup(setup) = &self.state else {
            return Err(invalid_data("broker control channel already active"));
        };
        if !setup.negotiated {
            return Err(invalid_data(
                "broker control channel activated before negotiation completed",
            ));
        }
        let UnixStreamLocalControlState::Setup(setup) =
            core::mem::replace(&mut self.state, UnixStreamLocalControlState::Failed)
        else {
            unreachable!("broker control setup state disappeared");
        };

        let mut monitor_stream = setup.stream;
        write_frame_with_deadline(
            &mut monitor_stream,
            CONTROL_RING_READY,
            setup.setup_deadline,
        )?;
        let Some(ready) = read_frame_with_deadline(&mut monitor_stream, setup.setup_deadline)?
        else {
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

        let shutdown_stream = monitor_stream.try_clone()?;
        let (request_producer, response_consumer) = ring.into_local();
        let pending_calls = Arc::new(PendingCalls::new());
        let association_failure: Arc<dyn Fn() + Send + Sync> = Arc::new(association_failure);
        let failure_coordinator = Arc::new(LocalActiveFailureCoordinator {
            stream: shutdown_stream,
            pending_calls: Arc::clone(&pending_calls),
            association_failure,
            request_wait: request_producer.wake_handle(),
            response_wait: response_consumer.wake_handle(),
        });
        let response_failure_coordinator = Arc::clone(&failure_coordinator);
        if let Err(error) = thread::Builder::new()
            .name("litebox-broker-responses".to_owned())
            .spawn(move || {
                dispatch_responses(response_consumer, response_failure_coordinator);
            })
        {
            let _ = failure_coordinator.fail(error);
            return Err(Error::other("failed to start broker response pump"));
        }
        let monitor_failure_coordinator = Arc::clone(&failure_coordinator);
        if let Err(error) = thread::Builder::new()
            .name("litebox-broker-liveness".to_owned())
            .spawn(move || {
                monitor_local_socket(&mut monitor_stream, &monitor_failure_coordinator);
            })
        {
            let _ = failure_coordinator.fail(error);
            return Err(Error::other("failed to start broker liveness monitor"));
        }

        self.state = UnixStreamLocalControlState::Active(UnixStreamLocalActive {
            request_producer: Mutex::new(request_producer),
            failure_coordinator: Arc::clone(&failure_coordinator),
        });
        Ok(UnixStreamLocalControlCancellation {
            failure_coordinator,
        })
    }
}

impl UnixStreamLocalControlCancellation {
    /// Shuts down the control stream, unblocking pending reads or writes.
    pub fn cancel(&self) -> IoResult<()> {
        self.failure_coordinator.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker association cancelled",
        ))
    }
}

impl Drop for UnixStreamLocalControlChannel {
    fn drop(&mut self) {
        let UnixStreamLocalControlState::Active(active) = &self.state else {
            return;
        };
        let _ = active.failure_coordinator.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker active channel dropped",
        ));
    }
}

fn shutdown(stream: &UnixStream) -> IoResult<()> {
    match stream.shutdown(Shutdown::Both) {
        Err(error) if error.kind() == ErrorKind::NotConnected => Ok(()),
        result => result,
    }
}

/// Host-side Unix-domain-socket control channel for the hosted userland POC.
pub struct UnixStreamHostControlChannel {
    stream: UnixStream,
    peer_credential: PeerCredential,
    setup_deadline: Option<Instant>,
    negotiated: bool,
}

/// Request-reading half of an active host control channel.
pub struct UnixStreamHostRequestSource {
    consumer: ControlRingConsumer<MemfdSharedMemory>,
    active: Arc<HostActiveState>,
}

/// Shared response-writing half of an active host control channel.
#[derive(Clone)]
pub struct UnixStreamHostResponseSink {
    producer: Arc<Mutex<crate::control_ring::ControlRingProducer<MemfdSharedMemory>>>,
    active: Arc<HostActiveState>,
}

/// RAII guard that interrupts all active host control-channel I/O when dropped.
pub struct UnixStreamHostControlShutdown {
    active: Arc<HostActiveState>,
}

struct HostActiveState {
    stream: UnixStream,
    status: Mutex<HostActiveStatus>,
    request_wait: ControlRingWakeHandle<MemfdSharedMemory>,
    response_wait: ControlRingWakeHandle<MemfdSharedMemory>,
}

enum HostActiveStatus {
    Live,
    PeerClosed,
    Failed(Arc<Error>),
}

/// Local-side Unix-domain-socket notification channel for the hosted userland POC.
pub struct UnixStreamLocalNotificationChannel {
    stream: UnixStream,
}

/// Independently owned handle for interrupting local notification-channel I/O.
pub struct UnixStreamLocalNotificationCancellation {
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
            negotiated: false,
        }
    }

    /// Creates a host control channel after the deployment has authenticated
    /// and bound the accepted peer. `setup_deadline` bounds handshake I/O.
    pub const fn from_host_guaranteed(stream: UnixStream, setup_deadline: Instant) -> Self {
        Self {
            stream,
            peer_credential: PeerCredential::HostGuaranteed,
            setup_deadline: Some(setup_deadline),
            negotiated: false,
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

    /// Consumes a negotiated setup channel into independently usable active
    /// request, response, and shutdown handles.
    pub fn into_active(
        mut self,
        ring: ControlRing<MemfdSharedMemory>,
    ) -> IoResult<(
        UnixStreamHostRequestSource,
        UnixStreamHostResponseSink,
        UnixStreamHostControlShutdown,
    )> {
        if !self.negotiated {
            return Err(invalid_data(
                "broker host control channel activated before negotiation completed",
            ));
        }
        let Some(ready) = read_frame_with_deadline(&mut self.stream, self.setup_deadline)? else {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "runner closed before control-ring setup acknowledgement",
            ));
        };
        if ready != CONTROL_RING_READY {
            return Err(invalid_data(
                "runner sent an invalid control-ring setup acknowledgement",
            ));
        }
        write_frame_with_deadline(&mut self.stream, CONTROL_RING_READY, self.setup_deadline)?;

        let shutdown_stream = self.stream.try_clone()?;
        let (response_producer, request_consumer) = ring.into_broker();
        let active = Arc::new(HostActiveState {
            stream: shutdown_stream,
            status: Mutex::new(HostActiveStatus::Live),
            request_wait: request_consumer.wake_handle(),
            response_wait: response_producer.wake_handle(),
        });
        let monitor_active = Arc::clone(&active);
        thread::Builder::new()
            .name("litebox-runner-liveness".to_owned())
            .spawn(move || monitor_host_socket(&mut self.stream, &monitor_active))?;
        Ok((
            UnixStreamHostRequestSource {
                consumer: request_consumer,
                active: Arc::clone(&active),
            },
            UnixStreamHostResponseSink {
                producer: Arc::new(Mutex::new(response_producer)),
                active: Arc::clone(&active),
            },
            UnixStreamHostControlShutdown { active },
        ))
    }
}

impl UnixStreamHostControlShutdown {
    /// Shuts down the active control socket without waiting for the response
    /// writer mutex.
    pub fn shutdown(&self) -> IoResult<()> {
        self.active.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker host control channel shut down",
        ))
    }
}

impl Drop for UnixStreamHostControlShutdown {
    fn drop(&mut self) {
        let _ = self.active.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker host control shutdown guard dropped",
        ));
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

    /// Creates a handle that can interrupt pending notification-channel I/O.
    pub fn cancellation_handle(&self) -> IoResult<UnixStreamLocalNotificationCancellation> {
        self.stream
            .try_clone()
            .map(|stream| UnixStreamLocalNotificationCancellation { stream })
    }
}

impl UnixStreamLocalNotificationCancellation {
    /// Shuts down the notification stream, unblocking pending reads.
    pub fn cancel(&self) -> IoResult<()> {
        shutdown(&self.stream)
    }
}

impl Drop for UnixStreamLocalNotificationChannel {
    fn drop(&mut self) {
        let _ = shutdown(&self.stream);
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
        let UnixStreamLocalControlState::Setup(setup) = &mut self.state else {
            return Err(invalid_data("broker control channel is already active"));
        };
        let frame = encode_handshake_request(request.clone());
        write_frame_with_deadline(&mut setup.stream, &frame, setup.setup_deadline)
    }

    fn recv_handshake_response(&mut self) -> IoResult<Option<BrokerHandshakeResponse>> {
        let UnixStreamLocalControlState::Setup(setup) = &mut self.state else {
            return Err(invalid_data("broker control channel is already active"));
        };
        let frame = read_frame_with_deadline(&mut setup.stream, setup.setup_deadline)?;
        match frame {
            Some(frame) => {
                let response = decode_handshake_response(&frame).map_err(wire_error)?;
                setup.negotiated = matches!(&response, BrokerHandshakeResponse::Negotiated { .. });
                Ok(Some(response))
            }
            None => Ok(None),
        }
    }

    fn call(&self, request: BrokerRequest) -> IoResult<BrokerResponse> {
        let UnixStreamLocalControlState::Active(active) = &self.state else {
            return Err(invalid_data("broker control channel is not active"));
        };
        let request_id = request.request_id;
        let pending_call = active
            .failure_coordinator
            .pending_calls
            .register(request_id)?;
        let request_frame = encode_request(request);

        let write_result = {
            let mut producer = active
                .request_producer
                .lock()
                .expect("broker request writer mutex poisoned");
            loop {
                let write_status = active
                    .failure_coordinator
                    .pending_calls
                    .run_if_live(|| producer.try_write(&request_frame).map_err(Error::from));
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
            let _ = active.failure_coordinator.fail(error);
        }

        pending_call.wait()
    }
}

impl HostSetupChannel for UnixStreamHostControlChannel {
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
        self.negotiated = matches!(response, BrokerHandshakeResponse::Negotiated { .. });
        Ok(())
    }
}

impl UnixStreamHostRequestSource {
    /// Receives one active broker request.
    pub fn recv_request(&mut self) -> IoResult<HostReceive<BrokerRequest>> {
        loop {
            if let Some(error) = self.active.request_failure() {
                return Err(error);
            }
            match self.consumer.try_read(decode_request) {
                Ok(ControlRingReadStatus::Message(request)) => {
                    self.active.acknowledge_request(&mut self.consumer)?;
                    return Ok(HostReceive::Message(request));
                }
                Ok(ControlRingReadStatus::Empty { wait_epoch }) => {
                    if let Some(terminal) = self.active.request_terminal_result() {
                        return terminal;
                    }
                    if let Err(error) = self.consumer.wait_for_message(wait_epoch) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.active.fail(error);
                        return result;
                    }
                }
                Err(ControlRingReadError::Decode(WireError::WrongMessagePhase)) => {
                    return Ok(HostReceive::ProtocolViolation);
                }
                Err(ControlRingReadError::Decode(error)) => {
                    let error = wire_error(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.active.fail(error);
                    return result;
                }
                Err(ControlRingReadError::Ring(error)) => {
                    let error = Error::from(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.active.fail(error);
                    return result;
                }
            }
        }
    }
}

impl UnixStreamHostResponseSink {
    /// Serializes and sends one complete active broker response.
    pub fn send_response(&self, response: &BrokerResponse) -> IoResult<()> {
        let frame = encode_response(response.clone());
        let mut producer = self
            .producer
            .lock()
            .map_err(|_| Error::other("broker response writer mutex poisoned"))?;
        loop {
            match self.active.try_publish_response(&mut producer, &frame)? {
                ControlRingWriteStatus::Written => return Ok(()),
                ControlRingWriteStatus::Full { wait_epoch } => {
                    if let Err(error) = producer.wait_for_capacity(wait_epoch) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.active.fail(error);
                        return result;
                    }
                }
            }
        }
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

struct PendingCalls {
    state: Mutex<PendingCallState>,
    capacity_available: Condvar,
}

struct PendingCallState {
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
            state: Mutex::new(PendingCallState {
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

impl LocalActiveFailureCoordinator {
    fn fail(&self, error: Error) -> IoResult<()> {
        let first_failure = self.pending_calls.record_failure(Arc::new(error));
        let request_wake = self.request_wait.interrupt_wait();
        let response_wake = self.response_wait.interrupt_wait();
        let shutdown_result = shutdown(&self.stream);
        if first_failure {
            (self.association_failure)();
        }
        request_wake.and(response_wake).and(shutdown_result)
    }
}

impl HostActiveState {
    fn acknowledge_request(
        &self,
        consumer: &mut ControlRingConsumer<MemfdSharedMemory>,
    ) -> IoResult<()> {
        let result = {
            let status = self
                .status
                .lock()
                .expect("broker host active-state mutex poisoned");
            if let HostActiveStatus::Failed(error) = &*status {
                return Err(copy_io_error(error));
            }
            consumer
                .publish_head()
                .map_err(Error::from)
                .and_then(|()| consumer.wake_producer())
        };
        if let Err(error) = result {
            let result = Err(copy_io_error(&error));
            let _ = self.fail(error);
            return result;
        }
        Ok(())
    }

    fn fail(&self, error: Error) -> IoResult<()> {
        {
            let mut status = self
                .status
                .lock()
                .expect("broker host active-state mutex poisoned");
            if matches!(*status, HostActiveStatus::Live) {
                *status = HostActiveStatus::Failed(Arc::new(error));
            }
        }
        let request_wake = self.request_wait.interrupt_wait();
        let response_wake = self.response_wait.interrupt_wait();
        request_wake.and(response_wake).and(shutdown(&self.stream))
    }

    fn peer_closed(&self) {
        {
            let mut status = self
                .status
                .lock()
                .expect("broker host active-state mutex poisoned");
            if matches!(*status, HostActiveStatus::Live) {
                *status = HostActiveStatus::PeerClosed;
            }
        }
        let _ = self.request_wait.interrupt_wait();
        let _ = self.response_wait.interrupt_wait();
    }

    fn request_terminal_result(&self) -> Option<IoResult<HostReceive<BrokerRequest>>> {
        match &*self
            .status
            .lock()
            .expect("broker host active-state mutex poisoned")
        {
            HostActiveStatus::Live => None,
            HostActiveStatus::PeerClosed => Some(Ok(HostReceive::PeerClosed)),
            HostActiveStatus::Failed(error) => Some(Err(copy_io_error(error))),
        }
    }

    fn request_failure(&self) -> Option<Error> {
        match &*self
            .status
            .lock()
            .expect("broker host active-state mutex poisoned")
        {
            HostActiveStatus::Failed(error) => Some(copy_io_error(error)),
            HostActiveStatus::Live | HostActiveStatus::PeerClosed => None,
        }
    }

    fn try_publish_response(
        &self,
        producer: &mut ControlRingProducer<MemfdSharedMemory>,
        frame: &[u8],
    ) -> IoResult<ControlRingWriteStatus> {
        let result = {
            let status = self
                .status
                .lock()
                .expect("broker host active-state mutex poisoned");
            match &*status {
                HostActiveStatus::Live => {}
                HostActiveStatus::PeerClosed => {
                    return Err(Error::new(
                        ErrorKind::BrokenPipe,
                        "runner closed the active control channel",
                    ));
                }
                HostActiveStatus::Failed(error) => return Err(copy_io_error(error)),
            }
            producer
                .try_write(frame)
                .map_err(Error::from)
                .and_then(|write_status| {
                    if matches!(write_status, ControlRingWriteStatus::Written) {
                        producer.wake_consumer()?;
                    }
                    Ok(write_status)
                })
        };
        if let Err(error) = result {
            let result = Err(copy_io_error(&error));
            let _ = self.fail(error);
            return result;
        }
        result
    }
}

fn monitor_local_socket(
    stream: &mut UnixStream,
    failure_coordinator: &LocalActiveFailureCoordinator,
) {
    let error = monitor_socket(stream, "broker");
    let _ = failure_coordinator.fail(error);
}

fn monitor_host_socket(stream: &mut UnixStream, active: &HostActiveState) {
    let mut byte = [0];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => {
                active.peer_closed();
                return;
            }
            Ok(_) => {
                let _ = active.fail(invalid_data(
                    "runner sent unexpected active control-socket data",
                ));
                return;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => {
                let _ = active.fail(error);
                return;
            }
        }
    }
}

fn monitor_socket(stream: &mut UnixStream, peer: &'static str) -> Error {
    let mut byte = [0];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => {
                return Error::new(
                    ErrorKind::UnexpectedEof,
                    format!("{peer} closed the active control channel"),
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
    failure_coordinator: Arc<LocalActiveFailureCoordinator>,
) {
    loop {
        match consumer.try_read(decode_response) {
            Ok(ControlRingReadStatus::Message(response)) => {
                if let Err(error) = consumer
                    .publish_head()
                    .map_err(Error::from)
                    .and_then(|()| consumer.wake_producer())
                    .and_then(|()| failure_coordinator.pending_calls.complete(response))
                {
                    let _ = failure_coordinator.fail(error);
                    return;
                }
            }
            Ok(ControlRingReadStatus::Empty { wait_epoch }) => {
                if failure_coordinator
                    .pending_calls
                    .current_failure()
                    .is_some()
                {
                    return;
                }
                if let Err(error) = consumer.wait_for_message(wait_epoch) {
                    let _ = failure_coordinator.fail(error);
                    return;
                }
            }
            Err(ControlRingReadError::Ring(error)) => {
                let _ = failure_coordinator.fail(Error::from(error));
                return;
            }
            Err(ControlRingReadError::Decode(error)) => {
                let _ = failure_coordinator.fail(wire_error(error));
                return;
            }
        }
    }
}

fn copy_io_error(error: &Error) -> Error {
    match error.raw_os_error() {
        Some(code) => Error::from_raw_os_error(code),
        None => Error::new(error.kind(), error.to_string()),
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

impl From<ControlRingError> for Error {
    fn from(error: ControlRingError) -> Self {
        Self::new(
            ErrorKind::InvalidData,
            format!("invalid broker control ring: {error:?}"),
        )
    }
}

#[cfg(test)]
mod control_ring_tests {
    use super::*;
    use crate::control_ring::{
        CONTROL_RING_MEMORY_SIZE, CONTROL_RING_SLOT_COUNT, ControlRingProducer,
    };
    use litebox_broker_protocol::channel::LocalControlChannel;
    use litebox_broker_protocol::message::{
        BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult,
    };
    use litebox_broker_protocol::wire::{
        decode_request, decode_response, encode_handshake_request, encode_response,
    };
    use litebox_broker_protocol::{ObjectHandle, RequestId};
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    type Producer = ControlRingProducer<MemfdSharedMemory>;
    type Consumer = ControlRingConsumer<MemfdSharedMemory>;

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

    fn negotiated_local(stream: UnixStream) -> UnixStreamLocalControlChannel {
        UnixStreamLocalControlChannel {
            state: UnixStreamLocalControlState::Setup(UnixStreamLocalSetup {
                stream,
                setup_deadline: Some(Instant::now() + Duration::from_secs(2)),
                negotiated: true,
            }),
        }
    }

    fn activate_local(
        association_failure: impl Fn() + Send + Sync + 'static,
    ) -> (
        UnixStreamLocalControlChannel,
        UnixStreamLocalControlCancellation,
        Producer,
        Consumer,
        UnixStream,
    ) {
        let (local_stream, peer_stream) = UnixStream::pair().unwrap();
        let mut ack_stream = peer_stream.try_clone().unwrap();
        let acknowledgement = thread::spawn(move || {
            assert_eq!(
                read_frame_with_deadline(&mut ack_stream, None)
                    .unwrap()
                    .unwrap(),
                CONTROL_RING_READY
            );
            write_frame_with_deadline(&mut ack_stream, CONTROL_RING_READY, None).unwrap();
        });
        let (local_ring, broker_ring) = ring_pair();
        let mut channel = negotiated_local(local_stream);
        let cancellation = channel.activate(local_ring, association_failure).unwrap();
        acknowledgement.join().unwrap();
        let (response_producer, request_consumer) = broker_ring.into_broker();
        (
            channel,
            cancellation,
            response_producer,
            request_consumer,
            peer_stream,
        )
    }

    fn split_host() -> (
        UnixStreamHostRequestSource,
        UnixStreamHostResponseSink,
        UnixStreamHostControlShutdown,
        Producer,
        Consumer,
        UnixStream,
    ) {
        let (peer_stream, host_stream) = UnixStream::pair().unwrap();
        let mut ack_stream = peer_stream.try_clone().unwrap();
        let acknowledgement = thread::spawn(move || {
            write_frame_with_deadline(&mut ack_stream, CONTROL_RING_READY, None).unwrap();
            assert_eq!(
                read_frame_with_deadline(&mut ack_stream, None)
                    .unwrap()
                    .unwrap(),
                CONTROL_RING_READY
            );
        });
        let (local_ring, host_ring) = ring_pair();
        let channel = UnixStreamHostControlChannel {
            stream: host_stream,
            peer_credential: PeerCredential::HostGuaranteed,
            setup_deadline: Some(Instant::now() + Duration::from_secs(2)),
            negotiated: true,
        };
        let (source, sink, shutdown) = channel.into_active(host_ring).unwrap();
        acknowledgement.join().unwrap();
        let (request_producer, response_consumer) = local_ring.into_local();
        (
            source,
            sink,
            shutdown,
            request_producer,
            response_consumer,
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

    fn read_response(consumer: &mut Consumer) -> BrokerResponse {
        loop {
            match consumer.try_read(decode_response).unwrap() {
                ControlRingReadStatus::Message(response) => {
                    consumer.publish_head().unwrap();
                    consumer.wake_producer().unwrap();
                    return response;
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
    fn setup_frames_round_trip_and_reject_invalid_boundaries() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        write_frame_with_deadline(&mut writer, &[1, 2, 3], None).unwrap();
        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap()
                .unwrap(),
            [1, 2, 3]
        );

        let (writer, mut reader) = UnixStream::pair().unwrap();
        drop(writer);
        assert!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap()
                .is_none()
        );

        for frame_prefix in [
            vec![1, 0],
            0u32.to_le_bytes().to_vec(),
            u32::try_from(MAX_FRAME_LEN + 1)
                .unwrap()
                .to_le_bytes()
                .to_vec(),
        ] {
            let (mut writer, mut reader) = UnixStream::pair().unwrap();
            writer.write_all(&frame_prefix).unwrap();
            drop(writer);
            assert_eq!(
                read_frame_with_deadline(&mut reader, None)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData
            );
        }

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
    fn local_control_channel_enforces_setup_and_active_phases() {
        let (local_stream, mut host_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamLocalControlChannel::from_connected(local_stream);
        assert_eq!(
            channel.call(request(0)).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        let (ring, _) = ring_pair();
        assert_eq!(
            channel.activate(ring, || {}).err().unwrap().kind(),
            ErrorKind::InvalidData
        );

        let handshake_request = BrokerHandshakeRequest {
            protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
        };
        channel.send_handshake_request(&handshake_request).unwrap();
        assert_eq!(
            decode_handshake_request(
                &read_frame_with_deadline(&mut host_stream, None)
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            handshake_request
        );
        write_frame_with_deadline(
            &mut host_stream,
            &encode_handshake_response(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
            }),
            None,
        )
        .unwrap();
        assert!(matches!(
            channel.recv_handshake_response().unwrap(),
            Some(BrokerHandshakeResponse::Negotiated { .. })
        ));

        let acknowledgement = thread::spawn(move || {
            assert_eq!(
                read_frame_with_deadline(&mut host_stream, None)
                    .unwrap()
                    .unwrap(),
                CONTROL_RING_READY
            );
            write_frame_with_deadline(&mut host_stream, CONTROL_RING_READY, None).unwrap();
            host_stream
        });
        let (ring, _) = ring_pair();
        let _cancellation = channel.activate(ring, || {}).unwrap();
        let mut host_stream = acknowledgement.join().unwrap();

        let (ring, _) = ring_pair();
        assert_eq!(
            channel.activate(ring, || {}).err().unwrap().kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            channel
                .send_handshake_request(&handshake_request)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );

        host_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        drop(channel);
        let mut byte = [0];
        assert_eq!(host_stream.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn two_way_ready_ack_activates_ring_transport() {
        let (local_stream, host_stream) = UnixStream::pair().unwrap();
        let (local_ring, host_ring) = ring_pair();
        let mut local = negotiated_local(local_stream);
        let host = UnixStreamHostControlChannel {
            stream: host_stream,
            peer_credential: PeerCredential::HostGuaranteed,
            setup_deadline: Some(Instant::now() + Duration::from_secs(2)),
            negotiated: true,
        };
        let host_active = thread::spawn(move || host.into_active(host_ring).unwrap());
        let _cancellation = local.activate(local_ring, || {}).unwrap();
        let (mut source, sink, _shutdown) = host_active.join().unwrap();

        let caller = thread::spawn(move || local.call(request(7)));
        let HostReceive::Message(received) = source.recv_request().unwrap() else {
            panic!("expected ring request");
        };
        sink.send_response(&response(received.request_id)).unwrap();
        assert_eq!(caller.join().unwrap().unwrap().request_id, RequestId(7));
    }

    #[test]
    fn local_matches_out_of_order_ring_responses_without_socket_frames() {
        let (channel, _cancellation, mut responses, mut requests, mut peer) = activate_local(|| {});
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
        let (channel, cancellation, mut responses, mut requests, _peer) = activate_local(|| {});
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

        cancellation.cancel().unwrap();
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
            let (channel, _cancellation, mut responses, mut requests, _peer) =
                activate_local(move || {
                    callback_failures.fetch_add(1, Ordering::SeqCst);
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
            assert_eq!(failures.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn local_socket_eof_and_cancellation_wake_pending_calls() {
        for close_peer in [false, true] {
            let (channel, cancellation, _responses, mut requests, peer) = activate_local(|| {});
            let caller = thread::spawn(move || channel.call(request(1)));
            read_request(&mut requests);
            if close_peer {
                drop(peer);
            } else {
                cancellation.cancel().unwrap();
            }
            assert!(caller.join().unwrap().is_err());
        }
    }

    #[test]
    fn host_split_decodes_requests_and_cloned_sinks_publish_complete_responses() {
        let (mut source, sink, _shutdown, mut requests, mut responses, _peer) = split_host();
        write_payload(&mut requests, &encode_request(request(1)));
        assert!(matches!(
            source.recv_request().unwrap(),
            HostReceive::Message(BrokerRequest {
                request_id: RequestId(1),
                ..
            })
        ));

        let first = sink.clone();
        let writer = thread::spawn(move || first.send_response(&response(RequestId(3))));
        sink.send_response(&response(RequestId(7))).unwrap();
        writer.join().unwrap().unwrap();
        let mut ids = [
            read_response(&mut responses).request_id,
            read_response(&mut responses).request_id,
        ];
        ids.sort();
        assert_eq!(ids, [RequestId(3), RequestId(7)]);
    }

    #[test]
    fn host_clean_close_wakes_request_wait_as_peer_closed() {
        let (mut source, _sink, _shutdown, _requests, _responses, peer) = split_host();
        let receiver = thread::spawn(move || source.recv_request());
        drop(peer);
        assert_eq!(receiver.join().unwrap().unwrap(), HostReceive::PeerClosed);
    }

    #[test]
    fn host_failure_preempts_queued_and_decoded_requests_but_peer_close_drains() {
        let (mut source, _sink, _shutdown, mut requests, _responses, _peer) = split_host();
        write_payload(&mut requests, &encode_request(request(1)));
        source
            .active
            .fail(Error::new(ErrorKind::TimedOut, "test failure"))
            .unwrap();
        assert_eq!(
            source.recv_request().unwrap_err().kind(),
            ErrorKind::TimedOut
        );

        let (mut source, _sink, _shutdown, mut requests, _responses, _peer) = split_host();
        write_payload(&mut requests, &encode_request(request(2)));
        assert!(matches!(
            source.consumer.try_read(decode_request).unwrap(),
            ControlRingReadStatus::Message(_)
        ));
        source
            .active
            .fail(Error::new(ErrorKind::TimedOut, "test failure"))
            .unwrap();
        assert_eq!(
            source
                .active
                .acknowledge_request(&mut source.consumer)
                .unwrap_err()
                .kind(),
            ErrorKind::TimedOut
        );

        let (mut source, _sink, _shutdown, mut requests, _responses, _peer) = split_host();
        write_payload(&mut requests, &encode_request(request(3)));
        source.active.peer_closed();
        assert!(matches!(
            source.recv_request().unwrap(),
            HostReceive::Message(BrokerRequest {
                request_id: RequestId(3),
                ..
            })
        ));
        assert_eq!(source.recv_request().unwrap(), HostReceive::PeerClosed);
    }

    #[test]
    fn dropping_host_shutdown_guard_wakes_request_wait_and_closes_socket() {
        let (mut source, sink, shutdown, _requests, _responses, mut peer) = split_host();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let receiver = thread::spawn(move || source.recv_request());

        drop(sink);
        drop(shutdown);

        assert_eq!(
            receiver.join().unwrap().unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn host_close_wakes_response_producer_blocked_on_full_ring() {
        let (_source, sink, _shutdown, _requests, _responses, peer) = split_host();
        for id in 0..CONTROL_RING_SLOT_COUNT {
            sink.send_response(&response(RequestId(id))).unwrap();
        }
        let blocked_sink = sink.clone();
        let blocked = thread::spawn(move || blocked_sink.send_response(&response(RequestId(99))));
        thread::sleep(Duration::from_millis(20));
        drop(peer);
        assert_eq!(
            blocked.join().unwrap().unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn host_reports_wrong_phase_ring_message_as_protocol_violation() {
        let (mut source, _sink, _shutdown, mut requests, _responses, _peer) = split_host();
        write_payload(
            &mut requests,
            &encode_handshake_request(BrokerHandshakeRequest {
                protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
            }),
        );
        assert_eq!(
            source.recv_request().unwrap(),
            HostReceive::ProtocolViolation
        );
    }

    #[test]
    fn malformed_host_ring_request_is_fatal_invalid_data() {
        let (mut source, _sink, _shutdown, mut requests, _responses, _peer) = split_host();
        write_payload(&mut requests, &[u8::MAX]);
        assert_eq!(
            source.recv_request().unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn host_setup_rejects_active_frames_and_requires_negotiation() {
        let (mut peer_stream, host_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamHostControlChannel::from_accepted(host_stream);
        write_frame_with_deadline(&mut peer_stream, &encode_request(request(0)), None).unwrap();
        assert_eq!(
            channel.recv_handshake_request().unwrap(),
            HostReceive::ProtocolViolation
        );

        let (_peer_stream, host_stream) = UnixStream::pair().unwrap();
        let channel = UnixStreamHostControlChannel::from_accepted(host_stream);
        let (ring, _) = ring_pair();
        let Err(error) = channel.into_active(ring) else {
            panic!("host control channel activated before negotiation");
        };
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn ready_ack_uses_absolute_setup_deadline() {
        let (local_stream, _peer) = UnixStream::pair().unwrap();
        let (ring, _) = ring_pair();
        let mut local = UnixStreamLocalControlChannel {
            state: UnixStreamLocalControlState::Setup(UnixStreamLocalSetup {
                stream: local_stream,
                setup_deadline: Some(Instant::now() + Duration::from_millis(30)),
                negotiated: true,
            }),
        };
        let Err(error) = local.activate(ring, || {}) else {
            panic!("activation unexpectedly succeeded");
        };
        assert!(matches!(
            error.kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut
        ));
    }

    #[test]
    fn handshake_reads_use_absolute_setup_deadlines() {
        let (mut host_stream, local_stream) = UnixStream::pair().unwrap();
        let mut local = UnixStreamLocalControlChannel {
            state: UnixStreamLocalControlState::Setup(UnixStreamLocalSetup {
                stream: local_stream,
                setup_deadline: Some(Instant::now() + Duration::from_millis(50)),
                negotiated: false,
            }),
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

        let (mut local_stream, host_stream) = UnixStream::pair().unwrap();
        let mut host = UnixStreamHostControlChannel::from_host_guaranteed(
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
    fn notification_frame_round_trips() {
        let (local_stream, host_stream) = UnixStream::pair().unwrap();
        let mut local = UnixStreamLocalNotificationChannel::from_connected(local_stream);
        let mut host = UnixStreamHostNotificationChannel::from_accepted(host_stream);
        let notification = BrokerNotification::Readiness(
            litebox_broker_protocol::message::ReadinessNotification {
                handle: ObjectHandle(7),
                readiness: litebox_broker_protocol::readiness::ReadinessFlags::READ,
            },
        );

        host.send_notification(&notification).unwrap();

        assert_eq!(local.recv_notification().unwrap(), Some(notification));
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
