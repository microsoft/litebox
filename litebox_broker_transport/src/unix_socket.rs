// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix-domain-socket broker channel for hosted userland deployments.
//!
//! This module deliberately uses `std` because Unix-domain sockets and `std::io`
//! framing are hosted userland concerns. Portable broker interfaces live in the
//! no_std protocol, local, core, and host crates.
//!
//! After setup, the authenticated socket is retained only for liveness and
//! fail-closed shutdown. Active requests, responses, and notifications use
//! shared control rings.

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
    HostNotificationChannel, HostReceive, HostSetupChannel, LocalCallChannel,
    LocalNotificationChannel, LocalSetupChannel, PeerCredential,
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

const MAX_SETUP_FRAME_LEN: usize = 64 * 1024;
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

fn peer_process_id(stream: &UnixStream) -> IoResult<u32> {
    let credentials = rustix::net::sockopt::socket_peercred(stream)?;
    u32::try_from(credentials.pid.as_raw_pid())
        .map_err(|_| invalid_data("Unix peer process ID is invalid"))
}

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
    request_producer: Mutex<crate::control_ring::ControlRingProducer<MemfdSharedMemory>>,
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
            negotiated: false,
        })
    }

    /// Receives one memfd offered by the broker during setup.
    pub fn receive_memfd(
        &mut self,
        expected_len: usize,
        deadline: Option<Instant>,
    ) -> IoResult<MemfdSharedMemory> {
        crate::shared_memory::receive_memfd(&mut self.stream, expected_len, deadline)
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
        let crate::control_ring::LocalControlRingEndpoints {
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

impl UnixControlRingLocalShutdown {
    /// Shuts down the active association, unblocking ring and socket waits.
    pub fn shutdown(&self) -> IoResult<()> {
        self.association.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker local association shut down",
        ))
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

fn shutdown_socket(stream: &UnixStream) -> IoResult<()> {
    match stream.shutdown(Shutdown::Both) {
        Err(error) if error.kind() == ErrorKind::NotConnected => Ok(()),
        result => result,
    }
}

/// Host-side broker association setup channel over a Unix stream.
pub struct UnixStreamHostSetupChannel {
    stream: UnixStream,
    peer_credential: PeerCredential,
    setup_deadline: Option<Instant>,
    negotiated: bool,
}

/// Request-reading endpoint of an active host control-ring association.
pub struct UnixControlRingHostRequestSource {
    consumer: ControlRingConsumer<MemfdSharedMemory>,
    association: Arc<HostRingAssociation>,
}

/// Shared response-writing endpoint of an active host control-ring association.
#[derive(Clone)]
pub struct UnixControlRingHostResponseSink {
    producer: Arc<Mutex<crate::control_ring::ControlRingProducer<MemfdSharedMemory>>>,
    association: Arc<HostRingAssociation>,
}

/// RAII guard that interrupts all active host ring I/O when dropped.
pub struct UnixControlRingHostShutdown {
    association: Arc<HostRingAssociation>,
}

/// State shared by every activated host endpoint of one association: the setup
/// socket used for liveness and teardown, terminal status, and the wake handles
/// of all three ring directions.
struct HostRingAssociation {
    control_stream: UnixStream,
    status: Mutex<HostAssociationStatus>,
    request_wake: ControlRingWakeHandle<MemfdSharedMemory>,
    response_wake: ControlRingWakeHandle<MemfdSharedMemory>,
    notification_wake: ControlRingWakeHandle<MemfdSharedMemory>,
}

enum HostAssociationStatus {
    Live,
    PeerClosed,
    Failed(Arc<Error>),
}

/// Host notification sender for a shared-ring Unix broker association.
pub struct UnixControlRingHostNotificationChannel {
    producer: ControlRingProducer<MemfdSharedMemory>,
    association: Arc<HostRingAssociation>,
}

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
        crate::shared_memory::send_memfd(&mut self.stream, shared_memory, deadline)
    }

    /// Consumes a negotiated setup channel into independently usable active
    /// request, response, notification, and shutdown handles.
    pub fn into_active(
        mut self,
        ring: ControlRing<MemfdSharedMemory>,
    ) -> IoResult<(
        UnixControlRingHostRequestSource,
        UnixControlRingHostResponseSink,
        UnixControlRingHostNotificationChannel,
        UnixControlRingHostShutdown,
    )> {
        if !self.negotiated {
            return Err(invalid_data(
                "broker host setup channel activated before negotiation completed",
            ));
        }
        let Some(ready) = read_setup_frame(&mut self.stream, self.setup_deadline)? else {
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
        write_setup_frame(&mut self.stream, CONTROL_RING_READY, self.setup_deadline)?;

        let shutdown_stream = self.stream.try_clone()?;
        let crate::control_ring::BrokerControlRingEndpoints {
            request_consumer,
            response_producer,
            notification_producer,
        } = ring.into_broker();
        let association = Arc::new(HostRingAssociation {
            control_stream: shutdown_stream,
            status: Mutex::new(HostAssociationStatus::Live),
            request_wake: request_consumer.wake_handle(),
            response_wake: response_producer.wake_handle(),
            notification_wake: notification_producer.wake_handle(),
        });
        let monitor_association = Arc::clone(&association);
        thread::Builder::new()
            .name("litebox-runner-liveness".to_owned())
            .spawn(move || monitor_host_socket(&mut self.stream, &monitor_association))?;
        Ok((
            UnixControlRingHostRequestSource {
                consumer: request_consumer,
                association: Arc::clone(&association),
            },
            UnixControlRingHostResponseSink {
                producer: Arc::new(Mutex::new(response_producer)),
                association: Arc::clone(&association),
            },
            UnixControlRingHostNotificationChannel {
                producer: notification_producer,
                association: Arc::clone(&association),
            },
            UnixControlRingHostShutdown { association },
        ))
    }
}

impl UnixControlRingHostShutdown {
    /// Shuts down the active association without waiting for a ring lock.
    pub fn shutdown(&self) -> IoResult<()> {
        self.association.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker host association shut down",
        ))
    }
}

impl Drop for UnixControlRingHostShutdown {
    fn drop(&mut self) {
        let _ = self.association.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker host association shutdown guard dropped",
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
            let _ = association.fail(error);
        }

        pending_call.wait()
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

impl UnixControlRingHostRequestSource {
    /// Receives one active broker request.
    pub fn recv_request(&mut self) -> IoResult<HostReceive<BrokerRequest>> {
        loop {
            if let Some(error) = self.association.current_failure() {
                return Err(error);
            }
            match self.consumer.try_read(decode_request) {
                Ok(ControlRingReadStatus::Message(request)) => {
                    self.association.acknowledge_request(&mut self.consumer)?;
                    return Ok(HostReceive::Message(request));
                }
                Ok(ControlRingReadStatus::Empty { wait_epoch }) => {
                    if let Some(terminal) = self.association.request_terminal_result() {
                        return terminal;
                    }
                    if let Err(error) = self.consumer.wait_for_message(wait_epoch) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.association.fail(error);
                        return result;
                    }
                }
                Err(ControlRingReadError::Decode(WireError::WrongMessagePhase)) => {
                    return Ok(HostReceive::ProtocolViolation);
                }
                Err(ControlRingReadError::Decode(error)) => {
                    let error = wire_error(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.association.fail(error);
                    return result;
                }
                Err(ControlRingReadError::Ring(error)) => {
                    let error = Error::from(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.association.fail(error);
                    return result;
                }
            }
        }
    }
}

impl UnixControlRingHostResponseSink {
    /// Serializes and sends one complete active broker response.
    pub fn send_response(&self, response: &BrokerResponse) -> IoResult<()> {
        let frame = encode_response(response.clone());
        let mut producer = self
            .producer
            .lock()
            .map_err(|_| Error::other("broker response writer mutex poisoned"))?;
        loop {
            match self.association.try_publish(&mut producer, &frame)? {
                ControlRingWriteStatus::Written => return Ok(()),
                ControlRingWriteStatus::Full { wait_epoch } => {
                    if let Err(error) = producer.wait_for_capacity(wait_epoch) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.association.fail(error);
                        return result;
                    }
                }
            }
        }
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
                    let error = Error::from(error);
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

impl HostNotificationChannel for UnixControlRingHostNotificationChannel {
    type Error = Error;

    fn send_notification(&mut self, notification: &BrokerNotification) -> IoResult<()> {
        let frame = encode_notification(notification.clone());
        loop {
            match self.association.try_publish(&mut self.producer, &frame)? {
                ControlRingWriteStatus::Written => return Ok(()),
                ControlRingWriteStatus::Full { wait_epoch } => {
                    if let Err(error) = self.producer.wait_for_capacity(wait_epoch) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.association.fail(error);
                        return result;
                    }
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
                .map_err(Error::from)
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

impl HostRingAssociation {
    fn acknowledge_request(
        &self,
        consumer: &mut ControlRingConsumer<MemfdSharedMemory>,
    ) -> IoResult<()> {
        let result = {
            let status = self
                .status
                .lock()
                .expect("broker host association mutex poisoned");
            if let HostAssociationStatus::Failed(error) = &*status {
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
                .expect("broker host association mutex poisoned");
            if matches!(*status, HostAssociationStatus::Live) {
                *status = HostAssociationStatus::Failed(Arc::new(error));
            }
        }
        let request_wake = self.request_wake.interrupt_wait();
        let response_wake = self.response_wake.interrupt_wait();
        let notification_wake = self.notification_wake.interrupt_wait();
        request_wake
            .and(response_wake)
            .and(notification_wake)
            .and(shutdown_socket(&self.control_stream))
    }

    fn peer_closed(&self) {
        {
            let mut status = self
                .status
                .lock()
                .expect("broker host association mutex poisoned");
            if matches!(*status, HostAssociationStatus::Live) {
                *status = HostAssociationStatus::PeerClosed;
            }
        }
        let _ = self.request_wake.interrupt_wait();
        let _ = self.response_wake.interrupt_wait();
        let _ = self.notification_wake.interrupt_wait();
    }

    fn request_terminal_result(&self) -> Option<IoResult<HostReceive<BrokerRequest>>> {
        match &*self
            .status
            .lock()
            .expect("broker host association mutex poisoned")
        {
            HostAssociationStatus::Live => None,
            HostAssociationStatus::PeerClosed => Some(Ok(HostReceive::PeerClosed)),
            HostAssociationStatus::Failed(error) => Some(Err(copy_io_error(error))),
        }
    }

    fn current_failure(&self) -> Option<Error> {
        match &*self
            .status
            .lock()
            .expect("broker host association mutex poisoned")
        {
            HostAssociationStatus::Failed(error) => Some(copy_io_error(error)),
            HostAssociationStatus::Live | HostAssociationStatus::PeerClosed => None,
        }
    }

    fn try_publish(
        &self,
        producer: &mut ControlRingProducer<MemfdSharedMemory>,
        frame: &[u8],
    ) -> IoResult<ControlRingWriteStatus> {
        let result = {
            let status = self
                .status
                .lock()
                .expect("broker host association mutex poisoned");
            match &*status {
                HostAssociationStatus::Live => {}
                HostAssociationStatus::PeerClosed => {
                    return Err(Error::new(
                        ErrorKind::BrokenPipe,
                        "runner closed the active broker association",
                    ));
                }
                HostAssociationStatus::Failed(error) => return Err(copy_io_error(error)),
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

fn monitor_local_socket(stream: &mut UnixStream, association: &LocalRingAssociation) {
    let error = wait_for_socket_termination(stream, "broker");
    let _ = association.fail(error);
}

fn monitor_host_socket(stream: &mut UnixStream, association: &HostRingAssociation) {
    let mut byte = [0];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => {
                association.peer_closed();
                return;
            }
            Ok(_) => {
                let _ = association.fail(invalid_data(
                    "runner sent unexpected active control-socket data",
                ));
                return;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => {
                let _ = association.fail(error);
                return;
            }
        }
    }
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
                    .map_err(Error::from)
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
                let _ = association.fail(Error::from(error));
                return;
            }
            Err(ControlRingReadError::Decode(error)) => {
                let _ = association.fail(wire_error(error));
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

fn read_setup_frame(
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
                Ok(0) => return Err(invalid_data("truncated broker setup frame length")),
                Ok(len) => read += len,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }

        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > MAX_SETUP_FRAME_LEN {
            return Err(invalid_data("invalid broker setup frame length"));
        }

        let mut frame = vec![0; len];
        let mut read = 0;
        while read < frame.len() {
            refresh_read_deadline(stream, deadline)?;
            match stream.read(&mut frame[read..]) {
                Ok(0) => return Err(invalid_data("truncated broker setup frame")),
                Ok(len) => read += len,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(Some(frame))
    })
}

fn write_setup_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Option<Instant>,
) -> IoResult<()> {
    with_write_deadline(stream, deadline, |stream, deadline| {
        if frame.is_empty() || frame.len() > MAX_SETUP_FRAME_LEN {
            return Err(invalid_data("invalid broker setup frame length"));
        }
        let len =
            u32::try_from(frame.len()).map_err(|_| invalid_data("broker setup frame too large"))?;
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
                    "failed to write broker setup frame",
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
    use litebox_broker_protocol::channel::{LocalCallChannel, LocalSetupChannel};
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
        let crate::control_ring::BrokerControlRingEndpoints {
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

    fn activate_host() -> (
        UnixControlRingHostRequestSource,
        UnixControlRingHostResponseSink,
        UnixControlRingHostShutdown,
        Producer,
        Consumer,
        UnixStream,
    ) {
        let (peer_stream, host_stream) = UnixStream::pair().unwrap();
        let mut ack_stream = peer_stream.try_clone().unwrap();
        let acknowledgement = thread::spawn(move || {
            write_setup_frame(&mut ack_stream, CONTROL_RING_READY, None).unwrap();
            assert_eq!(
                read_setup_frame(&mut ack_stream, None).unwrap().unwrap(),
                CONTROL_RING_READY
            );
        });
        let (local_ring, host_ring) = ring_pair();
        let channel = UnixStreamHostSetupChannel {
            stream: host_stream,
            peer_credential: PeerCredential::HostGuaranteed,
            setup_deadline: Some(Instant::now() + Duration::from_secs(2)),
            negotiated: true,
        };
        let (source, sink, _notifications, shutdown) = channel.into_active(host_ring).unwrap();
        acknowledgement.join().unwrap();
        let crate::control_ring::LocalControlRingEndpoints {
            request_producer,
            response_consumer,
            notification_consumer: _,
        } = local_ring.into_local();
        (
            source,
            sink,
            shutdown,
            request_producer,
            response_consumer,
            peer_stream,
        )
    }

    fn notification_channel_pair() -> (
        UnixControlRingLocalCallChannel,
        UnixControlRingLocalNotificationChannel,
        UnixControlRingHostNotificationChannel,
        UnixControlRingHostShutdown,
    ) {
        let (local_stream, host_stream) = UnixStream::pair().unwrap();
        let (local_ring, host_ring) = ring_pair();
        let local_setup = negotiated_local(local_stream);
        let host_control = UnixStreamHostSetupChannel {
            stream: host_stream,
            peer_credential: PeerCredential::HostGuaranteed,
            setup_deadline: Some(Instant::now() + Duration::from_secs(2)),
            negotiated: true,
        };
        let host_active = thread::spawn(move || host_control.into_active(host_ring).unwrap());
        let (local_call, local_notifications, _local_shutdown) =
            local_setup.into_active(local_ring, || {}).unwrap();
        let (_source, _sink, host_notifications, shutdown) = host_active.join().unwrap();
        (
            local_call,
            local_notifications,
            host_notifications,
            shutdown,
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
    fn setup_frames_round_trip_and_reject_invalid_boundaries() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        write_setup_frame(&mut writer, &[1, 2, 3], None).unwrap();
        assert_eq!(
            read_setup_frame(&mut reader, None).unwrap().unwrap(),
            [1, 2, 3]
        );

        let (writer, mut reader) = UnixStream::pair().unwrap();
        drop(writer);
        assert!(read_setup_frame(&mut reader, None).unwrap().is_none());

        for frame_prefix in [
            vec![1, 0],
            0u32.to_le_bytes().to_vec(),
            u32::try_from(MAX_SETUP_FRAME_LEN + 1)
                .unwrap()
                .to_le_bytes()
                .to_vec(),
        ] {
            let (mut writer, mut reader) = UnixStream::pair().unwrap();
            writer.write_all(&frame_prefix).unwrap();
            drop(writer);
            assert_eq!(
                read_setup_frame(&mut reader, None).unwrap_err().kind(),
                ErrorKind::InvalidData
            );
        }

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&4u32.to_le_bytes()).unwrap();
        writer.write_all(&[1, 2]).unwrap();
        drop(writer);
        assert_eq!(
            read_setup_frame(&mut reader, None).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
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
    fn two_way_ready_ack_activates_ring_transport() {
        let (local_stream, host_stream) = UnixStream::pair().unwrap();
        let (local_ring, host_ring) = ring_pair();
        let local_setup = negotiated_local(local_stream);
        let host = UnixStreamHostSetupChannel {
            stream: host_stream,
            peer_credential: PeerCredential::HostGuaranteed,
            setup_deadline: Some(Instant::now() + Duration::from_secs(2)),
            negotiated: true,
        };
        let host_active = thread::spawn(move || host.into_active(host_ring).unwrap());
        let (local, _local_notifications, _local_shutdown) =
            local_setup.into_active(local_ring, || {}).unwrap();
        let (mut source, sink, _host_notifications, _shutdown) = host_active.join().unwrap();

        let caller = thread::spawn(move || local.call(request(7)));
        let HostReceive::Message(received) = source.recv_request().unwrap() else {
            panic!("expected ring request");
        };
        sink.send_response(&response(received.request_id)).unwrap();
        assert_eq!(caller.join().unwrap().unwrap().request_id, RequestId(7));
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
            let (channel, _shutdown, mut responses, mut requests, _peer) =
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
    fn host_activation_decodes_requests_and_cloned_sinks_publish_complete_responses() {
        let (mut source, sink, _shutdown, mut requests, mut responses, _peer) = activate_host();
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
        let (mut source, _sink, _shutdown, _requests, _responses, peer) = activate_host();
        let receiver = thread::spawn(move || source.recv_request());
        drop(peer);
        assert_eq!(receiver.join().unwrap().unwrap(), HostReceive::PeerClosed);
    }

    #[test]
    fn host_failure_preempts_queued_and_decoded_requests_but_peer_close_drains() {
        let (mut source, _sink, _shutdown, mut requests, _responses, _peer) = activate_host();
        write_payload(&mut requests, &encode_request(request(1)));
        source
            .association
            .fail(Error::new(ErrorKind::TimedOut, "test failure"))
            .unwrap();
        assert_eq!(
            source.recv_request().unwrap_err().kind(),
            ErrorKind::TimedOut
        );

        let (mut source, _sink, _shutdown, mut requests, _responses, _peer) = activate_host();
        write_payload(&mut requests, &encode_request(request(2)));
        assert!(matches!(
            source.consumer.try_read(decode_request).unwrap(),
            ControlRingReadStatus::Message(_)
        ));
        source
            .association
            .fail(Error::new(ErrorKind::TimedOut, "test failure"))
            .unwrap();
        assert_eq!(
            source
                .association
                .acknowledge_request(&mut source.consumer)
                .unwrap_err()
                .kind(),
            ErrorKind::TimedOut
        );

        let (mut source, _sink, _shutdown, mut requests, _responses, _peer) = activate_host();
        write_payload(&mut requests, &encode_request(request(3)));
        source.association.peer_closed();
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
        let (mut source, sink, shutdown, _requests, _responses, mut peer) = activate_host();
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
        let (_source, sink, _shutdown, _requests, _responses, peer) = activate_host();
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
        let (mut source, _sink, _shutdown, mut requests, _responses, _peer) = activate_host();
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
        let (mut source, _sink, _shutdown, mut requests, _responses, _peer) = activate_host();
        write_payload(&mut requests, &[u8::MAX]);
        assert_eq!(
            source.recv_request().unwrap_err().kind(),
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
        let notification = BrokerNotification::Readiness(
            litebox_broker_protocol::message::ReadinessNotification {
                handle: ObjectHandle(7),
                readiness: litebox_broker_protocol::readiness::ReadinessFlags::READ,
            },
        );

        let receiver = thread::spawn(move || local.recv_notification());
        thread::sleep(Duration::from_millis(20));
        host.send_notification(&notification).unwrap();

        assert_eq!(receiver.join().unwrap().unwrap(), Some(notification));
    }

    #[test]
    fn full_notification_ring_wakes_after_consumer_progress() {
        let (_control, mut local, mut host, _shutdown) = notification_channel_pair();
        let notification = BrokerNotification::Readiness(
            litebox_broker_protocol::message::ReadinessNotification {
                handle: ObjectHandle(7),
                readiness: litebox_broker_protocol::readiness::ReadinessFlags::READ,
            },
        );
        for _ in 0..crate::control_ring::CONTROL_RING_NOTIFICATION_SLOT_COUNT {
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

    #[test]
    fn malformed_notification_fails_the_association() {
        let (control, mut local, mut host, _shutdown) = notification_channel_pair();
        assert_eq!(
            host.producer.try_write(&[0xff]).unwrap(),
            ControlRingWriteStatus::Written
        );
        host.producer.wake_consumer().unwrap();

        assert_eq!(
            local.recv_notification().unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        assert!(
            control
                .association
                .pending_calls
                .current_failure()
                .is_some()
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
