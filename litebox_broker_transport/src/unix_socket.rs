// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix-domain-socket broker channel for hosted userland deployments.
//!
//! This module deliberately uses `std` because Unix-domain sockets and `std::io`
//! framing are hosted userland concerns. Portable broker interfaces live in the
//! no_std protocol, local, core, and host crates.
//!
//! After setup, each caller thread registers its request and writes its complete
//! frame while holding the shared writer mutex; there is no local request worker.
//! One response-dispatcher thread exclusively reads responses, correlates them by
//! request ID, and wakes the matching callers.

use std::io::{Error, ErrorKind, Read, Result as IoResult, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;
use std::{collections::HashMap, thread};

use crate::shared_memory::MemfdSharedMemory;
use crate::unix_io::{
    refresh_read_deadline, refresh_write_deadline, with_read_deadline, with_write_deadline,
};
use litebox_broker_protocol::RequestId;
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
    stream: UnixStream,
    pending_calls: Arc<PendingCalls>,
    association_failure: Arc<dyn Fn() + Send + Sync>,
}

struct UnixStreamLocalActive {
    request_stream: Mutex<UnixStream>,
    shutdown_stream: UnixStream,
    pending_calls: Arc<PendingCalls>,
    association_failure: Arc<dyn Fn() + Send + Sync>,
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

    /// Completes setup and starts the active response pump.
    pub fn activate(
        &mut self,
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

        let response_stream = setup.stream;
        let request_stream = response_stream.try_clone()?;
        let shutdown_stream = response_stream.try_clone()?;
        let cancellation_stream = response_stream.try_clone()?;
        let response_cancellation = response_stream.try_clone()?;
        let pending_calls = Arc::new(PendingCalls::new());
        let association_failure: Arc<dyn Fn() + Send + Sync> = Arc::new(association_failure);
        let response_pending_calls = Arc::clone(&pending_calls);
        let response_failure = Arc::clone(&association_failure);
        thread::Builder::new()
            .name("litebox-broker-responses".to_owned())
            .spawn(move || {
                dispatch_responses(
                    response_stream,
                    response_cancellation,
                    response_pending_calls,
                    response_failure,
                );
            })?;

        self.state = UnixStreamLocalControlState::Active(UnixStreamLocalActive {
            request_stream: Mutex::new(request_stream),
            shutdown_stream,
            pending_calls: Arc::clone(&pending_calls),
            association_failure: Arc::clone(&association_failure),
        });
        Ok(UnixStreamLocalControlCancellation {
            stream: cancellation_stream,
            pending_calls,
            association_failure,
        })
    }
}

impl UnixStreamLocalControlCancellation {
    /// Shuts down the control stream, unblocking pending reads or writes.
    pub fn cancel(&self) -> IoResult<()> {
        fail_active_channel(
            &self.pending_calls,
            &self.stream,
            self.association_failure.as_ref(),
            Error::new(ErrorKind::ConnectionAborted, "broker association cancelled"),
        )
    }
}

impl Drop for UnixStreamLocalControlChannel {
    fn drop(&mut self) {
        let UnixStreamLocalControlState::Active(active) = &self.state else {
            return;
        };
        let _ = fail_active_channel(
            &active.pending_calls,
            &active.shutdown_stream,
            active.association_failure.as_ref(),
            Error::new(
                ErrorKind::ConnectionAborted,
                "broker active channel dropped",
            ),
        );
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
    stream: UnixStream,
}

/// Shared response-writing half of an active host control channel.
#[derive(Clone)]
pub struct UnixStreamHostResponseSink {
    stream: Arc<Mutex<UnixStream>>,
}

/// Handle that interrupts all active host control-channel I/O.
pub struct UnixStreamHostControlShutdown {
    stream: UnixStream,
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
        self,
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
        let response_stream = self.stream.try_clone()?;
        let shutdown_stream = self.stream.try_clone()?;
        Ok((
            UnixStreamHostRequestSource {
                stream: self.stream,
            },
            UnixStreamHostResponseSink {
                stream: Arc::new(Mutex::new(response_stream)),
            },
            UnixStreamHostControlShutdown {
                stream: shutdown_stream,
            },
        ))
    }
}

impl UnixStreamHostControlShutdown {
    /// Shuts down the active control socket without waiting for the response
    /// writer mutex.
    pub fn shutdown(&self) -> IoResult<()> {
        shutdown(&self.stream)
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
        setup.setup_deadline = None;
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
        let pending_call = active.pending_calls.register(request_id)?;
        let request_frame = encode_request(request);

        let write_result = {
            let mut request_stream = active
                .request_stream
                .lock()
                .expect("broker request writer mutex poisoned");
            match active.pending_calls.current_failure() {
                Some(error) => Err(copy_io_error(&error)),
                None => write_frame_with_deadline(&mut request_stream, &request_frame, None),
            }
        };
        if let Err(error) = write_result {
            let _ = fail_active_channel(
                &active.pending_calls,
                &active.shutdown_stream,
                active.association_failure.as_ref(),
                error,
            );
        }

        pending_call.wait()
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
        self.negotiated = matches!(response, BrokerHandshakeResponse::Negotiated { .. });
        if self.negotiated {
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

impl UnixStreamHostRequestSource {
    /// Receives one active broker request.
    pub fn recv_request(&mut self) -> IoResult<HostReceive<BrokerRequest>> {
        let Some(frame) = read_frame_with_deadline(&mut self.stream, None)? else {
            return Ok(HostReceive::PeerClosed);
        };
        match decode_request(&frame) {
            Ok(request) => Ok(HostReceive::Message(request)),
            Err(WireError::WrongMessagePhase) => Ok(HostReceive::ProtocolViolation),
            Err(error) => Err(wire_error(error)),
        }
    }
}

impl UnixStreamHostResponseSink {
    /// Serializes and sends one complete active broker response.
    pub fn send_response(&self, response: &BrokerResponse) -> IoResult<()> {
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| Error::other("broker response writer mutex poisoned"))?;
        write_frame_with_deadline(&mut stream, &encode_response(response.clone()), None)
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
}

fn dispatch_responses(
    mut response_stream: UnixStream,
    response_cancellation: UnixStream,
    pending_calls: Arc<PendingCalls>,
    association_failure: Arc<dyn Fn() + Send + Sync>,
) {
    loop {
        let response = match read_frame_with_deadline(&mut response_stream, None) {
            Ok(Some(frame)) => match decode_response(&frame).map_err(wire_error) {
                Ok(response) => response,
                Err(error) => {
                    let _ = fail_active_channel(
                        &pending_calls,
                        &response_cancellation,
                        association_failure.as_ref(),
                        error,
                    );
                    return;
                }
            },
            Ok(None) => {
                let _ = fail_active_channel(
                    &pending_calls,
                    &response_cancellation,
                    association_failure.as_ref(),
                    Error::new(
                        ErrorKind::UnexpectedEof,
                        "broker closed the active control channel",
                    ),
                );
                return;
            }
            Err(error) => {
                let _ = fail_active_channel(
                    &pending_calls,
                    &response_cancellation,
                    association_failure.as_ref(),
                    error,
                );
                return;
            }
        };

        if let Err(error) = pending_calls.complete(response) {
            let _ = fail_active_channel(
                &pending_calls,
                &response_cancellation,
                association_failure.as_ref(),
                error,
            );
            return;
        }
    }
}

fn fail_active_channel(
    pending_calls: &PendingCalls,
    shutdown_stream: &UnixStream,
    association_failure: &(dyn Fn() + Send + Sync),
    error: Error,
) -> IoResult<()> {
    let first_failure = pending_calls.record_failure(Arc::new(error));
    let shutdown_result = shutdown(shutdown_stream);
    if first_failure {
        association_failure();
    }
    shutdown_result
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

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_protocol::message::{
        BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult,
    };
    use litebox_broker_protocol::{ObjectHandle, RequestId};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Barrier, mpsc};
    use std::time::Duration;

    fn activate_test_channel(
        stream: UnixStream,
        association_failure: impl Fn() + Send + Sync + 'static,
    ) -> (
        UnixStreamLocalControlChannel,
        UnixStreamLocalControlCancellation,
    ) {
        let mut channel = UnixStreamLocalControlChannel {
            state: UnixStreamLocalControlState::Setup(UnixStreamLocalSetup {
                stream,
                setup_deadline: None,
                negotiated: true,
            }),
        };
        let cancellation = channel.activate(association_failure).unwrap();
        (channel, cancellation)
    }

    fn activate_counting_failure_channel(
        stream: UnixStream,
    ) -> (
        UnixStreamLocalControlChannel,
        UnixStreamLocalControlCancellation,
        Arc<AtomicUsize>,
        mpsc::Receiver<()>,
    ) {
        let failure_count = Arc::new(AtomicUsize::new(0));
        let response_failure_count = Arc::clone(&failure_count);
        let (failure_sender, failure_receiver) = mpsc::channel();
        let (channel, cancellation) = activate_test_channel(stream, move || {
            response_failure_count.fetch_add(1, Ordering::SeqCst);
            failure_sender.send(()).unwrap();
        });
        (channel, cancellation, failure_count, failure_receiver)
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
    fn local_control_channel_enforces_setup_and_active_phases() {
        let (local_stream, mut host_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamLocalControlChannel::from_connected(local_stream);
        assert_eq!(
            channel
                .call(BrokerRequest {
                    request_id: RequestId(0),
                    operation: BrokerOperation::CloseObject(ObjectHandle(1)),
                })
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );

        assert_eq!(
            channel.activate(|| {}).err().unwrap().kind(),
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

        let _cancellation = channel.activate(|| {}).unwrap();

        assert_eq!(
            channel.activate(|| {}).err().unwrap().kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            channel
                .send_handshake_request(&BrokerHandshakeRequest {
                    protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
                })
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );

        let channel = Arc::new(channel);
        let call_channel = Arc::clone(&channel);
        let call = thread::spawn(move || {
            call_channel.call(BrokerRequest {
                request_id: RequestId(1),
                operation: BrokerOperation::CloseObject(ObjectHandle(1)),
            })
        });
        let request = decode_request(
            &read_frame_with_deadline(&mut host_stream, None)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        write_frame_with_deadline(
            &mut host_stream,
            &encode_response(BrokerResponse {
                request_id: request.request_id,
                result: BrokerResult::ObjectClosed,
            }),
            None,
        )
        .unwrap();
        assert_eq!(call.join().unwrap().unwrap().request_id, RequestId(1));
    }

    #[test]
    fn active_channel_matches_out_of_order_responses() {
        let (local_stream, mut host_stream) = UnixStream::pair().unwrap();
        let (channel, _cancellation) = activate_test_channel(local_stream, || {});
        let channel = Arc::new(channel);

        let first_channel = Arc::clone(&channel);
        let first = thread::spawn(move || {
            first_channel.call(BrokerRequest {
                request_id: RequestId(3),
                operation: BrokerOperation::CloseObject(ObjectHandle(3)),
            })
        });
        let second_channel = Arc::clone(&channel);
        let second = thread::spawn(move || {
            second_channel.call(BrokerRequest {
                request_id: RequestId(7),
                operation: BrokerOperation::CloseObject(ObjectHandle(7)),
            })
        });

        let first_request = decode_request(
            &read_frame_with_deadline(&mut host_stream, None)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let second_request = decode_request(
            &read_frame_with_deadline(&mut host_stream, None)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let mut request_ids = [first_request.request_id, second_request.request_id];
        request_ids.sort();
        assert_eq!(request_ids, [RequestId(3), RequestId(7)]);

        write_frame_with_deadline(
            &mut host_stream,
            &encode_response(BrokerResponse {
                request_id: second_request.request_id,
                result: BrokerResult::ObjectClosed,
            }),
            None,
        )
        .unwrap();
        write_frame_with_deadline(
            &mut host_stream,
            &encode_response(BrokerResponse {
                request_id: first_request.request_id,
                result: BrokerResult::ObjectClosed,
            }),
            None,
        )
        .unwrap();

        assert_eq!(first.join().unwrap().unwrap().request_id, RequestId(3));
        assert_eq!(second.join().unwrap().unwrap().request_id, RequestId(7));
    }

    #[test]
    fn active_channel_bounds_pending_calls_before_publication() {
        let (local_stream, mut host_stream) = UnixStream::pair().unwrap();
        host_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (channel, cancellation) = activate_test_channel(local_stream, || {});
        let channel = Arc::new(channel);
        let call_start = Arc::new(Barrier::new(MAX_PENDING_CALLS + 2));
        let callers = (0..=MAX_PENDING_CALLS)
            .map(|request_id| {
                let channel = Arc::clone(&channel);
                let call_start = Arc::clone(&call_start);
                thread::spawn(move || {
                    call_start.wait();
                    channel.call(BrokerRequest {
                        request_id: RequestId(request_id as u64),
                        operation: BrokerOperation::CloseObject(ObjectHandle(request_id as u64)),
                    })
                })
            })
            .collect::<Vec<_>>();

        call_start.wait();
        let mut published_request_ids = Vec::with_capacity(MAX_PENDING_CALLS);
        for _ in 0..MAX_PENDING_CALLS {
            let frame = read_frame_with_deadline(&mut host_stream, None)
                .unwrap()
                .unwrap();
            published_request_ids.push(decode_request(&frame).unwrap().request_id);
        }
        host_stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let error = read_frame_with_deadline(&mut host_stream, None).unwrap_err();
        assert!(matches!(
            error.kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut
        ));

        write_frame_with_deadline(
            &mut host_stream,
            &encode_response(BrokerResponse {
                request_id: published_request_ids[0],
                result: BrokerResult::ObjectClosed,
            }),
            None,
        )
        .unwrap();
        host_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let released_request = decode_request(
            &read_frame_with_deadline(&mut host_stream, None)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(!published_request_ids.contains(&released_request.request_id));

        cancellation.cancel().unwrap();
        let mut completed = 0;
        let mut failed = 0;
        for caller in callers {
            match caller.join().unwrap() {
                Ok(_) => completed += 1,
                Err(_) => failed += 1,
            }
        }
        assert_eq!(completed, 1);
        assert_eq!(failed, MAX_PENDING_CALLS);
    }

    #[test]
    fn unknown_response_identifier_fails_all_pending_calls() {
        let (local_stream, mut host_stream) = UnixStream::pair().unwrap();
        let (channel, _cancellation, failure_count, failure_receiver) =
            activate_counting_failure_channel(local_stream);
        let channel = Arc::new(channel);
        let callers = [1, 2].map(|request_id| {
            let channel = Arc::clone(&channel);
            thread::spawn(move || {
                channel.call(BrokerRequest {
                    request_id: RequestId(request_id),
                    operation: BrokerOperation::CloseObject(ObjectHandle(request_id)),
                })
            })
        });

        for _ in 0..callers.len() {
            let frame = read_frame_with_deadline(&mut host_stream, None)
                .unwrap()
                .unwrap();
            decode_request(&frame).unwrap();
        }
        write_frame_with_deadline(
            &mut host_stream,
            &encode_response(BrokerResponse {
                request_id: RequestId(99),
                result: BrokerResult::ObjectClosed,
            }),
            None,
        )
        .unwrap();

        for caller in callers {
            assert_eq!(
                caller.join().unwrap().unwrap_err().kind(),
                ErrorKind::InvalidData
            );
        }
        failure_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(failure_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn malformed_response_fails_all_pending_calls() {
        let (local_stream, mut host_stream) = UnixStream::pair().unwrap();
        let (channel, _cancellation, failure_count, failure_receiver) =
            activate_counting_failure_channel(local_stream);
        let channel = Arc::new(channel);
        let callers = [1, 2].map(|request_id| {
            let channel = Arc::clone(&channel);
            thread::spawn(move || {
                channel.call(BrokerRequest {
                    request_id: RequestId(request_id),
                    operation: BrokerOperation::CloseObject(ObjectHandle(request_id)),
                })
            })
        });

        for _ in 0..callers.len() {
            let frame = read_frame_with_deadline(&mut host_stream, None)
                .unwrap()
                .unwrap();
            decode_request(&frame).unwrap();
        }
        write_frame_with_deadline(&mut host_stream, &[u8::MAX], None).unwrap();

        for caller in callers {
            assert_eq!(
                caller.join().unwrap().unwrap_err().kind(),
                ErrorKind::InvalidData
            );
        }
        failure_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(failure_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn response_eof_fails_all_pending_calls() {
        let (local_stream, mut host_stream) = UnixStream::pair().unwrap();
        let (channel, _cancellation, failure_count, failure_receiver) =
            activate_counting_failure_channel(local_stream);
        let channel = Arc::new(channel);
        let callers = [1, 2].map(|request_id| {
            let channel = Arc::clone(&channel);
            thread::spawn(move || {
                channel.call(BrokerRequest {
                    request_id: RequestId(request_id),
                    operation: BrokerOperation::CloseObject(ObjectHandle(request_id)),
                })
            })
        });

        for _ in 0..callers.len() {
            let frame = read_frame_with_deadline(&mut host_stream, None)
                .unwrap()
                .unwrap();
            decode_request(&frame).unwrap();
        }
        drop(host_stream);

        for caller in callers {
            assert_eq!(
                caller.join().unwrap().unwrap_err().kind(),
                ErrorKind::UnexpectedEof
            );
        }
        failure_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(failure_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn request_write_failure_fails_existing_pending_calls() {
        let (local_stream, mut host_stream) = UnixStream::pair().unwrap();
        let (channel, _cancellation, failure_count, failure_receiver) =
            activate_counting_failure_channel(local_stream);
        let channel = Arc::new(channel);
        let pending_callers = [1, 2].map(|request_id| {
            let channel = Arc::clone(&channel);
            thread::spawn(move || {
                channel.call(BrokerRequest {
                    request_id: RequestId(request_id),
                    operation: BrokerOperation::CloseObject(ObjectHandle(request_id)),
                })
            })
        });
        for _ in 0..pending_callers.len() {
            let frame = read_frame_with_deadline(&mut host_stream, None)
                .unwrap()
                .unwrap();
            decode_request(&frame).unwrap();
        }

        host_stream.shutdown(Shutdown::Read).unwrap();
        let failing_channel = Arc::clone(&channel);
        let failing_caller = thread::spawn(move || {
            failing_channel.call(BrokerRequest {
                request_id: RequestId(3),
                operation: BrokerOperation::CloseObject(ObjectHandle(3)),
            })
        });

        assert!(failing_caller.join().unwrap().is_err());
        for caller in pending_callers {
            assert!(caller.join().unwrap().is_err());
        }
        failure_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(failure_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn duplicate_response_identifier_fails_other_pending_calls() {
        let (local_stream, mut host_stream) = UnixStream::pair().unwrap();
        let (channel, _cancellation, failure_count, failure_receiver) =
            activate_counting_failure_channel(local_stream);
        let channel = Arc::new(channel);
        let first_channel = Arc::clone(&channel);
        let first = thread::spawn(move || {
            first_channel.call(BrokerRequest {
                request_id: RequestId(1),
                operation: BrokerOperation::CloseObject(ObjectHandle(1)),
            })
        });
        let second_channel = Arc::clone(&channel);
        let second = thread::spawn(move || {
            second_channel.call(BrokerRequest {
                request_id: RequestId(2),
                operation: BrokerOperation::CloseObject(ObjectHandle(2)),
            })
        });

        for _ in 0..2 {
            let frame = read_frame_with_deadline(&mut host_stream, None)
                .unwrap()
                .unwrap();
            decode_request(&frame).unwrap();
        }
        let response = encode_response(BrokerResponse {
            request_id: RequestId(1),
            result: BrokerResult::ObjectClosed,
        });
        write_frame_with_deadline(&mut host_stream, &response, None).unwrap();
        write_frame_with_deadline(&mut host_stream, &response, None).unwrap();

        assert_eq!(first.join().unwrap().unwrap().request_id, RequestId(1));
        assert_eq!(
            second.join().unwrap().unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        failure_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(failure_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn completed_call_wins_over_later_association_failure() {
        let pending = PendingCalls::new();
        let request_id = RequestId(1);
        let pending_call = pending.register(request_id).unwrap();
        pending
            .complete(BrokerResponse {
                request_id,
                result: BrokerResult::ObjectClosed,
            })
            .unwrap();
        pending.record_failure(Arc::new(Error::new(
            ErrorKind::ConnectionAborted,
            "test failure",
        )));

        assert_eq!(pending_call.wait().unwrap().request_id, request_id);
    }

    #[test]
    fn duplicate_pending_registration_preserves_the_original_call() {
        let pending = PendingCalls::new();
        let request_id = RequestId(1);
        let pending_call = pending.register(request_id).unwrap();
        assert_eq!(
            pending.register(request_id).err().unwrap().kind(),
            ErrorKind::InvalidData
        );
        pending
            .complete(BrokerResponse {
                request_id,
                result: BrokerResult::ObjectClosed,
            })
            .unwrap();

        assert_eq!(pending_call.wait().unwrap().request_id, request_id);
    }

    #[test]
    fn association_failure_wins_before_completion() {
        let pending = PendingCalls::new();
        let request_id = RequestId(1);
        let pending_call = pending.register(request_id).unwrap();
        pending.record_failure(Arc::new(Error::new(
            ErrorKind::ConnectionAborted,
            "test failure",
        )));

        assert!(
            pending
                .complete(BrokerResponse {
                    request_id,
                    result: BrokerResult::ObjectClosed,
                })
                .is_err()
        );
        assert_eq!(
            pending_call.wait().unwrap_err().kind(),
            ErrorKind::ConnectionAborted
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
            state: UnixStreamLocalControlState::Setup(UnixStreamLocalSetup {
                stream: local_stream,
                setup_deadline: Some(Instant::now() + Duration::from_millis(50)),
                negotiated: false,
            }),
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
    fn host_control_requires_negotiation_before_active_split() {
        let (_peer_stream, host_stream) = UnixStream::pair().unwrap();
        let channel = UnixStreamHostControlChannel::from_accepted(host_stream);

        assert!(channel.into_active().is_err());
    }

    #[test]
    fn concurrent_host_response_sinks_write_complete_frames() {
        let (mut peer_stream, host_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamHostControlChannel::from_accepted(host_stream);
        channel
            .send_handshake_response(&BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
            })
            .unwrap();
        let handshake = read_frame_with_deadline(&mut peer_stream, None)
            .unwrap()
            .unwrap();
        assert!(matches!(
            decode_handshake_response(&handshake).unwrap(),
            BrokerHandshakeResponse::Negotiated { .. }
        ));
        let (_request_source, response_sink, _shutdown) = channel.into_active().unwrap();
        let first_sink = response_sink.clone();
        let first = std::thread::spawn(move || {
            first_sink
                .send_response(&BrokerResponse {
                    request_id: RequestId(1),
                    result: BrokerResult::ObjectClosed,
                })
                .unwrap();
        });
        let second = std::thread::spawn(move || {
            response_sink
                .send_response(&BrokerResponse {
                    request_id: RequestId(2),
                    result: BrokerResult::ObjectClosed,
                })
                .unwrap();
        });

        let mut response_ids = [RequestId(0); 2];
        for response_id in &mut response_ids {
            let frame = read_frame_with_deadline(&mut peer_stream, None)
                .unwrap()
                .unwrap();
            *response_id = decode_response(&frame).unwrap().request_id;
        }
        response_ids.sort();
        assert_eq!(response_ids, [RequestId(1), RequestId(2)]);
        first.join().unwrap();
        second.join().unwrap();
    }

    #[test]
    fn local_control_cancellation_unblocks_pending_call() {
        let (local_stream, mut host_stream) = UnixStream::pair().unwrap();
        host_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (channel, cancellation) = activate_test_channel(local_stream, || {});
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let caller = std::thread::spawn(move || {
            result_sender
                .send(channel.call(BrokerRequest {
                    request_id: RequestId(0),
                    operation: BrokerOperation::CloseObject(litebox_broker_protocol::ObjectHandle(
                        1,
                    )),
                }))
                .unwrap();
        });

        let frame = read_frame_with_deadline(&mut host_stream, None)
            .unwrap()
            .unwrap();
        decode_request(&frame).unwrap();
        assert!(matches!(
            result_receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        cancellation.cancel().unwrap();

        assert_eq!(
            result_receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap_err()
                .kind(),
            ErrorKind::ConnectionAborted
        );
        caller.join().unwrap();
    }

    #[test]
    fn dropping_local_control_closes_connection_with_cancellation_clone() {
        let (local_stream, mut host_stream) = UnixStream::pair().unwrap();
        let (channel, _cancellation) = activate_test_channel(local_stream, || {});
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
            &encode_request(BrokerRequest {
                request_id: RequestId(0),
                operation: BrokerOperation::Event(
                    litebox_broker_protocol::message::EventRequest::Create(
                        litebox_broker_protocol::event::CreateEventRequest { initial_count: 0 },
                    ),
                ),
            }),
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
