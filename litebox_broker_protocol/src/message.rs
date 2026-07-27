// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::error::ErrorCode;
use crate::event::{
    AddEventRequest, AddEventResponse, ConsumeEventRequest, ConsumeEventResponse,
    CreateEventRequest, CreateEventResponse,
};
use crate::pipe::{
    CreatePipeRequest, CreatePipeResponse, ReadPipeRequest, ReadPipeResponse, WritePipeRequest,
    WritePipeResponse,
};
use crate::readiness::ReadinessFlags;
use crate::socket::{
    ConnectSocketRequest, ConnectSocketResponse, CreateSocketRequest, CreateSocketResponse,
    ReceiveSocketRequest, ReceiveSocketResponse, SendSocketRequest, SendSocketResponse,
    ShutdownSocketRequest, SocketError, SocketStatusRequest, SocketStatusResponse,
};
use crate::{ObjectHandle, ProtocolVersion, RequestId};

/// Broker handshake request sent before the control channel is active.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerHandshakeRequest {
    /// Required protocol version.
    pub protocol_version: ProtocolVersion,
}

/// Operation requested over an active broker control channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerOperation {
    /// Close one broker object reference.
    CloseObject(ObjectHandle),
    /// Check the current readiness of a broker-owned object.
    CheckReadiness(ObjectHandle),
    /// Event object request family.
    Event(EventRequest),
    /// Pipe object request family.
    Pipe(PipeRequest),
    /// Socket object request family.
    Socket(SocketRequest),
}

/// Request sent over an active broker control channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerRequest {
    /// Correlation identifier allocated by the local endpoint.
    pub request_id: RequestId,
    /// Requested broker operation.
    pub operation: BrokerOperation,
}

/// Broker handshake response sent before the control channel is active.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerHandshakeResponse {
    /// Negotiation result.
    Negotiated {
        /// Broker protocol version supported by this endpoint.
        ///
        /// The broker returns its supported version after validating that the
        /// requested version matches it.
        broker_protocol_version: ProtocolVersion,
    },
    /// Negotiation failed because the requested version is unsupported.
    ///
    /// The connection remains in negotiation state and the local peer may retry
    /// with a compatible version using the broker-supported version advertised
    /// here.
    VersionMismatch {
        /// Broker protocol version supported by this endpoint.
        broker_protocol_version: ProtocolVersion,
    },
    /// Handshake failed with an ABI-neutral broker error.
    Error(ErrorCode),
}

/// Broker-owned event object request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventRequest {
    /// Create a broker-owned event object.
    Create(CreateEventRequest),
    /// Add readiness credits to an event.
    Add(AddEventRequest),
    /// Consume readiness credits from an event.
    Consume(ConsumeEventRequest),
}

/// Broker-owned pipe object request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PipeRequest {
    /// Create a broker-owned byte pipe.
    Create(CreatePipeRequest),
    /// Read bytes from a pipe.
    Read(ReadPipeRequest),
    /// Write bytes to a pipe.
    Write(WritePipeRequest),
}

/// Broker-owned socket object request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketRequest {
    /// Create a broker-owned socket.
    Create(CreateSocketRequest),
    /// Connect a socket to a remote address.
    Connect(ConnectSocketRequest),
    /// Send bytes staged in shared memory.
    Send(SendSocketRequest),
    /// Receive bytes into shared memory.
    Receive(ReceiveSocketRequest),
    /// Shut down one or both directions.
    Shutdown(ShutdownSocketRequest),
    /// Read a socket's connection state.
    Status(SocketStatusRequest),
}

/// Result returned for an active broker operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerResult {
    /// Object close operation completed.
    ObjectClosed,
    /// Current readiness of a broker-owned object.
    Readiness(ReadinessFlags),
    /// Event object response family.
    Event(EventResponse),
    /// Pipe object response family.
    Pipe(PipeResponse),
    /// Socket object response family.
    Socket(SocketResponse),
    /// Operation failed with an ABI-neutral broker error.
    Error(ErrorCode),
}

/// Response sent over an active broker control channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerResponse {
    /// Correlation identifier copied from the request.
    pub request_id: RequestId,
    /// Result of the requested broker operation.
    pub result: BrokerResult,
}

/// Broker-owned event object response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventResponse {
    /// Create operation response.
    Create(CreateEventResponse),
    /// Add operation response.
    Add(AddEventResponse),
    /// Consume operation response.
    Consume(ConsumeEventResponse),
}

/// Broker-owned pipe object response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PipeResponse {
    /// Create operation response.
    Create(CreatePipeResponse),
    /// Read operation response.
    Read(ReadPipeResponse),
    /// Write operation response.
    Write(WritePipeResponse),
}

/// Broker-owned socket object response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketResponse {
    /// Create operation response.
    Create(CreateSocketResponse),
    /// Connect operation response.
    Connect(ConnectSocketResponse),
    /// Send operation response.
    Send(SendSocketResponse),
    /// Receive operation response.
    Receive(ReceiveSocketResponse),
    /// Shutdown operation completed.
    Shutdown,
    /// Status operation response.
    Status(SocketStatusResponse),
    /// A non-connect host network operation failed.
    ///
    /// Connect and status responses carry terminal failures in
    /// [`SocketConnectionStatus`] so repeated status requests remain
    /// idempotent. Broker and request-validation failures use
    /// [`BrokerResult::Error`] instead.
    ///
    /// [`SocketConnectionStatus`]: crate::socket::SocketConnectionStatus
    Failed(SocketError),
}

/// Broker-initiated asynchronous notification.
///
/// Notifications are level-triggered snapshots and may be coalesced or
/// duplicated by a transport. Local waiters must treat them as wakeups to
/// re-check authoritative state, not as ordered state transitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerNotification {
    /// Readiness changed or should be re-checked for a broker-owned object.
    Readiness(ReadinessNotification),
}

/// Readiness notification for a broker-owned object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadinessNotification {
    /// Broker object handle.
    pub handle: ObjectHandle,
    /// Current broker-authoritative readiness snapshot.
    pub readiness: ReadinessFlags,
}
