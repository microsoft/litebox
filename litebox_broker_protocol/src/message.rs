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
use crate::{ObjectHandle, ProtocolVersion};

/// Broker handshake request sent before the control channel is active.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerHandshakeRequest {
    /// Required protocol version.
    pub protocol_version: ProtocolVersion,
}

/// Broker request sent over an active control channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerRequest {
    /// Close one broker object reference.
    CloseObject(ObjectHandle),
    /// Check the current readiness of a broker-owned object.
    CheckReadiness(ObjectHandle),
    /// Event object request family.
    Event(EventRequest),
    /// Pipe object request family.
    Pipe(PipeRequest),
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

/// Broker response sent over an active control channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerResponse {
    /// Object close operation completed.
    ObjectClosed,
    /// Current readiness of a broker-owned object.
    Readiness(ReadinessFlags),
    /// Event object response family.
    Event(EventResponse),
    /// Pipe object response family.
    Pipe(PipeResponse),
    /// Operation failed with an ABI-neutral broker error.
    Error(ErrorCode),
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
