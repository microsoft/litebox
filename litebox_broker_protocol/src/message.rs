// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::error::ErrorCode;
use crate::event::{
    AddEventRequest, AddEventResponse, ConsumeEventRequest, ConsumeEventResponse,
    CreateEventRequest, CreateEventResponse, ReadinessState, WaitEventRequest, WaitEventResponse,
};
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
    /// Event object request family.
    Event(EventRequest),
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
    /// Check whether an event wait would complete now.
    Wait(WaitEventRequest),
    /// Add readiness credits to an event.
    Add(AddEventRequest),
    /// Consume readiness credits from an event.
    Consume(ConsumeEventRequest),
}

/// Broker response sent over an active control channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerResponse {
    /// Object close operation completed.
    ObjectClosed,
    /// Event object response family.
    Event(EventResponse),
    /// Operation failed with an ABI-neutral broker error.
    Error(ErrorCode),
}

/// Broker-owned event object response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventResponse {
    /// Create operation response.
    Create(CreateEventResponse),
    /// Wait operation response.
    Wait(WaitEventResponse),
    /// Add operation response.
    Add(AddEventResponse),
    /// Consume operation response.
    Consume(ConsumeEventResponse),
}

/// Broker-initiated asynchronous notification.
///
/// Notifications are level-triggered snapshots and may be coalesced or
/// duplicated by a transport. Local waiters must treat them as wakeups to
/// re-check authoritative state, not as ordered state transitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerNotification {
    /// Readiness changed or should be re-checked for a broker-owned event object.
    EventReadiness(EventReadinessNotification),
}

/// Readiness notification for a broker-owned event object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventReadinessNotification {
    /// Event object handle.
    pub handle: ObjectHandle,
    /// Current broker-authoritative readiness snapshot.
    pub readiness: ReadinessState,
}
