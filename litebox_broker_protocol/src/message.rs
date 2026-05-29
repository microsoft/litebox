// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{ErrorCode, ObjectHandle, ProtocolVersion};

/// Broker-authoritative readiness state for one object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadinessState {
    /// Whether the object is currently ready.
    pub ready: bool,
    /// Monotonic readiness generation used to invalidate user-side readiness caches.
    pub generation: u64,
}

impl ReadinessState {
    /// Creates a readiness state.
    pub const fn new(ready: bool, generation: u64) -> Self {
        Self { ready, generation }
    }
}

/// Result of checking a wait condition in BrokerCore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WaitOutcome {
    /// The object is ready now.
    Ready(ReadinessState),
    /// The object is not ready; deployment-specific wait plumbing may block.
    WouldBlock(ReadinessState),
}

/// Broker request transported over the control channel.
///
/// The outer broker request is intentionally small. Object-family and
/// domain-specific operations are grouped below it so new object families do not
/// accumulate as unrelated top-level broker variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BrokerRequest {
    /// Protocol negotiation request.
    Negotiate {
        /// Required protocol version.
        protocol_version: ProtocolVersion,
    },
    /// BrokerCore authority request.
    Core(CoreRequest),
}

/// Request adapted by the broker server into a BrokerCore domain call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreRequest {
    /// Event object request family.
    Event(EventRequest),
}

/// Broker-owned event object request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventRequest {
    /// Create a broker-owned event object.
    Create,
    /// Check whether an event wait would complete now.
    Wait {
        /// Event handle.
        handle: ObjectHandle,
    },
    /// Signal an event.
    Signal {
        /// Event handle.
        handle: ObjectHandle,
    },
}

/// Broker response transported over the control channel.
///
/// Common connection/protocol outcomes stay at this layer. Domain payloads are
/// grouped under [`CoreResponse`] so future object families can evolve without
/// turning the broker envelope into a flat operation/result list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BrokerResponse {
    /// Negotiation result.
    Negotiated {
        /// Broker protocol version supported by this endpoint.
        ///
        /// The broker returns its supported version after validating that the
        /// requested version is supported according to
        /// [`ProtocolVersion::is_supported_by`](crate::ProtocolVersion::is_supported_by).
        broker_protocol_version: ProtocolVersion,
    },
    /// Negotiation failed because the requested version is unsupported.
    ///
    /// The connection remains in negotiation state and the client may retry
    /// with a compatible version using the broker-supported version advertised
    /// here.
    VersionMismatch {
        /// Broker protocol version supported by this endpoint.
        broker_protocol_version: ProtocolVersion,
    },
    /// BrokerCore authority response.
    Core(CoreResponse),
    /// Operation failed with an ABI-neutral broker error.
    Error(ErrorCode),
}

/// Response returned by a BrokerCore domain request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreResponse {
    /// Event object response family.
    Event(EventResponse),
}

/// Broker-owned event object response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventResponse {
    /// Operation returned a broker object handle.
    Created { handle: ObjectHandle },
    /// Operation returned readiness state.
    Signaled { readiness: ReadinessState },
    /// Operation returned wait state.
    Wait { outcome: WaitOutcome },
}
