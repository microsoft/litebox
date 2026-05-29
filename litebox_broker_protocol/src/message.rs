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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BrokerRequest {
    /// Protocol negotiation request.
    Negotiate {
        /// Required protocol version.
        protocol_version: ProtocolVersion,
    },
    /// Create a broker-owned event object.
    CreateEvent,
    /// Check whether an event wait would complete now.
    WaitEvent {
        /// Event handle.
        handle: ObjectHandle,
    },
    /// Signal an event.
    SignalEvent {
        /// Event handle.
        handle: ObjectHandle,
    },
}

/// Broker response transported over the control channel.
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
    /// Operation returned a broker object handle.
    Handle(ObjectHandle),
    /// Operation returned readiness state.
    Readiness(ReadinessState),
    /// Operation returned wait state.
    Wait(WaitOutcome),
    /// Operation failed with an ABI-neutral broker error.
    Error(ErrorCode),
}
