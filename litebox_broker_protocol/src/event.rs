// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::ObjectHandle;

/// Broker-authoritative readiness state for one object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadinessState {
    /// Whether an event read/consume operation can complete without blocking.
    pub read_ready: bool,
    /// Whether an event write/add operation can complete without blocking.
    pub write_ready: bool,
}

/// Result of checking whether a broker event read wait would complete now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WaitOutcome {
    /// The object is read-ready now.
    Ready(ReadinessState),
    /// The object is not read-ready; deployment-specific wait plumbing may block.
    WouldBlock(ReadinessState),
}

/// How a broker event consume operation should remove readiness credits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventConsumeMode {
    /// Consume all currently available credits.
    All,
    /// Consume one credit.
    One,
}

/// Request to create a broker-owned event object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CreateEventRequest {
    /// Initial readiness credits.
    pub initial_count: u64,
}

/// Response to an event create request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateEventResponse {
    /// Created event handle.
    pub handle: ObjectHandle,
}

/// Request to check whether an event wait would complete now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitEventRequest {
    /// Event handle.
    pub handle: ObjectHandle,
}

/// Response to an event wait request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitEventResponse {
    /// Current wait outcome.
    pub outcome: WaitOutcome,
}

/// Request to add readiness credits to an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddEventRequest {
    /// Event handle.
    pub handle: ObjectHandle,
    /// Readiness credits to add.
    pub value: u64,
}

/// Response to an event add request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddEventResponse {
    /// Readiness state after adding credits.
    pub readiness: ReadinessState,
}

/// Request to consume readiness credits from an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumeEventRequest {
    /// Event handle.
    pub handle: ObjectHandle,
    /// Consume mode.
    pub mode: EventConsumeMode,
}

/// Result of consuming readiness credits from a broker-owned event object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventConsumption {
    /// Number of readiness credits consumed.
    pub value: u64,
    /// Readiness state after consuming credits.
    pub readiness: ReadinessState,
}

/// Response to an event consume request.
pub type ConsumeEventResponse = EventConsumption;
