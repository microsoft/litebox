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

impl ReadinessState {
    /// Creates a readiness state.
    pub const fn new(read_ready: bool, write_ready: bool) -> Self {
        Self {
            read_ready,
            write_ready,
        }
    }
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

impl CreateEventRequest {
    /// Creates an event create request.
    pub const fn new(initial_count: u64) -> Self {
        Self { initial_count }
    }
}

/// Response to an event create request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateEventResponse {
    /// Created event handle.
    pub handle: ObjectHandle,
}

impl CreateEventResponse {
    /// Creates an event create response.
    pub const fn new(handle: ObjectHandle) -> Self {
        Self { handle }
    }
}

/// Request to check whether an event wait would complete now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitEventRequest {
    /// Event handle.
    pub handle: ObjectHandle,
}

impl WaitEventRequest {
    /// Creates an event wait request.
    pub const fn new(handle: ObjectHandle) -> Self {
        Self { handle }
    }
}

/// Response to an event wait request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitEventResponse {
    /// Current wait outcome.
    pub outcome: WaitOutcome,
}

impl WaitEventResponse {
    /// Creates an event wait response.
    pub const fn new(outcome: WaitOutcome) -> Self {
        Self { outcome }
    }
}

/// Request to add readiness credits to an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddEventRequest {
    /// Event handle.
    pub handle: ObjectHandle,
    /// Readiness credits to add.
    pub value: u64,
}

impl AddEventRequest {
    /// Creates an event add request.
    pub const fn new(handle: ObjectHandle, value: u64) -> Self {
        Self { handle, value }
    }
}

/// Response to an event add request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddEventResponse {
    /// Readiness state after adding credits.
    pub readiness: ReadinessState,
}

impl AddEventResponse {
    /// Creates an event add response.
    pub const fn new(readiness: ReadinessState) -> Self {
        Self { readiness }
    }
}

/// Request to consume readiness credits from an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumeEventRequest {
    /// Event handle.
    pub handle: ObjectHandle,
    /// Consume mode.
    pub mode: EventConsumeMode,
}

impl ConsumeEventRequest {
    /// Creates an event consume request.
    pub const fn new(handle: ObjectHandle, mode: EventConsumeMode) -> Self {
        Self { handle, mode }
    }
}

/// Result of consuming readiness credits from a broker-owned event object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventConsumption {
    /// Number of readiness credits consumed.
    pub value: u64,
    /// Readiness state after consuming credits.
    pub readiness: ReadinessState,
}

impl EventConsumption {
    /// Creates an event consumption result.
    pub const fn new(value: u64, readiness: ReadinessState) -> Self {
        Self { value, readiness }
    }
}

/// Response to an event consume request.
pub type ConsumeEventResponse = EventConsumption;
