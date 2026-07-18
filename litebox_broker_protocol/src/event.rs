// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::ObjectHandle;
use crate::readiness::ReadinessFlags;

/// How a broker event consume operation should remove readiness credits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    pub readiness: ReadinessFlags,
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
    pub readiness: ReadinessFlags,
}

/// Response to an event consume request.
pub type ConsumeEventResponse = EventConsumption;
