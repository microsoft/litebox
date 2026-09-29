// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::ObjectHandle;

/// Relative expiration schedule of a broker-owned timer.
///
/// Times are nanoseconds on the broker's monotonic clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimerSpec {
    /// Time until the next expiration, or zero if the timer is disarmed.
    pub value_ns: u64,
    /// Period of subsequent expirations, or zero for a one-shot timer.
    pub interval_ns: u64,
}

/// Response to a timer create request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateTimerResponse {
    /// Created timer handle.
    pub handle: ObjectHandle,
}

/// Request to arm or disarm a timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetTimerRequest {
    /// Timer handle.
    pub handle: ObjectHandle,
    /// New schedule. A zero `value_ns` disarms the timer.
    pub spec: TimerSpec,
}

/// Response to a timer set request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetTimerResponse {
    /// Schedule in effect before the set request.
    pub previous: TimerSpec,
}

/// Request to read a timer's current schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetTimerRequest {
    /// Timer handle.
    pub handle: ObjectHandle,
}

/// Response to a timer get request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetTimerResponse {
    /// Current schedule.
    pub current: TimerSpec,
}

/// Request to consume a timer's pending expirations.
///
/// The broker returns `WouldBlock` when no expiration is pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadTimerRequest {
    /// Timer handle.
    pub handle: ObjectHandle,
}

/// Response to a timer read request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadTimerResponse {
    /// Number of expirations consumed. Always nonzero.
    pub expirations: u64,
}
