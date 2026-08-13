// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned timerfd object contracts.
//!
//! A broker timerfd delegates all timekeeping to a host-owned Linux `timerfd`
//! descriptor; these messages carry only the ABI-neutral timer specification and
//! the drained expiration count. Readiness (`READ` when at least one expiration
//! is pending) is published asynchronously through the shared readiness path,
//! exactly like broker sockets.

use crate::ObjectHandle;
use crate::readiness::ReadinessFlags;

/// A timerfd setting (initial expiration plus interval), mirroring the Linux
/// `struct itimerspec`.
///
/// Seconds and nanoseconds are carried verbatim so the broker core can validate
/// nanosecond ranges rather than trusting the local endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimerSpec {
    /// Seconds until the initial expiration (`it_value.tv_sec`).
    pub value_seconds: u64,
    /// Nanoseconds until the initial expiration (`it_value.tv_nsec`).
    pub value_nanoseconds: u64,
    /// Interval seconds for periodic re-arming (`it_interval.tv_sec`).
    pub interval_seconds: u64,
    /// Interval nanoseconds for periodic re-arming (`it_interval.tv_nsec`).
    pub interval_nanoseconds: u64,
}

/// Request to create a broker-owned timerfd object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateTimerRequest {
    /// Clock the timer is measured against (`CLOCK_MONOTONIC` / `CLOCK_REALTIME`).
    pub clock_id: i32,
}

/// Response to a timerfd create request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateTimerResponse {
    /// Created timerfd handle.
    pub handle: ObjectHandle,
}

/// Request to arm or disarm a broker-owned timerfd.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetTimerRequest {
    /// Timer handle.
    pub handle: ObjectHandle,
    /// New timer setting; an all-zero `value` disarms the timer.
    pub specification: TimerSpec,
    /// Set-time flags (`TFD_TIMER_ABSTIME`, `TFD_TIMER_CANCEL_ON_SET`).
    pub flags: u32,
}

/// Response to a timerfd set-time request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetTimerResponse {
    /// The timer setting that was in effect before this call.
    pub previous: TimerSpec,
    /// Readiness state after re-arming.
    pub readiness: ReadinessFlags,
}

/// Request to read a broker-owned timerfd's current setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetTimerRequest {
    /// Timer handle.
    pub handle: ObjectHandle,
}

/// Response to a timerfd get-time request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetTimerResponse {
    /// The time remaining until the next expiration and the current interval.
    pub current: TimerSpec,
}

/// Request to drain a broker-owned timerfd's expiration count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadTimerRequest {
    /// Timer handle.
    pub handle: ObjectHandle,
}

/// Response to a timerfd read request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadTimerResponse {
    /// Number of expirations since the last successful read (`>= 1` for a real
    /// expiration, `0` when the read was cancelled).
    pub expirations: u64,
    /// Set when the timer was cancelled by a discontinuous clock change
    /// (`CANCEL_ON_SET`); the guest maps this to `ECANCELED`.
    pub cancelled: bool,
    /// Readiness state after draining.
    pub readiness: ReadinessFlags,
}
