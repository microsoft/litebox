// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::time::Duration;

use crate::ObjectHandle;
use crate::fs::FileOpenFlags;

wire_struct! {
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
}

wire_enum! {
    /// Guest clock against which absolute expiration times are measured.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub enum TimerClock {
        #[default]
        Monotonic,
        /// XXX: Unlike Linux, armed absolute timers use a monotonic delay and ignore later wall-clock changes.
        RealTime,
    }
}

wire_enum! {
    /// Both kinds of schedule arm a broker monotonic alarm. Guest clocks need
    /// not share the broker clock's epoch.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TimerSetting {
        Relative(TimerSpec),
        Absolute {
            deadline: Duration,
            interval_ns: u64,
            realtime_now: Duration,
            monotonic_now: Duration,
        },
    }
}

impl From<TimerSpec> for TimerSetting {
    fn from(spec: TimerSpec) -> Self {
        Self::Relative(spec)
    }
}

wire_struct! {
    /// Request to create a disarmed timer.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct CreateTimerRequest {
        /// Initial status flags, within [`FileOpenFlags::STATUS`].
        pub flags: FileOpenFlags,
        /// Clock used by absolute sets for the life of this timer.
        pub clock: TimerClock,
    }
}

wire_struct! {
    /// Response to a timer create request.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CreateTimerResponse {
        /// Created timer handle.
        pub handle: ObjectHandle,
    }
}

wire_struct! {
    /// Request to arm or disarm a timer.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SetTimerRequest {
        /// Timer handle.
        pub handle: ObjectHandle,
        /// New schedule. A zero deadline or relative delay disarms the timer.
        pub setting: TimerSetting,
    }
}

wire_struct! {
    /// Response to a timer set request.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SetTimerResponse {
        /// Schedule in effect before the set request.
        pub previous: TimerSpec,
    }
}

wire_struct! {
    /// Request to read a timer's current schedule.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct GetTimerRequest {
        /// Timer handle.
        pub handle: ObjectHandle,
    }
}

wire_struct! {
    /// Response to a timer get request.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct GetTimerResponse {
        /// Current schedule.
        pub current: TimerSpec,
    }
}

wire_struct! {
    /// Response to a clock read request.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ReadClocksResponse {
        /// Current time on the broker's monotonic clock.
        pub monotonic: Duration,
        /// Current wall-clock time since the Unix epoch.
        pub realtime: Duration,
    }
}

wire_struct! {
    /// Request to consume a timer's pending expirations.
    ///
    /// The broker returns `WouldBlock` when no expiration is pending, or
    /// `NonBlockingWouldBlock` if the timer is also non-blocking.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ReadTimerRequest {
        /// Timer handle.
        pub handle: ObjectHandle,
    }
}

wire_struct! {
    /// Response to a timer read request.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ReadTimerResponse {
        /// Number of expirations consumed. Always nonzero.
        pub expirations: u64,
    }
}
