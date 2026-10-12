// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Clock sources supplied through [`crate::BootConfig`].

pub trait ClockSource: Sync {
    /// Nanoseconds since an arbitrary origin that is fixed for the kernel's
    /// lifetime. Never decreases.
    fn monotonic_nanos(&self) -> u64;
}

impl ClockSource for litebox_hal::clock::Clock {
    fn monotonic_nanos(&self) -> u64 {
        self.nanos()
    }
}
