// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Clock sources supplied through [`crate::BootConfig`].

/// The kernel clock of `litebox_common_vm_abi`, which ring 3 reads too, from
/// a counter at `StartupInfo::clock_khz`: so the installed source must be
/// that counter's, at that frequency (as [`litebox_hal::clock::Clock`] is),
/// or the kernel and ring 3 silently disagree on every time and deadline.
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
