// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Common macOS types for LiteBox.

#![no_std]

use core::ffi::c_int;

bitflags::bitflags! {
    /// Address-wait/wake flags; empty flags select process-private synchronization.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(transparent)]
    pub struct OsSyncFlags: u32 {
        /// Synchronize processes using a shared-memory backing object.
        const SHARED = 1;
    }
}

/// Clock used for an address-wait timeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum OsClockId {
    /// Monotonic time excluding time spent asleep.
    MachAbsoluteTime = 32,
}

/// Address-wait/wake result: nonnegative on success, or -1 with `errno` set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
#[must_use]
pub struct OsSyncResult(c_int);

impl OsSyncResult {
    /// Whether the call succeeded; otherwise the caller must read `errno`.
    pub const fn is_success(self) -> bool {
        self.0 >= 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_match_the_c_abi_layout() {
        assert_eq!(size_of::<OsSyncFlags>(), size_of::<u32>());
        assert_eq!(align_of::<OsSyncFlags>(), align_of::<u32>());
        assert_eq!(size_of::<OsClockId>(), size_of::<u32>());
        assert_eq!(align_of::<OsClockId>(), align_of::<u32>());
        assert_eq!(size_of::<OsSyncResult>(), size_of::<c_int>());
        assert_eq!(align_of::<OsSyncResult>(), align_of::<c_int>());
    }

    #[test]
    fn constants_match_the_native_abi() {
        assert_eq!(OsSyncFlags::empty().bits(), 0);
        assert!(!OsSyncFlags::empty().contains(OsSyncFlags::SHARED));
        assert_eq!(OsSyncFlags::SHARED.bits(), 1);
        assert_eq!(OsClockId::MachAbsoluteTime as u32, 32);
    }

    #[test]
    fn success_includes_positive_waiter_counts() {
        assert!(!OsSyncResult(-1).is_success());
        assert!(OsSyncResult(0).is_success());
        assert!(OsSyncResult(1).is_success());
        assert!(OsSyncResult(c_int::MAX).is_success());
    }
}
