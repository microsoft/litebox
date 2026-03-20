// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NTSTATUS codes used by the NT shim.
//!
//! Only codes actually needed by the shim are defined here. Additional codes
//! should be added as new syscalls are implemented.

/// An NT status code (signed 32-bit value).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct NtStatus(pub i32);

impl NtStatus {
    /// Construct an `NtStatus` from a raw 32-bit value.
    #[inline]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw as i32)
    }

    /// Return the raw 32-bit value.
    #[inline]
    pub const fn raw(self) -> u32 {
        self.0 as u32
    }

    /// Returns true if this status represents success (bit 31 clear, bits 29-30 clear).
    #[inline]
    pub const fn is_success(self) -> bool {
        self.0 >= 0
    }

    /// Returns true if this status represents an error (bit 31 set).
    #[inline]
    pub const fn is_error(self) -> bool {
        self.0 < 0
    }

    // ---- Success codes ----

    pub const STATUS_SUCCESS: Self = Self(0x0000_0000);
    pub const STATUS_PENDING: Self = Self(0x0000_0103);
    pub const STATUS_BUFFER_OVERFLOW: Self = Self(0x8000_0005u32 as i32);

    // ---- Warning codes ----

    pub const STATUS_OBJECT_NAME_EXISTS: Self = Self(0x4000_0000);
    /// The image was loaded at a different address than its preferred base.
    pub const STATUS_IMAGE_NOT_AT_BASE: Self = Self(0x4000_0003);

    // ---- Error codes ----

    pub const STATUS_UNSUCCESSFUL: Self = Self(0xC000_0001u32 as i32);
    pub const STATUS_NOT_IMPLEMENTED: Self = Self(0xC000_0002u32 as i32);
    pub const STATUS_INVALID_INFO_CLASS: Self = Self(0xC000_0003u32 as i32);
    pub const STATUS_INFO_LENGTH_MISMATCH: Self = Self(0xC000_0004u32 as i32);
    pub const STATUS_ACCESS_VIOLATION: Self = Self(0xC000_0005u32 as i32);
    pub const STATUS_INVALID_HANDLE: Self = Self(0xC000_0008u32 as i32);
    pub const STATUS_INVALID_PARAMETER: Self = Self(0xC000_000Du32 as i32);
    pub const STATUS_NO_SUCH_FILE: Self = Self(0xC000_000Fu32 as i32);
    pub const STATUS_END_OF_FILE: Self = Self(0xC000_0011u32 as i32);
    pub const STATUS_NO_MEMORY: Self = Self(0xC000_0017u32 as i32);
    pub const STATUS_CONFLICTING_ADDRESSES: Self = Self(0xC000_0018u32 as i32);
    pub const STATUS_MEMORY_NOT_ALLOCATED: Self = Self(0xC000_0019u32 as i32);
    pub const STATUS_UNABLE_TO_FREE_VM: Self = Self(0xC000_001Au32 as i32);
    pub const STATUS_INVALID_ADDRESS: Self = Self(0xC000_0141u32 as i32);
    pub const STATUS_INVALID_PAGE_PROTECTION: Self = Self(0xC000_0045u32 as i32);
    pub const STATUS_OBJECT_NAME_INVALID: Self = Self(0xC000_0033u32 as i32);
    pub const STATUS_OBJECT_NAME_NOT_FOUND: Self = Self(0xC000_0034u32 as i32);
    pub const STATUS_OBJECT_NAME_COLLISION: Self = Self(0xC000_0035u32 as i32);
    pub const STATUS_OBJECT_PATH_INVALID: Self = Self(0xC000_0039u32 as i32);
    pub const STATUS_OBJECT_PATH_NOT_FOUND: Self = Self(0xC000_003Au32 as i32);
    pub const STATUS_OBJECT_PATH_SYNTAX_BAD: Self = Self(0xC000_003Bu32 as i32);
    pub const STATUS_OBJECT_TYPE_MISMATCH: Self = Self(0xC000_0024u32 as i32);
    pub const STATUS_NOT_SUPPORTED: Self = Self(0xC000_00BBu32 as i32);
    pub const STATUS_NOT_FOUND: Self = Self(0xC000_0225u32 as i32);
    pub const STATUS_NO_MORE_ENTRIES: Self = Self(0x8000_001Au32 as i32);
    pub const STATUS_ILLEGAL_FUNCTION: Self = Self(0xC000_0061u32 as i32);
    pub const STATUS_BUFFER_TOO_SMALL: Self = Self(0xC000_0023u32 as i32);
    pub const STATUS_ACCESS_DENIED: Self = Self(0xC000_0022u32 as i32);
    pub const STATUS_SHARING_VIOLATION: Self = Self(0xC000_0043u32 as i32);
    pub const STATUS_NOT_A_DIRECTORY: Self = Self(0xC000_0103u32 as i32);
    pub const STATUS_NO_MORE_FILES: Self = Self(0x8000_0006u32 as i32);
    pub const STATUS_TIMEOUT: Self = Self(0x0000_0102);
    pub const STATUS_SEMAPHORE_LIMIT_EXCEEDED: Self = Self(0xC000_004Bu32 as i32);
    pub const STATUS_NO_TOKEN: Self = Self(0xC000_007Cu32 as i32);
    pub const STATUS_PRIVILEGE_NOT_HELD: Self = Self(0xC000_0061u32 as i32);
    pub const STATUS_INVALID_IMAGE_FORMAT: Self = Self(0xC000_007Bu32 as i32);
    pub const STATUS_DLL_INIT_FAILED: Self = Self(0xC000_0142u32 as i32);
    pub const STATUS_DLL_NOT_FOUND: Self = Self(0xC000_0135u32 as i32);
    pub const STATUS_PROCEDURE_NOT_FOUND: Self = Self(0xC000_007Au32 as i32);

    // ---- Exception status codes (used as exit codes on unhandled exceptions) ----

    pub const STATUS_INTEGER_DIVIDE_BY_ZERO: Self = Self(0xC000_0094u32 as i32);
    pub const STATUS_BREAKPOINT: Self = Self(0x8000_0003u32 as i32);
    pub const STATUS_ILLEGAL_INSTRUCTION: Self = Self(0xC000_001Du32 as i32);
    pub const STATUS_IN_PAGE_ERROR: Self = Self(0xC000_0006u32 as i32);
}

impl core::fmt::Display for NtStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NTSTATUS(0x{:08X})", self.0 as u32)
    }
}
