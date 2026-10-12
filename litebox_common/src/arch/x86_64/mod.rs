// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared x86-64 CPU-state helpers.

use litebox::platform::PageManagementProvider;

pub mod xstate;

pub const EFLAGS_CF: usize = 1 << 0;
pub const EFLAGS_FIXED: usize = 1 << 1;
pub const EFLAGS_PF: usize = 1 << 2;
pub const EFLAGS_AF: usize = 1 << 4;
pub const EFLAGS_ZF: usize = 1 << 6;
pub const EFLAGS_SF: usize = 1 << 7;
pub const EFLAGS_IF: usize = 1 << 9;
pub const EFLAGS_DF: usize = 1 << 10;
pub const EFLAGS_OF: usize = 1 << 11;
pub const EFLAGS_RF: usize = 1 << 16;
pub const EFLAGS_ID: usize = 1 << 21;

/// Returns whether `base` is a valid user FS-segment base for `Platform`.
///
/// A user FS base is valid iff it is below the top of the platform's user
/// address space. A non-canonical FS base can cause `wrfsbase` to raise #GP.
#[must_use]
pub fn is_valid_user_fs_base<Platform, const ALIGN: usize>(base: usize) -> bool
where
    Platform: PageManagementProvider<ALIGN>,
{
    base < Platform::TASK_ADDR_MAX
}

/// Reads the FS segment base address
///
/// ## Safety
///
/// If `CR4.FSGSBASE` is not set, calling this instruction from user land will throw an `#UD`.
pub unsafe fn rdfsbase() -> usize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "rdfsbase {}",
            out(reg) ret,
            options(nostack, nomem, preserves_flags)
        );
    }
    ret
}

/// Writes the FS segment base address
///
/// ## Safety
///
/// If `CR4.FSGSBASE` is not set, calling this instruction from user land will throw an `#UD`.
///
/// The caller must ensure that this write operation has no unsafe side
/// effects, as the FS segment base address is often used for thread
/// local storage.
pub unsafe fn wrfsbase(fs_base: usize) {
    unsafe {
        core::arch::asm!(
            "wrfsbase {}",
            in(reg) fs_base,
            options(nostack, nomem, preserves_flags)
        );
    }
}

/// Reads the GS segment base address
///
/// ## Safety
///
/// If `CR4.FSGSBASE` is not set, this instruction will throw an `#UD`.
pub unsafe fn rdgsbase() -> usize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "rdgsbase {}",
            out(reg) ret,
            options(nostack, nomem, preserves_flags)
        );
    }
    ret
}

/// Writes the GS segment base address
///
/// ## Safety
///
/// If `CR4.FSGSBASE` is not set, this instruction will throw an `#UD`.
///
/// The caller must ensure that this write operation has no unsafe side
/// effects, as the GS segment base address might be in use.
pub unsafe fn wrgsbase(gs_base: usize) {
    unsafe {
        core::arch::asm!(
            "wrgsbase {}",
            in(reg) gs_base,
            options(nostack, nomem, preserves_flags)
        );
    }
}
