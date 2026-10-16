// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared x86-64 CPU-state helpers.

pub mod xstate;

/// Inclusive lower bound for user instruction and stack pointers, excluding the null guard.
pub const USER_ADDR_MIN: usize = 0x0000_0000_0001_0000;
/// Exclusive upper bound for user addresses, reserving the final low-canonical page as a guard.
pub const USER_ADDR_END: usize = 0x0000_7fff_ffff_f000;

bitflags::bitflags! {
    /// x86-64 RFLAGS bits used by CPU-state helpers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RFlags: u64 {
        /// Carry flag.
        const CF = 1 << 0;
        /// Reserved bit that must always be set.
        const FIXED = 1 << 1;
        /// Parity flag.
        const PF = 1 << 2;
        /// Auxiliary carry flag.
        const AF = 1 << 4;
        /// Zero flag.
        const ZF = 1 << 6;
        /// Sign flag.
        const SF = 1 << 7;
        /// Interrupt enable flag.
        const IF = 1 << 9;
        /// Direction flag.
        const DF = 1 << 10;
        /// Overflow flag.
        const OF = 1 << 11;
        /// Resume flag.
        const RF = 1 << 16;
        /// CPUID availability flag.
        const ID = 1 << 21;
    }
}

/// Returns whether `base` is a valid x86_64 Linux user FS-segment base.
///
/// A user FS base is valid iff it is below the top of the user address
/// space. Especially, if a given address is non-canonical, `wrfsbase`
/// can result in a #GP fault. This check is based on Linux kernel's
/// `do_arch_prctl_64`.
#[must_use]
pub const fn is_valid_user_fs_base(base: usize) -> bool {
    base < USER_ADDR_END
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
