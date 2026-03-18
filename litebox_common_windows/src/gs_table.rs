// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest GS → Host GS lookup table ABI.
//!
//! This module defines the shared data layout for the host-owned GS mapping
//! table. The table is allocated by the platform and referenced by the stub
//! DLL trampolines.
//!
//! Each entry maps a guest GS base (= guest TEB address) to the corresponding
//! host GS base (= host TEB address). The trampoline does a linear scan on
//! syscall entry to find the host GS for the current thread.
//!
//! An entry with `guest_gs == 0` acts as a sentinel (end of table / empty slot).

/// A single entry in the guest GS → host GS mapping table.
///
/// Alignment to 16 bytes ensures each entry fits in a single cache-line fetch
/// pattern and allows simple `index * 16` addressing in the trampoline asm.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct GsTableEntry {
    /// Guest GS base (guest TEB address). Zero = empty/sentinel.
    /// [`TOMBSTONE_GUEST_GS`] marks a removed entry that the scanner should
    /// skip (it is non-zero so the trampoline's `cmp qword [rcx], 0 / jne`
    /// loop keeps scanning past it).
    pub guest_gs: u64,
    /// Host GS base (host TEB address).
    pub host_gs: u64,
}

impl Default for GsTableEntry {
    fn default() -> Self {
        Self {
            guest_gs: 0,
            host_gs: 0,
        }
    }
}

/// Maximum number of active entries (concurrent guest threads).
pub const MAX_GS_TABLE_ENTRIES: usize = 64;

/// Tombstone value for `guest_gs` in a removed entry.
///
/// A removed entry has `guest_gs = TOMBSTONE_GUEST_GS` instead of zero so
/// the lock-free trampoline scanner (which stops at the first zero) keeps
/// scanning past it. Insert reuses tombstone slots; remove writes this
/// value instead of zero.
pub const TOMBSTONE_GUEST_GS: u64 = u64::MAX;

/// Size of one entry in bytes.
pub const GS_TABLE_ENTRY_SIZE: usize = core::mem::size_of::<GsTableEntry>();

/// Total table size in bytes (entries + one zero sentinel).
pub const GS_TABLE_SIZE: usize = (MAX_GS_TABLE_ENTRIES + 1) * GS_TABLE_ENTRY_SIZE;
