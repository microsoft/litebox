// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest GS ↔ Host GS bidirectional lookup tables.
//!
//! This module defines the shared data layout for two host-owned mapping
//! tables that the syscall/exception trampolines use to translate between
//! guest and host GS bases:
//!
//! 1. **Forward table** (`guest_gs → host_gs`): Used when a guest syscall
//!    enters the trampoline with GS pointing at the guest TEB. The trampoline
//!    scans this table to find the host TEB and swaps GS before entering the
//!    shim.
//!
//! 2. **Reverse table** (`host_gs → guest_gs`): Used when the Windows kernel
//!    has already restored GS to the host TEB before the trampoline runs
//!    (e.g., after exception dispatch or APC delivery). The trampoline scans
//!    the reverse table to confirm that GS is already the host TEB, and skips
//!    the swap.
//!
//! Both tables use the same entry layout ([`GsTableEntry`]) with a zero
//! sentinel. In the forward table, `guest_gs` is the key and `host_gs` is
//! the value. In the reverse table the fields are repurposed: `guest_gs`
//! stores the host GS (key) and `host_gs` stores the guest GS (value).
//!
//! An entry with `guest_gs == 0` acts as a sentinel (end of table / empty
//! slot) in both tables.

/// A single entry in a GS mapping table.
///
/// Alignment to 16 bytes ensures each entry fits in a single cache-line fetch
/// pattern and allows simple `index * 16` addressing in the trampoline asm.
///
/// In the **forward table**: `guest_gs` = guest TEB (key), `host_gs` = host TEB (value).
/// In the **reverse table**: `guest_gs` = host TEB (key), `host_gs` = guest TEB (value).
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct GsTableEntry {
    /// Key field (offset 0). The trampoline scans `[entry + 0]` for a match.
    /// Zero = empty/sentinel.
    /// [`TOMBSTONE_GUEST_GS`] marks a removed entry that the scanner should
    /// skip (it is non-zero so the trampoline's `cmp qword [rcx], 0 / jne`
    /// loop keeps scanning past it).
    pub guest_gs: u64,
    /// Value field (offset 8). The trampoline reads `[entry + 8]` on a match.
    pub host_gs: u64,
}

/// Maximum number of active entries (concurrent guest threads).
pub const MAX_GS_TABLE_ENTRIES: usize = 64;

/// Tombstone value for the key field in a removed entry.
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
