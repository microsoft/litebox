// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Binary-format-independent trampoline ABI, construction and validation.
#![no_std]
extern crate alloc;

pub mod aarch64;
use alloc::string::String;
use core::ops::Range;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Errors constructing or validating a trampoline.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("address overflow: {0}")]
    AddressOverflow(String),
    #[error("failed to patch trampoline: {0}")]
    TrampolinePatchFailure(String),
    #[error("unsupported executable: {0}")]
    UnsupportedExecutable(String),
}

/// Result of a trampoline operation.
pub type Result<T> = core::result::Result<T, Error>;

// Persisted image ABI.

/// The magic bytes used to identify the trampoline data.
/// This is checked by the loader to verify that the trampoline is valid.
pub const TRAMPOLINE_MAGIC: &[u8; 8] = b"LITEBOX0";

/// Required file alignment of the appended trampoline payload.
pub const TRAMPOLINE_FILE_ALIGNMENT: usize = 0x1000;

/// Trampoline header for 64-bit: 8 (magic) + 8 (file_offset) + 8 (vaddr) + 8 (size) = 32 bytes
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable)]
pub struct TrampolineHeader64 {
    pub magic: [u8; 8],
    pub file_offset: u64,
    pub vaddr: u64,
    pub trampoline_size: u64,
}

// Host conventions and runtime entry ABI.

/// Host operating system whose TLS and register conventions AArch64 gates use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TargetHost {
    /// Linux, using `TPIDR_EL0` as the host per-thread anchor.
    #[default]
    Linux,
    /// macOS, using `TPIDRRO_EL0` as the host anchor. Guest x18 is virtualized.
    MacOs,
    /// Experimental Windows emission using physical `x18` as the host anchor.
    /// No in-tree AArch64 Windows runtime consumes these artifacts.
    Windows,
}

/// Callback-slot bytes the caller must populate; zero when emitted inline.
#[cfg(target_arch = "x86_64")]
pub const TRAMPOLINE_ENTRY_POINT_BYTES: usize = size_of::<u64>();
#[cfg(target_arch = "aarch64")]
pub const TRAMPOLINE_ENTRY_POINT_BYTES: usize = 0;

/// Alignment every write cursor into a trampoline must satisfy.
#[cfg(target_arch = "x86_64")]
pub const TRAMPOLINE_CURSOR_ALIGN: usize = 1;
#[cfg(target_arch = "aarch64")]
pub const TRAMPOLINE_CURSOR_ALIGN: usize = aarch64::GATE_ALIGNMENT;

/// Furthest preferred trampoline base from the code segment.
///
/// AArch64 runtime reservations may exceed the nominal tail margin; each gate
/// performs its own reach check.
#[cfg(target_arch = "x86_64")]
pub const MAX_TRAMPOLINE_DISPLACEMENT: usize = 0x7FFF_0000;
#[cfg(target_arch = "aarch64")]
pub const MAX_TRAMPOLINE_DISPLACEMENT: usize = 0x07FF_0000;

/// Length of the `JMP [RIP + disp32]` through which an x86-64 ELF trampoline enters the syscall
/// callback. The preceding `LEA RCX, [RIP + len]` points RCX, the callback's resume PC, just past it.
pub const X86_64_SYSCALL_ENTRY_JMP_LEN: u8 = 6;

/// Length of the guest instruction through which a rewritten Linux syscall enters the syscall
/// callback.
///
/// The callback's resume PC immediately follows this instruction, so moving the PC back by this
/// length, with the syscall's registers restored, reissues the syscall. On x86-64 it is the ELF
/// trampoline's `JMP [RIP + disp32]`; on AArch64 it is the `B` that replaces the `SVC` in place.
#[cfg(target_arch = "x86_64")]
pub const SYSCALL_ENTRY_INSTRUCTION_LEN: usize = X86_64_SYSCALL_ENTRY_JMP_LEN as usize;
#[cfg(target_arch = "aarch64")]
pub const SYSCALL_ENTRY_INSTRUCTION_LEN: usize = aarch64::INSN_BYTES;

/// Conservative address bounds reachable from the entire nonempty code span.
///
/// A runtime trampoline's complete allocation must fit inside the returned
/// interval. Returns `None` if the span has no common reachable interval.
pub fn trampoline_allocation_range(code: Range<usize>) -> Option<Range<usize>> {
    let start = code.end.saturating_sub(MAX_TRAMPOLINE_DISPLACEMENT);
    let end = code.start.saturating_add(MAX_TRAMPOLINE_DISPLACEMENT);
    (code.start < code.end && start < end).then_some(start..end)
}
