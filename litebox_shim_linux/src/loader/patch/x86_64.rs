// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! x86-64 specifics of runtime ELF syscall patching.

use alloc::vec::Vec;
use core::ops::Range;

use litebox_common_linux::{ProtFlags, errno::Errno};

use super::{ElfPatchKey, ElfPatchState};
use crate::{ShimPlatform, Task, UserPtrMut};

/// Fixed size of every runtime trampoline.
pub(super) const RUNTIME_TRAMPOLINE_SIZE: usize =
    litebox_common_linux::loader::RUNTIME_TRAMPOLINE_RESERVATION_SIZE;

/// Pre-patched x86-64 code is fully rewritten ahead of time, so its trampoline
/// is populated only when mapped executable, never by `mprotect`.
pub(super) const PATCH_PRE_PATCHED_ON_MPROTECT_EXEC: bool = false;

/// x86-64 keeps no extra per-file patch state.
#[derive(Default)]
pub(super) struct ArchPatchState {}

impl ArchPatchState {
    /// x86-64 trampolines are never invalidated by partial unmaps.
    #[expect(clippy::unused_self, reason = "shared interface with AArch64")]
    pub(super) fn trampoline_invalidated(&self) -> bool {
        false
    }
}

/// x86-64 does not track trampoline unmaps.
pub(super) fn forget_unmapped_trampoline(_state: &mut ElfPatchState, _unmapped: &Range<usize>) {}

/// x86-64 trampolines need no finalization.
#[expect(
    clippy::unnecessary_wraps,
    reason = "shared interface with AArch64, which can fail"
)]
pub(super) fn finalize_trampoline(
    _platform: &impl litebox::platform::SystemInfoProvider,
    _trampoline: &mut [u8],
) -> Result<(), alloc::string::String> {
    Ok(())
}

/// Rewrites x86-64 `syscall` instructions in a mapped code segment.
pub(super) struct CodeRewriter;

impl CodeRewriter {
    pub(super) fn new(_state: &ArchPatchState, _file_offset: Option<usize>, _len: usize) -> Self {
        Self
    }

    /// Patches `code` and returns the trampoline stubs plus addresses that
    /// could not be patched.
    #[expect(clippy::unused_self, reason = "shared interface with AArch64")]
    pub(super) fn patch(
        &self,
        code: &mut [u8],
        code_vaddr: u64,
        trampoline_vaddr: u64,
        syscall_entry: u64,
    ) -> Result<(Vec<u8>, Vec<u64>), litebox_syscall_rewriter::Error> {
        litebox_syscall_rewriter::patch_code_segment(
            code,
            code_vaddr,
            trampoline_vaddr,
            syscall_entry,
        )
    }

    /// Replaces every patch site in `code` with a trap.
    #[expect(clippy::unused_self, reason = "shared interface with AArch64")]
    pub(super) fn trap_all(
        &self,
        code: &mut [u8],
        code_vaddr: u64,
    ) -> Result<usize, litebox_syscall_rewriter::Error> {
        litebox_syscall_rewriter::trap_all_syscalls_in_code(code, code_vaddr)
    }
}

impl<Platform: ShimPlatform> Task<Platform> {
    /// Returns the arch state and capacity of an unpatched file's runtime trampoline.
    #[expect(clippy::unused_self, reason = "shared interface with AArch64")]
    pub(super) fn plan_runtime_trampoline(&self, _fd: &ElfPatchKey) -> (ArchPatchState, usize) {
        (ArchPatchState {}, RUNTIME_TRAMPOLINE_SIZE)
    }

    /// Applies `prot` to the whole request; x86-64 never excludes trampolines.
    pub(crate) fn mprotect_around_trampolines(
        &self,
        start: usize,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        self.sys_mprotect_raw(UserPtrMut::<u8>::from_usize(start), len, prot)
    }
}
