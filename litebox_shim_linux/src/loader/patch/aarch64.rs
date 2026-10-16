// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 specifics of runtime ELF syscall patching.

use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Range;

use litebox_common_linux::{ProtFlags, errno::Errno, vmem::PAGE_SIZE};
use litebox_syscall_rewriter::aarch64::{CodeScanRanges, ElfCodeMetadata};
use zerocopy::FromZeros as _;

use super::{ElfPatchState, read_file_exact_at};
use crate::{ShimPlatform, Task, UserPtrMut, syscalls::file::File};

/// Pre-patched AArch64 trampolines are populated (and their gates finalized)
/// whenever a file mapping becomes executable, including through `mprotect`.
pub(super) const PATCH_PRE_PATCHED_ON_MPROTECT_EXEC: bool = true;

/// AArch64-specific per-file patch state.
#[derive(Default)]
pub(super) struct ArchPatchState {
    /// Set when part, but not all, of the trampoline was unmapped. Such a
    /// trampoline can no longer be trusted or excluded from `mprotect`.
    pub(super) trampoline_invalidated: bool,
    /// Pre-scanned code layout used to restrict rewriting to identified code.
    code_metadata: Option<ElfCodeMetadata>,
}

impl ArchPatchState {
    pub(super) fn trampoline_invalidated(&self) -> bool {
        self.trampoline_invalidated
    }
}

impl ElfPatchState {
    pub(crate) fn trampoline_is_populated(&self) -> bool {
        self.trampoline_mapped && !self.arch.trampoline_invalidated
    }
}

/// Updates trampoline tracking after `unmapped` is unmapped, so that later
/// `mprotect` requests stop excluding the removed trampoline.
pub(super) fn forget_unmapped_trampoline(state: &mut ElfPatchState, unmapped: &Range<usize>) {
    if !state.trampoline_mapped || state.trampoline_mapped_len == 0 {
        return;
    }
    let trampoline_end = state
        .trampoline_addr
        .saturating_add(state.trampoline_mapped_len);
    let overlaps = state.trampoline_addr < unmapped.end && unmapped.start < trampoline_end;
    let removes_all = unmapped.start <= state.trampoline_addr && unmapped.end >= trampoline_end;
    if overlaps && !removes_all {
        state.arch.trampoline_invalidated = true;
    }
    if removes_all {
        state.trampoline_mapped = false;
        state.trampoline_mapped_len = 0;
    }
}

/// Finalizes every gate with the platform's guest thread-pointer offset.
///
/// # Errors
///
/// Missing, unencodable, or unpatched offsets return an error.
pub(super) fn finalize_trampoline(
    platform: &impl litebox::platform::SystemInfoProvider,
    trampoline: &mut [u8],
) -> Result<(), String> {
    use alloc::format;

    let Some(offset) = platform.guest_thread_pointer_offset() else {
        return Err(String::from(
            "platform supplied no guest thread-pointer offset",
        ));
    };
    // Gates encode a scaled `u16`; the platform API remains pointer-width.
    let offset = u16::try_from(offset)
        .map_err(|_| format!("guest thread-pointer offset {offset} is too large for a gate"))?;
    let options = crate::aarch64_rewrite_options();
    if options.virtualizes_x18() {
        let x18 = offset
            .checked_add(
                u16::try_from(litebox_syscall_rewriter::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP)
                    .expect("guest x18 slot delta fits in a gate offset"),
            )
            .ok_or_else(|| String::from("guest x18 offset overflow"))?;
        litebox_syscall_rewriter::aarch64::finalize_trampoline_gates_for_host(
            trampoline,
            offset,
            x18,
            options.target_host(),
        )
        .map_err(|e| format!("failed to patch guest offsets {offset}/{x18}: {e}"))
    } else {
        litebox_syscall_rewriter::aarch64::finalize_trampoline_gates(trampoline, offset)
            .map_err(|e| format!("failed to patch guest thread-pointer offset {offset}: {e}"))
    }
}

/// Rewrites AArch64 patch sites in a mapped code segment, restricted to the
/// pre-scanned code ranges when they are known for the mapping.
pub(super) struct CodeRewriter {
    ranges: Option<CodeScanRanges>,
}

impl CodeRewriter {
    pub(super) fn new(state: &ArchPatchState, file_offset: Option<usize>, len: usize) -> Self {
        let ranges = file_offset.and_then(|file_offset| {
            state
                .code_metadata
                .as_ref()
                .and_then(|metadata| metadata.ranges_for_mapping(file_offset as u64, len).ok())
        });
        Self { ranges }
    }

    /// Patches `code` and returns the trampoline stubs plus addresses that
    /// could not be patched.
    pub(super) fn patch(
        &self,
        code: &mut [u8],
        code_vaddr: u64,
        trampoline_vaddr: u64,
        syscall_entry: u64,
    ) -> Result<(Vec<u8>, Vec<u64>), litebox_syscall_rewriter::Error> {
        if let Some(ranges) = &self.ranges {
            litebox_syscall_rewriter::patch_aarch64_code_segment_with_options_and_ranges(
                code,
                code_vaddr,
                ranges,
                trampoline_vaddr,
                syscall_entry,
                crate::aarch64_rewrite_options(),
            )
        } else {
            litebox_syscall_rewriter::patch_code_segment_with_options(
                code,
                code_vaddr,
                trampoline_vaddr,
                syscall_entry,
                crate::aarch64_rewrite_options(),
            )
        }
    }

    /// Replaces every patch site in `code` with a trap.
    pub(super) fn trap_all(
        &self,
        code: &mut [u8],
        code_vaddr: u64,
    ) -> Result<usize, litebox_syscall_rewriter::Error> {
        if let Some(ranges) = &self.ranges {
            litebox_syscall_rewriter::trap_all_aarch64_patch_sites_with_options_and_ranges(
                code,
                code_vaddr,
                ranges,
                crate::aarch64_rewrite_options(),
            )
        } else {
            litebox_syscall_rewriter::trap_all_syscalls_in_code_with_options(
                code,
                code_vaddr,
                crate::aarch64_rewrite_options(),
            )
        }
    }
}

impl<Platform: ShimPlatform> Task<Platform> {
    /// Pre-scans an unpatched file to size its runtime trampoline.
    ///
    /// Returns the arch state and the page-aligned trampoline capacity. Falls
    /// back to one page (with trap fallback on exhaustion) if scanning fails.
    pub(super) fn plan_runtime_trampoline(file: &File<Platform>) -> (ArchPatchState, usize) {
        let scanned = file.status().ok().and_then(|stat| {
            let file_size = usize::try_from(stat.size).ok()?;
            let word_len = file_size.div_ceil(8);
            let mut words = u64::new_vec_zeroed(word_len).ok()?;
            let bytes = zerocopy::IntoBytes::as_mut_bytes(words.as_mut_slice());
            read_file_exact_at(file, &mut bytes[..file_size], 0).ok()?;
            let metadata = ElfCodeMetadata::parse_aligned_in_place(&mut words, file_size).ok()?;
            let upper_bound = metadata
                .trampoline_size_upper_bound(
                    &zerocopy::IntoBytes::as_bytes(words.as_slice())[..file_size],
                    crate::aarch64_rewrite_options(),
                )
                .ok();
            Some((metadata, upper_bound))
        });
        let Some((metadata, upper_bound)) = scanned else {
            litebox_util_log::warn!(
                "AArch64 ELF pre-scan unavailable; using one-page trampoline with trap fallback"
            );
            return (ArchPatchState::default(), PAGE_SIZE);
        };
        let (executable_bytes, identified_bytes) = metadata.coverage_bytes();
        let initial_cursor = litebox_syscall_rewriter::TRAMPOLINE_ENTRY_POINT_BYTES
            .checked_next_multiple_of(litebox_syscall_rewriter::TRAMPOLINE_CURSOR_ALIGN);
        // Round up to at least one page; a zero estimate would otherwise
        // read as "no runtime trampoline" and force trap fallback.
        let capacity = upper_bound
            .zip(initial_cursor)
            .and_then(|(bound, cursor)| bound.checked_add(cursor))
            .and_then(|bound| bound.max(PAGE_SIZE).checked_next_multiple_of(PAGE_SIZE))
            .unwrap_or(PAGE_SIZE);
        if upper_bound.is_none() {
            litebox_util_log::warn!(
                "AArch64 trampoline size estimate unavailable; using one-page trampoline with trap fallback"
            );
        }
        litebox_util_log::debug!(
            executable_bytes:? = executable_bytes,
            identified_bytes:? = identified_bytes,
            trampoline_upper_bound:? = upper_bound,
            trampoline_capacity:? = capacity;
            "pre-scanned AArch64 ELF for runtime rewriting"
        );
        let arch = ArchPatchState {
            trampoline_invalidated: false,
            code_metadata: Some(metadata),
        };
        (arch, capacity)
    }

    /// Applies `prot`, excluding AOT trampolines placed inside their load spans,
    /// so that loader reprotection of the holes cannot clobber them.
    /// Runtime trampolines are outside the span and are not excluded.
    pub(crate) fn mprotect_around_trampolines(
        &self,
        start: usize,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        let range = start..start.saturating_add(len);
        let excluded: Vec<Range<usize>> = {
            let cache = self.global.elf_patch_cache.lock();
            cache
                .values()
                .filter(|state| {
                    !state.arch.trampoline_invalidated
                        && state.trampoline_mapped
                        && state.trampoline_mapped_len > 0
                })
                .filter_map(|state| {
                    let addr = state.trampoline_addr;
                    let range = addr..addr.saturating_add(state.trampoline_mapped_len);
                    let span = state.load_span.as_ref()?;
                    (range.start >= span.start && range.end <= span.end).then_some(range)
                })
                .collect()
        };

        let subranges = subtract_ranges(range.clone(), &excluded);
        if subranges.is_empty() {
            // Exclusions consume the whole request; no protection change is needed.
            return self.sys_mprotect_raw(UserPtrMut::<u8>::from_usize(range.start), 0, prot);
        }
        for sub in subranges {
            self.sys_mprotect_raw(UserPtrMut::<u8>::from_usize(sub.start), sub.len(), prot)?;
        }
        Ok(())
    }
}

/// Returns `range` minus possibly unsorted, overlapping `excluded` ranges.
fn subtract_ranges(range: Range<usize>, excluded: &[Range<usize>]) -> Vec<Range<usize>> {
    let mut blocks: Vec<Range<usize>> = excluded
        .iter()
        .filter(|block| block.start < range.end && range.start < block.end)
        .cloned()
        .collect();
    blocks.sort_unstable_by_key(|block| (block.start, block.end));

    let mut out = Vec::new();
    let mut cursor = range.start;
    for block in blocks {
        if block.start > cursor {
            out.push(cursor..block.start);
        }
        cursor = cursor.max(block.end);
        if cursor >= range.end {
            return out;
        }
    }
    if cursor < range.end {
        out.push(cursor..range.end);
    }
    out
}

#[cfg(test)]
mod tests {
    /// Fail closed: an unpatched placeholder executes silently.
    mod trampoline_gates {
        use litebox::platform::SystemInfoProvider;
        use litebox_syscall_rewriter::{
            RewriteOptions,
            aarch64::{GateMetadata, classify_copied_gate_slot_for_host},
            patch_code_segment_with_options,
        };

        struct StubPlatform(Option<usize>);

        impl SystemInfoProvider for StubPlatform {
            fn get_syscall_entry_point(&self) -> usize {
                0
            }
            fn get_vdso_address(&self) -> Option<usize> {
                None
            }
            fn guest_thread_pointer_offset(&self) -> Option<usize> {
                self.0
            }
        }

        fn unpatched_trampoline() -> alloc::vec::Vec<u8> {
            let options = crate::aarch64_rewrite_options();
            let mut code = 0xD53B_D049u32.to_le_bytes(); // MRS X9, TPIDR_EL0
            let (tramp, trapped) =
                patch_code_segment_with_options(&mut code, 0x1000, 0x400000, 0, options).unwrap();
            assert_eq!(trapped, []);
            let classified = classify_copied_gate_slot_for_host(
                &tramp[16..],
                0x400010,
                0x400010,
                options.target_host(),
            )
            .expect("emitted MRS slot must validate");
            assert!(matches!(
                classified.metadata(),
                GateMetadata::MrsTpidr { destination: 9 }
            ));
            tramp
        }

        #[test]
        fn x18_gate_matches_configured_policy() {
            let options = crate::aarch64_rewrite_options();
            let mut code = 0xaa00_03f2u32.to_le_bytes(); // mov x18, x0
            let (mut trampoline, trapped) = patch_code_segment_with_options(
                &mut code,
                0x1000,
                0x400000,
                0,
                RewriteOptions::new(options.target_host(), true),
            )
            .unwrap();
            assert_eq!(trapped, []);
            let before = trampoline.clone();
            let result =
                super::super::finalize_trampoline(&StubPlatform(Some(96)), &mut trampoline);
            if options.virtualizes_x18() {
                result.unwrap();
                assert!(matches!(
                    classify_copied_gate_slot_for_host(
                        &trampoline[16..],
                        0x400010,
                        0x400010,
                        options.target_host(),
                    )
                    .unwrap()
                    .metadata(),
                    GateMetadata::X18 { .. }
                ));
            } else {
                assert!(result.is_err());
                assert_eq!(trampoline, before);
            }
        }

        #[test]
        fn the_runtime_paths_argument_shape_produces_installable_gates() {
            const TRAMPOLINE_BASE: u64 = 0x40_0000;
            const SYSCALL_ENTRY: u64 = 0xDEAD_0000;
            let options = crate::aarch64_rewrite_options();
            let mut code = 0xD400_0001u32.to_le_bytes(); // SVC #0
            let (mut stubs, trapped) = patch_code_segment_with_options(
                &mut code,
                0x1000,
                TRAMPOLINE_BASE,
                SYSCALL_ENTRY,
                options,
            )
            .unwrap();
            assert_eq!(trapped, []);
            assert_eq!(
                u64::from_le_bytes(stubs[..8].try_into().unwrap()),
                SYSCALL_ENTRY
            );
            super::super::finalize_trampoline(&StubPlatform(Some(96)), &mut stubs).unwrap();
            assert!(matches!(
                classify_copied_gate_slot_for_host(
                    &stubs[16..],
                    TRAMPOLINE_BASE + 16,
                    TRAMPOLINE_BASE + 16,
                    options.target_host(),
                )
                .unwrap()
                .metadata(),
                GateMetadata::Svc
            ));
            let mut code = 0xD400_0001u32.to_le_bytes();
            assert!(
                patch_code_segment_with_options(
                    &mut code,
                    0x1000,
                    TRAMPOLINE_BASE + 8,
                    TRAMPOLINE_BASE,
                    options,
                )
                .is_err()
            );
        }

        #[test]
        fn a_supplied_offset_is_accepted() {
            let mut tramp = unpatched_trampoline();
            super::super::finalize_trampoline(&StubPlatform(Some(96)), &mut tramp).unwrap();
            if crate::aarch64_rewrite_options().target_host()
                == litebox_syscall_rewriter::TargetHost::Linux
            {
                assert_eq!(
                    litebox_syscall_rewriter::aarch64::find_guest_tpidr_placeholder(&tramp),
                    None
                );
            }
        }

        #[test]
        fn a_platform_with_no_offset_is_refused() {
            let mut tramp = unpatched_trampoline();
            let before = tramp.clone();
            let err =
                super::super::finalize_trampoline(&StubPlatform(None), &mut tramp).unwrap_err();
            assert!(err.contains("no guest thread-pointer offset"), "{err}");
            assert_eq!(tramp, before);
        }

        #[test]
        fn an_offset_no_gate_can_encode_is_refused() {
            let mut tramp = unpatched_trampoline();
            let before = tramp.clone();
            let err =
                super::super::finalize_trampoline(&StubPlatform(Some(4)), &mut tramp).unwrap_err();
            assert!(err.contains("failed to patch"), "{err}");
            assert_eq!(tramp, before);
        }
    }

    #[test]
    fn subtract_ranges_yields_every_unowned_subrange() {
        use super::subtract_ranges;
        use core::ops::Range;

        fn r(start: usize, end: usize) -> Range<usize> {
            start..end
        }

        assert_eq!(
            subtract_ranges(r(0x1000, 0x3000), &[]),
            alloc::vec![r(0x1000, 0x3000)]
        );

        assert_eq!(
            subtract_ranges(r(0x1000, 0x3000), &[r(0x1000, 0x2000)]),
            alloc::vec![r(0x2000, 0x3000)]
        );
        assert_eq!(
            subtract_ranges(r(0x1000, 0x3000), &[r(0x2000, 0x3000)]),
            alloc::vec![r(0x1000, 0x2000)]
        );

        assert_eq!(
            subtract_ranges(r(0x1000, 0x4000), &[r(0x2000, 0x3000)]),
            alloc::vec![r(0x1000, 0x2000), r(0x3000, 0x4000)]
        );

        assert_eq!(
            subtract_ranges(r(0x1000, 0x3000), &[r(0x0000, 0x9000)]),
            alloc::vec![]
        );

        assert_eq!(
            subtract_ranges(r(0x1000, 0x5000), &[r(0x3000, 0x4000), r(0x2000, 0x3500)]),
            alloc::vec![r(0x1000, 0x2000), r(0x4000, 0x5000)]
        );

        assert_eq!(
            subtract_ranges(r(0x1000, 0x2000), &[r(0x5000, 0x6000)]),
            alloc::vec![r(0x1000, 0x2000)]
        );
    }
}
