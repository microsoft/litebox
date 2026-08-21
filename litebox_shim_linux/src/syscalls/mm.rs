// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.
//! Most of these syscalls which are not backed by files are implemented in [`litebox_common_linux::mm`].

use alloc::collections::{BTreeMap, BTreeSet};
use litebox::{
    mm::linux::{MappingError, PAGE_SIZE, PageRange},
    platform::{
        PageManagementProvider, RawConstPointer,
        page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions},
    },
};
use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, errno::Errno};

use crate::ShimFS;
use crate::ShimPlatform;
use crate::Task;
use crate::UserPtrMut;
#[cfg(target_arch = "aarch64")]
use alloc::vec::Vec;
#[cfg(target_arch = "aarch64")]
use core::ops::Range;
#[cfg(target_arch = "aarch64")]
use litebox::mm::linux::VmFlags;
#[cfg(target_arch = "aarch64")]
use litebox::utils::ReinterpretUnsignedExt as _;
use litebox::utils::TruncateExt as _;
use object::elf::{ET_DYN, FileHeader64, PT_LOAD, ProgramHeader64};
use object::endian::LittleEndian;
#[cfg(all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"))]
use zerocopy::FromZeros as _;

#[cfg(not(target_pointer_width = "64"))]
compile_error!("ELF patching code assumes 64-bit pointers (u64 <-> usize is lossless)");

const ENDIAN: LittleEndian = LittleEndian;

/// Finalizes every gate with the platform's guest thread-pointer offset.
///
/// # Errors
///
/// Missing, unencodable, or unpatched offsets return an error.
#[cfg(target_arch = "aarch64")]
fn finalize_trampoline_gates(
    platform: &impl litebox::platform::SystemInfoProvider,
    trampoline: &mut [u8],
) -> Result<(), alloc::string::String> {
    use alloc::format;

    let Some(offset) = platform.guest_thread_pointer_offset() else {
        return Err(alloc::string::String::from(
            "platform supplied no guest thread-pointer offset",
        ));
    };
    // Gates encode a scaled `u16`; the platform API remains pointer-width.
    let offset = u16::try_from(offset)
        .map_err(|_| format!("guest thread-pointer offset {offset} is too large for a gate"))?;
    if cfg!(feature = "aarch64_virtualize_x18") {
        let x18 = offset
            .checked_add(
                u16::try_from(litebox_syscall_rewriter::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP)
                    .expect("guest x18 slot delta fits in a gate offset"),
            )
            .ok_or_else(|| alloc::string::String::from("guest x18 offset overflow"))?;
        litebox_syscall_rewriter::aarch64::finalize_trampoline_gates_with_x18(
            trampoline, offset, x18,
        )
        .map_err(|e| format!("failed to patch guest offsets {offset}/{x18}: {e}"))
    } else {
        litebox_syscall_rewriter::aarch64::finalize_trampoline_gates(trampoline, offset)
            .map_err(|e| format!("failed to patch guest thread-pointer offset {offset}: {e}"))
    }
}

/// Per-fd state for the shim's runtime ELF syscall rewriter.
///
/// Tracks base address and trampoline write cursor for each ELF file that
/// has executable segments mapped via `do_mmap_file()`.
#[cfg_attr(
    target_arch = "aarch64",
    expect(
        clippy::struct_excessive_bools,
        reason = "independent ELF patch state flags"
    )
)]
pub(crate) struct ElfPatchState {
    /// Whether this file is already pre-patched (trampoline magic found at file tail).
    pre_patched: bool,
    /// For pre-patched binaries: file offset and size of the trampoline data.
    trampoline_file_offset: u64,
    trampoline_file_size: usize,
    /// Start address of the trampoline region (runtime).
    trampoline_addr: usize,
    #[cfg(target_arch = "aarch64")]
    load_span: Option<Range<usize>>,
    /// Current write position within the trampoline (byte offset from `trampoline_addr`).
    trampoline_cursor: usize,
    /// Whether the trampoline region has been allocated.
    trampoline_mapped: bool,
    /// Total number of trampoline bytes currently mapped.
    trampoline_mapped_len: usize,
    /// Whether any runtime-generated stubs were successfully linked from code
    /// in this fd to the trampoline.
    runtime_patches_committed: bool,
    #[cfg(target_arch = "aarch64")]
    trampoline_invalidated: bool,
    #[cfg(all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"))]
    code_metadata: Option<litebox_syscall_rewriter::aarch64::ElfCodeMetadata>,
    /// Tracks file-backed mappings for this fd as (vaddr, len) pairs.
    /// Used to find mappings that need patching when mprotect adds PROT_EXEC.
    /// Cleared on munmap to allow re-patching.
    file_mappings: BTreeSet<(usize, usize)>,
    /// Ranges that have already been patched by the runtime rewriter.
    /// This is a performance guard only — re-running the rewriter on
    /// already-patched code is safe because the second run will not see
    /// syscall instructions. Cleared on munmap alongside file_mappings.
    patched_ranges: BTreeSet<(usize, usize)>,
}

impl ElfPatchState {
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn trampoline_is_populated(&self) -> bool {
        self.trampoline_mapped && !self.trampoline_invalidated
    }
}

/// Per-process collection of ELF patching state, keyed by fd number.
pub(crate) type ElfPatchCache = BTreeMap<i32, ElfPatchState>;

/// Returns `range` minus possibly unsorted, overlapping `excluded` ranges.
#[cfg(target_arch = "aarch64")]
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

#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (addr + align - 1) & !(align - 1)
}

#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    #[inline]
    fn do_mmap(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        ensure_space_after: bool,
        op: impl FnOnce(UserPtrMut<u8>) -> Result<usize, MappingError>,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        litebox_common_linux::mm::do_mmap(
            &self.global.pm,
            suggested_addr,
            len,
            prot,
            flags,
            ensure_space_after,
            op,
        )
    }

    #[inline]
    pub(crate) fn do_mmap_anonymous(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        let op = |_| Ok(0);
        self.do_mmap(suggested_addr, len, prot, flags, false, op)
    }

    fn do_mmap_file(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        let is_exec = prot.contains(ProtFlags::PROT_EXEC);

        // Perform the normal mmap first (CoW or memcpy fallback).
        let result = if let Some(cow_result) =
            self.try_cow_mmap_file(suggested_addr, len, &prot, &flags, fd, offset)
        {
            cow_result?
        } else {
            self.do_mmap_file_memcpy(suggested_addr, len, prot, flags, fd, offset)?
        };

        // Runtime syscall rewriting: patch PROT_EXEC segments in-place.
        if is_exec {
            let syscall_entry = self.global.platform.get_syscall_entry_point();
            if syscall_entry != 0
                && !self.maybe_patch_exec_segment(result, len, fd, syscall_entry, Some(offset))
            {
                // Trampoline setup failed for a pre-patched binary whose
                // .text already contains JMPs to the trampoline address.
                // Continuing would guarantee a SIGSEGV on the first
                // rewritten syscall, so fail the mmap instead.
                let _ = self.sys_munmap(result, len);
                return Err(MappingError::OutOfMemory);
            }
        } else {
            // Ensure patch state is initialized for this fd (no-op if already done).
            self.init_elf_patch_state(fd, result.as_usize(), offset);
            // Track non-exec file mappings so we can patch them if they later
            // gain PROT_EXEC via mprotect.
            let mut cache = self.global.elf_patch_cache.lock();
            if let Some(state) = cache.get_mut(&fd) {
                let mapping_key = (result.as_usize(), len);
                // Overlapping entries are safe here: file_mappings is only used
                // to know which (addr, len) ranges belong to this fd so we can
                // patch them later if mprotect adds PROT_EXEC.  Duplicates or
                // overlaps are harmless — the patching logic is idempotent.
                state.file_mappings.insert(mapping_key);
            }
        }

        Ok(result)
    }

    /// Attempt to create a CoW mapping for a file with static backing data.
    ///
    /// Returns `Some(result)` if CoW was attempted (success or failure),
    /// `None` if CoW is not applicable (fall back to memcpy).
    // TODO(jb): does this need to be Option-Result or can it just be Option?
    fn try_cow_mmap_file(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: &ProtFlags,
        flags: &MapFlags,
        fd: i32,
        offset: usize,
    ) -> Option<Result<UserPtrMut<u8>, MappingError>> {
        if !len.is_multiple_of(PAGE_SIZE) {
            return None;
        }

        let Ok(fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return None;
        };

        let files = self.files.borrow();
        let raw_fd = fd;

        let static_data = files
            .run_on_raw_fd(
                raw_fd,
                |typed_fd| files.fs.get_static_backing_data(typed_fd),
                |_| None,
                |_| None,
                |_| None,
                |_| None,
                |_| None,
            )
            .ok()??;

        if offset > static_data.len() {
            return None;
        }

        let available_len = static_data.len().saturating_sub(offset);
        if available_len < len {
            // Cannot fill full page
            return None;
        }

        let fixed_behavior = if flags.contains(MapFlags::MAP_FIXED_NOREPLACE) {
            FixedAddressBehavior::NoReplace
        } else if flags.contains(MapFlags::MAP_FIXED) {
            FixedAddressBehavior::Replace
        } else {
            FixedAddressBehavior::Hint
        };

        let permissions = {
            let mut perms = MemoryRegionPermissions::empty();
            perms.set(
                MemoryRegionPermissions::READ,
                prot.contains(ProtFlags::PROT_READ),
            );
            perms.set(
                MemoryRegionPermissions::WRITE,
                prot.contains(ProtFlags::PROT_WRITE),
            );
            perms.set(
                MemoryRegionPermissions::EXEC,
                prot.contains(ProtFlags::PROT_EXEC),
            );
            perms
        };

        // XXX: `try_allocate_cow_pages` and `register_existing_mapping` are not called under a
        // unified lock, so there is a theoretical race if two threads concurrently attempt a
        // fixed-address mapping with replacement at the same address. In practice this is benign:
        // if a program races like this both threads will register the same mapping anyway. Updating
        // to a begin/attempt/commit scheme could close this race window entirely.
        match <_ as PageManagementProvider<{ PAGE_SIZE }>>::try_allocate_cow_pages(
            self.global.platform,
            suggested_addr.unwrap_or(0),
            &static_data[offset..offset + len],
            permissions,
            fixed_behavior,
        ) {
            Ok(ptr) => {
                let range =
                    PageRange::new(ptr.as_usize(), ptr.as_usize().checked_add(len).unwrap())
                        .unwrap();
                // SAFETY: ptr is the freshly CoW-mapped region of exactly `len` bytes with
                // `permissions`.
                unsafe {
                    self.global.pm.register_existing_mapping(
                        range,
                        permissions,
                        true,
                        fixed_behavior == FixedAddressBehavior::Replace,
                        flags.contains(MapFlags::MAP_SHARED),
                    )
                }
                .unwrap();
                Some(Ok(UserPtrMut::from_platform_ptr::<Platform>(ptr)))
            }
            Err(_cow_not_supported) => None,
        }
    }

    /// Fallback mmap implementation using page-by-page memcpy, for files where the CoW attempt
    /// fails (either due to lack of support on platform, or non-static-backed data, etc.)
    fn do_mmap_file_memcpy(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        let op = |ptr: UserPtrMut<u8>| -> Result<usize, MappingError> {
            // Note a malicious user may unmap ptr while we are reading.
            // `sys_read` does not handle page faults, so we need to use a
            // temporary buffer to read the data from fs (without worrying page
            // faults) and write it to the user buffer with page fault handling.
            let mut file_offset = offset;
            let mut buffer = [0; PAGE_SIZE];
            let mut copied = 0;
            while copied < len {
                let size =
                    self.sys_read(fd, &mut buffer, Some(file_offset))
                        .map_err(|e| match e {
                            Errno::EBADF => MappingError::BadFD(fd),
                            Errno::EISDIR => MappingError::NotAFile,
                            Errno::EACCES => MappingError::NotForReading,
                            _ => unimplemented!(),
                        })?;
                if size == 0 {
                    break;
                }
                // ptr is a valid pointer returned by do_mmap.
                ptr.copy_from_slice::<Platform>(copied, &buffer[..size])
                    .unwrap();
                copied += size;
                file_offset += size;
            }
            Ok(copied)
        };
        let fixed_addr = flags.intersects(MapFlags::MAP_FIXED | MapFlags::MAP_FIXED_NOREPLACE);
        self.do_mmap(
            suggested_addr,
            len,
            prot,
            flags,
            // Note we need to ensure that the space after the mapping is available
            // so that we could load trampoline code right after the mapping.
            offset == 0 && !fixed_addr,
            op,
        )
    }

    /// Handle syscall `mmap`
    pub(crate) fn sys_mmap(
        &self,
        addr: usize,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
    ) -> Result<UserPtrMut<u8>, Errno> {
        // check alignment
        if !offset.is_multiple_of(PAGE_SIZE) || !addr.is_multiple_of(PAGE_SIZE) || len == 0 {
            return Err(Errno::EINVAL);
        }

        // MAP_SHARED is partially supported:
        // - Anonymous shared mappings are fully supported (no backing file concerns).
        //   Note: since fork is not yet supported, shared anonymous mappings behave
        //   identically to private ones (no cross-process sharing occurs).
        // - File-backed shared mappings are read-only: writable permission is rejected
        //   upfront and cannot be added later via mprotect, because writes cannot be
        //   propagated back to the underlying file.
        if flags.contains(MapFlags::MAP_SHARED)
            && prot.contains(ProtFlags::PROT_WRITE)
            && !flags.contains(MapFlags::MAP_ANONYMOUS)
        {
            todo!("MAP_SHARED with PROT_WRITE on file-backed mappings is not supported");
        }

        if flags.intersects(
            MapFlags::MAP_32BIT
                | MapFlags::MAP_GROWSDOWN
                | MapFlags::MAP_LOCKED
                | MapFlags::MAP_NONBLOCK
                | MapFlags::MAP_SYNC
                | MapFlags::MAP_HUGETLB
                | MapFlags::MAP_HUGE_2MB
                | MapFlags::MAP_HUGE_1GB,
        ) {
            todo!("Unsupported flags {:?}", flags);
        }

        let aligned_len = align_up(len, PAGE_SIZE);
        if aligned_len == 0 {
            return Err(Errno::ENOMEM);
        }
        if offset.checked_add(aligned_len).is_none() {
            return Err(Errno::EOVERFLOW);
        }

        let suggested_addr = if addr == 0 { None } else { Some(addr) };
        if flags.contains(MapFlags::MAP_ANONYMOUS) {
            self.do_mmap_anonymous(suggested_addr, aligned_len, prot, flags)
        } else {
            self.do_mmap_file(suggested_addr, aligned_len, prot, flags, fd, offset)
        }
        .map_err(Errno::from)
    }

    /// Handle syscall `munmap`
    #[inline]
    pub(crate) fn sys_munmap(&self, addr: UserPtrMut<u8>, len: usize) -> Result<(), Errno> {
        let result = self.sys_munmap_raw(addr, len);
        if result.is_ok() {
            self.clear_file_mappings_for_range(addr.as_usize(), len.next_multiple_of(PAGE_SIZE));
        }
        result
    }

    /// Raw munmap without clearing file_mappings — used internally by the
    /// patching logic to avoid deadlocks (the patch path holds elf_patch_cache).
    #[inline]
    fn sys_munmap_raw(&self, addr: UserPtrMut<u8>, len: usize) -> Result<(), Errno> {
        litebox_common_linux::mm::sys_munmap(&self.global.pm, addr, len)
    }

    /// Clear `file_mappings` entries for any segments that overlap the
    /// unmapped range, so that re-mapping the same file region will be
    /// re-patched instead of skipped.
    ///
    fn clear_file_mappings_for_range(&self, unmap_start: usize, unmap_len: usize) {
        let unmap_end = unmap_start.saturating_add(unmap_len);
        let mut cache = self.global.elf_patch_cache.lock();
        for state in cache.values_mut() {
            #[cfg(target_arch = "aarch64")]
            if state.trampoline_mapped && state.trampoline_mapped_len > 0 {
                // Stop excluding unmapped trampoline ranges from later
                // `mprotect` requests.
                let trampoline_end = state
                    .trampoline_addr
                    .saturating_add(state.trampoline_mapped_len);
                let overlaps = state.trampoline_addr < unmap_end && unmap_start < trampoline_end;
                let removes_all =
                    unmap_start <= state.trampoline_addr && unmap_end >= trampoline_end;
                if overlaps && !removes_all {
                    state.trampoline_invalidated = true;
                }
                if removes_all {
                    state.trampoline_mapped = false;
                    state.trampoline_mapped_len = 0;
                }
            }
            state.file_mappings.retain(|&(vaddr, seg_len)| {
                let seg_end = vaddr.saturating_add(seg_len);
                seg_end <= unmap_start || vaddr >= unmap_end
            });
            state.patched_ranges.retain(|&(vaddr, seg_len)| {
                let seg_end = vaddr.saturating_add(seg_len);
                seg_end <= unmap_start || vaddr >= unmap_end
            });
        }
    }

    /// Handle syscall `mprotect`
    #[inline]
    pub(crate) fn sys_mprotect(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        // Intercept transitions to PROT_EXEC: patch unpatched file mappings.
        if prot.contains(ProtFlags::PROT_EXEC) {
            let syscall_entry = self.global.platform.get_syscall_entry_point();
            if syscall_entry != 0 {
                #[cfg(target_arch = "x86_64")]
                self.maybe_patch_on_mprotect_exec(addr, len, syscall_entry);
                #[cfg(target_arch = "aarch64")]
                if !self.maybe_patch_on_mprotect_exec(addr, len, syscall_entry) {
                    return Err(Errno::ENOMEM);
                }
            }
        }
        // Only AArch64 needs protection from loader reprotection of its holes;
        // x86-64 must retain whole-request behavior.
        #[cfg(target_arch = "aarch64")]
        let result = self.mprotect_around_trampolines(addr.as_usize(), len, prot);
        #[cfg(target_arch = "x86_64")]
        let result = self.sys_mprotect_raw(addr, len, prot);
        result
    }

    /// Applies `prot`, excluding AOT trampolines placed inside their load spans.
    /// Runtime trampolines are outside the span and are not excluded.
    #[cfg(target_arch = "aarch64")]
    fn mprotect_around_trampolines(
        &self,
        start: usize,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        let range = start..start.saturating_add(len);
        let excluded: alloc::vec::Vec<Range<usize>> = {
            let cache = self.global.elf_patch_cache.lock();
            cache
                .values()
                .filter(|state| {
                    !state.trampoline_invalidated
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
            self.sys_mprotect_raw(
                UserPtrMut::<u8>::from_usize(sub.start),
                sub.len(),
                prot.clone(),
            )?;
        }
        Ok(())
    }

    /// Raw mprotect without exec interception — used internally by the
    /// patching logic to avoid deadlocks (the patch path holds elf_patch_cache).
    #[inline]
    pub(crate) fn sys_mprotect_raw(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        litebox_common_linux::mm::sys_mprotect(&self.global.pm, addr, len, prot)
    }

    #[inline]
    pub(crate) fn sys_mremap(
        &self,
        old_addr: UserPtrMut<u8>,
        old_size: usize,
        new_size: usize,
        flags: MRemapFlags,
        new_addr: usize,
    ) -> Result<UserPtrMut<u8>, Errno> {
        litebox_common_linux::mm::sys_mremap(
            &self.global.pm,
            old_addr,
            old_size,
            new_size,
            flags,
            new_addr,
        )
    }

    /// Handle syscall `brk`
    #[inline]
    pub(crate) fn sys_brk(&self, addr: UserPtrMut<u8>) -> Result<usize, Errno> {
        litebox_common_linux::mm::sys_brk(&self.global.pm, addr)
    }

    /// Handle syscall `madvise`
    #[inline]
    pub(crate) fn sys_madvise(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        advice: litebox_common_linux::MadviseBehavior,
    ) -> Result<(), Errno> {
        litebox_common_linux::mm::sys_madvise(&self.global.pm, addr, len, advice)
    }

    // ── Runtime ELF syscall patching ─────────────────────────────────────

    /// Check all tracked file mappings for unpatched regions that overlap the
    /// mprotect range. If found, run the runtime rewriter before the region
    /// becomes executable.
    fn maybe_patch_on_mprotect_exec(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        syscall_entry: usize,
    ) -> bool {
        let mprotect_start = addr.as_usize();
        let mprotect_end = mprotect_start.saturating_add(len);

        // Find unpatched file mappings that overlap this mprotect range.
        // We collect (fd, vaddr, seg_len, file_offset) to avoid holding
        // the lock while patching.
        let to_patch: alloc::vec::Vec<(i32, usize, usize)> = {
            let cache = self.global.elf_patch_cache.lock();
            let mut result = alloc::vec::Vec::new();
            for (&fd, state) in cache.iter() {
                #[cfg(target_arch = "x86_64")]
                if state.pre_patched {
                    continue;
                }
                for &(seg_start, seg_len) in &state.file_mappings {
                    let seg_end = seg_start.saturating_add(seg_len);
                    // Check overlap with the mprotect range.
                    if seg_start < mprotect_end && seg_end > mprotect_start {
                        result.push((fd, seg_start, seg_len));
                    }
                }
            }
            result
        };

        // A single mprotect range should only overlap mappings from one fd
        // (a given vaddr range is backed by at most one file at a time).
        if to_patch.len() > 1 {
            let fds: BTreeSet<i32> = to_patch.iter().map(|(fd, _, _)| *fd).collect();
            if fds.len() > 1 {
                litebox_util_log::warn!(
                    addr:? = mprotect_start, len:? = len, fds:? = fds;
                    "mprotect +EXEC range overlaps file mappings from multiple fds"
                );
            }
        }

        for (fd, seg_start, seg_len) in to_patch {
            // Clamp to the intersection of the tracked mapping and the
            // mprotect range — only patch the portion becoming executable.
            // Re-running the rewriter on already-patched bytes is safe,
            // so we don't need to track sub-range overlaps precisely.
            let seg_end = seg_start.saturating_add(seg_len);
            let patch_start = seg_start.max(mprotect_start);
            let patch_end = seg_end.min(mprotect_end);
            let patch_len = patch_end.saturating_sub(patch_start);
            if patch_len == 0 {
                continue;
            }
            let mapped_addr = UserPtrMut::<u8>::from_usize(patch_start);
            if !self.maybe_patch_exec_segment(mapped_addr, patch_len, fd, syscall_entry, None) {
                return false;
            }
        }
        true
    }

    /// Initialize ELF patch state for an fd on its first mmap.
    ///
    /// Derives patch state and the architecture-specific trampoline fallback.
    ///
    /// For ET_DYN binaries (PIE/shared libs), virtual addresses in program
    /// headers are relative to a base address chosen at load time. We derive
    /// the base from the caller's mapping: `base = mapped_addr - p_vaddr` of
    /// the segment being mapped. The `file_offset` parameter identifies which
    /// segment is being mapped so we can look up its `p_vaddr`.
    ///
    /// Requires the supported architectures' common 64-bit ELF layout.
    fn init_elf_patch_state(&self, fd: i32, mapped_addr: usize, file_offset: usize) {
        // Quick check: skip if already initialized.
        if self.global.elf_patch_cache.lock().contains_key(&fd) {
            return;
        }

        // Read the ELF header (64 bytes for Elf64).
        let mut ehdr_buf = [0u8; core::mem::size_of::<FileHeader64<LittleEndian>>()];
        match self.sys_read(fd, &mut ehdr_buf, Some(0)) {
            Ok(n) if n == ehdr_buf.len() => {}
            _ => return, // Not readable or short read, skip
        }

        // Parse as typed ELF64 header.
        let Ok((ehdr, _)) = object::from_bytes::<FileHeader64<LittleEndian>>(&ehdr_buf) else {
            return;
        };

        // Verify ELF magic
        if &ehdr.e_ident.magic != b"\x7fELF" {
            return;
        }

        let e_type = ehdr.e_type.get(ENDIAN);
        let e_machine = ehdr.e_machine.get(ENDIAN);
        let e_phoff: usize = ehdr.e_phoff.get(ENDIAN).trunc();
        let e_phentsize = ehdr.e_phentsize.get(ENDIAN) as usize;
        let e_phnum = ehdr.e_phnum.get(ENDIAN) as usize;

        // Validate e_phentsize: must be at least sizeof(Elf64_Phdr).
        if e_phentsize < core::mem::size_of::<ProgramHeader64<LittleEndian>>() {
            return;
        }

        // Read program headers.
        let Some(phdrs_size) = e_phentsize.checked_mul(e_phnum) else {
            return;
        };
        if phdrs_size == 0 || phdrs_size > 0x10000 {
            return; // Sanity check
        }
        let mut phdrs_buf = alloc::vec![0u8; phdrs_size];
        match self.sys_read(fd, &mut phdrs_buf, Some(e_phoff)) {
            Ok(n) if n == phdrs_buf.len() => {}
            _ => return,
        }

        // Find highest PT_LOAD end (p_vaddr + p_memsz) and compute base_addr
        // by matching the segment whose p_offset corresponds to file_offset.
        let mut max_load_end: u64 = 0;
        let mut min_load_start: u64 = u64::MAX;
        let mut max_load_align: u64 = 0;
        let mut base_addr: Option<usize> = None;
        for i in 0..e_phnum {
            let ph_bytes = &phdrs_buf[i * e_phentsize..][..e_phentsize];
            let Ok((ph, _)) = object::from_bytes::<ProgramHeader64<LittleEndian>>(ph_bytes) else {
                continue;
            };
            if ph.p_type.get(ENDIAN) != PT_LOAD {
                continue;
            }
            let p_offset: usize = ph.p_offset.get(ENDIAN).trunc();
            let p_vaddr = ph.p_vaddr.get(ENDIAN);
            let p_memsz = ph.p_memsz.get(ENDIAN);
            let Some(end) = p_vaddr.checked_add(p_memsz) else {
                litebox_util_log::warn!(
                    p_vaddr:? = p_vaddr, p_memsz:? = p_memsz;
                    "PT_LOAD p_vaddr + p_memsz overflow, skipping segment"
                );
                continue;
            };
            if end > max_load_end {
                max_load_end = end;
            }
            min_load_start = min_load_start.min(align_down(p_vaddr.trunc(), PAGE_SIZE) as u64);
            max_load_align = max_load_align.max(ph.p_align.get(ENDIAN));
            // Match segment by page-aligned file offset to derive base address.
            if base_addr.is_none()
                && align_down(p_offset, PAGE_SIZE) == align_down(file_offset, PAGE_SIZE)
            {
                base_addr = Some(mapped_addr.wrapping_sub(p_vaddr.trunc()));
            }
        }

        if max_load_end == 0 {
            return; // No PT_LOAD segments
        }

        // Check if file is pre-patched by reading the last 32 bytes for magic
        let (pre_patched, tramp_file_offset, tramp_vaddr, tramp_file_size) =
            self.check_trampoline_magic(fd);

        #[cfg(all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"))]
        let code_metadata = if pre_patched {
            None
        } else {
            self.sys_fstat(fd).ok().and_then(|stat| {
                let file_size: usize = stat.st_size.reinterpret_as_unsigned().trunc();
                let word_len = file_size.div_ceil(8);
                let mut words = u64::new_vec_zeroed(word_len).ok()?;
                let bytes = zerocopy::IntoBytes::as_mut_bytes(words.as_mut_slice());
                match self.sys_read(fd, &mut bytes[..file_size], Some(0)) {
                    Ok(n) if n == file_size => {
                        litebox_syscall_rewriter::aarch64::ElfCodeMetadata::parse_aligned_in_place(
                            &mut words, file_size,
                        )
                        .ok()
                    }
                    _ => None,
                }
            })
        };

        // Compute the trampoline virtual address.
        // - Pre-patched: use the exact address from the trampoline header (the
        //   code already contains JMPs there, so we MUST map at this address).
        // - Unpatched: use the architecture-specific fallback past the loader's
        //   alignment slack. This is only a hint; the runtime path re-checks
        //   the chosen address against the branch-reach limit below, and falls
        //   back to traps.
        // For ET_DYN, virtual addresses are relative to the load base.
        let trampoline_vaddr = if pre_patched {
            if e_type == ET_DYN {
                let Some(base) = base_addr else {
                    panic!(
                        "fatal: pre-patched ET_DYN binary but cannot determine load base address"
                    );
                };
                let vaddr: usize = tramp_vaddr.trunc();
                base + vaddr
            } else {
                tramp_vaddr.trunc()
            }
        } else {
            let base = if e_type == ET_DYN {
                base_addr.unwrap_or(mapped_addr)
            } else {
                0
            };
            // On x86-64, the fallback is the page-aligned end of the highest
            // PT_LOAD segment.
            // No trustworthy program-header view of a partially mapped file
            // here, so take the `trampoline_addr_for` fallback rather than the
            // hole `trampoline_placement_for` would pick.
            let Ok(offset) = litebox_syscall_rewriter::trampoline_addr_for(
                max_load_end,
                max_load_align,
                e_machine,
            ) else {
                return;
            };
            let offset: usize = offset.trunc();
            base + offset
        };

        // Never synthesize an ET_DYN span from an unknown base: it could cover
        // unrelated mappings.
        #[cfg(target_arch = "aarch64")]
        let load_span = if e_type == ET_DYN {
            base_addr.map(|load_base| {
                load_base.wrapping_add(min_load_start.trunc())
                    ..load_base.wrapping_add(align_up(max_load_end.trunc(), PAGE_SIZE))
            })
        } else {
            Some(min_load_start.trunc()..align_up(max_load_end.trunc(), PAGE_SIZE))
        };

        // Insert under lock (re-check for races).
        let mut cache = self.global.elf_patch_cache.lock();
        cache.entry(fd).or_insert(ElfPatchState {
            pre_patched,
            trampoline_file_offset: tramp_file_offset,
            trampoline_file_size: tramp_file_size.trunc(),
            trampoline_addr: trampoline_vaddr,
            #[cfg(target_arch = "aarch64")]
            load_span,
            trampoline_cursor: 0,
            trampoline_mapped: false,
            trampoline_mapped_len: 0,
            runtime_patches_committed: false,
            #[cfg(target_arch = "aarch64")]
            trampoline_invalidated: false,
            #[cfg(all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"))]
            code_metadata,
            file_mappings: BTreeSet::new(),
            patched_ranges: BTreeSet::new(),
        });
    }

    /// Allows `MAP_FIXED` inside the computed load span. Outside it, rejects
    /// overlap with accessible mappings. This does not prove current ownership.
    #[cfg(target_arch = "aarch64")]
    fn trampoline_range_is_safe_to_map(
        &self,
        state: &ElfPatchState,
        start: usize,
        len: usize,
    ) -> bool {
        let range = start..start.saturating_add(len);
        let end = range.end;
        if state
            .load_span
            .as_ref()
            .is_some_and(|span| range.start >= span.start && range.end <= span.end)
        {
            return true;
        }
        for (range, flags) in self.global.pm.mappings() {
            if range.end <= start || range.start >= end {
                continue;
            }
            if flags.intersects(VmFlags::VM_ACCESS_FLAGS) {
                litebox_util_log::error!(
                    tramp_start:? = start, tramp_end:? = end,
                    victim_start:? = range.start, victim_end:? = range.end,
                    victim_flags:? = flags;
                    "refusing to map a trampoline over another mapping's live pages"
                );
                return false;
            }
        }
        true
    }

    /// Check if a file has the LITEBOX trampoline magic at its tail.
    /// Returns (is_pre_patched, file_offset, vaddr, trampoline_size).
    fn check_trampoline_magic(&self, fd: i32) -> (bool, u64, u64, u64) {
        const HEADER_SIZE: usize = 32; // TrampolineHeader64: magic(8) + file_offset(8) + vaddr(8) + size(8)
        let Ok(stat) = self.sys_fstat(fd) else {
            return (false, 0, 0, 0);
        };
        #[cfg(target_arch = "x86_64")]
        let file_size: usize = stat.st_size;
        #[cfg(target_arch = "aarch64")]
        let file_size: usize = {
            // The asm-generic ABI uses signed `st_size`.
            stat.st_size.reinterpret_as_unsigned().trunc()
        };
        if file_size < HEADER_SIZE {
            return (false, 0, 0, 0);
        }
        let mut tail = [0u8; HEADER_SIZE];
        match self.sys_read(fd, &mut tail, Some(file_size - HEADER_SIZE)) {
            Ok(n) if n == HEADER_SIZE => {}
            _ => return (false, 0, 0, 0),
        }
        if &tail[0..8] != litebox_syscall_rewriter::TRAMPOLINE_MAGIC {
            return (false, 0, 0, 0);
        }
        let file_offset = u64::from_le_bytes(tail[8..16].try_into().unwrap());
        let vaddr = u64::from_le_bytes(tail[16..24].try_into().unwrap());
        let trampoline_size = u64::from_le_bytes(tail[24..32].try_into().unwrap());
        (true, file_offset, vaddr, trampoline_size)
    }

    /// Apply the trap fallback to a mapped code segment: replace every patch
    /// site with the rewriter's trap, then restore RX.
    ///
    /// If `already_rw` is true, the segment is assumed to already be writable
    /// and the initial mprotect RW is skipped.
    ///
    /// Panics on infrastructure failures (mprotect/read/write/disassembly).
    #[cfg(target_arch = "aarch64")]
    fn apply_aarch64_trap_fallback(
        &self,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        already_rw: bool,
        ranges: Option<&litebox_syscall_rewriter::aarch64::CodeScanRanges>,
    ) {
        if !already_rw {
            self.sys_mprotect_raw(
                mapped_addr,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
            .expect("fatal: failed to mprotect code segment RW for trap fallback");
        }

        // Read, patch using the rewriter (proper disassembly), write back.
        let Some(code_owned) = mapped_addr.to_owned_slice::<Platform>(len) else {
            panic!("fatal: failed to read code segment for trap fallback");
        };
        let mut code_buf = code_owned.into_vec();
        let code_vaddr = mapped_addr.as_usize() as u64;
        let count = if let Some(ranges) = ranges {
            litebox_syscall_rewriter::trap_all_aarch64_patch_sites_with_options_and_ranges(
                &mut code_buf,
                code_vaddr,
                ranges,
                crate::aarch64_rewrite_options(),
            )
        } else {
            litebox_syscall_rewriter::trap_all_syscalls_in_code_with_options(
                &mut code_buf,
                code_vaddr,
                crate::aarch64_rewrite_options(),
            )
        }
        .unwrap_or_else(|e| {
            panic!("fatal: failed to disassemble code segment for trap fallback: {e:?}");
        });
        if count > 0 {
            litebox_util_log::warn!(
                count:? = count, addr:? = mapped_addr.as_usize(), len:? = len;
                "applied trap fallback to AArch64 patch sites"
            );
        }
        assert!(
            mapped_addr
                .copy_from_slice::<Platform>(0, &code_buf)
                .is_some(),
            "fatal: failed to write trap bytes back to code segment"
        );

        // Restore RX.
        self.sys_mprotect_raw(
            mapped_addr,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
        )
        .expect("fatal: failed to restore code segment to RX after trap fallback");
    }

    #[cfg(target_arch = "x86_64")]
    fn apply_trap_fallback(&self, mapped_addr: UserPtrMut<u8>, len: usize, already_rw: bool) {
        if !already_rw {
            self.sys_mprotect_raw(
                mapped_addr,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
            .expect("fatal: failed to mprotect code segment RW for trap fallback");
        }
        let Some(code_owned) = mapped_addr.to_owned_slice::<Platform>(len) else {
            panic!("fatal: failed to read code segment for trap fallback");
        };
        let mut code_buf = code_owned.into_vec();
        let code_vaddr = mapped_addr.as_usize() as u64;
        let count = litebox_syscall_rewriter::trap_all_syscalls_in_code(&mut code_buf, code_vaddr)
            .unwrap_or_else(|e| {
                panic!("fatal: failed to disassemble code segment for trap fallback: {e:?}");
            });
        if count > 0 {
            litebox_util_log::warn!(
                count:? = count, addr:? = mapped_addr.as_usize(), len:? = len;
                "applied trap fallback to syscall instructions"
            );
        }
        assert!(
            mapped_addr
                .copy_from_slice::<Platform>(0, &code_buf)
                .is_some(),
            "fatal: failed to write trap bytes back to code segment"
        );

        // Restore RX.
        self.sys_mprotect_raw(
            mapped_addr,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
        )
        .expect("fatal: failed to restore code segment to RX after trap fallback");
    }

    /// Patch an executable segment in-place after it has been mapped.
    ///
    /// For pre-patched binaries: maps the trampoline from the file and writes
    /// the syscall entry point.
    /// For unpatched binaries: calls `patch_code_segment()` to rewrite syscall
    /// instructions and places the generated stubs in the trampoline region.
    ///
    /// Returns `true` on success or non-fatal skip. Returns `false` when a
    /// pre-patched binary's trampoline could not be set up — the caller must
    /// fail the mapping because the code already contains JMPs to the
    /// trampoline address.
    fn maybe_patch_exec_segment(
        &self,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        fd: i32,
        syscall_entry: usize,
        file_offset: Option<usize>,
    ) -> bool {
        // Initialize patch state if this is the first mmap for this fd.
        // Typically the first mapping is at offset 0 (the ELF header), but
        // some loaders may map an executable segment at a non-zero offset first.
        if !self.global.elf_patch_cache.lock().contains_key(&fd) {
            self.init_elf_patch_state(fd, mapped_addr.as_usize(), file_offset.unwrap_or(0));
        }

        // This lock guards the elf_patch_cache and is held for the entire
        // patching operation. In practice this is fine because the dynamic
        // linker loads shared libraries sequentially.
        let mut cache = self.global.elf_patch_cache.lock();
        let Some(state) = cache.get_mut(&fd) else {
            return true; // No patch state — not an ELF we're tracking
        };
        #[cfg(target_arch = "aarch64")]
        if state.trampoline_invalidated {
            return false;
        }

        if state.pre_patched {
            // Pre-patched binary: map the trampoline data from the file.
            if !state.trampoline_mapped && state.trampoline_file_size > 0 {
                let tramp_addr = state.trampoline_addr;
                let tramp_len = align_up(state.trampoline_file_size, PAGE_SIZE);

                // MAP_FIXED_NOREPLACE would reject the legitimate PROT_NONE or
                // object-span reservation, so validate ownership before MAP_FIXED.
                #[cfg(target_arch = "aarch64")]
                if !self.trampoline_range_is_safe_to_map(state, tramp_addr, tramp_len) {
                    return false;
                }
                let alloc_result = self.do_mmap_anonymous(
                    Some(tramp_addr),
                    tramp_len,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                );
                let Ok(alloc_ptr) = alloc_result else {
                    return false;
                };
                let actual_addr = alloc_ptr.as_usize();
                if actual_addr != tramp_addr {
                    let _ =
                        self.sys_munmap_raw(UserPtrMut::<u8>::from_usize(actual_addr), tramp_len);
                    return false;
                }

                // Read trampoline data from the file.
                let mut tramp_data = alloc::vec![0u8; state.trampoline_file_size];
                let file_off = state.trampoline_file_offset.trunc();
                let tramp_ptr = UserPtrMut::<u8>::from_usize(tramp_addr);
                match self.sys_read(fd, &mut tramp_data, Some(file_off)) {
                    Ok(n) if n == tramp_data.len() => {}
                    _ => {
                        let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
                        return false;
                    }
                }

                // Write syscall entry point to the first 8 bytes.
                if tramp_data.len() >= 8 {
                    tramp_data[..8].copy_from_slice(&syscall_entry.to_le_bytes());
                }

                // Finalize in staging so an unpatched gate is never published.
                #[cfg(target_arch = "aarch64")]
                if let Err(e) = finalize_trampoline_gates(self.global.platform, &mut tramp_data) {
                    litebox_util_log::error!(err:% = e; "refusing to map a trampoline whose guest thread-pointer gates are not patched");
                    let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
                    return false;
                }

                // Write to the mapped region.
                if tramp_ptr
                    .copy_from_slice::<Platform>(0, &tramp_data)
                    .is_none()
                {
                    let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
                    return false;
                }

                // Protect as RX immediately.
                if self
                    .sys_mprotect_raw(
                        tramp_ptr,
                        tramp_len,
                        ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                    )
                    .is_err()
                {
                    let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
                    return false;
                }

                state.trampoline_mapped = true;
                state.trampoline_mapped_len = tramp_len;
            }
            return true;
        }

        // ── Runtime patching path (unpatched binaries) ───────────────

        #[cfg(all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"))]
        let scan_ranges = file_offset.and_then(|file_offset| {
            state
                .code_metadata
                .as_ref()
                .and_then(|metadata| metadata.ranges_for_mapping(file_offset as u64, len).ok())
        });
        #[cfg(all(target_arch = "aarch64", not(feature = "aarch64_virtualize_x18")))]
        let scan_ranges: Option<litebox_syscall_rewriter::aarch64::CodeScanRanges> = None;
        #[cfg(target_arch = "aarch64")]
        let apply_trap_fallback = |mapped_addr, len, already_rw| {
            self.apply_aarch64_trap_fallback(mapped_addr, len, already_rw, scan_ranges.as_ref());
        };
        #[cfg(target_arch = "x86_64")]
        let apply_trap_fallback = |mapped_addr, len, already_rw| {
            self.apply_trap_fallback(mapped_addr, len, already_rw);
        };

        // Allocate the trampoline region if not yet done.
        let addr_usize = mapped_addr.as_usize();
        if !state.trampoline_mapped {
            let tramp_addr = state.trampoline_addr;

            // Try MAP_FIXED_NOREPLACE first — works when the preferred
            // trampoline address is available. If that fails, let the VM
            // manager choose a free address and validate that it is still
            // within JMP rel32 range below.
            let actual_addr = self
                .do_mmap_anonymous(
                    Some(tramp_addr),
                    PAGE_SIZE,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                )
                .or_else(|_| {
                    self.do_mmap_anonymous(
                        None,
                        PAGE_SIZE,
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                        MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                    )
                });
            let Ok(actual_addr_ptr) = actual_addr else {
                litebox_util_log::warn!("failed to allocate trampoline region");
                apply_trap_fallback(mapped_addr, len, false);
                return true;
            };
            let actual_addr = actual_addr_ptr.as_usize();

            let far_end = addr_usize.saturating_add(len);
            let distance = actual_addr
                .abs_diff(addr_usize)
                .max(actual_addr.abs_diff(far_end));
            if distance > litebox_syscall_rewriter::MAX_TRAMPOLINE_DISPLACEMENT {
                litebox_util_log::warn!(
                    distance:? = distance;
                    "trampoline too far from code segment, skipping patching"
                );
                let _ = self.sys_munmap_raw(UserPtrMut::<u8>::from_usize(actual_addr), PAGE_SIZE);
                apply_trap_fallback(mapped_addr, len, false);
                return true;
            }

            state.trampoline_addr = actual_addr;

            if litebox_syscall_rewriter::TRAMPOLINE_ENTRY_POINT_BYTES != 0 {
                let entry_ptr = UserPtrMut::<u8>::from_usize(actual_addr);
                if entry_ptr
                    .copy_from_slice::<Platform>(0, &syscall_entry.to_le_bytes())
                    .is_none()
                {
                    litebox_util_log::warn!("failed to write syscall entry point to trampoline");
                    let _ =
                        self.sys_munmap_raw(UserPtrMut::<u8>::from_usize(actual_addr), PAGE_SIZE);
                    apply_trap_fallback(mapped_addr, len, false);
                    return true;
                }
                state.trampoline_cursor = litebox_syscall_rewriter::TRAMPOLINE_ENTRY_POINT_BYTES;
            } else {
                state.trampoline_cursor = 0;
            }
            state.trampoline_mapped = true;
            state.trampoline_mapped_len = PAGE_SIZE;
        }

        // Performance guard: skip if this exact range was already patched.
        let mapping_key = (mapped_addr.as_usize(), len);
        if state.patched_ranges.contains(&mapping_key) {
            return true;
        }
        state.patched_ranges.insert(mapping_key);

        let restore_trampoline_rx = |task: &Self, state: &ElfPatchState| {
            if state.trampoline_mapped_len > 0 {
                let _ = task.sys_mprotect_raw(
                    UserPtrMut::<u8>::from_usize(state.trampoline_addr),
                    state.trampoline_mapped_len,
                    ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                );
            }
        };

        // Make the trampoline RW for writing stubs.
        if state.trampoline_mapped_len > 0
            && self
                .sys_mprotect_raw(
                    UserPtrMut::<u8>::from_usize(state.trampoline_addr),
                    state.trampoline_mapped_len,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                )
                .is_err()
        {
            panic!("fatal: failed to mprotect trampoline to RW");
        }
        if self
            .sys_mprotect_raw(
                mapped_addr,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
            .is_err()
        {
            restore_trampoline_rx(self, state);
            panic!("fatal: failed to mprotect code segment to RW for patching");
        }

        // Read the mapped code into a buffer, patch it, write back.
        let Some(code_owned) = mapped_addr.to_owned_slice::<Platform>(len) else {
            let _ = self.sys_mprotect_raw(
                mapped_addr,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
            );
            restore_trampoline_rx(self, state);
            panic!("fatal: failed to read code segment for patching");
        };
        let mut code_buf = code_owned.into_vec();
        let original_code = code_buf.clone();

        let code_vaddr = addr_usize as u64;
        state.trampoline_cursor = align_up(
            state.trampoline_cursor,
            litebox_syscall_rewriter::TRAMPOLINE_CURSOR_ALIGN,
        );
        let trampoline_write_vaddr = (state.trampoline_addr + state.trampoline_cursor) as u64;
        let syscall_entry_addr = if litebox_syscall_rewriter::TRAMPOLINE_ENTRY_POINT_BYTES != 0 {
            state.trampoline_addr as u64
        } else {
            syscall_entry as u64
        };

        #[cfg(target_arch = "aarch64")]
        let patch_result = if let Some(ranges) = &scan_ranges {
            litebox_syscall_rewriter::patch_aarch64_code_segment_with_options_and_ranges(
                &mut code_buf,
                code_vaddr,
                ranges,
                trampoline_write_vaddr,
                syscall_entry_addr,
                crate::aarch64_rewrite_options(),
            )
        } else {
            litebox_syscall_rewriter::patch_code_segment_with_options(
                &mut code_buf,
                code_vaddr,
                trampoline_write_vaddr,
                syscall_entry_addr,
                crate::aarch64_rewrite_options(),
            )
        };
        #[cfg(target_arch = "x86_64")]
        let patch_result = litebox_syscall_rewriter::patch_code_segment(
            &mut code_buf,
            code_vaddr,
            trampoline_write_vaddr,
            syscall_entry_addr,
        );
        let patch_result = match patch_result {
            Ok((stubs, skipped_addrs)) => {
                if !skipped_addrs.is_empty() {
                    litebox_util_log::warn!(
                        count:? = skipped_addrs.len(), addrs:? = skipped_addrs;
                        "syscall instruction(s) could not be patched"
                    );
                }
                Ok(stubs)
            }
            Err(e) => Err(e),
        };
        match patch_result {
            Ok(stubs) if !stubs.is_empty() => {
                // Replace recognized sites with traps before discarding gates
                // whose thread-pointer placeholder could not be finalized.
                #[cfg(target_arch = "aarch64")]
                let stubs = {
                    let mut stubs = stubs;
                    if let Err(e) = finalize_trampoline_gates(self.global.platform, &mut stubs) {
                        litebox_util_log::error!(err:% = e; "refusing to install runtime gates whose guest thread-pointer is not patched");
                        apply_trap_fallback(mapped_addr, len, true);
                        restore_trampoline_rx(self, state);
                        return true;
                    }
                    stubs
                };
                let Some(new_cursor) = state.trampoline_cursor.checked_add(stubs.len()) else {
                    litebox_util_log::warn!("trampoline cursor overflow");
                    apply_trap_fallback(mapped_addr, len, true);
                    restore_trampoline_rx(self, state);
                    return true;
                };
                let tramp_pages_needed = align_up(new_cursor, PAGE_SIZE);
                if tramp_pages_needed > state.trampoline_mapped_len {
                    let extra_start = state.trampoline_addr + state.trampoline_mapped_len;
                    let extra_len = tramp_pages_needed - state.trampoline_mapped_len;
                    if self
                        .do_mmap_anonymous(
                            Some(extra_start),
                            extra_len,
                            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                            MapFlags::MAP_ANONYMOUS
                                | MapFlags::MAP_PRIVATE
                                | MapFlags::MAP_FIXED_NOREPLACE,
                        )
                        .is_err()
                    {
                        litebox_util_log::warn!("failed to expand trampoline region");
                        apply_trap_fallback(mapped_addr, len, true);
                        restore_trampoline_rx(self, state);
                        return true;
                    }
                    state.trampoline_mapped_len = tramp_pages_needed;
                }

                // Write stubs before patching the code so rewritten jumps
                // never target an uninitialized trampoline.
                let tramp_write_ptr =
                    UserPtrMut::<u8>::from_usize(state.trampoline_addr + state.trampoline_cursor);
                if tramp_write_ptr
                    .copy_from_slice::<Platform>(0, &stubs)
                    .is_none()
                {
                    let _ = self.sys_mprotect_raw(
                        mapped_addr,
                        len,
                        ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                    );
                    restore_trampoline_rx(self, state);
                    panic!("fatal: failed to write trampoline stubs");
                }

                // Write patched code back to the mapped region.
                if mapped_addr
                    .copy_from_slice::<Platform>(0, &code_buf)
                    .is_none()
                {
                    let _ = mapped_addr.copy_from_slice::<Platform>(0, &original_code);
                    let _ = self.sys_mprotect_raw(
                        mapped_addr,
                        len,
                        ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
                    );
                    restore_trampoline_rx(self, state);
                    panic!("fatal: failed to write patched code back to code segment");
                }
                state.trampoline_cursor = new_cursor;
                state.runtime_patches_committed = true;
            }
            Ok(_) => {
                // No trampoline stubs were generated, but the rewriter may
                // have replaced unpatchable syscalls with trap instructions.
                // Write back the modified code if it changed.
                if code_buf != original_code
                    && mapped_addr
                        .copy_from_slice::<Platform>(0, &code_buf)
                        .is_none()
                {
                    let _ = mapped_addr.copy_from_slice::<Platform>(0, &original_code);
                    panic!("fatal: failed to write trap bytes back to code segment");
                }
                // Fall through to restore RX protections below.
            }
            Err(e) => {
                litebox_util_log::warn!(err:? = e; "patch_code_segment failed");
                apply_trap_fallback(mapped_addr, len, true);
                restore_trampoline_rx(self, state);
                return true;
            }
        }

        // Restore the code segment to RX.
        let _ = self.sys_mprotect_raw(
            mapped_addr,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
        );
        restore_trampoline_rx(self, state);
        true
    }

    /// Finalize the ELF patching state for `fd`.
    ///
    /// Removes the cache entry (preventing stale state if the fd is reused)
    /// and unmaps any trampoline that was allocated but never used.
    pub(crate) fn finalize_elf_patch(&self, fd: i32) {
        // TODO: retain patch state for mappings that outlive `fd`, together
        // with an owned backing-file handle. Dropping it here makes a later
        // mprotect(PROT_EXEC) unable to patch those mappings.
        let state = self.global.elf_patch_cache.lock().remove(&fd);
        if let Some(state) = state
            && state.trampoline_mapped
            && !state.pre_patched
            && !state.runtime_patches_committed
        {
            let tramp_len = state.trampoline_mapped_len;
            if tramp_len > 0 {
                let _ = self.sys_munmap(
                    UserPtrMut::<u8>::from_usize(state.trampoline_addr),
                    tramp_len,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use litebox::{
        fs::{Mode, OFlags},
        platform::PageManagementProvider,
    };
    use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, errno::Errno};

    use crate::syscalls::tests::TestPlatform as Platform;
    use crate::{UserPtrMut, syscalls::tests::init_platform};

    /// Fail closed: an unpatched placeholder executes silently.
    #[cfg(target_arch = "aarch64")]
    mod aarch64_trampoline_gates {
        use litebox::platform::SystemInfoProvider;

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
            let mut code = 0xD53B_D049u32.to_le_bytes(); // MRS X9, TPIDR_EL0
            let (tramp, trapped) =
                litebox_syscall_rewriter::patch_code_segment(&mut code, 0x1000, 0x400000, 0)
                    .unwrap();
            assert!(trapped.is_empty());
            assert_eq!(
                litebox_syscall_rewriter::aarch64::find_guest_tpidr_placeholder(&tramp),
                Some(16 + 4),
                "the fixture must start out unpatched, or these tests prove nothing"
            );
            let classified =
                litebox_syscall_rewriter::aarch64::classify_gate_pc(&tramp, 0x400000, 0x400010)
                    .expect("emitted MRS slot must validate");
            assert_eq!(classified.slot_offset(), 16);
            assert!(matches!(
                classified.metadata(),
                litebox_syscall_rewriter::aarch64::GateMetadata::MrsTpidr { destination: 9, .. }
            ));
            tramp
        }

        #[cfg(feature = "aarch64_virtualize_x18")]
        #[test]
        fn x18_gate_is_finalized_with_the_platform_offset() {
            let mut code = 0xaa00_03f2u32.to_le_bytes(); // mov x18, x0
            let options = litebox_syscall_rewriter::RewriteOptions::new(
                litebox_syscall_rewriter::TargetHost::Linux,
                true,
            );
            let (mut trampoline, trapped) =
                litebox_syscall_rewriter::patch_code_segment_with_options(
                    &mut code, 0x1000, 0x400000, 0, options,
                )
                .unwrap();
            assert!(trapped.is_empty());

            super::super::finalize_trampoline_gates(&StubPlatform(Some(96)), &mut trampoline)
                .unwrap();

            assert!(matches!(
                litebox_syscall_rewriter::aarch64::classify_gate_pc(
                    &trampoline,
                    0x400000,
                    0x400010,
                )
                .unwrap()
                .metadata(),
                litebox_syscall_rewriter::aarch64::GateMetadata::X18 { .. }
            ));
        }

        /// Runtime gates receive the callback address, not a callback-slot address.
        #[test]
        fn the_runtime_paths_argument_shape_produces_installable_gates() {
            const TRAMPOLINE_BASE: u64 = 0x40_0000;
            const SYSCALL_ENTRY: u64 = 0xDEAD_0000;
            const GUEST_THREAD_POINTER_OFFSET: usize = 96;

            let mut code = 0xD400_0001u32.to_le_bytes(); // SVC #0
            let (mut stubs, trapped) = litebox_syscall_rewriter::patch_code_segment(
                &mut code,
                0x1000,
                TRAMPOLINE_BASE,
                SYSCALL_ENTRY,
            )
            .expect("a gate-aligned base and a real callback must be accepted");
            assert!(trapped.is_empty());

            assert_eq!(
                u64::from_le_bytes(stubs[..8].try_into().unwrap()),
                SYSCALL_ENTRY
            );

            super::super::finalize_trampoline_gates(
                &StubPlatform(Some(GUEST_THREAD_POINTER_OFFSET)),
                &mut stubs,
            )
            .expect("runtime gates must be patchable exactly like ahead-of-time ones");
            assert_eq!(
                litebox_syscall_rewriter::aarch64::find_guest_tpidr_placeholder(&stubs),
                None
            );
            litebox_syscall_rewriter::aarch64::classify_gate_pc(
                &stubs,
                TRAMPOLINE_BASE,
                TRAMPOLINE_BASE + 16,
            )
            .expect("the installed gate must classify at runtime");

            let mut code = 0xD400_0001u32.to_le_bytes();
            assert!(
                litebox_syscall_rewriter::patch_code_segment(
                    &mut code,
                    0x1000,
                    TRAMPOLINE_BASE + 8,
                    TRAMPOLINE_BASE,
                )
                .is_err(),
                "a base-relative callback has to be rejected, or this test proves nothing"
            );
        }

        #[test]
        fn a_supplied_offset_is_baked_into_every_gate() {
            let mut tramp = unpatched_trampoline();
            super::super::finalize_trampoline_gates(&StubPlatform(Some(96)), &mut tramp)
                .expect("a well-formed trampoline and a valid offset must be accepted");
            assert_eq!(
                litebox_syscall_rewriter::aarch64::find_guest_tpidr_placeholder(&tramp),
                None
            );
        }

        #[test]
        fn a_platform_with_no_offset_is_refused() {
            let mut tramp = unpatched_trampoline();
            let err = super::super::finalize_trampoline_gates(&StubPlatform(None), &mut tramp)
                .expect_err(
                    "an AArch64 platform that supplies no offset must be fatal for the \
                         binary, not a silent skip",
                );
            assert!(err.contains("no guest thread-pointer offset"), "{err}");
            assert_eq!(
                litebox_syscall_rewriter::aarch64::find_guest_tpidr_placeholder(&tramp),
                Some(16 + 4)
            );
        }

        #[test]
        fn an_offset_no_gate_can_encode_is_refused() {
            let mut tramp = unpatched_trampoline();
            let err = super::super::finalize_trampoline_gates(&StubPlatform(Some(4)), &mut tramp)
                .expect_err("an offset the gates' scaled immediate cannot hold is fatal");
            assert!(err.contains("failed to patch"), "{err}");
        }
    }

    #[test]
    fn test_anonymous_mmap() {
        let task = init_platform();

        let addr = task
            .sys_mmap(
                0,
                0x2000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
                -1,
                0,
            )
            .unwrap();
        addr.write_slice_at_offset::<Platform>(0, &[0xff; 0x2000])
            .unwrap();
        assert_eq!(addr.read_at_offset::<Platform>(0x1000).unwrap(), 0xff,);
        task.sys_munmap(addr, 0x2000).unwrap();
    }

    #[test]
    fn test_file_backed_mmap() {
        let task = init_platform();

        let content = b"Hello, world!";
        let fd = task
            .sys_open("test.txt", OFlags::RDWR | OFlags::CREAT, Mode::RWXU)
            .unwrap();
        let fd = i32::try_from(fd).unwrap();
        assert_eq!(task.sys_write(fd, content, None).unwrap(), content.len());
        let addr = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd,
                0,
            )
            .unwrap();
        assert_eq!(
            addr.to_owned_slice::<Platform>(content.len())
                .unwrap()
                .as_ref(),
            content.as_slice(),
        );
        task.sys_munmap(addr, 0x1000).unwrap();
        task.sys_close(fd).unwrap();
    }

    #[test]
    fn test_mremap() {
        let task = init_platform();

        let addr = task
            .sys_mmap(
                0,
                0x2000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
                -1,
                0,
            )
            .unwrap();

        assert!(matches!(
            task.sys_mremap(
                addr,
                0x1000,
                0x2000,
                litebox_common_linux::MRemapFlags::empty(),
                0
            ),
            Err(litebox_common_linux::errno::Errno::ENOMEM)
        ),);
        let new_addr = task
            .sys_mremap(
                addr,
                0x1000,
                0x2000,
                litebox_common_linux::MRemapFlags::MREMAP_MAYMOVE,
                0,
            )
            .unwrap();
        task.sys_munmap(addr, 0x2000).unwrap();
        task.sys_munmap(new_addr, 0x2000).unwrap();
    }

    #[test]
    fn test_mmap_fixed_noreplace() {
        let task = init_platform();

        // First, create an initial mapping at a specific address away from boundaries
        let base_addr = 0x1000_0000usize; // 256 MiB - safe middle ground
        let addr1 = task
            .sys_mmap(
                base_addr,
                0x2000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap();
        assert_eq!(
            addr1.as_usize(),
            base_addr,
            "First mapping should be at exact address"
        );

        // Test 1: Full overlap - should fail with EEXIST
        let err = task
            .sys_mmap(
                addr1.as_usize(),
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap_err();
        assert_eq!(err, Errno::EEXIST);

        // Test 2: Partial overlap at end - should fail with EEXIST
        // Existing: [addr1, addr1 + 0x2000), New: [addr1 + 0x1000, addr1 + 0x3000)
        let err = task
            .sys_mmap(
                addr1.as_usize() + 0x1000,
                0x2000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap_err();
        assert_eq!(err, Errno::EEXIST);

        // Test 3: Partial overlap at start - should fail with EEXIST
        // Existing: [addr1, addr1 + 0x2000), New: [addr1 - 0x1000, addr1 + 0x1000)
        let err = task
            .sys_mmap(
                addr1.as_usize() - 0x1000,
                0x2000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap_err();
        assert_eq!(err, Errno::EEXIST);

        // Test 4: Adjacent mapping (right after) - should succeed
        let addr2 = task
            .sys_mmap(
                addr1.as_usize() + 0x2000,
                0x1000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap();
        assert_eq!(addr2.as_usize(), addr1.as_usize() + 0x2000);

        // Test 5: Adjacent mapping (right before) - should succeed
        let addr3 = task
            .sys_mmap(
                addr1.as_usize() - 0x1000,
                0x1000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap();
        assert_eq!(addr3.as_usize(), addr1.as_usize() - 0x1000);

        // Test 6: Zero address with MAP_FIXED_NOREPLACE - should fail with EPERM
        // (matches Linux behavior where vm.mmap_min_addr prevents mapping at address 0)
        let err = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap_err();
        assert_eq!(err, Errno::EPERM);

        // Clean up
        task.sys_munmap(addr3, 0x1000).unwrap();
        task.sys_munmap(addr1, 0x2000).unwrap();
        task.sys_munmap(addr2, 0x1000).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn test_collision_with_global_allocator() {
        let task = init_platform();
        let platform = task.global.platform;
        let mut data = alloc::vec::Vec::new();
        // Find an address that is allocated to the global allocator but not in reserved regions.
        // LiteBox's page manager is not aware of the global allocator's allocations.
        let addr = loop {
            #[allow(
                unused_variables,
                reason = "the following features are mutually exclusive"
            )]
            #[cfg(target_os = "windows")]
            let addr = {
                let buf = alloc::vec::Vec::<u8>::with_capacity(0x10_0000);
                let addr = buf.as_ptr() as usize;
                data.push(buf);
                addr
            };
            #[cfg(target_os = "linux")]
            let addr = {
                let addr = unsafe {
                    libc::mmap(
                        core::ptr::null_mut(),
                        0x10_000,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                } as usize;
                data.push(alloc::vec::Vec::<u8>::from(unsafe {
                    core::slice::from_raw_parts(addr as *const u8, 0x10_000)
                }));
                addr
            };

            let mut included = false;
            for r in <crate::syscalls::tests::TestPlatform as PageManagementProvider<
                4096,
            >>::reserved_pages(platform)
            {
                if r.contains(&addr) {
                    included = true;
                    break;
                }
            }

            if !included {
                // Also ensure that [addr - 0x1000, addr) is available, which is needed in the test below.
                if let Ok(ptr) = task.sys_mmap(
                    addr - 0x1000,
                    0x1000,
                    ProtFlags::PROT_READ,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON,
                    -1,
                    0,
                ) {
                    if ptr.as_usize() != addr - 0x1000 {
                        task.sys_munmap(ptr, 0x1000).unwrap();
                        continue;
                    }
                    break addr;
                }
            }
        };

        // mmap with the found address should still succeed but not at the exact address.
        let res = task
            .sys_mmap(
                addr,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON,
                -1,
                0,
            )
            .unwrap();
        assert_ne!(res.as_usize(), 0);
        assert_ne!(res.as_usize(), addr);

        // grow the mapping without MREMAP_MAYMOVE should fail as the new region collides with the global allocator
        let err = task
            .sys_mremap(
                UserPtrMut::from_usize(addr - 0x1000),
                0x1000,
                0x2000,
                MRemapFlags::empty(),
                addr - 0x1000,
            )
            .unwrap_err();
        assert_eq!(err, Errno::ENOMEM);
    }

    #[test]
    fn test_map_shared_anonymous() {
        let task = init_platform();

        // MAP_SHARED | MAP_ANON with PROT_READ should succeed
        let addr = task
            .sys_mmap(
                0,
                0x2000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_ANON | MapFlags::MAP_SHARED,
                -1,
                0,
            )
            .unwrap();

        // Reading should work
        let _val: u8 = addr.read_at_offset::<Platform>(0).unwrap();

        // Anonymous shared mappings allow permission changes including write
        task.sys_mprotect(addr, 0x2000, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)
            .unwrap();
        addr.write_slice_at_offset::<Platform>(0, &[0xab; 0x10])
            .unwrap();
        assert_eq!(addr.read_at_offset::<Platform>(0).unwrap(), 0xab_u8);

        // mprotect to read-only or read-exec should also succeed
        task.sys_mprotect(addr, 0x2000, ProtFlags::PROT_READ)
            .unwrap();
        task.sys_mprotect(addr, 0x2000, ProtFlags::PROT_READ_EXEC)
            .unwrap();

        task.sys_munmap(addr, 0x2000).unwrap();
    }

    #[test]
    fn test_map_shared_anonymous_writable() {
        let task = init_platform();

        // MAP_SHARED | MAP_ANON with PROT_WRITE should succeed
        let addr = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_SHARED,
                -1,
                0,
            )
            .unwrap();

        addr.write_slice_at_offset::<Platform>(0, &[0xcd; 0x10])
            .unwrap();
        assert_eq!(addr.read_at_offset::<Platform>(0).unwrap(), 0xcd_u8);

        task.sys_munmap(addr, 0x1000).unwrap();
    }

    #[test]
    fn test_map_shared_readonly_file() {
        let task = init_platform();

        let content = b"Hello, shared!";
        let fd = task
            .sys_open("shared.txt", OFlags::RDWR | OFlags::CREAT, Mode::RWXU)
            .unwrap();
        let fd = i32::try_from(fd).unwrap();
        assert_eq!(task.sys_write(fd, content, None).unwrap(), content.len());

        // MAP_SHARED with PROT_READ on a file should succeed
        let addr = task
            .sys_mmap(0, 0x1000, ProtFlags::PROT_READ, MapFlags::MAP_SHARED, fd, 0)
            .unwrap();

        // Data should match
        assert_eq!(
            addr.to_owned_slice::<Platform>(content.len())
                .unwrap()
                .as_ref(),
            content.as_slice(),
        );

        // mprotect to add write permission should fail
        let err = task
            .sys_mprotect(addr, 0x1000, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)
            .unwrap_err();
        assert_eq!(err, Errno::EACCES);

        task.sys_munmap(addr, 0x1000).unwrap();
        task.sys_close(fd).unwrap();
    }

    #[test]
    fn test_madvise() {
        let task = init_platform();

        let addr = task
            .sys_mmap(
                0,
                0x2000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
                -1,
                0,
            )
            .unwrap();

        addr.write_slice_at_offset::<Platform>(0, &[0xff; 0x10])
            .unwrap();

        // Test MADV_NORMAL
        assert!(
            task.sys_madvise(addr, 0x2000, litebox_common_linux::MadviseBehavior::Normal)
                .is_ok()
        );

        // Test MADV_DONTNEED
        assert!(
            task.sys_madvise(
                addr,
                0x2000,
                litebox_common_linux::MadviseBehavior::DontNeed
            )
            .is_ok()
        );

        addr.to_owned_slice::<Platform>(0x10)
            .unwrap()
            .iter()
            .for_each(|&x| {
                assert_eq!(x, 0); // Should be zeroed after MADV_DONTNEED
            });

        task.sys_munmap(addr, 0x2000).unwrap();
    }

    // Signal support for Windows is not ready yet.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_fallible_read() {
        let _ = init_platform();

        let ptr = UserPtrMut::<u8>::from_usize(0xdeadbeef);
        let result = ptr.read_at_offset::<Platform>(0);
        assert!(result.is_none());
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
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
