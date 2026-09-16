// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.
//! Most of these syscalls which are not backed by files are implemented in [`litebox_common_linux::mm`].

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use litebox::fs::errors::ReadError;
use litebox::{
    mm::linux::{MappingError, PAGE_SIZE, PageRange},
    platform::{
        PageManagementProvider, RawConstPointer,
        page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions},
    },
};
use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, errno::Errno};

use crate::FileFd;
use crate::ShimPlatform;
use crate::Task;
use crate::UserPtrMut;
use crate::syscalls::file::{AnyTypedFd, FilesState};
use litebox::utils::TruncateExt as _;
use object::elf::{ET_DYN, FileHeader64, PT_LOAD, ProgramHeader64};
use object::endian::LittleEndian;
use rangemap::RangeSet;

#[cfg(not(target_pointer_width = "64"))]
compile_error!("ELF patching code assumes 64-bit pointers (u64 <-> usize is lossless)");

const ENDIAN: LittleEndian = LittleEndian;

/// The trampoline opens with a pointer to the platform syscall entry point.
const TRAMPOLINE_ENTRY_SIZE: usize = core::mem::size_of::<usize>();

/// Per-descriptor state for the shim's runtime ELF syscall rewriter.
///
/// Tracks base address and trampoline data for each ELF file that
/// has executable segments mapped via `do_mmap_file()`.
pub(crate) struct ElfPatchState {
    /// Whether this file is already pre-patched (trampoline magic found at file tail).
    pre_patched: bool,
    /// For pre-patched binaries, trampoline bytes cached while the descriptor is open.
    trampoline_data: Option<alloc::vec::Vec<u8>>,
    /// The descriptor no longer names this state, but mappings may still need it.
    descriptor_closed: bool,
    /// Start address of the trampoline region (runtime).
    trampoline_addr: usize,
    /// Current write position within the trampoline (byte offset from `trampoline_addr`).
    trampoline_cursor: usize,
    /// Whether the trampoline region has been allocated.
    trampoline_mapped: bool,
    /// Total number of trampoline bytes currently mapped.
    trampoline_mapped_len: usize,
    /// Tracks file-backed virtual address ranges for this descriptor.
    /// Used to find mappings that need patching when mprotect adds PROT_EXEC.
    /// Cleared on munmap to allow re-patching.
    file_mappings: RangeSet<usize>,
    /// Ranges that have already been patched by the runtime rewriter.
    /// This is a performance guard only — re-running the rewriter on
    /// already-patched code is safe because the second run will not see
    /// syscall instructions. Cleared on munmap alongside file_mappings.
    patched_ranges: RangeSet<usize>,
}

/// Identity of a resolved filesystem descriptor.
pub(crate) struct ElfPatchKey<Platform: ShimPlatform>(Arc<FileFd<Platform>>);

impl<Platform: ShimPlatform> Clone for ElfPatchKey<Platform> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<Platform: ShimPlatform> PartialEq for ElfPatchKey<Platform> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<Platform: ShimPlatform> Eq for ElfPatchKey<Platform> {}

impl<Platform: ShimPlatform> PartialOrd for ElfPatchKey<Platform> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Platform: ShimPlatform> Ord for ElfPatchKey<Platform> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        Arc::as_ptr(&self.0).cmp(&Arc::as_ptr(&other.0))
    }
}

/// Per-process ELF patching state, keyed by retained descriptor identity.
///
/// A `None` value is a negative cache entry, recorded when a descriptor has been
/// probed and found not to be an ELF image we patch. It stops the header probe
/// from re-running on every mapping of the same descriptor.
///
pub(crate) type ElfPatchCache<Platform> = BTreeMap<ElfPatchKey<Platform>, Option<ElfPatchState>>;

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

impl<Platform: ShimPlatform> Task<Platform> {
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
    fn do_mmap_anonymous(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> Result<UserPtrMut<u8>, Errno> {
        let op = |_| Ok(0);
        self.do_mmap(suggested_addr, len, prot, flags, false, op)
            .map_err(Errno::from)
    }

    fn do_mmap_file(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
    ) -> Result<UserPtrMut<u8>, Errno> {
        let is_exec = prot.contains(ProtFlags::PROT_EXEC);
        let AnyTypedFd::Fs(typed_fd) = self.typed_fd(fd)? else {
            return Err(Errno::ENODEV);
        };

        // Perform the normal mmap first (CoW or memcpy fallback).
        let result = if let Some(cow_result) =
            self.try_cow_mmap_file(suggested_addr, len, prot, &flags, &typed_fd, offset)
        {
            cow_result?
        } else {
            self.do_mmap_file_memcpy(suggested_addr, len, prot, flags, &typed_fd, offset)?
        };

        // A zero entry point means the platform has no syscall rewriting.
        let syscall_entry = self.global.platform.get_syscall_entry_point();
        if syscall_entry == 0 {
            return Ok(result);
        }

        let patch_key = ElfPatchKey(typed_fd);
        // Runtime syscall rewriting: patch PROT_EXEC segments in-place.
        if is_exec {
            if let Err(e) =
                self.maybe_patch_exec_segment(result, len, &patch_key, syscall_entry, offset)
            {
                // The segment may still contain raw `syscall` instructions, or
                // (for a pre-patched binary) JMPs to a trampoline that was never
                // mapped. Either way, exposing it as executable is unsafe, so
                // fail the mmap instead.
                let _ = self.sys_munmap(result, len);
                return Err(e);
            }
            // The patcher leaves the segment read-execute, so a writable request
            // has to be re-applied. That drops the patch record: the guest can
            // now overwrite the rewritten code.
            if prot.contains(ProtFlags::PROT_WRITE) {
                if let Err(e) = self.sys_mprotect_raw(result, len, prot) {
                    let _ = self.sys_munmap(result, len);
                    return Err(e);
                }
                self.invalidate_patched_ranges(result.as_usize(), len);
            }
        } else {
            // Ensure patch state is initialized for this fd (no-op if already done).
            self.init_elf_patch_state(&patch_key, result.as_usize(), len, offset);
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
        prot: ProtFlags,
        flags: &MapFlags,
        fd: &FileFd<Platform>,
        offset: usize,
    ) -> Option<Result<UserPtrMut<u8>, MappingError>> {
        if !len.is_multiple_of(PAGE_SIZE) {
            return None;
        }

        let files = self.files.borrow();
        let static_data = files.fs.get_static_backing_data(fd)?;

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
        fd: &FileFd<Platform>,
        offset: usize,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        let op = |ptr: UserPtrMut<u8>| -> Result<usize, MappingError> {
            // Note a malicious user may unmap ptr while we are reading.
            // `sys_read` does not handle page faults, so we need to use a
            // temporary buffer to read the data from fs (without worrying page
            // faults) and write it to the user buffer with page fault handling.
            let files = self.files.borrow();
            let mut file_offset = offset;
            let mut buffer = [0; PAGE_SIZE];
            let mut copied = 0;
            while copied < len {
                let size =
                    files
                        .fs
                        .read(fd, &mut buffer, Some(file_offset))
                        .map_err(|e| match e {
                            // The raw fd was resolved once at syscall entry and is intentionally
                            // not retained; this payload is discarded when converted to EBADF.
                            ReadError::ClosedFd => MappingError::BadFD(-1),
                            ReadError::NotAFile => MappingError::NotAFile,
                            ReadError::NotForReading => MappingError::NotForReading,
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
    }

    /// Handle syscall `munmap`
    #[inline]
    pub(crate) fn sys_munmap(&self, addr: UserPtrMut<u8>, len: usize) -> Result<(), Errno> {
        let result = self.sys_munmap_raw(addr, len);
        if result.is_ok() {
            self.clear_file_mappings_for_range(addr.as_usize(), len);
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
    fn clear_file_mappings_for_range(&self, unmap_start: usize, unmap_len: usize) {
        let syscall_entry = self.global.platform.get_syscall_entry_point();
        if syscall_entry == 0 {
            return;
        }

        let unmap_end = unmap_start.saturating_add(unmap_len);
        let mut detached = alloc::vec::Vec::new();
        let mut cache = self.global.elf_patch_cache.lock();
        for (key, entry) in cache.iter_mut() {
            let Some(state) = entry else { continue };
            state.file_mappings.remove(unmap_start..unmap_end);
            state.patched_ranges.remove(unmap_start..unmap_end);
            if !state.file_mappings.is_empty() {
                continue;
            }
            if state.descriptor_closed {
                detached.push(key.clone());
            } else if state.trampoline_mapped && !state.pre_patched {
                // Nothing can reach the stubs now, so let the next patch overwrite them
                // instead of growing the trampoline on every map/unmap cycle.
                state.trampoline_cursor = TRAMPOLINE_ENTRY_SIZE;
            }
        }
        let stale_states: alloc::vec::Vec<_> = detached
            .into_iter()
            .filter_map(|key| cache.remove(&key).flatten())
            .collect();
        drop(cache);

        for state in stale_states {
            self.release_elf_patch_state(state);
        }
    }

    /// Forget that ranges overlapping `[start, start + len)` were patched.
    ///
    /// The rewriter leaves patched code read-execute, so the guest must request
    /// `PROT_WRITE` before it can modify it. Once it does, the patch no longer
    /// holds and the rewriter has to run again if the range becomes executable.
    fn invalidate_patched_ranges(&self, start: usize, len: usize) {
        if len == 0 {
            return;
        }
        let end = start.saturating_add(len);
        let mut cache = self.global.elf_patch_cache.lock();
        for state in cache.values_mut().flatten() {
            state.patched_ranges.remove(start..end);
        }
    }

    /// Handle syscall `mprotect`
    pub(crate) fn sys_mprotect(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        let syscall_entry = self.global.platform.get_syscall_entry_point();
        // If a tracked mapping cannot be patched we must not let it become executable.
        if syscall_entry != 0 && prot.contains(ProtFlags::PROT_EXEC) {
            self.maybe_patch_on_mprotect_exec(addr, len, syscall_entry)?;
        }
        self.sys_mprotect_raw(addr, len, prot)?;
        if syscall_entry != 0 && prot.contains(ProtFlags::PROT_WRITE) {
            self.invalidate_patched_ranges(addr.as_usize(), len);
        }
        Ok(())
    }

    /// Raw mprotect without exec interception — used internally by the
    /// patching logic to avoid deadlocks (the patch path holds elf_patch_cache).
    #[inline]
    fn sys_mprotect_raw(
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
    ) -> Result<(), Errno> {
        let mprotect_start = addr.as_usize();
        let mprotect_end = mprotect_start.saturating_add(len);

        // Held for the whole operation: releasing it between selecting and
        // patching would let a concurrent `close` drop the patch state and
        // leave unpatched code to become executable.
        let mut cache = self.global.elf_patch_cache.lock();

        // Find unpatched file mappings that overlap this mprotect range.
        let mut to_patch: alloc::vec::Vec<(ElfPatchKey<Platform>, usize, usize)> =
            alloc::vec::Vec::new();
        for (fd, state) in cache.iter() {
            let Some(state) = state else { continue };
            for segment in state.file_mappings.iter() {
                let seg_start = segment.start;
                let seg_end = segment.end;
                // Check overlap with the mprotect range.
                if seg_start < mprotect_end && seg_end > mprotect_start {
                    to_patch.push((fd.clone(), seg_start, seg_end - seg_start));
                }
            }
        }

        // A single mprotect range should only overlap mappings from one fd
        // (a given vaddr range is backed by at most one file at a time).
        if let Some(((first, _, _), rest)) = to_patch.split_first()
            && rest.iter().any(|(fd, _, _)| !Arc::ptr_eq(&fd.0, &first.0))
        {
            let ranges: alloc::vec::Vec<_> = to_patch
                .iter()
                .map(|&(_, seg_start, seg_len)| (seg_start, seg_len))
                .collect();
            litebox_util_log::warn!(
                addr:? = mprotect_start, len:? = len, ranges:? = ranges;
                "mprotect +EXEC range overlaps file mappings from multiple fds"
            );
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
            let Some(Some(state)) = cache.get_mut(&fd) else {
                continue;
            };
            let mapped_addr = UserPtrMut::<u8>::from_usize(patch_start);
            self.patch_exec_segment(mapped_addr, patch_len, state, syscall_entry)?;
        }
        Ok(())
    }

    /// Initialize ELF patch state for an fd on its first mmap and record the mapping.
    ///
    /// The mapping is recorded under the lock that publishes the state, so a concurrent
    /// `munmap` never sees a tracked ELF that momentarily owns no mappings.
    fn init_elf_patch_state(
        &self,
        fd: &ElfPatchKey<Platform>,
        mapped_addr: usize,
        len: usize,
        file_offset: usize,
    ) {
        let mut cache = self.global.elf_patch_cache.lock();
        if !cache.contains_key(fd) {
            // Probe outside the lock so header I/O does not serialize other mappings.
            drop(cache);
            let state = self.probe_elf_patch_state(&fd.0, mapped_addr, file_offset);
            cache = self.global.elf_patch_cache.lock();
            cache.entry(fd.clone()).or_insert(state);
        }
        if let Some(Some(state)) = cache.get_mut(fd) {
            state
                .file_mappings
                .insert(mapped_addr..mapped_addr.saturating_add(len));
        }
    }

    /// Read `fd`'s ELF headers and derive its patch state, or `None` if it is
    /// not an ELF image we patch.
    ///
    /// Reads the ELF header to determine the trampoline address (page-aligned
    /// end of the highest PT_LOAD segment) and checks the file tail for the
    /// trampoline magic to determine if it's pre-patched.
    ///
    /// For ET_DYN binaries (PIE/shared libs), virtual addresses in program
    /// headers are relative to a base address chosen at load time. We derive
    /// the base from the caller's mapping: `base = mapped_addr - p_vaddr` of
    /// the segment being mapped. The `file_offset` parameter identifies which
    /// segment is being mapped so we can look up its `p_vaddr`.
    ///
    /// x86_64 only: assumes 64-bit ELF layout and program header offsets.
    fn probe_elf_patch_state(
        &self,
        fd: &FileFd<Platform>,
        mapped_addr: usize,
        file_offset: usize,
    ) -> Option<ElfPatchState> {
        let files = self.files.borrow();

        // Read the ELF header (64 bytes for Elf64).
        let mut ehdr_buf = [0u8; core::mem::size_of::<FileHeader64<LittleEndian>>()];
        match files.fs.read(fd, &mut ehdr_buf, Some(0)) {
            Ok(n) if n == ehdr_buf.len() => {}
            _ => return None, // Not readable or short read, skip
        }

        // Parse as typed ELF64 header.
        let (ehdr, _) = object::from_bytes::<FileHeader64<LittleEndian>>(&ehdr_buf).ok()?;

        // Verify ELF magic
        if &ehdr.e_ident.magic != b"\x7fELF" {
            return None;
        }

        let e_type = ehdr.e_type.get(ENDIAN);
        let e_phoff: usize = ehdr.e_phoff.get(ENDIAN).trunc();
        let e_phentsize = ehdr.e_phentsize.get(ENDIAN) as usize;
        let e_phnum = ehdr.e_phnum.get(ENDIAN) as usize;

        // Validate e_phentsize: must be at least sizeof(Elf64_Phdr).
        if e_phentsize < core::mem::size_of::<ProgramHeader64<LittleEndian>>() {
            return None;
        }

        // Read program headers.
        let phdrs_size = e_phentsize.checked_mul(e_phnum)?;
        if phdrs_size == 0 || phdrs_size > 0x10000 {
            return None; // Sanity check
        }
        let mut phdrs_buf = alloc::vec![0u8; phdrs_size];
        match files.fs.read(fd, &mut phdrs_buf, Some(e_phoff)) {
            Ok(n) if n == phdrs_buf.len() => {}
            _ => return None,
        }

        // Find highest PT_LOAD end (p_vaddr + p_memsz) and compute base_addr
        // by matching the segment whose p_offset corresponds to file_offset.
        let mut max_load_end: u64 = 0;
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
            // Match segment by page-aligned file offset to derive base address.
            if base_addr.is_none()
                && align_down(p_offset, PAGE_SIZE) == align_down(file_offset, PAGE_SIZE)
            {
                base_addr = Some(mapped_addr.wrapping_sub(p_vaddr.trunc()));
            }
        }

        if max_load_end == 0 {
            return None; // No PT_LOAD segments
        }

        // Check if file is pre-patched by reading the last 32 bytes for magic
        let (pre_patched, tramp_file_offset, tramp_vaddr, tramp_file_size) =
            Self::check_trampoline_magic(&files, fd);
        let trampoline_data = if pre_patched && tramp_file_size > 0 {
            let trampoline_size: usize = tramp_file_size.try_into().ok()?;
            let trampoline_offset: usize = tramp_file_offset.try_into().ok()?;
            let mut data = alloc::vec![0u8; trampoline_size];
            match files.fs.read(fd, &mut data, Some(trampoline_offset)) {
                Ok(n) if n == data.len() => Some(data),
                _ => None,
            }
        } else {
            Some(alloc::vec::Vec::new())
        };

        // Compute the trampoline virtual address.
        // - Pre-patched: use the exact address from the trampoline header (the
        //   code already contains JMPs there, so we MUST map at this address).
        // - Unpatched: place it just past the highest PT_LOAD end (this is just
        //   a hint — validated by the ±2GB distance check with trap fallback).
        // For ET_DYN, virtual addresses are relative to the load base.
        let trampoline_vaddr = if pre_patched {
            if e_type == ET_DYN {
                let Some(base) = base_addr else {
                    litebox_util_log::warn!(
                        mapped_addr:? = mapped_addr, file_offset:? = file_offset;
                        "pre-patched ET_DYN binary but cannot determine load base address"
                    );
                    return None;
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
            let max_end: usize = max_load_end.trunc();
            base + max_end.next_multiple_of(PAGE_SIZE)
        };

        Some(ElfPatchState {
            pre_patched,
            trampoline_data,
            descriptor_closed: false,
            trampoline_addr: trampoline_vaddr,
            trampoline_cursor: 0,
            trampoline_mapped: false,
            trampoline_mapped_len: 0,
            file_mappings: RangeSet::new(),
            patched_ranges: RangeSet::new(),
        })
    }

    /// Check if a file has the LITEBOX trampoline magic at its tail.
    /// Returns (is_pre_patched, file_offset, vaddr, trampoline_size).
    fn check_trampoline_magic(
        files: &FilesState<Platform>,
        fd: &FileFd<Platform>,
    ) -> (bool, u64, u64, u64) {
        const HEADER_SIZE: usize = 32; // TrampolineHeader64: magic(8) + file_offset(8) + vaddr(8) + size(8)
        let Ok(stat) = files.fs.fd_file_status(fd) else {
            return (false, 0, 0, 0);
        };
        let file_size = stat.size;
        if file_size < HEADER_SIZE {
            return (false, 0, 0, 0);
        }
        let mut tail = [0u8; HEADER_SIZE];
        match files.fs.read(fd, &mut tail, Some(file_size - HEADER_SIZE)) {
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

    /// Apply the trap fallback to a mapped code segment: replace all `syscall`
    /// instructions with traps (`ICEBP;HLT`), then restore RX.
    ///
    /// If `already_rw` is true, the segment is assumed to already be writable
    /// and the initial mprotect RW is skipped.
    ///
    /// On any error the segment is left non-executable.
    fn apply_trap_fallback(
        &self,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        already_rw: bool,
    ) -> Result<(), Errno> {
        if !already_rw {
            self.sys_mprotect_raw(
                mapped_addr,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )?;
        }

        let result = self.trap_syscalls_in_place(mapped_addr, len);
        self.restore_rx_or_deny_exec(mapped_addr, len, result)
    }

    /// Rewrite every `syscall` instruction in an already-writable segment to a
    /// trap, using the rewriter's disassembler.
    fn trap_syscalls_in_place(&self, mapped_addr: UserPtrMut<u8>, len: usize) -> Result<(), Errno> {
        let code_owned = mapped_addr
            .to_owned_slice::<Platform>(len)
            .ok_or(Errno::EFAULT)?;
        let mut code_buf = code_owned.into_vec();
        let code_vaddr = mapped_addr.as_usize() as u64;
        let count = litebox_syscall_rewriter::trap_all_syscalls_in_code(&mut code_buf, code_vaddr)
            .map_err(|e| {
                litebox_util_log::warn!(
                    err:? = e, addr:? = mapped_addr.as_usize(), len:? = len;
                    "failed to disassemble code segment for trap fallback"
                );
                Errno::ENOEXEC
            })?;
        if count > 0 {
            litebox_util_log::warn!(
                count:? = count, addr:? = mapped_addr.as_usize(), len:? = len;
                "applied trap fallback to syscall instructions"
            );
        }
        mapped_addr
            .copy_from_slice::<Platform>(0, &code_buf)
            .ok_or(Errno::EFAULT)
    }

    /// Restore read-execute on a segment the patcher made writable.
    ///
    /// Patched code is never left writable: the guest must go through
    /// `mprotect(PROT_WRITE)` to modify it, which invalidates the patch so the
    /// rewriter runs again before the range can become executable.
    ///
    /// If `result` already failed, or the restore itself fails, the segment is
    /// forced to `PROT_READ` so a failed patch can never leave it executable.
    fn restore_rx_or_deny_exec(
        &self,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        result: Result<(), Errno>,
    ) -> Result<(), Errno> {
        let restore = match result {
            Ok(()) => self.sys_mprotect_raw(
                mapped_addr,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
            ),
            Err(e) => Err(e),
        };
        if let Err(e) = restore {
            let _ = self.sys_mprotect_raw(mapped_addr, len, ProtFlags::PROT_READ);
            return Err(e);
        }
        Ok(())
    }

    /// Patch an executable segment mapped by `mmap` from `fd`.
    ///
    /// Initializes patch state for the descriptor if this is its first mapping,
    /// then defers to [`Self::patch_exec_segment`].
    fn maybe_patch_exec_segment(
        &self,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        fd: &ElfPatchKey<Platform>,
        syscall_entry: usize,
        file_offset: usize,
    ) -> Result<(), Errno> {
        self.init_elf_patch_state(fd, mapped_addr.as_usize(), len, file_offset);

        // This lock guards the elf_patch_cache and is held for the entire
        // patching operation. In practice this is fine because the dynamic
        // linker loads shared libraries sequentially.
        let mut cache = self.global.elf_patch_cache.lock();
        let Some(Some(state)) = cache.get_mut(fd) else {
            return Ok(()); // No patch state — not an ELF we're tracking
        };
        self.patch_exec_segment(mapped_addr, len, state, syscall_entry)
    }

    /// Patch an executable segment in-place after it has been mapped.
    ///
    /// For pre-patched binaries: maps the trampoline from the file and writes
    /// the syscall entry point.
    /// For unpatched binaries: calls `patch_code_segment()` to rewrite syscall
    /// instructions and places the generated stubs in the trampoline region.
    ///
    /// Fails closed: any error leaves the segment non-executable and must be
    /// surfaced to the guest, because the code may still contain raw `syscall`
    /// instructions or JMPs to a trampoline that was never mapped.
    ///
    /// Must be called with the `elf_patch_cache` lock held (`state` is borrowed
    /// from it); only `_raw` mm helpers may be used from here.
    fn patch_exec_segment(
        &self,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        state: &mut ElfPatchState,
        syscall_entry: usize,
    ) -> Result<(), Errno> {
        if state.pre_patched {
            if state.trampoline_mapped {
                return Ok(());
            }
            // Pre-patched binary: map the trampoline data cached during probing.
            let tramp_data = state.trampoline_data.as_deref().ok_or(Errno::EIO)?;
            if tramp_data.is_empty() {
                return Ok(());
            }
            let tramp_addr = state.trampoline_addr;
            let tramp_len = align_up(tramp_data.len(), PAGE_SIZE);

            // Allocate RW region at the trampoline address. Use MAP_FIXED
            // because the code already contains JMPs to this exact address
            // and we MUST map here. The region may already be reserved as
            // PROT_NONE by the ElfLoader's reserve() call, which would
            // cause MAP_FIXED_NOREPLACE to fail with EEXIST.
            let alloc_ptr = self.do_mmap_anonymous(
                Some(tramp_addr),
                tramp_len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            )?;
            let actual_addr = alloc_ptr.as_usize();
            if actual_addr != tramp_addr {
                let _ = self.sys_munmap_raw(UserPtrMut::<u8>::from_usize(actual_addr), tramp_len);
                return Err(Errno::ENOMEM);
            }

            // Write the cached image, then stamp the syscall entry point over its first
            // word in place.
            let tramp_ptr = UserPtrMut::<u8>::from_usize(tramp_addr);
            let mut written = tramp_ptr
                .copy_from_slice::<Platform>(0, tramp_data)
                .is_some();
            if written && tramp_data.len() >= TRAMPOLINE_ENTRY_SIZE {
                written = tramp_ptr
                    .copy_from_slice::<Platform>(0, &syscall_entry.to_le_bytes())
                    .is_some();
            }
            if !written {
                let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
                return Err(Errno::EFAULT);
            }

            // Protect as RX immediately.
            if let Err(e) = self.sys_mprotect_raw(
                tramp_ptr,
                tramp_len,
                ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
            ) {
                let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
                return Err(e);
            }

            state.trampoline_mapped = true;
            state.trampoline_mapped_len = tramp_len;
            state.trampoline_data = None;
            return Ok(());
        }

        // ── Runtime patching path (unpatched binaries) ───────────────

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
                return self.apply_trap_fallback(mapped_addr, len, false);
            };
            let actual_addr = actual_addr_ptr.as_usize();

            // Verify the trampoline is within JMP rel32 range (+-2GB) of the
            // entire code segment, not just its start.
            let far_end = addr_usize.saturating_add(len);
            let distance = actual_addr
                .abs_diff(addr_usize)
                .max(actual_addr.abs_diff(far_end));
            if distance > 0x7FFF_0000 {
                litebox_util_log::warn!(
                    distance:? = distance;
                    "trampoline too far from code segment, skipping patching"
                );
                let _ = self.sys_munmap_raw(UserPtrMut::<u8>::from_usize(actual_addr), PAGE_SIZE);
                return self.apply_trap_fallback(mapped_addr, len, false);
            }

            state.trampoline_addr = actual_addr;

            // Write the 8-byte syscall entry point at the start.
            let entry_ptr = UserPtrMut::<u8>::from_usize(actual_addr);
            if entry_ptr
                .copy_from_slice::<Platform>(0, &syscall_entry.to_le_bytes())
                .is_none()
            {
                litebox_util_log::warn!("failed to write syscall entry point to trampoline");
                let _ = self.sys_munmap_raw(UserPtrMut::<u8>::from_usize(actual_addr), PAGE_SIZE);
                return self.apply_trap_fallback(mapped_addr, len, false);
            }
            state.trampoline_cursor = TRAMPOLINE_ENTRY_SIZE;
            state.trampoline_mapped = true;
            state.trampoline_mapped_len = PAGE_SIZE;
        }

        // Performance guard: skip if this exact range was already patched.
        let mapping_start = mapped_addr.as_usize();
        let mapping_range = mapping_start..mapping_start.saturating_add(len);
        if state.patched_ranges.gaps(&mapping_range).next().is_none() {
            return Ok(());
        }

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
            && let Err(e) = self.sys_mprotect_raw(
                UserPtrMut::<u8>::from_usize(state.trampoline_addr),
                state.trampoline_mapped_len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
        {
            litebox_util_log::warn!(err:? = e; "failed to mprotect trampoline to RW");
            return Err(e);
        }
        // Nothing has been modified yet, so failing here leaves the segment
        // exactly as the caller found it.
        if let Err(e) = self.sys_mprotect_raw(
            mapped_addr,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        ) {
            litebox_util_log::warn!(
                err:? = e, addr:? = addr_usize, len:? = len;
                "failed to mprotect code segment to RW for patching"
            );
            restore_trampoline_rx(self, state);
            return Err(e);
        }

        // Past this point the segment is writable, so every exit must go
        // through `restore_rx_or_deny_exec`.

        // Read the mapped code into a buffer, patch it, write back.
        let Some(code_owned) = mapped_addr.to_owned_slice::<Platform>(len) else {
            restore_trampoline_rx(self, state);
            return self.restore_rx_or_deny_exec(mapped_addr, len, Err(Errno::EFAULT));
        };
        let mut code_buf = code_owned.into_vec();
        let original_code = code_buf.clone();

        let code_vaddr = addr_usize as u64;
        let trampoline_write_vaddr = (state.trampoline_addr + state.trampoline_cursor) as u64;
        let syscall_entry_addr = state.trampoline_addr as u64;

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
        let outcome: Result<(), Errno> = match patch_result {
            Ok(stubs) if !stubs.is_empty() => {
                let Some(new_cursor) = state.trampoline_cursor.checked_add(stubs.len()) else {
                    litebox_util_log::warn!("trampoline cursor overflow");
                    restore_trampoline_rx(self, state);
                    return self.apply_trap_fallback(mapped_addr, len, true);
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
                        restore_trampoline_rx(self, state);
                        return self.apply_trap_fallback(mapped_addr, len, true);
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
                    litebox_util_log::warn!("failed to write trampoline stubs");
                    Err(Errno::EFAULT)
                } else if mapped_addr
                    .copy_from_slice::<Platform>(0, &code_buf)
                    .is_none()
                {
                    // Write patched code back to the mapped region.
                    litebox_util_log::warn!("failed to write patched code back to code segment");
                    let _ = mapped_addr.copy_from_slice::<Platform>(0, &original_code);
                    Err(Errno::EFAULT)
                } else {
                    state.trampoline_cursor = new_cursor;
                    Ok(())
                }
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
                    litebox_util_log::warn!("failed to write trap bytes back to code segment");
                    let _ = mapped_addr.copy_from_slice::<Platform>(0, &original_code);
                    Err(Errno::EFAULT)
                } else {
                    Ok(())
                }
            }
            Err(e) => {
                litebox_util_log::warn!(err:? = e; "patch_code_segment failed");
                restore_trampoline_rx(self, state);
                return self.apply_trap_fallback(mapped_addr, len, true);
            }
        };

        restore_trampoline_rx(self, state);
        // Only a committed patch may be skipped next time; marking a failed
        // attempt would let the guard above wave raw syscalls through to RX.
        if outcome.is_ok() {
            state.patched_ranges.insert(mapping_range);
        }
        self.restore_rx_or_deny_exec(mapped_addr, len, outcome)
    }

    /// Finalize the ELF patching state for `fd`.
    ///
    /// Detaches the descriptor from its patch state. Mapping-owned state remains
    /// available for deferred patching until its final mapping is unmapped.
    pub(crate) fn finalize_elf_patch(&self, fd: Arc<FileFd<Platform>>) {
        let syscall_entry = self.global.platform.get_syscall_entry_point();
        if syscall_entry == 0 {
            return;
        }

        let key = ElfPatchKey(fd);
        let state = {
            let mut cache = self.global.elf_patch_cache.lock();
            match cache.get_mut(&key) {
                Some(Some(state)) if !state.file_mappings.is_empty() => {
                    state.descriptor_closed = true;
                    None
                }
                Some(_) => cache.remove(&key).flatten(),
                None => None,
            }
        };
        if let Some(state) = state {
            self.release_elf_patch_state(state);
        }
    }

    fn release_elf_patch_state(&self, state: ElfPatchState) {
        if state.trampoline_mapped && state.trampoline_mapped_len > 0 {
            let _ = self.sys_munmap_raw(
                UserPtrMut::<u8>::from_usize(state.trampoline_addr),
                state.trampoline_mapped_len,
            );
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

    /// A minimal ET_DYN ELF64 image with a single `PT_LOAD` segment, padded to
    /// `len` bytes so that mapping it succeeds.
    fn minimal_elf(len: usize) -> alloc::vec::Vec<u8> {
        const EHDR_SIZE: u16 = 64;
        const PHDR_SIZE: u16 = 56;
        let ehdr_size = usize::from(EHDR_SIZE);
        let mut buf = alloc::vec![0u8; len];

        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // ELFDATA2LSB
        buf[6] = 1; // EV_CURRENT
        buf[16..18].copy_from_slice(&3u16.to_le_bytes()); // e_type = ET_DYN
        buf[18..20].copy_from_slice(&62u16.to_le_bytes()); // e_machine = EM_X86_64
        buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        buf[32..40].copy_from_slice(&u64::from(EHDR_SIZE).to_le_bytes()); // e_phoff
        buf[52..54].copy_from_slice(&EHDR_SIZE.to_le_bytes()); // e_ehsize
        buf[54..56].copy_from_slice(&PHDR_SIZE.to_le_bytes()); // e_phentsize
        buf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum

        let ph = &mut buf[ehdr_size..ehdr_size + usize::from(PHDR_SIZE)];
        ph[0..4].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        ph[4..8].copy_from_slice(&5u32.to_le_bytes()); // p_flags = R|X
        ph[32..40].copy_from_slice(&(len as u64).to_le_bytes()); // p_filesz
        ph[40..48].copy_from_slice(&(len as u64).to_le_bytes()); // p_memsz
        ph[48..56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align
        buf
    }

    fn minimal_pre_patched_elf() -> alloc::vec::Vec<u8> {
        const TRAMPOLINE_OFFSET: usize = 0x1000;
        const TRAMPOLINE_VADDR: u64 = 0x1000;
        const TRAMPOLINE_SIZE: usize = 8;

        let mut elf = minimal_elf(TRAMPOLINE_OFFSET);
        elf.extend_from_slice(&[0; TRAMPOLINE_SIZE]);
        elf.extend_from_slice(litebox_syscall_rewriter::TRAMPOLINE_MAGIC);
        elf.extend_from_slice(&(TRAMPOLINE_OFFSET as u64).to_le_bytes());
        elf.extend_from_slice(&TRAMPOLINE_VADDR.to_le_bytes());
        elf.extend_from_slice(&(TRAMPOLINE_SIZE as u64).to_le_bytes());
        elf
    }

    fn map_elf(name: &str, elf: &[u8], len: usize) -> (crate::Task<Platform>, i32, UserPtrMut<u8>) {
        let task = init_platform(None);
        let fd = i32::try_from(
            task.sys_open(name, OFlags::RDWR | OFlags::CREAT, Mode::RWXU)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(task.sys_write(fd, elf, None).unwrap(), elf.len());
        let addr = task
            .sys_mmap(0, len, ProtFlags::PROT_READ, MapFlags::MAP_PRIVATE, fd, 0)
            .unwrap();
        (task, fd, addr)
    }

    #[test]
    fn test_deferred_elf_patch_survives_close() {
        let elf = minimal_elf(0x1000);
        let (task, fd, addr) = map_elf("deferred.so", &elf, 0x1000);
        task.sys_close(fd).unwrap();

        {
            let cache = task.global.elf_patch_cache.lock();
            let state = cache.values().next().unwrap().as_ref().unwrap();
            assert!(state.descriptor_closed);
            assert!(
                state
                    .file_mappings
                    .gaps(&(addr.as_usize()..addr.as_usize() + 0x1000))
                    .next()
                    .is_none()
            );
        }

        task.sys_mprotect(addr, 0x1000, ProtFlags::PROT_READ_EXEC)
            .unwrap();
        {
            let cache = task.global.elf_patch_cache.lock();
            let state = cache.values().next().unwrap().as_ref().unwrap();
            assert!(
                state
                    .patched_ranges
                    .gaps(&(addr.as_usize()..addr.as_usize() + 0x1000))
                    .next()
                    .is_none()
            );
        }

        task.sys_munmap(addr, 0x1000).unwrap();
        assert!(task.global.elf_patch_cache.lock().is_empty());
    }

    #[test]
    fn test_deferred_pre_patched_trampoline_survives_close() {
        let elf = minimal_pre_patched_elf();
        let (task, fd, addr) = map_elf("pre-patched.so", &elf, 0x1000);
        task.sys_close(fd).unwrap();
        task.sys_mprotect(addr, 0x1000, ProtFlags::PROT_READ_EXEC)
            .unwrap();

        {
            let cache = task.global.elf_patch_cache.lock();
            let state = cache.values().next().unwrap().as_ref().unwrap();
            assert!(state.pre_patched);
            assert!(state.trampoline_mapped);
            // Mapping the trampoline releases the copy cached at probe time.
            assert!(state.trampoline_data.is_none());
        }

        task.sys_munmap(addr, 0x1000).unwrap();
        assert!(task.global.elf_patch_cache.lock().is_empty());
    }

    #[test]
    fn test_deferred_elf_state_survives_partial_unmap() {
        let elf = minimal_elf(0x2000);
        let (task, fd, addr) = map_elf("partial.so", &elf, 0x2000);
        task.sys_close(fd).unwrap();
        task.sys_munmap(addr, 0x1000).unwrap();

        {
            let cache = task.global.elf_patch_cache.lock();
            let state = cache.values().next().unwrap().as_ref().unwrap();
            let mappings = state.file_mappings.iter().collect::<alloc::vec::Vec<_>>();
            assert_eq!(mappings.len(), 1);
            assert_eq!(
                mappings[0],
                &(addr.as_usize() + 0x1000..addr.as_usize() + 0x2000)
            );
        }

        task.sys_munmap(UserPtrMut::from_usize(addr.as_usize() + 0x1000), 0x1000)
            .unwrap();
        assert!(task.global.elf_patch_cache.lock().is_empty());
    }

    /// Losing the last mapping of a still-open descriptor must rewind the trampoline,
    /// so repeated map/unmap cycles cannot grow it without bound.
    #[test]
    fn test_trampoline_rewinds_when_last_mapping_goes_away() {
        let elf = minimal_elf(0x1000);
        let (task, fd, addr) = map_elf("rewind.so", &elf, 0x1000);
        task.sys_mprotect(addr, 0x1000, ProtFlags::PROT_READ_EXEC)
            .unwrap();

        {
            let mut cache = task.global.elf_patch_cache.lock();
            let state = cache.values_mut().next().unwrap().as_mut().unwrap();
            assert!(state.trampoline_mapped);
            // Stand in for stubs the rewriter would have emitted.
            state.trampoline_cursor += 0x40;
        }

        task.sys_munmap(addr, 0x1000).unwrap();
        {
            let cache = task.global.elf_patch_cache.lock();
            let state = cache.values().next().unwrap().as_ref().unwrap();
            assert!(state.file_mappings.is_empty());
            assert_eq!(state.trampoline_cursor, super::TRAMPOLINE_ENTRY_SIZE);
        }

        task.sys_close(fd).unwrap();
        assert!(task.global.elf_patch_cache.lock().is_empty());
    }

    /// Closing a descriptor must drop its ELF patch state, so that a later
    /// descriptor reusing the same fd number does not inherit it.
    #[test]
    fn test_elf_patch_state_not_reused_across_fd_reuse() {
        let elf = minimal_elf(0x1000);
        let (task, elf_fd, addr) = map_elf("lib.so", &elf, 0x1000);

        // The ELF was recognized and the mapping is tracked for deferred patching.
        {
            let cache = task.global.elf_patch_cache.lock();
            assert_eq!(cache.len(), 1);
            let state = cache.values().next().unwrap().as_ref().unwrap();
            assert!(
                state
                    .file_mappings
                    .gaps(&(addr.as_usize()..addr.as_usize() + 0x1000))
                    .next()
                    .is_none()
            );
        }

        task.sys_munmap(addr, 0x1000).unwrap();
        task.sys_close(elf_fd).unwrap();
        assert!(
            task.global.elf_patch_cache.lock().is_empty(),
            "closing the descriptor must drop its patch state"
        );

        // Reopen so the same raw fd number is handed out again, this time for a
        // file that is not an ELF image.
        let plain_fd = i32::try_from(
            task.sys_open("plain.bin", OFlags::RDWR | OFlags::CREAT, Mode::RWXU)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(plain_fd, elf_fd, "expected the fd number to be reused");
        assert_eq!(
            task.sys_write(plain_fd, &[0xab; 0x1000], None).unwrap(),
            0x1000
        );

        let addr = task
            .sys_mmap(
                0,
                0x1000,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                plain_fd,
                0,
            )
            .unwrap();

        // Negative cache entry: probed once, not an ELF, no state inherited.
        {
            let cache = task.global.elf_patch_cache.lock();
            assert_eq!(cache.len(), 1);
            assert!(cache.values().next().unwrap().is_none());
        }

        task.sys_munmap(addr, 0x1000).unwrap();
        task.sys_close(plain_fd).unwrap();
    }

    #[test]
    fn test_anonymous_mmap() {
        let task = init_platform(None);

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
        let task = init_platform(None);

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
        let task = init_platform(None);

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
        let task = init_platform(None);

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
        let task = init_platform(None);
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
        let task = init_platform(None);

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
        let task = init_platform(None);

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
        let task = init_platform(None);

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
        let task = init_platform(None);

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
        let _ = init_platform(None);

        let ptr = UserPtrMut::<u8>::from_usize(0xdeadbeef);
        let result = ptr.read_at_offset::<Platform>(0);
        assert!(result.is_none());
    }
}
