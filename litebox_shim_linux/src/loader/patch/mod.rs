// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runtime ELF syscall patching.
//!
//! Executable file mappings are rewritten in place so that syscall
//! instructions jump to a per-file trampoline that enters LiteBox. Pre-patched
//! binaries carry their trampoline in the file; for unpatched binaries the
//! trampoline is generated at runtime, falling back to traps when it cannot
//! be placed within branch reach. Architecture specifics live in the `x86_64`
//! and `aarch64` submodules.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use core::ops::Range;
use litebox_common_linux::{
    MapFlags, ProtFlags,
    errno::Errno,
    loader::{
        TRAMPOLINE_HEADER_SIZE, TrampolineHeaderError, TrampolineLayout, parse_trampoline_header,
    },
    mm::MmapPlacement,
    vmem::PAGE_SIZE,
};
use litebox_syscall_rewriter::trampoline_allocation_range;

use crate::ShimPlatform;
use crate::Task;
use crate::UserPtrMut;
use crate::syscalls::file::{File, FileFd};
use crate::syscalls::mm::prot_flags_from_permissions;
use litebox::utils::TruncateExt as _;
use litebox_common_linux::vmem::VmFlags;
use object::elf::{ET_DYN, FileHeader64, PT_LOAD, ProgramHeader64};
use object::endian::LittleEndian;
use rangemap::RangeSet;

// Architecture-specific parts of runtime ELF patching. Each module provides
// the same interface, consumed below through `arch`.
#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
use aarch64 as arch;
#[cfg(target_arch = "x86_64")]
use x86_64 as arch;

#[cfg(not(target_pointer_width = "64"))]
compile_error!("ELF patching code assumes 64-bit pointers (u64 <-> usize is lossless)");

const ENDIAN: LittleEndian = LittleEndian;

type ProtectionRange = (usize, usize, ProtFlags);
type PatchRange<Platform> = (
    ElfPatchKey<Platform>,
    usize,
    usize,
    alloc::vec::Vec<ProtectionRange>,
);

/// Outcome of initializing [`ElfPatchState`] for a file mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ElfPatchInit {
    /// Patch state was cached for the file by this mapping.
    Ready,
    /// Patch state was already cached by a concurrent mapping of the same file.
    AlreadyTracked,
    /// The file is not a patchable ELF; nothing is cached.
    Untracked,
    /// The file is a pre-patched `ET_DYN`, but this mapping does not reveal its load base.
    MissingLoadBase,
    /// The file carries malformed ELF or LiteBox trampoline metadata.
    Malformed,
}

/// ELF patch metadata that does not depend on the mapping address.
struct ElfPatchMetadata {
    e_type: u16,
    mapping_vaddr: Option<usize>,
    load_span: Range<usize>,
    trampoline_layout: Option<TrampolineLayout>,
    arch: arch::ArchPatchState,
    trampoline_capacity: usize,
}

impl ElfPatchMetadata {
    /// Extra extent relative to the first mapping, only for a pre-patched
    /// `ET_DYN` whose fixed trampoline extends past the requested pages.
    fn pre_patched_trampoline_extent(&self, len: usize) -> Result<Option<Range<usize>>, Errno> {
        if self.e_type != ET_DYN {
            return Ok(None);
        }
        let Some(layout) = self
            .trampoline_layout
            .as_ref()
            .filter(|layout| layout.size > 0)
        else {
            return Ok(None);
        };
        let Some(start) = self
            .mapping_vaddr
            .and_then(|vaddr| layout.vaddr.checked_sub(vaddr))
        else {
            return Ok(None);
        };
        let end = start
            .checked_add(layout.size)
            .and_then(|end| end.checked_next_multiple_of(PAGE_SIZE))
            .ok_or(Errno::ENOMEM)?;
        Ok((end > len).then_some(start..end))
    }
}

/// Per-descriptor state for the shim's runtime ELF syscall rewriter.
///
/// Tracks base address and trampoline write cursor for each ELF file that
/// has executable segments mapped via `do_mmap_file()`.
pub(crate) struct ElfPatchState {
    /// Whether this file is already pre-patched (trampoline magic found at file tail).
    pre_patched: bool,
    /// For pre-patched binaries: file offset and size of the trampoline data.
    trampoline_file_offset: u64,
    trampoline_file_size: usize,
    /// Inaccessible pages owned until a pre-patched trampoline is populated.
    pre_patched_trampoline_reservation: Option<Range<usize>>,
    /// Actual trampoline address, or the required address for pre-patched code.
    trampoline_addr: usize,
    /// Page-aligned guest address span enclosing all PT_LOAD segments, including gaps.
    /// `None` means the load base is unknown.
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
    /// Architecture-specific patch state.
    arch: arch::ArchPatchState,
    /// Pre-scanned, page-aligned trampoline capacity.
    trampoline_capacity: usize,
    /// Tracks the address coverage of file-backed mappings for this fd.
    /// Used to find mappings that need patching when mprotect adds PROT_EXEC.
    /// Cleared on munmap to allow re-patching.
    file_mappings: RangeSet<usize>,
    /// Ranges that have already been patched by the runtime rewriter.
    /// This is a performance guard only — re-running the rewriter on
    /// already-patched code is safe because the second run will not see
    /// syscall instructions. Cleared on munmap alongside file_mappings.
    patched_ranges: BTreeSet<(usize, usize)>,
}

/// Identity of a resolved filesystem descriptor.
pub(crate) struct ElfPatchKey<Platform: ShimPlatform>(pub(crate) Arc<FileFd<Platform>>);

impl<Platform: ShimPlatform> core::fmt::Debug for ElfPatchKey<Platform> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("ElfPatchKey")
            .field(&Arc::as_ptr(&self.0))
            .finish()
    }
}

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
/// TODO: Deferred patching currently assumes the descriptor remains open until its
/// mappings gain `PROT_EXEC`. Closing the descriptor removes its entry even if
/// mappings survive, so `mmap -> close -> mprotect(PROT_EXEC)` can skip patching.
/// Supporting that sequence requires patch state to follow mapping lifetime,
/// independently of descriptor lifetime.
pub(crate) type ElfPatchCache<Platform> = BTreeMap<ElfPatchKey<Platform>, ElfPatchState>;

/// Fills `data` from `file` at `offset`, failing with `EIO` at end of file.
fn read_file_exact_at<Platform: ShimPlatform>(
    file: &File<Platform>,
    mut data: &mut [u8],
    mut offset: usize,
) -> Result<(), Errno> {
    while !data.is_empty() {
        let read = file.read(data, Some(offset), None)?;
        if read == 0 {
            return Err(Errno::EIO);
        }
        offset = offset.checked_add(read).ok_or(Errno::EOVERFLOW)?;
        data = &mut data[read..];
    }
    Ok(())
}

/// Reads the LiteBox trampoline header at the file tail.
/// Returns `Ok(None)` if the file is unreadable or carries no LiteBox header.
fn read_trampoline_layout<Platform: ShimPlatform>(
    file: &File<Platform>,
) -> Result<Option<TrampolineLayout>, TrampolineHeaderError> {
    let Ok(stat) = file.status() else {
        return Ok(None);
    };
    let Some(header_offset) = stat.size.checked_sub(TRAMPOLINE_HEADER_SIZE as u64) else {
        return Ok(None);
    };
    let Ok(read_offset) = usize::try_from(header_offset) else {
        return Ok(None);
    };

    let mut tail = [0u8; TRAMPOLINE_HEADER_SIZE];
    match file.read(&mut tail, Some(read_offset), None) {
        Ok(n) if n == TRAMPOLINE_HEADER_SIZE => {}
        _ => return Ok(None),
    }
    parse_trampoline_header(&tail, header_offset)
}

/// Patching work for one file mapping, started by
/// [`Task::begin_file_patch`] before the file is mapped and finished by
/// [`Task::complete_file_patch`] (or [`Task::abort_file_patch`]) afterwards.
#[must_use]
pub(crate) struct PendingFilePatch<Platform: ShimPlatform> {
    key: ElfPatchKey<Platform>,
    /// Platform syscall entry point; zero disables rewriting.
    syscall_entry: usize,
    len: usize,
    prot: ProtFlags,
    offset: usize,
    /// Metadata read by the first mapping of an untracked file.
    metadata: Option<Result<ElfPatchMetadata, ElfPatchInit>>,
    /// Extent, relative to the mapping start, of a pre-patched trampoline that
    /// extends past the mapping.
    trampoline_extent: Option<Range<usize>>,
    /// Inaccessible pages reserved for the mapping plus `trampoline_extent`.
    reservation: Option<UserPtrMut<u8>>,
    /// Whether completing this mapping cached the patch state, rather than a
    /// concurrent mapping of the same file.
    inserted: bool,
}

impl<Platform: ShimPlatform> PendingFilePatch<Platform> {
    /// Returns where and how to map the file: inside the reservation, if any.
    pub(crate) fn placement(
        &self,
        suggested_addr: Option<usize>,
        flags: MapFlags,
    ) -> (Option<usize>, MapFlags) {
        match self.reservation {
            Some(reservation) => (Some(reservation.as_usize()), flags | MapFlags::MAP_FIXED),
            None => (suggested_addr, flags),
        }
    }

    /// Length of the reservation, or of the mapping alone without one.
    fn allocation_len(&self) -> usize {
        self.trampoline_extent
            .as_ref()
            .map_or(self.len, |extent| extent.end)
    }
}

/// How [`Task::rewrite_into_trampoline`] left a code segment.
enum RewriteOutcome {
    /// The segment was rewritten (or needed no changes).
    Done,
    /// The segment is unchanged; patch sites must be replaced with traps.
    TrapFallback,
}

#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

impl<Platform: ShimPlatform> Task<Platform> {
    #[inline]
    fn do_mmap_trampoline(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        allowed_range: Option<Range<usize>>,
    ) -> Result<UserPtrMut<u8>, Errno> {
        self.global
            .mm
            .do_mmap(
                suggested_addr,
                len,
                prot,
                flags,
                MmapPlacement {
                    direction: litebox::platform::page_mgmt::AllocationDirection::TopDown,
                    allowed_range,
                },
                |_| Ok(0),
            )
            .map_err(Errno::from)
    }

    /// Clear `file_mappings` entries for any segments that overlap the
    /// unmapped range, so that re-mapping the same file region will be
    /// re-patched instead of skipped.
    pub(crate) fn clear_file_mappings_for_range(&self, unmap_start: usize, unmap_len: usize) {
        let unmap_end = unmap_start.saturating_add(unmap_len);
        let mut cache = self.global.elf_patch_cache.lock();
        for state in cache.values_mut() {
            arch::forget_unmapped_trampoline(state, &(unmap_start..unmap_end));
            state.file_mappings.remove(unmap_start..unmap_end);
            if state
                .pre_patched_trampoline_reservation
                .as_ref()
                .is_some_and(|reserved| reserved.start < unmap_end && unmap_start < reserved.end)
            {
                // The pages were released or replaced; never unmap them on close.
                state.pre_patched_trampoline_reservation = None;
            }
            state.patched_ranges.retain(|&(vaddr, seg_len)| {
                let seg_end = vaddr.saturating_add(seg_len);
                seg_end <= unmap_start || vaddr >= unmap_end
            });
        }
    }

    fn restore_page_permissions(&self, protections: &[ProtectionRange]) -> Result<(), Errno> {
        let mut first_error = None;
        for (start, len, prot) in protections {
            if let Err(error) =
                self.sys_mprotect_raw(UserPtrMut::<u8>::from_usize(*start), *len, *prot)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Prepares to patch a `len`-byte mapping of `file` at `offset`.
    ///
    /// Reads patch metadata on the first mapping of a file. If a pre-patched
    /// trampoline must lie past the mapping, reserves room for both so the
    /// mapping lands where its trampoline can be placed; map the file at
    /// [`PendingFilePatch::placement`].
    pub(crate) fn begin_file_patch(
        &self,
        file: &Arc<FileFd<Platform>>,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        offset: usize,
    ) -> Result<PendingFilePatch<Platform>, Errno> {
        let key = ElfPatchKey(Arc::clone(file));
        let syscall_entry = self.global.platform.get_syscall_entry_point();
        let metadata = if (syscall_entry != 0 || !prot.contains(ProtFlags::PROT_EXEC))
            && !self.global.elf_patch_cache.lock().contains_key(&key)
        {
            Some(
                self.global
                    .with_file(file, |file| Ok(Self::read_elf_patch_metadata(file, offset)))
                    .unwrap_or(Err(ElfPatchInit::Untracked)),
            )
        } else {
            None
        };
        let trampoline_extent = if syscall_entry != 0
            && !flags.intersects(MapFlags::MAP_FIXED | MapFlags::MAP_FIXED_NOREPLACE)
        {
            metadata
                .as_ref()
                .and_then(|metadata| metadata.as_ref().ok())
                .map_or(Ok(None), |metadata| {
                    metadata.pre_patched_trampoline_extent(len)
                })
                .inspect_err(|error| {
                    litebox_util_log::warn!(
                        error:? = error, fd:? = key, offset:? = offset;
                        "failed to determine pre-patched ELF placement"
                    );
                })?
        } else {
            None
        };
        let mut pending = PendingFilePatch {
            key,
            syscall_entry,
            len,
            prot,
            offset,
            metadata,
            trampoline_extent,
            reservation: None,
            inserted: false,
        };
        if pending.trampoline_extent.is_some() {
            pending.reservation = Some(
                self.do_mmap(
                    suggested_addr,
                    pending.allocation_len(),
                    ProtFlags::PROT_NONE,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
                    |_| Ok(0),
                )
                .map_err(Errno::from)?,
            );
        }
        Ok(pending)
    }

    /// Releases the reservation of a patch whose file mapping failed.
    pub(crate) fn abort_file_patch(&self, pending: PendingFilePatch<Platform>) {
        if let Some(reservation) = pending.reservation
            && let Err(error) = self.sys_munmap_raw(reservation, pending.allocation_len())
        {
            litebox_util_log::warn!(
                error:? = error;
                "failed to release pre-patched ELF reservation"
            );
        }
    }

    /// Patches or tracks the file mapping at `mapped`, then trims any unused
    /// reservation.
    ///
    /// On failure, releases the mapping and its reservation.
    pub(crate) fn complete_file_patch(
        &self,
        mut pending: PendingFilePatch<Platform>,
        mapped: UserPtrMut<u8>,
    ) -> Result<(), Errno> {
        let result = self.try_complete_file_patch(&mut pending, mapped);
        if result.is_err() {
            // A failed first mapping must not retain its provisional load base.
            if pending.inserted && pending.reservation.is_some() {
                self.global.elf_patch_cache.lock().remove(&pending.key);
            }
            if let Err(error) = self.sys_munmap(mapped, pending.allocation_len()) {
                litebox_util_log::warn!(
                    error:? = error;
                    "failed to release a failed file mapping"
                );
            }
        }
        result
    }

    fn try_complete_file_patch(
        &self,
        pending: &mut PendingFilePatch<Platform>,
        mapped: UserPtrMut<u8>,
    ) -> Result<(), Errno> {
        let key = &pending.key;
        let len = pending.len;
        let is_exec = pending.prot.contains(ProtFlags::PROT_EXEC);
        if let Some(metadata) = pending.metadata.take() {
            let init = match metadata {
                Ok(metadata) => self.init_elf_patch_state(key, mapped.as_usize(), metadata),
                Err(init) => init,
            };
            pending.inserted = init == ElfPatchInit::Ready;
            // A missing load base is not fatal for a non-executable mapping:
            // a later mapping may reveal it.
            if init == ElfPatchInit::Malformed || (is_exec && init == ElfPatchInit::MissingLoadBase)
            {
                return Err(Errno::ENOMEM);
            }
        }
        if is_exec {
            // Runtime syscall rewriting: patch PROT_EXEC segments in-place.
            if pending.syscall_entry != 0 {
                let restore_protections = [(mapped.as_usize(), len, pending.prot)];
                self.maybe_patch_exec_segment(
                    mapped,
                    len,
                    key,
                    pending.syscall_entry,
                    Some(pending.offset),
                    &restore_protections,
                )
                .map_err(|_| Errno::ENOMEM)?;
            }
        } else if let Some(state) = self.global.elf_patch_cache.lock().get_mut(key) {
            // Track non-exec file mappings so we can patch them if they later
            // gain PROT_EXEC via mprotect.
            state
                .file_mappings
                .insert(mapped.as_usize()..mapped.as_usize() + len);
        }
        // | <------------- Reservation -----------------> |
        // | mapped file | unused reservation | trampoline |
        // Clean up any excessive reservation beyond the mapped length.
        if let Some(extent) = &pending.trampoline_extent {
            let tail_start = len.max(extent.start);
            if tail_start > len {
                self.sys_munmap_raw(
                    UserPtrMut::from_usize(mapped.as_usize() + len),
                    tail_start - len,
                )?;
            }
            let unused = mapped.as_usize() + tail_start..mapped.as_usize() + extent.end;
            self.retain_pre_patched_reservation(key, unused, pending.inserted)?;
        }
        Ok(())
    }

    /// Keeps `unused`, the reserved pages of a not-yet-populated pre-patched
    /// trampoline, until the trampoline is mapped or the file is closed.
    ///
    /// If a concurrent mapping cached the patch state (`inserted` is false),
    /// its trampoline lies elsewhere and `unused` is released immediately.
    fn retain_pre_patched_reservation(
        &self,
        fd: &ElfPatchKey<Platform>,
        unused: Range<usize>,
        inserted: bool,
    ) -> Result<(), Errno> {
        let mut cache = self.global.elf_patch_cache.lock();
        let Some(state) = cache.get_mut(fd).filter(|state| state.pre_patched) else {
            litebox_util_log::warn!("pre-patched ELF changed during mapping");
            return Err(Errno::ENOMEM);
        };
        if !inserted {
            drop(cache);
            self.sys_munmap_raw(UserPtrMut::from_usize(unused.start), unused.len())?;
        } else if !state.trampoline_mapped {
            state.pre_patched_trampoline_reservation = Some(unused);
        }
        Ok(())
    }

    /// Check all tracked file mappings for unpatched regions that overlap the
    /// mprotect range. If found, run the runtime rewriter before the region
    /// becomes executable.
    pub(crate) fn maybe_patch_on_mprotect_exec(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        syscall_entry: usize,
    ) -> Result<(), Errno> {
        if len == 0 {
            return Ok(());
        }
        let mprotect_start = addr.as_usize();
        let mprotect_end = mprotect_start.saturating_add(len);

        // Find unpatched file mappings that overlap this mprotect range, and
        // record each underlying mapping's protection for restoration. A
        // segment is patched as a whole, so instructions spanning mappings are
        // not split; if part of it is unmapped, making it writable fails and
        // the mprotect is rejected, as it would be anyway.
        let to_patch: alloc::vec::Vec<PatchRange<Platform>> = {
            let cache = self.global.elf_patch_cache.lock();
            let mut result = alloc::vec::Vec::new();
            for (fd, state) in cache.iter() {
                if state.pre_patched && !arch::PATCH_PRE_PATCHED_ON_MPROTECT_EXEC {
                    continue;
                }
                for segment in state
                    .file_mappings
                    .overlapping(mprotect_start..mprotect_end)
                {
                    let patch_start = segment.start.max(mprotect_start);
                    let patch_end = segment.end.min(mprotect_end);
                    let restore_protections: alloc::vec::Vec<ProtectionRange> = self
                        .global
                        .mm
                        .overlapping(patch_start..patch_end)
                        .into_iter()
                        .map(|(mapping, flags)| {
                            let start = patch_start.max(mapping.start);
                            let end = patch_end.min(mapping.end);
                            (
                                start,
                                end - start,
                                prot_flags_from_permissions(flags.into()),
                            )
                        })
                        .collect();
                    // Nothing of a fully unmapped segment is left to patch, and
                    // the mprotect itself will fail.
                    if restore_protections.is_empty() {
                        continue;
                    }
                    result.push((
                        fd.clone(),
                        patch_start,
                        patch_end - patch_start,
                        restore_protections,
                    ));
                }
            }
            result
        };

        // A single mprotect range should only overlap mappings from one fd
        // (a given vaddr range is backed by at most one file at a time).
        if to_patch.len() > 1 {
            let fds: BTreeSet<_> = to_patch
                .iter()
                .map(|(fd, _, _, _)| Arc::as_ptr(&fd.0) as usize)
                .collect();
            if fds.len() > 1 {
                litebox_util_log::warn!(
                    addr:? = mprotect_start, len:? = len, count:? = fds.len();
                    "mprotect +EXEC range overlaps file mappings from multiple fds"
                );
            }
        }

        for (fd, patch_start, patch_len, restore_protections) in to_patch {
            let mapped_addr = UserPtrMut::<u8>::from_usize(patch_start);
            self.maybe_patch_exec_segment(
                mapped_addr,
                patch_len,
                &fd,
                syscall_entry,
                None,
                &restore_protections,
            )?;
        }
        Ok(())
    }

    /// Read address-independent ELF patch metadata for a file on its first mmap.
    ///
    /// Derives patch state and the architecture-specific trampoline fallback.
    ///
    /// The `file_offset` parameter identifies the segment being mapped so its
    /// virtual address can later establish the ET_DYN load base.
    ///
    /// Requires the supported architectures' common 64-bit ELF layout.
    fn read_elf_patch_metadata(
        file: &File<Platform>,
        file_offset: usize,
    ) -> Result<ElfPatchMetadata, ElfPatchInit> {
        // Read the ELF header (64 bytes for Elf64).
        let mut ehdr_buf = [0u8; core::mem::size_of::<FileHeader64<LittleEndian>>()];
        match file.read(&mut ehdr_buf, Some(0), None) {
            Ok(n) if n == ehdr_buf.len() => {}
            _ => return Err(ElfPatchInit::Untracked), // Not readable or short read, skip
        }

        // Parse as typed ELF64 header.
        let Ok((ehdr, _)) = object::from_bytes::<FileHeader64<LittleEndian>>(&ehdr_buf) else {
            return Err(ElfPatchInit::Untracked);
        };

        // Verify ELF magic
        if &ehdr.e_ident.magic != b"\x7fELF" {
            return Err(ElfPatchInit::Untracked);
        }

        let e_type = ehdr.e_type.get(ENDIAN);
        let e_phoff: usize = ehdr.e_phoff.get(ENDIAN).trunc();
        let e_phentsize = ehdr.e_phentsize.get(ENDIAN) as usize;
        let e_phnum = ehdr.e_phnum.get(ENDIAN) as usize;

        // Validate e_phentsize: must be at least sizeof(Elf64_Phdr).
        if e_phentsize < core::mem::size_of::<ProgramHeader64<LittleEndian>>() {
            return Err(ElfPatchInit::Untracked);
        }

        // Read program headers.
        let Some(phdrs_size) = e_phentsize.checked_mul(e_phnum) else {
            return Err(ElfPatchInit::Untracked);
        };
        if phdrs_size == 0 || phdrs_size > 0x10000 {
            return Err(ElfPatchInit::Untracked); // Sanity check
        }
        let mut phdrs_buf = alloc::vec![0u8; phdrs_size];
        match file.read(&mut phdrs_buf, Some(e_phoff), None) {
            Ok(n) if n == phdrs_buf.len() => {}
            _ => return Err(ElfPatchInit::Untracked),
        }

        // Compute the complete load span and identify the mapped segment.
        let mut max_load_end: u64 = 0;
        let mut min_load_start: u64 = u64::MAX;
        let mut mapping_vaddr = None;
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
                    "PT_LOAD p_vaddr + p_memsz overflow"
                );
                return Err(ElfPatchInit::Malformed);
            };
            if end > max_load_end {
                max_load_end = end;
            }
            min_load_start = min_load_start.min(align_down(p_vaddr.trunc(), PAGE_SIZE) as u64);
            // Match segment by page-aligned file offset to derive the ET_DYN load base.
            if e_type == ET_DYN
                && mapping_vaddr.is_none()
                && align_down(p_offset, PAGE_SIZE) == align_down(file_offset, PAGE_SIZE)
            {
                mapping_vaddr = Some(align_down(p_vaddr.trunc(), PAGE_SIZE));
            }
        }

        if max_load_end == 0 {
            return Err(ElfPatchInit::Untracked); // No PT_LOAD segments
        }

        let trampoline_layout = match read_trampoline_layout(file) {
            Err(error) => {
                litebox_util_log::debug!(
                    file_offset:? = file_offset, error:? = error;
                    "malformed LiteBox trampoline"
                );
                return Err(ElfPatchInit::Malformed);
            }
            Ok(layout) => layout,
        };

        let (arch, trampoline_capacity) = if trampoline_layout.is_some() {
            // Pre-patched files carry their own trampoline.
            (arch::ArchPatchState::default(), 0)
        } else {
            Self::plan_runtime_trampoline(file)
        };
        let min_load_start: usize = min_load_start.trunc();
        let max_load_end: usize = max_load_end.trunc();
        let Some(load_end) = max_load_end.checked_next_multiple_of(PAGE_SIZE) else {
            return Err(ElfPatchInit::Malformed);
        };
        Ok(ElfPatchMetadata {
            e_type,
            mapping_vaddr,
            load_span: min_load_start..load_end,
            trampoline_layout,
            arch,
            trampoline_capacity,
        })
    }

    /// Relocate parsed ELF metadata and cache patch state after mapping succeeds.
    fn init_elf_patch_state(
        &self,
        fd: &ElfPatchKey<Platform>,
        mapped_addr: usize,
        metadata: ElfPatchMetadata,
    ) -> ElfPatchInit {
        let mut cache = self.global.elf_patch_cache.lock();
        if cache.contains_key(fd) {
            return ElfPatchInit::AlreadyTracked;
        }
        let ElfPatchMetadata {
            e_type,
            mapping_vaddr,
            load_span,
            trampoline_layout,
            arch,
            trampoline_capacity,
        } = metadata;
        let relocation_offset = mapping_vaddr.map(|vaddr| mapped_addr.wrapping_sub(vaddr));
        // Compute the trampoline virtual address.
        // - Pre-patched: use the exact address from the trampoline header (the
        //   code already contains JMPs there, so we MUST map at this address).
        // - Unpatched: allocate lazily inside the whole image's branch-reach range.
        //   Fallback to traps if the trampoline cannot be allocated.
        // For ET_DYN, virtual addresses are relative to the load base.
        let (pre_patched, trampoline_file_offset, trampoline_file_size, trampoline_addr) =
            match trampoline_layout {
                // Zero-sized trampoline
                Some(layout) if layout.size == 0 => (true, layout.file_offset, 0, 0),
                Some(layout) => {
                    let base = if e_type == ET_DYN {
                        let Some(base) = relocation_offset else {
                            litebox_util_log::debug!(
                                mapped_addr:? = mapped_addr;
                                "pre-patched ET_DYN load base is unknown for this mapping"
                            );
                            return ElfPatchInit::MissingLoadBase;
                        };
                        base
                    } else {
                        0
                    };
                    let addr = base.wrapping_add(layout.vaddr);
                    if layout.vaddr >= Platform::TASK_ADDR_MAX
                        || layout
                            .size
                            .checked_next_multiple_of(PAGE_SIZE)
                            .and_then(|len| addr.checked_add(len))
                            .is_none_or(|end| end > Platform::TASK_ADDR_MAX)
                    {
                        litebox_util_log::debug!(
                            base:? = base, layout:? = layout;
                            "pre-patched trampoline range is invalid"
                        );
                        return ElfPatchInit::Malformed;
                    }
                    (true, layout.file_offset, layout.size, addr)
                }
                None => (false, 0, 0, 0),
            };

        // Never synthesize an ET_DYN span from an unknown base: it could cover
        // unrelated mappings.
        let load_span = if e_type == ET_DYN {
            relocation_offset.map(|relocation_offset| {
                let start = relocation_offset.wrapping_add(load_span.start);
                let end = relocation_offset.wrapping_add(load_span.end);
                start..end
            })
        } else {
            Some(load_span)
        };

        cache.insert(
            fd.clone(),
            ElfPatchState {
                pre_patched,
                trampoline_file_offset,
                trampoline_file_size,
                pre_patched_trampoline_reservation: None,
                trampoline_addr,
                load_span,
                trampoline_cursor: 0,
                trampoline_mapped: false,
                trampoline_mapped_len: 0,
                runtime_patches_committed: false,
                arch,
                trampoline_capacity,
                file_mappings: RangeSet::new(),
                patched_ranges: BTreeSet::new(),
            },
        );
        ElfPatchInit::Ready
    }

    /// Allows `MAP_FIXED` inside the computed load span. Outside it, rejects
    /// overlap with accessible mappings. This does not prove current ownership.
    fn trampoline_range_is_safe_to_map(
        &self,
        state: &ElfPatchState,
        start: usize,
        len: usize,
    ) -> bool {
        let range = start..start.saturating_add(len);
        if state
            .load_span
            .as_ref()
            .is_some_and(|span| range.start >= span.start && range.end <= span.end)
        {
            return true;
        }
        for (victim_range, flags) in self.global.mm.overlapping(range.clone()) {
            if flags.intersects(VmFlags::VM_ACCESS_FLAGS) {
                litebox_util_log::error!(
                    tramp_start:? = range.start, tramp_end:? = range.end,
                    victim_start:? = victim_range.start, victim_end:? = victim_range.end,
                    victim_flags:? = flags;
                    "refusing to map a trampoline over another mapping's live pages"
                );
                return false;
            }
        }
        true
    }

    /// Apply the trap fallback to a mapped code segment: replace every patch
    /// site with the rewriter's trap, then restore the caller-selected permissions.
    ///
    /// If `already_rw` is true, the segment is assumed to already be writable
    /// and the initial mprotect RW is skipped.
    ///
    /// Returns an error, leaving the segment untouched, if it cannot be made
    /// writable (e.g. part of it is unmapped), or if the caller-selected
    /// permissions cannot be restored.
    /// Panics on other infrastructure failures (read/write/disassembly).
    fn apply_trap_fallback(
        &self,
        rewriter: &arch::CodeRewriter,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        already_rw: bool,
        restore_protections: &[ProtectionRange],
    ) -> Result<(), Errno> {
        if !already_rw {
            self.sys_mprotect_raw(
                mapped_addr,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )?;
        }

        // Read, patch using the rewriter (proper disassembly), write back.
        let Some(code_owned) = mapped_addr.to_owned_slice::<Platform>(len) else {
            panic!("fatal: failed to read code segment for trap fallback");
        };
        let mut code_buf = code_owned.into_vec();
        let code_vaddr = mapped_addr.as_usize() as u64;
        let count = rewriter
            .trap_all(&mut code_buf, code_vaddr)
            .unwrap_or_else(|e| {
                panic!("fatal: failed to disassemble code segment for trap fallback: {e:?}");
            });
        if count > 0 {
            litebox_util_log::warn!(
                count:? = count, addr:? = mapped_addr.as_usize(), len:? = len;
                "applied trap fallback to syscall patch sites"
            );
        }
        assert!(
            mapped_addr
                .copy_from_slice::<Platform>(0, &code_buf)
                .is_some(),
            "fatal: failed to write trap bytes back to code segment"
        );

        // Restore the caller-selected permissions.
        self.restore_page_permissions(restore_protections)
    }

    /// Maps a pre-patched binary's trampoline from the file at its required
    /// address, writes the syscall entry point, finalizes it, and protects it RX.
    ///
    /// Does nothing if the trampoline is already mapped or empty. On failure,
    /// the partially set-up trampoline is unmapped and `ENOMEM` is returned.
    fn map_pre_patched_trampoline(
        &self,
        fd: &ElfPatchKey<Platform>,
        state: &mut ElfPatchState,
        syscall_entry: usize,
    ) -> Result<(), Errno> {
        if state.trampoline_mapped || state.trampoline_file_size == 0 {
            return Ok(());
        }
        let tramp_addr = state.trampoline_addr;
        let tramp_len = state.trampoline_file_size.next_multiple_of(PAGE_SIZE);

        // MAP_FIXED_NOREPLACE would reject the legitimate PROT_NONE or
        // object-span reservation, so validate ownership before MAP_FIXED.
        if !self.trampoline_range_is_safe_to_map(state, tramp_addr, tramp_len) {
            return Err(Errno::ENOMEM);
        }
        let alloc_result = self.do_mmap_trampoline(
            Some(tramp_addr),
            tramp_len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            None,
        );
        let Ok(alloc_ptr) = alloc_result else {
            return Err(Errno::ENOMEM);
        };
        let actual_addr = alloc_ptr.as_usize();
        if actual_addr != tramp_addr {
            let _ = self.sys_munmap_raw(UserPtrMut::<u8>::from_usize(actual_addr), tramp_len);
            return Err(Errno::ENOMEM);
        }
        // The trampoline replaced any reservation, and failures below unmap it.
        state.pre_patched_trampoline_reservation = None;

        // Read trampoline data from the file.
        let mut tramp_data = alloc::vec![0u8; state.trampoline_file_size];
        let file_off = state.trampoline_file_offset.trunc();
        let tramp_ptr = UserPtrMut::<u8>::from_usize(tramp_addr);
        if self
            .global
            .with_file(&fd.0, |file| {
                read_file_exact_at(file, &mut tramp_data, file_off)
            })
            .is_err()
        {
            let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
            return Err(Errno::ENOMEM);
        }

        // Write syscall entry point to the first 8 bytes.
        if tramp_data.len() >= 8 {
            tramp_data[..8].copy_from_slice(&syscall_entry.to_le_bytes());
        }

        // Finalize in staging so an unfinalized trampoline is never published.
        if let Err(e) = arch::finalize_trampoline(self.global.platform, &mut tramp_data) {
            litebox_util_log::error!(err:% = e; "refusing to map a trampoline that could not be finalized");
            let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
            return Err(Errno::ENOMEM);
        }

        // Write to the mapped region.
        if tramp_ptr
            .copy_from_slice::<Platform>(0, &tramp_data)
            .is_none()
        {
            let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
            return Err(Errno::ENOMEM);
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
            return Err(Errno::ENOMEM);
        }

        state.trampoline_mapped = true;
        state.trampoline_mapped_len = tramp_len;
        Ok(())
    }

    /// Patch an executable segment in-place after it has been mapped.
    ///
    /// For pre-patched binaries: maps the trampoline from the file and writes
    /// the syscall entry point.
    /// For unpatched binaries: calls `patch_code_segment()` to rewrite syscall
    /// instructions and places the generated stubs in the trampoline region.
    ///
    /// Returns an error when a pre-patched binary's trampoline cannot be set
    /// up, the segment or trampoline cannot be made writable (e.g. part of it
    /// is unmapped), or the caller-selected code permissions cannot be restored.
    fn maybe_patch_exec_segment(
        &self,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        fd: &ElfPatchKey<Platform>,
        syscall_entry: usize,
        file_offset: Option<usize>,
        restore_protections: &[ProtectionRange],
    ) -> Result<(), Errno> {
        // This lock guards the elf_patch_cache and is held for the entire
        // patching operation. In practice this is fine because the dynamic
        // linker loads shared libraries sequentially.
        let mut cache = self.global.elf_patch_cache.lock();
        let Some(state) = cache.get_mut(fd) else {
            return Ok(()); // No patch state — not an ELF we're tracking
        };
        if state.arch.trampoline_invalidated() {
            return Err(Errno::ENOMEM);
        }

        if state.pre_patched {
            self.map_pre_patched_trampoline(fd, state, syscall_entry)
        } else {
            self.patch_with_runtime_trampoline(
                state,
                mapped_addr,
                len,
                syscall_entry,
                file_offset,
                restore_protections,
            )
        }
    }

    /// Rewrites an unpatched executable segment, placing the generated stubs
    /// in the file's runtime trampoline. Falls back to traps if no reachable
    /// trampoline is available or the stubs cannot be installed.
    ///
    /// Returns an error, without rewriting anything, if the segment or the
    /// trampoline cannot be made writable (e.g. part of it is unmapped), or if
    /// the caller-selected code permissions cannot be restored.
    fn patch_with_runtime_trampoline(
        &self,
        state: &mut ElfPatchState,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        syscall_entry: usize,
        file_offset: Option<usize>,
        restore_protections: &[ProtectionRange],
    ) -> Result<(), Errno> {
        let rewriter = arch::CodeRewriter::new(&state.arch, file_offset, len);
        let code = mapped_addr.as_usize()..mapped_addr.as_usize().saturating_add(len);
        if !self.ensure_runtime_trampoline(state, code, syscall_entry) {
            return self.apply_trap_fallback(
                &rewriter,
                mapped_addr,
                len,
                false,
                restore_protections,
            );
        }

        // Performance guard: skip if this exact range was already patched.
        let mapping_key = (mapped_addr.as_usize(), len);
        if state.patched_ranges.contains(&mapping_key) {
            return Ok(());
        }

        // Make the trampoline and the code RW for writing. LiteBox applies
        // `mprotect` all-or-nothing, so if the guest unmapped any of their
        // pages this fails without changing them, and the request is rejected.
        self.protect_trampoline(state, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)?;
        if let Err(error) = self.sys_mprotect_raw(
            mapped_addr,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        ) {
            let _ = self.protect_trampoline(state, ProtFlags::PROT_READ | ProtFlags::PROT_EXEC);
            return Err(error);
        }
        state.patched_ranges.insert(mapping_key);

        let restored = match self.rewrite_into_trampoline(
            state,
            &rewriter,
            mapped_addr,
            len,
            syscall_entry,
            restore_protections,
        ) {
            RewriteOutcome::Done => self.restore_page_permissions(restore_protections),
            RewriteOutcome::TrapFallback => {
                self.apply_trap_fallback(&rewriter, mapped_addr, len, true, restore_protections)
            }
        };
        let _ = self.protect_trampoline(state, ProtFlags::PROT_READ | ProtFlags::PROT_EXEC);
        restored
    }

    /// Ensures `state` has a mapped runtime trampoline within branch reach of
    /// `code` and of the whole ELF image, allocating one on first use.
    ///
    /// Returns `false`, after logging why, if the trap fallback must be used.
    fn ensure_runtime_trampoline(
        &self,
        state: &mut ElfPatchState,
        mut code: Range<usize>,
        syscall_entry: usize,
    ) -> bool {
        if let Some(load_span) = &state.load_span {
            code.start = code.start.min(load_span.start);
            code.end = code.end.max(load_span.end);
        }
        let Some(allowed) = trampoline_allocation_range(code) else {
            litebox_util_log::warn!("ELF and code mapping span exceeds trampoline branch reach");
            return false;
        };
        if state.trampoline_mapped {
            let in_reach = state.trampoline_addr >= allowed.start
                && state
                    .trampoline_addr
                    .saturating_add(state.trampoline_mapped_len)
                    <= allowed.end;
            if !in_reach {
                litebox_util_log::warn!(
                    "ELF trampoline is outside branch reach; using trap fallback"
                );
            }
            return in_reach;
        }
        if state.trampoline_capacity == 0 {
            litebox_util_log::warn!("ELF trampoline capacity unavailable; using trap fallback");
            return false;
        }
        // Prefer the region the loader keeps free past the image, so that the
        // trampoline does not cap brk; otherwise search top-down within reach.
        let hint = state
            .load_span
            .as_ref()
            .and_then(|span| litebox_common_linux::loader::runtime_trampoline_reservation(span.end))
            .filter(|reservation| state.trampoline_capacity <= reservation.len())
            .map(|reservation| reservation.start);
        let trampoline = match self.do_mmap_trampoline(
            hint,
            state.trampoline_capacity,
            ProtFlags::PROT_READ_WRITE,
            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
            Some(allowed),
        ) {
            Ok(pointer) => pointer,
            Err(error) => {
                litebox_util_log::warn!(error:? = error; "failed to allocate reachable trampoline");
                return false;
            }
        };
        state.trampoline_addr = trampoline.as_usize();

        if litebox_syscall_rewriter::TRAMPOLINE_ENTRY_POINT_BYTES != 0 {
            if trampoline
                .copy_from_slice::<Platform>(0, &syscall_entry.to_le_bytes())
                .is_none()
            {
                litebox_util_log::warn!("failed to write syscall entry point to trampoline");
                let _ = self.sys_munmap_raw(trampoline, state.trampoline_capacity);
                return false;
            }
            state.trampoline_cursor = litebox_syscall_rewriter::TRAMPOLINE_ENTRY_POINT_BYTES;
        } else {
            state.trampoline_cursor = 0;
        }
        state.trampoline_mapped = true;
        state.trampoline_mapped_len = state.trampoline_capacity;
        true
    }

    /// Rewrites the writable code segment at `mapped_addr`, appending the
    /// generated stubs to the writable trampoline.
    ///
    /// Stubs are written before the code, so rewritten jumps never target an
    /// uninitialized trampoline. Leaves protections to the caller.
    fn rewrite_into_trampoline(
        &self,
        state: &mut ElfPatchState,
        rewriter: &arch::CodeRewriter,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        syscall_entry: usize,
        restore_protections: &[ProtectionRange],
    ) -> RewriteOutcome {
        let Some(code_owned) = mapped_addr.to_owned_slice::<Platform>(len) else {
            self.abort_rewrite(
                state,
                restore_protections,
                "failed to read code segment for patching",
            );
        };
        let mut code_buf = code_owned.into_vec();
        let original_code = code_buf.clone();

        let Some(aligned_cursor) = state
            .trampoline_cursor
            .checked_next_multiple_of(litebox_syscall_rewriter::TRAMPOLINE_CURSOR_ALIGN)
        else {
            return RewriteOutcome::TrapFallback;
        };
        state.trampoline_cursor = aligned_cursor;
        let trampoline_write_vaddr = (state.trampoline_addr + state.trampoline_cursor) as u64;
        let syscall_entry_addr = if litebox_syscall_rewriter::TRAMPOLINE_ENTRY_POINT_BYTES != 0 {
            state.trampoline_addr as u64
        } else {
            syscall_entry as u64
        };

        let (mut stubs, skipped_addrs) = match rewriter.patch(
            &mut code_buf,
            mapped_addr.as_usize() as u64,
            trampoline_write_vaddr,
            syscall_entry_addr,
        ) {
            Ok(patched) => patched,
            Err(e) => {
                litebox_util_log::warn!(err:? = e; "patch_code_segment failed");
                return RewriteOutcome::TrapFallback;
            }
        };
        if !skipped_addrs.is_empty() {
            litebox_util_log::warn!(
                count:? = skipped_addrs.len(), addrs:? = skipped_addrs;
                "syscall instruction(s) could not be patched"
            );
        }

        if stubs.is_empty() {
            // No trampoline stubs were generated, but the rewriter may have
            // replaced unpatchable syscalls with trap instructions.
            if code_buf != original_code
                && mapped_addr
                    .copy_from_slice::<Platform>(0, &code_buf)
                    .is_none()
            {
                let _ = mapped_addr.copy_from_slice::<Platform>(0, &original_code);
                self.abort_rewrite(
                    state,
                    restore_protections,
                    "failed to write trap bytes back to code segment",
                );
            }
            return RewriteOutcome::Done;
        }

        // Replace recognized sites with traps before discarding stubs that
        // could not be finalized.
        if let Err(e) = arch::finalize_trampoline(self.global.platform, &mut stubs) {
            litebox_util_log::error!(err:% = e; "refusing to install runtime stubs that could not be finalized");
            return RewriteOutcome::TrapFallback;
        }
        let Some(new_cursor) = state.trampoline_cursor.checked_add(stubs.len()) else {
            litebox_util_log::warn!("trampoline cursor overflow");
            return RewriteOutcome::TrapFallback;
        };
        if new_cursor > state.trampoline_mapped_len {
            litebox_util_log::warn!("ELF trampoline capacity exhausted; using trap fallback");
            return RewriteOutcome::TrapFallback;
        }

        let stub_ptr =
            UserPtrMut::<u8>::from_usize(state.trampoline_addr + state.trampoline_cursor);
        if stub_ptr.copy_from_slice::<Platform>(0, &stubs).is_none() {
            self.abort_rewrite(
                state,
                restore_protections,
                "failed to write trampoline stubs",
            );
        }
        if mapped_addr
            .copy_from_slice::<Platform>(0, &code_buf)
            .is_none()
        {
            let _ = mapped_addr.copy_from_slice::<Platform>(0, &original_code);
            self.abort_rewrite(
                state,
                restore_protections,
                "failed to write patched code back to code segment",
            );
        }
        state.trampoline_cursor = new_cursor;
        state.runtime_patches_committed = true;
        RewriteOutcome::Done
    }

    /// Applies `prot` to the mapped trampoline, if any.
    fn protect_trampoline(&self, state: &ElfPatchState, prot: ProtFlags) -> Result<(), Errno> {
        if state.trampoline_mapped_len == 0 {
            return Ok(());
        }
        self.sys_mprotect_raw(
            UserPtrMut::<u8>::from_usize(state.trampoline_addr),
            state.trampoline_mapped_len,
            prot,
        )
    }

    /// Best-effort restores code and trampoline protections, then panics:
    /// a partially written rewrite cannot be recovered.
    fn abort_rewrite(
        &self,
        state: &ElfPatchState,
        restore_protections: &[ProtectionRange],
        reason: &str,
    ) -> ! {
        let _ = self.restore_page_permissions(restore_protections);
        let _ = self.protect_trampoline(state, ProtFlags::PROT_READ | ProtFlags::PROT_EXEC);
        panic!("fatal: {reason}");
    }

    /// Finalize the ELF patching state for `fd`.
    ///
    /// Removes the cache entry and unmaps any trampoline that was allocated but never used.
    pub(crate) fn finalize_elf_patch(&self, fd: Arc<FileFd<Platform>>) {
        let state = self.global.elf_patch_cache.lock().remove(&ElfPatchKey(fd));
        if let Some(reservation) = state
            .as_ref()
            .and_then(|state| state.pre_patched_trampoline_reservation.clone())
            && let Err(error) =
                self.sys_munmap_raw(UserPtrMut::from_usize(reservation.start), reservation.len())
        {
            litebox_util_log::warn!(
                error:? = error, range:? = reservation;
                "failed to release unused pre-patched trampoline reservation"
            );
        }
        if let Some(state) = state
            && state.trampoline_mapped
            && !state.pre_patched
            && !state.runtime_patches_committed
        {
            let tramp_len = state.trampoline_mapped_len;
            if tramp_len > 0
                && let Err(error) =
                    self.sys_munmap_raw(UserPtrMut::from_usize(state.trampoline_addr), tramp_len)
            {
                litebox_util_log::warn!(error:? = error, addr:? = state.trampoline_addr, len:? = tramp_len; "failed to unmap ELF trampoline");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ElfPatchKey, ElfPatchState, PAGE_SIZE, Task};
    use alloc::collections::BTreeSet;
    use alloc::vec::Vec;
    use litebox::platform::page_mgmt::MemoryRegionPermissions;
    use litebox_broker_protocol::fs::FileMode as Mode;
    use litebox_common_linux::{
        MapFlags, OFlags, ProtFlags,
        errno::Errno,
        vmem::{NonZeroAddress, NonZeroPageSize},
    };
    use rangemap::RangeSet;

    use crate::UserPtrMut;
    use crate::syscalls::file::AnyTypedFd;
    use crate::syscalls::tests::{TestPlatform as Platform, create_file, init_platform};

    fn elf_patch_key(task: &Task<Platform>, fd: i32) -> ElfPatchKey<Platform> {
        let AnyTypedFd::File(fd) = task.typed_fd(fd).expect("file descriptor should resolve")
        else {
            panic!("descriptor should refer to a file");
        };
        ElfPatchKey(fd)
    }

    fn runtime_patch_state(
        file_mappings: RangeSet<usize>,
        trampoline_addr: usize,
        trampoline_mapped: bool,
    ) -> ElfPatchState {
        ElfPatchState {
            pre_patched: false,
            trampoline_file_offset: 0,
            trampoline_file_size: 0,
            pre_patched_trampoline_reservation: None,
            trampoline_addr,
            load_span: None,
            trampoline_cursor: 0,
            trampoline_mapped,
            trampoline_mapped_len: 0,
            runtime_patches_committed: false,
            arch: super::arch::ArchPatchState::default(),
            trampoline_capacity: 64 * PAGE_SIZE,
            file_mappings,
            patched_ranges: BTreeSet::new(),
        }
    }

    fn mapping_permissions(
        task: &Task<Platform>,
        address: UserPtrMut<u8>,
    ) -> MemoryRegionPermissions {
        task.global
            .mm
            .get_memory_permissions(
                NonZeroAddress::new(address.as_usize()).expect("mapping address is aligned"),
                NonZeroPageSize::new(PAGE_SIZE).expect("page size is valid"),
            )
            .expect("mapping permissions should be tracked")
    }

    fn check_file_mmap_permissions(
        task: &Task<Platform>,
        fd: i32,
        prot: ProtFlags,
        expected: MemoryRegionPermissions,
    ) {
        let address = task
            .do_mmap_file(None, PAGE_SIZE, prot, MapFlags::MAP_PRIVATE, fd, 0)
            .expect("file mapping should succeed");
        assert_eq!(mapping_permissions(task, address), expected);
        task.sys_munmap(address, PAGE_SIZE)
            .expect("test mapping should unmap");
    }

    #[test]
    fn file_mmap_preserves_requested_permissions() {
        let task = init_platform();
        create_file(&task, "/mmap-permissions", &[0]);
        let fd = i32::try_from(
            task.sys_open("/mmap-permissions", OFlags::RDONLY, Mode::empty())
                .expect("test file should open"),
        )
        .expect("file descriptor should fit i32");
        task.global.elf_patch_cache.lock().insert(
            elf_patch_key(&task, fd),
            runtime_patch_state(RangeSet::new(), 0, true),
        );

        for (prot, permissions) in [
            (ProtFlags::PROT_NONE, MemoryRegionPermissions::empty()),
            (ProtFlags::PROT_READ, MemoryRegionPermissions::READ),
            (ProtFlags::PROT_WRITE, MemoryRegionPermissions::WRITE),
            (ProtFlags::PROT_EXEC, MemoryRegionPermissions::EXEC),
            (
                ProtFlags::PROT_READ_WRITE,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            ),
            (
                ProtFlags::PROT_READ_EXEC,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
            ),
        ] {
            check_file_mmap_permissions(&task, fd, prot, permissions);
        }

        #[cfg(target_os = "linux")]
        for (prot, permissions) in [
            (
                ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC,
                MemoryRegionPermissions::WRITE | MemoryRegionPermissions::EXEC,
            ),
            (
                ProtFlags::PROT_READ_WRITE_EXEC,
                MemoryRegionPermissions::READ
                    | MemoryRegionPermissions::WRITE
                    | MemoryRegionPermissions::EXEC,
            ),
        ] {
            check_file_mmap_permissions(&task, fd, prot, permissions);
        }

        let address = task
            .do_mmap_file(
                None,
                PAGE_SIZE,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd,
                0,
            )
            .expect("file mapping should succeed");
        assert_eq!(
            task.sys_mprotect(
                address,
                PAGE_SIZE,
                ProtFlags::PROT_EXEC | ProtFlags::PROT_GROWSDOWN,
            ),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            mapping_permissions(&task, address),
            MemoryRegionPermissions::READ
        );
        task.sys_munmap(address, PAGE_SIZE)
            .expect("test mapping should unmap");

        #[cfg(target_os = "macos")]
        {
            let address = task
                .do_mmap_file(
                    None,
                    PAGE_SIZE,
                    ProtFlags::PROT_READ,
                    MapFlags::MAP_PRIVATE,
                    fd,
                    0,
                )
                .expect("file mapping should succeed");
            assert_eq!(
                task.sys_mprotect(
                    address,
                    PAGE_SIZE,
                    ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC,
                ),
                Err(Errno::EACCES)
            );
            assert_eq!(
                mapping_permissions(&task, address),
                MemoryRegionPermissions::READ
            );
            task.sys_munmap(address, PAGE_SIZE)
                .expect("test mapping should unmap");
        }

        task.sys_close(fd).expect("test file should close");
    }

    /// Builds a one-page `ET_DYN` image that runtime rewriting tracks.
    fn minimal_dyn_elf() -> alloc::vec::Vec<u8> {
        dyn_elf_with_load_size(PAGE_SIZE)
    }

    fn dyn_elf_with_load_size(load_size: usize) -> alloc::vec::Vec<u8> {
        use object::elf::{ET_DYN, PT_LOAD};
        #[cfg(target_arch = "x86_64")]
        let machine = object::elf::EM_X86_64;
        #[cfg(target_arch = "aarch64")]
        let machine = object::elf::EM_AARCH64;
        let page = u64::try_from(PAGE_SIZE).unwrap();
        let load_size = u64::try_from(load_size).unwrap();
        let mut elf = alloc::vec::Vec::new();
        elf.extend_from_slice(b"\x7fELF");
        elf.extend_from_slice(&[2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        elf.extend_from_slice(&ET_DYN.to_le_bytes());
        elf.extend_from_slice(&machine.to_le_bytes());
        elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        elf.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        elf.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
        elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
        elf.extend_from_slice(&[0; 6]); // e_shentsize, e_shnum, e_shstrndx
        elf.extend_from_slice(&PT_LOAD.to_le_bytes());
        elf.extend_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
        for value in [0, 0, 0, page, load_size, page] {
            elf.extend_from_slice(&u64::to_le_bytes(value));
        }
        elf.resize(PAGE_SIZE, 0);
        elf
    }

    fn open_test_file(task: &Task<Platform>, path: &str, content: &[u8]) -> i32 {
        create_file(task, path, content);
        i32::try_from(
            task.sys_open(path, OFlags::RDONLY, Mode::empty())
                .expect("test file should open"),
        )
        .expect("file descriptor should fit i32")
    }

    fn map_file_at_offset_zero(task: &Task<Platform>, fd: i32, prot: ProtFlags) -> UserPtrMut<u8> {
        task.do_mmap_file(None, PAGE_SIZE, prot, MapFlags::MAP_PRIVATE, fd, 0)
            .expect("file mapping should succeed")
    }

    fn trampoline_mapping(task: &Task<Platform>, fd: i32) -> Option<core::ops::Range<usize>> {
        task.global
            .elf_patch_cache
            .lock()
            .get(&elf_patch_key(task, fd))
            .filter(|state| state.trampoline_mapped)
            .map(|state| state.trampoline_addr..state.trampoline_addr + state.trampoline_mapped_len)
    }

    fn pre_patched_dyn_elf(file_offset: usize, gap: usize) -> Vec<u8> {
        let mut elf = minimal_dyn_elf();
        let vaddr = 3 * litebox_common_linux::HOST_PAGE_SIZE;
        elf[72..80].copy_from_slice(&(file_offset as u64).to_le_bytes());
        elf[80..88].copy_from_slice(&(vaddr as u64).to_le_bytes());
        elf[88..96].copy_from_slice(&(vaddr as u64).to_le_bytes());
        elf.resize(file_offset + PAGE_SIZE, 0);
        let trampoline_offset = elf.len();
        let trampoline_size = 2 * PAGE_SIZE;
        elf.resize(trampoline_offset + trampoline_size, 0x90);
        elf.extend_from_slice(b"LITEBOX0");
        for value in [trampoline_offset, vaddr + PAGE_SIZE + gap, trampoline_size] {
            elf.extend_from_slice(&(value as u64).to_le_bytes());
        }
        elf
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn pre_patched_placement_keeps_exact_trampoline_extent_clear_of_neighbors() {
        for (offset, gap, path) in [
            (0, 0, "/pre-patched-zero-offset"),
            (PAGE_SIZE, 2 * PAGE_SIZE, "/pre-patched-nonzero-offset"),
        ] {
            let task = init_platform();
            let before = task.global.mm.mappings();
            let fd = open_test_file(&task, path, &pre_patched_dyn_elf(offset, gap));
            let arena = task
                .do_mmap(
                    None,
                    5 * PAGE_SIZE,
                    ProtFlags::PROT_READ_WRITE,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
                    |_| Ok(0),
                )
                .unwrap();
            let neighbor = UserPtrMut::<u8>::from_usize(arena.as_usize() + PAGE_SIZE);
            let contents = alloc::vec![0xa5; 4 * PAGE_SIZE];
            neighbor.copy_from_slice::<Platform>(0, &contents).unwrap();
            task.sys_munmap(arena, PAGE_SIZE).unwrap();
            let address = task
                .do_mmap_file(
                    Some(arena.as_usize()),
                    PAGE_SIZE,
                    ProtFlags::PROT_READ,
                    MapFlags::MAP_PRIVATE,
                    fd,
                    offset,
                )
                .unwrap();
            assert_ne!(address.as_usize(), arena.as_usize());
            let trampoline =
                address.as_usize() + PAGE_SIZE + gap..address.as_usize() + 3 * PAGE_SIZE + gap;
            {
                let cache = task.global.elf_patch_cache.lock();
                let state = &cache[&elf_patch_key(&task, fd)];
                assert_eq!(
                    state.pre_patched_trampoline_reservation,
                    Some(trampoline.clone())
                );
                assert!(!state.trampoline_mapped);
            }
            assert_eq!(
                mapping_permissions(&task, UserPtrMut::from_usize(trampoline.start)),
                MemoryRegionPermissions::empty(),
            );
            if gap > 0 {
                assert!(
                    task.global
                        .mm
                        .get_memory_permissions(
                            NonZeroAddress::new(address.as_usize() + PAGE_SIZE).unwrap(),
                            NonZeroPageSize::new(gap).unwrap(),
                        )
                        .is_none()
                );
            }
            task.do_mmap_file(
                Some(address.as_usize()),
                PAGE_SIZE,
                ProtFlags::PROT_READ_EXEC,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                fd,
                offset,
            )
            .unwrap();
            assert_eq!(trampoline_mapping(&task, fd), Some(trampoline.clone()));
            assert!(
                task.global.elf_patch_cache.lock()[&elf_patch_key(&task, fd)]
                    .pre_patched_trampoline_reservation
                    .is_none()
            );
            assert_eq!(
                neighbor
                    .to_owned_slice::<Platform>(contents.len())
                    .unwrap()
                    .as_ref(),
                contents.as_slice(),
            );
            task.sys_close(fd).unwrap();
            assert_eq!(
                mapping_permissions(&task, UserPtrMut::from_usize(trampoline.start)),
                MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
            );
            task.sys_munmap(address, PAGE_SIZE).unwrap();
            task.sys_munmap(UserPtrMut::from_usize(trampoline.start), trampoline.len())
                .unwrap();
            task.sys_munmap(neighbor, contents.len()).unwrap();
            assert_eq!(task.global.mm.mappings(), before);
        }
    }

    #[test]
    fn unused_or_failed_pre_patched_mapping_releases_trampoline_reservation() {
        for malformed in [false, true] {
            let task = init_platform();
            let before = task.global.mm.mappings();
            let mut elf = pre_patched_dyn_elf(PAGE_SIZE, 2 * PAGE_SIZE);
            if malformed {
                elf[104..112].copy_from_slice(&u64::MAX.to_le_bytes());
            }
            let path = if malformed {
                "/failed-pre-patched"
            } else {
                "/unused-pre-patched"
            };
            let fd = open_test_file(&task, path, &elf);
            let key = elf_patch_key(&task, fd);
            let address = task.do_mmap_file(
                None,
                PAGE_SIZE,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd,
                PAGE_SIZE,
            );
            if malformed {
                assert_eq!(address.err(), Some(Errno::ENOMEM));
                assert!(!task.global.elf_patch_cache.lock().contains_key(&key));
            } else {
                let address = address.unwrap();
                let trampoline = task.global.elf_patch_cache.lock()[&key]
                    .pre_patched_trampoline_reservation
                    .clone()
                    .unwrap();
                assert_eq!(
                    trampoline,
                    address.as_usize() + 3 * PAGE_SIZE..address.as_usize() + 5 * PAGE_SIZE
                );
                task.sys_close(fd).unwrap();
                assert!(
                    task.global
                        .mm
                        .get_memory_permissions(
                            NonZeroAddress::new(trampoline.start).unwrap(),
                            NonZeroPageSize::new(trampoline.len()).unwrap(),
                        )
                        .is_none()
                );
                assert_eq!(
                    mapping_permissions(&task, address),
                    MemoryRegionPermissions::READ
                );
                task.sys_munmap(address, PAGE_SIZE).unwrap();
            }
            if malformed {
                task.sys_close(fd).unwrap();
            }
            assert_eq!(task.global.mm.mappings(), before);
        }
    }

    #[test]
    fn readonly_mappings_track_complete_load_span_without_allocating_trampoline() {
        let task = init_platform();
        let before = task.global.mm.mappings();
        let load_size = 4 * PAGE_SIZE;
        let fd = open_test_file(
            &task,
            "/partial-initial-mapping",
            &dyn_elf_with_load_size(load_size),
        );
        // Like a loader, reserve the whole image before mapping segments into it,
        // so that the later fixed mapping cannot collide with unrelated memory.
        let image = task
            .do_mmap(
                None,
                load_size,
                ProtFlags::PROT_NONE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
                |_| Ok(0),
            )
            .unwrap();
        let first = task
            .do_mmap_file(
                Some(image.as_usize()),
                PAGE_SIZE,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                fd,
                0,
            )
            .unwrap();
        assert_eq!(first.as_usize(), image.as_usize());
        {
            let cache = task.global.elf_patch_cache.lock();
            let state = &cache[&elf_patch_key(&task, fd)];
            assert_eq!(
                state.load_span,
                Some(first.as_usize()..first.as_usize() + load_size)
            );
            #[cfg(target_arch = "x86_64")]
            let capacity = super::arch::RUNTIME_TRAMPOLINE_SIZE;
            #[cfg(target_arch = "aarch64")]
            let capacity = PAGE_SIZE;
            assert_eq!(
                state.trampoline_capacity,
                capacity.next_multiple_of(PAGE_SIZE)
            );
            assert!(!state.trampoline_mapped);
        }

        let before_second = task.global.mm.mappings();
        let second = map_file_at_offset_zero(&task, fd, ProtFlags::PROT_READ);
        assert!(trampoline_mapping(&task, fd).is_none());
        task.sys_munmap(second, PAGE_SIZE).unwrap();
        assert_eq!(task.global.mm.mappings(), before_second);

        let later_segment = task
            .sys_mmap(
                first.as_usize() + PAGE_SIZE,
                PAGE_SIZE,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                fd,
                PAGE_SIZE,
            )
            .expect("later ELF segment should map");
        assert_eq!(later_segment.as_usize(), first.as_usize() + PAGE_SIZE);
        assert!(trampoline_mapping(&task, fd).is_none());

        task.sys_munmap(image, load_size).unwrap();
        task.sys_close(fd).unwrap();
        assert_eq!(task.global.mm.mappings(), before);
    }

    #[test]
    fn initial_mapping_offset_determines_complete_load_span() {
        let task = init_platform();
        let before = task.global.mm.mappings();
        let segment_start = 3 * litebox_common_linux::HOST_PAGE_SIZE;
        let mut elf = minimal_dyn_elf();
        elf[56..58].copy_from_slice(&2u16.to_le_bytes());
        let mut segment = Vec::new();
        segment.extend_from_slice(&object::elf::PT_LOAD.to_le_bytes());
        segment.extend_from_slice(&5u32.to_le_bytes());
        for value in [
            PAGE_SIZE,
            segment_start,
            segment_start,
            PAGE_SIZE,
            2 * PAGE_SIZE,
            PAGE_SIZE,
        ] {
            segment.extend_from_slice(&(value as u64).to_le_bytes());
        }
        elf[120..176].copy_from_slice(&segment);
        elf.resize(3 * PAGE_SIZE, 0);
        for (path, offset) in [
            ("/nonzero-initial-offset", PAGE_SIZE),
            ("/unmatched-initial-offset", 2 * PAGE_SIZE),
        ] {
            let fd = open_test_file(&task, path, &elf);
            let address = task
                .do_mmap_file(
                    None,
                    PAGE_SIZE,
                    ProtFlags::PROT_READ,
                    MapFlags::MAP_PRIVATE,
                    fd,
                    offset,
                )
                .unwrap();
            assert!(trampoline_mapping(&task, fd).is_none());
            let expected_span = if offset == PAGE_SIZE {
                Some(address.as_usize() - segment_start..address.as_usize() + 2 * PAGE_SIZE)
            } else {
                None
            };
            assert_eq!(
                task.global.elf_patch_cache.lock()[&elf_patch_key(&task, fd)].load_span,
                expected_span,
            );
            task.sys_munmap(address, PAGE_SIZE).unwrap();
            task.sys_close(fd).unwrap();
            assert_eq!(task.global.mm.mappings(), before);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn single_full_capacity_trampoline_is_reused_and_survives_close() {
        let task = init_platform();
        let mut elf = dyn_elf_with_load_size(2 * PAGE_SIZE);
        elf[96..104].copy_from_slice(&(2 * PAGE_SIZE as u64).to_le_bytes());
        elf.resize(2 * PAGE_SIZE, 0x90);
        elf[128..].fill(0x90);
        for slot in elf[128..].as_chunks_mut::<16>().0 {
            slot[..2].copy_from_slice(&[0x0f, 0x05]);
        }
        let fd = open_test_file(&task, "/growing-reservation", &elf);
        let key = elf_patch_key(&task, fd);
        let address = task
            .do_mmap_file(
                None,
                2 * PAGE_SIZE,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd,
                0,
            )
            .unwrap();
        assert!(trampoline_mapping(&task, fd).is_none());
        task.sys_mprotect(address, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
            .unwrap();
        let trampoline = {
            let cache = task.global.elf_patch_cache.lock();
            let state = &cache[&elf_patch_key(&task, fd)];
            assert!(state.runtime_patches_committed);
            assert!(state.trampoline_cursor > PAGE_SIZE);
            assert!(state.trampoline_mapped_len > PAGE_SIZE);
            let range = state.trampoline_addr..state.trampoline_addr + state.trampoline_mapped_len;
            assert_eq!(state.trampoline_mapped_len, state.trampoline_capacity);
            assert_eq!(
                state.trampoline_capacity,
                super::arch::RUNTIME_TRAMPOLINE_SIZE
            );
            let allowed =
                super::trampoline_allocation_range(state.load_span.clone().unwrap()).unwrap();
            assert!(range.start >= allowed.start && range.end <= allowed.end);
            range
        };
        let first_cursor = task.global.elf_patch_cache.lock()[&key].trampoline_cursor;
        task.sys_mprotect(
            UserPtrMut::from_usize(address.as_usize() + PAGE_SIZE),
            PAGE_SIZE,
            ProtFlags::PROT_READ_EXEC,
        )
        .unwrap();
        assert_eq!(trampoline_mapping(&task, fd), Some(trampoline.clone()));
        assert!(task.global.elf_patch_cache.lock()[&key].trampoline_cursor > first_cursor);
        let before = task.global.mm.mappings();
        task.sys_mprotect(address, PAGE_SIZE, ProtFlags::PROT_READ)
            .unwrap();
        task.sys_mprotect(address, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
            .unwrap();
        assert_eq!(trampoline_mapping(&task, fd), Some(trampoline.clone()));
        assert_eq!(task.global.mm.mappings(), before);
        task.sys_close(fd).unwrap();
        assert_eq!(
            mapping_permissions(&task, UserPtrMut::from_usize(trampoline.start)),
            MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
        );
        assert!(!task.global.elf_patch_cache.lock().contains_key(&key));
        task.sys_munmap(address, 2 * PAGE_SIZE).unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn runtime_trampoline_fallback_never_grows_or_allocates_outside_reach() {
        let task = init_platform();
        let elf = minimal_dyn_elf();
        let mut code = alloc::vec![0x90; PAGE_SIZE];
        for slot in code[128..].as_chunks_mut::<16>().0 {
            slot[..2].copy_from_slice(&[0x0f, 0x05]);
        }
        let before = task.global.mm.mappings();
        for (case, path) in [
            "/zero-capacity",
            "/exhausted-capacity",
            "/unreachable-span",
            "/no-gap",
        ]
        .into_iter()
        .enumerate()
        {
            let fd = open_test_file(&task, path, &elf);
            let key = elf_patch_key(&task, fd);
            let address = map_file_at_offset_zero(&task, fd, ProtFlags::PROT_READ);
            task.sys_mprotect(address, PAGE_SIZE, ProtFlags::PROT_READ_WRITE)
                .unwrap();
            assert!(address.copy_from_slice::<Platform>(0, &code).is_some());
            {
                let mut cache = task.global.elf_patch_cache.lock();
                let state = cache.get_mut(&key).unwrap();
                match case {
                    0 => state.trampoline_capacity = 0,
                    1 => state.trampoline_capacity = PAGE_SIZE,
                    2 => {
                        state.load_span =
                            Some(0..2 * litebox_syscall_rewriter::MAX_TRAMPOLINE_DISPLACEMENT);
                    }
                    _ => {
                        state.trampoline_capacity =
                            2 * litebox_syscall_rewriter::MAX_TRAMPOLINE_DISPLACEMENT;
                    }
                }
            }
            task.sys_mprotect(address, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
                .unwrap();
            {
                let cache = task.global.elf_patch_cache.lock();
                let state = &cache[&key];
                assert!(!state.runtime_patches_committed);
                assert_eq!(
                    state.trampoline_mapped_len,
                    if case == 1 { PAGE_SIZE } else { 0 }
                );
                if state.trampoline_mapped {
                    assert_eq!(
                        mapping_permissions(&task, UserPtrMut::from_usize(state.trampoline_addr)),
                        MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
                    );
                }
            }
            let patched = address.to_owned_slice::<Platform>(PAGE_SIZE).unwrap();
            for offset in (128..PAGE_SIZE).step_by(16) {
                assert_eq!(&patched[offset..offset + 2], &[0xf1, 0xf4]);
            }
            assert_eq!(
                mapping_permissions(&task, address),
                MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC
            );
            task.sys_munmap(address, PAGE_SIZE).unwrap();
            task.sys_close(fd).unwrap();
            assert_eq!(task.global.mm.mappings(), before);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn runtime_trampoline_prefers_loader_reservation_and_falls_back_within_reach() {
        let task = init_platform();
        let mut elf = minimal_dyn_elf();
        elf[128..].fill(0x90);
        for slot in elf[128..].as_chunks_mut::<16>().0 {
            slot[..2].copy_from_slice(&[0x0f, 0x05]);
        }
        let arena_len = PAGE_SIZE
            + litebox_common_linux::HOST_PAGE_SIZE
            + litebox_common_linux::loader::RUNTIME_TRAMPOLINE_RESERVATION_SIZE;
        let before = task.global.mm.mappings();
        for (blocked, path) in [(false, "/free-reservation"), (true, "/blocked-reservation")] {
            // Find a free arena so that the area past the image is known to be unmapped.
            let arena = task
                .do_mmap(
                    None,
                    arena_len,
                    ProtFlags::PROT_NONE,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
                    |_| Ok(0),
                )
                .unwrap();
            task.sys_munmap(arena, arena_len).unwrap();
            let fd = open_test_file(&task, path, &elf);
            let address = task
                .do_mmap_file(
                    Some(arena.as_usize()),
                    PAGE_SIZE,
                    ProtFlags::PROT_READ,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                    fd,
                    0,
                )
                .unwrap();
            let preferred = litebox_common_linux::loader::runtime_trampoline_reservation(
                address.as_usize() + PAGE_SIZE,
            )
            .unwrap();
            let blocker = blocked.then(|| {
                task.do_mmap(
                    Some(preferred.start),
                    PAGE_SIZE,
                    ProtFlags::PROT_NONE,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED_NOREPLACE,
                    |_| Ok(0),
                )
                .unwrap()
            });
            task.sys_mprotect(address, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
                .unwrap();
            let trampoline = trampoline_mapping(&task, fd).unwrap();
            assert!(
                task.global.elf_patch_cache.lock()[&elf_patch_key(&task, fd)]
                    .runtime_patches_committed
            );
            if blocked {
                assert!(
                    trampoline.end <= preferred.start
                        || trampoline.start >= preferred.start + PAGE_SIZE
                );
            } else {
                assert_eq!(trampoline.start, preferred.start);
                assert!(trampoline.end <= preferred.end);
            }
            let allowed = super::trampoline_allocation_range(
                address.as_usize()..address.as_usize() + PAGE_SIZE,
            )
            .unwrap();
            assert!(trampoline.start >= allowed.start && trampoline.end <= allowed.end);
            task.sys_close(fd).unwrap();
            task.sys_munmap(address, PAGE_SIZE).unwrap();
            task.sys_munmap(UserPtrMut::from_usize(trampoline.start), trampoline.len())
                .unwrap();
            if let Some(blocker) = blocker {
                task.sys_munmap(blocker, PAGE_SIZE).unwrap();
            }
            assert_eq!(task.global.mm.mappings(), before);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn existing_trampoline_outside_reach_uses_trap_fallback() {
        let task = init_platform();
        let mut elf = dyn_elf_with_load_size(2 * PAGE_SIZE);
        elf[96..104].copy_from_slice(&(2 * PAGE_SIZE as u64).to_le_bytes());
        elf.resize(2 * PAGE_SIZE, 0x90);
        elf[128..].fill(0x90);
        for slot in elf[128..].as_chunks_mut::<16>().0 {
            slot[..2].copy_from_slice(&[0x0f, 0x05]);
        }
        let fd = open_test_file(&task, "/unreachable-existing-trampoline", &elf);
        let key = elf_patch_key(&task, fd);
        let address = task
            .do_mmap_file(
                None,
                2 * PAGE_SIZE,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd,
                0,
            )
            .unwrap();
        task.sys_mprotect(address, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
            .unwrap();
        let (trampoline_addr, cursor) = {
            let mut cache = task.global.elf_patch_cache.lock();
            let state = cache.get_mut(&key).unwrap();
            assert!(state.runtime_patches_committed);
            let allowed =
                super::trampoline_allocation_range(state.load_span.clone().unwrap()).unwrap();
            let original = state.trampoline_addr;
            // Pretend the trampoline lies just beyond reach of the image.
            state.trampoline_addr = allowed.end;
            (original, state.trampoline_cursor)
        };
        let second = UserPtrMut::<u8>::from_usize(address.as_usize() + PAGE_SIZE);
        task.sys_mprotect(second, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
            .unwrap();
        let patched = second.to_owned_slice::<Platform>(PAGE_SIZE).unwrap();
        for offset in (0..PAGE_SIZE).step_by(16) {
            assert_eq!(&patched[offset..offset + 2], &[0xf1, 0xf4]);
        }
        assert_eq!(
            mapping_permissions(&task, second),
            MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC
        );
        let tramp_len = {
            let mut cache = task.global.elf_patch_cache.lock();
            let state = cache.get_mut(&key).unwrap();
            assert_eq!(state.trampoline_cursor, cursor);
            state.trampoline_addr = trampoline_addr;
            state.trampoline_mapped_len
        };
        task.sys_close(fd).unwrap();
        task.sys_munmap(address, 2 * PAGE_SIZE).unwrap();
        task.sys_munmap(UserPtrMut::from_usize(trampoline_addr), tramp_len)
            .unwrap();
    }

    #[test]
    fn released_pre_patched_reservation_is_never_unmapped_or_replaced() {
        let task = init_platform();
        let before = task.global.mm.mappings();
        let fd = open_test_file(
            &task,
            "/released-pre-patched",
            &pre_patched_dyn_elf(PAGE_SIZE, 2 * PAGE_SIZE),
        );
        let key = elf_patch_key(&task, fd);
        let address = task
            .do_mmap_file(
                None,
                PAGE_SIZE,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd,
                PAGE_SIZE,
            )
            .unwrap();
        let reservation = task.global.elf_patch_cache.lock()[&key]
            .pre_patched_trampoline_reservation
            .clone()
            .unwrap();
        task.sys_munmap(UserPtrMut::from_usize(reservation.start), reservation.len())
            .unwrap();
        assert!(
            task.global.elf_patch_cache.lock()[&key]
                .pre_patched_trampoline_reservation
                .is_none()
        );
        let neighbor = task
            .do_mmap(
                Some(reservation.start),
                PAGE_SIZE,
                ProtFlags::PROT_READ_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED_NOREPLACE,
                |_| Ok(0),
            )
            .unwrap();
        neighbor
            .copy_from_slice::<Platform>(0, b"neighbor")
            .unwrap();
        {
            let cache = task.global.elf_patch_cache.lock();
            let state = &cache[&key];
            assert_eq!(state.trampoline_addr, reservation.start);
            assert!(!task.trampoline_range_is_safe_to_map(
                state,
                reservation.start,
                reservation.len()
            ));
        }
        // The trampoline would overlap live memory outside the load span.
        assert_eq!(
            task.do_mmap_file(
                Some(address.as_usize()),
                PAGE_SIZE,
                ProtFlags::PROT_READ_EXEC,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                fd,
                PAGE_SIZE,
            )
            .err(),
            Some(Errno::ENOMEM)
        );
        task.sys_close(fd).unwrap();
        assert_eq!(
            &*neighbor.to_owned_slice::<Platform>(8).unwrap(),
            b"neighbor"
        );
        assert_eq!(
            mapping_permissions(&task, neighbor),
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE
        );
        task.sys_munmap(neighbor, PAGE_SIZE).unwrap();
        assert_eq!(task.global.mm.mappings(), before);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn removing_file_suffix_keeps_surviving_code_patchable() {
        let task = init_platform();
        let mut elf = minimal_dyn_elf();
        elf[128..].fill(0x90);
        elf[PAGE_SIZE / 2..PAGE_SIZE / 2 + 2].copy_from_slice(&[0x0f, 0x05]);
        let fd = open_test_file(&task, "/file-suffix", &elf);
        for shrink in [false, true] {
            let address = task
                .do_mmap_file(
                    None,
                    2 * PAGE_SIZE,
                    ProtFlags::PROT_READ,
                    MapFlags::MAP_PRIVATE,
                    fd,
                    0,
                )
                .unwrap();
            if shrink {
                task.sys_mremap(
                    address,
                    2 * PAGE_SIZE,
                    PAGE_SIZE,
                    litebox_common_linux::MRemapFlags::empty(),
                    0,
                )
                .unwrap();
            } else {
                task.sys_munmap(
                    UserPtrMut::from_usize(address.as_usize() + PAGE_SIZE),
                    PAGE_SIZE,
                )
                .unwrap();
            }
            task.sys_mprotect(address, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
                .unwrap();
            let trampoline = {
                let cache = task.global.elf_patch_cache.lock();
                let state = &cache[&elf_patch_key(&task, fd)];
                assert!(state.runtime_patches_committed);
                assert_eq!(
                    state.file_mappings.iter().cloned().collect::<Vec<_>>(),
                    core::iter::once(address.as_usize()..address.as_usize() + PAGE_SIZE)
                        .collect::<Vec<_>>(),
                );
                state.trampoline_addr..state.trampoline_addr + state.trampoline_mapped_len
            };
            let key = elf_patch_key(&task, fd);
            task.global.elf_patch_cache.lock().remove(&key).unwrap();
            task.sys_munmap(UserPtrMut::from_usize(trampoline.start), trampoline.len())
                .unwrap();
            task.sys_munmap(address, PAGE_SIZE).unwrap();
        }
        task.sys_close(fd).unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn adjacent_file_mappings_rewrite_across_mapping_and_permission_boundaries() {
        let task = init_platform();
        let mut elf = dyn_elf_with_load_size(2 * PAGE_SIZE);
        elf.resize(2 * PAGE_SIZE, 0x90);
        elf[128..].fill(0x90);
        elf[PAGE_SIZE - 1..=PAGE_SIZE].copy_from_slice(&[0x0f, 0x05]);
        let fd = open_test_file(&task, "/adjacent-file-mappings", &elf);
        let address = task
            .do_mmap_file(
                None,
                2 * PAGE_SIZE,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd,
                0,
            )
            .unwrap();
        task.sys_mmap(
            address.as_usize() + PAGE_SIZE,
            PAGE_SIZE,
            ProtFlags::PROT_READ_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            fd,
            PAGE_SIZE,
        )
        .unwrap();
        {
            let cache = task.global.elf_patch_cache.lock();
            assert_eq!(
                cache[&elf_patch_key(&task, fd)]
                    .file_mappings
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>(),
                core::iter::once(address.as_usize()..address.as_usize() + 2 * PAGE_SIZE)
                    .collect::<Vec<_>>(),
            );
        }
        task.sys_mprotect(address, 2 * PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
            .unwrap();
        let rewritten = UserPtrMut::<u8>::from_usize(address.as_usize() + PAGE_SIZE - 1)
            .to_owned_slice::<Platform>(2)
            .unwrap();
        assert_ne!(rewritten.as_ref(), &[0x0f, 0x05]);
        task.sys_munmap(address, 2 * PAGE_SIZE).unwrap();
        task.sys_close(fd).unwrap();
    }

    #[test]
    fn clearing_file_mapping_coverage_preserves_surviving_ranges() {
        let task = init_platform();
        let fd = open_test_file(&task, "/file-mapping-coverage", &minimal_dyn_elf());
        let key = elf_patch_key(&task, fd);
        let start = 16 * PAGE_SIZE;
        let end = start + 4 * PAGE_SIZE;
        let mut state = runtime_patch_state(core::iter::once(start..end).collect(), 0, false);
        state.patched_ranges.insert((start, 4 * PAGE_SIZE));
        task.global
            .elf_patch_cache
            .lock()
            .insert(key.clone(), state);

        task.clear_file_mappings_for_range(start + PAGE_SIZE, PAGE_SIZE);
        {
            let cache = task.global.elf_patch_cache.lock();
            assert_eq!(
                cache[&key]
                    .file_mappings
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>(),
                [start..start + PAGE_SIZE, start + 2 * PAGE_SIZE..end],
            );
            assert!(cache[&key].patched_ranges.is_empty());
        }
        task.clear_file_mappings_for_range(start, PAGE_SIZE);
        task.clear_file_mappings_for_range(end - PAGE_SIZE, PAGE_SIZE);
        {
            let cache = task.global.elf_patch_cache.lock();
            assert_eq!(
                cache[&key]
                    .file_mappings
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>(),
                core::iter::once(start + 2 * PAGE_SIZE..end - PAGE_SIZE).collect::<Vec<_>>(),
            );
        }
        task.sys_close(fd).unwrap();
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn clearing_trampoline_mappings_updates_aarch64_state() {
        let task = init_platform();
        let fd = open_test_file(&task, "/trampoline-invalidation", &minimal_dyn_elf());
        let key = elf_patch_key(&task, fd);
        let start = 16 * PAGE_SIZE;
        for removes_all in [false, true] {
            let mut state = runtime_patch_state(RangeSet::new(), start, true);
            state.trampoline_mapped_len = 2 * PAGE_SIZE;
            task.global
                .elf_patch_cache
                .lock()
                .insert(key.clone(), state);
            task.clear_file_mappings_for_range(
                start,
                if removes_all {
                    2 * PAGE_SIZE
                } else {
                    PAGE_SIZE
                },
            );
            let state = task.global.elf_patch_cache.lock().remove(&key).unwrap();
            assert!(!state.trampoline_is_populated());
            assert_eq!(state.arch.trampoline_invalidated, !removes_all);
            assert_eq!(state.trampoline_mapped, !removes_all);
            assert_eq!(
                state.trampoline_mapped_len,
                if removes_all { 0 } else { 2 * PAGE_SIZE },
            );
        }
        task.sys_close(fd).unwrap();
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    #[test]
    fn mprotect_patches_only_mapped_runs() {
        let task = init_platform();
        let mut content = alloc::vec![0x90; 3 * PAGE_SIZE];
        content[PAGE_SIZE / 2] = 0x0f;
        content[PAGE_SIZE / 2 + 1] = 0x05;
        create_file(&task, "/mprotect-mapped-run", &content);
        let fd = i32::try_from(
            task.sys_open("/mprotect-mapped-run", OFlags::RDONLY, Mode::empty())
                .expect("test file should open"),
        )
        .expect("file descriptor should fit i32");
        let address = task
            .do_mmap_file(
                None,
                3 * PAGE_SIZE,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd,
                0,
            )
            .expect("file mapping should succeed");
        task.global.elf_patch_cache.lock().insert(
            elf_patch_key(&task, fd),
            runtime_patch_state(
                core::iter::once(address.as_usize()..address.as_usize() + 3 * PAGE_SIZE).collect(),
                address.as_usize() + 3 * PAGE_SIZE,
                false,
            ),
        );

        assert_eq!(
            task.sys_mremap(
                address,
                3 * PAGE_SIZE,
                PAGE_SIZE,
                litebox_common_linux::MRemapFlags::empty(),
                0,
            )
            .expect("file mapping should shrink")
            .as_usize(),
            address.as_usize()
        );
        assert_eq!(
            task.sys_mprotect(address, 3 * PAGE_SIZE, ProtFlags::PROT_READ_EXEC),
            Err(Errno::ENOMEM),
            "mprotect should report the unmapped tail",
        );

        let rewritten = UserPtrMut::<u8>::from_usize(address.as_usize() + PAGE_SIZE / 2)
            .to_owned_slice::<Platform>(2)
            .expect("rewritten bytes should remain readable");
        assert_ne!(rewritten.as_ref(), &[0x0f, 0x05]);

        task.sys_munmap(address, PAGE_SIZE)
            .expect("test mapping should unmap");
        task.sys_close(fd).expect("test file should close");
    }

    #[test]
    fn permission_restoration_continues_after_error() {
        let task = init_platform();
        let missing = task
            .do_mmap(
                None,
                PAGE_SIZE,
                ProtFlags::PROT_READ_WRITE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                |_| Ok(0),
            )
            .expect("first test mapping should succeed");
        let surviving = task
            .do_mmap(
                None,
                PAGE_SIZE,
                ProtFlags::PROT_READ_WRITE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                |_| Ok(0),
            )
            .expect("second test mapping should succeed");
        task.sys_munmap(missing, PAGE_SIZE)
            .expect("first test mapping should unmap");

        assert!(
            task.restore_page_permissions(&[
                (missing.as_usize(), PAGE_SIZE, ProtFlags::PROT_READ),
                (surviving.as_usize(), PAGE_SIZE, ProtFlags::PROT_READ),
            ])
            .is_err()
        );
        assert_eq!(
            mapping_permissions(&task, surviving),
            MemoryRegionPermissions::READ
        );

        task.sys_munmap(surviving, PAGE_SIZE)
            .expect("second test mapping should unmap");
    }

    #[test]
    fn trampoline_range_covers_whole_code_span_and_saturates_at_address_limits() {
        let distance = litebox_syscall_rewriter::MAX_TRAMPOLINE_DISPLACEMENT;
        assert_eq!(
            super::trampoline_allocation_range(0..PAGE_SIZE),
            Some(0..distance)
        );
        assert_eq!(
            super::trampoline_allocation_range(usize::MAX - PAGE_SIZE..usize::MAX),
            Some(usize::MAX - distance..usize::MAX),
        );
        assert_eq!(
            super::trampoline_allocation_range(PAGE_SIZE..PAGE_SIZE),
            None
        );
        assert_eq!(super::trampoline_allocation_range(0..2 * distance), None);
        assert_eq!(
            super::trampoline_allocation_range(distance..distance + PAGE_SIZE),
            Some(PAGE_SIZE..2 * distance),
        );
    }
}
