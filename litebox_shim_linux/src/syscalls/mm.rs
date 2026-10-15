// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.
//! Most of these syscalls which are not backed by files are implemented in [`litebox_common_linux::mm`].

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use core::ops::Range;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox_common_linux::{
    MRemapFlags, MapFlags, ProtFlags,
    errno::Errno,
    loader::{
        TRAMPOLINE_HEADER_SIZE, TrampolineHeaderError, TrampolineLayout, parse_trampoline_header,
    },
    mm::MmapPlacement,
    vmem::{MappingError, PAGE_SIZE, VmemProtectError},
};
use litebox_syscall_rewriter::trampoline_allocation_range;

use crate::FileFd;
use crate::ShimPlatform;
use crate::Task;
use crate::UserPtrMut;
use crate::syscalls::file::AnyTypedFd;
#[cfg(target_arch = "aarch64")]
use alloc::vec::Vec;
use litebox::utils::TruncateExt as _;
use litebox_common_linux::vmem::VmFlags;
use object::elf::{ET_DYN, FileHeader64, PT_LOAD, ProgramHeader64};
use object::endian::LittleEndian;
use rangemap::RangeSet;
#[cfg(target_arch = "aarch64")]
use zerocopy::FromZeros as _;

#[cfg(not(target_pointer_width = "64"))]
compile_error!("ELF patching code assumes 64-bit pointers (u64 <-> usize is lossless)");

const ENDIAN: LittleEndian = LittleEndian;

#[cfg(target_arch = "x86_64")]
const RUNTIME_TRAMPOLINE_SIZE: usize =
    litebox_common_linux::loader::RUNTIME_TRAMPOLINE_RESERVATION_SIZE;

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
    let options = crate::aarch64_rewrite_options();
    if options.virtualizes_x18() {
        let x18 = offset
            .checked_add(
                u16::try_from(litebox_syscall_rewriter::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP)
                    .expect("guest x18 slot delta fits in a gate offset"),
            )
            .ok_or_else(|| alloc::string::String::from("guest x18 offset overflow"))?;
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

pub(super) fn prot_flags_from_permissions(permissions: MemoryRegionPermissions) -> ProtFlags {
    let mut prot = ProtFlags::PROT_NONE;
    prot.set(
        ProtFlags::PROT_READ,
        permissions.contains(MemoryRegionPermissions::READ),
    );
    prot.set(
        ProtFlags::PROT_WRITE,
        permissions.contains(MemoryRegionPermissions::WRITE),
    );
    prot.set(
        ProtFlags::PROT_EXEC,
        permissions.contains(MemoryRegionPermissions::EXEC),
    );
    prot
}

type ProtectionRange = (usize, usize, ProtFlags);
type PatchRange = (ElfPatchKey, usize, usize, alloc::vec::Vec<ProtectionRange>);

fn push_patch_range(
    result: &mut alloc::vec::Vec<PatchRange>,
    fd: &ElfPatchKey,
    protections: &mut alloc::vec::Vec<ProtectionRange>,
) {
    let (Some(first), Some(last)) = (protections.first(), protections.last()) else {
        return;
    };
    let start = first.0;
    let end = last.0 + last.1;
    result.push((fd.clone(), start, end - start, core::mem::take(protections)));
}

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
    #[cfg(target_arch = "aarch64")]
    code_metadata: Option<litebox_syscall_rewriter::aarch64::ElfCodeMetadata>,
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
    #[cfg(target_arch = "aarch64")]
    trampoline_invalidated: bool,
    #[cfg(target_arch = "aarch64")]
    code_metadata: Option<litebox_syscall_rewriter::aarch64::ElfCodeMetadata>,
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

impl ElfPatchState {
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn trampoline_is_populated(&self) -> bool {
        self.trampoline_mapped && !self.trampoline_invalidated
    }
}

/// Identity of a resolved filesystem descriptor.
pub(crate) struct ElfPatchKey(pub(crate) Arc<FileFd>);

impl core::fmt::Debug for ElfPatchKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("ElfPatchKey")
            .field(&Arc::as_ptr(&self.0))
            .finish()
    }
}

impl Clone for ElfPatchKey {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl PartialEq for ElfPatchKey {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ElfPatchKey {}

impl PartialOrd for ElfPatchKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ElfPatchKey {
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
pub(crate) type ElfPatchCache = BTreeMap<ElfPatchKey, ElfPatchState>;

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
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

impl<Platform: ShimPlatform> Task<Platform> {
    #[inline]
    pub(crate) fn do_mmap(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        op: impl FnOnce(UserPtrMut<u8>) -> Result<usize, MappingError>,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        let fixed_start = suggested_addr.filter(|_| flags.contains(MapFlags::MAP_FIXED));
        self.global.mm.do_mmap(
            suggested_addr,
            len,
            prot,
            flags,
            MmapPlacement {
                direction: litebox::platform::page_mgmt::AllocationDirection::TopDown,
                allowed_range: None,
            },
            |pointer| {
                if let Some(start) = fixed_start {
                    self.clear_file_mappings_for_range(start, len);
                }
                op(pointer)
            },
        )
    }

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
        let typed_fd = self.typed_fd(fd)?;
        let AnyTypedFd::Fs(file_fd) = &typed_fd else {
            return Err(Errno::ENODEV);
        };

        let patch_key = ElfPatchKey(Arc::clone(file_fd));
        let syscall_entry = self.global.platform.get_syscall_entry_point();
        let metadata = if (syscall_entry != 0 || !is_exec)
            && !self.global.elf_patch_cache.lock().contains_key(&patch_key)
        {
            Some(self.read_elf_patch_metadata(&patch_key, offset))
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
                        error:? = error, fd:? = fd, offset:? = offset;
                        "failed to determine pre-patched ELF placement"
                    );
                })?
        } else {
            None
        };
        let allocation_len = trampoline_extent.as_ref().map_or(len, |extent| extent.end);
        let reservation = if trampoline_extent.is_some() {
            Some(
                self.do_mmap(
                    suggested_addr,
                    allocation_len,
                    ProtFlags::PROT_NONE,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
                    |_| Ok(0),
                )
                .map_err(Errno::from)?,
            )
        } else {
            None
        };
        let result = self.do_mmap_file_memcpy(
            reservation
                .map(|address| address.as_usize())
                .or(suggested_addr),
            len,
            prot,
            if reservation.is_some() {
                flags | MapFlags::MAP_FIXED
            } else {
                flags
            },
            &typed_fd,
            offset,
        );
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                if let Some(reservation) = reservation
                    && let Err(cleanup) = self.sys_munmap_raw(reservation, allocation_len)
                {
                    litebox_util_log::warn!(
                        error:? = cleanup;
                        "failed to release pre-patched ELF reservation"
                    );
                }
                return Err(error.into());
            }
        };

        // Whether this call cached the patch state, rather than a concurrent mapping.
        let mut inserted = false;
        let initialized = (|| {
            if let Some(metadata) = metadata {
                let init = match metadata {
                    Ok(metadata) => {
                        self.init_elf_patch_state(&patch_key, result.as_usize(), metadata)
                    }
                    Err(init) => init,
                };
                inserted = init == ElfPatchInit::Ready;
                // A missing load base is not fatal for a non-executable mapping:
                // a later mapping may reveal it.
                if init == ElfPatchInit::Malformed
                    || (is_exec && init == ElfPatchInit::MissingLoadBase)
                {
                    return Err(Errno::ENOMEM);
                }
            }
            // Runtime syscall rewriting: patch PROT_EXEC segments in-place.
            if is_exec {
                let restore_protections = [(result.as_usize(), len, prot)];
                if syscall_entry != 0 {
                    self.maybe_patch_exec_segment(
                        result,
                        len,
                        &patch_key,
                        syscall_entry,
                        Some(offset),
                        &restore_protections,
                    )
                    .map_err(|_| Errno::ENOMEM)?;
                }
            } else {
                // Track non-exec file mappings so we can patch them if they later
                // gain PROT_EXEC via mprotect.
                let mut cache = self.global.elf_patch_cache.lock();
                if let Some(state) = cache.get_mut(&patch_key) {
                    state
                        .file_mappings
                        .insert(result.as_usize()..result.as_usize() + len);
                }
            }
            // | <------------- Reservation -----------------> |
            // | mapped file | unused reservation | trampoline |
            // Clean up any excess reservation beyond the mapped length.
            if let Some(extent) = trampoline_extent {
                let tail_start = len.max(extent.start);
                if tail_start > len {
                    self.sys_munmap_raw(
                        UserPtrMut::from_usize(result.as_usize() + len),
                        tail_start - len,
                    )?;
                }
                let unused = result.as_usize() + tail_start..result.as_usize() + extent.end;
                let mut cache = self.global.elf_patch_cache.lock();
                let Some(state) = cache.get_mut(&patch_key).filter(|state| state.pre_patched)
                else {
                    litebox_util_log::warn!("pre-patched ELF changed during mapping");
                    return Err(Errno::ENOMEM);
                };
                if !inserted {
                    // A concurrent mapping cached the state; its trampoline lies elsewhere.
                    drop(cache);
                    self.sys_munmap_raw(UserPtrMut::from_usize(unused.start), unused.len())?;
                } else if !state.trampoline_mapped {
                    state.pre_patched_trampoline_reservation = Some(unused);
                }
            }
            Ok(result)
        })();
        if initialized.is_err() {
            // A failed first mapping must not retain its provisional load base.
            if inserted && reservation.is_some() {
                self.global.elf_patch_cache.lock().remove(&patch_key);
            }
            if let Err(error) = self.sys_munmap(result, allocation_len) {
                litebox_util_log::warn!(
                    error:? = error;
                    "failed to release a failed file mapping"
                );
            }
        }
        initialized
    }

    /// Map a file by reading its contents through the filesystem API into allocated pages.
    fn do_mmap_file_memcpy(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: &AnyTypedFd<Platform>,
        offset: usize,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        let op = |ptr: UserPtrMut<u8>| -> Result<usize, MappingError> {
            // Note a malicious user may unmap ptr while we are reading.
            // `sys_read` does not handle page faults, so we need to use a
            // temporary buffer to read the data from fs (without worrying page
            // faults) and write it to the user buffer with page fault handling.
            let mut file_offset = offset;
            // Read in the largest chunks the broker transfers, as each read is a round trip.
            let max_read = usize::try_from(litebox_broker_protocol::fs::MAX_FILE_TRANSFER_SIZE)
                .expect("the broker transfer size fits usize");
            let mut buffer = alloc::vec![0; len.min(max_read)];
            let mut copied = 0;
            while copied < len {
                let want = (len - copied).min(buffer.len());
                let size = self
                    .do_read(fd, &mut buffer[..want], Some(file_offset))
                    .map_err(|e| match e {
                        // The raw fd was resolved once at syscall entry and is intentionally
                        // not retained; this payload is discarded when converted to EBADF.
                        Errno::EBADF => MappingError::BadFD(-1),
                        Errno::EISDIR => MappingError::NotAFile,
                        Errno::EACCES => MappingError::NotForReading,
                        _ => unimplemented!(),
                    })?;
                if size == 0 {
                    break;
                }
                ptr.copy_from_slice::<Platform>(copied, &buffer[..size])
                    .ok_or(MappingError::MemoryAccess)?;
                copied += size;
                file_offset += size;
            }
            Ok(copied)
        };
        let ptr = self.do_mmap(suggested_addr, len, ProtFlags::PROT_READ_WRITE, flags, op)?;
        if prot != ProtFlags::PROT_READ_WRITE && self.sys_mprotect_raw(ptr, len, prot).is_err() {
            // TODO: Protection may be unsupported (e.g. write-only), or another thread may
            // have unmapped the range. Best-effort cleanup may unmap a replacement
            // mapping if another thread unmaps and remaps this range before cleanup.
            let _ = self.sys_munmap_raw(ptr, len);
            return Err(VmemProtectError::UnsupportedProtection.into());
        }
        Ok(ptr)
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

        let aligned_len = len
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Errno::ENOMEM)?;
        if offset.checked_add(aligned_len).is_none() {
            return Err(Errno::EOVERFLOW);
        }

        let suggested_addr = if addr == 0 { None } else { Some(addr) };
        if flags.contains(MapFlags::MAP_ANONYMOUS) {
            self.do_mmap(suggested_addr, aligned_len, prot, flags, |_| Ok(0))
                .map_err(Errno::from)
        } else {
            self.do_mmap_file(suggested_addr, aligned_len, prot, flags, fd, offset)
        }
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
        self.global.mm.sys_munmap(addr, len)
    }

    /// Clear `file_mappings` entries for any segments that overlap the
    /// unmapped range, so that re-mapping the same file region will be
    /// re-patched instead of skipped.
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

    /// Handle syscall `mprotect`
    #[inline]
    pub(crate) fn sys_mprotect(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        if !addr.as_usize().is_multiple_of(PAGE_SIZE)
            || !len.is_multiple_of(PAGE_SIZE)
            || addr.as_usize().checked_add(len).is_none()
            || prot.bits() & !ProtFlags::PROT_READ_WRITE_EXEC.bits() != 0
        {
            return Err(Errno::EINVAL);
        }

        // Intercept transitions to PROT_EXEC: patch unpatched file mappings.
        if prot.contains(ProtFlags::PROT_EXEC) {
            let syscall_entry = self.global.platform.get_syscall_entry_point();
            if syscall_entry != 0 {
                self.maybe_patch_on_mprotect_exec(addr, len, syscall_entry)?;
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
            self.sys_mprotect_raw(UserPtrMut::<u8>::from_usize(sub.start), sub.len(), prot)?;
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
        self.global.mm.sys_mprotect(addr, len, prot)
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

    #[inline]
    pub(crate) fn sys_mremap(
        &self,
        old_addr: UserPtrMut<u8>,
        old_size: usize,
        new_size: usize,
        flags: MRemapFlags,
        new_addr: usize,
    ) -> Result<UserPtrMut<u8>, Errno> {
        let result = self
            .global
            .mm
            .sys_mremap(old_addr, old_size, new_size, flags, new_addr)?;
        let old_size = old_size.next_multiple_of(PAGE_SIZE);
        let new_size = new_size.next_multiple_of(PAGE_SIZE);
        if result.as_usize() != old_addr.as_usize() {
            self.clear_file_mappings_for_range(old_addr.as_usize(), old_size);
            self.clear_file_mappings_for_range(result.as_usize(), new_size);
        } else if new_size < old_size {
            self.clear_file_mappings_for_range(old_addr.as_usize() + new_size, old_size - new_size);
        }
        Ok(result)
    }

    /// Handle syscall `brk`
    #[inline]
    pub(crate) fn sys_brk(&self, addr: UserPtrMut<u8>) -> Result<usize, Errno> {
        // On failure, Linux returns the current break rather than a negative errno.
        unsafe {
            self.global
                .mm
                .brk(addr.as_usize())
                .or_else(|_| self.global.mm.brk(0))
        }
        .map_err(Errno::from)
    }

    /// Handle syscall `madvise`
    #[inline]
    pub(crate) fn sys_madvise(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        advice: litebox_common_linux::MadviseBehavior,
    ) -> Result<(), Errno> {
        self.global.mm.sys_madvise(addr, len, advice)
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
        let mappings = self.global.mm.mappings();

        // Find unpatched file mappings that overlap this mprotect range.
        // Preserve the VMA boundaries for restoration without splitting the
        // instruction stream passed to the runtime rewriter.
        let to_patch: alloc::vec::Vec<PatchRange> = {
            let cache = self.global.elf_patch_cache.lock();
            let mut result = alloc::vec::Vec::new();
            for (fd, state) in cache.iter() {
                #[cfg(target_arch = "x86_64")]
                if state.pre_patched {
                    continue;
                }
                for segment in state
                    .file_mappings
                    .overlapping(mprotect_start..mprotect_end)
                {
                    let patch_start = segment.start.max(mprotect_start);
                    let patch_end = segment.end.min(mprotect_end);
                    let mut restore_protections: alloc::vec::Vec<ProtectionRange> =
                        alloc::vec::Vec::new();
                    for (mapping, flags) in &mappings {
                        let start = patch_start.max(mapping.start);
                        let end = patch_end.min(mapping.end);
                        if start < end {
                            if restore_protections.last().is_some_and(
                                |(last_start, last_len, _)| {
                                    last_start.saturating_add(*last_len) != start
                                },
                            ) {
                                push_patch_range(&mut result, fd, &mut restore_protections);
                            }
                            restore_protections.push((
                                start,
                                end - start,
                                prot_flags_from_permissions((*flags).into()),
                            ));
                        }
                    }
                    push_patch_range(&mut result, fd, &mut restore_protections);
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

    /// Read address-independent ELF patch metadata for an fd on its first mmap.
    ///
    /// Derives patch state and the architecture-specific trampoline fallback.
    ///
    /// The `file_offset` parameter identifies the segment being mapped so its
    /// virtual address can later establish the ET_DYN load base.
    ///
    /// Requires the supported architectures' common 64-bit ELF layout.
    fn read_elf_patch_metadata(
        &self,
        fd: &ElfPatchKey,
        file_offset: usize,
    ) -> Result<ElfPatchMetadata, ElfPatchInit> {
        // Read the ELF header (64 bytes for Elf64).
        let mut ehdr_buf = [0u8; core::mem::size_of::<FileHeader64<LittleEndian>>()];
        match self
            .global
            .litebox
            .read_file(&fd.0, &mut ehdr_buf, Some(0), None)
        {
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
        match self
            .global
            .litebox
            .read_file(&fd.0, &mut phdrs_buf, Some(e_phoff), None)
        {
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

        let trampoline_layout = match self.read_trampoline_layout(&fd.0) {
            Err(error) => {
                litebox_util_log::debug!(
                    file_offset:? = file_offset, error:? = error;
                    "malformed LiteBox trampoline"
                );
                return Err(ElfPatchInit::Malformed);
            }
            Ok(layout) => layout,
        };

        #[cfg(target_arch = "aarch64")]
        let (code_metadata, trampoline_capacity) = if trampoline_layout.is_some() {
            (None, 0)
        } else {
            let scanned = self
                .global
                .litebox
                .file_status(&fd.0)
                .ok()
                .and_then(|stat| {
                    let file_size = usize::try_from(stat.size).ok()?;
                    let word_len = file_size.div_ceil(8);
                    let mut words = u64::new_vec_zeroed(word_len).ok()?;
                    let bytes = zerocopy::IntoBytes::as_mut_bytes(words.as_mut_slice());
                    self.read_file_exact_at(&fd.0, &mut bytes[..file_size], 0)
                        .ok()?;
                    let metadata =
                        litebox_syscall_rewriter::aarch64::ElfCodeMetadata::parse_aligned_in_place(
                            &mut words, file_size,
                        )
                        .ok()?;
                    let upper_bound = metadata
                        .trampoline_size_upper_bound(
                            &zerocopy::IntoBytes::as_bytes(words.as_slice())[..file_size],
                            crate::aarch64_rewrite_options(),
                        )
                        .ok();
                    Some((metadata, upper_bound))
                });
            if let Some((metadata, upper_bound)) = scanned {
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
                        fd:? = fd;
                        "AArch64 trampoline size estimate unavailable; using one-page trampoline with trap fallback"
                    );
                }
                litebox_util_log::debug!(
                    fd:? = fd,
                    executable_bytes:? = executable_bytes,
                    identified_bytes:? = identified_bytes,
                    trampoline_upper_bound:? = upper_bound,
                    trampoline_capacity:? = capacity;
                    "pre-scanned AArch64 ELF for runtime rewriting"
                );
                (Some(metadata), capacity)
            } else {
                litebox_util_log::warn!(
                    fd:? = fd;
                    "AArch64 ELF pre-scan unavailable; using one-page trampoline with trap fallback"
                );
                (None, PAGE_SIZE)
            }
        };
        #[cfg(target_arch = "x86_64")]
        let trampoline_capacity = if trampoline_layout.is_some() {
            0
        } else {
            RUNTIME_TRAMPOLINE_SIZE
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
            #[cfg(target_arch = "aarch64")]
            code_metadata,
            trampoline_capacity,
        })
    }

    /// Relocate parsed ELF metadata and cache patch state after mapping succeeds.
    fn init_elf_patch_state(
        &self,
        fd: &ElfPatchKey,
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
            #[cfg(target_arch = "aarch64")]
            code_metadata,
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
                #[cfg(target_arch = "aarch64")]
                trampoline_invalidated: false,
                #[cfg(target_arch = "aarch64")]
                code_metadata,
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
        let end = range.end;
        if state
            .load_span
            .as_ref()
            .is_some_and(|span| range.start >= span.start && range.end <= span.end)
        {
            return true;
        }
        for (range, flags) in self.global.mm.mappings() {
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

    fn read_file_exact_at(
        &self,
        fd: &FileFd,
        mut data: &mut [u8],
        mut offset: usize,
    ) -> Result<(), Errno> {
        while !data.is_empty() {
            let read = self
                .global
                .litebox
                .read_file(fd, data, Some(offset), None)
                .map_err(Errno::from)?;
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
    fn read_trampoline_layout(
        &self,
        fd: &FileFd,
    ) -> Result<Option<TrampolineLayout>, TrampolineHeaderError> {
        let Ok(stat) = self.global.litebox.file_status(fd) else {
            return Ok(None);
        };
        let Some(header_offset) = stat.size.checked_sub(TRAMPOLINE_HEADER_SIZE as u64) else {
            return Ok(None);
        };
        let Ok(read_offset) = usize::try_from(header_offset) else {
            return Ok(None);
        };

        let mut tail = [0u8; TRAMPOLINE_HEADER_SIZE];
        match self
            .global
            .litebox
            .read_file(fd, &mut tail, Some(read_offset), None)
        {
            Ok(n) if n == TRAMPOLINE_HEADER_SIZE => {}
            _ => return Ok(None),
        }
        parse_trampoline_header(&tail, header_offset)
    }

    /// Apply the trap fallback to a mapped code segment: replace every patch
    /// site with the rewriter's trap, then restore the caller-selected permissions.
    ///
    /// If `already_rw` is true, the segment is assumed to already be writable
    /// and the initial mprotect RW is skipped.
    ///
    /// Returns an error if those permissions cannot be restored.
    /// Panics on other infrastructure failures (mprotect/read/write/disassembly).
    #[cfg(target_arch = "aarch64")]
    fn apply_aarch64_trap_fallback(
        &self,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        already_rw: bool,
        ranges: Option<&litebox_syscall_rewriter::aarch64::CodeScanRanges>,
        restore_protections: &[ProtectionRange],
    ) -> Result<(), Errno> {
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

        // Restore the caller-selected permissions.
        self.restore_page_permissions(restore_protections)
    }

    #[cfg(target_arch = "x86_64")]
    fn apply_trap_fallback(
        &self,
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

        // Restore the caller-selected permissions.
        self.restore_page_permissions(restore_protections)
    }

    /// Patch an executable segment in-place after it has been mapped.
    ///
    /// For pre-patched binaries: maps the trampoline from the file and writes
    /// the syscall entry point.
    /// For unpatched binaries: calls `patch_code_segment()` to rewrite syscall
    /// instructions and places the generated stubs in the trampoline region.
    ///
    /// Returns an error when a pre-patched binary's trampoline cannot be set
    /// up or the caller-selected code permissions cannot be restored.
    fn maybe_patch_exec_segment(
        &self,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        fd: &ElfPatchKey,
        syscall_entry: usize,
        file_offset: Option<usize>,
        restore_protections: &[ProtectionRange],
    ) -> Result<(), Errno> {
        #[cfg(target_arch = "x86_64")]
        let _ = file_offset;
        // This lock guards the elf_patch_cache and is held for the entire
        // patching operation. In practice this is fine because the dynamic
        // linker loads shared libraries sequentially.
        let mut cache = self.global.elf_patch_cache.lock();
        let Some(state) = cache.get_mut(fd) else {
            return Ok(()); // No patch state — not an ELF we're tracking
        };
        #[cfg(target_arch = "aarch64")]
        if state.trampoline_invalidated {
            return Err(Errno::ENOMEM);
        }

        if state.pre_patched {
            // Pre-patched binary: map the trampoline data from the file.
            if !state.trampoline_mapped && state.trampoline_file_size > 0 {
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
                    let _ =
                        self.sys_munmap_raw(UserPtrMut::<u8>::from_usize(actual_addr), tramp_len);
                    return Err(Errno::ENOMEM);
                }
                // The trampoline replaced any reservation, and failures below unmap it.
                state.pre_patched_trampoline_reservation = None;

                // Read trampoline data from the file.
                let mut tramp_data = alloc::vec![0u8; state.trampoline_file_size];
                let file_off = state.trampoline_file_offset.trunc();
                let tramp_ptr = UserPtrMut::<u8>::from_usize(tramp_addr);
                if self
                    .read_file_exact_at(&fd.0, &mut tramp_data, file_off)
                    .is_err()
                {
                    let _ = self.sys_munmap_raw(tramp_ptr, tramp_len);
                    return Err(Errno::ENOMEM);
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
            }
            return Ok(());
        }

        // ── Runtime patching path (unpatched binaries) ───────────────

        #[cfg(target_arch = "aarch64")]
        let scan_ranges = file_offset.and_then(|file_offset| {
            state
                .code_metadata
                .as_ref()
                .and_then(|metadata| metadata.ranges_for_mapping(file_offset as u64, len).ok())
        });
        #[cfg(target_arch = "aarch64")]
        let apply_trap_fallback = |mapped_addr, len, already_rw| {
            self.apply_aarch64_trap_fallback(
                mapped_addr,
                len,
                already_rw,
                scan_ranges.as_ref(),
                restore_protections,
            )
        };
        #[cfg(target_arch = "x86_64")]
        let apply_trap_fallback = |mapped_addr, len, already_rw| {
            self.apply_trap_fallback(mapped_addr, len, already_rw, restore_protections)
        };

        let addr_usize = mapped_addr.as_usize();
        let mut code_range = addr_usize..addr_usize.saturating_add(len);
        if let Some(load_span) = &state.load_span {
            code_range.start = code_range.start.min(load_span.start);
            code_range.end = code_range.end.max(load_span.end);
        }
        let Some(allowed) = trampoline_allocation_range(code_range) else {
            litebox_util_log::warn!("ELF and code mapping span exceeds trampoline branch reach");
            return apply_trap_fallback(mapped_addr, len, false);
        };
        if state.trampoline_mapped
            && (state.trampoline_addr < allowed.start
                || state
                    .trampoline_addr
                    .saturating_add(state.trampoline_mapped_len)
                    > allowed.end)
        {
            litebox_util_log::warn!("ELF trampoline is outside branch reach; using trap fallback");
            return apply_trap_fallback(mapped_addr, len, false);
        }
        if !state.trampoline_mapped {
            if state.trampoline_capacity == 0 {
                litebox_util_log::warn!("ELF trampoline capacity unavailable; using trap fallback");
                return apply_trap_fallback(mapped_addr, len, false);
            }
            // Prefer the region the loader keeps free past the image, so that the
            // trampoline does not cap brk; otherwise search top-down within reach.
            let hint = state
                .load_span
                .as_ref()
                .and_then(|span| {
                    litebox_common_linux::loader::runtime_trampoline_reservation(span.end)
                })
                .filter(|reservation| state.trampoline_capacity <= reservation.len())
                .map(|reservation| reservation.start);
            let actual_addr_ptr = match self.do_mmap_trampoline(
                hint,
                state.trampoline_capacity,
                ProtFlags::PROT_READ_WRITE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                Some(allowed.clone()),
            ) {
                Ok(pointer) => pointer,
                Err(error) => {
                    litebox_util_log::warn!(error:? = error; "failed to allocate reachable trampoline");
                    return apply_trap_fallback(mapped_addr, len, false);
                }
            };
            let actual_addr = actual_addr_ptr.as_usize();
            state.trampoline_addr = actual_addr;

            if litebox_syscall_rewriter::TRAMPOLINE_ENTRY_POINT_BYTES != 0 {
                let entry_ptr = UserPtrMut::<u8>::from_usize(actual_addr);
                if entry_ptr
                    .copy_from_slice::<Platform>(0, &syscall_entry.to_le_bytes())
                    .is_none()
                {
                    litebox_util_log::warn!("failed to write syscall entry point to trampoline");
                    let _ = self.sys_munmap_raw(actual_addr_ptr, state.trampoline_capacity);
                    return apply_trap_fallback(mapped_addr, len, false);
                }
                state.trampoline_cursor = litebox_syscall_rewriter::TRAMPOLINE_ENTRY_POINT_BYTES;
            } else {
                state.trampoline_cursor = 0;
            }
            state.trampoline_mapped = true;
            state.trampoline_mapped_len = state.trampoline_capacity;
        }

        // Performance guard: skip if this exact range was already patched.
        let mapping_key = (mapped_addr.as_usize(), len);
        if state.patched_ranges.contains(&mapping_key) {
            return Ok(());
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
            let _ = self.restore_page_permissions(restore_protections);
            restore_trampoline_rx(self, state);
            panic!("fatal: failed to read code segment for patching");
        };
        let mut code_buf = code_owned.into_vec();
        let original_code = code_buf.clone();

        let code_vaddr = addr_usize as u64;
        let Some(aligned_cursor) = state
            .trampoline_cursor
            .checked_next_multiple_of(litebox_syscall_rewriter::TRAMPOLINE_CURSOR_ALIGN)
        else {
            let restored = apply_trap_fallback(mapped_addr, len, true);
            restore_trampoline_rx(self, state);
            return restored;
        };
        state.trampoline_cursor = aligned_cursor;
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
                        let restored = apply_trap_fallback(mapped_addr, len, true);
                        restore_trampoline_rx(self, state);
                        return restored;
                    }
                    stubs
                };
                let Some(new_cursor) = state.trampoline_cursor.checked_add(stubs.len()) else {
                    litebox_util_log::warn!("trampoline cursor overflow");
                    let restored = apply_trap_fallback(mapped_addr, len, true);
                    restore_trampoline_rx(self, state);
                    return restored;
                };
                if new_cursor > state.trampoline_mapped_len {
                    litebox_util_log::warn!(
                        "ELF trampoline capacity exhausted; using trap fallback"
                    );
                    let restored = apply_trap_fallback(mapped_addr, len, true);
                    restore_trampoline_rx(self, state);
                    return restored;
                }

                // Write stubs before patching the code so rewritten jumps
                // never target an uninitialized trampoline.
                let tramp_write_ptr =
                    UserPtrMut::<u8>::from_usize(state.trampoline_addr + state.trampoline_cursor);
                if tramp_write_ptr
                    .copy_from_slice::<Platform>(0, &stubs)
                    .is_none()
                {
                    let _ = self.restore_page_permissions(restore_protections);
                    restore_trampoline_rx(self, state);
                    panic!("fatal: failed to write trampoline stubs");
                }

                // Write patched code back to the mapped region.
                if mapped_addr
                    .copy_from_slice::<Platform>(0, &code_buf)
                    .is_none()
                {
                    let _ = mapped_addr.copy_from_slice::<Platform>(0, &original_code);
                    let _ = self.restore_page_permissions(restore_protections);
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
                    let _ = self.restore_page_permissions(restore_protections);
                    panic!("fatal: failed to write trap bytes back to code segment");
                }
                // Fall through to restore the caller-selected protections below.
            }
            Err(e) => {
                litebox_util_log::warn!(err:? = e; "patch_code_segment failed");
                let restored = apply_trap_fallback(mapped_addr, len, true);
                restore_trampoline_rx(self, state);
                return restored;
            }
        }

        // Restore the caller-selected code-segment permissions.
        let restored = self.restore_page_permissions(restore_protections);
        restore_trampoline_rx(self, state);
        restored
    }

    /// Finalize the ELF patching state for `fd`.
    ///
    /// Removes the cache entry and unmaps any trampoline that was allocated but never used.
    pub(crate) fn finalize_elf_patch(&self, fd: Arc<FileFd>) {
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
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    use litebox::platform::PageManagementProvider;
    use litebox::platform::page_mgmt::MemoryRegionPermissions;
    use litebox_broker_protocol::fs::FileMode as Mode;
    use litebox_common_linux::MRemapFlags;
    use litebox_common_linux::{
        MapFlags, OFlags, ProtFlags,
        errno::Errno,
        vmem::{NonZeroAddress, NonZeroPageSize},
    };
    use rangemap::RangeSet;

    use crate::UserPtrMut;
    use crate::syscalls::file::AnyTypedFd;
    use crate::syscalls::tests::{TestPlatform as Platform, create_file, init_platform};

    fn elf_patch_key(task: &Task<Platform>, fd: i32) -> ElfPatchKey {
        let AnyTypedFd::Fs(fd) = task.typed_fd(fd).expect("file descriptor should resolve") else {
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
            #[cfg(target_arch = "aarch64")]
            trampoline_invalidated: false,
            #[cfg(target_arch = "aarch64")]
            code_metadata: None,
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
            let capacity = super::RUNTIME_TRAMPOLINE_SIZE;
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
            assert_eq!(state.trampoline_capacity, super::RUNTIME_TRAMPOLINE_SIZE);
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
                task.sys_mremap(address, 2 * PAGE_SIZE, PAGE_SIZE, MRemapFlags::empty(), 0)
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
            assert_eq!(state.trampoline_invalidated, !removes_all);
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
            task.sys_mremap(address, 3 * PAGE_SIZE, PAGE_SIZE, MRemapFlags::empty(), 0,)
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

    /// Fail closed: an unpatched placeholder executes silently.
    #[cfg(target_arch = "aarch64")]
    mod aarch64_trampoline_gates {
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
                super::super::finalize_trampoline_gates(&StubPlatform(Some(96)), &mut trampoline);
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
            super::super::finalize_trampoline_gates(&StubPlatform(Some(96)), &mut stubs).unwrap();
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
            super::super::finalize_trampoline_gates(&StubPlatform(Some(96)), &mut tramp).unwrap();
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
            let err = super::super::finalize_trampoline_gates(&StubPlatform(None), &mut tramp)
                .unwrap_err();
            assert!(err.contains("no guest thread-pointer offset"), "{err}");
            assert_eq!(tramp, before);
        }

        #[test]
        fn an_offset_no_gate_can_encode_is_refused() {
            let mut tramp = unpatched_trampoline();
            let before = tramp.clone();
            let err = super::super::finalize_trampoline_gates(&StubPlatform(Some(4)), &mut tramp)
                .unwrap_err();
            assert!(err.contains("failed to patch"), "{err}");
            assert_eq!(tramp, before);
        }
    }

    #[test]
    fn brk_respects_initial_break_and_shrinks_within_current_page() {
        let task = init_platform();
        let initial = 0x4000_0123;
        let below_initial = 0x4000_0042;
        let grown = 0x4000_0321;
        let requested = 0x4000_0246;
        task.global.mm.set_initial_brk(initial);

        assert_eq!(
            task.sys_brk(UserPtrMut::from_usize(below_initial)),
            Ok(initial)
        );
        assert_eq!(
            task.sys_brk(UserPtrMut::from_usize(usize::MAX)),
            Ok(initial)
        );
        assert_eq!(task.sys_brk(UserPtrMut::from_usize(0)), Ok(initial));
        assert_eq!(task.sys_brk(UserPtrMut::from_usize(grown)), Ok(grown));
        assert_eq!(
            task.sys_brk(UserPtrMut::from_usize(requested)),
            Ok(requested)
        );
        assert_eq!(task.sys_brk(UserPtrMut::from_usize(0)), Ok(requested));
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
        let content = b"Hello, world!";
        let task = init_platform();
        create_file(&task, "/test.txt", content);
        let fd = i32::try_from(
            task.sys_open("/test.txt", OFlags::RDONLY, Mode::empty())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            task.sys_mmap(
                0,
                usize::MAX - super::PAGE_SIZE + 1,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd,
                0,
            )
            .unwrap_err(),
            Errno::ENOMEM
        );
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
            task.sys_mremap(addr, 0x1000, 0x2000, MRemapFlags::empty(), 0),
            Err(litebox_common_linux::errno::Errno::ENOMEM)
        ),);
        let new_addr = task
            .sys_mremap(addr, 0x1000, 0x2000, MRemapFlags::MREMAP_MAYMOVE, 0)
            .unwrap();
        task.sys_munmap(addr, 0x2000).unwrap();
        task.sys_munmap(new_addr, 0x2000).unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn self_placed_mappings_stay_below_placement_limit() {
        let task = init_platform();
        let limit = <Platform as PageManagementProvider<PAGE_SIZE>>::PLACEMENT_ADDR_MAX;
        assert!(limit < <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX);
        let below_limit = |address: UserPtrMut<u8>, len: usize| {
            assert!(
                address.as_usize() + len <= limit,
                "mapping at {:#x} crosses the placement limit {limit:#x}",
                address.as_usize(),
            );
        };
        let read_write = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE;
        let anonymous = MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE;

        let unhinted = task
            .sys_mmap(0, 2 * PAGE_SIZE, read_write, anonymous, -1, 0)
            .unwrap();
        below_limit(unhinted, 2 * PAGE_SIZE);

        let hinted = task
            .sys_mmap(limit, PAGE_SIZE, read_write, anonymous, -1, 0)
            .unwrap();
        below_limit(hinted, PAGE_SIZE);

        // Native remapping must honor the destination vmem chose instead of letting the host
        // kernel pick one, and must still carry the contents along.
        unhinted
            .write_slice_at_offset::<Platform>(0, &[0xa5; 0x10])
            .unwrap();
        let moved = task
            .sys_mremap(
                unhinted,
                PAGE_SIZE,
                4 * PAGE_SIZE,
                MRemapFlags::MREMAP_MAYMOVE,
                0,
            )
            .unwrap();
        below_limit(moved, 4 * PAGE_SIZE);
        assert_eq!(moved.read_at_offset::<Platform>(0).unwrap(), 0xa5_u8);

        let fixed = task
            .sys_mmap(
                limit,
                PAGE_SIZE,
                read_write,
                anonymous | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .unwrap();
        assert_eq!(fixed.as_usize(), limit);

        for (address, len) in [
            (unhinted, 2 * PAGE_SIZE),
            (hinted, PAGE_SIZE),
            (moved, 4 * PAGE_SIZE),
            (fixed, PAGE_SIZE),
        ] {
            task.sys_munmap(address, len).unwrap();
        }
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn repeated_moving_growth_keeps_contents() {
        const PAGE: isize = PAGE_SIZE.cast_signed();
        let task = init_platform();
        let read_write = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE;
        let anonymous = MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE;
        // Occupies the page after a mapping so that growing it has to move it.
        let block_after = |address: UserPtrMut<u8>, len: usize| {
            task.sys_mmap(
                address.as_usize() + len,
                PAGE_SIZE,
                ProtFlags::PROT_NONE,
                anonymous | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .ok()
        };

        let first = task
            .sys_mmap(0, 2 * PAGE_SIZE, read_write, anonymous, -1, 0)
            .unwrap();
        first
            .write_slice_at_offset::<Platform>(0, &[0xa5; 0x10])
            .unwrap();
        let first_block = block_after(first, 2 * PAGE_SIZE);
        let second = task
            .sys_mremap(
                first,
                2 * PAGE_SIZE,
                4 * PAGE_SIZE,
                MRemapFlags::MREMAP_MAYMOVE,
                0,
            )
            .unwrap();
        assert_ne!(second.as_usize(), first.as_usize());
        second
            .write_slice_at_offset::<Platform>(3 * PAGE, &[0x5a; 0x10])
            .unwrap();

        // The moved pages and the grown tail are separate host mappings that must move together.
        let second_block = block_after(second, 4 * PAGE_SIZE);
        let third = task
            .sys_mremap(
                second,
                4 * PAGE_SIZE,
                8 * PAGE_SIZE,
                MRemapFlags::MREMAP_MAYMOVE,
                0,
            )
            .unwrap();
        assert_ne!(third.as_usize(), second.as_usize());
        assert_eq!(third.read_at_offset::<Platform>(0).unwrap(), 0xa5_u8);
        assert_eq!(third.read_at_offset::<Platform>(3 * PAGE).unwrap(), 0x5a_u8);
        assert_eq!(third.read_at_offset::<Platform>(5 * PAGE).unwrap(), 0_u8);

        task.sys_munmap(third, 8 * PAGE_SIZE).unwrap();
        for block in [first_block, second_block].into_iter().flatten() {
            task.sys_munmap(block, PAGE_SIZE).unwrap();
        }
    }

    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "fixed address lies in Darwin's PAGEZERO"
    )]
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
        let external_platform = Platform::new();
        let mut data = alloc::vec::Vec::new();
        let mut count = 0;
        // Model an external allocator allocation that LiteBox's page manager does not track.
        let addr = loop {
            assert!(
                count < 100,
                "Failed to find a suitable address after 100 attempts"
            );
            count += 1;
            let addr = {
                use litebox::platform::page_mgmt::{
                    AllocationDirection, FixedAddressBehavior, MemoryRegionPermissions,
                    PageReservation as _,
                };

                let task_addr_min = <Platform as PageManagementProvider<4096>>::TASK_ADDR_MIN;
                let reservation_alignment =
                    <Platform as PageManagementProvider<4096>>::RESERVATION_ALIGNMENT;
                let suggested_start = task_addr_min + count * reservation_alignment;
                // SAFETY: The hint is aligned and within task bounds; no mappings are replaced.
                let reservation = unsafe {
                    <Platform as PageManagementProvider<4096>>::reserve_and_commit_pages(
                        external_platform,
                        core::iter::empty,
                        suggested_start..suggested_start + 0x1000,
                        MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                        false,
                        false,
                        FixedAddressBehavior::Hint(AllocationDirection::TopDown),
                    )
                }
                .unwrap();
                let allocation = reservation.range().start;
                data.push(reservation);
                allocation
            };

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

        // Growing without MREMAP_MAYMOVE must fail because the next page belongs to the
        // independently managed external allocation.
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

        task.sys_munmap(res, 0x1000).unwrap();
        task.sys_munmap(UserPtrMut::from_usize(addr - 0x1000), 0x1000)
            .unwrap();
        #[cfg_attr(
            target_os = "windows",
            expect(
                clippy::useless_conversion,
                reason = "tracked Windows reservations are their own release target"
            )
        )]
        for reservation in data {
            // SAFETY: The page belongs to the external provider and has no outstanding references.
            unsafe {
                <Platform as PageManagementProvider<4096>>::release_pages(
                    external_platform,
                    reservation.into(),
                )
                .unwrap();
            }
        }
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
        let content = b"Hello, shared!";
        let task = init_platform();
        create_file(&task, "/shared.txt", content);
        let fd = i32::try_from(
            task.sys_open("/shared.txt", OFlags::RDONLY, Mode::empty())
                .unwrap(),
        )
        .unwrap();

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

    #[cfg(target_arch = "aarch64")]
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
