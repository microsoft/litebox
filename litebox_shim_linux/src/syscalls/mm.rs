// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.
//! Most of these syscalls which are not backed by files are implemented in [`litebox_common_linux::mm`].

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox_common_linux::{
    HOST_PAGE_SIZE, MRemapFlags, MapFlags, ProtFlags,
    errno::Errno,
    loader::{TRAMPOLINE_HEADER_SIZE, TrampolineHeader64},
    vmem::{MappingError, PAGE_SIZE, VmemProtectError},
};

use crate::FileFd;
use crate::ShimPlatform;
use crate::Task;
use crate::UserPtrMut;
use crate::syscalls::file::AnyTypedFd;
#[cfg(target_arch = "aarch64")]
use alloc::vec::Vec;
#[cfg(target_arch = "aarch64")]
use core::ops::Range;
use litebox::utils::TruncateExt as _;
#[cfg(target_arch = "aarch64")]
use litebox_common_linux::vmem::VmFlags;
#[cfg(target_arch = "x86_64")]
use object::elf::ET_DYN;
use object::elf::{FileHeader64, PT_LOAD, ProgramHeader64};
use object::endian::LittleEndian;
use zerocopy::FromBytes as _;
#[cfg(target_arch = "aarch64")]
use zerocopy::FromZeros as _;

#[cfg(not(target_pointer_width = "64"))]
compile_error!("ELF patching code assumes 64-bit pointers (u64 <-> usize is lossless)");

const ENDIAN: LittleEndian = LittleEndian;

#[cfg(target_arch = "aarch64")]
mod islands;

/// Finalizes every gate with the platform's guest thread-pointer offset.
///
/// # Errors
///
/// Missing, unencodable, or unpatched offsets return an error.
#[cfg(all(test, target_arch = "aarch64"))]
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

fn prot_flags_from_permissions(permissions: MemoryRegionPermissions) -> ProtFlags {
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

/// Per-call source provenance, never cached as a descriptor's current bias.
pub(crate) struct FileMappingSource {
    pub offset: usize,
    #[cfg(target_arch = "aarch64")]
    pub load_bias: Option<usize>,
}

impl From<usize> for FileMappingSource {
    fn from(offset: usize) -> Self {
        Self {
            offset,
            #[cfg(target_arch = "aarch64")]
            load_bias: None,
        }
    }
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

/// Per-descriptor state for the shim's runtime ELF syscall rewriter.
///
/// AArch64 runtime and AOT instances live in `islands`; direct fields serve x86. Descriptor identity is retained across close
/// while AArch64 mappings or island references remain live.
#[cfg_attr(
    target_arch = "aarch64",
    expect(
        clippy::struct_excessive_bools,
        reason = "independent ELF patch state flags"
    )
)]
pub(crate) struct ElfPatchState {
    #[cfg(target_arch = "aarch64")]
    islands: islands::RuntimeIslands,
    /// Whether this file is already pre-patched (trampoline magic found at file tail).
    pre_patched: bool,
    /// For pre-patched binaries: file offset and size of the trampoline data.
    #[cfg(target_arch = "x86_64")]
    trampoline_file_offset: u64,
    #[cfg(target_arch = "x86_64")]
    trampoline_file_size: usize,
    /// Start address of the trampoline region (runtime).
    trampoline_addr: usize,
    /// Current write position within the trampoline (byte offset from `trampoline_addr`).
    #[cfg(target_arch = "x86_64")]
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
    /// Pre-scanned slot estimate; current mapped bytes determine actual capacity.
    #[cfg(target_arch = "aarch64")]
    island_slot_estimate: usize,
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
        !self.trampoline_invalidated
            && self
                .islands
                .serialized
                .as_ref()
                .is_some_and(|p| p.pairs.is_empty() || !self.islands.pairs.is_empty())
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

/// Loader-supplied main-image identity; never inferred from low addresses or
/// numerical load-span inclusion. The heap floor is established by its LOADs.
#[cfg(target_arch = "aarch64")]
#[derive(Default)]
pub(crate) struct ElfHeapPlacement {
    main: Option<ElfPatchKey>,
    floor: Option<usize>,
    current_brk: Option<usize>,
}

#[cfg(target_arch = "aarch64")]
impl ElfHeapPlacement {
    fn corridor(&self, mapping_starts: impl Iterator<Item = usize>) -> Option<Range<usize>> {
        let floor = self.floor?;
        // Heap VMAs are not barriers to their OWN future growth. Only a mapping
        // starting at/above the current break can establish the upper boundary.
        let heap_end = align_up(self.current_brk.unwrap_or(floor), HOST_PAGE_SIZE);
        let ceiling = mapping_starts
            .filter(|&start| start >= heap_end)
            .min()
            .unwrap_or(usize::MAX);
        Some(floor..ceiling)
    }

    fn island_corridor(
        &self,
        file: &ElfPatchKey,
        mapping_starts: impl Iterator<Item = usize>,
    ) -> Option<islands::HeapCorridor> {
        Some(islands::HeapCorridor {
            range: self.corridor(mapping_starts)?,
            heap_end: self
                .current_brk
                .unwrap_or(self.floor?)
                .checked_next_multiple_of(HOST_PAGE_SIZE)?,
            // Unknown main identity confers no permission to consume brk space.
            dso: self.main.as_ref().is_some_and(|main| main != file),
        })
    }
}

/// Per-process ELF metadata keyed by retained descriptor identity. On AArch64,
/// runtime mapping offsets and island ownership outlive close and distinguish
/// simultaneous mappings at different load biases.
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
fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (addr + align - 1) & !(align - 1)
}

#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

/// Tries preferred-full, anywhere-full, then preferred-one-page.
#[cfg(any(target_arch = "x86_64", test))]
fn choose_trampoline_reservation<T>(
    capacity: usize,
    page_size: usize,
    mut map_preferred: impl FnMut(usize) -> Option<T>,
    mut map_anywhere: impl FnMut(usize) -> Option<T>,
) -> Option<(T, usize)> {
    map_preferred(capacity)
        .map(|reservation| (reservation, capacity))
        .or_else(|| map_anywhere(capacity).map(|reservation| (reservation, capacity)))
        .or_else(|| {
            if capacity > page_size {
                map_preferred(page_size).map(|reservation| (reservation, page_size))
            } else {
                None
            }
        })
}

impl<Platform: ShimPlatform> Task<Platform> {
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn begin_main_elf_load(&self, fd: Arc<FileFd>) {
        let _update = self.global.elf_mapping_update.lock();
        *self.global.elf_heap_placement.lock() = ElfHeapPlacement {
            main: Some(ElfPatchKey(fd)),
            floor: None,
            current_brk: None,
        };
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn set_main_elf_heap_floor(&self, brk: usize) {
        let mut heap = self.global.elf_heap_placement.lock();
        heap.floor = Some(align_down(brk, HOST_PAGE_SIZE));
        heap.current_brk = Some(brk);
    }

    #[inline]
    pub(crate) fn do_mmap(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        ensure_space_after: bool,
        op: impl FnOnce(UserPtrMut<u8>) -> Result<usize, MappingError>,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        self.global.mm.do_mmap(
            suggested_addr,
            len,
            prot,
            flags,
            litebox_common_linux::mm::MmapPlacement {
                direction: litebox::platform::page_mgmt::AllocationDirection::TopDown,
                ensure_space_after,
            },
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

    #[cfg(test)]
    fn do_mmap_file(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        let typed_fd = self.typed_fd(fd).map_err(|_| MappingError::BadFD(fd))?;
        self.do_mmap_resolved_file(suggested_addr, len, prot, flags, &typed_fd, offset.into())
    }

    fn do_mmap_resolved_file(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        typed_fd: &AnyTypedFd<Platform>,
        source: FileMappingSource,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        let offset = source.offset;
        let is_exec = prot.contains(ProtFlags::PROT_EXEC);
        let AnyTypedFd::Fs(file_fd) = typed_fd else {
            return Err(MappingError::BadFD(-1));
        };

        #[cfg(target_arch = "aarch64")]
        let replaces_mapping =
            flags.contains(MapFlags::MAP_FIXED) && !flags.contains(MapFlags::MAP_FIXED_NOREPLACE);
        let staging_prot = prot;
        #[cfg(target_arch = "aarch64")]
        let staging_prot = if is_exec {
            (staging_prot | ProtFlags::PROT_READ | ProtFlags::PROT_WRITE) & !ProtFlags::PROT_EXEC
        } else {
            staging_prot
        };
        let patch_key = ElfPatchKey(Arc::clone(file_fd));
        #[cfg(target_arch = "aarch64")]
        self.init_elf_patch_state(&patch_key, 0, offset);
        #[cfg(target_arch = "aarch64")]
        let envelope =
            self.reserve_mmap_island_envelope(&patch_key, suggested_addr, len, offset, flags)?;
        #[cfg(target_arch = "aarch64")]
        let (suggested_addr, flags) = if let Some(envelope) = &envelope {
            (Some(envelope.file_start), flags | MapFlags::MAP_FIXED)
        } else {
            (suggested_addr, flags)
        };
        let mapped =
            self.do_mmap_file_memcpy(suggested_addr, len, staging_prot, flags, typed_fd, offset);
        #[cfg(target_arch = "aarch64")]
        if let Some(envelope) = envelope {
            if mapped.is_err() {
                let _ = self.sys_munmap_raw(
                    UserPtrMut::from_usize(envelope.range.start),
                    envelope.range.len(),
                );
            } else {
                let mut keep = envelope.islands.clone();
                keep.push(envelope.file_start..envelope.file_start + len);
                for part in subtract_ranges(envelope.range, &keep) {
                    self.sys_munmap_raw(UserPtrMut::from_usize(part.start), part.len())
                        .expect("trim owned mmap envelope");
                }
                self.global
                    .elf_patch_cache
                    .lock()
                    .get_mut(&patch_key)
                    .expect("initialized ELF")
                    .islands
                    .mmap_reservations
                    .extend(
                        envelope
                            .islands
                            .into_iter()
                            .filter(|r| {
                                r.start < envelope.file_start || r.end > envelope.file_start + len
                            })
                            .map(|r| (envelope.bias, r)),
                    );
            }
        }
        let result = mapped?;

        #[cfg(target_arch = "aarch64")]
        if replaces_mapping {
            self.clear_file_mappings_for_range(result.as_usize(), len);
        }
        self.init_elf_patch_state(&patch_key, result.as_usize(), offset);
        #[cfg(target_arch = "aarch64")]
        {
            let mut cache = self.global.elf_patch_cache.lock();
            if let Some(state) = cache.get_mut(&patch_key) {
                state.file_mappings.insert((result.as_usize(), len));
                if !state.islands.loads.is_empty()
                    && state
                        .islands
                        .record_mapping(result.as_usize(), len, offset, source.load_bias)
                        .is_err()
                {
                    let _ = self.sys_munmap_raw(result, len);
                    state.file_mappings.remove(&(result.as_usize(), len));
                    drop(cache);
                    self.clear_file_mappings_for_range(result.as_usize(), len);
                    return Err(MappingError::OutOfMemory);
                }
                let mut heap = self.global.elf_heap_placement.lock();
                if heap.floor.is_none() && heap.main.as_ref() == Some(&patch_key) {
                    heap.floor = state
                        .islands
                        .future_loads()
                        .ok()
                        .and_then(|loads| loads.into_iter().map(|r| r.end).max());
                }
            }
        }

        // Runtime syscall rewriting: patch PROT_EXEC segments in-place.
        if is_exec {
            let syscall_entry = self.global.platform.get_syscall_entry_point();
            let restore_protections = [(result.as_usize(), len, prot)];
            if (syscall_entry != 0 || cfg!(target_arch = "aarch64"))
                && self
                    .maybe_patch_exec_segment(
                        result,
                        len,
                        &patch_key,
                        syscall_entry,
                        Some(offset),
                        &restore_protections,
                    )
                    .is_err()
            {
                // Runtime patching, trampoline setup, or restoration of the
                // requested permissions failed, so fail the mmap.
                let _ = self.sys_munmap_raw(result, len);
                self.clear_file_mappings_for_range(result.as_usize(), len);
                return Err(MappingError::OutOfMemory);
            }
            #[cfg(target_arch = "aarch64")]
            if let Some(state) = self.global.elf_patch_cache.lock().get_mut(&patch_key) {
                // mmap staged the whole image RW; displaced gaps inherit the
                // guest's requested view, not those temporary staging permissions.
                state
                    .islands
                    .protect_displaced(&(result.as_usize()..result.as_usize() + len), prot);
            }
        } else {
            // Ensure patch state is initialized for this fd (no-op if already done).
            self.init_elf_patch_state(&patch_key, result.as_usize(), offset);
            // Track non-exec file mappings so we can patch them if they later
            // gain PROT_EXEC via mprotect.
            let mut cache = self.global.elf_patch_cache.lock();
            if let Some(state) = cache.get_mut(&patch_key) {
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
            let mut buffer = [0; PAGE_SIZE];
            let mut copied = 0;
            while copied < len {
                let size =
                    self.do_read(fd, &mut buffer, Some(file_offset))
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
                // ptr is a valid pointer returned by do_mmap.
                ptr.copy_from_slice::<Platform>(copied, &buffer[..size])
                    .unwrap();
                copied += size;
                file_offset += size;
            }
            Ok(copied)
        };
        let fixed_addr = flags.intersects(MapFlags::MAP_FIXED | MapFlags::MAP_FIXED_NOREPLACE);
        let ptr = self.do_mmap(
            suggested_addr,
            len,
            ProtFlags::PROT_READ_WRITE,
            flags,
            // Note we need to ensure that the space after the mapping is available
            // so that we could load trampoline code right after the mapping.
            offset == 0
                && !fixed_addr
                && self
                    .global
                    .platform
                    .get_aarch64_island_entry_point()
                    .is_none(),
            op,
        )?;
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
        self.mmap_with_source(addr, len, prot, flags, fd, offset.into())
    }

    pub(crate) fn mmap_with_source(
        &self,
        addr: usize,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        source: FileMappingSource,
    ) -> Result<UserPtrMut<u8>, Errno> {
        #[cfg(target_arch = "aarch64")]
        let _update = self.global.elf_mapping_update.lock();
        let offset = source.offset;
        // check alignment
        if !offset.is_multiple_of(PAGE_SIZE)
            || !addr.is_multiple_of(PAGE_SIZE)
            || len == 0
            || prot.bits() & !ProtFlags::PROT_READ_WRITE_EXEC.bits() != 0
        {
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
        if aligned_len == 0 {
            return Err(Errno::ENOMEM);
        }
        if offset.checked_add(aligned_len).is_none() {
            return Err(Errno::EOVERFLOW);
        }

        // Resolve the fd once and perform side-effect-free checks BEFORE
        // closing old executable sites. EBADF must leave a valid mapping usable.
        let typed_fd = if flags.contains(MapFlags::MAP_ANONYMOUS) {
            None
        } else {
            let typed = self.typed_fd(fd)?;
            let AnyTypedFd::Fs(file) = &typed else {
                return Err(Errno::EBADF);
            };
            #[cfg(target_arch = "aarch64")]
            self.do_read(&typed, &mut [], Some(offset))?;
            #[cfg(target_arch = "aarch64")]
            if prot.contains(ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC) {
                let mut magic = [0; 4];
                if self
                    .global
                    .litebox
                    .read_file(file, &mut magic, Some(0), None)
                    .map_err(Errno::from)?
                    == 4
                    && magic == *b"\x7fELF"
                {
                    return Err(Errno::EACCES);
                }
            }
            #[cfg(target_arch = "x86_64")]
            let _ = file;
            Some(typed)
        };
        #[cfg(target_arch = "aarch64")]
        if let Some(bias) = source.load_bias {
            let Some(AnyTypedFd::Fs(file)) = &typed_fd else {
                return Err(Errno::ENOEXEC);
            };
            if !flags.contains(MapFlags::MAP_FIXED) {
                return Err(Errno::ENOEXEC);
            }
            let key = ElfPatchKey(Arc::clone(file));
            self.init_elf_patch_state(&key, addr, offset);
            self.global
                .elf_patch_cache
                .lock()
                .get(&key)
                .ok_or(Errno::ENOEXEC)?
                .islands
                .validate_load_mapping(addr, aligned_len, offset, bias)?;
        }
        #[cfg(target_arch = "aarch64")]
        let replaces_mapping =
            flags.contains(MapFlags::MAP_FIXED) && !flags.contains(MapFlags::MAP_FIXED_NOREPLACE);
        #[cfg(target_arch = "aarch64")]
        if replaces_mapping {
            let end = addr.checked_add(aligned_len).ok_or(Errno::EINVAL)?;
            self.island_removal_allowed(addr..end)?;
            self.preflight_island_replacement(&(addr..end))?;
            // A failing fixed allocation may leave some original pages intact.
            // Close their sites before any transport can be removed/replaced.
            self.close_island_sites_for_replacement(&(addr..end))?;
        }
        let suggested_addr = if addr == 0 { None } else { Some(addr) };
        let anonymous = flags.contains(MapFlags::MAP_ANONYMOUS);
        let result = if anonymous {
            self.do_mmap_anonymous(suggested_addr, aligned_len, prot, flags)
        } else {
            self.do_mmap_resolved_file(
                suggested_addr,
                aligned_len,
                prot,
                flags,
                typed_fd
                    .as_ref()
                    .expect("file fd resolved before replacement"),
                source,
            )
        }
        .map_err(Errno::from);
        #[cfg(target_arch = "aarch64")]
        if replaces_mapping {
            if result.is_err() {
                self.invalidate_failed_island_replacement(&(addr..addr + aligned_len));
            } else if anonymous {
                // File replacements retire metadata immediately after creation,
                // before rewriting/recording the new mapping. Anonymous ones
                // have no new ELF records to protect from this removal.
                self.clear_file_mappings_for_range(addr, aligned_len);
            }
        }
        result
    }

    /// Handle syscall `munmap`
    #[inline]
    pub(crate) fn sys_munmap(&self, addr: UserPtrMut<u8>, len: usize) -> Result<(), Errno> {
        #[cfg(target_arch = "aarch64")]
        let _update = self.global.elf_mapping_update.lock();
        #[cfg(target_arch = "aarch64")]
        self.island_removal_allowed(
            addr.as_usize()
                ..addr
                    .as_usize()
                    .checked_add(
                        len.checked_next_multiple_of(PAGE_SIZE)
                            .ok_or(Errno::EINVAL)?,
                    )
                    .ok_or(Errno::EINVAL)?,
        )?;
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
    ///
    fn clear_file_mappings_for_range(&self, unmap_start: usize, unmap_len: usize) {
        let unmap_end = unmap_start.saturating_add(unmap_len);
        let mut cache = self.global.elf_patch_cache.lock();
        for state in cache.values_mut() {
            #[cfg(target_arch = "aarch64")]
            {
                for released in state.islands.remove(&(unmap_start..unmap_end)) {
                    self.retire_island_mapping(released, &(unmap_start..unmap_end));
                }
                let mut surviving = BTreeSet::new();
                for &(start, len) in &state.file_mappings {
                    for part in subtract_ranges(
                        start..start + len,
                        core::slice::from_ref(&(unmap_start..unmap_end)),
                    ) {
                        surviving.insert((part.start, part.len()));
                    }
                }
                state.file_mappings = surviving;
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
        #[cfg(target_arch = "aarch64")]
        cache.retain(|_, state| {
            !state.file_mappings.is_empty()
                || !state.islands.pairs.is_empty()
                || !state.islands.loader_reservations.is_empty()
                || !state.islands.mmap_reservations.is_empty()
        });
    }

    /// Handle syscall `mprotect`
    #[inline]
    pub(crate) fn sys_mprotect(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        #[cfg(target_arch = "aarch64")]
        let _update = self.global.elf_mapping_update.lock();
        if !addr.as_usize().is_multiple_of(PAGE_SIZE)
            || !len.is_multiple_of(PAGE_SIZE)
            || addr.as_usize().checked_add(len).is_none()
            || prot.bits() & !ProtFlags::PROT_READ_WRITE_EXEC.bits() != 0
        {
            return Err(Errno::EINVAL);
        }

        #[cfg(target_arch = "aarch64")]
        if prot.contains(ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC)
            && self
                .global
                .elf_patch_cache
                .lock()
                .values()
                .any(|s| s.islands.touches(&(addr.as_usize()..addr.as_usize() + len)))
        {
            return Err(Errno::EACCES);
        }
        #[cfg(target_arch = "aarch64")]
        if prot.contains(ProtFlags::PROT_WRITE) {
            // Permission updates can partially succeed before returning an error.
            // Invalidate before any mutation so a later +X rescans every byte the
            // guest could have changed, even after a failed writable transition.
            // Existing pairs remain immutable and retained until their sites unmap.
            let end = addr.as_usize() + len;
            for state in self.global.elf_patch_cache.lock().values_mut() {
                state
                    .patched_ranges
                    .retain(|&(start, size)| start >= end || start + size <= addr.as_usize());
            }
        }
        // Intercept transitions to PROT_EXEC: patch unpatched file mappings.
        if prot.contains(ProtFlags::PROT_EXEC) {
            let syscall_entry = self.global.platform.get_syscall_entry_point();
            if syscall_entry != 0 || cfg!(target_arch = "aarch64") {
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

    /// Applies `prot` excluding owned transport and its unpublished mmap reservations.
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
                .flat_map(|s| {
                    s.islands
                        .owned_ranges()
                        .chain(s.islands.mmap_reservations.iter().map(|(_, r)| r.clone()))
                })
                .collect()
        };

        // Walk in address order, so a failed earlier VMA does not update a
        // later displaced page's deferred guest protection intent.
        let mut boundaries = alloc::vec![range.start, range.end];
        for r in &excluded {
            if r.start < range.end && range.start < r.end {
                boundaries.extend([r.start.max(range.start), r.end.min(range.end)]);
            }
        }
        boundaries.sort_unstable();
        boundaries.dedup();
        for pair in boundaries.windows(2) {
            let part = pair[0]..pair[1];
            if excluded.iter().any(|r| r.contains(&part.start)) {
                for state in self.global.elf_patch_cache.lock().values_mut() {
                    state.islands.protect_displaced(&part, prot);
                }
            } else {
                self.sys_mprotect_raw(UserPtrMut::from_usize(part.start), part.len(), prot)?;
            }
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
        #[cfg(target_arch = "aarch64")]
        let _update = self.global.elf_mapping_update.lock();
        #[cfg(target_arch = "aarch64")]
        {
            let old_end = old_addr
                .as_usize()
                .checked_add(old_size)
                .ok_or(Errno::EINVAL)?;
            let destination = if flags.contains(MRemapFlags::MREMAP_FIXED) {
                Some(new_addr..new_addr.checked_add(new_size).ok_or(Errno::EINVAL)?)
            } else {
                None
            };
            if self.global.elf_patch_cache.lock().values().any(|s| {
                s.islands.touches(&(old_addr.as_usize()..old_end))
                    || destination
                        .as_ref()
                        .is_some_and(|range| s.islands.touches(range))
            }) {
                return Err(Errno::EINVAL);
            }
        }
        self.global
            .mm
            .sys_mremap(old_addr, old_size, new_size, flags, new_addr)
    }

    /// Handle syscall `brk`
    #[inline]
    pub(crate) fn sys_brk(&self, addr: UserPtrMut<u8>) -> Result<usize, Errno> {
        #[cfg(target_arch = "aarch64")]
        let _update = self.global.elf_mapping_update.lock();
        // On failure, Linux returns the current break rather than a negative errno.
        let result = unsafe {
            self.global
                .mm
                .brk(addr.as_usize())
                .or_else(|_| self.global.mm.brk(0))
        }
        .map_err(Errno::from);
        #[cfg(target_arch = "aarch64")]
        if let Ok(brk) = result {
            self.global.elf_heap_placement.lock().current_brk = Some(brk);
        }
        result
    }

    /// Handle syscall `madvise`
    #[inline]
    pub(crate) fn sys_madvise(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        advice: litebox_common_linux::MadviseBehavior,
    ) -> Result<(), Errno> {
        #[cfg(target_arch = "aarch64")]
        let _update = self.global.elf_mapping_update.lock();
        #[cfg(target_arch = "aarch64")]
        if len != 0
            && matches!(
                advice,
                litebox_common_linux::MadviseBehavior::DontNeed
                    | litebox_common_linux::MadviseBehavior::Free
            )
        {
            let end = addr
                .as_usize()
                .checked_add(
                    len.checked_next_multiple_of(PAGE_SIZE)
                        .ok_or(Errno::EINVAL)?,
                )
                .ok_or(Errno::EINVAL)?;
            if self
                .global
                .elf_patch_cache
                .lock()
                .values()
                .any(|s| s.islands.protects_advice(&(addr.as_usize()..end)))
            {
                return Err(Errno::EBUSY);
            }
        }
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
                for &(seg_start, seg_len) in &state.file_mappings {
                    let seg_end = seg_start.saturating_add(seg_len);
                    // Check overlap with the mprotect range.
                    if seg_start < mprotect_end && seg_end > mprotect_start {
                        let patch_start = seg_start.max(mprotect_start);
                        let patch_end = seg_end.min(mprotect_end);
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
    fn init_elf_patch_state(&self, fd: &ElfPatchKey, mapped_addr: usize, file_offset: usize) {
        #[cfg(target_arch = "aarch64")]
        let _ = (mapped_addr, file_offset);
        // Quick check: skip if already initialized.
        if self.global.elf_patch_cache.lock().contains_key(fd) {
            return;
        }

        // Read the ELF header (64 bytes for Elf64).
        let mut ehdr_buf = [0u8; core::mem::size_of::<FileHeader64<LittleEndian>>()];
        match self
            .global
            .litebox
            .read_file(&fd.0, &mut ehdr_buf, Some(0), None)
        {
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
        #[cfg(target_arch = "x86_64")]
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
        match self
            .global
            .litebox
            .read_file(&fd.0, &mut phdrs_buf, Some(e_phoff), None)
        {
            Ok(n) if n == phdrs_buf.len() => {}
            _ => return,
        }

        // Find highest PT_LOAD end (p_vaddr + p_memsz) and compute base_addr
        // by matching the segment whose p_offset corresponds to file_offset.
        let mut max_load_end: u64 = 0;
        #[cfg(target_arch = "x86_64")]
        let mut max_load_align: u64 = 0;
        #[cfg(target_arch = "x86_64")]
        let mut base_addr: Option<usize> = None;
        #[cfg(target_arch = "aarch64")]
        let mut loads = Vec::new();
        #[cfg(target_arch = "aarch64")]
        let mut load_alignment = Some(PAGE_SIZE);
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
            let p_memsz = ph.p_memsz.get(ENDIAN).max(ph.p_filesz.get(ENDIAN));
            #[cfg(target_arch = "aarch64")]
            {
                let align = usize::try_from(ph.p_align.get(ENDIAN)).unwrap_or(0).max(1);
                load_alignment = load_alignment
                    .filter(|_| {
                        align.is_power_of_two()
                            && p_vaddr % align as u64 == p_offset as u64 % align as u64
                            && ph.p_filesz.get(ENDIAN) <= ph.p_memsz.get(ENDIAN)
                            && p_vaddr % PAGE_SIZE as u64 == p_offset as u64 % PAGE_SIZE as u64
                    })
                    .map(|a| a.max(align));
            }
            #[cfg(target_arch = "aarch64")]
            if let (Some(file_end), Some(address_end)) = (
                p_offset
                    .checked_add(ph.p_filesz.get(ENDIAN).trunc())
                    .and_then(|v| v.checked_next_multiple_of(PAGE_SIZE)),
                usize::try_from(p_vaddr)
                    .expect("64-bit pointer")
                    .checked_add(p_memsz.trunc())
                    .and_then(|v| v.checked_next_multiple_of(PAGE_SIZE)),
            ) {
                loads.push(islands::Load {
                    file: align_down(p_offset, PAGE_SIZE)..file_end,
                    address: align_down(p_vaddr.trunc(), PAGE_SIZE)..address_end,
                });
            } else {
                load_alignment = None;
            }
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
            #[cfg(target_arch = "x86_64")]
            {
                max_load_align = max_load_align.max(ph.p_align.get(ENDIAN));
            }
            #[cfg(target_arch = "x86_64")]
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
        #[cfg(target_arch = "x86_64")]
        let (pre_patched, tramp_file_offset, tramp_vaddr, tramp_file_size) =
            self.check_trampoline_magic(&fd.0);
        #[cfg(target_arch = "aarch64")]
        let (pre_patched, _, _, _) = self.check_trampoline_magic(&fd.0);

        #[cfg(target_arch = "aarch64")]
        let serialized = self
            .global
            .litebox
            .file_status(&fd.0)
            .map_err(|_| Errno::ENOEXEC)
            .and_then(|stat| {
                litebox_syscall_rewriter::aarch64::elf_islands::ElfIslands::read(
                    stat.size,
                    |offset, bytes| {
                        let offset = usize::try_from(offset).map_err(|_| {
                            litebox_syscall_rewriter::Error::AddressOverflow(
                                "ELF file offset".into(),
                            )
                        })?;
                        self.read_file_exact_at(&fd.0, bytes, offset).map_err(|_| {
                            litebox_syscall_rewriter::Error::ParseError("ELF island read".into())
                        })
                    },
                )
                .and_then(|payload| {
                    if let Some(payload) = &payload {
                        payload.check_compatibility(
                            crate::aarch64_rewrite_options(),
                            HOST_PAGE_SIZE,
                        )?;
                    }
                    Ok(payload)
                })
                .map_err(|_| Errno::ENOEXEC)
            });
        #[cfg(target_arch = "aarch64")]
        let (code_metadata, island_slot_estimate) = if serialized.is_err() {
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
                        .island_slot_upper_bound(
                            &zerocopy::IntoBytes::as_bytes(words.as_slice())[..file_size],
                            crate::aarch64_rewrite_options(),
                        )
                        .ok();
                    Some((metadata, upper_bound))
                });
            if let Some((metadata, upper_bound)) = scanned {
                let (executable_bytes, identified_bytes) = metadata.coverage_bytes();
                let capacity = upper_bound.unwrap_or(0);
                litebox_util_log::debug!(
                    fd:? = fd,
                    executable_bytes:? = executable_bytes,
                    identified_bytes:? = identified_bytes,
                    island_slot_estimate:? = capacity;
                    "pre-scanned AArch64 ELF for runtime rewriting"
                );
                (Some(metadata), capacity)
            } else {
                litebox_util_log::warn!(
                    fd:? = fd;
                    "AArch64 ELF code metadata unavailable; executable mappings will fail closed"
                );
                (None, 0)
            }
        };

        // Compute the trampoline virtual address.
        // - Pre-patched: use the exact address from the trampoline header (the
        //   code already contains JMPs there, so we MUST map at this address).
        // - Unpatched: use the architecture-specific fallback past the loader's
        //   alignment slack. This is only a hint; the runtime path re-checks
        //   the chosen address against the branch-reach limit below, and falls
        //   back to traps.
        // For ET_DYN, virtual addresses are relative to the load base.
        #[cfg(target_arch = "aarch64")]
        let trampoline_vaddr = 0;
        #[cfg(target_arch = "x86_64")]
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
            // Keep a runtime trampoline's RW staging off the ELF's RX host
            // page, even when its guest LOAD alignment is smaller.
            align_up(base + offset, HOST_PAGE_SIZE)
        };

        #[cfg(target_arch = "aarch64")]
        let whole_span = (|| {
            if e_type != object::elf::ET_DYN
                || &ehdr_buf[..7] != b"\x7fELF\x02\x01\x01"
                || ehdr.e_machine.get(ENDIAN) != object::elf::EM_AARCH64
            {
                return None;
            }
            let first = loads.iter().min_by_key(|l| l.address.start)?;
            if loads
                .iter()
                .filter(|l| l.address.start == first.address.start)
                .count()
                != 1
            {
                return None;
            }
            Some(islands::WholeSpan {
                address: first.address.start..loads.iter().map(|l| l.address.end).max()?,
                offset: first.file.start,
                align: load_alignment?.max(HOST_PAGE_SIZE),
            })
        })();
        // Insert under lock (re-check for races).
        let mut cache = self.global.elf_patch_cache.lock();
        cache.entry(fd.clone()).or_insert(ElfPatchState {
            #[cfg(target_arch = "aarch64")]
            islands: islands::RuntimeIslands {
                whole_span,
                loads,
                load_alignment,
                serialized: serialized.as_ref().ok().cloned().flatten(),
                ..Default::default()
            },
            pre_patched,
            #[cfg(target_arch = "x86_64")]
            trampoline_file_offset: tramp_file_offset,
            #[cfg(target_arch = "x86_64")]
            trampoline_file_size: tramp_file_size.trunc(),
            trampoline_addr: trampoline_vaddr,
            #[cfg(target_arch = "x86_64")]
            trampoline_cursor: 0,
            trampoline_mapped: false,
            trampoline_mapped_len: 0,
            runtime_patches_committed: false,
            #[cfg(target_arch = "aarch64")]
            trampoline_invalidated: serialized.is_err(),
            #[cfg(target_arch = "aarch64")]
            code_metadata,
            #[cfg(target_arch = "aarch64")]
            island_slot_estimate,
            file_mappings: BTreeSet::new(),
            patched_ranges: BTreeSet::new(),
        });
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

    /// Check if a file has the LITEBOX trampoline magic at its tail.
    /// Returns (is_pre_patched, file_offset, vaddr, trampoline_size).
    fn check_trampoline_magic(&self, fd: &FileFd) -> (bool, u64, u64, u64) {
        let Ok(stat) = self.global.litebox.file_status(fd) else {
            return (false, 0, 0, 0);
        };
        let Some(tail_offset) = stat.size.checked_sub(TRAMPOLINE_HEADER_SIZE as u64) else {
            return (false, 0, 0, 0);
        };
        let Ok(tail_offset) = usize::try_from(tail_offset) else {
            return (false, 0, 0, 0);
        };

        let mut tail = [0u8; TRAMPOLINE_HEADER_SIZE];
        match self
            .global
            .litebox
            .read_file(fd, &mut tail, Some(tail_offset), None)
        {
            Ok(n) if n == TRAMPOLINE_HEADER_SIZE => {}
            _ => return (false, 0, 0, 0),
        }
        let Ok(header) = TrampolineHeader64::read_from_bytes(&tail) else {
            return (false, 0, 0, 0);
        };
        // LITEBOX0 is the complete magic, not a prefix plus a version selector.
        // AArch64 payload validation runs separately, including corruption checks.
        if !header.has_valid_magic() {
            return (false, 0, 0, 0);
        }
        (
            true,
            header.file_offset,
            header.vaddr,
            header.trampoline_size,
        )
    }

    /// Apply the trap fallback to a mapped code segment: replace every patch
    /// site with the rewriter's trap, then restore the caller-selected permissions.
    ///
    /// If `already_rw` is true, the segment is assumed to already be writable
    /// and the initial mprotect RW is skipped.
    ///
    /// Returns an error if those permissions cannot be restored.
    /// Panics on other infrastructure failures (mprotect/read/write/disassembly).
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
        // Initialize patch state if this is the first mmap for this fd.
        // Typically the first mapping is at offset 0 (the ELF header), but
        // some loaders may map an executable segment at a non-zero offset first.
        if let Some(file_offset) = file_offset {
            self.init_elf_patch_state(fd, mapped_addr.as_usize(), file_offset);
        }

        // This lock guards the elf_patch_cache and is held for the entire
        // patching operation. In practice this is fine because the dynamic
        // linker loads shared libraries sequentially.
        let mut cache = self.global.elf_patch_cache.lock();
        #[cfg(target_arch = "aarch64")]
        let future_loads: Vec<_> = cache
            .values()
            .map(|s| s.islands.future_loads())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect();
        #[cfg(target_arch = "aarch64")]
        let heap_corridor = self.global.elf_heap_placement.lock().island_corridor(
            fd,
            self.global
                .mm
                .mappings()
                .into_iter()
                .map(|(range, _)| range.start),
        );
        let Some(state) = cache.get_mut(fd) else {
            #[cfg(target_arch = "aarch64")]
            {
                let size = self
                    .global
                    .litebox
                    .file_status(&fd.0)
                    .map_err(|_| Errno::ENOEXEC)?
                    .size;
                let marker = litebox_syscall_rewriter::aarch64::elf_islands::ElfIslands::read(
                    size,
                    |offset, bytes| {
                        self.read_file_exact_at(
                            &fd.0,
                            bytes,
                            usize::try_from(offset).map_err(|_| {
                                litebox_syscall_rewriter::Error::ParseError("file offset".into())
                            })?,
                        )
                        .map_err(|_| {
                            litebox_syscall_rewriter::Error::ParseError("island read".into())
                        })
                    },
                )
                .map_err(|_| Errno::ENOEXEC)?;
                if marker.is_some_and(|p| !p.pairs.is_empty()) {
                    return Err(Errno::ENOEXEC);
                }
            }
            return self.restore_page_permissions(restore_protections); // Not an ELF
        };
        #[cfg(target_arch = "aarch64")]
        if state.trampoline_invalidated {
            return Err(Errno::ENOMEM);
        }
        #[cfg(target_arch = "aarch64")]
        if syscall_entry == 0
            && state
                .islands
                .serialized
                .as_ref()
                .is_none_or(|p| p.pairs.is_empty())
        {
            return self.restore_page_permissions(restore_protections);
        }

        #[cfg(target_arch = "x86_64")]
        if state.pre_patched {
            // x86 keeps its existing contiguous executable payload.
            if !state.trampoline_mapped && state.trampoline_file_size > 0 {
                let tramp_addr = state.trampoline_addr;
                let tramp_len = align_up(state.trampoline_file_size, PAGE_SIZE);

                let alloc_result = self.do_mmap_anonymous(
                    Some(tramp_addr),
                    tramp_len,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
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
            return self.restore_page_permissions(restore_protections);
        }

        #[cfg(target_arch = "aarch64")]
        {
            self.patch_exec_with_islands(
                state,
                mapped_addr,
                len,
                restore_protections,
                &future_loads,
                heap_corridor.as_ref(),
            )
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.patch_exec_x86_64(state, mapped_addr, len, syscall_entry, restore_protections)
        }
    }

    /// The distinct direct x86 runtime path. AArch64 runtime never falls back here.
    #[cfg(target_arch = "x86_64")]
    fn patch_exec_x86_64(
        &self,
        state: &mut ElfPatchState,
        mapped_addr: UserPtrMut<u8>,
        len: usize,
        syscall_entry: usize,
        restore_protections: &[ProtectionRange],
    ) -> Result<(), Errno> {
        // ── Runtime patching path (unpatched binaries) ───────────────

        let apply_trap_fallback = |mapped_addr, len, already_rw| {
            self.apply_trap_fallback(mapped_addr, len, already_rw, restore_protections)
        };

        // Allocate the trampoline region if not yet done.
        let addr_usize = mapped_addr.as_usize();
        if !state.trampoline_mapped {
            let tramp_addr = state.trampoline_addr;
            let initial_trampoline_len = PAGE_SIZE;

            let map_preferred = |reservation_len| match self.do_mmap_anonymous(
                Some(tramp_addr),
                reservation_len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
            ) {
                Ok(ptr) => {
                    if ptr.as_usize() == tramp_addr {
                        Some(ptr)
                    } else {
                        let _ = self.sys_munmap_raw(ptr, reservation_len);
                        None
                    }
                }
                Err(_) => None,
            };
            let far_end = addr_usize.saturating_add(len);
            let trampoline_distance = |actual_addr: usize| {
                actual_addr
                    .abs_diff(addr_usize)
                    .max(actual_addr.abs_diff(far_end))
            };
            let mut rejected_distance = None;
            let reservation = choose_trampoline_reservation(
                initial_trampoline_len,
                PAGE_SIZE,
                map_preferred,
                |reservation_len| {
                    self.do_mmap_anonymous(
                        None,
                        reservation_len,
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                        MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                    )
                    .ok()
                    .and_then(|ptr| {
                        let distance = trampoline_distance(ptr.as_usize());
                        if distance > litebox_syscall_rewriter::MAX_TRAMPOLINE_DISPLACEMENT {
                            rejected_distance = Some(distance);
                            litebox_util_log::debug!(
                                distance:? = distance;
                                "rejecting arbitrary trampoline reservation outside branch range"
                            );
                            let _ = self.sys_munmap_raw(ptr, reservation_len);
                            None
                        } else {
                            Some(ptr)
                        }
                    })
                },
            );
            let Some((actual_addr_ptr, reservation_len)) = reservation else {
                if let Some(distance) = rejected_distance {
                    litebox_util_log::warn!(
                        distance:? = distance;
                        "trampoline too far from code segment, skipping patching"
                    );
                } else {
                    litebox_util_log::warn!("failed to allocate trampoline region");
                }
                return apply_trap_fallback(mapped_addr, len, false);
            };
            let actual_addr = actual_addr_ptr.as_usize();

            // Defend the preferred paths; individual gates also check reach.
            let distance = trampoline_distance(actual_addr);
            if distance > litebox_syscall_rewriter::MAX_TRAMPOLINE_DISPLACEMENT {
                litebox_util_log::warn!(
                    distance:? = distance;
                    "trampoline too far from code segment, skipping patching"
                );
                let _ =
                    self.sys_munmap_raw(UserPtrMut::<u8>::from_usize(actual_addr), reservation_len);
                return apply_trap_fallback(mapped_addr, len, false);
            }

            state.trampoline_addr = actual_addr;

            if litebox_syscall_rewriter::TRAMPOLINE_ENTRY_POINT_BYTES != 0 {
                let entry_ptr = UserPtrMut::<u8>::from_usize(actual_addr);
                if entry_ptr
                    .copy_from_slice::<Platform>(0, &syscall_entry.to_le_bytes())
                    .is_none()
                {
                    litebox_util_log::warn!("failed to write syscall entry point to trampoline");
                    let _ = self
                        .sys_munmap_raw(UserPtrMut::<u8>::from_usize(actual_addr), reservation_len);
                    return apply_trap_fallback(mapped_addr, len, false);
                }
                state.trampoline_cursor = litebox_syscall_rewriter::TRAMPOLINE_ENTRY_POINT_BYTES;
            } else {
                state.trampoline_cursor = 0;
            }
            state.trampoline_mapped = true;
            state.trampoline_mapped_len = reservation_len;
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
                let Some(new_cursor) = state.trampoline_cursor.checked_add(stubs.len()) else {
                    litebox_util_log::warn!("trampoline cursor overflow");
                    let restored = apply_trap_fallback(mapped_addr, len, true);
                    restore_trampoline_rx(self, state);
                    return restored;
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
                        let restored = apply_trap_fallback(mapped_addr, len, true);
                        restore_trampoline_rx(self, state);
                        return restored;
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
    /// AArch64 runtime state follows mapping lifetime, not fd lifetime. Otherwise
    /// remove the entry and unmap any direct trampoline that was never used.
    pub(crate) fn finalize_elf_patch(&self, fd: Arc<FileFd>) {
        #[cfg(target_arch = "aarch64")]
        {
            // Runtime metadata was captured before close. Keep its descriptor
            // identity (not the raw fd) until the last mapping disappears.
            let cache = self.global.elf_patch_cache.lock();
            if cache.get(&ElfPatchKey(Arc::clone(&fd))).is_some_and(|s| {
                !s.file_mappings.is_empty()
                    || !s.islands.pairs.is_empty()
                    || !s.islands.mmap_reservations.is_empty()
                    || !s.islands.loader_reservations.is_empty()
            }) {
                return;
            }
        }
        let state = self.global.elf_patch_cache.lock().remove(&ElfPatchKey(fd));
        if let Some(state) = state
            && state.trampoline_mapped
            && !state.pre_patched
            && !state.runtime_patches_committed
        {
            let tramp_len = state.trampoline_mapped_len;
            if tramp_len > 0 {
                // The entry was removed above; fd close already holds the VM
                // update lock on AArch64, so do not re-enter the syscall wrapper.
                let _ = self.sys_munmap_raw(
                    UserPtrMut::<u8>::from_usize(state.trampoline_addr),
                    tramp_len,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ElfPatchKey, ElfPatchState, PAGE_SIZE, Task};
    use alloc::collections::BTreeSet;
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    use litebox::platform::PageManagementProvider;
    use litebox::platform::page_mgmt::MemoryRegionPermissions;
    use litebox_broker_protocol::fs::FileMode as Mode;
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    use litebox_common_linux::MRemapFlags;
    use litebox_common_linux::{
        MapFlags, OFlags, ProtFlags,
        errno::Errno,
        vmem::{NonZeroAddress, NonZeroPageSize},
    };

    use crate::UserPtrMut;
    use crate::syscalls::file::AnyTypedFd;
    use crate::syscalls::tests::{TestPlatform as Platform, create_file, init_platform};

    pub(super) fn elf_patch_key(task: &Task<Platform>, fd: i32) -> ElfPatchKey {
        let AnyTypedFd::Fs(fd) = task.typed_fd(fd).expect("file descriptor should resolve") else {
            panic!("descriptor should refer to a file");
        };
        ElfPatchKey(fd)
    }

    fn runtime_patch_state(
        file_mappings: BTreeSet<(usize, usize)>,
        trampoline_addr: usize,
        trampoline_mapped: bool,
    ) -> ElfPatchState {
        ElfPatchState {
            #[cfg(target_arch = "aarch64")]
            islands: super::islands::RuntimeIslands::default(),
            pre_patched: false,
            #[cfg(target_arch = "x86_64")]
            trampoline_file_offset: 0,
            #[cfg(target_arch = "x86_64")]
            trampoline_file_size: 0,
            trampoline_addr,
            #[cfg(target_arch = "x86_64")]
            trampoline_cursor: 0,
            trampoline_mapped,
            trampoline_mapped_len: 0,
            runtime_patches_committed: false,
            #[cfg(target_arch = "aarch64")]
            trampoline_invalidated: false,
            #[cfg(target_arch = "aarch64")]
            code_metadata: None,
            #[cfg(target_arch = "aarch64")]
            island_slot_estimate: 0,
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
            runtime_patch_state(BTreeSet::new(), 0, true),
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

    #[test]
    fn trampoline_detection_requires_exact_magic() {
        let task = init_platform();
        for (index, magic) in [*b"LITEBOX0", *b"LITEBOX?", *b"LITEBOX\0", *b"?ITEBOX0"]
            .into_iter()
            .enumerate()
        {
            let mut content = alloc::vec![0; PAGE_SIZE];
            content.extend_from_slice(&magic);
            content.extend_from_slice(&[0; 24]);
            let path = alloc::format!("/trampoline-magic-{index}");
            create_file(&task, &path, &content);
            let fd = i32::try_from(task.sys_open(&path, OFlags::RDONLY, Mode::empty()).unwrap())
                .unwrap();
            let key = elf_patch_key(&task, fd);
            assert_eq!(task.check_trampoline_magic(&key.0).0, magic == *b"LITEBOX0");
            task.sys_close(fd).unwrap();
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn check_corrupt_magic_rewriting(exec_at_mmap: bool) {
        const SYSCALL_OFFSET: usize = 0x110;
        let task = init_platform();
        for corruption in [b'?', 0] {
            // A minimal ET_DYN with one executable LOAD, containing a raw
            // SYSCALL and followed by a zero-size footer with corrupted magic.
            let mut content = alloc::vec![0; PAGE_SIZE];
            content[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
            for (at, value) in [(16, 3u16), (18, 62), (52, 64), (54, 56), (56, 1)] {
                content[at..at + 2].copy_from_slice(&value.to_le_bytes());
            }
            content[20..24].copy_from_slice(&1u32.to_le_bytes());
            content[64..68].copy_from_slice(&1u32.to_le_bytes());
            content[68..72].copy_from_slice(&5u32.to_le_bytes());
            for (at, value) in [
                (24, 0x100u64),
                (32, 64),
                (96, PAGE_SIZE as u64),
                (104, PAGE_SIZE as u64),
                (112, PAGE_SIZE as u64),
            ] {
                content[at..at + 8].copy_from_slice(&value.to_le_bytes());
            }
            content[0x100..].fill(0x90);
            content[SYSCALL_OFFSET..SYSCALL_OFFSET + 2].copy_from_slice(&[0x0f, 0x05]);
            content.extend_from_slice(b"LITEBOX0");
            content[PAGE_SIZE + 7] = corruption;
            content.extend_from_slice(&[0; 24]);
            let path = alloc::format!("/corrupt-footer-{exec_at_mmap}-{corruption}");
            create_file(&task, &path, &content);
            let fd = i32::try_from(task.sys_open(&path, OFlags::RDONLY, Mode::empty()).unwrap())
                .unwrap();
            let address = task
                .sys_mmap(
                    0,
                    PAGE_SIZE,
                    if exec_at_mmap {
                        ProtFlags::PROT_READ_EXEC
                    } else {
                        ProtFlags::PROT_READ
                    },
                    MapFlags::MAP_PRIVATE,
                    fd,
                    0,
                )
                .unwrap();
            let site = UserPtrMut::<u8>::from_usize(address.as_usize() + SYSCALL_OFFSET);
            if !exec_at_mmap {
                assert_eq!(
                    site.to_owned_slice::<Platform>(2).unwrap().as_ref(),
                    &[0x0f, 0x05]
                );
                task.sys_mprotect(address, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
                    .unwrap();
            }
            assert_ne!(
                site.to_owned_slice::<Platform>(2).unwrap().as_ref(),
                &[0x0f, 0x05],
                "corrupted footer magic ({corruption:#x}) bypassed rewriting"
            );
            assert_eq!(
                mapping_permissions(&task, address),
                MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC
            );
            let trampoline = {
                let cache = task.global.elf_patch_cache.lock();
                let state = cache
                    .get(&elf_patch_key(&task, fd))
                    .expect("ELF state should be initialized");
                assert!(!state.pre_patched);
                state
                    .trampoline_mapped
                    .then_some((state.trampoline_addr, state.trampoline_mapped_len))
            };
            task.sys_munmap(address, PAGE_SIZE).unwrap();
            if let Some((start, len)) = trampoline {
                task.sys_munmap(UserPtrMut::from_usize(start), len).unwrap();
            }
            task.sys_close(fd).unwrap();
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mmap_corrupt_magic_does_not_bypass_rewriting() {
        check_corrupt_magic_rewriting(true);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mprotect_corrupt_magic_does_not_bypass_rewriting() {
        check_corrupt_magic_rewriting(false);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mprotect_rewrites_across_permission_boundaries() {
        let task = init_platform();
        let mut content = alloc::vec![0x90; 2 * PAGE_SIZE];
        content[PAGE_SIZE - 1] = 0x0f;
        content[PAGE_SIZE] = 0x05;
        create_file(&task, "/mprotect-boundary", &content);
        let fd = i32::try_from(
            task.sys_open("/mprotect-boundary", OFlags::RDONLY, Mode::empty())
                .expect("test file should open"),
        )
        .expect("file descriptor should fit i32");
        let address = task
            .do_mmap_file(
                None,
                2 * PAGE_SIZE,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd,
                0,
            )
            .expect("file mapping should succeed");
        task.global.elf_patch_cache.lock().insert(
            elf_patch_key(&task, fd),
            runtime_patch_state(
                BTreeSet::from([(address.as_usize(), 2 * PAGE_SIZE)]),
                address.as_usize() + 2 * PAGE_SIZE,
                false,
            ),
        );

        task.sys_mprotect(
            UserPtrMut::from_usize(address.as_usize() + PAGE_SIZE),
            PAGE_SIZE,
            ProtFlags::PROT_READ_WRITE,
        )
        .expect("second page permissions should change");
        task.sys_mprotect(address, 2 * PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
            .expect("whole mapping should become executable");

        let rewritten = UserPtrMut::<u8>::from_usize(address.as_usize() + PAGE_SIZE - 1)
            .to_owned_slice::<Platform>(2)
            .expect("rewritten bytes should remain readable");
        assert_ne!(rewritten.as_ref(), &[0x0f, 0x05]);

        task.sys_munmap(address, 2 * PAGE_SIZE)
            .expect("test mapping should unmap");
        task.sys_close(fd).expect("test file should close");
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
                BTreeSet::from([(address.as_usize(), 3 * PAGE_SIZE)]),
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
            .do_mmap_anonymous(
                None,
                PAGE_SIZE,
                ProtFlags::PROT_READ_WRITE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
            )
            .expect("first test mapping should succeed");
        let surviving = task
            .do_mmap_anonymous(
                None,
                PAGE_SIZE,
                ProtFlags::PROT_READ_WRITE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
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
    fn full_capacity_anywhere_precedes_preferred_one_page() {
        let calls = core::cell::RefCell::new(alloc::vec::Vec::new());
        let reservation = super::choose_trampoline_reservation(
            7 * PAGE_SIZE,
            PAGE_SIZE,
            |len| {
                calls.borrow_mut().push(("preferred", len));
                None
            },
            |len| {
                calls.borrow_mut().push(("anywhere", len));
                Some("full capacity")
            },
        );

        assert_eq!(reservation, Some(("full capacity", 7 * PAGE_SIZE)));
        assert_eq!(
            calls.into_inner(),
            alloc::vec![("preferred", 7 * PAGE_SIZE), ("anywhere", 7 * PAGE_SIZE),]
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
                use litebox::platform::{
                    RawConstPointer as _,
                    page_mgmt::{
                        AllocationDirection, FixedAddressBehavior, MemoryRegionPermissions,
                    },
                };

                let task_addr_min = <Platform as PageManagementProvider<4096>>::TASK_ADDR_MIN;
                let reservation_alignment =
                    <Platform as PageManagementProvider<4096>>::RESERVATION_ALIGNMENT;
                let suggested_start = task_addr_min + count * reservation_alignment;
                let allocation = <Platform as PageManagementProvider<4096>>::allocate_pages(
                    external_platform,
                    suggested_start..suggested_start + 0x1000,
                    MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                    false,
                    false,
                    FixedAddressBehavior::Hint(AllocationDirection::TopDown),
                )
                .unwrap()
                .as_usize();
                data.push(allocation);
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
        for allocation in data {
            // SAFETY: The page belongs to the external provider and has no outstanding references.
            unsafe {
                <Platform as PageManagementProvider<4096>>::release_pages(
                    external_platform,
                    allocation..allocation + 0x1000,
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

        create_file(&task, "/advice-file", &[0x5a; 0x1000]);
        let fd = i32::try_from(
            task.sys_open("/advice-file", OFlags::RDONLY, Mode::empty())
                .unwrap(),
        )
        .unwrap();
        task.sys_mmap(
            addr.as_usize() + 0x1000,
            0x1000,
            ProtFlags::PROT_READ,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            fd,
            0,
        )
        .unwrap();
        addr.write_slice_at_offset::<Platform>(0, &[0xff]).unwrap();
        for advice in [
            litebox_common_linux::MadviseBehavior::DontNeed,
            litebox_common_linux::MadviseBehavior::Free,
        ] {
            // An unsupported later file VMA must not discard the anonymous prefix.
            assert_eq!(task.sys_madvise(addr, 0x2000, advice), Err(Errno::EINVAL));
            assert_eq!(addr.read_at_offset::<Platform>(0), Some(0xff));
        }
        task.sys_close(fd).unwrap();
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
