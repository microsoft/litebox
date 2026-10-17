// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin virtual-memory syscalls and dynamic Mach-O rewriting.
//!
//! File-backed Mach-O code is rewritten when mapped executable or when a
//! previously mapped range becomes executable through `mprotect`. Mappings
//! retain cached rewrite metadata after their descriptors are closed.

use alloc::{collections::BTreeSet, sync::Arc, vec, vec::Vec};
use core::ops::Range;
use litebox::mm::page::{NonZeroAddress, NonZeroPageSize};
use litebox::{
    fs::errors::ReadError,
    platform::{
        RawConstPointer as _, RawMutPointer as _,
        page_mgmt::{AllocationDirection, MemoryRegionPermissions as Permissions},
    },
    utils::TruncateExt as _,
};
use litebox_common_linux::vmem::{CreatePagesFlags, MappingError, VmFlags, VmemProtectError};
use litebox_common_macos::{
    MmapFlags, PAGE_SIZE, VmProtection, errno::Errno, loader::MAX_IMAGE_SIZE,
};
use litebox_syscall_rewriter::{
    macho::{CodeMetadata, Rewriter},
    trampoline_allocation_range,
};

use crate::syscalls::file::{FileFd, FileSubsystem};
use crate::{SharedCacheRegion, SharedCacheTrampoline, ShimPlatform, Task};

#[derive(Clone, Copy, PartialEq, Eq)]
enum SharedCacheRewriteMode {
    Guest,
    HostAware,
    NativeThreadPointer,
}

/// File provenance and rewrite state retained for a live guest mapping.
pub(crate) struct MachoMapping {
    range: Range<usize>,
    file_offset: usize,
    patch_info: Arc<MachoPatchInfo>,
    patched_ranges: BTreeSet<(usize, usize)>,
    trampoline_invalidated: bool,
}

impl MachoMapping {
    fn slice(&self, range: Range<usize>) -> Self {
        debug_assert!(range.start >= self.range.start && range.end <= self.range.end);
        let intersect = |candidate: &Range<usize>| {
            let start = range.start.max(candidate.start);
            let end = range.end.min(candidate.end);
            (start < end).then_some(start..end)
        };
        Self {
            file_offset: self.file_offset + range.start - self.range.start,
            patched_ranges: self
                .patched_ranges
                .iter()
                .filter_map(|&(start, len)| {
                    intersect(&(start..start.saturating_add(len)))
                        .map(|range| (range.start, range.len()))
                })
                .collect(),
            range,
            patch_info: Arc::clone(&self.patch_info),
            trampoline_invalidated: self.trampoline_invalidated,
        }
    }
}

struct MachoPatchInfo {
    metadata: CodeMetadata,
    slice_range: Range<usize>,
    trampoline_capacity: usize,
    rewrite_id: Arc<()>,
}

impl MachoPatchInfo {
    fn load_span_for_mapping(
        &self,
        file_offset: usize,
        mapping_len: usize,
        mapping_address: usize,
    ) -> Result<Option<Range<usize>>, litebox_syscall_rewriter::Error> {
        let overflow =
            || litebox_syscall_rewriter::Error::AddressOverflow("Mach-O container mapping".into());
        let mapping_end = file_offset.checked_add(mapping_len).ok_or_else(overflow)?;
        let start = file_offset.max(self.slice_range.start);
        let end = mapping_end.min(self.slice_range.end);
        if start >= end {
            return Ok(None);
        }
        self.metadata.load_span_for_mapping(
            (start - self.slice_range.start) as u64,
            end - start,
            mapping_address
                .checked_add(start - file_offset)
                .ok_or_else(overflow)?,
        )
    }

    /// Project container-relative mmap offsets through the selected Mach-O slice.
    fn ranges_for_mapping(
        &self,
        file_offset: usize,
        mapping_len: usize,
    ) -> Result<Vec<Range<usize>>, litebox_syscall_rewriter::Error> {
        let mapping_end = file_offset.checked_add(mapping_len).ok_or_else(|| {
            litebox_syscall_rewriter::Error::AddressOverflow("Mach-O container mapping".into())
        })?;
        let start = file_offset.max(self.slice_range.start);
        let end = mapping_end.min(self.slice_range.end);
        if start >= end {
            return Ok(Vec::new());
        }
        let shift = start - file_offset;
        let slice_offset = u64::try_from(start - self.slice_range.start).map_err(|_| {
            litebox_syscall_rewriter::Error::AddressOverflow("Mach-O slice offset".into())
        })?;
        let mut ranges = self
            .metadata
            .ranges_for_mapping(slice_offset, end - start)?;
        for range in &mut ranges {
            range.start += shift;
            range.end += shift;
        }
        Ok(ranges)
    }
}

/// Shared append-only runtime trampoline for one parsed Mach-O image.
pub(crate) struct MachoRuntimeTrampoline {
    rewrite_id: Arc<()>,
    range: Option<Range<usize>>,
    cursor: usize,
    invalidated: bool,
}

struct MachoTrampolineCheckpoint {
    range: Option<Range<usize>>,
    cursor: usize,
}

/// Rewrite analysis attached to LiteBox's shared descriptor entry.
///
/// Entry metadata is visible through every descriptor produced by `dup`, so
/// aliases reuse both successful analysis and negative classification results.
#[derive(Clone)]
struct MachoPatchMetadata(Option<Arc<MachoPatchInfo>>);

fn permissions(protection: VmProtection) -> Permissions {
    let mut permissions = Permissions::empty();
    permissions.set(Permissions::READ, protection.contains(VmProtection::READ));
    permissions.set(Permissions::WRITE, protection.contains(VmProtection::WRITE));
    permissions.set(
        Permissions::EXEC,
        protection.contains(VmProtection::EXECUTE),
    );
    permissions
}

fn mapping_flags(
    flags: MmapFlags,
    file_backed: bool,
    direction: AllocationDirection,
) -> CreatePagesFlags {
    let mut result = CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;
    result.set(
        CreatePagesFlags::FIXED_ADDR,
        flags.contains(MmapFlags::FIXED),
    );
    result.set(CreatePagesFlags::SHARED, flags.contains(MmapFlags::SHARED));
    result.set(CreatePagesFlags::MAP_FILE, file_backed);
    result.set(
        CreatePagesFlags::TOP_DOWN,
        direction == AllocationDirection::TopDown,
    );
    result
}

fn mapping_error(error: MappingError) -> Errno {
    match error {
        MappingError::BadFD(_) => Errno::EBADF,
        MappingError::NotForReading => Errno::EACCES,
        MappingError::MemoryAccess => Errno::EFAULT,
        MappingError::OutOfMemory | MappingError::MapError(_) => Errno::ENOMEM,
        _ => Errno::EINVAL,
    }
}

fn mmap_read_error(error: ReadError) -> Errno {
    match error {
        ReadError::ClosedFd => Errno::EBADF,
        ReadError::NotAFile => Errno::EINVAL,
        ReadError::NotForReading => Errno::EACCES,
        _ => Errno::EIO,
    }
}

fn read_file_exact_at<P: ShimPlatform>(
    file: &litebox::fs::File<P>,
    mut bytes: &mut [u8],
    mut offset: usize,
) -> Result<(), Errno> {
    while !bytes.is_empty() {
        let read = file
            .read(bytes, Some(offset), None)
            .map_err(|_| Errno::EIO)?;
        if read == 0 || read > bytes.len() {
            return Err(Errno::EIO);
        }
        offset = offset.checked_add(read).ok_or(Errno::EFBIG)?;
        bytes = &mut bytes[read..];
    }
    Ok(())
}

fn protection_error(error: VmemProtectError) -> Errno {
    use litebox::platform::page_mgmt::PermissionUpdateError;

    match error {
        VmemProtectError::InvalidRange(_) => Errno::ENOMEM,
        VmemProtectError::NoAccess { .. } => Errno::EACCES,
        VmemProtectError::UnAligned(_) | VmemProtectError::UnsupportedProtection => Errno::EINVAL,
        VmemProtectError::ProtectError(error) => match error {
            PermissionUpdateError::Unallocated | PermissionUpdateError::OutOfMemory => {
                Errno::ENOMEM
            }
            PermissionUpdateError::PermissionDenied => Errno::EACCES,
            PermissionUpdateError::Unaligned | PermissionUpdateError::PlatformFailure => {
                Errno::EINVAL
            }
            _ => Errno::EINVAL,
        },
    }
}

struct MmapRequest {
    address: usize,
    length: usize,
    protection: VmProtection,
    flags: MmapFlags,
    fd: i32,
    offset: i64,
    direction: AllocationDirection,
}

fn record_patched_range(patched: &mut BTreeSet<(usize, usize)>, range: Range<usize>) {
    let mut merged = range;
    let mut remove = Vec::new();
    for &(start, len) in patched.iter() {
        let end = start.saturating_add(len);
        if end < merged.start {
            continue;
        }
        if start > merged.end {
            break;
        }
        merged.start = merged.start.min(start);
        merged.end = merged.end.max(end);
        remove.push((start, len));
    }
    for range in remove {
        patched.remove(&range);
    }
    patched.insert((merged.start, merged.len()));
}

fn forget_patched_range(patched: &mut BTreeSet<(usize, usize)>, range: Range<usize>) {
    let overlapping: Vec<_> = patched
        .iter()
        .copied()
        .filter(|&(start, len)| start < range.end && range.start < start.saturating_add(len))
        .collect();
    for (start, len) in overlapping {
        patched.remove(&(start, len));
        let end = start.saturating_add(len);
        if start < range.start {
            patched.insert((start, range.start - start));
        }
        if range.end < end {
            patched.insert((range.end, end - range.end));
        }
    }
}

fn reserve_shared_cache_gates(
    cursor: usize,
    gate_length: usize,
    capacity: usize,
) -> Option<Range<usize>> {
    let start =
        cursor.checked_next_multiple_of(litebox_syscall_rewriter::TRAMPOLINE_CURSOR_ALIGN)?;
    let end = start.checked_add(gate_length)?;
    (end <= capacity).then_some(start..end)
}

impl<P: ShimPlatform> Task<P> {
    fn mapping_snapshot(&self, target: Range<usize>) -> Vec<(Range<usize>, VmFlags)> {
        self.global
            .mm
            .mappings()
            .into_iter()
            .filter_map(|(range, flags)| {
                let start = range.start.max(target.start);
                let end = range.end.min(target.end);
                (start < end).then_some((start..end, flags))
            })
            .collect()
    }

    /// Rewrite one executable region of an externally prepared shared cache.
    pub(crate) fn rewrite_shared_cache_region(
        &self,
        region: &SharedCacheRegion<'_>,
        trampoline: &SharedCacheTrampoline,
        trampoline_cursor: usize,
    ) -> Result<usize, crate::SharedCacheInstallError> {
        use crate::SharedCacheInstallError as Error;
        const DARWIN_SVC: u32 = 0xd400_1001;
        const MRS_TPIDRRO_MASK: u32 = 0xffff_ffe0;
        const MRS_TPIDRRO_BITS: u32 = 0xd53b_d060;
        const MAX_BATCH_SPAN: usize = 64 * 1024;

        let length = region.range.len();
        let valid_ranges = |ranges: &[Range<usize>]| {
            !ranges.iter().any(|range| {
                range.start >= range.end
                    || range.end > length
                    || !range.start.is_multiple_of(size_of::<u32>())
                    || !range.end.is_multiple_of(size_of::<u32>())
            }) && !ranges.windows(2).any(|pair| pair[0].end > pair[1].start)
        };
        let range_sets = [
            region.guest_ranges,
            region.host_aware_ranges,
            region.native_thread_pointer_ranges,
        ];
        if range_sets.iter().all(|ranges| ranges.is_empty())
            || range_sets.iter().any(|ranges| !valid_ranges(ranges))
            || range_sets.iter().enumerate().any(|(index, ranges)| {
                range_sets[index + 1..].iter().any(|other| {
                    ranges.iter().any(|range| {
                        other.iter().any(|candidate| {
                            range.start < candidate.end && candidate.start < range.end
                        })
                    })
                })
            })
        {
            return Err(Error::InvalidRegion);
        }
        let pointer = P::RawMutPointer::<u8>::from_usize(region.writable_alias);
        let rewriter = Rewriter::new(crate::aarch64_rewrite_options().target_host())
            .map_err(|_| Error::Rewrite)?;
        let callback = self.global.platform.get_syscall_entry_point();
        let tls_offset = self
            .global
            .platform
            .guest_thread_pointer_offset()
            .and_then(|offset| u16::try_from(offset).ok())
            .ok_or(Error::Rewrite)?;
        let mut patches = Vec::new();
        let mut next_cursor = trampoline_cursor;
        for (ranges, mode) in [
            (region.guest_ranges, SharedCacheRewriteMode::Guest),
            (region.host_aware_ranges, SharedCacheRewriteMode::HostAware),
            (
                region.native_thread_pointer_ranges,
                SharedCacheRewriteMode::NativeThreadPointer,
            ),
        ] {
            let mut first = 0;
            while first < ranges.len() {
                let batch_start = ranges[first].start;
                let mut batch_end = ranges[first].end;
                let mut last = first + 1;
                while let Some(next) = ranges.get(last)
                    && next.end - batch_start <= MAX_BATCH_SPAN
                    && next.start - batch_end <= PAGE_SIZE
                {
                    batch_end = next.end;
                    last += 1;
                }
                let mut code =
                    P::RawMutPointer::<u8>::from_usize(region.writable_alias + batch_start)
                        .to_owned_slice(batch_end - batch_start)
                        .ok_or(Error::UnreadableAlias)?
                        .into_vec();
                let mut local_ranges: Vec<_> = ranges[first..last]
                    .iter()
                    .map(|range| range.start - batch_start..range.end - batch_start)
                    .collect();
                local_ranges.retain(|range| {
                    code[range.clone()].as_chunks::<4>().0.iter().any(|word| {
                        let word = u32::from_le_bytes(*word);
                        word == DARWIN_SVC
                            || (mode != SharedCacheRewriteMode::NativeThreadPointer
                                && word & MRS_TPIDRRO_MASK == MRS_TPIDRRO_BITS)
                    })
                });
                first = last;
                if local_ranges.is_empty() {
                    continue;
                }
                let cursor = next_cursor
                    .checked_next_multiple_of(litebox_syscall_rewriter::TRAMPOLINE_CURSOR_ALIGN)
                    .ok_or(Error::Rewrite)?;
                let gate_address = trampoline
                    .range
                    .start
                    .checked_add(cursor)
                    .ok_or(Error::Rewrite)?;
                let code_address = region
                    .range
                    .start
                    .checked_add(batch_start)
                    .ok_or(Error::Rewrite)?;
                let result = match mode {
                    SharedCacheRewriteMode::Guest => rewriter.patch_code_segment(
                        &mut code,
                        code_address as u64,
                        &local_ranges,
                        gate_address as u64,
                        callback as u64,
                        tls_offset,
                    ),
                    SharedCacheRewriteMode::HostAware => rewriter.patch_host_shared_cache_code(
                        &mut code,
                        code_address as u64,
                        &local_ranges,
                        gate_address as u64,
                        callback as u64,
                        tls_offset,
                    ),
                    SharedCacheRewriteMode::NativeThreadPointer => rewriter
                        .patch_native_guest_tpidrro_code(
                            &mut code,
                            code_address as u64,
                            &local_ranges,
                            gate_address as u64,
                            callback as u64,
                            tls_offset,
                        ),
                };
                let (gates, trapped) = result.map_err(|error| {
                    litebox_util_log::warn!(error:?; "failed to build shared-cache gates");
                    Error::Rewrite
                })?;
                let gate_range =
                    reserve_shared_cache_gates(next_cursor, gates.len(), trampoline.range.len())
                        .ok_or(Error::Rewrite)?;
                if !trapped.is_empty() {
                    litebox_util_log::warn!(trapped:? = trapped, gates:? = gates.len(), cursor:? = cursor; "shared-cache gates do not fit or cannot reach their sites");
                    return Err(Error::Rewrite);
                }
                P::RawMutPointer::<u8>::from_usize(trampoline.writable_alias + gate_range.start)
                    .copy_from_slice(0, &gates)
                    .ok_or(Error::Rewrite)?;
                next_cursor = gate_range.end;
                patches.push((batch_start, code, local_ranges));
            }
        }
        for (batch_start, code, local_ranges) in patches {
            for local_range in local_ranges {
                pointer
                    .copy_from_slice(batch_start + local_range.start, &code[local_range])
                    .ok_or(Error::Rewrite)?;
            }
        }
        Ok(next_cursor)
    }

    pub(crate) fn sys_mmap(
        &self,
        address: usize,
        length: usize,
        protection: VmProtection,
        flags: MmapFlags,
        fd: i32,
        offset: i64,
    ) -> Result<usize, Errno> {
        self.mmap(MmapRequest {
            address,
            length,
            protection,
            flags,
            fd,
            offset,
            direction: AllocationDirection::BottomUp,
        })
    }

    pub(crate) fn reserve_anonymous(
        &self,
        address: usize,
        length: usize,
        direction: AllocationDirection,
    ) -> Result<usize, Errno> {
        self.mmap(MmapRequest {
            address,
            length,
            protection: VmProtection::empty(),
            flags: MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
            fd: -1,
            offset: 0,
            direction,
        })
    }

    fn mmap(&self, request: MmapRequest) -> Result<usize, Errno> {
        let MmapRequest {
            address,
            length,
            protection,
            flags,
            fd,
            offset,
            direction,
        } = request;
        if length == 0
            || !address.is_multiple_of(PAGE_SIZE)
            || flags.contains(MmapFlags::SHARED) == flags.contains(MmapFlags::PRIVATE)
        {
            return Err(Errno::EINVAL);
        }
        let length = length
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Errno::ENOMEM)?;
        let offset = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        if !offset.is_multiple_of(PAGE_SIZE)
            || offset.checked_add(length).is_none()
            || address.checked_add(length).is_none()
        {
            return Err(Errno::EINVAL);
        }
        if flags.contains(MmapFlags::SHARED)
            && protection.contains(VmProtection::WRITE)
            && !flags.contains(MmapFlags::ANONYMOUS)
        {
            return Err(Errno::ENOTSUP);
        }
        let suggested = NonZeroAddress::new(address);
        let length = NonZeroPageSize::new(length).ok_or(Errno::EINVAL)?;
        let fixed_range = address..address + length.as_usize();
        let fixed_snapshot = flags
            .contains(MmapFlags::FIXED)
            .then(|| self.mapping_snapshot(fixed_range.clone()));
        if flags.contains(MmapFlags::ANONYMOUS) {
            // SAFETY: MAP_FIXED has Darwin's replacement semantics; otherwise
            // PageManager treats `suggested` only as an allocation hint.
            let result = unsafe {
                self.global.mm.create_pages_with_permissions(
                    suggested,
                    length,
                    mapping_flags(flags, false, direction),
                    permissions(protection),
                    None,
                    |_| Ok(0),
                )
            };
            let replaced = result.is_ok()
                || fixed_snapshot
                    .as_ref()
                    .is_some_and(|before| *before != self.mapping_snapshot(fixed_range.clone()));
            if flags.contains(MmapFlags::FIXED) && replaced {
                self.replace_macho_mappings(fixed_range.clone(), None);
            }
            return result
                .map(|pointer| pointer.as_usize())
                .map_err(mapping_error);
        }

        let file = self.files.typed_fd(fd)?;
        let contents = self.files.file(&file)?;
        let executable = protection.contains(VmProtection::EXECUTE);
        let macho = if executable {
            Some(self.macho_patch_info(&file)?)
        } else {
            self.macho_patch_info(&file).ok()
        };
        let ranges = if let Some(info) = macho.as_ref().filter(|_| executable) {
            info.ranges_for_mapping(offset, length.as_usize())
                .map_err(|_| Errno::ENOEXEC)?
        } else {
            Vec::new()
        };
        let final_permissions = permissions(protection);
        let trampoline_checkpoint = macho
            .as_ref()
            .filter(|_| executable)
            .map(|patch_info| self.macho_trampoline_checkpoint(patch_info));
        let mut file_offset = offset;
        let mut buffer = [0; PAGE_SIZE];
        let mut initialization_error = None;
        // SAFETY: MAP_FIXED has Darwin's replacement semantics. Initialization
        // runs while the new mapping is private to this syscall and still RW.
        let result = unsafe {
            self.global.mm.create_pages_with_permissions(
                suggested,
                length,
                mapping_flags(flags, true, direction),
                final_permissions,
                None,
                |pointer| {
                    let mut copied = 0;
                    while copied < length.as_usize() {
                        let chunk = (length.as_usize() - copied).min(buffer.len());
                        let read = contents
                            .read(&mut buffer[..chunk], Some(file_offset), None)
                            .map_err(|error| {
                                initialization_error = Some(error);
                                MappingError::NotForReading
                            })?;
                        if read == 0 {
                            break;
                        }
                        pointer
                            .copy_from_slice(copied, &buffer[..read])
                            .ok_or(MappingError::MemoryAccess)?;
                        copied += read;
                        file_offset = file_offset
                            .checked_add(read)
                            .expect("validated mapping offset and length cannot overflow");
                    }
                    if let Some(info) = macho.as_ref().filter(|_| executable) {
                        self.rewrite_macho_mapping(
                            pointer,
                            length.as_usize(),
                            &ranges,
                            info,
                            offset,
                        )?;
                    }
                    Ok(copied)
                },
            )
        };
        let pointer = match result {
            Ok(pointer) => pointer,
            Err(error) => {
                if let (Some(patch_info), Some(checkpoint)) =
                    (macho.as_ref(), trampoline_checkpoint)
                {
                    self.rollback_macho_trampoline(patch_info, checkpoint);
                }
                let replaced = fixed_snapshot
                    .as_ref()
                    .is_some_and(|before| *before != self.mapping_snapshot(fixed_range.clone()));
                if flags.contains(MmapFlags::FIXED) && replaced {
                    self.replace_macho_mappings(fixed_range.clone(), None);
                }
                return Err(
                    initialization_error.map_or_else(|| mapping_error(error), mmap_read_error)
                );
            }
        };
        let address = pointer.as_usize();
        let mapping = macho.map(|patch_info| {
            let mut patched_ranges = BTreeSet::new();
            if executable {
                record_patched_range(&mut patched_ranges, address..address + length.as_usize());
            }
            MachoMapping {
                range: address..address + length.as_usize(),
                file_offset: offset,
                patch_info,
                patched_ranges,
                trampoline_invalidated: false,
            }
        });
        if flags.contains(MmapFlags::FIXED) || mapping.is_some() {
            self.replace_macho_mappings(address..address + length.as_usize(), mapping);
        }
        Ok(address)
    }

    // TODO: serialize this checkpoint through rollback with other mmap-based
    // rewrites before supporting concurrent mmap of the same Mach-O. The
    // current task model does not run mmap-based rewriting concurrently.
    fn macho_trampoline_checkpoint(
        &self,
        patch_info: &Arc<MachoPatchInfo>,
    ) -> MachoTrampolineCheckpoint {
        let key = Arc::as_ptr(&patch_info.rewrite_id) as usize;
        let trampolines = self.global.macho_trampolines.lock();
        if let Some(state) = trampolines.get(&key) {
            MachoTrampolineCheckpoint {
                range: state.range.clone(),
                cursor: state.cursor,
            }
        } else {
            MachoTrampolineCheckpoint {
                range: None,
                cursor: 0,
            }
        }
    }

    fn rollback_macho_trampoline(
        &self,
        patch_info: &Arc<MachoPatchInfo>,
        checkpoint: MachoTrampolineCheckpoint,
    ) {
        self.rollback_macho_trampoline_for_id(&patch_info.rewrite_id, checkpoint);
    }

    fn rollback_macho_trampoline_for_id(
        &self,
        rewrite_id: &Arc<()>,
        checkpoint: MachoTrampolineCheckpoint,
    ) {
        let key = Arc::as_ptr(rewrite_id) as usize;
        let mut trampolines = self.global.macho_trampolines.lock();
        let Some(state) = trampolines.get_mut(&key) else {
            return;
        };
        if state.invalidated {
            // Invalidated ownership cannot be restored.
            return;
        }
        let current = state.range.clone();
        let MachoTrampolineCheckpoint { range, cursor } = checkpoint;
        if range.is_some() {
            state.range.clone_from(&range);
            state.cursor = cursor;
        } else {
            trampolines.remove(&key);
        }
        drop(trampolines);

        if range.is_none()
            && let Some(current) = current
        {
            self.remove_trampoline(current);
        }
    }

    fn rewrite_macho_mapping(
        &self,
        pointer: P::RawMutPointer<u8>,
        length: usize,
        ranges: &[core::ops::Range<usize>],
        patch_info: &MachoPatchInfo,
        file_offset: usize,
    ) -> Result<(), MappingError> {
        if ranges.is_empty() {
            return Ok(());
        }
        let rewriter = Rewriter::new(crate::aarch64_rewrite_options().target_host())
            .map_err(|_| MappingError::OutOfMemory)?;
        let callback = self.global.platform.get_syscall_entry_point();
        if callback == 0 {
            litebox_util_log::warn!(
                "skipping Mach-O mapping rewrite because the platform supplied no syscall callback"
            );
            return Ok(());
        }
        let original = pointer
            .to_owned_slice(length)
            .ok_or(MappingError::OutOfMemory)?
            .into_vec();
        let virtual_address = pointer.as_usize();
        let trap_fallback = |error: &dyn core::fmt::Display| {
            litebox_util_log::warn!(error:% = error; "using traps for Mach-O mapping rewrite");
            let mut trapped = original.clone();
            let count = rewriter
                .trap_code_segment(&mut trapped, virtual_address as u64, ranges)
                .map_err(|rewrite_error| {
                    litebox_util_log::error!(error:% = rewrite_error; "Mach-O trap fallback failed");
                    MappingError::OutOfMemory
                })?;
            if count != 0 {
                litebox_util_log::warn!(count:? = count, address:? = pointer.as_usize(), length:? = length; "trapped Mach-O patch sites");
            }
            pointer
                .copy_from_slice(0, &trapped)
                .ok_or(MappingError::OutOfMemory)
        };
        let Some(tls_offset) = self
            .global
            .platform
            .guest_thread_pointer_offset()
            .and_then(|offset| u16::try_from(offset).ok())
        else {
            return trap_fallback(&"invalid guest thread-pointer offset");
        };

        let load_span = match patch_info.load_span_for_mapping(file_offset, length, virtual_address)
        {
            Ok(span) => span,
            Err(error) => return trap_fallback(&error),
        };
        let code_end = virtual_address
            .checked_add(length)
            .ok_or(MappingError::OutOfMemory)?;
        let code_span = load_span.map_or(virtual_address..code_end, |span| {
            span.start.min(virtual_address)..span.end.max(code_end)
        });
        let Some(allowed_range) = trampoline_allocation_range(code_span) else {
            return trap_fallback(&"Mach-O image exceeds trampoline branch reach");
        };
        let rewrite_id = &patch_info.rewrite_id;
        let key = Arc::as_ptr(rewrite_id) as usize;
        let mut trampolines = self.global.macho_trampolines.lock();
        let state = trampolines
            .entry(key)
            .or_insert_with(|| MachoRuntimeTrampoline {
                rewrite_id: Arc::clone(rewrite_id),
                range: None,
                cursor: 0,
                invalidated: false,
            });
        debug_assert!(Arc::ptr_eq(&state.rewrite_id, rewrite_id));
        if state.invalidated {
            return Err(MappingError::OutOfMemory);
        }
        if state
            .range
            .as_ref()
            .is_some_and(|range| range.start < allowed_range.start || range.end > allowed_range.end)
        {
            return trap_fallback(&"Mach-O trampoline is outside branch reach");
        }
        let newly_allocated = state.range.is_none();
        if newly_allocated {
            let capacity = patch_info.trampoline_capacity;
            let Some(length) = NonZeroPageSize::new(capacity) else {
                return trap_fallback(&"invalid Mach-O trampoline capacity");
            };
            // SAFETY: no fixed address or replacement is requested; the entire
            // allocation is constrained to unused pages within branch reach.
            let allocation = unsafe {
                self.global.mm.create_pages_with_permissions(
                    None,
                    length,
                    CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY | CreatePagesFlags::TOP_DOWN,
                    Permissions::READ | Permissions::WRITE,
                    Some(allowed_range),
                    |_| Ok(0),
                )
            };
            state.range = match allocation {
                Ok(pointer) => Some(pointer.as_usize()..pointer.as_usize() + capacity),
                Err(error) => return trap_fallback(&error),
            };
            state.cursor = 0;
        }
        let range = state.range.clone().expect("trampoline was just allocated");
        let cursor = state
            .cursor
            .checked_next_multiple_of(litebox_syscall_rewriter::TRAMPOLINE_CURSOR_ALIGN)
            .ok_or(MappingError::OutOfMemory)?;
        let trampoline_address = range
            .start
            .checked_add(cursor)
            .ok_or(MappingError::OutOfMemory)?;
        let mut code = original.clone();
        let patch = rewriter.patch_code_segment(
            &mut code,
            virtual_address as u64,
            ranges,
            trampoline_address as u64,
            callback as u64,
            tls_offset,
        );
        let (gates, trapped) = match patch {
            Ok(result) => result,
            Err(error) => {
                if newly_allocated {
                    state.range = None;
                    self.remove_trampoline(range);
                }
                return trap_fallback(&error);
            }
        };
        if !trapped.is_empty() {
            litebox_util_log::warn!(count:? = trapped.len(), addresses:? = trapped; "Mach-O patch sites fell back to traps");
        }
        if gates.is_empty() {
            if newly_allocated {
                state.range = None;
                self.remove_trampoline(range);
            }
            return pointer
                .copy_from_slice(0, &code)
                .ok_or(MappingError::OutOfMemory);
        }
        let new_cursor = cursor
            .checked_add(gates.len())
            .ok_or(MappingError::OutOfMemory)?;
        if new_cursor > range.len() {
            if newly_allocated {
                state.range = None;
                self.remove_trampoline(range);
            }
            return trap_fallback(&"Mach-O trampoline capacity exhausted");
        }
        // Existing gates are RX. Temporarily make the shared region writable,
        // append the new gates, then publish all gates RX before code branches.
        if !newly_allocated {
            // SAFETY: `range` is the live trampoline allocation, and the
            // trampoline lock serializes permission changes and gate appends.
            unsafe {
                self.global.mm.change_page_permissions(
                    P::RawMutPointer::from_usize(range.start),
                    range.len(),
                    Permissions::READ | Permissions::WRITE,
                )
            }
            .map_err(MappingError::ProtectError)?;
        }
        if P::RawMutPointer::from_usize(range.start)
            .copy_from_slice(cursor, &gates)
            .is_none()
        {
            if newly_allocated {
                state.range = None;
                self.remove_trampoline(range);
            } else {
                // SAFETY: `range` remains the live trampoline allocation and
                // the trampoline lock still serializes this RX restoration.
                let _ = unsafe {
                    self.global.mm.change_page_permissions(
                        P::RawMutPointer::from_usize(range.start),
                        range.len(),
                        Permissions::READ | Permissions::EXEC,
                    )
                };
            }
            return Err(MappingError::OutOfMemory);
        }
        // SAFETY: no code points to the newly appended gates until the final
        // code copy. The RW-to-RX transition synchronizes instruction caches.
        unsafe {
            self.global.mm.change_page_permissions(
                P::RawMutPointer::from_usize(range.start),
                range.len(),
                Permissions::READ | Permissions::EXEC,
            )
        }
        .map_err(MappingError::ProtectError)?;
        if pointer.copy_from_slice(0, &code).is_none() {
            return Err(MappingError::OutOfMemory);
        }
        state.cursor = new_cursor;
        Ok(())
    }

    /// Remove tracking for `replaced`, preserving any mapped prefix and suffix,
    /// and optionally install the mapping that replaced it. Published runtime
    /// trampolines follow the Linux baseline and live until address-space teardown.
    fn replace_macho_mappings(&self, replaced: Range<usize>, replacement: Option<MachoMapping>) {
        let invalidated: Vec<_> = {
            let mut trampolines = self.global.macho_trampolines.lock();
            trampolines
                .iter_mut()
                .filter_map(|(&key, state)| {
                    let range = state.range.as_ref()?;
                    (range.start < replaced.end && replaced.start < range.end).then(|| {
                        state.invalidated = true;
                        key
                    })
                })
                .collect()
        };
        let mut mappings = self.global.macho_mappings.lock();
        for mapping in mappings.values_mut() {
            if invalidated.contains(&(Arc::as_ptr(&mapping.patch_info.rewrite_id) as usize)) {
                mapping.trampoline_invalidated = true;
            }
        }
        let overlapping: Vec<_> = mappings
            .iter()
            .filter(|(_, mapping)| {
                mapping.range.start < replaced.end && replaced.start < mapping.range.end
            })
            .map(|(&start, _)| start)
            .collect();
        let mut survivors = Vec::new();
        for start in overlapping {
            let mapping = mappings
                .remove(&start)
                .expect("overlapping Mach-O mapping disappeared while locked");
            if mapping.range.start < replaced.start {
                survivors.push(
                    mapping.slice(mapping.range.start..mapping.range.end.min(replaced.start)),
                );
            }
            if mapping.range.end > replaced.end {
                survivors
                    .push(mapping.slice(mapping.range.start.max(replaced.end)..mapping.range.end));
            }
        }
        for mapping in survivors.into_iter().chain(replacement) {
            mappings.insert(mapping.range.start, mapping);
        }
    }

    fn remove_trampoline(&self, range: Range<usize>) {
        // SAFETY: only unpublished or no-longer-referenced trampoline ranges
        // are passed here.
        if let Err(error) = unsafe {
            self.global
                .mm
                .remove_pages(P::RawMutPointer::from_usize(range.start), range.len())
        } {
            litebox_util_log::warn!(error:? = error; "failed to release Mach-O trampoline");
        }
    }

    fn cache_macho_patch_info(&self, file: &FileFd<P>, patch_info: Option<Arc<MachoPatchInfo>>) {
        self.global
            .litebox
            .descriptor_table_mut()
            .set_entry_metadata::<FileSubsystem<P>, _>(file, MachoPatchMetadata(patch_info));
    }

    fn macho_patch_info(&self, file: &Arc<FileFd<P>>) -> Result<Arc<MachoPatchInfo>, Errno> {
        if let Ok(patch_info) = self
            .global
            .litebox
            .descriptor_table()
            .with_metadata::<FileSubsystem<P>, MachoPatchMetadata, _>(file, |metadata| {
                metadata.0.clone()
            })
        {
            return patch_info.ok_or(Errno::ENOEXEC);
        }
        let contents = self.files.file(file)?;
        // Status and oversize failures are deliberately not cached: the backing
        // file may change and become a valid, bounded image before a later mmap.
        let size = contents.status().map_err(|_| Errno::EIO)?.size;
        if size > u64::try_from(MAX_IMAGE_SIZE).expect("image limit fits in u64") {
            return Err(Errno::EFBIG);
        }
        let size: usize = size.trunc();
        let mut header = [0; litebox_common_macos::loader::MACH_HEADER_SIZE];
        let supported_header = if size < header.len() {
            false
        } else {
            read_file_exact_at(&contents, &mut header, 0)?;
            litebox_common_macos::loader::may_contain_arm64_macho(&header)
        };
        if !supported_header {
            self.cache_macho_patch_info(file, None);
            return Err(Errno::ENOEXEC);
        }
        let mut bytes = vec![0; size];
        read_file_exact_at(&contents, &mut bytes, 0)?;
        let parsed = (|| {
            let slice_range = litebox_common_macos::loader::arm64_slice_range(&bytes)
                .map_err(|_| Errno::ENOEXEC)?;
            let slice = &bytes[slice_range.clone()];
            let metadata = CodeMetadata::parse(slice).map_err(|error| {
                litebox_util_log::warn!(error:% = error; "refusing executable mmap of invalid Mach-O");
                Errno::ENOEXEC
            })?;
            Ok::<_, Errno>((slice_range, metadata))
        })();
        let (slice_range, metadata) = match parsed {
            Ok(parsed) => parsed,
            Err(error) => {
                self.cache_macho_patch_info(file, None);
                return Err(error);
            }
        };
        let slice = &bytes[slice_range.clone()];
        let trampoline_capacity = metadata
            .trampoline_size_upper_bound(
                slice,
                crate::aarch64_rewrite_options(),
            )
            .and_then(|size| {
                size.max(PAGE_SIZE)
                    .checked_next_multiple_of(PAGE_SIZE)
                    .ok_or_else(|| litebox_syscall_rewriter::Error::AddressOverflow(
                        "Mach-O trampoline size".into(),
                    ))
            })
            .unwrap_or_else(|error| {
                litebox_util_log::warn!(error:% = error; "Mach-O sizing unavailable; using one trampoline page");
                PAGE_SIZE
            });
        let patch_info = Arc::new(MachoPatchInfo {
            metadata,
            slice_range,
            trampoline_capacity,
            rewrite_id: Arc::new(()),
        });
        self.cache_macho_patch_info(file, Some(Arc::clone(&patch_info)));
        Ok(patch_info)
    }

    fn rewrite_mprotect_range(&self, address: usize, length: usize) -> Result<(), Errno> {
        struct RewriteRange {
            mapping_start: usize,
            range: Range<usize>,
            file_offset: usize,
            patch_info: Arc<MachoPatchInfo>,
        }

        let end = address + length;
        // Serialize discovery, rewriting, and publication with munmap and other
        // executable transitions. The page-manager operations below do not
        // acquire `macho_mappings`.
        let mut mappings = self.global.macho_mappings.lock();
        let patches = {
            let mut patches = Vec::new();
            for (&mapping_start, mapping) in mappings.iter() {
                let start = address.max(mapping.range.start);
                let patch_end = end.min(mapping.range.end);
                if start >= patch_end {
                    continue;
                }
                if mapping.trampoline_invalidated {
                    return Err(Errno::ENOMEM);
                }
                let mut cursor = start;
                for &(patched_start, patched_len) in &mapping.patched_ranges {
                    let patched_end = patched_start.saturating_add(patched_len);
                    if patched_end <= cursor || patched_start >= patch_end {
                        continue;
                    }
                    if cursor < patched_start {
                        patches.push(RewriteRange {
                            mapping_start,
                            range: cursor..patched_start.min(patch_end),
                            file_offset: mapping.file_offset + cursor - mapping.range.start,
                            patch_info: Arc::clone(&mapping.patch_info),
                        });
                    }
                    cursor = cursor.max(patched_end);
                    if cursor >= patch_end {
                        break;
                    }
                }
                if cursor < patch_end {
                    patches.push(RewriteRange {
                        mapping_start,
                        range: cursor..patch_end,
                        file_offset: mapping.file_offset + cursor - mapping.range.start,
                        patch_info: Arc::clone(&mapping.patch_info),
                    });
                }
            }
            patches
        };

        for patch in patches {
            let ranges = patch
                .patch_info
                .ranges_for_mapping(patch.file_offset, patch.range.len())
                .map_err(|_| Errno::ENOEXEC)?;
            if ranges.is_empty() {
                let completed = &mut mappings
                    .get_mut(&patch.mapping_start)
                    .expect("Mach-O mapping disappeared while its state lock was held")
                    .patched_ranges;
                record_patched_range(completed, patch.range.clone());
                continue;
            }
            let previous: Vec<_> = self
                .global
                .mm
                .mappings()
                .into_iter()
                .filter_map(|(range, flags)| {
                    let start = patch.range.start.max(range.start);
                    let end = patch.range.end.min(range.end);
                    (start < end).then(|| (start..end, Permissions::from(flags)))
                })
                .collect();
            let mut made_writable = Vec::new();
            for (range, previous_permissions) in &previous {
                if let Err(error) = self.change_initialization_permissions(
                    range.clone(),
                    Permissions::READ | Permissions::WRITE,
                ) {
                    for (range, previous_permissions) in made_writable {
                        let _ = self.change_initialization_permissions(range, previous_permissions);
                    }
                    return Err(error);
                }
                made_writable.push((range.clone(), *previous_permissions));
            }
            let rewrite = self.rewrite_macho_mapping(
                P::RawMutPointer::from_usize(patch.range.start),
                patch.range.len(),
                &ranges,
                &patch.patch_info,
                patch.file_offset,
            );
            let mut restore_error = None;
            for (range, previous_permissions) in previous {
                if let Err(error) =
                    self.change_initialization_permissions(range, previous_permissions)
                    && restore_error.is_none()
                {
                    restore_error = Some(error);
                }
            }
            rewrite.map_err(mapping_error)?;
            let mapping = mappings
                .get_mut(&patch.mapping_start)
                .expect("Mach-O mapping disappeared while its state lock was held");
            record_patched_range(&mut mapping.patched_ranges, patch.range.clone());
            if let Some(error) = restore_error {
                return Err(error);
            }
        }
        Ok(())
    }

    fn change_initialization_permissions(
        &self,
        range: Range<usize>,
        permissions: Permissions,
    ) -> Result<(), Errno> {
        // SAFETY: the Mach-O mapping lock serializes rewriting and mapping
        // lifetime. This platform-only transition intentionally bypasses the
        // guest mapping's VM_MAYWRITE restriction and is restored before the
        // guest-visible mprotect completes.
        unsafe {
            self.global
                .platform
                .protect_pages(core::iter::empty, range, permissions)
        }
        .map_err(|error| protection_error(VmemProtectError::ProtectError(error)))
    }

    fn change_permissions(
        &self,
        range: Range<usize>,
        protection: VmProtection,
    ) -> Result<(), Errno> {
        // SAFETY: PageManager validates the tracked range and maximum allowed
        // permissions. Callers prevent concurrent execution while rewriting.
        unsafe {
            self.global.mm.change_page_permissions(
                P::RawMutPointer::from_usize(range.start),
                range.len(),
                permissions(protection),
            )
        }
        .map_err(protection_error)
    }

    pub(crate) fn sys_munmap(&self, address: usize, length: usize) -> Result<(), Errno> {
        let length = length
            .checked_next_multiple_of(PAGE_SIZE)
            .filter(|length| *length != 0)
            .ok_or(Errno::EINVAL)?;
        address.checked_add(length).ok_or(Errno::EINVAL)?;
        // SAFETY: Darwin munmap relinquishes the caller-selected guest range.
        unsafe {
            self.global
                .mm
                .remove_pages(P::RawMutPointer::from_usize(address), length)
        }
        .map_err(|_| Errno::EINVAL)?;
        self.replace_macho_mappings(address..address + length, None);
        Ok(())
    }

    pub(crate) fn sys_mprotect(
        &self,
        address: usize,
        length: usize,
        protection: VmProtection,
    ) -> Result<(), Errno> {
        if !address.is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        if length == 0 {
            return Ok(());
        }
        let length = length
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Errno::EINVAL)?;
        let end = address.checked_add(length).ok_or(Errno::EINVAL)?;
        let dyld_range = self.global.privately_mapped_dyld_range.lock().clone();
        // This process-lifetime override lets dyld update DATA_CONST: its
        // helper restarts at the authenticated call site after a fault, so a
        // read-only transition would repeatedly fault before the write. Remove
        // it when those protection transitions can complete without that loop.
        let protection = if dyld_range
            .as_ref()
            .is_some_and(|dyld| address >= dyld.start && end <= dyld.end)
            && protection.contains(VmProtection::READ)
            && !protection.intersects(VmProtection::WRITE | VmProtection::EXECUTE)
        {
            protection | VmProtection::WRITE
        } else {
            protection
        };
        if protection.contains(VmProtection::EXECUTE) {
            self.rewrite_mprotect_range(address, length)?;
        }
        let range = address..end;
        if protection.contains(VmProtection::WRITE) {
            // Publish writable permissions and invalidate rewrite state while
            // holding the same lock used by executable transitions. Code may
            // be changed as soon as this syscall returns.
            let mut mappings = self.global.macho_mappings.lock();
            self.change_permissions(range.clone(), protection)?;
            for mapping in mappings.values_mut().filter(|mapping| {
                mapping.range.start < range.end && range.start < mapping.range.end
            }) {
                forget_patched_range(&mut mapping.patched_ranges, range.clone());
            }
            Ok(())
        } else {
            self.change_permissions(range.clone(), protection)?;
            Ok(())
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    extern crate std;

    use super::*;
    use alloc::{sync::Arc, vec::Vec};
    use core::sync::atomic::AtomicI32;
    use litebox::LiteBox;
    use litebox_broker_core::{
        ObjectRights, PolicyEngine,
        fs::{
            in_mem::{InMem, InitialNode},
            resolver::Resolver,
        },
        test_support::TestBrokerCoreBuilder,
    };
    use litebox_broker_host::test_support::InProcessBrokerSetup;
    use litebox_broker_local::BrokerLocal;
    use litebox_broker_protocol::fs::{FileAccessMode, FileMode, FileOpenFlags, FileUser};
    use litebox_common_linux::{PtRegs, vmem::VmFlags};
    use litebox_common_macos::{TaskParams, syscall::nr, user_pointers::UserPtr};
    use litebox_platform_macos_userland::MacosUserland as Platform;
    use litebox_syscall_rewriter::aarch64::{GateMetadata, decode_branch_target};

    use crate::{MacosShimBuilder, Process};

    const TEXT: usize = 0x400;
    const SVC: u32 = 0xd400_1001;

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn macho_image() -> Vec<u8> {
        const BASE: u64 = 0x1_0000_0000;
        const SECTION: usize = 32 + 72;
        let mut bytes = vec![0; PAGE_SIZE];
        put32(&mut bytes, 0, 0xfeed_facf); // MH_MAGIC_64
        put32(&mut bytes, 4, 0x0100_000c); // CPU_TYPE_ARM64
        put32(&mut bytes, 12, 6); // MH_DYLIB
        put32(&mut bytes, 16, 1);
        put32(&mut bytes, 20, 72 + 80);
        put32(&mut bytes, 24, 0x20_0000); // MH_PIE
        put32(&mut bytes, 32, 0x19); // LC_SEGMENT_64
        put32(&mut bytes, 36, 72 + 80);
        bytes[40..46].copy_from_slice(b"__TEXT");
        put64(&mut bytes, 56, BASE);
        put64(&mut bytes, 64, PAGE_SIZE as u64);
        put64(&mut bytes, 80, PAGE_SIZE as u64);
        put32(&mut bytes, 88, 5);
        put32(&mut bytes, 92, 5);
        put32(&mut bytes, 96, 1);
        bytes[SECTION..SECTION + 6].copy_from_slice(b"__text");
        bytes[SECTION + 16..SECTION + 22].copy_from_slice(b"__TEXT");
        put64(&mut bytes, SECTION + 32, BASE + TEXT as u64);
        put64(&mut bytes, SECTION + 40, 4);
        put32(&mut bytes, SECTION + 48, u32::try_from(TEXT).unwrap());
        put32(&mut bytes, SECTION + 52, 2);
        put32(&mut bytes, SECTION + 64, 0x8000_0000); // S_ATTR_PURE_INSTRUCTIONS
        put32(&mut bytes, TEXT, SVC);
        bytes
    }

    fn universal_macho_image() -> Vec<u8> {
        let thin = macho_image();
        let offset = PAGE_SIZE;
        let mut fat = vec![0; offset + thin.len()];
        fat[..4].copy_from_slice(&0xcafebabfu32.to_be_bytes()); // FAT_MAGIC_64
        fat[4..8].copy_from_slice(&1u32.to_be_bytes());
        fat[8..12].copy_from_slice(&0x0100_000cu32.to_be_bytes()); // CPU_TYPE_ARM64
        fat[12..16].copy_from_slice(&0u32.to_be_bytes()); // CPU_SUBTYPE_ARM64_ALL
        fat[16..24].copy_from_slice(&u64::try_from(offset).unwrap().to_be_bytes());
        fat[24..32].copy_from_slice(&u64::try_from(thin.len()).unwrap().to_be_bytes());
        fat[32..36].copy_from_slice(&14u32.to_be_bytes()); // 16 KiB alignment
        fat[offset..].copy_from_slice(&thin);
        fat
    }

    fn task_with_file(data: &[u8]) -> Task<Platform> {
        let platform = Platform::new();
        let mode = FileMode::RWXU | FileMode::RWXG | FileMode::RWXO;
        let fs = InMem::<Platform>::new_initialized(vec![
            (
                "/",
                InitialNode::Directory {
                    mode,
                    owner: FileUser::ROOT,
                },
            ),
            (
                "/image",
                InitialNode::File {
                    mode,
                    owner: FileUser::ROOT,
                    data: data.to_vec().into(),
                },
            ),
        ]);
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_file_service(Arc::new(Resolver::<Platform, _>::new(fs)))
        .build()
        .unwrap();
        let setup = InProcessBrokerSetup::new(broker);
        let readiness = setup.readiness_sink();
        let (local, _startup, ()) = BrokerLocal::negotiate(setup, |setup| {
            let memory = setup.shared_memory();
            Ok((setup.activate(), memory, ()))
        })
        .unwrap();
        let litebox = LiteBox::new_with_broker_local(platform, local);
        readiness.attach(litebox.broker_notification_dispatcher());
        let mut builder = MacosShimBuilder::new_with_litebox(platform, litebox);
        let file = builder
            .litebox()
            .open_file(
                &litebox::fs::Context::new(),
                "/image",
                FileAccessMode::ReadOnly,
                FileOpenFlags::NONE,
                FileMode::empty(),
            )
            .unwrap();
        assert_eq!(builder.inherit_file(file), Ok(0));
        let shim = builder.build();
        let thread = crate::ThreadState::new(1u64 << 32, shim.global.platform);
        Task {
            global: shim.global,
            files: shim.files,
            params: TaskParams::default(),
            process: Process(Arc::new(AtomicI32::new(-1))),
            thread,
        }
    }

    fn mmap_with_protection(
        task: &Task<Platform>,
        protection: VmProtection,
    ) -> Result<usize, Errno> {
        let mut ctx = PtRegs::default();
        ctx.regs[16] = nr::MMAP;
        ctx.regs[1] = PAGE_SIZE;
        ctx.regs[2] = usize::try_from(protection.bits().cast_unsigned()).unwrap();
        ctx.regs[3] = usize::try_from(MmapFlags::PRIVATE.bits().cast_unsigned()).unwrap();
        ctx.regs[4] = 0;
        task.do_syscall(&ctx)
    }

    #[test]
    fn patched_ranges_merge_adjacent_updates() {
        let mut patched = BTreeSet::new();
        for page in 0..128 {
            let start = page * PAGE_SIZE;
            record_patched_range(&mut patched, start..start + PAGE_SIZE);
        }
        assert_eq!(patched, BTreeSet::from([(0, 128 * PAGE_SIZE)]));
    }

    #[test]
    fn forgetting_patched_range_preserves_disjoint_sides() {
        let mut patched = BTreeSet::from([(PAGE_SIZE, 3 * PAGE_SIZE)]);
        forget_patched_range(&mut patched, 2 * PAGE_SIZE..3 * PAGE_SIZE);
        assert_eq!(
            patched,
            BTreeSet::from([(PAGE_SIZE, PAGE_SIZE), (3 * PAGE_SIZE, PAGE_SIZE),])
        );
    }

    #[test]
    fn mprotect_validates_ranges() {
        let platform = Platform::new();
        let shim = MacosShimBuilder::new(platform).build();
        let thread = crate::ThreadState::new(1u64 << 32, shim.global.platform);
        let task = Task {
            global: shim.global,
            files: shim.files,
            params: TaskParams::default(),
            process: Process(Arc::new(AtomicI32::new(-1))),
            thread,
        };

        assert_eq!(
            task.sys_mprotect(PAGE_SIZE, PAGE_SIZE, VmProtection::READ),
            Err(Errno::ENOMEM)
        );
        assert_eq!(
            task.sys_mprotect(1, 0, VmProtection::READ),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn readonly_mappings_track_the_whole_image_without_allocating_trampoline() {
        let mut image = macho_image();
        put64(&mut image, 64, (4 * PAGE_SIZE) as u64);
        let task = task_with_file(&image);
        let before = task.global.mm.mappings();
        let first = mmap_with_protection(&task, VmProtection::READ).unwrap();
        let after_first = task.global.mm.mappings();
        let second = mmap_with_protection(&task, VmProtection::READ).unwrap();
        assert!(task.global.macho_trampolines.lock().is_empty());
        {
            let mappings = task.global.macho_mappings.lock();
            assert_eq!(
                mappings[&first]
                    .patch_info
                    .load_span_for_mapping(0, PAGE_SIZE, first)
                    .unwrap(),
                Some(first..first + 4 * PAGE_SIZE),
            );
        }
        task.sys_munmap(second, PAGE_SIZE).unwrap();
        assert_eq!(task.global.mm.mappings(), after_first);
        task.sys_close(0).unwrap();
        task.sys_munmap(first, PAGE_SIZE).unwrap();
        assert_eq!(task.global.mm.mappings(), before);
    }

    #[test]
    fn sizing_failure_uses_traps_without_growing_trampoline() {
        let mut image = macho_image();
        image.resize(2 * PAGE_SIZE, 0);
        put64(&mut image, 64, (2 * PAGE_SIZE) as u64);
        put64(&mut image, 80, (2 * PAGE_SIZE) as u64);
        put64(&mut image, 32 + 72 + 40, (PAGE_SIZE + 4 - TEXT) as u64);
        for offset in (TEXT..PAGE_SIZE).step_by(4) {
            put32(&mut image, offset, SVC);
        }
        // Unsupported SVC in an unmapped page prevents whole-file sizing.
        put32(&mut image, PAGE_SIZE, 0xd400_0001);
        let task = task_with_file(&image);
        let address = mmap_with_protection(&task, VmProtection::READ).unwrap();
        task.sys_close(0).unwrap();
        task.sys_mprotect(
            address,
            PAGE_SIZE,
            VmProtection::READ | VmProtection::EXECUTE,
        )
        .unwrap();
        let code = UserPtr::<u8>::from_usize(address + TEXT)
            .to_owned_slice::<Platform>(PAGE_SIZE - TEXT)
            .unwrap();
        for word in code.as_chunks::<4>().0 {
            assert_eq!(u32::from_le_bytes(*word), 0xd436_2160); // BRK #0xB10B
        }
        let patch_info = {
            let mappings = task.global.macho_mappings.lock();
            let patch_info = Arc::clone(&mappings[&address].patch_info);
            assert_eq!(patch_info.trampoline_capacity, PAGE_SIZE);
            patch_info
        };
        let trampolines = task.global.macho_trampolines.lock();
        let trampoline = &trampolines[&(Arc::as_ptr(&patch_info.rewrite_id) as usize)];
        assert!(trampoline.range.is_none());
        assert_eq!(trampoline.cursor, 0);
        drop(trampolines);
        assert_eq!(
            task.global.mm.get_memory_permissions(
                NonZeroAddress::new(address).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            ),
            Some(Permissions::READ | Permissions::EXEC),
        );
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    /// Maps code whose trampoline cannot be allocated within reach and expects traps.
    fn assert_unavailable_trampoline_uses_traps(span: usize, capacity: usize) {
        let mut image = macho_image();
        put64(&mut image, 64, span as u64);
        let task = task_with_file(&image);
        let file = task.files.typed_fd(0).unwrap();
        task.cache_macho_patch_info(
            &file,
            Some(Arc::new(MachoPatchInfo {
                metadata: CodeMetadata::parse(&image).unwrap(),
                slice_range: 0..image.len(),
                trampoline_capacity: capacity,
                rewrite_id: Arc::new(()),
            })),
        );
        let before = task.global.mm.mappings();
        let address =
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE).unwrap();
        assert_eq!(
            UserPtr::<u8>::from_usize(address + TEXT)
                .to_owned_slice::<Platform>(4)
                .unwrap()
                .as_ref(),
            &0xd436_2160u32.to_le_bytes(), // BRK #0xB10B
        );
        assert!(
            task.global
                .macho_trampolines
                .lock()
                .values()
                .all(|state| state.range.is_none() && state.cursor == 0)
        );
        assert_eq!(
            task.global.mm.get_memory_permissions(
                NonZeroAddress::new(address).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            ),
            Some(Permissions::READ | Permissions::EXEC),
        );
        task.sys_munmap(address, PAGE_SIZE).unwrap();
        assert_eq!(task.global.mm.mappings(), before);
    }

    // Each case needs its own process: a process may construct only one broker core.
    #[test]
    fn zero_trampoline_capacity_uses_traps() {
        assert_unavailable_trampoline_uses_traps(PAGE_SIZE, 0);
    }

    #[test]
    fn image_span_beyond_trampoline_reach_uses_traps() {
        assert_unavailable_trampoline_uses_traps(
            2 * litebox_syscall_rewriter::MAX_TRAMPOLINE_DISPLACEMENT,
            PAGE_SIZE,
        );
    }

    #[test]
    fn trampoline_capacity_beyond_reach_uses_traps() {
        assert_unavailable_trampoline_uses_traps(
            PAGE_SIZE,
            2 * litebox_syscall_rewriter::MAX_TRAMPOLINE_DISPLACEMENT,
        );
    }

    #[test]
    fn non_macho_classification_is_cached() {
        let task = task_with_file(b"plain data");
        let first = mmap_with_protection(&task, VmProtection::READ).unwrap();
        let second = mmap_with_protection(&task, VmProtection::READ).unwrap();
        let file = task.files.typed_fd(0).unwrap();
        assert!(
            task.global
                .litebox
                .descriptor_table()
                .with_metadata::<FileSubsystem<Platform>, MachoPatchMetadata, _>(
                    &file,
                    |metadata| metadata.0.is_none(),
                )
                .unwrap()
        );
        task.sys_munmap(first, PAGE_SIZE).unwrap();
        task.sys_munmap(second, PAGE_SIZE).unwrap();
    }

    #[test]
    fn cached_metadata_does_not_cache_mapped_file_contents() {
        let task = task_with_file(&macho_image());
        let original = mmap_with_protection(&task, VmProtection::READ).unwrap();
        let writer = task
            .global
            .litebox
            .open_file(
                &litebox::fs::Context::new(),
                "/image",
                FileAccessMode::ReadWrite,
                FileOpenFlags::NONE,
                FileMode::empty(),
            )
            .unwrap();
        let nop = 0xd503_201fu32.to_le_bytes();
        assert_eq!(writer.write(&nop, Some(TEXT), None).unwrap(), 4);
        let updated =
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE).unwrap();
        assert_eq!(
            &*UserPtr::<u8>::from_usize(updated + TEXT)
                .to_owned_slice::<Platform>(4)
                .unwrap(),
            &nop,
        );
        assert_eq!(
            &*UserPtr::<u8>::from_usize(original + TEXT)
                .to_owned_slice::<Platform>(4)
                .unwrap(),
            &SVC.to_le_bytes(),
        );
        drop(writer);
        task.sys_munmap(original, PAGE_SIZE).unwrap();
        task.sys_munmap(updated, PAGE_SIZE).unwrap();
    }

    #[test]
    fn universal_macho_mapping_translates_container_offset() {
        let task = task_with_file(&universal_macho_image());
        let address = task
            .sys_mmap(
                0,
                PAGE_SIZE,
                VmProtection::READ | VmProtection::EXECUTE,
                MmapFlags::PRIVATE,
                0,
                i64::try_from(PAGE_SIZE).unwrap(),
            )
            .unwrap();
        let site = address + TEXT;
        let instruction = u32::from_le_bytes(
            *UserPtr::<u8>::from_usize(site)
                .to_owned_slice::<Platform>(4)
                .unwrap()
                .first_chunk()
                .unwrap(),
        );
        assert!(decode_branch_target(instruction, site as u64).is_some());
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    #[test]
    fn executable_file_mmap_publishes_rewritten_code_and_rx_gate() {
        let image = macho_image();
        let task = task_with_file(&image);
        let address =
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE).unwrap();
        let code_address = address + TEXT;
        let code = u32::from_le_bytes(
            *UserPtr::<u8>::from_usize(code_address)
                .to_owned_slice::<Platform>(4)
                .unwrap()
                .first_chunk()
                .unwrap(),
        );
        let target =
            usize::try_from(decode_branch_target(code, code_address as u64).unwrap()).unwrap();
        let mappings = task.global.mm.mappings();
        assert!(mappings.iter().any(|(range, flags)| {
            range.contains(&target)
                && flags.contains(VmFlags::VM_EXEC)
                && !flags.contains(VmFlags::VM_WRITE)
        }));
        let gate = UserPtr::<u8>::from_usize(target)
            .to_owned_slice::<Platform>(64)
            .unwrap();
        let classified = Rewriter::new(litebox_syscall_rewriter::TargetHost::MacOs)
            .unwrap()
            .classify_gate_slot(&gate, target as u64, target as u64)
            .unwrap();
        assert_eq!(classified.metadata(), GateMetadata::Svc);
        assert_eq!(classified.original_site(), code_address as u64);
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    #[test]
    fn writable_transition_rewrites_modified_code_when_made_executable_again() {
        use litebox_common_macos::user_pointers::UserPtrMut;

        let task = task_with_file(&macho_image());
        let address =
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE).unwrap();
        let site = address + TEXT;

        task.sys_mprotect(address, PAGE_SIZE, VmProtection::READ | VmProtection::WRITE)
            .unwrap();
        UserPtrMut::<u8>::from_usize(site)
            .copy_from_slice::<Platform>(0, &SVC.to_le_bytes())
            .unwrap();
        task.sys_mprotect(
            address,
            PAGE_SIZE,
            VmProtection::READ | VmProtection::EXECUTE,
        )
        .unwrap();

        let instruction = u32::from_le_bytes(
            *UserPtr::<u8>::from_usize(site)
                .to_owned_slice::<Platform>(4)
                .unwrap()
                .first_chunk()
                .unwrap(),
        );
        assert!(decode_branch_target(instruction, site as u64).is_some());
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    #[test]
    fn failed_partial_map_fixed_preserves_macho_tracking() {
        let task = task_with_file(&macho_image());
        let address = mmap_with_protection(&task, VmProtection::READ).unwrap();
        assert!(
            task.sys_mmap(
                address,
                2 * PAGE_SIZE,
                VmProtection::READ | VmProtection::WRITE,
                MmapFlags::ANONYMOUS | MmapFlags::PRIVATE | MmapFlags::FIXED,
                -1,
                0,
            )
            .is_err()
        );
        task.sys_mprotect(
            address,
            PAGE_SIZE,
            VmProtection::READ | VmProtection::EXECUTE,
        )
        .unwrap();
        let site = address + TEXT;
        let instruction = u32::from_le_bytes(
            *UserPtr::<u8>::from_usize(site)
                .to_owned_slice::<Platform>(4)
                .unwrap()
                .first_chunk()
                .unwrap(),
        );
        assert!(decode_branch_target(instruction, site as u64).is_some());
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    /// Fails an executable mapping and checks that new gates and pages are rolled back.
    fn assert_failed_executable_mmap_rolls_back_new_gates(existing: bool) {
        let task = task_with_file(&macho_image());
        let address = existing.then(|| {
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE).unwrap()
        });
        let before = task.global.mm.mappings();
        let previous = task
            .global
            .macho_trampolines
            .lock()
            .values()
            .next()
            .map(|state| (state.range.clone(), state.cursor));
        assert!(
            mmap_with_protection(
                &task,
                VmProtection::READ | VmProtection::WRITE | VmProtection::EXECUTE,
            )
            .is_err()
        );
        assert_eq!(task.global.mm.mappings(), before);
        assert_eq!(
            task.global
                .macho_trampolines
                .lock()
                .values()
                .next()
                .map(|state| (state.range.clone(), state.cursor)),
            previous,
        );
        if let Some(address) = address {
            task.sys_munmap(address, PAGE_SIZE).unwrap();
        }
    }

    #[test]
    fn failed_executable_mmap_releases_new_trampoline() {
        assert_failed_executable_mmap_rolls_back_new_gates(false);
    }

    #[test]
    fn failed_executable_mmap_rolls_back_gates_in_existing_trampoline() {
        assert_failed_executable_mmap_rolls_back_new_gates(true);
    }

    #[test]
    fn trampoline_allocation_preserves_writable_neighbor() {
        use litebox_common_macos::user_pointers::UserPtrMut;

        let task = task_with_file(&macho_image());
        let address = task
            .reserve_anonymous(0, 2 * PAGE_SIZE, AllocationDirection::BottomUp)
            .unwrap();
        task.sys_mmap(
            address,
            PAGE_SIZE,
            VmProtection::READ,
            MmapFlags::PRIVATE | MmapFlags::FIXED,
            0,
            0,
        )
        .unwrap();
        let neighbor = address + PAGE_SIZE;
        task.sys_mprotect(
            neighbor,
            PAGE_SIZE,
            VmProtection::READ | VmProtection::WRITE,
        )
        .unwrap();
        UserPtrMut::<u8>::from_usize(neighbor)
            .copy_from_slice::<Platform>(0, b"keep")
            .unwrap();
        task.sys_mprotect(
            address,
            PAGE_SIZE,
            VmProtection::READ | VmProtection::EXECUTE,
        )
        .unwrap();
        assert_eq!(
            UserPtr::<u8>::from_usize(neighbor)
                .to_owned_slice::<Platform>(4)
                .unwrap()
                .as_ref(),
            b"keep",
        );
        task.sys_munmap(address, 2 * PAGE_SIZE).unwrap();
    }

    #[test]
    fn map_fixed_replacement_discards_macho_state() {
        let task = task_with_file(&macho_image());
        let address = mmap_with_protection(&task, VmProtection::READ).unwrap();
        let code_address = address + TEXT;

        task.sys_mmap(
            address,
            PAGE_SIZE,
            VmProtection::READ | VmProtection::WRITE,
            MmapFlags::ANONYMOUS | MmapFlags::PRIVATE | MmapFlags::FIXED,
            -1,
            0,
        )
        .unwrap();

        litebox_common_macos::user_pointers::UserPtrMut::<u8>::from_usize(code_address)
            .copy_from_slice::<Platform>(0, &SVC.to_le_bytes())
            .unwrap();
        task.sys_mprotect(
            address,
            PAGE_SIZE,
            VmProtection::READ | VmProtection::EXECUTE,
        )
        .unwrap();
        assert_eq!(
            &*UserPtr::<u8>::from_usize(code_address)
                .to_owned_slice::<Platform>(4)
                .unwrap(),
            &SVC.to_le_bytes()
        );
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    #[test]
    fn partial_munmap_preserves_surviving_macho_tracking() {
        let task = task_with_file(&macho_image());
        let address = task
            .sys_mmap(
                0,
                2 * PAGE_SIZE,
                VmProtection::READ,
                MmapFlags::PRIVATE,
                0,
                0,
            )
            .unwrap();
        task.sys_munmap(address + PAGE_SIZE, PAGE_SIZE).unwrap();
        task.sys_mprotect(
            address,
            PAGE_SIZE,
            VmProtection::READ | VmProtection::EXECUTE,
        )
        .unwrap();
        let code_address = address + TEXT;
        let rewritten = u32::from_le_bytes(
            *UserPtr::<u8>::from_usize(code_address)
                .to_owned_slice::<Platform>(4)
                .unwrap()
                .first_chunk()
                .unwrap(),
        );
        assert!(decode_branch_target(rewritten, code_address as u64).is_some());
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    #[test]
    fn executable_mappings_share_one_trampoline_per_file() {
        let task = task_with_file(&macho_image());
        let duplicate = i32::try_from(task.sys_dup(0).unwrap()).unwrap();
        let first =
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE).unwrap();
        let (first_range, first_cursor) = {
            let trampolines = task.global.macho_trampolines.lock();
            let trampoline = trampolines.values().next().unwrap();
            (trampoline.range.clone().unwrap(), trampoline.cursor)
        };
        let second = task
            .sys_mmap(
                0,
                PAGE_SIZE,
                VmProtection::READ | VmProtection::EXECUTE,
                MmapFlags::PRIVATE,
                duplicate,
                0,
            )
            .unwrap();
        let targets: Vec<_> = [first, second]
            .map(|address| {
                let site = address + TEXT;
                let instruction = u32::from_le_bytes(
                    *UserPtr::<u8>::from_usize(site)
                        .to_owned_slice::<Platform>(4)
                        .unwrap()
                        .first_chunk()
                        .unwrap(),
                );
                usize::try_from(decode_branch_target(instruction, site as u64).unwrap()).unwrap()
            })
            .into();
        let trampolines = task.global.macho_trampolines.lock();
        assert_eq!(trampolines.len(), 1);
        let trampoline = trampolines.values().next().unwrap();
        let range = trampoline.range.as_ref().unwrap();
        assert_eq!(range, &first_range);
        assert!(trampoline.cursor > first_cursor);
        assert!(targets.into_iter().all(|target| range.contains(&target)));
        for address in [first, second] {
            let allowed = trampoline_allocation_range(address..address + PAGE_SIZE).unwrap();
            assert!(range.start >= allowed.start && range.end <= allowed.end);
        }
        drop(trampolines);
        let file = task.files.typed_fd(0).unwrap();
        let patch_info = task.macho_patch_info(&file).unwrap();
        assert_eq!(first_range.len(), patch_info.trampoline_capacity);
        let key = Arc::as_ptr(&patch_info.rewrite_id) as usize;
        task.global
            .macho_trampolines
            .lock()
            .get_mut(&key)
            .unwrap()
            .cursor = first_range.len();
        let exhausted =
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE).unwrap();
        let allowed = trampoline_allocation_range(exhausted..exhausted + PAGE_SIZE).unwrap();
        assert!(first_range.start >= allowed.start && first_range.end <= allowed.end);
        assert_eq!(
            UserPtr::<u8>::from_usize(exhausted + TEXT)
                .to_owned_slice::<Platform>(4)
                .unwrap()
                .as_ref(),
            &0xd436_2160u32.to_le_bytes(), // BRK #0xB10B
        );
        {
            let trampolines = task.global.macho_trampolines.lock();
            assert_eq!(trampolines.len(), 1);
            assert_eq!(trampolines[&key].range.as_ref(), Some(&first_range));
            assert_eq!(trampolines[&key].cursor, first_range.len());
        }
        task.sys_munmap(exhausted, PAGE_SIZE).unwrap();
        task.sys_munmap(first, PAGE_SIZE).unwrap();
        task.sys_munmap(second, PAGE_SIZE).unwrap();
        task.sys_close(0).unwrap();
        task.sys_close(duplicate).unwrap();
        assert_eq!(
            task.global.mm.get_memory_permissions(
                NonZeroAddress::new(first_range.start).unwrap(),
                NonZeroPageSize::new(first_range.len()).unwrap(),
            ),
            Some(Permissions::READ | Permissions::EXEC),
        );
    }

    #[test]
    fn mapping_without_patch_sites_does_not_retain_trampoline() {
        let mut image = macho_image();
        put32(&mut image, TEXT, 0xd503_201f); // NOP
        let task = task_with_file(&image);
        let address =
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE).unwrap();
        let trampolines = task.global.macho_trampolines.lock();
        assert_eq!(trampolines.len(), 1);
        assert!(trampolines.values().next().unwrap().range.is_none());
        drop(trampolines);
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    /// Unmaps part or all of a trampoline and checks that its surviving code is invalidated.
    fn assert_unmapping_trampoline_invalidates_surviving_code(remove_all: bool) {
        let mut image = macho_image();
        put64(&mut image, 32 + 72 + 40, (PAGE_SIZE - TEXT) as u64);
        for offset in (TEXT..PAGE_SIZE).step_by(4) {
            put32(&mut image, offset, SVC);
        }
        let task = task_with_file(&image);
        let address =
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE).unwrap();
        let trampoline = task
            .global
            .macho_trampolines
            .lock()
            .values()
            .next()
            .unwrap()
            .range
            .clone()
            .unwrap();
        assert!(trampoline.len() > PAGE_SIZE);
        task.sys_munmap(
            trampoline.start,
            if remove_all {
                trampoline.len()
            } else {
                PAGE_SIZE
            },
        )
        .unwrap();
        assert!(
            task.global
                .macho_trampolines
                .lock()
                .values()
                .next()
                .unwrap()
                .invalidated
        );
        assert_eq!(
            task.sys_mprotect(
                address,
                PAGE_SIZE,
                VmProtection::READ | VmProtection::EXECUTE
            ),
            Err(Errno::ENOMEM),
        );
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    #[test]
    fn partially_unmapping_trampoline_invalidates_surviving_code() {
        assert_unmapping_trampoline_invalidates_surviving_code(false);
    }

    #[test]
    fn fully_unmapping_trampoline_invalidates_surviving_code() {
        assert_unmapping_trampoline_invalidates_surviving_code(true);
    }

    #[test]
    fn executable_file_mmap_rejects_non_macho_without_publishing_pages() {
        let task = task_with_file(b"not a Mach-O");
        let before = task.global.mm.mappings();
        assert_eq!(
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE),
            Err(Errno::ENOEXEC)
        );
        assert_eq!(task.global.mm.mappings(), before);
    }

    #[test]
    fn mprotect_exec_rewrites_after_the_file_descriptor_is_closed() {
        let task = task_with_file(&macho_image());
        let address = mmap_with_protection(&task, VmProtection::READ).unwrap();
        task.sys_close(0).unwrap();
        let code_address = address + TEXT;
        let original = UserPtr::<u8>::from_usize(code_address)
            .to_owned_slice::<Platform>(4)
            .unwrap();
        assert_eq!(u32::from_le_bytes(*original.first_chunk().unwrap()), SVC);
        task.sys_mprotect(address, 1, VmProtection::READ | VmProtection::EXECUTE)
            .unwrap();
        let rewritten = UserPtr::<u8>::from_usize(code_address)
            .to_owned_slice::<Platform>(4)
            .unwrap();
        assert!(
            decode_branch_target(
                u32::from_le_bytes(*rewritten.first_chunk().unwrap()),
                code_address as u64,
            )
            .is_some()
        );
        assert_eq!(
            task.sys_mprotect(usize::MAX, 0, VmProtection::empty()),
            Err(Errno::EINVAL)
        );
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    #[test]
    fn invalid_ranges_and_unsupported_shared_writeback_are_rejected() {
        let task = task_with_file(&macho_image());
        let address = usize::MAX & !(PAGE_SIZE - 1);
        assert_eq!(task.sys_munmap(address, PAGE_SIZE), Err(Errno::EINVAL));
        assert_eq!(
            task.sys_mprotect(address, PAGE_SIZE, VmProtection::READ),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            task.sys_mmap(
                0,
                PAGE_SIZE,
                VmProtection::READ | VmProtection::WRITE,
                MmapFlags::SHARED,
                0,
                0,
            ),
            Err(Errno::ENOTSUP)
        );
    }
}
