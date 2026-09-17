// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin virtual-memory syscalls and dynamic Mach-O rewriting.
//!
//! File-backed Mach-O code is rewritten when mapped executable or when a
//! previously mapped range becomes executable through `mprotect`. Mappings
//! retain cached rewrite metadata after their descriptors are closed.

use alloc::{collections::BTreeSet, sync::Arc, vec, vec::Vec};
use core::ops::Range;
use litebox::{
    fs::errors::ReadError,
    mm::linux::{
        CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize, VmFlags, VmemProtectError,
    },
    platform::{
        RawConstPointer as _, RawMutPointer as _, page_mgmt::MemoryRegionPermissions as Permissions,
    },
    utils::TruncateExt as _,
};
use litebox_common_macos::{
    MmapFlags, PAGE_SIZE, VmProtection, errno::Errno, loader::MAX_IMAGE_SIZE,
};
use litebox_syscall_rewriter::{
    TargetHost,
    macho::{CodeMetadata, Rewriter},
};

use crate::{ShimPlatform, Task};

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
}

impl MachoPatchInfo {
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
    patch_info: Arc<MachoPatchInfo>,
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

/// Tries preferred-full, anywhere-full, then preferred-one-page, matching the Linux shim.
fn choose_trampoline_reservation<T>(
    capacity: usize,
    mut map_preferred: impl FnMut(usize) -> Option<T>,
    mut map_anywhere: impl FnMut(usize) -> Option<T>,
) -> Option<(T, usize)> {
    map_preferred(capacity)
        .map(|reservation| (reservation, capacity))
        .or_else(|| map_anywhere(capacity).map(|reservation| (reservation, capacity)))
        .or_else(|| {
            (capacity > PAGE_SIZE)
                .then(|| map_preferred(PAGE_SIZE).map(|reservation| (reservation, PAGE_SIZE)))
                .flatten()
        })
}

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

fn mapping_flags(flags: MmapFlags, file_backed: bool) -> CreatePagesFlags {
    let mut result = CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;
    result.set(
        CreatePagesFlags::FIXED_ADDR,
        flags.contains(MmapFlags::FIXED),
    );
    result.set(CreatePagesFlags::SHARED, flags.contains(MmapFlags::SHARED));
    result.set(CreatePagesFlags::MAP_FILE, file_backed);
    result
}

fn mapping_error(error: MappingError) -> Errno {
    match error {
        MappingError::BadFD(_) => Errno::EBADF,
        MappingError::NotForReading => Errno::EACCES,
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

fn protection_error(error: VmemProtectError) -> Errno {
    use litebox::platform::page_mgmt::PermissionUpdateError;

    match error {
        VmemProtectError::InvalidRange(_) => Errno::ENOMEM,
        VmemProtectError::NoAccess { .. } => Errno::EACCES,
        VmemProtectError::UnAligned(_) => Errno::EINVAL,
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

fn protection_from_permissions(permissions: Permissions) -> VmProtection {
    let mut protection = VmProtection::empty();
    protection.set(VmProtection::READ, permissions.contains(Permissions::READ));
    protection.set(
        VmProtection::WRITE,
        permissions.contains(Permissions::WRITE),
    );
    protection.set(
        VmProtection::EXECUTE,
        permissions.contains(Permissions::EXEC),
    );
    protection
}

impl<P: ShimPlatform> Task<P> {
    fn mapping_snapshot(&self, target: Range<usize>) -> Vec<(Range<usize>, VmFlags)> {
        self.global
            .pm
            .mappings()
            .into_iter()
            .filter_map(|(range, flags)| {
                let start = range.start.max(target.start);
                let end = range.end.min(target.end);
                (start < end).then_some((start..end, flags))
            })
            .collect()
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
                self.global.pm.create_pages_with_permissions(
                    suggested,
                    length,
                    mapping_flags(flags, false),
                    permissions(protection),
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
        let mut create_flags = mapping_flags(flags, true);
        if macho.is_some() && !flags.contains(MmapFlags::FIXED) {
            create_flags |= CreatePagesFlags::ENSURE_SPACE_AFTER;
        }
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
            self.global.pm.create_pages_with_permissions(
                suggested,
                length,
                create_flags,
                final_permissions,
                |pointer| {
                    let mut copied = 0;
                    while copied < length.as_usize() {
                        let chunk = (length.as_usize() - copied).min(buffer.len());
                        let read = self
                            .global
                            .litebox
                            .read_file(&file, &mut buffer[..chunk], Some(file_offset))
                            .map_err(|error| {
                                initialization_error = Some(error);
                                MappingError::NotForReading
                            })?;
                        if read == 0 {
                            break;
                        }
                        pointer
                            .copy_from_slice(copied, &buffer[..read])
                            .ok_or(MappingError::OutOfMemory)?;
                        copied += read;
                        file_offset = file_offset
                            .checked_add(read)
                            .ok_or(MappingError::OutOfMemory)?;
                    }
                    if let Some(info) = macho.as_ref().filter(|_| executable) {
                        self.rewrite_macho_mapping(pointer, length.as_usize(), &ranges, info)?;
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
        let key = Arc::as_ptr(patch_info) as usize;
        self.global.macho_trampolines.lock().get(&key).map_or(
            MachoTrampolineCheckpoint {
                range: None,
                cursor: 0,
            },
            |state| MachoTrampolineCheckpoint {
                range: state.range.clone(),
                cursor: state.cursor,
            },
        )
    }

    fn rollback_macho_trampoline(
        &self,
        patch_info: &Arc<MachoPatchInfo>,
        checkpoint: MachoTrampolineCheckpoint,
    ) {
        let key = Arc::as_ptr(patch_info) as usize;
        let mut trampolines = self.global.macho_trampolines.lock();
        let Some(state) = trampolines.get_mut(&key) else {
            return;
        };
        if state.invalidated {
            return;
        }
        let current = state.range.clone();
        state.range.clone_from(&checkpoint.range);
        state.cursor = checkpoint.cursor;
        if checkpoint.range.is_none() {
            trampolines.remove(&key);
        }
        drop(trampolines);

        match (checkpoint.range, current) {
            (None, Some(current)) => self.remove_trampoline(current),
            (Some(previous), Some(current)) if current.end > previous.end => {
                self.remove_trampoline(previous.end..current.end);
            }
            _ => {}
        }
    }

    fn rewrite_macho_mapping(
        &self,
        pointer: P::RawMutPointer<u8>,
        length: usize,
        ranges: &[core::ops::Range<usize>],
        patch_info: &Arc<MachoPatchInfo>,
    ) -> Result<(), MappingError> {
        if ranges.is_empty() {
            return Ok(());
        }
        let rewriter = Rewriter::new(TargetHost::MacOs).map_err(|_| MappingError::OutOfMemory)?;
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
        let trap_fallback = |error: &dyn core::fmt::Display| {
            litebox_util_log::warn!(error:% = error; "using traps for Mach-O mapping rewrite");
            let mut trapped = original.clone();
            let count = rewriter
                .trap_code_segment(&mut trapped, pointer.as_usize() as u64, ranges)
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

        let key = Arc::as_ptr(patch_info) as usize;
        let mut trampolines = self.global.macho_trampolines.lock();
        let state = trampolines
            .entry(key)
            .or_insert_with(|| MachoRuntimeTrampoline {
                patch_info: Arc::clone(patch_info),
                range: None,
                cursor: 0,
                invalidated: false,
            });
        debug_assert!(Arc::ptr_eq(&state.patch_info, patch_info));
        if state.invalidated {
            return Err(MappingError::OutOfMemory);
        }
        let newly_allocated = state.range.is_none();
        if newly_allocated {
            state.range = match self.reserve_trampoline(
                pointer.as_usize(),
                length,
                patch_info.trampoline_capacity,
            ) {
                Ok(range) => Some(range),
                Err(error) => return trap_fallback(&error),
            };
            state.cursor = 0;
        }
        let mut range = state.range.clone().expect("trampoline was just allocated");
        let cursor = state
            .cursor
            .checked_next_multiple_of(litebox_syscall_rewriter::TRAMPOLINE_CURSOR_ALIGN)
            .ok_or(MappingError::OutOfMemory)?;
        let trampoline_address = range
            .start
            .checked_add(cursor)
            .ok_or(MappingError::OutOfMemory)?;
        let mut code = original.clone();
        let (gates, trapped) = match rewriter.patch_code_segment(
            &mut code,
            pointer.as_usize() as u64,
            ranges,
            trampoline_address as u64,
            callback as u64,
            tls_offset,
        ) {
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
        if let Err(error) = self.grow_trampoline(&mut range, new_cursor) {
            if newly_allocated {
                state.range = None;
                self.remove_trampoline(range);
            }
            return trap_fallback(&error);
        }
        state.range = Some(range.clone());
        // Existing gates are RX. Temporarily make the shared region writable,
        // append the new gates, then publish all gates RX before code branches.
        if !newly_allocated {
            unsafe {
                self.global.pm.change_page_permissions(
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
                let _ = unsafe {
                    self.global.pm.change_page_permissions(
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
            self.global.pm.change_page_permissions(
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

    fn reserve_trampoline(
        &self,
        code_address: usize,
        code_length: usize,
        capacity: usize,
    ) -> Result<Range<usize>, MappingError> {
        let code_end = code_address
            .checked_add(code_length)
            .ok_or(MappingError::OutOfMemory)?;
        let reachable = |address: usize| {
            address
                .abs_diff(code_address)
                .max(address.abs_diff(code_end))
                <= litebox_syscall_rewriter::MAX_TRAMPOLINE_DISPLACEMENT
        };
        // TODO: derive preferred placement from the full image load layout once
        // dynamic loading is supported, as the Linux shim does for ELF.
        let hint = self
            .trampoline_address_after(code_address, code_length, capacity)
            .filter(|&address| reachable(address))
            .or_else(|| {
                self.trampoline_address_after(code_address, code_length, PAGE_SIZE)
                    .filter(|&address| reachable(address))
            });
        let map = |hint, length| {
            let address = self.allocate_trampoline(hint, length).ok()?;
            if !reachable(address) {
                self.remove_trampoline(address..address + length);
                return None;
            }
            Some(address)
        };
        choose_trampoline_reservation(
            capacity,
            |length| map(Some(hint?), length),
            |length| map(None, length),
        )
        .map(|(address, length)| address..address + length)
        .ok_or(MappingError::OutOfMemory)
    }

    fn allocate_trampoline(
        &self,
        address: Option<usize>,
        length: usize,
    ) -> Result<usize, MappingError> {
        let suggested = address
            .map(|address| NonZeroAddress::new(address).ok_or(MappingError::OutOfMemory))
            .transpose()?;
        let length = NonZeroPageSize::new(length).ok_or(MappingError::OutOfMemory)?;
        let mut flags = CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;
        flags.set(
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
            suggested.is_some(),
        );
        // SAFETY: fixed allocations use NOREPLACE; non-fixed allocations let
        // the platform choose unused memory. No existing mappings are replaced.
        unsafe {
            self.global
                .pm
                .create_writable_pages(suggested, length, flags, |_| Ok(0))
        }
        .map(|pointer| pointer.as_usize())
    }

    fn grow_trampoline(&self, range: &mut Range<usize>, used: usize) -> Result<(), MappingError> {
        let required = used
            .max(PAGE_SIZE)
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(MappingError::OutOfMemory)?;
        if required > range.len() {
            let end = range
                .start
                .checked_add(required)
                .ok_or(MappingError::OutOfMemory)?;
            self.allocate_trampoline(Some(range.end), end - range.end)?;
            range.end = end;
        }
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
            if invalidated.contains(&(Arc::as_ptr(&mapping.patch_info) as usize)) {
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
                .pm
                .remove_pages(P::RawMutPointer::from_usize(range.start), range.len())
        } {
            litebox_util_log::warn!(error:? = error; "failed to release Mach-O trampoline");
        }
    }

    fn cache_macho_patch_info(
        &self,
        file: &litebox::fs::FileFd,
        patch_info: Option<Arc<MachoPatchInfo>>,
    ) {
        self.global
            .litebox
            .descriptor_table_mut()
            .set_entry_metadata::<litebox::fs::BrokerFile, _>(file, MachoPatchMetadata(patch_info));
    }

    fn macho_patch_info(
        &self,
        file: &Arc<litebox::fs::FileFd>,
    ) -> Result<Arc<MachoPatchInfo>, Errno> {
        if let Ok(patch_info) = self
            .global
            .litebox
            .descriptor_table()
            .with_metadata::<litebox::fs::BrokerFile, MachoPatchMetadata, _>(file, |metadata| {
                metadata.0.clone()
            })
        {
            return patch_info.ok_or(Errno::ENOEXEC);
        }
        // Status and oversize failures are deliberately not cached: the backing
        // file may change and become a valid, bounded image before a later mmap.
        let size = self
            .global
            .litebox
            .file_status(file)
            .map_err(|_| Errno::EIO)?
            .size;
        if size > u64::try_from(MAX_IMAGE_SIZE).expect("image limit fits in u64") {
            return Err(Errno::EFBIG);
        }
        let size: usize = size.trunc();
        let mut header = [0; litebox_common_macos::loader::MACH_HEADER_SIZE];
        let supported_header = if size < header.len() {
            false
        } else {
            self.read_file_exact_at(file, &mut header, 0)?;
            litebox_common_macos::loader::may_contain_arm64_macho(&header)
        };
        if !supported_header {
            self.cache_macho_patch_info(file, None);
            return Err(Errno::ENOEXEC);
        }
        let mut bytes = vec![0; size];
        self.read_file_exact_at(file, &mut bytes, 0)?;
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
        let rewriter = Rewriter::new(TargetHost::MacOs).map_err(|_| Errno::ENOEXEC)?;
        let trampoline_capacity = metadata
            .trampoline_size_upper_bound(slice, rewriter)
            .and_then(|size| {
                size.max(PAGE_SIZE)
                    .checked_next_multiple_of(PAGE_SIZE)
                    .ok_or_else(|| litebox_syscall_rewriter::Error::AddressOverflow(
                        "Mach-O trampoline size".into(),
                    ))
            })
            .unwrap_or_else(|error| {
                litebox_util_log::warn!(error:% = error; "Mach-O sizing unavailable; starting with one trampoline page");
                PAGE_SIZE
            });
        let patch_info = Arc::new(MachoPatchInfo {
            metadata,
            slice_range,
            trampoline_capacity,
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
                .pm
                .mappings()
                .into_iter()
                .filter_map(|(range, flags)| {
                    let start = patch.range.start.max(range.start);
                    let end = patch.range.end.min(range.end);
                    (start < end).then(|| {
                        (
                            start..end,
                            protection_from_permissions(Permissions::from(flags)),
                        )
                    })
                })
                .collect();
            let mut made_writable = Vec::new();
            for (range, protection) in &previous {
                if let Err(error) = self.change_initialization_permissions(
                    range.clone(),
                    Permissions::READ | Permissions::WRITE,
                ) {
                    for (range, protection) in made_writable {
                        let _ =
                            self.change_initialization_permissions(range, permissions(protection));
                    }
                    return Err(error);
                }
                made_writable.push((range.clone(), *protection));
            }
            let rewrite = self.rewrite_macho_mapping(
                P::RawMutPointer::from_usize(patch.range.start),
                patch.range.len(),
                &ranges,
                &patch.patch_info,
            );
            let mut restore_error = None;
            for (range, protection) in previous {
                if let Err(error) =
                    self.change_initialization_permissions(range, permissions(protection))
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
        unsafe { self.global.platform.update_permissions(range, permissions) }
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
            self.global.pm.change_page_permissions(
                P::RawMutPointer::from_usize(range.start),
                range.len(),
                permissions(protection),
            )
        }
        .map_err(protection_error)
    }

    fn trampoline_address_after(
        &self,
        code_address: usize,
        code_length: usize,
        trampoline_length: usize,
    ) -> Option<usize> {
        let mut candidate = code_address.checked_add(code_length)?;
        for (range, _) in self.global.pm.mappings() {
            if range.end <= candidate {
                continue;
            }
            let candidate_end = candidate.checked_add(trampoline_length)?;
            if range.start >= candidate_end {
                return Some(candidate);
            }
            candidate = range.end;
        }
        candidate.checked_add(trampoline_length)?;
        Some(candidate)
    }

    fn read_file_exact_at(
        &self,
        file: &litebox::fs::FileFd,
        mut bytes: &mut [u8],
        mut offset: usize,
    ) -> Result<(), Errno> {
        while !bytes.is_empty() {
            let read = self
                .global
                .litebox
                .read_file(file, bytes, Some(offset))
                .map_err(|_| Errno::EIO)?;
            if read == 0 || read > bytes.len() {
                return Err(Errno::EIO);
            }
            offset = offset.checked_add(read).ok_or(Errno::EFBIG)?;
            bytes = &mut bytes[read..];
        }
        Ok(())
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
                .pm
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
        address.checked_add(length).ok_or(Errno::EINVAL)?;
        if protection.contains(VmProtection::EXECUTE) {
            self.rewrite_mprotect_range(address, length)?;
        }
        self.change_permissions(address..address + length, protection)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    extern crate std;

    use super::*;
    use alloc::{sync::Arc, vec::Vec};
    use core::sync::atomic::AtomicI32;
    use litebox::{LiteBox, mm::linux::VmFlags};
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
    use litebox_common_macos::{PtRegs, TaskParams, syscall::nr, user_pointers::UserPtr};
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
        let (local, ()) = BrokerLocal::negotiate(setup, |setup| {
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
        Task {
            global: shim.global,
            files: shim.files,
            params: TaskParams::default(),
            process: Process(Arc::new(AtomicI32::new(-1))),
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
    fn mprotect_validates_ranges() {
        let platform = Platform::new();
        let shim = MacosShimBuilder::new(platform).build();
        let task = Task {
            global: shim.global,
            files: shim.files,
            params: TaskParams::default(),
            process: Process(Arc::new(AtomicI32::new(-1))),
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
    fn preferred_gap_fits_full_capacity() {
        let task = task_with_file(&macho_image());
        let base = task.allocate_trampoline(None, 6 * PAGE_SIZE).unwrap();
        task.sys_munmap(base + PAGE_SIZE, PAGE_SIZE).unwrap();
        task.sys_munmap(base + 3 * PAGE_SIZE, 2 * PAGE_SIZE)
            .unwrap();
        let range = task
            .reserve_trampoline(base, PAGE_SIZE, 2 * PAGE_SIZE)
            .unwrap();
        assert_eq!(range, base + 3 * PAGE_SIZE..base + 5 * PAGE_SIZE);
        task.remove_trampoline(range);
        task.sys_munmap(base, PAGE_SIZE).unwrap();
        task.sys_munmap(base + 2 * PAGE_SIZE, PAGE_SIZE).unwrap();
        task.sys_munmap(base + 5 * PAGE_SIZE, PAGE_SIZE).unwrap();
    }

    #[test]
    fn sizing_failure_retains_tracking_and_allows_trampoline_growth() {
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
            .to_owned_slice::<Platform>(4)
            .unwrap();
        let target = usize::try_from(
            decode_branch_target(
                u32::from_le_bytes(*code.first_chunk().unwrap()),
                (address + TEXT) as u64,
            )
            .unwrap(),
        )
        .unwrap();
        let patch_info = {
            let mappings = task.global.macho_mappings.lock();
            let patch_info = Arc::clone(&mappings[&address].patch_info);
            assert_eq!(patch_info.trampoline_capacity, PAGE_SIZE);
            patch_info
        };
        let trampolines = task.global.macho_trampolines.lock();
        let range = trampolines[&(Arc::as_ptr(&patch_info) as usize)]
            .range
            .as_ref()
            .unwrap();
        assert!(range.contains(&target) && range.len() > PAGE_SIZE);
        drop(trampolines);
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    #[test]
    fn one_page_fallback_grows_without_replacing_neighbors() {
        use litebox_common_macos::user_pointers::UserPtrMut;

        let task = task_with_file(&macho_image());
        let base = task.allocate_trampoline(None, 4 * PAGE_SIZE).unwrap();
        task.sys_munmap(base, 3 * PAGE_SIZE).unwrap();
        let blocker = base + 3 * PAGE_SIZE;
        UserPtrMut::<u8>::from_usize(blocker)
            .copy_from_slice::<Platform>(0, b"neighbor")
            .unwrap();
        let (address, length) = choose_trampoline_reservation(
            4 * PAGE_SIZE,
            |length| task.allocate_trampoline(Some(base), length).ok(),
            |_| None,
        )
        .unwrap();
        assert_eq!((address, length), (base, PAGE_SIZE));
        let mut range = address..address + length;
        UserPtrMut::<u8>::from_usize(address)
            .copy_from_slice::<Platform>(0, b"gate")
            .unwrap();
        task.grow_trampoline(&mut range, 2 * PAGE_SIZE + 1).unwrap();
        assert_eq!(range, base..base + 3 * PAGE_SIZE);
        assert_eq!(
            &*UserPtr::<u8>::from_usize(base)
                .to_owned_slice::<Platform>(4)
                .unwrap(),
            b"gate"
        );
        assert!(task.grow_trampoline(&mut range, 4 * PAGE_SIZE).is_err());
        assert_eq!(range, base..base + 3 * PAGE_SIZE);
        assert_eq!(
            &*UserPtr::<u8>::from_usize(blocker)
                .to_owned_slice::<Platform>(8)
                .unwrap(),
            b"neighbor"
        );
        task.remove_trampoline(range);
        task.sys_munmap(blocker, PAGE_SIZE).unwrap();
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
                .with_metadata::<litebox::fs::BrokerFile, MachoPatchMetadata, _>(
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
        assert_eq!(
            task.global
                .litebox
                .write_file(&writer, &nop, Some(TEXT))
                .unwrap(),
            4
        );
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
        task.global.litebox.close_file(&writer).unwrap();
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
        let mappings = task.global.pm.mappings();
        assert!(mappings.iter().any(|(range, flags)| {
            range.contains(&target)
                && flags.contains(VmFlags::VM_EXEC)
                && !flags.contains(VmFlags::VM_WRITE)
        }));
        let gate = UserPtr::<u8>::from_usize(target)
            .to_owned_slice::<Platform>(64)
            .unwrap();
        let classified = Rewriter::new(TargetHost::MacOs)
            .unwrap()
            .classify_gate_slot(&gate, target as u64, target as u64)
            .unwrap();
        assert_eq!(classified.metadata(), GateMetadata::Svc);
        assert_eq!(classified.original_site(), code_address as u64);
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    #[test]
    fn shared_read_mapping_can_be_rewritten_when_made_executable() {
        let task = task_with_file(&macho_image());
        let address = task
            .sys_mmap(0, PAGE_SIZE, VmProtection::READ, MmapFlags::SHARED, 0, 0)
            .unwrap();
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

    #[test]
    fn shared_mapping_without_code_can_be_made_executable() {
        let mut image = macho_image();
        image.resize(2 * PAGE_SIZE, 0);
        let task = task_with_file(&image);
        let address = task
            .sys_mmap(
                0,
                PAGE_SIZE,
                VmProtection::READ,
                MmapFlags::SHARED,
                0,
                i64::try_from(PAGE_SIZE).unwrap(),
            )
            .unwrap();
        task.sys_mprotect(
            address,
            PAGE_SIZE,
            VmProtection::READ | VmProtection::EXECUTE,
        )
        .unwrap();
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

    #[test]
    fn failed_executable_mmap_rolls_back_unpublished_trampoline() {
        let task = task_with_file(&macho_image());
        let before = task.global.pm.mappings();
        assert!(
            mmap_with_protection(
                &task,
                VmProtection::READ | VmProtection::WRITE | VmProtection::EXECUTE,
            )
            .is_err()
        );
        assert_eq!(task.global.pm.mappings(), before);
        assert!(task.global.macho_trampolines.lock().is_empty());
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
        let range = trampolines.values().next().unwrap().range.as_ref().unwrap();
        assert!(targets.into_iter().all(|target| range.contains(&target)));
        drop(trampolines);
        task.sys_munmap(first, PAGE_SIZE).unwrap();
        task.sys_munmap(second, PAGE_SIZE).unwrap();
        task.sys_close(duplicate).unwrap();
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

    #[test]
    fn executable_file_mmap_rejects_non_macho_without_publishing_pages() {
        let task = task_with_file(b"not a Mach-O");
        let before = task.global.pm.mappings();
        assert_eq!(
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE),
            Err(Errno::ENOEXEC)
        );
        assert_eq!(task.global.pm.mappings(), before);
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
