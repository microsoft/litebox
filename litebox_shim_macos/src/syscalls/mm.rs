// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin virtual-memory syscalls and dynamic Mach-O rewriting.
//!
//! File-backed Mach-O code is rewritten when mapped executable or when a
//! previously mapped range becomes executable through `mprotect`. Mappings
//! retain cached rewrite metadata after their descriptors are closed.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec,
    vec::Vec,
};
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
    KernReturn, MmapFlags, PAGE_SIZE, VmProtection, errno::Errno, loader::MAX_IMAGE_SIZE,
};
use litebox_syscall_rewriter::{macho::CodeMetadata, macho::Rewriter};
use litebox_trampoline::trampoline_allocation_range;

use crate::syscalls::file::{FileFd, FileSubsystem};
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

/// Test-only pause points: a hook set on a host thread runs when that thread
/// reaches a `Point`.
#[cfg(all(test, target_os = "macos"))]
pub(crate) mod hook {
    extern crate std;

    use alloc::boxed::Box;
    use std::sync::Mutex;
    use std::thread::{self, ThreadId};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Point {
        /// An executable file mapping took its trampoline checkpoint.
        Checkpointed,
        /// An append made an existing trampoline's unpublished pages RW.
        GatePagesWritable,
        /// A mapping change replaced or removed mappings and has not updated
        /// their Mach-O tracking yet.
        MappingsChanged,
        /// A MAP_FIXED mapping took its snapshot of the range it replaces and
        /// has not changed the range yet.
        FixedSnapshot,
        /// A guest mapping's pages are in place, still RW, and do not have
        /// their final permissions yet.
        MappingInitializing,
        /// An mprotect of task memory rewrote what it makes executable and has
        /// not changed permissions yet.
        Protecting,
        /// An mprotect across the shared-cache instance checked every part
        /// and has not changed any yet.
        SplitChecked,
        /// A shared-cache page-in checked the supplied page and has not put
        /// it at its guest address yet.
        PageInSupplied,
        /// A Mach message receive found a message on its port and has not
        /// dequeued it yet.
        MessageFound,
        /// A new thread was admitted below the thread limit and is not
        /// registered with its process yet.
        ThreadAdmitted,
        /// The last owner of the process's state is releasing its guest
        /// mappings.
        ReleasingMappings,
    }

    type Hook = Box<dyn FnMut(Point) + Send>;

    #[derive(Default)]
    pub(crate) struct Slot(Mutex<Option<(ThreadId, Hook)>>);

    impl Slot {
        pub(crate) fn set(&self, hook: impl FnMut(Point) + Send + 'static) {
            *self.0.lock().unwrap() = Some((thread::current().id(), Box::new(hook)));
        }

        pub(crate) fn clear(&self) {
            *self.0.lock().unwrap() = None;
        }

        pub(crate) fn reach(&self, point: Point) {
            let mut slot = self.0.lock().unwrap();
            let Some((owner, mut hook)) = slot.take() else {
                return;
            };
            if owner != thread::current().id() {
                *slot = Some((owner, hook));
                return;
            }
            drop(slot);
            hook(point);
            let mut slot = self.0.lock().unwrap();
            if slot.is_none() {
                *slot = Some((owner, hook));
            }
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

/// Shared append-only runtime trampoline allocations for one parsed Mach-O
/// image, in allocation order; gates are appended to the last one at
/// `cursor`.
pub(crate) struct MachoRuntimeTrampoline {
    rewrite_id: Arc<()>,
    allocations: Vec<Range<usize>>,
    cursor: usize,
    invalidated: bool,
}

struct MachoTrampolineCheckpoint {
    allocations: usize,
    cursor: usize,
}

/// Rewrite analysis attached to LiteBox's shared descriptor entry.
///
/// Entry metadata is visible through every descriptor produced by `dup`, so
/// aliases reuse both successful analysis and negative classification results.
#[derive(Clone)]
struct MachoPatchMetadata(Option<Arc<MachoPatchInfo>>);

pub(crate) fn permissions(protection: VmProtection) -> Permissions {
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
            .read(&mut *bytes, Some(offset), None)
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

/// Where [`Task::map_anonymous`] places pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AnonymousPlacement {
    /// Prefer the address hint; otherwise any free range.
    Hint,
    /// Exactly at the address, replacing existing mappings or failing.
    Fixed { replace: bool },
}

/// Mapped guest ranges whose maximum protection is below `VM_PROT_ALL`,
/// keyed by start; disjoint. A mapped page without an entry has the maximum
/// `VM_PROT_ALL`, still bounded by its area's `VM_MAY*` flags. Every change
/// that replaces or removes mappings updates the entries of its range.
#[derive(Default)]
pub(crate) struct MaximumProtections(BTreeMap<usize, (usize, VmProtection)>);

impl MaximumProtections {
    /// Record `maximum` for `range`, replacing what overlaps it.
    fn set(&mut self, range: Range<usize>, maximum: VmProtection) {
        let overlapping: Vec<_> = self
            .0
            .range(..range.end)
            .rev()
            .take_while(|&(_, &(end, _))| end > range.start)
            .map(|(&start, &entry)| (start, entry))
            .collect();
        for (start, (end, entry_maximum)) in overlapping {
            self.0.remove(&start);
            if start < range.start {
                self.0.insert(start, (range.start, entry_maximum));
            }
            if end > range.end {
                self.0.insert(range.end, (end, entry_maximum));
            }
        }
        if maximum != VmProtection::all() {
            self.0.insert(range.start, (range.end, maximum));
        }
    }

    /// Whether every maximum in `range` allows `protection`, as
    /// `vm_map_protect_preflight` requires of each entry.
    fn allows(&self, range: &Range<usize>, protection: VmProtection) -> bool {
        self.0
            .range(..range.end)
            .rev()
            .take_while(|&(_, &(end, _))| end > range.start)
            .all(|(_, &(_, maximum))| maximum.contains(protection))
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

impl<P: ShimPlatform> Task<P> {
    /// Drop the maximum protections of the unmapped parts of `range`, after
    /// a change that may have removed some of its pages. Pages it left
    /// mapped keep theirs.
    fn forget_unmapped_maximum_protections(
        &self,
        maximums: &mut MaximumProtections,
        range: Range<usize>,
    ) {
        let mut cursor = range.start;
        for (mapping, _) in self.global.mm.overlapping(range.clone()) {
            if mapping.start > cursor {
                maximums.set(cursor..mapping.start, VmProtection::all());
            }
            cursor = cursor.max(mapping.end);
        }
        if cursor < range.end {
            maximums.set(cursor..range.end, VmProtection::all());
        }
    }

    /// Drop the maximum protections of `range` after an mmap or munmap that
    /// replaced or removed all of it (`complete`) or failed part way. The
    /// caller holds `macho_mappings`.
    pub(crate) fn forget_replaced_maximum_protections(&self, range: Range<usize>, complete: bool) {
        let mut maximums = self.global.maximum_protections.lock();
        if complete {
            maximums.set(range, VmProtection::all());
        } else {
            self.forget_unmapped_maximum_protections(&mut maximums, range);
        }
    }

    /// The mapped parts of `target` with the flags an mprotect cannot change,
    /// merging neighbors that differ only in flags it can. A failed MAP_FIXED
    /// or replacing Mach allocation replaced or removed mappings if this
    /// changed, since the page manager leaves a hole where a failed mapping
    /// replaced pages. The caller holds `macho_mappings`, which every guest
    /// mapping, unmap and mprotect takes, so none lands in the window.
    fn mapping_snapshot(&self, target: Range<usize>) -> Vec<(Range<usize>, VmFlags)> {
        let mut snapshot: Vec<(Range<usize>, VmFlags)> = Vec::new();
        for (range, flags) in self.global.mm.overlapping(target.clone()) {
            let range = range.start.max(target.start)..range.end.min(target.end);
            let flags = flags - VmFlags::VM_ACCESS_FLAGS - VmFlags::VM_HAS_CONTENTS;
            match snapshot.last_mut() {
                Some((last, last_flags)) if last.end == range.start && *last_flags == flags => {
                    last.end = range.end;
                }
                _ => snapshot.push((range, flags)),
            }
        }
        snapshot
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

    /// Map zero-filled pages for Mach VM. `Fixed { replace: false }` fails
    /// with `MappingError::MapError(AddressInUse)` (or `...ByPlatform`) if
    /// any page is already mapped. Later protection changes cannot exceed
    /// `maximum`, which must contain `protection`.
    pub(crate) fn map_anonymous(
        &self,
        address: usize,
        length: usize,
        placement: AnonymousPlacement,
        protection: VmProtection,
        maximum: VmProtection,
    ) -> Result<usize, MappingError> {
        let length = NonZeroPageSize::new(length).ok_or(MappingError::UnAligned)?;
        let mut flags = CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;
        if let AnonymousPlacement::Fixed { replace } = placement {
            flags |= CreatePagesFlags::FIXED_ADDR;
            flags.set(CreatePagesFlags::NOREPLACE, !replace);
        }
        let range = address..address.saturating_add(length.as_usize());
        let replace = placement == (AnonymousPlacement::Fixed { replace: true });
        // Held from before the pages exist until their final permissions and
        // maximum are in place, so no mprotect or set_maximum lands between.
        let mut macho_mappings = self.global.macho_mappings.lock();
        let before = replace.then(|| self.mapping_snapshot(range.clone()));
        // SAFETY: a replacing fixed mapping has Mach's VM_FLAGS_OVERWRITE
        // semantics; otherwise nothing existing is replaced.
        let result = unsafe {
            self.global.mm.create_pages_with_permissions(
                NonZeroAddress::new(address),
                length,
                flags,
                permissions(protection),
                None,
                |_| {
                    #[cfg(all(test, target_os = "macos"))]
                    self.global
                        .mapping_hook
                        .reach(hook::Point::MappingInitializing);
                    Ok(0)
                },
            )
        };
        {
            let mut maximums = self.global.maximum_protections.lock();
            match &result {
                Ok(pointer) => {
                    let start = pointer.as_usize();
                    maximums.set(start..start + length.as_usize(), maximum);
                }
                Err(_) if replace => {
                    self.forget_unmapped_maximum_protections(&mut maximums, range.clone());
                }
                Err(_) => {}
            }
        }
        if replace
            && (result.is_ok()
                || before.is_some_and(|before| before != self.mapping_snapshot(range.clone())))
        {
            #[cfg(all(test, target_os = "macos"))]
            self.global.mapping_hook.reach(hook::Point::MappingsChanged);
            self.replace_macho_mappings(&mut macho_mappings, range, None);
        }
        Ok(result?.as_usize())
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
        if flags.contains(MmapFlags::FIXED) && self.overlaps_shared_cache(fixed_range.clone()) {
            return Err(Errno::EINVAL);
        }
        let fixed = flags.contains(MmapFlags::FIXED);
        if flags.contains(MmapFlags::ANONYMOUS) {
            // Held through the final permissions, as in `map_anonymous`.
            let mut macho_mappings = self.global.macho_mappings.lock();
            let before = fixed.then(|| self.mapping_snapshot(fixed_range.clone()));
            #[cfg(all(test, target_os = "macos"))]
            if fixed {
                self.global.mapping_hook.reach(hook::Point::FixedSnapshot);
            }
            // SAFETY: MAP_FIXED has Darwin's replacement semantics; otherwise
            // PageManager treats `suggested` only as an allocation hint.
            let result = unsafe {
                self.global.mm.create_pages_with_permissions(
                    suggested,
                    length,
                    mapping_flags(flags, false, direction),
                    permissions(protection),
                    None,
                    |_| {
                        #[cfg(all(test, target_os = "macos"))]
                        self.global
                            .mapping_hook
                            .reach(hook::Point::MappingInitializing);
                        Ok(0)
                    },
                )
            };
            if fixed {
                self.forget_replaced_maximum_protections(fixed_range.clone(), result.is_ok());
                if result.is_ok()
                    || before
                        .is_some_and(|before| before != self.mapping_snapshot(fixed_range.clone()))
                {
                    #[cfg(all(test, target_os = "macos"))]
                    self.global.mapping_hook.reach(hook::Point::MappingsChanged);
                    self.replace_macho_mappings(&mut macho_mappings, fixed_range.clone(), None);
                }
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
        let rewritten = macho.as_ref().filter(|_| executable);
        // Held through initialization, tracking, final permissions and the
        // trampoline's publication or rollback; see `GlobalState`.
        let mut macho_mappings = self.global.macho_mappings.lock();
        let trampoline_checkpoint =
            rewritten.map(|patch_info| self.macho_trampoline_checkpoint(patch_info));
        #[cfg(all(test, target_os = "macos"))]
        if rewritten.is_some() {
            self.global.mapping_hook.reach(hook::Point::Checkpointed);
        }
        let before = fixed.then(|| self.mapping_snapshot(fixed_range.clone()));
        #[cfg(all(test, target_os = "macos"))]
        if fixed {
            self.global.mapping_hook.reach(hook::Point::FixedSnapshot);
        }
        let mut file_offset = offset;
        let mut buffer = [0; PAGE_SIZE];
        let mut initialization_error = None;
        // TODO: initialize a MAP_FIXED replacement before it replaces the old
        // pages. Until then a sibling reading the range sees zeros or partial
        // file contents where XNU shows the old or the new mapping.
        // SAFETY: MAP_FIXED has Darwin's replacement semantics; the new pages
        // are RW while they are initialized.
        let result = unsafe {
            self.global.mm.create_pages_with_permissions(
                suggested,
                length,
                mapping_flags(flags, true, direction),
                final_permissions,
                None,
                |pointer| {
                    #[cfg(all(test, target_os = "macos"))]
                    self.global
                        .mapping_hook
                        .reach(hook::Point::MappingInitializing);
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
                    if let Some(info) = rewritten {
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
        let replaced = result.is_ok()
            || before.is_some_and(|before| before != self.mapping_snapshot(fixed_range.clone()));
        #[cfg(all(test, target_os = "macos"))]
        if fixed && replaced {
            self.global.mapping_hook.reach(hook::Point::MappingsChanged);
        }
        let pointer = match result {
            Ok(pointer) => pointer,
            Err(error) => {
                if let (Some(patch_info), Some(checkpoint)) = (rewritten, trampoline_checkpoint) {
                    self.rollback_macho_trampoline(patch_info, checkpoint);
                }
                if replaced {
                    self.replace_macho_mappings(&mut macho_mappings, fixed_range.clone(), None);
                }
                if fixed {
                    self.forget_replaced_maximum_protections(fixed_range.clone(), false);
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
        if fixed || mapping.is_some() {
            self.replace_macho_mappings(
                &mut macho_mappings,
                address..address + length.as_usize(),
                mapping,
            );
        }
        if fixed {
            self.forget_replaced_maximum_protections(fixed_range, true);
        }
        Ok(address)
    }

    /// Callers hold `macho_mappings` from the checkpoint through rollback or
    /// publication.
    fn macho_trampoline_checkpoint(
        &self,
        patch_info: &Arc<MachoPatchInfo>,
    ) -> MachoTrampolineCheckpoint {
        let key = Arc::as_ptr(&patch_info.rewrite_id) as usize;
        let trampolines = self.global.macho_trampolines.lock();
        if let Some(state) = trampolines.get(&key) {
            MachoTrampolineCheckpoint {
                allocations: state.allocations.len(),
                cursor: state.cursor,
            }
        } else {
            MachoTrampolineCheckpoint {
                allocations: 0,
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
        let added = state.allocations.split_off(checkpoint.allocations);
        if checkpoint.allocations == 0 {
            trampolines.remove(&key);
        } else {
            state.cursor = checkpoint.cursor;
        }
        drop(trampolines);
        for range in added {
            self.remove_trampoline(range);
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
                allocations: Vec::new(),
                cursor: 0,
                invalidated: false,
            });
        debug_assert!(Arc::ptr_eq(&state.rewrite_id, rewrite_id));
        if state.invalidated {
            return Err(MappingError::OutOfMemory);
        }
        let patch_at = |trampoline_address: usize| {
            let mut code = original.clone();
            rewriter
                .patch_code_segment(
                    &mut code,
                    virtual_address as u64,
                    ranges,
                    trampoline_address as u64,
                    callback as u64,
                    tls_offset,
                )
                .map(|(gates, trapped)| {
                    if !trapped.is_empty() {
                        litebox_util_log::warn!(count:? = trapped.len(), addresses:? = trapped; "Mach-O patch sites fell back to traps");
                    }
                    (code, gates)
                })
        };
        // Published gate pages stay RX: other threads may be running them.
        // New gates go on the next page of the last allocation if they fit
        // and it is in reach, else into a new allocation in reach (each holds
        // `trampoline_capacity`, the image's gate upper bound), else traps.
        // TODO: reuse free pages of any allocation in reach, and release an
        // image's allocations once no mapping of it remains.
        let fresh_page = state
            .allocations
            .last()
            .filter(|range| allowed_range.start <= range.start && range.end <= allowed_range.end)
            .and_then(|range| {
                let cursor = state.cursor.checked_next_multiple_of(PAGE_SIZE)?;
                (cursor < range.len()).then(|| (range.clone(), cursor))
            });
        let mut appended = None;
        if let Some((range, cursor)) = fresh_page {
            let (code, gates) = match patch_at(range.start + cursor) {
                Ok(patched) => patched,
                Err(error) => return trap_fallback(&error),
            };
            if gates.is_empty() {
                return pointer
                    .copy_from_slice(0, &code)
                    .ok_or(MappingError::OutOfMemory);
            }
            if gates.len() <= range.len() - cursor {
                appended = Some((range, cursor, code, gates));
            }
        }
        let newly_allocated = appended.is_none();
        let (range, cursor, code, gates) = if let Some(appended) = appended {
            appended
        } else {
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
            let range = match allocation {
                Ok(pointer) => pointer.as_usize()..pointer.as_usize() + capacity,
                Err(error) => return trap_fallback(&error),
            };
            match patch_at(range.start) {
                Ok((code, gates)) if gates.is_empty() => {
                    self.remove_trampoline(range);
                    return pointer
                        .copy_from_slice(0, &code)
                        .ok_or(MappingError::OutOfMemory);
                }
                Ok((_, gates)) if gates.len() > range.len() => {
                    self.remove_trampoline(range);
                    return trap_fallback(&"Mach-O trampoline capacity exhausted");
                }
                Ok((code, gates)) => (range, 0, code, gates),
                Err(error) => {
                    self.remove_trampoline(range);
                    return trap_fallback(&error);
                }
            }
        };
        // A new allocation is still RW; in an existing one, the unpublished
        // pages from `cursor` on are made RW, the gates written, and then
        // every page is RX before code branches to them.
        let unpublished = range.start + cursor..range.end;
        if !newly_allocated {
            // SAFETY: `unpublished` is in the live trampoline allocation, no
            // code branches to it, and the trampoline lock serializes
            // permission changes and gate appends.
            unsafe {
                self.global.mm.change_page_permissions(
                    P::RawMutPointer::from_usize(unpublished.start),
                    unpublished.len(),
                    Permissions::READ | Permissions::WRITE,
                )
            }
            .map_err(MappingError::ProtectError)?;
            #[cfg(all(test, target_os = "macos"))]
            self.global
                .mapping_hook
                .reach(hook::Point::GatePagesWritable);
        }
        if P::RawMutPointer::from_usize(range.start)
            .copy_from_slice(cursor, &gates)
            .is_none()
        {
            if newly_allocated {
                self.remove_trampoline(range);
            } else {
                // SAFETY: `unpublished` remains in the live trampoline
                // allocation and the trampoline lock still serializes this RX
                // restoration.
                let _ = unsafe {
                    self.global.mm.change_page_permissions(
                        P::RawMutPointer::from_usize(unpublished.start),
                        unpublished.len(),
                        Permissions::READ | Permissions::EXEC,
                    )
                };
            }
            return Err(MappingError::OutOfMemory);
        }
        // SAFETY: no code points to the newly appended gates until the final
        // code copy. The RW-to-RX transition synchronizes instruction caches.
        let published = unsafe {
            self.global.mm.change_page_permissions(
                P::RawMutPointer::from_usize(unpublished.start),
                unpublished.len(),
                Permissions::READ | Permissions::EXEC,
            )
        };
        if let Err(error) = published {
            if newly_allocated {
                self.remove_trampoline(range);
            }
            return Err(MappingError::ProtectError(error));
        }
        if newly_allocated {
            state.allocations.push(range);
        }
        state.cursor = cursor + gates.len();
        pointer
            .copy_from_slice(0, &code)
            .ok_or(MappingError::OutOfMemory)
    }

    /// Remove tracking for `replaced`, preserving any mapped prefix and suffix,
    /// and optionally install the mapping that replaced it. Published runtime
    /// trampolines follow the Linux baseline and live until address-space teardown.
    fn replace_macho_mappings(
        &self,
        mappings: &mut BTreeMap<usize, MachoMapping>,
        replaced: Range<usize>,
        replacement: Option<MachoMapping>,
    ) {
        let invalidated: Vec<_> = {
            let mut trampolines = self.global.macho_trampolines.lock();
            trampolines
                .iter_mut()
                .filter_map(|(&key, state)| {
                    state
                        .allocations
                        .iter()
                        .any(|range| range.start < replaced.end && replaced.start < range.end)
                        .then(|| {
                            state.invalidated = true;
                            key
                        })
                })
                .collect()
        };
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

    /// Rewrite what `range` makes executable. The caller holds
    /// `macho_mappings` through the permission change.
    fn rewrite_mprotect_range(
        &self,
        mappings: &mut BTreeMap<usize, MachoMapping>,
        range: Range<usize>,
    ) -> Result<(), Errno> {
        struct RewriteRange {
            mapping_start: usize,
            range: Range<usize>,
            file_offset: usize,
            patch_info: Arc<MachoPatchInfo>,
        }

        let (address, end) = (range.start, range.end);
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
        let end = address.checked_add(length).ok_or(Errno::EINVAL)?;
        if self.overlaps_shared_cache(address..end) {
            return Err(Errno::EINVAL);
        }
        let mut macho_mappings = self.global.macho_mappings.lock();
        // SAFETY: Darwin munmap relinquishes the caller-selected guest range.
        let result = unsafe {
            self.global
                .mm
                .remove_pages(P::RawMutPointer::from_usize(address), length)
        };
        self.forget_replaced_maximum_protections(address..end, result.is_ok());
        result.map_err(|_| Errno::EINVAL)?;
        #[cfg(all(test, target_os = "macos"))]
        self.global.mapping_hook.reach(hook::Point::MappingsChanged);
        self.replace_macho_mappings(&mut macho_mappings, address..end, None);
        Ok(())
    }

    /// `vm_map_protect` with `set_max`: lower the maximum protection of the
    /// page-aligned `range` to `maximum` and each page's current protection
    /// to what it allows. All or nothing: every page must be mapped
    /// (`KERN_INVALID_ADDRESS`) and its maximum must allow `maximum`
    /// (`KERN_PROTECTION_FAILURE`), checked in address order. A range
    /// overlapping a live runtime trampoline fails closed with
    /// `KERN_NOT_SUPPORTED`: appending gates makes its unpublished pages RW
    /// and then RX without consulting recorded maxima.
    pub(crate) fn set_maximum_protection(
        &self,
        range: Range<usize>,
        maximum: VmProtection,
    ) -> Result<(), KernReturn> {
        let requested = permissions(maximum);
        // Serialized with mprotect and every mapping change, as
        // vm_map_protect holds the map lock.
        let _mappings = self.global.macho_mappings.lock();
        let trampoline = self
            .global
            .macho_trampolines
            .lock()
            .values()
            .filter(|state| !state.invalidated)
            .flat_map(|state| &state.allocations)
            .any(|trampoline| trampoline.start < range.end && range.start < trampoline.end);
        if trampoline {
            self.log_unsupported_once(
                "mach_vm_protect(set_maximum) of a runtime trampoline",
                0,
                format_args!(""),
            );
            return Err(KernReturn::NOT_SUPPORTED);
        }
        let mut maximums = self.global.maximum_protections.lock();
        let mappings = self.global.mm.overlapping(range.clone());
        let mut cursor = range.start;
        for (mapping, flags) in &mappings {
            if mapping.start > cursor {
                return Err(KernReturn::INVALID_ADDRESS);
            }
            // VM_MAY% is VM_% << 4.
            let may = Permissions::from(VmFlags::from_bits_truncate(flags.bits() >> 4));
            let part = mapping.start.max(range.start)..mapping.end.min(range.end);
            if !may.contains(requested) || !maximums.allows(&part, maximum) {
                return Err(KernReturn::PROTECTION_FAILURE);
            }
            cursor = mapping.end;
        }
        if cursor < range.end {
            return Err(KernReturn::INVALID_ADDRESS);
        }
        // Pages are lowered before the new maximum is recorded, so a host
        // failure part way never leaves a page above its recorded maximum.
        for (mapping, flags) in mappings {
            let current = Permissions::from(flags);
            if requested.contains(current) {
                continue;
            }
            let part = mapping.start.max(range.start)..mapping.end.min(range.end);
            // SAFETY: only removes access from guest pages found mapped above.
            unsafe {
                self.global.mm.change_page_permissions(
                    P::RawMutPointer::from_usize(part.start),
                    part.len(),
                    current & requested,
                )
            }
            .map_err(|_| KernReturn::FAILURE)?;
        }
        maximums.set(range, maximum);
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
        let range = address..end;
        let mut mappings = self.global.macho_mappings.lock();
        let cache_range = self.global.shared_cache.lock().as_ref().and_then(|cache| {
            let inner = cache.range.start.max(address)..cache.range.end.min(end);
            (inner.start < inner.end).then_some(inner)
        });
        let Some(cache_range) = cache_range else {
            self.check_task_memory_protection(range.clone(), protection)?;
            return self.mprotect_task_memory_locked(&mut mappings, range, protection);
        };
        let below = address..cache_range.start;
        let above = cache_range.end..end;
        // vm_map_protect: every part is checked in address order, then
        // changed, under one hold of `macho_mappings`. Cache maximums live in
        // `SharedCacheState`. A part can still fail after an earlier one
        // changed; that error is returned.
        self.check_task_memory_protection(below.clone(), protection)?;
        let allowed = self
            .global
            .shared_cache
            .lock()
            .as_ref()
            .is_some_and(|cache| cache.allows(&cache_range, protection));
        if !allowed {
            return Err(Errno::EACCES);
        }
        self.check_task_memory_protection(above.clone(), protection)?;
        #[cfg(all(test, target_os = "macos"))]
        self.global.mapping_hook.reach(hook::Point::SplitChecked);
        for part in [below, above] {
            if part.start < part.end {
                self.mprotect_task_memory_locked(&mut mappings, part, protection)?;
            }
        }
        let mut cache = self.global.shared_cache.lock();
        let cache = cache.as_mut().ok_or(Errno::EACCES)?;
        // Unsupplied pages get the new protection at page-in.
        for (part, paged) in cache.paged_parts(&cache_range) {
            if !paged {
                self.change_permissions(part, protection)?;
            }
        }
        cache.set_protection(&cache_range, protection);
        Ok(())
    }

    /// `vm_map_protect_preflight` for an mprotect of `range`, before anything
    /// changes and in address order: a hole fails with ENOMEM, a mapping whose
    /// `VM_MAY*` flags or recorded maximum protection do not allow
    /// `protection` with EACCES. The caller holds `macho_mappings` through
    /// the change.
    fn check_task_memory_protection(
        &self,
        range: Range<usize>,
        protection: VmProtection,
    ) -> Result<(), Errno> {
        let requested = VmFlags::from_bits_truncate(u32::from(permissions(protection).bits()))
            & VmFlags::VM_ACCESS_FLAGS;
        let maximums = self.global.maximum_protections.lock();
        let mut cursor = range.start;
        for (mapping, flags) in self.global.mm.overlapping(range.clone()) {
            if mapping.start > cursor {
                return Err(Errno::ENOMEM);
            }
            let may = VmFlags::from_bits_truncate(flags.bits() >> 4);
            let part = mapping.start.max(range.start)..mapping.end.min(range.end);
            if (flags & VmFlags::VM_ACCESS_FLAGS != requested && !may.contains(requested))
                || !maximums.allows(&part, protection)
            {
                return Err(Errno::EACCES);
            }
            cursor = mapping.end;
        }
        if cursor < range.end {
            return Err(Errno::ENOMEM);
        }
        Ok(())
    }

    /// `mprotect` of task memory outside the shared-cache instance. The caller
    /// holds `macho_mappings` from the rewrite through the permission change
    /// (`vm_map_protect`).
    fn mprotect_task_memory_locked(
        &self,
        mappings: &mut BTreeMap<usize, MachoMapping>,
        range: Range<usize>,
        protection: VmProtection,
    ) -> Result<(), Errno> {
        if protection.contains(VmProtection::EXECUTE) {
            self.rewrite_mprotect_range(mappings, range.clone())?;
        }
        #[cfg(all(test, target_os = "macos"))]
        self.global.mapping_hook.reach(hook::Point::Protecting);
        self.change_permissions(range.clone(), protection)?;
        if protection.contains(VmProtection::WRITE) {
            for mapping in mappings.values_mut().filter(|mapping| {
                mapping.range.start < range.end && range.start < mapping.range.end
            }) {
                forget_patched_range(&mut mapping.patched_ranges, range.clone());
            }
        }
        Ok(())
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    extern crate std;

    use super::*;
    use alloc::{sync::Arc, vec::Vec};
    use litebox::LiteBox;
    use litebox_broker_core::{
        CallerCredential, ObjectRights, PolicyEngine,
        fs::{
            in_mem::{InMem, InitialNode},
            inode_allocator::InodeAllocators,
            resolver::Resolver,
        },
        test_support::TestBrokerBuilder,
    };
    use litebox_broker_host::test_support::InProcessBrokerSetup;
    use litebox_broker_local::BrokerLocal;
    use litebox_broker_protocol::fs::{FileAccessMode, FileMode, FileOpenFlags, FileUser};
    use litebox_common_linux::{PtRegs, vmem::VmFlags};
    use litebox_common_macos::{TaskParams, syscall::nr, user_pointers::UserPtr};
    use litebox_platform_macos_userland::MacosUserland as Platform;
    use litebox_trampoline::{aarch64::GateMetadata, aarch64::decode_branch_target};

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

    /// `macho_image` whose `__text` also fills a second page with syscalls,
    /// so its trampoline spans several pages and mapping the first page
    /// alone leaves room for later mappings' gates.
    fn two_page_macho_image() -> Vec<u8> {
        const SECTION: usize = 32 + 72;
        let mut bytes = macho_image();
        bytes.resize(2 * PAGE_SIZE, 0);
        put64(&mut bytes, 64, 2 * PAGE_SIZE as u64);
        put64(&mut bytes, 80, 2 * PAGE_SIZE as u64);
        put64(&mut bytes, SECTION + 40, (2 * PAGE_SIZE - TEXT) as u64);
        for offset in (PAGE_SIZE..2 * PAGE_SIZE).step_by(4) {
            put32(&mut bytes, offset, SVC);
        }
        bytes
    }

    /// Map one page of the image on descriptor 0 at `offset`.
    fn map_image_page(
        task: &Task<Platform>,
        offset: usize,
        protection: VmProtection,
    ) -> Result<usize, Errno> {
        task.sys_mmap(
            0,
            PAGE_SIZE,
            protection,
            MmapFlags::PRIVATE,
            0,
            i64::try_from(offset).unwrap(),
        )
    }

    /// The gate the rewritten syscall at `site` branches to; asserts that it
    /// is an RX svc gate for `site`.
    fn published_gate(task: &Task<Platform>, site: usize) -> usize {
        let target =
            usize::try_from(decode_branch_target(instruction_at(site), site as u64).unwrap())
                .unwrap();
        assert_eq!(
            task.global.mm.get_memory_permissions(
                NonZeroAddress::new(target & !(PAGE_SIZE - 1)).unwrap(),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            ),
            Some(Permissions::READ | Permissions::EXEC),
        );
        let gate = UserPtr::<u8>::from_usize(target)
            .to_owned_slice::<Platform>(64)
            .unwrap();
        let classified = Rewriter::new(litebox_trampoline::TargetHost::MacOs)
            .unwrap()
            .classify_gate_slot(&gate, target as u64, target as u64)
            .unwrap();
        assert_eq!(classified.metadata(), GateMetadata::Svc);
        assert_eq!(classified.original_site(), site as u64);
        target
    }

    /// The trampoline allocations of the task's one rewritten image.
    fn trampoline_allocations(task: &Task<Platform>) -> Vec<Range<usize>> {
        let trampolines = task.global.macho_trampolines.lock();
        assert_eq!(trampolines.len(), 1);
        trampolines.values().next().unwrap().allocations.clone()
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
        task_with_files(&[data])
    }

    /// A task with each of `files` open read-only on the descriptor of its
    /// index, at `/image` for the first and `/image<index>` for the others.
    fn task_with_files(files: &[&[u8]]) -> Task<Platform> {
        let platform = Platform::new();
        let mode = FileMode::RWXU | FileMode::RWXG | FileMode::RWXO;
        let paths: Vec<_> = (0..files.len())
            .map(|index| match index {
                0 => std::string::String::from("/image"),
                _ => std::format!("/image{index}"),
            })
            .collect();
        let mut nodes = vec![(
            "/",
            InitialNode::Directory {
                mode,
                owner: FileUser::ROOT,
            },
        )];
        for (path, data) in paths.iter().zip(files) {
            nodes.push((
                path.as_str(),
                InitialNode::File {
                    mode,
                    owner: FileUser::ROOT,
                    data: data.to_vec().into(),
                },
            ));
        }
        let fs = InMem::<Platform>::new_initialized(nodes, InodeAllocators::new().next());
        let broker = TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_file_service(Arc::new(Resolver::<Platform, _>::new(fs)))
        .build()
        .unwrap();
        let setup = InProcessBrokerSetup::new(
            broker
                .create_process(CallerCredential::Unauthenticated)
                .unwrap(),
        );
        let readiness = setup.readiness_sink();
        let (local, _startup, ()) = BrokerLocal::negotiate(setup, |setup| {
            let memory = setup.shared_memory();
            Ok((setup.activate(), memory, ()))
        })
        .unwrap();
        let litebox = LiteBox::new_with_broker_local(platform, local);
        readiness.attach(litebox.broker_notification_dispatcher());
        let mut builder = MacosShimBuilder::new_with_litebox(platform, litebox);
        for (fd, path) in (0..).zip(&paths) {
            let file = builder
                .litebox()
                .open_file(
                    &litebox::fs::Context::new(),
                    path.as_str(),
                    FileAccessMode::ReadOnly,
                    FileOpenFlags::NONE,
                    FileMode::empty(),
                )
                .unwrap();
            assert_eq!(builder.inherit_file(file), Ok(fd));
        }
        let shim = builder.build();
        Task::new_main(
            shim.global,
            shim.files,
            TaskParams::default(),
            Process::new(),
        )
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
        let task = Task::new_main(
            shim.global,
            shim.files,
            TaskParams::default(),
            Process::new(),
        );

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

    /// A file mapping that replaces pages with MAP_FIXED drops their
    /// maximum protection, like any other replacement.
    #[test]
    fn file_map_fixed_drops_the_maximum_protection_it_replaced() {
        let task = task_with_file(&macho_image());
        let rw = VmProtection::READ | VmProtection::WRITE;
        let address = task
            .map_anonymous(
                0,
                PAGE_SIZE,
                AnonymousPlacement::Hint,
                VmProtection::empty(),
                VmProtection::empty(),
            )
            .unwrap();
        assert_eq!(
            task.sys_mprotect(address, PAGE_SIZE, rw),
            Err(Errno::EACCES)
        );
        assert_eq!(
            task.sys_mmap(
                address,
                PAGE_SIZE,
                VmProtection::READ,
                MmapFlags::PRIVATE | MmapFlags::FIXED,
                0,
                0,
            ),
            Ok(address)
        );
        assert_eq!(task.sys_mprotect(address, PAGE_SIZE, rw), Ok(()));
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    /// A read-only shared file mapping's maximum (no `VM_MAYWRITE`) bounds a
    /// new maximum too.
    #[test]
    fn set_maximum_protection_stays_within_the_mapping_maximum() {
        let task = task_with_file(&macho_image());
        let address = task
            .sys_mmap(0, PAGE_SIZE, VmProtection::READ, MmapFlags::SHARED, 0, 0)
            .unwrap();
        let range = address..address + PAGE_SIZE;
        assert_eq!(
            task.set_maximum_protection(range.clone(), VmProtection::READ | VmProtection::WRITE),
            Err(KernReturn::PROTECTION_FAILURE)
        );
        assert_eq!(
            task.set_maximum_protection(range, VmProtection::READ),
            Ok(())
        );
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    /// Appending gates makes a runtime trampoline's pages RW and then RX,
    /// so a maximum is never recorded over them: lowering one fails and
    /// changes nothing, and a later append still publishes its gates RX.
    #[test]
    fn set_maximum_protection_refuses_runtime_trampoline_pages() {
        let rx = VmProtection::READ | VmProtection::EXECUTE;
        let task = task_with_file(&two_page_macho_image());
        let first = map_image_page(&task, 0, rx).unwrap();
        let (range, cursor) = {
            let trampolines = task.global.macho_trampolines.lock();
            let state = trampolines.values().next().unwrap();
            (state.allocations[0].clone(), state.cursor)
        };
        // The page the next append starts on.
        let unpublished = range.start + cursor.next_multiple_of(PAGE_SIZE);
        assert!(unpublished < range.end);
        assert_eq!(
            task.set_maximum_protection(
                unpublished..unpublished + PAGE_SIZE,
                VmProtection::empty()
            ),
            Err(KernReturn::NOT_SUPPORTED)
        );
        assert!(
            task.global
                .maximum_protections
                .lock()
                .allows(&range, VmProtection::all())
        );
        let second = map_image_page(&task, PAGE_SIZE, rx).unwrap();
        let gate = published_gate(&task, second);
        assert!((unpublished..unpublished + PAGE_SIZE).contains(&gate));
        task.sys_munmap(second, PAGE_SIZE).unwrap();
        task.sys_munmap(first, PAGE_SIZE).unwrap();
    }

    /// A replacing Mach allocation whose final protection the host refuses
    /// (W+X) fails after it destroyed the old mapping, so the old mapping's
    /// Mach-O tracking goes with it.
    #[test]
    fn failed_overwrite_drops_the_macho_tracking_it_destroyed() {
        let task = task_with_file(&macho_image());
        let address = mmap_with_protection(&task, VmProtection::READ).unwrap();
        assert!(task.global.macho_mappings.lock().contains_key(&address));
        assert!(
            task.map_anonymous(
                address,
                PAGE_SIZE,
                AnonymousPlacement::Fixed { replace: true },
                VmProtection::all(),
                VmProtection::all(),
            )
            .is_err()
        );
        assert!(
            task.global
                .mm
                .overlapping(address..address + PAGE_SIZE)
                .is_empty(),
            "the failed overwrite left the old mapping"
        );
        assert!(task.global.macho_mappings.lock().is_empty());
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
        assert_eq!(trampoline.allocations, []);
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
                .all(|state| state.allocations.is_empty() && state.cursor == 0)
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
            2 * litebox_trampoline::MAX_TRAMPOLINE_DISPLACEMENT,
            PAGE_SIZE,
        );
    }

    #[test]
    fn trampoline_capacity_beyond_reach_uses_traps() {
        assert_unavailable_trampoline_uses_traps(
            PAGE_SIZE,
            2 * litebox_trampoline::MAX_TRAMPOLINE_DISPLACEMENT,
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
        assert_eq!(writer.write(nop, Some(TEXT), None).unwrap(), 4);
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
        let classified = Rewriter::new(litebox_trampoline::TargetHost::MacOs)
            .unwrap()
            .classify_gate_slot(&gate, target as u64, target as u64)
            .unwrap();
        assert_eq!(classified.metadata(), GateMetadata::Svc);
        assert_eq!(classified.original_site(), code_address as u64);
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    /// Make the page at `address` writable, store a syscall at `site`, and
    /// make it executable again, which rewrites it.
    fn rewrite_stored_syscall(task: &Task<Platform>, address: usize, site: usize) {
        use litebox_common_macos::user_pointers::UserPtrMut;

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
    }

    #[test]
    fn writable_transition_rewrites_modified_code_when_made_executable_again() {
        let task = task_with_file(&two_page_macho_image());
        let address =
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE).unwrap();
        let first_gate = published_gate(&task, address + TEXT);
        let site = address + TEXT + 4;
        rewrite_stored_syscall(&task, address, site);
        // The new gate is on a fresh page; the first stays published.
        assert!(published_gate(&task, site) > (first_gate | (PAGE_SIZE - 1)));
        assert_eq!(published_gate(&task, address + TEXT), first_gate);
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    /// Rewriting text again once the small image's only gate page is
    /// published puts the new gate in another allocation in reach and keeps
    /// the published one.
    #[test]
    fn rewrite_without_a_fresh_gate_page_uses_another_allocation() {
        let task = task_with_file(&macho_image());
        let address =
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE).unwrap();
        let site = address + TEXT;
        let first_gate = published_gate(&task, site);
        rewrite_stored_syscall(&task, address, site);
        let gate = published_gate(&task, site);
        let allocations = trampoline_allocations(&task);
        assert_eq!(allocations.len(), 2);
        assert!(allocations[0].contains(&first_gate));
        assert!(allocations[1].contains(&gate));
        let allowed = trampoline_allocation_range(address..address + PAGE_SIZE).unwrap();
        assert!(allocations[1].start >= allowed.start && allocations[1].end <= allowed.end);
        assert_eq!(
            task.global.mm.get_memory_permissions(
                NonZeroAddress::new(allocations[0].start).unwrap(),
                NonZeroPageSize::new(allocations[0].len()).unwrap(),
            ),
            Some(Permissions::READ | Permissions::EXEC),
        );
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
            .map(|state| (state.allocations.clone(), state.cursor));
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
                .map(|state| (state.allocations.clone(), state.cursor)),
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

    /// Mappings through a descriptor and its `dup` share the image's
    /// rewrite state, and the syscall site branches to a published gate in
    /// both. The small image's gates fill its one-page allocation's only
    /// page, so the second mapping's go to another allocation.
    #[test]
    fn executable_mappings_share_one_trampoline_per_file() {
        let task = task_with_file(&macho_image());
        let duplicate = i32::try_from(task.sys_dup(0).unwrap()).unwrap();
        let first =
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE).unwrap();
        let first_gate = published_gate(&task, first + TEXT);
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
        let targets = [first_gate, published_gate(&task, second + TEXT)];
        assert_eq!(published_gate(&task, first + TEXT), first_gate);
        let file = task.files.typed_fd(0).unwrap();
        let patch_info = task.macho_patch_info(&file).unwrap();
        assert_eq!(patch_info.trampoline_capacity, PAGE_SIZE);
        let allocations = trampoline_allocations(&task);
        assert_eq!(allocations.len(), 2);
        for ((allocation, address), target) in allocations.iter().zip([first, second]).zip(targets)
        {
            assert_eq!(allocation.len(), patch_info.trampoline_capacity);
            assert!(allocation.contains(&target));
            let allowed = trampoline_allocation_range(address..address + PAGE_SIZE).unwrap();
            assert!(allocation.start >= allowed.start && allocation.end <= allowed.end);
        }
        task.sys_munmap(first, PAGE_SIZE).unwrap();
        task.sys_munmap(second, PAGE_SIZE).unwrap();
        task.sys_close(0).unwrap();
        task.sys_close(duplicate).unwrap();
        for allocation in allocations {
            assert_eq!(
                task.global.mm.get_memory_permissions(
                    NonZeroAddress::new(allocation.start).unwrap(),
                    NonZeroPageSize::new(allocation.len()).unwrap(),
                ),
                Some(Permissions::READ | Permissions::EXEC),
            );
        }
    }

    /// When no gate page can be allocated in a mapping's reach, its sites
    /// become traps rather than stay syscalls. `far` is twice the branch
    /// reach above `near`, out of reach of `near`'s gates, in a reservation
    /// that covers its whole reach; a free page below `near` holds `near`'s
    /// gates.
    #[test]
    fn mapping_without_a_gate_page_in_reach_traps_its_sites() {
        const BRK_TRAP: u32 = 0xd436_2160; // BRK #0xB10B
        let task = task_with_file(&macho_image());
        let reach = litebox_trampoline::MAX_TRAMPOLINE_DISPLACEMENT;
        let base = task
            .reserve_anonymous(0, 3 * reach + 2 * PAGE_SIZE, AllocationDirection::TopDown)
            .unwrap();
        task.sys_munmap(base, PAGE_SIZE).unwrap();
        let [near, far] = [base + PAGE_SIZE, base + PAGE_SIZE + 2 * reach].map(|address| {
            task.sys_mmap(
                address,
                PAGE_SIZE,
                VmProtection::READ | VmProtection::EXECUTE,
                MmapFlags::PRIVATE | MmapFlags::FIXED,
                0,
                0,
            )
            .unwrap()
        });
        let gate = published_gate(&task, near + TEXT);
        assert!(
            gate < trampoline_allocation_range(far..far + PAGE_SIZE)
                .unwrap()
                .start
        );
        assert_eq!(
            &*UserPtr::<u8>::from_usize(far + TEXT)
                .to_owned_slice::<Platform>(4)
                .unwrap(),
            &BRK_TRAP.to_le_bytes(),
        );
        assert_eq!(published_gate(&task, near + TEXT), gate);
        assert_eq!(trampoline_allocations(&task).len(), 1);
    }

    /// A failed executable mapping that took its checkpoint before another
    /// thread's mapping published gates of the same image must not reclaim
    /// (no prior trampoline) or rewind over (existing trampoline) them.
    fn assert_failed_mmap_keeps_gates_published_concurrently(existing: bool) {
        let task = task_with_file(&two_page_macho_image());
        let earlier = existing
            .then(|| map_image_page(&task, 0, VmProtection::READ | VmProtection::EXECUTE).unwrap());
        // Cache the image's rewrite metadata, so both mappings share it.
        task.macho_patch_info(&task.files.typed_fd(0).unwrap())
            .unwrap();
        // W^X: the mapping fails after its rewrite and rolls back. Between its
        // checkpoint and its rollback, the other thread maps the same image.
        let (excluded, failed, mapped) = race_at(
            &task,
            hook::Point::Checkpointed,
            || {
                mmap_with_protection(
                    &task,
                    VmProtection::READ | VmProtection::WRITE | VmProtection::EXECUTE,
                )
            },
            |other| map_image_page(other, PAGE_SIZE, VmProtection::READ | VmProtection::EXECUTE),
        );
        assert!(
            excluded,
            "another mapping could enter this mapping's transaction"
        );
        assert!(failed.is_err());
        let address = mapped.unwrap();
        published_gate(&task, address);
        let trampolines = task.global.macho_trampolines.lock();
        let trampoline = trampolines.values().next().unwrap();
        let range = trampoline.allocations.last().unwrap().clone();
        let last_gate = published_gate(&task, address + PAGE_SIZE - 4);
        assert!(trampoline.cursor > last_gate - range.start);
        drop(trampolines);
        task.sys_munmap(address, PAGE_SIZE).unwrap();
        if let Some(earlier) = earlier {
            published_gate(&task, earlier + TEXT);
            task.sys_munmap(earlier, PAGE_SIZE).unwrap();
        }
    }

    #[test]
    fn failed_mmap_keeps_a_new_trampoline_published_concurrently() {
        assert_failed_mmap_keeps_gates_published_concurrently(false);
    }

    #[test]
    fn failed_mmap_keeps_gates_appended_concurrently() {
        assert_failed_mmap_keeps_gates_published_concurrently(true);
    }

    /// Appending gates to a trampoline makes only its unpublished pages
    /// writable: a published gate page, which other threads may be running,
    /// stays RX while the append writes the page at the cursor.
    #[test]
    fn appending_gates_keeps_published_gate_pages_executable() {
        let task = task_with_file(&two_page_macho_image());
        let first = map_image_page(&task, 0, VmProtection::READ | VmProtection::EXECUTE).unwrap();
        let gate = published_gate(&task, first + TEXT);
        let (range, cursor) = {
            let trampolines = task.global.macho_trampolines.lock();
            let trampoline = trampolines.values().next().unwrap();
            (trampoline.allocations[0].clone(), trampoline.cursor)
        };
        let gate_page = range.start..range.start + PAGE_SIZE;
        assert!(gate_page.contains(&gate));
        let next_page = range.start + cursor.next_multiple_of(PAGE_SIZE);
        let global = Arc::clone(&task.global);
        let (report, permissions) = std::sync::mpsc::channel();
        task.global.mapping_hook.set(move |point| {
            if point == hook::Point::GatePagesWritable {
                let permissions_at = |address| {
                    global.mm.get_memory_permissions(
                        NonZeroAddress::new(address).unwrap(),
                        NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    )
                };
                report
                    .send((permissions_at(gate_page.start), permissions_at(next_page)))
                    .unwrap();
            }
        });
        let second =
            map_image_page(&task, PAGE_SIZE, VmProtection::READ | VmProtection::EXECUTE).unwrap();
        task.global.mapping_hook.clear();
        assert_eq!(
            permissions.try_recv(),
            Ok((
                Some(Permissions::READ | Permissions::EXEC),
                Some(Permissions::READ | Permissions::WRITE)
            )),
            "gates were not appended, or the published page was writable"
        );
        assert!(published_gate(&task, second) >= gate_page.end);
        assert_eq!(published_gate(&task, first + TEXT), gate);
        task.sys_munmap(second, PAGE_SIZE).unwrap();
        task.sys_munmap(first, PAGE_SIZE).unwrap();
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
        assert_eq!(trampolines.values().next().unwrap().allocations, []);
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
            .allocations[0]
            .clone();
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

    fn instruction_at(site: usize) -> u32 {
        u32::from_le_bytes(
            *UserPtr::<u8>::from_usize(site)
                .to_owned_slice::<Platform>(4)
                .unwrap()
                .first_chunk()
                .unwrap(),
        )
    }

    fn map_image_at(
        task: &Task<Platform>,
        address: usize,
        flags: MmapFlags,
    ) -> Result<usize, Errno> {
        task.sys_mmap(
            address,
            PAGE_SIZE,
            VmProtection::READ,
            flags | MmapFlags::FIXED,
            0,
            0,
        )
    }

    /// [`race_at`] at [`hook::Point::MappingsChanged`]: after `change` has
    /// changed the address space and before it has updated Mach-O tracking.
    fn race_mapping_change<C, R>(
        task: &Task<Platform>,
        change: impl FnOnce() -> C,
        racer: impl FnOnce(&Task<Platform>) -> R + Send,
    ) -> (bool, C, R)
    where
        R: Send,
    {
        race_at(task, hook::Point::MappingsChanged, change, racer)
    }

    /// Run `change` on this thread and `racer` on a sibling that starts
    /// once `change` reaches `at`. `change` resumes once the sibling has
    /// checked whether `macho_mappings` is held, which this returns with both
    /// results; `racer` needs `macho_mappings`, so if it is held, `racer`
    /// completes only after `change` does.
    fn race_at<C, R>(
        task: &Task<Platform>,
        at: hook::Point,
        change: impl FnOnce() -> C,
        racer: impl FnOnce(&Task<Platform>) -> R + Send,
    ) -> (bool, C, R)
    where
        R: Send,
    {
        const BOUND: std::time::Duration = std::time::Duration::from_secs(10);
        let sibling = task.new_sibling(0);
        let (go, start) = std::sync::mpsc::channel::<()>();
        let (report, held) = std::sync::mpsc::channel::<bool>();
        std::thread::scope(|scope| {
            let racer = scope.spawn(move || {
                <Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
                    start.recv_timeout(BOUND).unwrap();
                    report
                        .send(sibling.global.macho_mappings.try_lock().is_none())
                        .unwrap();
                    racer(&sibling)
                })
            });
            let (pass, excluded) = std::sync::mpsc::channel::<bool>();
            let mut go = Some(go);
            task.global.mapping_hook.set(move |point| {
                if point == at {
                    go.take().unwrap().send(()).unwrap();
                    pass.send(held.recv_timeout(BOUND).unwrap()).unwrap();
                }
            });
            let changed = change();
            task.global.mapping_hook.clear();
            (excluded.try_recv().unwrap(), changed, racer.join().unwrap())
        })
    }

    /// A Mach-O mapping is tracked before it is visible: an `mprotect`
    /// making it executable while it is being mapped rewrites it.
    #[test]
    fn mprotect_exec_racing_a_readonly_macho_map_fixed_rewrites_it() {
        let task = task_with_file(&macho_image());
        let address = task
            .sys_mmap(
                0,
                PAGE_SIZE,
                VmProtection::READ | VmProtection::WRITE,
                MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
                -1,
                0,
            )
            .unwrap();
        let (excluded, mapped, protected) = race_mapping_change(
            &task,
            || map_image_at(&task, address, MmapFlags::PRIVATE),
            |sibling| {
                sibling.sys_mprotect(
                    address,
                    PAGE_SIZE,
                    VmProtection::READ | VmProtection::EXECUTE,
                )
            },
        );
        assert!(excluded, "the mapping was visible before its tracking");
        assert_eq!((mapped, protected), (Ok(address), Ok(())));
        assert!(
            decode_branch_target(instruction_at(address + TEXT), (address + TEXT) as u64).is_some()
        );
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    /// An unmap or replacement racing a Mach-O mapping removes its tracking
    /// with it: no stale tracking rewrites what is mapped there later.
    fn assert_change_racing_a_macho_map_fixed_leaves_no_tracking(replace: bool) {
        let task = task_with_file(&macho_image());
        let address = map_image_at(&task, 0x7b_0000_0000, MmapFlags::PRIVATE).unwrap();
        let (excluded, mapped, changed) = race_mapping_change(
            &task,
            || map_image_at(&task, address, MmapFlags::PRIVATE),
            |sibling| {
                if replace {
                    sibling
                        .sys_mmap(
                            address,
                            PAGE_SIZE,
                            VmProtection::READ | VmProtection::WRITE,
                            MmapFlags::ANONYMOUS | MmapFlags::PRIVATE | MmapFlags::FIXED,
                            -1,
                            0,
                        )
                        .map(|_| ())
                } else {
                    sibling.sys_munmap(address, PAGE_SIZE)
                }
            },
        );
        assert!(excluded, "the mapping was visible before its tracking");
        assert_eq!((mapped, changed), (Ok(address), Ok(())));
        assert!(
            task.global
                .macho_mappings
                .lock()
                .values()
                .all(|mapping| mapping.range.end <= address
                    || mapping.range.start >= address + PAGE_SIZE),
            "replace: {replace}"
        );
        if replace {
            litebox_common_macos::user_pointers::UserPtrMut::<u8>::from_usize(address + TEXT)
                .copy_from_slice::<Platform>(0, &SVC.to_le_bytes())
                .unwrap();
            task.sys_mprotect(
                address,
                PAGE_SIZE,
                VmProtection::READ | VmProtection::EXECUTE,
            )
            .unwrap();
            assert_eq!(instruction_at(address + TEXT), SVC);
            task.sys_munmap(address, PAGE_SIZE).unwrap();
        }
    }

    /// A replacement's maximum protection is recorded while it holds
    /// `macho_mappings`: it is in place when the change updates the replaced
    /// pages' tracking, and an mprotect racing a replacing Mach allocation
    /// with maximum VM_PROT_NONE waits for it and is refused.
    #[test]
    fn mprotect_racing_a_replacement_sees_its_maximum_protection() {
        let task = task_with_file(&macho_image());
        let rw = VmProtection::READ | VmProtection::WRITE;
        let address = task
            .map_anonymous(0, PAGE_SIZE, AnonymousPlacement::Hint, rw, rw)
            .unwrap();
        let replace = || {
            task.map_anonymous(
                address,
                PAGE_SIZE,
                AnonymousPlacement::Fixed { replace: true },
                VmProtection::empty(),
                VmProtection::empty(),
            )
        };
        let global = Arc::clone(&task.global);
        let (seen, recorded) = std::sync::mpsc::channel();
        task.global.mapping_hook.set(move |point| {
            if point == hook::Point::MappingsChanged {
                let page = address..address + PAGE_SIZE;
                let maximums = global.maximum_protections.lock();
                seen.send(!maximums.allows(&page, VmProtection::READ))
                    .unwrap();
            }
        });
        assert_eq!(replace().ok(), Some(address));
        task.global.mapping_hook.clear();
        assert_eq!(recorded.try_recv(), Ok(true));
        task.map_anonymous(
            address,
            PAGE_SIZE,
            AnonymousPlacement::Fixed { replace: true },
            rw,
            rw,
        )
        .unwrap();
        let (excluded, mapped, protected) = race_mapping_change(&task, replace, |sibling| {
            sibling.sys_mprotect(address, PAGE_SIZE, VmProtection::READ)
        });
        assert!(excluded);
        assert_eq!(mapped.ok(), Some(address));
        assert_eq!(protected, Err(Errno::EACCES));
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    /// A guest mapping holds `macho_mappings` from before its pages exist
    /// through their final permissions and maximum: a `set_maximum` of NONE
    /// racing it waits, then lowers the mapped page, so current access never
    /// exceeds the recorded maximum.
    fn assert_set_maximum_racing_a_mapping_waits_for_it(
        task: &Task<Platform>,
        address: usize,
        map: impl FnOnce() -> Result<usize, Errno>,
    ) {
        let page = address..address + PAGE_SIZE;
        let (excluded, mapped, lowered) =
            race_at(task, hook::Point::MappingInitializing, map, |sibling| {
                sibling.set_maximum_protection(page.clone(), VmProtection::empty())
            });
        assert!(
            excluded,
            "set_maximum could land before the final permissions"
        );
        assert_eq!((mapped, lowered), (Ok(address), Ok(())));
        assert!(!crate::tests::guest_flags(task, address).intersects(VmFlags::VM_ACCESS_FLAGS));
        assert_eq!(
            task.sys_mprotect(address, PAGE_SIZE, VmProtection::READ),
            Err(Errno::EACCES)
        );
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    #[test]
    fn set_maximum_racing_an_anonymous_mmap_waits_for_it() {
        let task = task_with_file(&macho_image());
        let address = 0x7a_8000_0000;
        assert_set_maximum_racing_a_mapping_waits_for_it(&task, address, || {
            task.sys_mmap(
                address,
                PAGE_SIZE,
                VmProtection::READ,
                MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
                -1,
                0,
            )
        });
    }

    #[test]
    fn set_maximum_racing_a_mach_allocation_waits_for_it() {
        let task = task_with_file(&macho_image());
        let address = 0x7a_9000_0000;
        assert_set_maximum_racing_a_mapping_waits_for_it(&task, address, || {
            task.map_anonymous(
                address,
                PAGE_SIZE,
                AnonymousPlacement::Fixed { replace: false },
                VmProtection::READ,
                VmProtection::all(),
            )
            .map_err(mapping_error)
        });
    }

    #[test]
    fn set_maximum_racing_a_file_mmap_waits_for_it() {
        let task = task_with_files(&[&macho_image(), &[0x5a; PAGE_SIZE]]);
        let address = 0x7a_a000_0000;
        assert_set_maximum_racing_a_mapping_waits_for_it(&task, address, || {
            task.sys_mmap(
                address,
                PAGE_SIZE,
                VmProtection::READ,
                MmapFlags::PRIVATE,
                1,
                0,
            )
        });
    }

    /// An mprotect checks maximum protections under `macho_mappings`: one
    /// racing a MAP_FIXED over a NONE/NONE page waits for it and sees the
    /// limit the replacement dropped.
    #[test]
    fn mprotect_racing_a_map_fixed_sees_the_maximum_it_dropped() {
        let task = task_with_file(&macho_image());
        let rw = VmProtection::READ | VmProtection::WRITE;
        let address = task
            .map_anonymous(
                0,
                PAGE_SIZE,
                AnonymousPlacement::Hint,
                VmProtection::empty(),
                VmProtection::empty(),
            )
            .unwrap();
        let (excluded, mapped, protected) = race_at(
            &task,
            hook::Point::FixedSnapshot,
            || {
                task.sys_mmap(
                    address,
                    PAGE_SIZE,
                    VmProtection::empty(),
                    MmapFlags::ANONYMOUS | MmapFlags::PRIVATE | MmapFlags::FIXED,
                    -1,
                    0,
                )
            },
            |sibling| sibling.sys_mprotect(address, PAGE_SIZE, rw),
        );
        assert!(excluded);
        assert_eq!((mapped, protected), (Ok(address), Ok(())));
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    #[test]
    fn unmap_racing_a_macho_map_fixed_leaves_no_tracking() {
        assert_change_racing_a_macho_map_fixed_leaves_no_tracking(false);
    }

    #[test]
    fn replacement_racing_a_macho_map_fixed_leaves_no_tracking() {
        assert_change_racing_a_macho_map_fixed_leaves_no_tracking(true);
    }

    /// An unmap updates tracking before another mapping can take its range:
    /// a Mach-O mapping made there while the unmap runs stays tracked, so
    /// making it executable rewrites it.
    #[test]
    fn macho_mapping_racing_an_unmap_of_its_range_stays_tracked() {
        let task = task_with_file(&macho_image());
        let address = task
            .sys_mmap(
                0x7c_0000_0000,
                PAGE_SIZE,
                VmProtection::READ | VmProtection::WRITE,
                MmapFlags::ANONYMOUS | MmapFlags::PRIVATE | MmapFlags::FIXED,
                -1,
                0,
            )
            .unwrap();
        let (excluded, unmapped, mapped) = race_mapping_change(
            &task,
            || task.sys_munmap(address, PAGE_SIZE),
            |sibling| map_image_at(sibling, address, MmapFlags::PRIVATE),
        );
        assert!(excluded, "the unmap's tracking update could be overtaken");
        assert_eq!((unmapped, mapped), (Ok(()), Ok(address)));
        task.sys_mprotect(
            address,
            PAGE_SIZE,
            VmProtection::READ | VmProtection::EXECUTE,
        )
        .unwrap();
        assert!(
            decode_branch_target(instruction_at(address + TEXT), (address + TEXT) as u64).is_some()
        );
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    /// A mapping of a file that is not Mach-O replacing a tracked Mach-O
    /// mapping drops the old tracking before an `mprotect` making it
    /// executable can apply it to the new contents.
    #[test]
    fn mprotect_exec_racing_a_non_macho_map_fixed_never_applies_old_tracking() {
        let mut other = vec![0; PAGE_SIZE];
        put32(&mut other, TEXT, SVC);
        let task = task_with_files(&[&macho_image(), &other]);
        let address = map_image_at(&task, 0x7d_0000_0000, MmapFlags::PRIVATE).unwrap();
        let (excluded, mapped, protected) = race_mapping_change(
            &task,
            || {
                task.sys_mmap(
                    address,
                    PAGE_SIZE,
                    VmProtection::READ,
                    MmapFlags::PRIVATE | MmapFlags::FIXED,
                    1,
                    0,
                )
            },
            |sibling| {
                sibling.sys_mprotect(
                    address,
                    PAGE_SIZE,
                    VmProtection::READ | VmProtection::EXECUTE,
                )
            },
        );
        assert!(excluded, "the old tracking outlived the replacement");
        assert_eq!((mapped, protected), (Ok(address), Ok(())));
        assert_eq!(instruction_at(address + TEXT), SVC);
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    /// An `mprotect` holds mapping changes off from its rewrite through its
    /// permission change: a read-only Mach-O MAP_FIXED racing it between
    /// the two lands after it, so an executable transition never grants
    /// execute to bytes it did not rewrite.
    #[test]
    fn macho_map_fixed_racing_mprotect_exec_waits_for_its_permission_change() {
        let address = 0x7e_0000_0000;
        let task = task_with_file(&macho_image());
        assert_eq!(
            map_image_at(&task, address, MmapFlags::PRIVATE),
            Ok(address)
        );
        let (excluded, protected, mapped) = race_at(
            &task,
            hook::Point::Protecting,
            || {
                task.sys_mprotect(
                    address,
                    PAGE_SIZE,
                    VmProtection::READ | VmProtection::EXECUTE,
                )
            },
            |sibling| map_image_at(sibling, address, MmapFlags::PRIVATE),
        );
        assert!(
            excluded,
            "a mapping change could land before the permission change"
        );
        assert_eq!((protected, mapped), (Ok(()), Ok(address)));
        assert!(
            !crate::tests::guest_flags(&task, address).contains(VmFlags::VM_EXEC),
            "the replacement mapping is executable"
        );
        assert_eq!(instruction_at(address + TEXT), SVC);
        task.sys_mprotect(
            address,
            PAGE_SIZE,
            VmProtection::READ | VmProtection::EXECUTE,
        )
        .unwrap();
        // Rewritten: to a gate branch, or to a trap if no gate is available.
        assert_ne!(instruction_at(address + TEXT), SVC);
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    /// A MAP_FIXED that fails without changing the address space keeps the
    /// Mach-O tracking of its range, even when the range's permissions change
    /// after its snapshot: whether it replaced anything depends on what is
    /// mapped, not on permissions.
    #[test]
    fn failed_map_fixed_keeps_tracking_of_reprotected_pages() {
        let task = task_with_file(&macho_image());
        let address = map_image_at(&task, 0x7e_2000_0000, MmapFlags::PRIVATE).unwrap();
        let global = Arc::clone(&task.global);
        task.global.mapping_hook.set(move |point| {
            if point == hook::Point::FixedSnapshot {
                // SAFETY: the page stays mapped; nothing runs from it.
                unsafe {
                    global.mm.change_page_permissions(
                        <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<u8>::from_usize(address),
                        PAGE_SIZE,
                        Permissions::empty(),
                    )
                }
                .unwrap();
            }
        });
        // The second page is unmapped, so the mapping fails before it changes
        // anything.
        let mapped = task.sys_mmap(
            address,
            2 * PAGE_SIZE,
            VmProtection::READ | VmProtection::WRITE,
            MmapFlags::ANONYMOUS | MmapFlags::PRIVATE | MmapFlags::FIXED,
            -1,
            0,
        );
        task.global.mapping_hook.clear();
        assert!(mapped.is_err());
        assert!(!crate::tests::guest_flags(&task, address).contains(VmFlags::VM_READ));
        task.sys_mprotect(
            address,
            PAGE_SIZE,
            VmProtection::READ | VmProtection::EXECUTE,
        )
        .unwrap();
        assert!(
            decode_branch_target(instruction_at(address + TEXT), (address + TEXT) as u64).is_some(),
            "the Mach-O tracking was dropped"
        );
        task.sys_munmap(address, PAGE_SIZE).unwrap();
    }

    #[test]
    fn executable_mprotect_across_the_shared_cache_rewrites_task_memory() {
        let base = 0x74_0000_0000;
        let program = crate::tests::install_test_cache_for(task_with_file(&macho_image()), base);
        let task = &program.entrypoints.task;
        // Mach-O code right below the instance's rewritten code page (maximum
        // RX): an executable request over both rewrites the task memory part.
        let below = base - PAGE_SIZE;
        assert_eq!(
            task.sys_mmap(
                below,
                PAGE_SIZE,
                VmProtection::READ,
                MmapFlags::PRIVATE | MmapFlags::FIXED,
                0,
                0,
            ),
            Ok(below)
        );
        assert_eq!(instruction_at(below + TEXT), SVC);
        assert_eq!(
            task.sys_mprotect(
                below,
                2 * PAGE_SIZE,
                VmProtection::READ | VmProtection::EXECUTE
            ),
            Ok(())
        );
        assert!(crate::tests::guest_flags(task, below).contains(VmFlags::VM_EXEC));
        assert!(
            decode_branch_target(instruction_at(below + TEXT), (below + TEXT) as u64).is_some()
        );
        task.sys_munmap(below, PAGE_SIZE).unwrap();
    }

    /// An mprotect across the shared-cache instance holds `macho_mappings`
    /// from its checks through every part's change, so an unmap of one part
    /// after the checks waits and the request applies to every part.
    #[test]
    fn mprotect_across_the_shared_cache_applies_atomically() {
        use crate::shared_cache::{SharedCacheBacking, SharedCacheLayout, SharedCachePiece};
        const RW: VmProtection = VmProtection::READ.union(VmProtection::WRITE);

        let base = 0x76_0000_0000;
        let program = crate::tests::loaded_program(task_with_file(&macho_image()));
        let task = &program.entrypoints.task;
        let cache = base..base + PAGE_SIZE;
        program.reserve_shared_cache(cache.clone()).unwrap();
        let data = [0x22u8; 4];
        program
            .install_shared_cache(&SharedCacheLayout {
                range: cache.clone(),
                pieces: &[SharedCachePiece {
                    range: cache.clone(),
                    backing: SharedCacheBacking::Copy(&data),
                    protection: VmProtection::READ,
                    max_protection: RW,
                }],
                code_regions: &[],
                gate_islands: &[],
                pager: None,
            })
            .unwrap();
        let below = base - PAGE_SIZE;
        let above = cache.end;
        assert_eq!(map_image_at(task, below, MmapFlags::PRIVATE), Ok(below));
        assert_eq!(map_image_at(task, above, MmapFlags::PRIVATE), Ok(above));
        let (excluded, protected, unmapped) = race_at(
            task,
            hook::Point::SplitChecked,
            || task.sys_mprotect(below, 3 * PAGE_SIZE, RW),
            |sibling| sibling.sys_munmap(above, PAGE_SIZE),
        );
        assert!(excluded, "the unmap ran between the checks and the change");
        assert_eq!(protected, Ok(()));
        assert_eq!(unmapped, Ok(()));
        assert!(crate::tests::guest_flags(task, below).contains(VmFlags::VM_WRITE));
        assert!(crate::tests::guest_flags(task, base).contains(VmFlags::VM_WRITE));
        task.sys_munmap(below, PAGE_SIZE).unwrap();
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
