// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Common implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.

use litebox::{
    mm::vmem::{
        CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize, PAGE_SIZE, VmemUnmapError,
    },
    platform::page_mgmt::{DeallocationError, MemoryRegionPermissions},
};

use crate::{MRemapFlags, MapFlags, ProtFlags, UserPtrMut, errno::Errno};

const PAGE_MASK: usize = !(PAGE_SIZE - 1);

/// Maps `mmap`/`mprotect` protection bits onto the permissions the page manager can express.
///
/// Write and execute each imply read: the page tables litebox targets have no write-only mode
/// (Linux widens `PROT_WRITE` the same way on x86-64) and an execute-only mapping is served
/// as its readable superset. Non-access bits (`PROT_GROWSDOWN`/`PROT_GROWSUP`, AArch64
/// `PROT_BTI`/`PROT_MTE`, ...) are not access modes and are ignored here; a caller that has
/// to refuse one checks before calling. Total over every `ProtFlags` value, so no protection
/// value can reach a `todo!()`/`unimplemented!()` in a syscall handler.
fn prot_to_permissions(prot: &ProtFlags) -> MemoryRegionPermissions {
    let mut perms = MemoryRegionPermissions::empty();
    if prot.intersects(ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC) {
        perms |= MemoryRegionPermissions::READ;
    }
    if prot.contains(ProtFlags::PROT_WRITE) {
        perms |= MemoryRegionPermissions::WRITE;
    }
    if prot.contains(ProtFlags::PROT_EXEC) {
        perms |= MemoryRegionPermissions::EXEC;
    }
    perms
}

#[allow(
    clippy::too_many_arguments,
    reason = "each parameter is independently required by the platform allocation contract"
)]
pub fn do_mmap<
    Platform: litebox::platform::RawPointerProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::PageManagementProvider<{ litebox::mm::vmem::PAGE_SIZE }>,
>(
    pm: &litebox::mm::PageManager<Platform, { litebox::mm::vmem::PAGE_SIZE }>,
    suggested_addr: Option<usize>,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
    ensure_space_after: bool,
    shared_futex_backing: Option<(litebox::mm::vmem::SharedFutexBacking, usize)>,
    op: impl FnOnce(UserPtrMut<u8>) -> Result<usize, litebox::mm::vmem::MappingError>,
) -> Result<UserPtrMut<u8>, litebox::mm::vmem::MappingError> {
    let op = |p: Platform::RawMutPointer<u8>| op(UserPtrMut::from_platform_ptr::<Platform>(p));
    let flags = {
        let mut create_flags = CreatePagesFlags::empty();
        // MAP_FIXED_NOREPLACE implies MAP_FIXED behavior (exact address, not a hint)
        create_flags.set(
            CreatePagesFlags::FIXED_ADDR,
            flags.intersects(MapFlags::MAP_FIXED | MapFlags::MAP_FIXED_NOREPLACE),
        );
        create_flags.set(
            CreatePagesFlags::NOREPLACE,
            flags.contains(MapFlags::MAP_FIXED_NOREPLACE),
        );
        create_flags.set(
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            flags.contains(MapFlags::MAP_POPULATE),
        );
        create_flags.set(CreatePagesFlags::ENSURE_SPACE_AFTER, ensure_space_after);
        create_flags.set(
            CreatePagesFlags::MAP_FILE,
            !flags.contains(MapFlags::MAP_ANONYMOUS),
        );
        create_flags.set(
            CreatePagesFlags::SHARED,
            flags.contains(MapFlags::MAP_SHARED),
        );
        create_flags
    };
    let suggested_addr = match suggested_addr {
        Some(addr) => Some(NonZeroAddress::new(addr).ok_or(MappingError::UnAligned)?),
        None => None,
    };
    let length = NonZeroPageSize::new(len).ok_or(MappingError::UnAligned)?;
    // Only the access bits decide a mapping's permissions: Linux's `mmap` ignores
    // `PROT_GROWSDOWN`/`PROT_GROWSUP`, and architecture hints refine an access mode this
    // manager does not model. See [`prot_to_permissions`] for the widening; every value is
    // handled -- the previous wildcard arm panicked in debug builds and, in release builds,
    // silently mapped the range inaccessible, so `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)`
    // faulted on first touch.
    let after_perms = prot_to_permissions(&prot);
    let before_perms = if after_perms.is_empty() {
        MemoryRegionPermissions::empty()
    } else {
        // The mapping is populated (file contents, zero fill) before it takes its final mode.
        MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE
    };
    unsafe {
        pm.create_pages_with_shared_futex_backing(
            suggested_addr,
            length,
            flags,
            before_perms,
            after_perms,
            shared_futex_backing,
            op,
        )
    }
    .map(UserPtrMut::from_platform_ptr::<Platform>)
}

/// Handle syscall `munmap`
pub fn sys_munmap<
    Platform: litebox::platform::RawPointerProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::PageManagementProvider<{ litebox::mm::vmem::PAGE_SIZE }>,
>(
    pm: &litebox::mm::PageManager<Platform, { litebox::mm::vmem::PAGE_SIZE }>,
    addr: UserPtrMut<u8>,
    len: usize,
) -> Result<(), Errno> {
    if addr.as_usize() & !PAGE_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Err(Errno::EINVAL);
    }
    let aligned_len = len
        .checked_next_multiple_of(PAGE_SIZE)
        .ok_or(Errno::EINVAL)?;
    let end = addr
        .as_usize()
        .checked_add(aligned_len)
        .ok_or(Errno::EINVAL)?;
    if end > Platform::TASK_ADDR_MAX {
        return Err(Errno::EINVAL);
    }

    match unsafe { pm.remove_pages(addr.to_platform_ptr::<Platform>(), aligned_len) } {
        Err(VmemUnmapError::UnAligned) => Err(Errno::EINVAL),
        Err(VmemUnmapError::UnmapError(e)) => match e {
            // It is not an error if the indicated range does not contain any mapped pages.
            DeallocationError::AlreadyUnallocated => Ok(()),
            // `DeallocationError` is `#[non_exhaustive]`: a variant a future platform adds is
            // refused with `EINVAL`, never a panic inside a syscall handler.
            // (This crate has no logger; the shim traces the returned errno with the syscall.)
            _ => Err(Errno::EINVAL),
        },
        Ok(()) => Ok(()),
    }
}

/// Handle syscall `mprotect`
pub fn sys_mprotect<
    Platform: litebox::platform::RawPointerProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::PageManagementProvider<{ litebox::mm::vmem::PAGE_SIZE }>,
>(
    pm: &litebox::mm::PageManager<Platform, { litebox::mm::vmem::PAGE_SIZE }>,
    addr: UserPtrMut<u8>,
    len: usize,
    prot: ProtFlags,
) -> Result<(), Errno> {
    if addr.as_usize() & !PAGE_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(());
    }
    // Linux guests issue mprotect() at their own (typically 4 KiB) page
    // granularity, which can be smaller than this platform's real page size
    // (e.g. 16 KiB on macOS/HVF, matching the host's `PAGE_SIZE`). Round up
    // to a whole platform page the same way `do_mmap`/`sys_mremap` already
    // do for their lengths, so a guest-granularity request that is fully
    // contained within one platform page still resolves to a valid
    // `PageRange` instead of failing `PageRange::new`'s alignment check
    // (which previously surfaced as a spurious ENOMEM on the guest's exact
    // syscall length, e.g. a stock JIT's `mprotect(page, 4096, PROT_EXEC)`).
    let len = len
        .checked_next_multiple_of(PAGE_SIZE)
        .ok_or(Errno::EINVAL)?;

    // Linux refuses both growth directions at once; either one alone extends the change to
    // the whole `VM_GROWSDOWN`/`VM_GROWSUP` mapping, which this manager does not model, so
    // it is refused as before (`EINVAL`) instead of being applied to the wrong range.
    if prot.intersects(ProtFlags::PROT_GROWSDOWN | ProtFlags::PROT_GROWSUP) {
        return Err(Errno::EINVAL);
    }
    let addr = addr.to_platform_ptr::<Platform>();
    // Total over `ProtFlags` (see `prot_to_permissions`): no protection value panics here.
    let perms = prot_to_permissions(&prot);
    let result = if perms.is_empty() {
        unsafe { pm.make_pages_inaccessible(addr, len) }
    } else if perms == MemoryRegionPermissions::READ {
        unsafe { pm.make_pages_readable(addr, len) }
    } else if perms == (MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE) {
        unsafe { pm.make_pages_writable(addr, len) }
    } else if perms == (MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC) {
        unsafe { pm.make_pages_executable(addr, len) }
    } else {
        debug_assert_eq!(
            perms,
            MemoryRegionPermissions::READ
                | MemoryRegionPermissions::WRITE
                | MemoryRegionPermissions::EXEC
        );
        unsafe { pm.make_pages_rwx(addr, len) }
    };
    result.map_err(Errno::from)
}

/// Handle syscall `mremap`
pub fn sys_mremap<
    Platform: litebox::platform::RawPointerProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::PageManagementProvider<{ litebox::mm::vmem::PAGE_SIZE }>,
>(
    pm: &litebox::mm::PageManager<Platform, { litebox::mm::vmem::PAGE_SIZE }>,
    old_addr: UserPtrMut<u8>,
    old_size: usize,
    new_size: usize,
    flags: MRemapFlags,
    _new_addr: usize,
) -> Result<UserPtrMut<u8>, Errno> {
    if flags.intersects(
        (MRemapFlags::MREMAP_FIXED | MRemapFlags::MREMAP_MAYMOVE | MRemapFlags::MREMAP_DONTUNMAP)
            .complement(),
    ) {
        return Err(Errno::EINVAL);
    }
    if flags.contains(MRemapFlags::MREMAP_FIXED) && !flags.contains(MRemapFlags::MREMAP_MAYMOVE) {
        return Err(Errno::EINVAL);
    }
    /*
     * MREMAP_DONTUNMAP is always a move and it does not allow resizing
     * in the process.
     */
    if flags.contains(MRemapFlags::MREMAP_DONTUNMAP)
        && (!flags.contains(MRemapFlags::MREMAP_MAYMOVE) || old_size != new_size)
    {
        return Err(Errno::EINVAL);
    }
    if old_addr.as_usize() & !PAGE_MASK != 0 {
        return Err(Errno::EINVAL);
    }

    let old_size = old_size
        .checked_next_multiple_of(PAGE_SIZE)
        .ok_or(Errno::EINVAL)?;
    let new_size = new_size
        .checked_next_multiple_of(PAGE_SIZE)
        .ok_or(Errno::EINVAL)?;
    if new_size == 0 {
        return Err(Errno::EINVAL);
    }

    if flags.intersects(MRemapFlags::MREMAP_FIXED | MRemapFlags::MREMAP_DONTUNMAP) {
        // Not modelled by the page manager (a move to a caller-chosen address, or a move that
        // keeps the source mapped). Refused in every build: a syscall handler never panics.
        return Err(Errno::EINVAL);
    }

    unsafe {
        pm.remap_pages(
            old_addr.to_platform_ptr::<Platform>(),
            old_size,
            new_size,
            flags.contains(MRemapFlags::MREMAP_MAYMOVE),
        )
    }
    .map(UserPtrMut::from_platform_ptr::<Platform>)
    .map_err(Errno::from)
}

pub fn sys_brk<
    Platform: litebox::platform::RawPointerProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::PageManagementProvider<{ litebox::mm::vmem::PAGE_SIZE }>,
>(
    pm: &litebox::mm::PageManager<Platform, { litebox::mm::vmem::PAGE_SIZE }>,
    addr: UserPtrMut<u8>,
) -> Result<usize, Errno> {
    unsafe { pm.brk(addr.as_usize()) }.map_err(Errno::from)
}

/// How [`sys_madvise`] treats one advice value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MadviseSupport {
    /// The advice changes the mapping and is implemented.
    Implemented,
    /// A pure hint (page-reference pattern, THP/KSM/coredump preferences): Linux records it
    /// and returns 0 without any effect a program can observe through memory, so accepting it
    /// as a no-op is the same contract. No memory is touched.
    AdvisoryNoop,
    /// Advice with a real effect this manager cannot provide; refused with `EINVAL` rather
    /// than faked.
    Unsupported,
}

/// Classifies `advice` for [`sys_madvise`]; the shim uses it to log what it declines.
pub fn madvise_support(advice: &crate::MadviseBehavior) -> MadviseSupport {
    use crate::MadviseBehavior as M;
    match advice {
        M::Normal
        | M::DontNeed
        | M::DontNeedLocked
        | M::Free
        | M::DontFork
        | M::DoFork
        | M::WipeOnFork
        | M::KeepOnFork => MadviseSupport::Implemented,
        // Reclaim (`COLD`/`PAGEOUT`) and prefault (`POPULATE_*`) advice only move pages
        // between resident and not; contents are unchanged either way, and pages fault in
        // lazily here regardless.
        M::Random
        | M::Sequential
        | M::WillNeed
        | M::Mergeable
        | M::Unmergeable
        | M::HugePage
        | M::NoHugePage
        | M::DontDump
        | M::DoDump
        | M::Cold
        | M::Pageout
        | M::PopulateRead
        | M::PopulateWrite => MadviseSupport::AdvisoryNoop,
        // `MADV_REMOVE` is `EINVAL` on private anonymous memory in Linux too (it is a
        // shmem/tmpfs hole-punch); poisoning/offlining are privileged testing hooks.
        M::Remove | M::HWPoison | M::SoftOffline => MadviseSupport::Unsupported,
    }
}

/// Handle syscall `madvise`.
///
/// Never panics on an advice value: the decoder only admits [`crate::MadviseBehavior`]
/// variants, and every variant is classified by [`madvise_support`] -- a `match` with no
/// wildcard arm, so a variant added to the enum has to be placed here before it compiles.
pub fn sys_madvise<
    Platform: litebox::platform::RawPointerProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::PageManagementProvider<{ litebox::mm::vmem::PAGE_SIZE }>,
>(
    pm: &litebox::mm::PageManager<Platform, { litebox::mm::vmem::PAGE_SIZE }>,
    addr: UserPtrMut<u8>,
    len: usize,
    advice: crate::MadviseBehavior,
) -> Result<(), Errno> {
    if addr.as_usize() & !PAGE_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(());
    }
    let aligned_len = len.next_multiple_of(PAGE_SIZE);
    if aligned_len == 0 {
        // overflow
        return Err(Errno::EINVAL);
    }
    let Some(_end) = addr.as_usize().checked_add(aligned_len) else {
        return Err(Errno::EINVAL);
    };

    let addr = addr.to_platform_ptr::<Platform>();
    match advice {
        crate::MadviseBehavior::Normal
        | crate::MadviseBehavior::DontFork
        | crate::MadviseBehavior::DoFork => {
            // No-op for now, as we don't support fork yet.
            Ok(())
        }
        // No `mlock` here, so `MADV_DONTNEED_LOCKED` is plain `MADV_DONTNEED`.
        crate::MadviseBehavior::DontNeed | crate::MadviseBehavior::DontNeedLocked => {
            // After a successful MADV_DONTNEED operation, the semantics of memory access in the specified region are changed:
            // subsequent accesses of pages in the range will succeed, but will result in either repopulating the memory contents
            // from the up-to-date contents of the underlying mapped file (for shared file mappings, shared anonymous mappings,
            // and shmem-based techniques such as System V shared memory segments) or zero-fill-on-demand pages for anonymous private mappings.
            //
            // Note we do not support shared memory yet, so this is just to discard the pages without removing the mapping.
            unsafe { pm.reset_pages(addr, aligned_len, false) }.map_err(Errno::from)
        }
        crate::MadviseBehavior::Free => {
            unsafe { pm.reset_pages(addr, aligned_len, true) }.map_err(Errno::from)
        }
        crate::MadviseBehavior::WipeOnFork | crate::MadviseBehavior::KeepOnFork => {
            // Records `VM_WIPEONFORK` on the mappings; the zeroing itself happens in the
            // child at fork (`PageManager::wipe_on_fork_child`). Same error contract as
            // Linux's `madvise_vma_behavior`: `EINVAL` for file-backed/shared, `ENOMEM` for
            // a hole in the range.
            let enable = matches!(advice, crate::MadviseBehavior::WipeOnFork);
            pm.set_wipe_on_fork(addr, aligned_len, enable)
                .map_err(|error| match error {
                    litebox::mm::vmem::VmemWipeOnForkError::UnAligned
                    | litebox::mm::vmem::VmemWipeOnForkError::NotPrivateAnonymous(_) => {
                        Errno::EINVAL
                    }
                    litebox::mm::vmem::VmemWipeOnForkError::Unmapped(_) => Errno::ENOMEM,
                })
        }
        crate::MadviseBehavior::Random
        | crate::MadviseBehavior::Sequential
        | crate::MadviseBehavior::WillNeed
        | crate::MadviseBehavior::Mergeable
        | crate::MadviseBehavior::Unmergeable
        | crate::MadviseBehavior::HugePage
        | crate::MadviseBehavior::NoHugePage
        | crate::MadviseBehavior::DontDump
        | crate::MadviseBehavior::DoDump
        | crate::MadviseBehavior::Cold
        | crate::MadviseBehavior::Pageout
        | crate::MadviseBehavior::PopulateRead
        | crate::MadviseBehavior::PopulateWrite => {
            debug_assert_eq!(madvise_support(&advice), MadviseSupport::AdvisoryNoop);
            Ok(())
        }
        crate::MadviseBehavior::Remove
        | crate::MadviseBehavior::HWPoison
        | crate::MadviseBehavior::SoftOffline => {
            debug_assert_eq!(madvise_support(&advice), MadviseSupport::Unsupported);
            Err(Errno::EINVAL)
        }
    }
}
