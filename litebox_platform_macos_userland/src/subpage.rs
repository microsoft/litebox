// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Page ownership on 16 KiB macOS backing.
//!
//! Native instances track one slot per host page. With `subpage_compat`, 4 KiB
//! instances fuse permissions across live subpages: RO/PROT_NONE subpages and
//! unmapped holes can inherit neighboring access. Only these instances publish
//! recovery state for switching mixed W/X pages between RW and RX.

use litebox::utils::TruncateExt as _;
use std::collections::HashMap;
use std::ops::Range;

use super::{
    AllocationError, DeallocationError, FixedAddressBehavior, HOST_PAGE_SIZE, KernReturn,
    MachVmFlags, MemoryRegionPermissions as Perm, PermissionUpdateError, TASK_ADDR_MAX,
    TASK_ADDR_MIN, mach_task_self, mach_vm_allocate, prot_flags, sys_icache_invalidate,
};

// Fixed-capacity storage for the smallest supported granularity.
const MAX_SUBPAGES: usize = HOST_PAGE_SIZE / 4096;
type Slots = [Option<Perm>; MAX_SUBPAGES];

#[derive(Default)]
pub(super) struct Pages<const PAGE_SIZE: usize>(HashMap<usize, Slots>);

fn host_base(address: usize) -> usize {
    address & !(HOST_PAGE_SIZE - 1)
}

fn host_range(range: &Range<usize>) -> Range<usize> {
    host_base(range.start)
        ..range
            .end
            .checked_next_multiple_of(HOST_PAGE_SIZE)
            .unwrap_or(usize::MAX)
}

fn fused(slots: Slots) -> Perm {
    let mut permissions = slots.iter().flatten().fold(Perm::empty(), |p, s| p | *s);
    // Cache maintenance requires executable pages to be readable.
    if permissions.contains(Perm::EXEC) {
        permissions |= Perm::READ;
    }
    permissions
}

fn change_slots<const PAGE_SIZE: usize>(
    slots: &mut Slots,
    base: usize,
    range: &Range<usize>,
    value: Option<Perm>,
) {
    for address in
        (base.max(range.start)..(base + HOST_PAGE_SIZE).min(range.end)).step_by(PAGE_SIZE)
    {
        slots[(address - base) / PAGE_SIZE] = value;
    }
}

fn permission_error() -> PermissionUpdateError {
    // SAFETY: __error returns this thread's errno slot.
    match unsafe { *libc::__error() } {
        libc::EACCES | libc::EPERM => PermissionUpdateError::PermissionDenied,
        libc::ENOMEM => PermissionUpdateError::OutOfMemory,
        _ => PermissionUpdateError::PlatformFailure,
    }
}

fn allocation_error(error: PermissionUpdateError) -> AllocationError {
    match error {
        PermissionUpdateError::PermissionDenied => AllocationError::PermissionDenied,
        _ => AllocationError::OutOfMemory,
    }
}

/// Owned native mapping.
struct Mapping {
    base: usize,
    len: usize,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this object exclusively owns the entire native mapping.
        assert_eq!(unsafe { libc::munmap(self.base as *mut _, self.len) }, 0);
    }
}

unsafe extern "C" {
    fn mach_vm_remap(
        task: u32,
        target: *mut u64,
        size: u64,
        mask: u64,
        flags: MachVmFlags,
        source_task: u32,
        source: u64,
        copy: i32,
        current_protection: *mut i32,
        max_protection: *mut i32,
        inheritance: u32,
    ) -> KernReturn;
}

impl Mapping {
    /// Writable alias for zeroing without revoking a neighbor's execute access.
    fn write_alias(base: usize) -> Result<Self, AllocationError> {
        let mut target = 0;
        let mut current = 0;
        let mut maximum = 0;
        // SAFETY: the registry owns the source; all outputs are valid. copy=false
        // shares the backing storage, and ANYWHERE cannot overwrite host memory.
        let result = unsafe {
            mach_vm_remap(
                mach_task_self(),
                &raw mut target,
                HOST_PAGE_SIZE as u64,
                0,
                MachVmFlags::ANYWHERE,
                mach_task_self(),
                base as u64,
                0,
                &raw mut current,
                &raw mut maximum,
                2, // VM_INHERIT_NONE
            )
        };
        if result != KernReturn::SUCCESS {
            return Err(result.into());
        }
        let alias = Self {
            base: target.trunc(),
            len: HOST_PAGE_SIZE,
        };
        protect(alias.base, Perm::READ | Perm::WRITE).map_err(allocation_error)?;
        Ok(alias)
    }
}

#[cfg(feature = "subpage_compat")]
pub(super) fn recover_fault(pc: usize, fault_address: usize, esr: u64) -> bool {
    recovery::recover(pc, fault_address, esr) != recovery::Recovery::Unhandled
}

fn protect(base: usize, permissions: Perm) -> Result<(), PermissionUpdateError> {
    // Start mixed pages RW; recovery selects RX on instruction faults.
    let native = if permissions.contains(Perm::WRITE | Perm::EXEC) {
        (permissions | Perm::READ) & !Perm::EXEC
    } else {
        permissions
    };
    // SAFETY: callers hold the registry lock and own this entire native page.
    if unsafe { libc::mprotect(base as *mut _, HOST_PAGE_SIZE, prot_flags(native)) } != 0 {
        return Err(permission_error());
    }
    Ok(())
}

fn flush(base: usize, permissions: Perm) {
    if permissions.contains(Perm::EXEC) {
        // SAFETY: fused executable permissions always include READ.
        unsafe { sys_icache_invalidate(base as *mut _, HOST_PAGE_SIZE) };
    }
}

impl<const PAGE_SIZE: usize> Pages<PAGE_SIZE> {
    pub(super) fn contains_range(&self, range: Range<usize>) -> bool {
        range.step_by(PAGE_SIZE).all(|address| {
            self.0
                .get(&host_base(address))
                .is_some_and(|slots| slots[(address % HOST_PAGE_SIZE) / PAGE_SIZE].is_some())
        })
    }

    /// Apply protections with rollback on failure; hold the returned gate through commit.
    fn protect_changes(
        &self,
        changes: &[(usize, Slots)],
    ) -> Result<recovery::Update, PermissionUpdateError> {
        let update = recovery::begin_update();
        for (index, (base, slots)) in changes.iter().enumerate() {
            if let Err(error) = protect(*base, fused(*slots)) {
                for (base, _) in &changes[..index] {
                    let previous = self
                        .0
                        .get(base)
                        .copied()
                        .map_or(Perm::READ | Perm::WRITE, fused);
                    protect(*base, previous).expect("failed to roll back native page protection");
                }
                return Err(error);
            }
        }
        Ok(update)
    }

    pub(super) fn allocate(
        &mut self,
        range: Range<usize>,
        permissions: Perm,
        behavior: FixedAddressBehavior,
    ) -> Result<usize, AllocationError> {
        if permissions.contains(Perm::WRITE | Perm::EXEC) {
            return Err(AllocationError::PermissionDenied);
        }
        // Reject unsupported flags before allocating.
        let _ = prot_flags(permissions);
        if behavior == FixedAddressBehavior::Hint {
            let len = range.len().next_multiple_of(HOST_PAGE_SIZE);
            let mut error = AllocationError::OutOfMemory;
            for hint in [host_base(range.start), 0] {
                // SAFETY: no MAP_FIXED; the kernel chooses unused native pages.
                let mapped = unsafe {
                    libc::mmap(
                        hint as *mut _,
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANON,
                        -1,
                        0,
                    )
                };
                if mapped == libc::MAP_FAILED {
                    error = allocation_error(permission_error());
                    continue;
                }
                let mapping = Mapping {
                    base: mapped as usize,
                    len,
                };
                let base = mapping.base;
                if base < TASK_ADDR_MIN
                    || base.checked_add(len).is_none_or(|end| end > TASK_ADDR_MAX)
                {
                    continue;
                }
                let range = base..base + range.len();
                let changes: Vec<_> = (base..base + len)
                    .step_by(HOST_PAGE_SIZE)
                    .map(|address| {
                        let mut slots = [None; MAX_SUBPAGES];
                        change_slots::<PAGE_SIZE>(&mut slots, address, &range, Some(permissions));
                        (address, slots)
                    })
                    .collect();
                let mut update = self.protect_changes(&changes).map_err(allocation_error)?;
                for (base, slots) in changes {
                    flush(base, fused(slots));
                    update.set::<PAGE_SIZE>(base, Some(fused(slots)));
                    self.0.insert(base, slots);
                }
                std::mem::forget(mapping); // Ownership transferred to the registry.
                return Ok(base);
            }
            return Err(error);
        }

        let mut changes = Vec::new();
        for base in host_range(&range).step_by(HOST_PAGE_SIZE) {
            let mut slots = self.0.get(&base).copied().unwrap_or([None; MAX_SUBPAGES]);
            if behavior != FixedAddressBehavior::Replace {
                for address in (base.max(range.start)..(base + HOST_PAGE_SIZE).min(range.end))
                    .step_by(PAGE_SIZE)
                {
                    if slots[(address - base) / PAGE_SIZE].is_some() {
                        return Err(AllocationError::AddressInUse);
                    }
                }
            }
            change_slots::<PAGE_SIZE>(&mut slots, base, &range, Some(permissions));
            changes.push((base, slots));
        }
        let mut reservations = Vec::new();
        let mut aliases = Vec::new();
        for (base, _) in &changes {
            if self.0.contains_key(base) {
                aliases.push((*base, Mapping::write_alias(*base)?));
            } else {
                let mut address = *base as u64;
                // SAFETY: the native-aligned FIXED reservation cannot overwrite host memory.
                let result = unsafe {
                    mach_vm_allocate(
                        mach_task_self(),
                        &raw mut address,
                        HOST_PAGE_SIZE as u64,
                        MachVmFlags::FIXED,
                    )
                };
                if result != KernReturn::SUCCESS {
                    return Err(result.into());
                }
                reservations.push(Mapping {
                    base: *base,
                    len: HOST_PAGE_SIZE,
                });
            }
        }
        let mut update = self.protect_changes(&changes).map_err(allocation_error)?;
        for (base, alias) in &aliases {
            let start = range.start.max(*base);
            let end = range.end.min(base + HOST_PAGE_SIZE);
            // SAFETY: the temporary alias is writable, shares this owned guest page,
            // and only the subpages being replaced/allocated are touched.
            unsafe {
                std::ptr::write_bytes((alias.base + start - base) as *mut u8, 0, end - start);
            };
        }
        for (base, slots) in changes {
            flush(base, fused(slots));
            update.set::<PAGE_SIZE>(base, Some(fused(slots)));
            self.0.insert(base, slots);
        }
        for reservation in reservations {
            std::mem::forget(reservation);
        }
        Ok(range.start)
    }

    pub(super) fn update_permissions(
        &mut self,
        range: Range<usize>,
        permissions: Perm,
    ) -> Result<(), PermissionUpdateError> {
        if permissions.contains(Perm::WRITE | Perm::EXEC) {
            return Err(PermissionUpdateError::PermissionDenied);
        }
        let _ = prot_flags(permissions);
        if !self.contains_range(range.clone()) {
            return Err(PermissionUpdateError::Unallocated);
        }
        let mut changes = Vec::new();
        for base in host_range(&range).step_by(HOST_PAGE_SIZE) {
            let mut slots = self.0[&base];
            change_slots::<PAGE_SIZE>(&mut slots, base, &range, Some(permissions));
            changes.push((base, slots));
        }
        let mut update = self.protect_changes(&changes)?;
        for (base, slots) in changes {
            flush(base, fused(slots));
            update.set::<PAGE_SIZE>(base, Some(fused(slots)));
            self.0.insert(base, slots);
        }
        Ok(())
    }

    pub(super) fn deallocate(&mut self, range: Range<usize>) -> Result<(), DeallocationError> {
        // Bound sparse-unmap work by the smaller of the span and table capacity.
        let native = host_range(&range);
        let mut changes: Vec<_> = if native.len().div_ceil(HOST_PAGE_SIZE) <= self.0.capacity() {
            native
                .step_by(HOST_PAGE_SIZE)
                .filter_map(|base| self.0.get(&base).map(|&slots| (base, slots)))
                .collect()
        } else {
            self.0
                .iter()
                .filter(|(base, _)| native.contains(*base))
                .map(|(&base, &slots)| (base, slots))
                .collect()
        };
        for (base, slots) in &mut changes {
            change_slots::<PAGE_SIZE>(slots, *base, &range, None);
        }
        let mut update = self
            .protect_changes(&changes)
            .map_err(|_| DeallocationError::AlreadyUnallocated)?;
        for (base, slots) in changes {
            if slots.iter().all(Option::is_none) {
                drop(Mapping {
                    base,
                    len: HOST_PAGE_SIZE,
                });
                self.0.remove(&base);
                update.set::<PAGE_SIZE>(base, None);
            } else {
                self.0.insert(base, slots);
                update.set::<PAGE_SIZE>(base, Some(fused(slots)));
            }
        }
        Ok(())
    }
}

mod recovery {
    //! Serializes recovery with native mapping changes to prevent address-reuse races.
    //!
    //! Track current permissions for every owned host page so late faults can be
    //! retried after a conflict resolves without restoring revoked access.

    use std::cell::UnsafeCell;
    use std::collections::HashMap;
    use std::hash::{BuildHasherDefault, DefaultHasher};
    use std::marker::PhantomData;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[cfg(feature = "subpage_compat")]
    use super::host_base;
    use super::{HOST_PAGE_SIZE, Perm};
    #[cfg(feature = "subpage_compat")]
    use crate::{Exception, exception_class};
    use crate::{read_tls, tls_offset, write_tls};

    struct Registry {
        busy: AtomicBool,
        writers: AtomicUsize,
        pages: UnsafeCell<HashMap<usize, Perm, BuildHasherDefault<DefaultHasher>>>,
    }

    // SAFETY: busy grants exclusive access to pages with acquire/release ordering.
    unsafe impl Sync for Registry {}

    static REGISTRY: Registry = Registry {
        busy: AtomicBool::new(false),
        writers: AtomicUsize::new(0),
        // Const-initializable hasher with no randomness or TLS access during recovery.
        pages: UnsafeCell::new(HashMap::with_hasher(BuildHasherDefault::new())),
    };

    struct Guard {
        registry: &'static Registry,
        writer: bool,
        // Tied to this thread's PAGE_RECOVERY_LOCK slot.
        _not_send: PhantomData<*mut ()>,
    }

    #[cfg(feature = "subpage_compat")]
    impl Guard {
        fn permissions(&self, base: usize) -> Option<Perm> {
            // SAFETY: the guard owns exclusive access to REGISTRY.pages.
            unsafe { &*self.registry.pages.get() }.get(&base).copied()
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            self.registry.busy.store(false, Ordering::Release);
            if self.writer {
                self.registry.writers.fetch_sub(1, Ordering::Release);
            }
            write_tls(tls_offset::PAGE_RECOVERY_LOCK, 0);
        }
    }

    /// While held, do not run guest code, access fallible guest pointers, or invoke
    /// callbacks. Writable aliases and readable cache flushes are OK.
    pub(super) struct Update {
        guard: Guard,
    }

    pub(super) fn begin_update() -> Update {
        assert_eq!(
            read_tls(tls_offset::PAGE_RECOVERY_LOCK),
            0,
            "recursive native page update"
        );
        write_tls(tls_offset::PAGE_RECOVERY_LOCK, 1);
        // Give updates priority so repeated faults cannot starve them.
        REGISTRY.writers.fetch_add(1, Ordering::AcqRel);
        while REGISTRY
            .busy
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::thread::yield_now();
        }
        Update {
            guard: Guard {
                registry: &REGISTRY,
                writer: true,
                _not_send: PhantomData,
            },
        }
    }

    impl Update {
        pub(super) fn set<const PAGE_SIZE: usize>(
            &mut self,
            base: usize,
            permissions: Option<Perm>,
        ) {
            // Native mappings must never participate in compatibility fault recovery.
            if PAGE_SIZE == HOST_PAGE_SIZE {
                return;
            }
            // SAFETY: Update owns the exclusive gate; only ordinary threads call set.
            let pages = unsafe { &mut *self.guard.registry.pages.get() };
            if let Some(permissions) = permissions {
                pages.insert(base, permissions);
            } else {
                pages.remove(&base);
            }
        }

        #[cfg(all(test, feature = "subpage_compat"))]
        pub(super) fn permissions(&self, base: usize) -> Option<Perm> {
            self.guard.permissions(base)
        }
    }

    #[cfg(feature = "subpage_compat")]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Recovery {
        Unhandled,
        /// Retry after another thread finishes its update/recovery.
        Deferred,
        Recovered,
    }

    /// For synchronous SIGSEGV/SIGBUS only. Never allocates or blocks.
    /// Defer when the gate is busy; never retry our own interrupted update.
    #[cfg(feature = "subpage_compat")]
    pub(super) fn recover(pc: usize, fault_address: usize, esr: u64) -> Recovery {
        #[derive(PartialEq, Eq)]
        enum Access {
            Execute,
            Write,
        }
        const FSC_MASK: u64 = 0x3f;
        const FSC_PERMISSION_LEVEL_0: u64 = 0x0c;
        const FSC_PERMISSION_LEVEL_3: u64 = 0x0f;
        const ISS_WRITE_NOT_READ: u64 = 1 << 6;

        if !(FSC_PERMISSION_LEVEL_0..=FSC_PERMISSION_LEVEL_3).contains(&(esr & FSC_MASK)) {
            return Recovery::Unhandled;
        }
        let access = match Exception(exception_class(esr)) {
            Exception::INSTRUCTION_ABORT_LOWER_EL | Exception::INSTRUCTION_ABORT_CURRENT_EL => {
                Access::Execute
            }
            Exception::DATA_ABORT_LOWER_EL | Exception::DATA_ABORT_CURRENT_EL
                if esr & ISS_WRITE_NOT_READ != 0 =>
            {
                Access::Write
            }
            _ => return Recovery::Unhandled,
        };
        let base = host_base(if access == Access::Execute {
            pc
        } else {
            fault_address
        });
        // RW would prevent refetching this store, causing an endless RW/RX loop.
        if access == Access::Write && host_base(pc) == base {
            return Recovery::Unhandled;
        }
        // Preallocated TSD avoids lazy TLS initialization in the signal handler.
        if read_tls(tls_offset::PAGE_RECOVERY_LOCK) != 0 {
            return Recovery::Unhandled;
        }
        if REGISTRY.writers.load(Ordering::Acquire) != 0
            || REGISTRY
                .busy
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return Recovery::Deferred;
        }
        write_tls(tls_offset::PAGE_RECOVERY_LOCK, 1);
        let guard = Guard {
            registry: &REGISTRY,
            writer: false,
            _not_send: PhantomData,
        };
        let Some(permissions) = guard.permissions(base) else {
            return Recovery::Unhandled;
        };
        let required = if access == Access::Execute {
            Perm::EXEC
        } else {
            Perm::WRITE
        };
        if !permissions.contains(required) {
            return Recovery::Unhandled;
        }
        let protection = if permissions.contains(Perm::WRITE | Perm::EXEC) {
            if access == Access::Execute {
                libc::PROT_READ | libc::PROT_EXEC
            } else {
                libc::PROT_READ | libc::PROT_WRITE
            }
        } else {
            super::prot_flags(permissions)
        };
        // SAFETY: __error returns this thread's errno slot; preserve it across recovery.
        let errno = unsafe { libc::__error() };
        let saved_errno = unsafe { *errno };
        if access == Access::Execute {
            // SAFETY: EXEC implies READ, and the gate pins the mapping and its protection.
            unsafe { super::sys_icache_invalidate(base as *mut _, HOST_PAGE_SIZE) };
        }
        // SAFETY: the gate pins this owned page. Darwin mprotect is signal-safe.
        let result = unsafe { libc::mprotect(base as *mut _, HOST_PAGE_SIZE, protection) };
        // SAFETY: errno remains this thread's live errno slot.
        unsafe { *errno = saved_errno };
        if result == 0 {
            Recovery::Recovered
        } else {
            Recovery::Unhandled
        }
    }
}

#[cfg(all(test, feature = "subpage_compat"))]
mod tests {
    #![expect(
        clippy::cast_possible_wrap,
        reason = "test offsets are bounded by two native pages"
    )]

    use super::*;

    use crate::{MacosUserland4K as MacosUserland, UserMutPtr, run_thread};
    use litebox::mm::linux::PAGE_SIZE;
    use litebox::platform::{
        PageManagementProvider as _, RawConstPointer as _, RawMutPointer as _,
    };
    use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
    use litebox_common_linux::PtRegs;
    use litebox_common_linux::loader::{ElfParsedFile, MapMemory, Protection, ReadAt};

    const R: Perm = Perm::READ;
    const RW: Perm = Perm::READ.union(Perm::WRITE);
    const RX: Perm = Perm::READ.union(Perm::EXEC);

    fn write_code(address: usize, code: &[u32]) {
        let bytes: Vec<_> = code.iter().flat_map(|word| word.to_le_bytes()).collect();
        assert_eq!(ptr(address).write_slice_at_offset(0, &bytes), Some(()));
    }

    struct Image(Vec<u8>);
    impl ReadAt for Image {
        type Error = ();

        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ()> {
            let start = usize::try_from(offset).map_err(|_| ())?;
            let end = start.checked_add(buf.len()).ok_or(())?;
            buf.copy_from_slice(self.0.get(start..end).ok_or(())?);
            Ok(())
        }

        fn size(&mut self) -> Result<u64, ()> {
            Ok(self.0.len() as u64)
        }
    }

    struct ImageMapper<'a> {
        image: &'a Image,
        pages: TestPages,
    }

    impl MapMemory for ImageMapper<'_> {
        type Error = ();

        fn reserve(&mut self, len: usize, align: usize) -> Result<usize, ()> {
            // These fixtures require only guest-page alignment; native allocation is stronger.
            assert_eq!(align, PAGE_SIZE);
            let base = self.pages.allocate(len, Perm::empty());
            assert_eq!(base % align, 0);
            Ok(base)
        }

        fn map_file(
            &mut self,
            address: usize,
            len: usize,
            offset: u64,
            prot: &Protection,
        ) -> Result<(), ()> {
            let offset = usize::try_from(offset).unwrap();
            assert_eq!(offset % PAGE_SIZE, 0);
            self.pages
                .0
                .allocate(address..address + len, RW, FixedAddressBehavior::Replace)
                .unwrap();
            let data = &self.image.0[offset..self.image.0.len().min(offset + len)];
            assert_eq!(ptr(address).write_slice_at_offset(0, data), Some(()));
            self.protect(address, len, prot)
        }

        fn map_zero(&mut self, address: usize, len: usize, prot: &Protection) -> Result<(), ()> {
            self.pages
                .0
                .allocate(address..address + len, RW, FixedAddressBehavior::Replace)
                .unwrap();
            self.protect(address, len, prot)
        }

        fn protect(&mut self, address: usize, len: usize, prot: &Protection) -> Result<(), ()> {
            let mut permissions = Perm::empty();
            permissions.set(Perm::READ, prot.read);
            permissions.set(Perm::WRITE, prot.write);
            permissions.set(Perm::EXEC, prot.execute);
            self.pages
                .0
                .update_permissions(address..address + len, permissions)
                .unwrap();
            Ok(())
        }
    }

    #[test]
    fn accepts_4k_loads_sharing_a_native_page() {
        // RO headers at VA 0 and RX text at VA 0x2000. The text's file offset
        // (0x1000) is congruent at 4 KiB but deliberately not at 16 KiB.
        let mut image = Image(vec![0; 2 * PAGE_SIZE]);
        let bytes = &mut image.0;
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        bytes[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x2000u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
        for (index, (flags, offset, vaddr, size)) in
            [(4u32, 0u64, 0u64, 0x1000u64), (5, 0x1000, 0x2000, 8)]
                .into_iter()
                .enumerate()
        {
            let ph = &mut bytes[64 + index * 56..120 + index * 56];
            ph[..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
            ph[4..8].copy_from_slice(&flags.to_le_bytes());
            for (i, value) in [offset, vaddr, 0, size, size, 0x1000]
                .into_iter()
                .enumerate()
            {
                ph[8 + i * 8..16 + i * 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        bytes[PAGE_SIZE..PAGE_SIZE + 4].copy_from_slice(&0xd2800540u32.to_le_bytes()); // mov x0, #42
        bytes[PAGE_SIZE + 4..PAGE_SIZE + 8].copy_from_slice(&0xd65f03c0u32.to_le_bytes()); // ret
        let elf = ElfParsedFile::parse(&mut image).unwrap();
        let mut mapper = ImageMapper {
            image: &image,
            pages: TestPages::new(),
        };
        let info = elf
            .load(&mut mapper, &mut MacosUserland::new(), None)
            .unwrap();
        assert_eq!(info.entry_point, info.base_addr + 2 * PAGE_SIZE);
        assert_eq!(info.phdrs_addr, info.base_addr + 64);
        assert_eq!(info.num_phdrs, 2);
        assert_eq!(info.brk, info.base_addr + HOST_PAGE_SIZE);
        assert_eq!(
            &*ptr(info.base_addr).to_owned_slice(PAGE_SIZE).unwrap(),
            &image.0[..PAGE_SIZE]
        );
        assert_eq!(ptr(info.base_addr).write_at_offset(0, 0), None);
        assert_eq!(execute(info.entry_point), 42);
    }

    #[test]
    fn executes_and_writes_mixed_subpages_from_another_native_page() {
        let mut pages = TestPages::new();
        let base = pages.allocate(2 * HOST_PAGE_SIZE, RW);
        let helper = base + HOST_PAGE_SIZE;
        let data = helper + PAGE_SIZE;
        // Only caller-saved registers are modified. x1=data, x2=helper.
        write_code(
            base,
            &[
                0xaa1e03e9, // mov x9, x30
                0xd63f0040, // blr x2 -- helper's native page becomes RX
                0xb9000020, // str w0, [x1] -- helper's native page becomes RW
                0xd63f0040, // blr x2 -- back to RX
                0x11000400, // add w0, w0, #1
                0xb9000020, // str w0, [x1] -- back to RW
                0xaa0903fe, // mov x30, x9
                0xd65f03c0, // ret
            ],
        );
        write_code(helper, &[0xd2800540, 0xd65f03c0]); // mov x0, #42; ret
        pages
            .0
            .update_permissions(base..base + HOST_PAGE_SIZE, RX)
            .unwrap();
        pages
            .0
            .update_permissions(helper..helper + PAGE_SIZE, RX)
            .unwrap();
        let result: usize;
        // SAFETY: both code stubs obey the C ABI and all code/data mappings remain live.
        unsafe {
            core::arch::asm!("blr {entry}", entry = in(reg) base,
                in("x1") data, in("x2") helper, lateout("x0") result, clobber_abi("C"));
        }
        assert_eq!(result, 43);
        assert_eq!(
            UserMutPtr::<u32>::from_usize(data).read_at_offset(0),
            Some(43)
        );
    }

    #[test]
    fn same_native_page_store_faults_instead_of_looping() {
        const CHILD_ENV: &str = "LITEBOX_SUBPAGE_SAME_PAGE_STORE_TEST";
        const COMPLETED: &str = "same-page store fault verified";
        struct FaultProbe<'a> {
            entry: usize,
            data: usize,
            stack: usize,
            fault: &'a std::cell::Cell<Option<(usize, ExceptionInfo)>>,
        }
        impl EnterShim for FaultProbe<'_> {
            type ExecutionContext = PtRegs;

            fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
                ctx.pc = self.entry;
                ctx.sp = self.stack;
                ctx.regs[0] = 42;
                ctx.regs[1] = self.data;
                ContinueOperation::Resume
            }
            fn syscall(&self, _: &mut PtRegs) -> ContinueOperation {
                panic!("unexpected syscall");
            }
            fn exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
                self.fault.set(Some((ctx.pc, *info)));
                ContinueOperation::Terminate
            }
            fn interrupt(&self, _: &mut PtRegs) -> ContinueOperation {
                ContinueOperation::Resume
            }
        }
        if std::env::var_os(CHILD_ENV).is_none() {
            // Isolate a fatal fault and bound an accidental RX/RW retry loop.
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "subpage::tests::same_native_page_store_faults_instead_of_looping",
                    "--nocapture",
                ])
                .env(CHILD_ENV, "1")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while child.try_wait().unwrap().is_none() {
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    let output = child.wait_with_output().unwrap();
                    panic!("same-page store did not terminate: {output:?}");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success(), "{output:?}");
            // Also reject a stale --exact filter that silently runs zero child tests.
            assert!(
                String::from_utf8_lossy(&output.stdout).contains(COMPLETED),
                "{output:?}"
            );
            return;
        }
        let mut pages = TestPages::new();
        let base = pages.allocate(2 * HOST_PAGE_SIZE, RW);
        // If the store incorrectly succeeds, the BRK reports a distinguishable exception.
        write_code(base, &[0xb9000020, 0xd4200000]); // str w0, [x1]; brk #0
        pages
            .0
            .update_permissions(base..base + PAGE_SIZE, RX)
            .unwrap();
        let fault = std::cell::Cell::new(None);
        crate::set_guest_abi(crate::GuestAbi::Linux);
        // SAFETY: the probe supplies live code/data and a separate writable guest stack.
        unsafe {
            run_thread(
                FaultProbe {
                    entry: base,
                    data: base + PAGE_SIZE,
                    stack: base + 2 * HOST_PAGE_SIZE,
                    fault: &fault,
                },
                &mut PtRegs::default(),
            );
        }
        let (pc, info) = fault
            .get()
            .expect("store must reach the shim's exception handler");
        assert_eq!(pc, base);
        assert_eq!(info.fault_address, base + PAGE_SIZE);
        assert_eq!(info.esr >> 26, 0x24); // Data abort from a lower exception level.
        assert_ne!(info.esr & (1 << 6), 0); // Write, not instruction fetch.
        assert_eq!(
            UserMutPtr::<u32>::from_usize(base + PAGE_SIZE).read_at_offset(0),
            Some(0),
            "the rejected store must not execute"
        );
        println!("{COMPLETED}");
    }

    struct TestPages(Pages<PAGE_SIZE>);
    impl TestPages {
        fn new() -> Self {
            MacosUserland::new(); // Install exception-table recovery for fault-safe probes.
            Self(Pages::default())
        }

        fn allocate(&mut self, len: usize, permissions: Perm) -> usize {
            self.0
                .allocate(
                    TASK_ADDR_MIN..TASK_ADDR_MIN + len,
                    permissions,
                    FixedAddressBehavior::Hint,
                )
                .unwrap()
        }
    }
    impl Drop for TestPages {
        fn drop(&mut self) {
            self.0.deallocate(TASK_ADDR_MIN..TASK_ADDR_MAX).unwrap();
        }
    }

    fn ptr(base: usize) -> UserMutPtr<u8> {
        UserMutPtr::from_usize(base)
    }

    #[test]
    fn subpage_lifetime_zeroing_and_bounded_fusion() {
        let mut pages = TestPages::new();
        let base = pages.allocate(2 * HOST_PAGE_SIZE, RW);
        let memory = ptr(base);
        assert_eq!(base % HOST_PAGE_SIZE, 0);
        for slot in 0..8 {
            assert_eq!(
                memory.write_at_offset(
                    (slot * PAGE_SIZE) as isize,
                    0x40 + u8::try_from(slot).unwrap()
                ),
                Some(())
            );
        }
        pages
            .0
            .update_permissions(base..base + PAGE_SIZE, R)
            .unwrap();
        // RO inherits W only from its native-page neighbors.
        assert_eq!(memory.write_at_offset(0, 0x41), Some(()));
        pages
            .0
            .update_permissions(base + HOST_PAGE_SIZE..base + 2 * HOST_PAGE_SIZE, R)
            .unwrap();
        assert_eq!(memory.write_at_offset(HOST_PAGE_SIZE as isize, 0xff), None);

        let hole = base + PAGE_SIZE..base + 2 * PAGE_SIZE;
        pages.0.deallocate(hole.clone()).unwrap();
        assert!(!pages.0.contains_range(hole.clone()));
        assert!(matches!(
            pages.0.update_permissions(hole.clone(), R),
            Err(PermissionUpdateError::Unallocated)
        ));
        assert_eq!(memory.read_at_offset((2 * PAGE_SIZE) as isize), Some(0x42));
        pages
            .0
            .allocate(hole, RW, FixedAddressBehavior::NoReplace)
            .unwrap();
        assert_eq!(memory.read_at_offset(PAGE_SIZE as isize), Some(0));
        assert_eq!(memory.read_at_offset((2 * PAGE_SIZE) as isize), Some(0x42));

        pages
            .0
            .allocate(
                base + 2 * PAGE_SIZE..base + 3 * PAGE_SIZE,
                RW,
                FixedAddressBehavior::Replace,
            )
            .unwrap();
        assert_eq!(memory.read_at_offset((2 * PAGE_SIZE) as isize), Some(0));
        assert_eq!(memory.read_at_offset((3 * PAGE_SIZE) as isize), Some(0x43));
        assert!(matches!(
            pages
                .0
                .allocate(base..base + PAGE_SIZE, R, FixedAddressBehavior::NoReplace),
            Err(AllocationError::AddressInUse)
        ));

        // Sparse unmap must preserve the mapping at its exclusive end.
        pages.0.deallocate(0..base + HOST_PAGE_SIZE).unwrap();
        assert_eq!(memory.read_at_offset(0), None);
        assert_eq!(memory.read_at_offset(HOST_PAGE_SIZE as isize), Some(0x44));
        pages
            .0
            .deallocate(base + HOST_PAGE_SIZE..base + 2 * HOST_PAGE_SIZE)
            .unwrap();
        assert!(pages.0.0.is_empty());
        // Sparse holes near usize::MAX must neither overflow nor require a page walk.
        pages
            .0
            .deallocate(TASK_ADDR_MIN..usize::MAX - (PAGE_SIZE - 1))
            .unwrap();
    }

    fn execute(base: usize) -> usize {
        let value: usize;
        // SAFETY: callers installed an RX C-ABI mov/ret stub at base.
        unsafe {
            core::arch::asm!("blr {entry}", entry = in(reg) base,
                lateout("x0") value, clobber_abi("C"));
        }
        value
    }

    #[test]
    fn executable_neighbors_survive_replacement_and_permission_changes() {
        let mut pages = TestPages::new();
        let base = pages.allocate(HOST_PAGE_SIZE, RW);
        // mov x0, #42; ret
        assert_eq!(
            ptr(base).write_slice_at_offset(0, &[0x40, 0x05, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6]),
            Some(())
        );
        pages
            .0
            .update_permissions(base..base + HOST_PAGE_SIZE, RX)
            .unwrap();
        let middle = base + PAGE_SIZE..base + 2 * PAGE_SIZE;
        pages.0.update_permissions(middle.clone(), R).unwrap();
        assert_eq!(execute(base), 42);
        // Zeroing RO subpages must preserve executable neighbors.
        pages
            .0
            .allocate(middle.clone(), R, FixedAddressBehavior::Replace)
            .unwrap();
        assert_eq!(execute(base), 42);
        pages.0.update_permissions(middle.clone(), RX).unwrap();
        pages
            .0
            .update_permissions(middle.clone(), Perm::empty())
            .unwrap();
        assert_eq!(execute(base), 42);
        assert_eq!(ptr(base + PAGE_SIZE).read_at_offset(0), Some(0));
        pages.0.update_permissions(middle.clone(), RW).unwrap();
        for byte in [7, 9] {
            assert_eq!(execute(base), 42);
            assert_eq!(ptr(base + PAGE_SIZE).write_at_offset(0, byte), Some(()));
        }
        assert_eq!(execute(base), 42);
        pages.0.deallocate(middle.clone()).unwrap();
        assert_eq!(execute(base), 42);
        pages
            .0
            .allocate(middle, R, FixedAddressBehavior::NoReplace)
            .unwrap();
        assert_eq!(execute(base), 42);
        pages
            .0
            .update_permissions(base..base + HOST_PAGE_SIZE, R)
            .unwrap();
        pages
            .0
            .update_permissions(base..base + PAGE_SIZE, RW)
            .unwrap();
        assert_eq!(ptr(base + PAGE_SIZE).write_at_offset(0, 7), Some(()));
    }

    #[test]
    fn rw_initialization_preserves_executable_neighbors_and_flushes_code() {
        let mut pages = TestPages::new();
        let base = pages.allocate(2 * HOST_PAGE_SIZE, RW);
        assert_eq!(ptr(base).write_slice_at_offset(0, STUB), Some(()));
        pages
            .0
            .update_permissions(base..base + 2 * HOST_PAGE_SIZE, RX)
            .unwrap();
        let start = base + 3 * PAGE_SIZE;
        for value in [42, 43] {
            // Initialize across a host-page boundary while neighboring code remains live.
            pages
                .0
                .allocate(
                    start..start + 2 * PAGE_SIZE,
                    RW,
                    FixedAddressBehavior::Replace,
                )
                .unwrap();
            assert_eq!(execute(base), 42);
            let mov = 0xd2800000u32 | (value << 5);
            assert_eq!(
                ptr(start).write_slice_at_offset(0, &mov.to_le_bytes()),
                Some(())
            );
            assert_eq!(
                ptr(start).write_slice_at_offset(4, &0xd65f03c0u32.to_le_bytes()),
                Some(())
            );
            assert_eq!(ptr(start + PAGE_SIZE).write_at_offset(0, 99), Some(()));
            pages
                .0
                .update_permissions(start..start + 2 * PAGE_SIZE, RX)
                .unwrap();
            assert_eq!(execute(start), value as usize);
            assert_eq!(execute(base), 42);
            assert_eq!(ptr(start + PAGE_SIZE).read_at_offset(0), Some(99));
            assert_eq!(ptr(start).write_at_offset(0, 0), None);
        }
        assert_eq!(ptr(start - PAGE_SIZE).read_at_offset(0), Some(0));
    }

    #[test]
    fn native_protection_failure_rolls_back_permissions_and_metadata() {
        unsafe extern "C" {
            fn mach_vm_protect(
                task: u32,
                address: u64,
                size: u64,
                maximum: i32,
                protection: i32,
            ) -> i32;
        }
        let mut pages = TestPages::new();
        let base = pages.allocate(2 * HOST_PAGE_SIZE, R);
        // SAFETY: the second native page is test-owned and no access requires W/X.
        assert_eq!(
            unsafe {
                mach_vm_protect(
                    mach_task_self(),
                    (base + HOST_PAGE_SIZE) as u64,
                    HOST_PAGE_SIZE as u64,
                    1,
                    libc::PROT_READ,
                )
            },
            0
        );
        let before = pages.0.0.clone();
        assert!(matches!(
            pages
                .0
                .update_permissions(base..base + 2 * HOST_PAGE_SIZE, RW),
            Err(PermissionUpdateError::PermissionDenied)
        ));
        assert_eq!(pages.0.0, before);
        assert_eq!(ptr(base).write_at_offset(0, 1), None);
        assert!(matches!(
            pages.0.allocate(
                base..base + 2 * HOST_PAGE_SIZE,
                R,
                FixedAddressBehavior::Replace
            ),
            Err(AllocationError::PermissionDenied)
        ));
        assert_eq!(pages.0.0, before);
    }

    #[test]
    fn subpage_remap_within_one_native_page_preserves_neighbors() {
        let platform = MacosUserland::new();
        let memory = platform
            .allocate_pages(
                TASK_ADDR_MIN..TASK_ADDR_MIN + HOST_PAGE_SIZE,
                RW,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
        let base = memory.as_usize();
        let _cleanup = litebox::utils::defer(|| {
            // SAFETY: the test's native page has no active users at cleanup.
            unsafe {
                platform
                    .deallocate_pages(base..base + HOST_PAGE_SIZE)
                    .unwrap();
            };
        });
        assert_eq!(memory.write_at_offset(0, 42), Some(()));
        assert_eq!(memory.write_at_offset(PAGE_SIZE as isize, 99), Some(()));
        let target = base + 2 * PAGE_SIZE..base + HOST_PAGE_SIZE;
        // SAFETY: source and target are idle, disjoint guest subpages of our mapping.
        let moved = unsafe {
            platform.deallocate_pages(target.clone()).unwrap();
            platform
                .remap_pages(base..base + PAGE_SIZE, target, RW)
                .unwrap()
        };
        assert_eq!(moved.as_usize(), base + 2 * PAGE_SIZE);
        assert_eq!(moved.read_at_offset(0), Some(42));
        assert_eq!(moved.read_at_offset(PAGE_SIZE as isize), Some(0));
        assert_eq!(memory.read_at_offset(PAGE_SIZE as isize), Some(99));
        assert!(
            !platform
                .pages
                .lock()
                .unwrap()
                .contains_range(base..base + PAGE_SIZE)
        );
    }

    // Wait out parallel updates before asserting a synthetic recovery result.
    fn recover_fault(pc: usize, address: usize, esr: u64) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match recovery::recover(pc, address, esr) {
                recovery::Recovery::Unhandled => return false,
                recovery::Recovery::Recovered => return true,
                recovery::Recovery::Deferred => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "recovery gate remained busy"
                    );
                    std::thread::yield_now();
                }
            }
        }
    }

    const INSTRUCTION_PERMISSION: u64 = (0x20 << 26) | 0x0f;
    const WRITE_PERMISSION: u64 = (0x24 << 26) | (1 << 6) | 0x0f;
    const STUB: &[u8] = &[0x40, 0x05, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6];

    fn mixed_page(pages: &mut TestPages) -> usize {
        let base = pages.allocate(HOST_PAGE_SIZE, RW);
        assert_eq!(ptr(base).write_slice_at_offset(0, STUB), Some(()));
        pages
            .0
            .update_permissions(base..base + PAGE_SIZE, RX)
            .unwrap();
        assert_eq!(
            recovery::begin_update().permissions(base),
            Some(RW | Perm::EXEC)
        );
        base
    }

    #[test]
    fn recovery_uses_current_permissions_not_conflict_history() {
        for final_permissions in [R, Perm::empty(), RW, RX] {
            let mut pages = TestPages::new();
            let base = mixed_page(&mut pages);
            assert_eq!(execute(base), 42);
            assert_eq!(ptr(base + PAGE_SIZE).write_at_offset(0, 7), Some(()));
            pages
                .0
                .update_permissions(base..base + HOST_PAGE_SIZE, final_permissions)
                .unwrap();
            assert_eq!(
                recovery::begin_update().permissions(base),
                Some(final_permissions)
            );
            // Probe late faults without executing a now non-executable host address.
            assert_eq!(
                recover_fault(base, base, INSTRUCTION_PERMISSION),
                final_permissions.contains(Perm::EXEC)
            );
            assert_eq!(
                recover_fault(0, base, WRITE_PERMISSION),
                final_permissions.contains(Perm::WRITE)
            );
            assert_eq!(
                ptr(base + PAGE_SIZE).write_at_offset(0, 9).is_some(),
                final_permissions.contains(Perm::WRITE)
            );
            if final_permissions.is_empty() {
                assert_eq!(ptr(base).read_at_offset(0), None);
            }
            if final_permissions.contains(Perm::EXEC) {
                assert_eq!(execute(base), 42);
            }
        }
    }

    #[test]
    fn resolved_conflict_and_late_fault_cannot_touch_reused_host_memory() {
        let mut pages = TestPages::new();
        let base = mixed_page(&mut pages);
        assert_eq!(execute(base), 42);
        pages.0.deallocate(base..base + HOST_PAGE_SIZE).unwrap();
        assert_eq!(recovery::begin_update().permissions(base), None);
        let mut address = base as u64;
        // SAFETY: FIXED only reserves the released native range if it is still free.
        assert_eq!(
            unsafe {
                mach_vm_allocate(
                    mach_task_self(),
                    &raw mut address,
                    HOST_PAGE_SIZE as u64,
                    MachVmFlags::FIXED,
                )
            },
            KernReturn::SUCCESS
        );
        let host = Mapping {
            base,
            len: HOST_PAGE_SIZE,
        };
        assert_eq!(ptr(base).write_at_offset(0, 42), Some(()));
        assert!(!recover_fault(base, base, INSTRUCTION_PERMISSION));
        assert!(!recover_fault(0, base, WRITE_PERMISSION));
        assert!(matches!(
            pages
                .0
                .allocate(base..base + PAGE_SIZE, RW, FixedAddressBehavior::NoReplace),
            Err(AllocationError::AddressInUseByPlatform)
        ));
        assert_eq!(ptr(base).read_at_offset(0), Some(42));
        drop(host);
    }

    #[test]
    fn failed_replacement_does_not_publish_reserved_host_ownership() {
        unsafe extern "C" {
            fn mach_vm_protect(
                task: u32,
                address: u64,
                size: u64,
                maximum: i32,
                protection: i32,
            ) -> i32;
        }
        let mut pages = TestPages::new();
        let base = pages.allocate(2 * HOST_PAGE_SIZE, R);
        // SAFETY: this test owns both idle native pages; the second needs only READ.
        assert_eq!(
            unsafe {
                mach_vm_protect(
                    mach_task_self(),
                    (base + HOST_PAGE_SIZE) as u64,
                    HOST_PAGE_SIZE as u64,
                    1,
                    libc::PROT_READ,
                )
            },
            0
        );
        pages.0.deallocate(base..base + HOST_PAGE_SIZE).unwrap();
        // Roll back the first reservation when the second page's write alias fails.
        assert!(matches!(
            pages.0.allocate(
                base..base + 2 * HOST_PAGE_SIZE,
                RW,
                FixedAddressBehavior::Replace
            ),
            Err(AllocationError::PermissionDenied)
        ));
        assert!(!pages.0.0.contains_key(&base));
        assert_eq!(recovery::begin_update().permissions(base), None);
        let mut address = base as u64;
        // SAFETY: non-overwriting reservation of the just-released native page.
        assert_eq!(
            unsafe {
                mach_vm_allocate(
                    mach_task_self(),
                    &raw mut address,
                    HOST_PAGE_SIZE as u64,
                    MachVmFlags::FIXED,
                )
            },
            KernReturn::SUCCESS
        );
        let host = Mapping {
            base,
            len: HOST_PAGE_SIZE,
        };
        assert_eq!(ptr(base).write_at_offset(0, 42), Some(()));
        assert!(matches!(
            pages
                .0
                .allocate(base..base + PAGE_SIZE, RW, FixedAddressBehavior::NoReplace),
            Err(AllocationError::AddressInUseByPlatform)
        ));
        assert_eq!(ptr(base).read_at_offset(0), Some(42));
        drop(host);
    }

    #[test]
    fn failed_update_preserves_mixed_recovery_state() {
        unsafe extern "C" {
            fn mach_vm_protect(
                task: u32,
                address: u64,
                size: u64,
                maximum: i32,
                protection: i32,
            ) -> i32;
        }
        let mut pages = TestPages::new();
        let base = pages.allocate(2 * HOST_PAGE_SIZE, RW);
        assert_eq!(ptr(base).write_slice_at_offset(0, STUB), Some(()));
        pages
            .0
            .update_permissions(base..base + PAGE_SIZE, RX)
            .unwrap();
        pages
            .0
            .update_permissions(base + HOST_PAGE_SIZE..base + 2 * HOST_PAGE_SIZE, R)
            .unwrap();
        assert_eq!(execute(base), 42);
        // SAFETY: this test owns the second native page and only needs READ there.
        assert_eq!(
            unsafe {
                mach_vm_protect(
                    mach_task_self(),
                    (base + HOST_PAGE_SIZE) as u64,
                    HOST_PAGE_SIZE as u64,
                    1,
                    libc::PROT_READ,
                )
            },
            0
        );
        let before = pages.0.0.clone();
        assert!(matches!(
            pages
                .0
                .update_permissions(base..base + 2 * HOST_PAGE_SIZE, RW),
            Err(PermissionUpdateError::PermissionDenied)
        ));
        assert_eq!(pages.0.0, before);
        assert_eq!(
            recovery::begin_update().permissions(base),
            Some(RW | Perm::EXEC)
        );
        assert_eq!(
            recovery::begin_update().permissions(base + HOST_PAGE_SIZE),
            Some(R)
        );
        assert_eq!(execute(base), 42);
        assert_eq!(ptr(base + PAGE_SIZE).write_at_offset(0, 7), Some(()));
        assert_eq!(execute(base), 42);
    }

    #[test]
    fn failed_signal_recovery_preserves_errno() {
        unsafe extern "C" {
            fn mach_vm_protect(
                task: u32,
                address: u64,
                size: u64,
                maximum: i32,
                protection: i32,
            ) -> i32;
        }
        let mut pages = TestPages::new();
        let base = pages.allocate(HOST_PAGE_SIZE, RX);
        // SAFETY: the idle test-owned native page is made readable but incapable
        // of execution, forcing recovery's mprotect to fail without a cache fault.
        unsafe {
            assert_eq!(
                mach_vm_protect(
                    mach_task_self(),
                    base as u64,
                    HOST_PAGE_SIZE as u64,
                    1,
                    libc::PROT_READ
                ),
                0
            );
            let errno = libc::__error();
            let previous = *errno;
            *errno = libc::E2BIG;
            assert!(!recover_fault(base, base, INSTRUCTION_PERMISSION));
            assert_eq!(*errno, libc::E2BIG);
            *errno = previous;
        }
    }

    #[test]
    fn signal_path_never_waits_for_an_update_or_retries_its_own_updater() {
        let mut pages = TestPages::new();
        let base = mixed_page(&mut pages);
        let update = recovery::begin_update();
        assert!(!recover_fault(base, base, INSTRUCTION_PERMISSION));
        let (send, receive) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            send.send(super::recover_fault(base, base, INSTRUCTION_PERMISSION))
                .unwrap();
        });
        // Catch a signal path that blocks on the updater instead of deferring.
        let result = receive.recv_timeout(std::time::Duration::from_secs(5));
        drop(update);
        thread.join().unwrap();
        assert!(result.unwrap());
        assert_eq!(execute(base), 42);
    }

    #[test]
    fn concurrent_execution_writes_and_neighbor_mprotect_make_progress() {
        let mut pages = TestPages::new();
        let base = mixed_page(&mut pages);
        std::thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(move || {
                    MacosUserland::new();
                    for _ in 0..2000 {
                        assert_eq!(execute(base), 42);
                    }
                });
            }
            for _ in 0..500 {
                pages
                    .0
                    .update_permissions(base + PAGE_SIZE..base + HOST_PAGE_SIZE, R)
                    .unwrap();
                pages
                    .0
                    .update_permissions(base + PAGE_SIZE..base + HOST_PAGE_SIZE, RW)
                    .unwrap();
                assert_eq!(ptr(base + PAGE_SIZE).write_at_offset(0, 9), Some(()));
            }
        });
        assert_eq!(execute(base), 42);
        assert_eq!(ptr(base + PAGE_SIZE).read_at_offset(0), Some(9));
    }
}
