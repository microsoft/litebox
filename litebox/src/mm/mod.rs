// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Memory management related functionality

#[cfg(panic = "unwind")]
extern crate std;

pub mod allocator;
pub mod exception_table;
pub mod vmem;

#[cfg(test)]
mod tests;

use core::ops::Range;

use alloc::boxed::Box;
use alloc::vec::Vec;
use vmem::{
    CreatePagesFlags, InitializationId, MappingError, PageFaultError, PageRange,
    SharedFutexBacking, VmArea, VmFlags, Vmem, VmemPageFaultHandler, VmemProtectError,
    VmemUnmapError,
};

use crate::{
    LiteBox,
    mm::vmem::{NonZeroAddress, NonZeroPageSize, VmemResetError, VmemWipeOnForkError},
    platform::{
        PageManagementProvider, RawConstPointer,
        page_mgmt::{DeallocationError, MemoryRegionPermissions, RemapError},
    },
    sync::{RawSyncPrimitivesProvider, RwLock, RwLockReadGuard},
};

/// A page manager to support `mmap`, `munmap`, and etc.
pub struct PageManager<Platform, const ALIGN: usize>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    vmem: RwLock<Platform, Vmem<Platform, ALIGN>>,
}

/// A stable read-side view of a page manager's mapping metadata.
///
/// Keeping this guard alive prevents concurrent mmap/munmap/mremap operations from changing the
/// mapping identity used by synchronization primitives.
pub struct MappingReadGuard<'a, Platform, const ALIGN: usize>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    vmem: RwLockReadGuard<'a, Platform, Vmem<Platform, ALIGN>>,
}

struct InitializationGuard<'a, Platform, const ALIGN: usize>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    manager: &'a PageManager<Platform, ALIGN>,
    range: PageRange<ALIGN>,
    identity: InitializationId,
    armed: bool,
}

impl<Platform, const ALIGN: usize> InitializationGuard<'_, Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<Platform, const ALIGN: usize> Drop for InitializationGuard<'_, Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        #[cfg(panic = "unwind")]
        {
            let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut vmem = self.manager.vmem.write();
                unsafe { vmem.cleanup_initialization(self.range, self.identity) }
            }));
            if !matches!(cleanup, Ok(Ok(()))) {
                std::process::abort();
            }
        }
        #[cfg(not(panic = "unwind"))]
        {
            let mut vmem = self.manager.vmem.write();
            if let Err(error) = unsafe { vmem.cleanup_initialization(self.range, self.identity) } {
                panic!("cleaning a mapping after its initialization callback panicked: {error}");
            }
        }
    }
}

impl<Platform, const ALIGN: usize> MappingReadGuard<'_, Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    /// Returns the flags for the mapping containing `address`.
    pub fn flags_at(&self, address: usize) -> Option<VmFlags> {
        self.vmem.flags_at(address)
    }

    /// Returns the stable shared-backing identity and byte offset for `address`.
    pub fn shared_futex_key_at(&self, address: usize) -> Option<(usize, usize)> {
        self.vmem.shared_futex_key_at(address)
    }
}

impl<Platform, const ALIGN: usize> PageManager<Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    /// Create a new `PageManager` instance.
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        let vmem = RwLock::new(vmem::Vmem::new(litebox.x.platform));
        Self { vmem }
    }

    fn cleanup_initialization_error(
        vmem: &mut Vmem<Platform, ALIGN>,
        range: PageRange<ALIGN>,
        identity: InitializationId,
        primary: MappingError,
    ) -> MappingError {
        match unsafe { vmem.cleanup_initialization(range, identity) } {
            Ok(()) => primary,
            Err(cleanup) => MappingError::Cleanup {
                primary: Box::new(primary),
                cleanup,
            },
        }
    }

    /// Create a mapping with the given flags.
    ///
    /// `suggested_new_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// `before_perms` and `after_perms` are the permissions to set before and after the call to `op`.
    ///
    /// # Safety
    ///
    /// Note that if the suggested address is given and [`CreatePagesFlags::FIXED_ADDR`] is set,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    ///
    /// Also, caller must ensure flags are set correctly.
    #[allow(
        clippy::too_many_arguments,
        reason = "each parameter is independently required by the platform allocation contract"
    )]
    unsafe fn create_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        before_perms: MemoryRegionPermissions,
        after_perms: MemoryRegionPermissions,
        shared_futex_backing: Option<(SharedFutexBacking, usize)>,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        let (addr, identity) = {
            let mut vmem = self.vmem.write();
            // Reserve before allocation so identity exhaustion cannot occur after
            // the platform has already published the new mapping.
            let identity = vmem.reserve_initialization_id()?;
            let addr = unsafe {
                vmem.create_pages(
                    suggested_address,
                    length,
                    flags,
                    before_perms,
                    shared_futex_backing,
                )
            }?;
            let range = PageRange::new(addr.as_usize(), addr.as_usize() + length.as_usize())
                .expect("a platform allocation must retain the requested alignment and length");
            vmem.track_initialization(range, identity);
            (addr, identity)
        };
        let range = PageRange::new(addr.as_usize(), addr.as_usize() + length.as_usize())
            .expect("the tracked mapping range was already validated");
        let mut initialization = InitializationGuard {
            manager: self,
            range,
            identity,
            armed: true,
        };
        // `op` may trigger the page-fault handler, which requires the same write lock.
        #[cfg(panic = "unwind")]
        let callback = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| op(addr))) {
            Ok(callback) => callback,
            Err(payload) => {
                drop(initialization);
                std::panic::resume_unwind(payload)
            }
        };
        #[cfg(not(panic = "unwind"))]
        let callback = op(addr);
        let mut vmem = self.vmem.write();

        if let Err(primary) = callback {
            initialization.disarm();
            return Err(Self::cleanup_initialization_error(
                &mut vmem, range, identity, primary,
            ));
        }

        // A sibling sharing this address space may have unmapped, reset, or replaced the range
        // while the callback ran. The transient ID is invalidated by those mutations, so
        // identical metadata at the same address cannot pass this check after an ABA replacement.
        if !vmem.owns_initialization(range, identity) {
            initialization.disarm();
            return Err(Self::cleanup_initialization_error(
                &mut vmem,
                range,
                identity,
                MappingError::ConcurrentlyRemoved,
            ));
        }

        if let Err(error) = unsafe { vmem.protect_mapping(range, after_perms) } {
            initialization.disarm();
            return Err(Self::cleanup_initialization_error(
                &mut vmem,
                range,
                identity,
                MappingError::FinalizeProtection(error),
            ));
        }

        if !vmem.finish_initialization(range, identity) {
            initialization.disarm();
            return Err(Self::cleanup_initialization_error(
                &mut vmem,
                range,
                identity,
                MappingError::ConcurrentlyRemoved,
            ));
        }
        initialization.disarm();
        Ok(addr)
    }

    /// Creates pages whose non-private futexes are keyed by a stable backing object and byte
    /// offset rather than by this mapping's virtual address.
    ///
    /// # Safety
    ///
    /// Note that if the suggested address is given and [`CreatePagesFlags::FIXED_ADDR`] is set,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any
    /// other.
    ///
    /// Also, caller must ensure flags are set correctly.
    #[allow(
        clippy::too_many_arguments,
        reason = "each parameter is independently required by the platform allocation contract"
    )]
    pub unsafe fn create_pages_with_shared_futex_backing<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        before_perms: MemoryRegionPermissions,
        after_perms: MemoryRegionPermissions,
        shared_futex_backing: Option<(SharedFutexBacking, usize)>,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_address,
                length,
                flags,
                before_perms,
                after_perms,
                shared_futex_backing,
                op,
            )
        }
    }

    /// Create readable and executable pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_executable_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_address,
                length,
                flags,
                // create READ | WRITE pages (as `op` may need to write to them, e.g., fill in the code)
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                // keep READ, turn off WRITE and turn on EXEC
                MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
                None,
                op,
            )
        }
    }

    /// Create readable and writable pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_writable_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        let perms = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        unsafe { self.create_pages(suggested_address, length, flags, perms, perms, None, op) }
    }

    /// Create read-only pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_readable_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_address,
                length,
                flags,
                // create READ | WRITE pages (as `op` may need to write to them, e.g., fill in the data)
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                // keep READ, turn off WRITE
                MemoryRegionPermissions::READ,
                None,
                op,
            )
        }
    }

    /// Create inaccessible pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_inaccessible_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_address,
                length,
                flags,
                MemoryRegionPermissions::empty(),
                MemoryRegionPermissions::empty(),
                None,
                op,
            )
        }
    }

    /// Create stack pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_stack_pages(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        let perms = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        let flags = CreatePagesFlags::IS_STACK | flags;
        unsafe {
            self.create_pages(suggested_address, length, flags, perms, perms, None, |_| {
                Ok(0)
            })
        }
    }

    /// Set the initial program break address.
    ///
    /// This function should be called once per image to set the initial program break,
    /// which is usually the end of the data segment.
    ///
    /// Under the per-process swap protocol described at [`Self::swap_brk`] the manager's
    /// break is 0 between operations, so a non-zero value here is a break that a previous
    /// caller published and never took back -- an `exec` that failed between publishing
    /// the new image's break and swapping it out (stack allocation is the fallible step
    /// in between, and under a spawn storm it does fail). That value belongs to nobody:
    /// its process either died or still holds its own authoritative slot. It is replaced
    /// and logged rather than asserted on, because this runs inside the mapping lock and
    /// a panic here took every other guest process's heap down with it (observed live as
    /// `initial brk is already set` under ~900 concurrent spawns).
    pub fn set_initial_brk(&self, brk: usize) {
        let mut vmem = self.vmem.write();
        if vmem.brk != 0 {
            litebox_util_log::warn!(
                stale:? = vmem.brk, new:? = brk;
                "initial brk is already set; replacing a break left behind by an aborted exec"
            );
        }
        vmem.brk = brk;
    }

    /// Installs `brk` as the current program break, returning the value it
    /// replaced.
    ///
    /// [`Self::set_initial_brk`] and [`Self::brk`] together model a *single*
    /// program break, which is correct only while one page manager backs
    /// exactly one guest process. A shim that runs more than one guest process
    /// against a shared page manager (litebox's Linux shim does, once `fork`
    /// exists: every guest process shares one host address space, at disjoint
    /// addresses) needs one break *per process*, so it keeps the authoritative
    /// value itself and swaps it in around each break operation. Returning the
    /// old value is what lets the caller both save and restore in one call, so
    /// the manager's own field can be left at the "no break set" sentinel of 0
    /// between operations and [`Self::set_initial_brk`]'s assertion keeps
    /// meaning what it says.
    pub fn swap_brk(&self, brk: usize) -> usize {
        let mut vmem = self.vmem.write();
        core::mem::replace(&mut vmem.brk, brk)
    }

    /// Set the program break to the given address.
    ///
    /// Increasing the program break has the effect of allocating memory to the process;
    /// decreasing the break deallocates memory.
    /// Calling `brk` with 0 can be used to find the current location of the program break.
    ///
    /// Note the initial program break is set to zero and the first call to `brk` would set it
    /// to the given address, which is usually the end of the data segment.
    ///
    /// ## Returns
    ///
    /// If the operation is successful, it returns the new program break address.
    ///
    /// # Panics
    ///
    /// Panics if the initial program break is not set yet.
    ///
    /// # Safety
    ///
    /// If shrinking the program break, the caller must ensure that the released memory region is no longer used.
    pub unsafe fn brk(&self, brk: usize) -> Result<usize, MappingError> {
        let mut vmem = self.vmem.write();
        if vmem.brk == 0 {
            // No break is installed. Under the shim's per-process swap protocol this means the
            // calling process's own break was never initialized (its exec skipped break
            // setup). Refusing is safe -- libc mallocs fall back to `mmap` on `brk` failure --
            // while the previous `assert!` here took down the whole runner from inside the
            // shim's global brk critical section, deadlocking every other process's heap
            // (observed live as a desktop-wide freeze).
            return Err(MappingError::OutOfMemory);
        }
        if brk == 0 {
            // Calling `brk` with 0 can be used to find the current location of the program break.
            return Ok(vmem.brk);
        }

        let old_brk = vmem.brk.next_multiple_of(vmem::PAGE_SIZE);
        let new_brk = brk.next_multiple_of(vmem::PAGE_SIZE);
        if vmem.brk >= brk {
            // Shrink the memory region
            if new_brk < old_brk && vmem.has_pending_initialization(&(new_brk..old_brk)) {
                return Ok(vmem.brk);
            }
            let brk = match unsafe {
                vmem.remove_mapping(
                    PageRange::new(new_brk, old_brk).ok_or(MappingError::UnAligned)?,
                )
            } {
                Ok(()) => {
                    vmem.brk = brk;
                    brk
                }
                Err(_) => {
                    vmem.brk // No change, return the old brk
                }
            };
            return Ok(brk);
        }

        if vmem.overlapping(old_brk..new_brk).next().is_some() {
            return Err(MappingError::OutOfMemory);
        }
        if let Some(range) = PageRange::<ALIGN>::new(old_brk, new_brk) {
            let (suggested_address, length) = range.start_and_length();
            let perms = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
            unsafe {
                vmem.create_pages(
                    Some(suggested_address),
                    length,
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                    perms,
                    None,
                )
            }?;
        }
        vmem.brk = brk;
        Ok(brk)
    }

    /// Release memory mappings. The program break is not touched, see the note at the end.
    ///
    /// `releasable` is called once per tracked mapping and returns the *sub-ranges* of it to
    /// release, not merely whether to release the whole of it. That distinction is load-bearing,
    /// because a tracked mapping is not the same thing as a mapping the caller made: the VMA tree
    /// coalesces adjacent ranges carrying identical properties into a single entry
    /// (see [`Self::mappings`]), so one entry can span several unrelated `mmap`s -- and, when one
    /// manager backs more than one owner (litebox's Linux shim runs every guest process against
    /// one manager, at disjoint addresses in one host address space), several unrelated *owners*.
    /// A caller that only wants its own memory gone therefore has to be able to name the addresses
    /// it means; a whole-entry predicate cannot, and releasing the whole entry would unmap a
    /// neighbour's live memory. Ranges are clamped to the entry they came from, and empty ones are
    /// skipped, so an owner set that does not intersect an entry simply releases nothing of it.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the released memory regions are no longer used.
    pub unsafe fn release_memory<R>(
        &self,
        releasable: impl Fn(Range<usize>, VmFlags) -> R,
    ) -> Result<(), VmemUnmapError>
    where
        R: IntoIterator<Item = Range<usize>>,
    {
        for (r, vma) in self.mappings() {
            for part in releasable(r.clone(), vma) {
                let Some(range) = PageRange::new(part.start.max(r.start), part.end.min(r.end))
                else {
                    continue;
                };
                let mut vmem = self.vmem.write();
                unsafe { vmem.remove_mapping(range) }?;
            }
        }

        // The program break is deliberately left alone. Under the per-process swap protocol
        // ([`Self::swap_brk`]) the manager's break is 0 between operations and, during one, it
        // is *another* process's live break -- the releasing process is exiting or exec'ing on
        // its own thread and holds no break operation of its own. Zeroing it here (as this
        // used to) therefore never cleared anything of the caller's and could only clobber a
        // neighbour's, which was observed live under a 900-process spawn storm as an exec
        // reading back a zero break right after its loader published one ("execve: loader
        // left no initial brk", 2 of 900 execs), leaving that process with no heap. A caller
        // that models a single break for a single process resets it through
        // [`Self::swap_brk`] or the next [`Self::set_initial_brk`].

        Ok(())
    }

    /// Expands (or shrinks) an existing memory mapping
    ///
    /// `old_addr` is the old address of the virtual memory block that you want to expand (or shrink).
    ///
    /// `old_size` is the size of the old memory block.
    ///
    /// `new_size` is the new size of the memory block.
    ///
    /// `may_move` indicates whether the memory block can be moved to a new address if there is not sufficient
    /// space to expand the old memory block at its current location.
    ///
    /// ## Returns
    ///
    /// If the operation is successful, it returns the new address of the memory block.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    pub unsafe fn remap_pages(
        &self,
        old_addr: Platform::RawMutPointer<u8>,
        old_size: usize,
        new_size: usize,
        may_move: bool,
    ) -> Result<Platform::RawMutPointer<u8>, RemapError> {
        let mut vmem = self.vmem.write();
        let old_range = PageRange::new(old_addr.as_usize(), old_addr.as_usize() + old_size)
            .ok_or(RemapError::Unaligned)?;
        match unsafe {
            vmem.resize_mapping(
                old_range,
                vmem::NonZeroPageSize::new(new_size).ok_or(RemapError::Unaligned)?,
            )
        } {
            Ok(()) => Ok(old_addr),
            Err(vmem::VmemResizeError::RangeOccupied(_)) => {
                // trying to remap a subset of an existing mapping
                if !may_move {
                    return Err(RemapError::OutOfMemory);
                }
                match unsafe {
                    vmem.move_mappings(
                        old_range,
                        None,
                        NonZeroPageSize::new(new_size).ok_or(RemapError::Unaligned)?,
                    )
                } {
                    Ok(new_addr) => Ok(new_addr),
                    Err(vmem::VmemMoveError::OutOfMemory) => Err(RemapError::OutOfMemory),
                    Err(vmem::VmemMoveError::UnAligned) => Err(RemapError::Unaligned),
                    Err(vmem::VmemMoveError::RemapError(err)) => Err(err),
                }
            }
            Err(vmem::VmemResizeError::NotExist(_)) => {
                // The old range's start is not inside a tracked VMA. For a grow,
                // degrade to `OutOfMemory` (ENOMEM) instead of the fatal
                // `AlreadyUnallocated` (EFAULT): this is exactly the errno Linux
                // returns when an mmap-region grow cannot be satisfied in place,
                // and it lets a guest heap allocator (musl grows a chunk via
                // `mremap` without `MREMAP_MAYMOVE`) fall back to allocate-and-copy
                // rather than treat it as a corrupt pointer and crash. A non-grow
                // on an untracked range is a genuine bad address and stays EFAULT.
                if new_size > old_size {
                    Err(RemapError::OutOfMemory)
                } else {
                    Err(RemapError::AlreadyUnallocated)
                }
            }
            Err(vmem::VmemResizeError::InvalidAddr { .. }) => Err(RemapError::AlreadyAllocated),
            Err(
                vmem::VmemResizeError::InitializationPending(_)
                | vmem::VmemResizeError::OutOfMemory,
            ) => Err(RemapError::OutOfMemory),
            Err(vmem::VmemResizeError::UnmapError(
                VmemUnmapError::UnAligned
                | VmemUnmapError::UnmapError(DeallocationError::Unaligned),
            )) => Err(RemapError::Unaligned),
            Err(vmem::VmemResizeError::UnmapError(VmemUnmapError::UnmapError(
                DeallocationError::AlreadyUnallocated,
            ))) => Err(RemapError::AlreadyUnallocated),
        }
    }

    /// Remove pages from the mapping.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    pub unsafe fn remove_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemUnmapError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let range = PageRange::new(start, start + len).ok_or(VmemUnmapError::UnAligned)?;
        unsafe { vmem.remove_mapping(range) }
    }

    /// Reset pages without removing its mapping.
    ///
    /// If `anonymous_only` is true and any part of the range is non‑anonymous (i.e., file‑backed),
    /// returns `Err(VmemResetError::FileBacked)`.
    ///
    /// After calling this function, the memory region remains mapped, but its contents are invalidated.
    /// Subsequent accesses to the region will result in repopulating the memory contents, either from
    /// the underlying mapped file (for file-backed mappings, which is supported) or as zero-filled pages
    /// (for anonymous mappings).
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory contents in the affected region are no longer accessed or
    /// relied upon. Any pointers or references to the previous contents become invalid.
    pub unsafe fn reset_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        anonymous_only: bool,
    ) -> Result<(), VmemResetError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let range = PageRange::new(start, start + len).ok_or(VmemResetError::UnAligned)?;
        unsafe { vmem.reset_pages(range, anonymous_only) }
    }

    /// `madvise(MADV_WIPEONFORK)` (`enable`) / `madvise(MADV_KEEPONFORK)` (`!enable`): marks
    /// the mappings in `[ptr, ptr + len)` so that a forked child sees them zero-filled while
    /// the parent keeps its contents. Only the flag is recorded here; the wipe itself is
    /// [`Self::wipe_on_fork_child`], which the process model calls at the point where the
    /// child's view of memory diverges from the parent's.
    ///
    /// Fails with [`VmemWipeOnForkError::NotPrivateAnonymous`] on a file-backed or shared
    /// mapping (Linux: `EINVAL`) and [`VmemWipeOnForkError::Unmapped`] on a hole (`ENOMEM`).
    pub fn set_wipe_on_fork(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        enable: bool,
    ) -> Result<(), VmemWipeOnForkError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let range = PageRange::new(start, start + len).ok_or(VmemWipeOnForkError::UnAligned)?;
        vmem.set_wipe_on_fork(range, enable)
    }

    /// Every mapping marked `MADV_WIPEONFORK`, with its flags. Like [`Self::mappings`], one
    /// entry can span more than one `mmap`; callers that act on a subset of a process's memory
    /// intersect these with their own ownership records, see [`Self::wipe_on_fork_child`].
    pub fn ranges_to_wipe_on_fork(&self) -> Vec<(Range<usize>, VmFlags)> {
        self.vmem.read().wipe_on_fork_ranges()
    }

    /// Gives the *child* of a fork the `MADV_WIPEONFORK` view of memory: every wipe-marked
    /// private anonymous mapping is dropped and re-created zero-filled, keeping its flags
    /// (including the wipe mark itself, which Linux also inherits, so grandchildren are
    /// wiped too).
    ///
    /// Written for a process model where the child runs on the parent's live pages after the
    /// parent copied its own contents out (litebox's Linux shim: `save_address_space`, then
    /// `hand_off_to`): calling this between those two steps makes the child start from zeros
    /// while the parent's saved image brings its bytes back untouched. Call order is what
    /// makes it child-only -- called before the parent's copy-out it would wipe the parent.
    ///
    /// `restrict` names the parts of each marked mapping that belong to the forking process,
    /// exactly as [`Self::release_memory`]'s predicate does, because a coalesced manager
    /// entry can cover a neighbour's memory; parts are clamped to the entry and empty ones
    /// are skipped. Only writable, materialized, private anonymous pieces are wiped: those
    /// are precisely the ones a copy-out saves, so nothing the parent cannot restore is ever
    /// zeroed. A piece that cannot be wiped is logged loudly and left as is, because fork must
    /// not fail for it, but a child then sees inherited bytes the program asked to be gone.
    ///
    /// Returns the number of bytes wiped.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the previous contents of the wiped ranges are no longer
    /// relied upon by whoever runs on these pages next (the parent's copy must already be
    /// saved).
    pub unsafe fn wipe_on_fork_child<R>(
        &self,
        restrict: impl Fn(Range<usize>, VmFlags) -> R,
    ) -> usize
    where
        R: IntoIterator<Item = Range<usize>>,
    {
        let mut wiped = 0;
        for (r, flags) in self.ranges_to_wipe_on_fork() {
            if !flags.contains(VmFlags::VM_WRITE)
                || flags.contains(VmFlags::VM_SHARED)
                || flags.contains(VmFlags::VM_DEFERRED)
            {
                // Not writable: the parent's copy-out skipped it, so a wipe here would be
                // parent-visible. Deferred: nothing has been materialized to wipe.
                litebox_util_log::debug!(
                    start:? = r.start, end:? = r.end, flags:? = flags;
                    "wipe-on-fork range skipped: not a writable materialized private mapping"
                );
                continue;
            }
            for part in restrict(r.clone(), flags) {
                let Some(range) = PageRange::new(part.start.max(r.start), part.end.min(r.end))
                else {
                    continue;
                };
                let mut vmem = self.vmem.write();
                match unsafe { vmem.reset_pages(range, true) } {
                    Ok(()) => wiped += range.len(),
                    Err(error) => litebox_util_log::error!(
                        start:? = range.start, end:? = range.end, error:% = error;
                        "wipe-on-fork range could not be zeroed; the child inherits its contents"
                    ),
                }
            }
        }
        if wiped != 0 {
            litebox_util_log::debug!(bytes:? = wiped; "wiped MADV_WIPEONFORK ranges for a forked child");
        }
        wiped
    }

    /// Internal common function used by `make_pages_*` to change page permissions.
    fn change_page_permissions(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let range = PageRange::new(start, start + len)
            .ok_or(VmemProtectError::InvalidRange(start..start + len))?;
        unsafe { vmem.protect_mapping(range, new_permissions) }
    }

    /// Make pages readable and writable.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent `execute` access to the memory region.
    pub unsafe fn make_pages_writable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(
            ptr,
            len,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
        )
    }

    /// Make pages readable and executable.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent `write` access to the memory region.
    pub unsafe fn make_pages_executable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(
            ptr,
            len,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
        )
    }

    /// Make pages readable only.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent `write/execute` access to the memory region.
    pub unsafe fn make_pages_readable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(ptr, len, MemoryRegionPermissions::READ)
    }

    /// Make pages inaccessible.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent access to the memory region.
    pub unsafe fn make_pages_inaccessible(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(ptr, len, MemoryRegionPermissions::empty())
    }

    /// Make pages readable, writable and executable.
    ///
    /// # Safety
    ///
    /// This operation is inherently dangerous and should be used with extreme caution.
    /// Allowing pages to be both writable and executable can lead to severe security vulnerabilities,
    /// such as code injection attacks or exploitation of memory corruption bugs.
    ///
    /// The caller must ensure the following:
    /// 1. The memory region is only used for legitimate purposes, such as JIT compilation,
    ///    where writable and executable permissions are strictly necessary.
    /// 2. The memory region is properly sanitized and does not contain malicious or unintended code.
    ///
    /// It is highly recommended to minimize the use of this function and to prefer safer alternatives
    /// whenever possible. If this function must be used, ensure that the memory region is locked down
    /// and access is strictly controlled.
    pub unsafe fn make_pages_rwx(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(
            ptr,
            len,
            MemoryRegionPermissions::READ
                | MemoryRegionPermissions::WRITE
                | MemoryRegionPermissions::EXEC,
        )
    }

    /// Register an already-allocated memory region in the VMA tracker.
    ///
    /// This is used when memory has been allocated by some means other than the normal
    /// `create_*_pages` path (e.g., CoW mappings created directly by the platform), so that the
    /// page manager tracks the region for future `mprotect`, `munmap`, etc.
    ///
    /// If `replace` is `true`, any overlapping tracked mappings are evicted from the tracker
    /// (without calling the platform deallocator) before inserting. Otherwise, returns `None`
    /// without registering if the provided `range` overlaps with any existing mapping.
    ///
    /// # Safety
    ///
    /// The `range` must be an already-mapped region with the given `permissions`.
    #[must_use]
    pub unsafe fn register_existing_mapping(
        &self,
        range: PageRange<ALIGN>,
        permissions: MemoryRegionPermissions,
        is_file_backed: bool,
        replace: bool,
        shared: bool,
    ) -> Option<()> {
        let vma = VmArea::new(
            VmFlags::from(permissions) | VmFlags::may_flags_for_mapping(shared, is_file_backed),
            is_file_backed,
            None,
        );
        let mut vmem = self.vmem.write();
        if !replace && vmem.overlapping(range.into()).next().is_some() {
            return None;
        }
        vmem.register_existing_mapping_overwrite(range, vma);
        Some(())
    }

    /// Locks mapping metadata for a stable sequence of identity-sensitive operations.
    pub fn lock_mappings(&self) -> MappingReadGuard<'_, Platform, ALIGN> {
        MappingReadGuard {
            vmem: self.vmem.read(),
        }
    }

    /// Returns all mappings in a vector.
    ///
    /// One returned range is *not* one `mmap`: the underlying VMA tree coalesces adjacent ranges
    /// whose properties are identical, so two separately created mappings that happen to abut --
    /// which is the common case here, since `Vmem::get_unmmaped_area`'s placement search returns
    /// the address immediately below an existing range -- are reported as a single entry. Any
    /// caller that acts on a whole returned range therefore acts on memory it may not have
    /// created; see [`Self::release_memory`], which takes sub-ranges for exactly this reason.
    pub fn mappings(&self) -> Vec<(Range<usize>, VmFlags)> {
        self.vmem
            .read()
            .iter()
            .map(|(r, vma)| (r.start..r.end, vma.flags()))
            .collect()
    }

    /// Reserves `range` so a flexible (non-`MAP_FIXED`) placement search steers around it even
    /// though it has no live mapping. See `vmem::Vmem::reserve_external`'s doc comment for why
    /// this exists (a saved-but-currently-unmapped fork-family member's memory).
    pub fn reserve_external(&self, range: Range<usize>) {
        self.vmem.write().reserve_external(range);
    }

    /// Releases a reservation made by [`Self::reserve_external`].
    pub fn release_external(&self, range: Range<usize>) {
        self.vmem.write().release_external(range);
    }

    /// Get the memory permissions of a given address range.
    ///
    /// `ptr` specifies the start address of the memory range.
    /// `len` specifies the length of the memory range.
    /// This function returns `MemoryRegionPermissions` only if the range is valid.
    /// A memory range is invalid if it contains:
    /// - Unmapped pages
    /// - Memory pages with different permissions
    pub fn get_memory_permissions(
        &self,
        ptr: NonZeroAddress<ALIGN>,
        len: NonZeroPageSize<ALIGN>,
    ) -> Option<MemoryRegionPermissions> {
        let vmem = self.vmem.read();
        let start = ptr.as_usize();
        let end = start + len.as_usize();
        let page_range = PageRange::<ALIGN>::new(start, end)?;
        vmem.get_memory_permissions(page_range)
    }
}

/// If Backend also implements [`VmemPageFaultHandler`], it can handle page faults.
impl<Platform, const ALIGN: usize> PageManager<Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
    Platform: VmemPageFaultHandler,
{
    /// Handle page fault at the given address.
    ///
    /// # Safety
    ///
    /// This should only be called from the kernel page fault handler.
    pub unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        error_code: u64,
    ) -> Result<(), PageFaultError> {
        let fault_addr = fault_addr & !(ALIGN - 1);
        if !(Platform::TASK_ADDR_MIN..Platform::TASK_ADDR_MAX).contains(&fault_addr) {
            return Err(PageFaultError::AccessError("Invalid address"));
        }

        let mut vmem = self.vmem.write();
        // Find the range closest to the fault address
        let (mapped_range, vma) = {
            let (r, vma) = vmem
                .overlapping(fault_addr..Platform::TASK_ADDR_MAX)
                .next()
                .ok_or(PageFaultError::AccessError("no mapping"))?;
            (r.clone(), *vma)
        };
        let start = mapped_range.start;
        if fault_addr < start {
            // address is out of range, test if it is next to a stack
            if !vma.flags().contains(VmFlags::VM_GROWSDOWN) {
                return Err(PageFaultError::AccessError("no mapping"));
            }
            if vmem.has_pending_initialization(&mapped_range) {
                return Err(PageFaultError::AllocationFailed);
            }

            if !vmem
                .overlapping(Platform::TASK_ADDR_MIN..fault_addr)
                .next_back()
                .is_none_or(|(prev_range, prev_vma)| {
                    // Enforce gap between stack and other preceding non-stack mappings.
                    // Either the previous mapping is also a stack mapping w/ some access flags
                    // or the previous mapping is far enough from the fault address
                    (prev_vma.flags().contains(VmFlags::VM_GROWSDOWN)
                        && !(prev_vma.flags() & VmFlags::VM_ACCESS_FLAGS).is_empty())
                        || fault_addr - prev_range.end >= Vmem::<Platform, ALIGN>::STACK_GUARD_GAP
                })
            {
                return Err(PageFaultError::AllocationFailed);
            }
            let Some(range) = PageRange::new(fault_addr, start) else {
                unreachable!()
            };
            if let Err(err) = unsafe {
                vmem.insert_mapping(
                    range,
                    vma,
                    false,
                    crate::platform::page_mgmt::FixedAddressBehavior::NoReplace,
                )
            } {
                unimplemented!("failed to grow stack: {:?}", err)
            }
        }

        if <Platform as VmemPageFaultHandler>::access_error(error_code, vma.flags()) {
            return Err(PageFaultError::AccessError("access error"));
        }

        unsafe {
            vmem.platform
                .handle_page_fault(fault_addr, vma.flags(), error_code)
        }
    }
}
