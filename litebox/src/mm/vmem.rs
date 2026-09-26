// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This module implements a virtual memory manager `Vmem` that manages virtual address spaces
//! backed by a memory [backend](PageManagementProvider). It provides functionality to create, remove, resize,
//! move, and protect memory mappings within a process's virtual address space.

use core::ops::Range;
use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use rangemap::RangeMap;
use thiserror::Error;

use crate::platform::PageManagementProvider;
use crate::platform::RawConstPointer;
use crate::platform::page_mgmt::AllocationError;
use crate::platform::page_mgmt::FixedAddressBehavior;
use crate::platform::page_mgmt::MemoryRegionPermissions;

/// Page size in bytes.
///
/// This is the granularity at which LiteBox maps, unmaps and re-protects guest
/// memory, so it has to be at least the host's own page size -- a host kernel
/// rejects a fixed mapping or a protection change that is not aligned to it.
///
/// Apple Silicon uses 16 KiB pages, so a macOS/aarch64 host needs the larger
/// value; every other supported host uses 4 KiB. The guest sees this through
/// `AT_PAGESZ`, which is exactly how a Linux kernel configured for 16 KiB or
/// 64 KiB pages reports itself, and aarch64 ELF images are conventionally
/// linked with a 64 KiB maximum page size so their segments stay aligned either
/// way.
#[cfg(not(all(target_vendor = "apple", target_arch = "aarch64")))]
pub const PAGE_SIZE: usize = 4096;

/// Page size in bytes. See the 4 KiB definition for details.
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
pub const PAGE_SIZE: usize = 16384;

bitflags::bitflags! {
    /// Flags to describe the properties of a memory region.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct VmFlags: u32 {
        /// Readable.
        const VM_READ = 1 << 0;
        /// Writable.
        const VM_WRITE = 1 << 1;
        /// Executable.
        const VM_EXEC = 1 << 2;
        /// Shared between processes.
        const VM_SHARED = 1 << 3;

        /* limits for mprotect() etc */
        /// `mprotect` can turn on VM_READ
        const VM_MAYREAD = 1 << 4;
        /// `mprotect` can turn on VM_WRITE
        const VM_MAYWRITE = 1 << 5;
        /// `mprotect` can turn on VM_EXEC
        const VM_MAYEXEC = 1 << 6;
        /// `mprotect` can turn on VM_SHARED
        const VM_MAYSHARE = 1 << 7;

        /// The area can grow downward upon page fault.
        const VM_GROWSDOWN = 1 << 8;

        /// LiteBox-internal, never guest-visible: the range is reserved in the
        /// VMA tracker only, and the platform holds no state for it yet.
        /// Set on `PROT_NONE` anonymous private mappings (pure VA reservations,
        /// e.g. V8's multi-GiB cage/sandbox), which Linux also books without
        /// any page-table state. Materialized lazily by `protect_mapping` when
        /// any access flag is first added; unmapping one never touches the
        /// platform.
        const VM_DEFERRED = 1 << 9;

        /// `MADV_WIPEONFORK`: a forked child sees this range zero-filled
        /// instead of inheriting the parent's contents (the parent keeps
        /// its own). Linux records it as `VM_WIPEONFORK` on the VMA; only
        /// private anonymous mappings can carry it, `MADV_KEEPONFORK`
        /// clears it, and a mapping created over the range drops it with
        /// the VMA it belonged to. See [`Vmem::set_wipe_on_fork`] and
        /// [`Vmem::wipe_on_fork_ranges`].
        const VM_WIPEONFORK = 1 << 10;

        const VM_ACCESS_FLAGS = Self::VM_READ.bits()
            | Self::VM_WRITE.bits()
            | Self::VM_EXEC.bits();
        const VM_MAY_ACCESS_FLAGS = Self::VM_MAYREAD.bits()
            | Self::VM_MAYWRITE.bits()
            | Self::VM_MAYEXEC.bits();
    }
}

impl VmFlags {
    /// Compute the default `VM_MAY*` and `VM_SHARED` flags for a mapping.
    pub(super) fn may_flags_for_mapping(shared: bool, _file_backed: bool) -> Self {
        let shared_flag = if shared {
            Self::VM_SHARED
        } else {
            Self::empty()
        };
        Self::VM_MAY_ACCESS_FLAGS | shared_flag
    }
}

impl From<MemoryRegionPermissions> for VmFlags {
    fn from(value: MemoryRegionPermissions) -> Self {
        let mut flags = VmFlags::empty();
        flags.set(
            VmFlags::VM_READ,
            value.contains(MemoryRegionPermissions::READ),
        );
        flags.set(
            VmFlags::VM_WRITE,
            value.contains(MemoryRegionPermissions::WRITE),
        );
        flags.set(
            VmFlags::VM_EXEC,
            value.contains(MemoryRegionPermissions::EXEC),
        );
        if value.contains(MemoryRegionPermissions::SHARED) {
            unimplemented!("SHARED permission is not supported yet");
        }
        flags
    }
}

impl From<VmFlags> for MemoryRegionPermissions {
    fn from(value: VmFlags) -> Self {
        let mut flags = MemoryRegionPermissions::empty();
        flags.set(
            MemoryRegionPermissions::READ,
            value.contains(VmFlags::VM_READ),
        );
        flags.set(
            MemoryRegionPermissions::WRITE,
            value.contains(VmFlags::VM_WRITE),
        );
        flags.set(
            MemoryRegionPermissions::EXEC,
            value.contains(VmFlags::VM_EXEC),
        );
        flags.set(
            MemoryRegionPermissions::SHARED,
            value.contains(VmFlags::VM_SHARED),
        );
        flags
    }
}

pub const DEFAULT_RESERVED_SPACE_SIZE: usize = 0x100_0000; // 16 MiB

bitflags::bitflags! {
    /// Options for page creation.
    pub struct CreatePagesFlags: u8 {
        /// Force the mapping to be created at the given address, resulting in any
        /// existing overlapping mappings being removed.
        const FIXED_ADDR     = 1 << 0;
        /// The mapping is used for stack.
        const IS_STACK       = 1 << 1;
        /// Populate the pages immediately.
        const POPULATE_PAGES_IMMEDIATELY = 1 << 2;
        /// Ensure there is more space (i.e., `DEFAULT_RESERVED_SPACE_SIZE`) after the
        /// mapping so that user can grow the mapping later.
        const ENSURE_SPACE_AFTER = 1 << 3;
        // This flag indicates that the mapping is backed by a file.
        const MAP_FILE = 1 << 4;
        /// When combined with [`Self::FIXED_ADDR`], fail with [`AllocationError::AddressInUse`]
        /// if any part of the range is already mapped, instead of replacing existing mappings.
        const NOREPLACE = 1 << 5;
        /// The mapping is shared.
        const SHARED = 1 << 6;
    }
}

/// A non-empty range of page-aligned addresses
#[derive(Clone, Copy)]
pub struct PageRange<const ALIGN: usize> {
    /// Start page of the range.
    pub start: usize,
    /// End page of the range.
    pub end: usize,
}

impl<const ALIGN: usize> From<PageRange<ALIGN>> for Range<usize> {
    fn from(range: PageRange<ALIGN>) -> Self {
        range.start..range.end
    }
}

impl<const ALIGN: usize> IntoIterator for PageRange<ALIGN> {
    type Item = usize;
    type IntoIter = core::iter::StepBy<Range<usize>>;

    fn into_iter(self) -> Self::IntoIter {
        (self.start..self.end).step_by(ALIGN)
    }
}

impl<const ALIGN: usize> PageRange<ALIGN> {
    /// Create a new [`PageRange`].
    ///
    /// Returns `None` if the range is not `ALIGN`-aligned or empty.
    pub fn new(start: usize, end: usize) -> Option<Self> {
        if !start.is_multiple_of(ALIGN) || !end.is_multiple_of(ALIGN) {
            return None;
        }
        if start >= end {
            return None;
        }
        Some(Self { start, end })
    }

    /// Get the size of this `ALIGN`-aligned range
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the range is empty or not
    ///
    /// Note this range is never empty.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Get the start address and length of this range as a tuple.
    #[allow(
        clippy::missing_panics_doc,
        reason = "This function should not fail as the range is guaranteed to be non-empty and aligned."
    )]
    pub fn start_and_length(&self) -> (NonZeroAddress<ALIGN>, NonZeroPageSize<ALIGN>) {
        (
            NonZeroAddress::new(self.start).unwrap(),
            NonZeroPageSize::new(self.len()).unwrap(),
        )
    }
}

/// A non-zero `ALIGN`-aligned size in bytes.
#[derive(Clone, Copy)]
pub struct NonZeroPageSize<const ALIGN: usize> {
    size: usize,
}

impl<const ALIGN: usize> NonZeroPageSize<ALIGN> {
    /// Create a new non-zero `ALIGN`-aligned size.
    ///
    /// Returns `None` if the size is zero or not `ALIGN`-aligned.
    pub fn new(size: usize) -> Option<Self> {
        if size == 0 || !size.is_multiple_of(ALIGN) {
            return None;
        }
        Some(Self { size })
    }

    /// Get the size
    #[inline]
    pub fn as_usize(self) -> usize {
        self.size
    }
}

impl<const ALIGN: usize> core::ops::Add<usize> for NonZeroPageSize<ALIGN> {
    type Output = Option<Self>;

    fn add(self, rhs: usize) -> Self::Output {
        NonZeroPageSize::new(self.size + rhs)
    }
}

/// A non-zero address that is `ALIGN`-aligned.
#[derive(Clone, Copy)]
pub struct NonZeroAddress<const ALIGN: usize>(usize);

impl<const ALIGN: usize> NonZeroAddress<ALIGN> {
    /// Create a new `NonZeroAddress`, if the address is non-zero and aligned.
    pub fn new(address: usize) -> Option<Self> {
        if address == 0 || !address.is_multiple_of(ALIGN) {
            return None;
        }
        Some(Self(address))
    }

    /// Get the address
    #[inline]
    pub fn as_usize(self) -> usize {
        self.0
    }
}

static NEXT_SHARED_FUTEX_BACKING_ID: AtomicUsize = AtomicUsize::new(1);

/// Stable identity of one shared memory backing object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedFutexBacking {
    identity: usize,
}

impl SharedFutexBacking {
    /// Allocates a process-wide identity that is never reused.
    ///
    /// # Panics
    ///
    /// Panics if the process has exhausted the `usize` identity space (never
    /// happens in practice).
    pub fn new() -> Self {
        let identity = NEXT_SHARED_FUTEX_BACKING_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |identity| {
                identity.checked_add(1)
            })
            .expect("shared futex backing identity space exhausted");
        Self { identity }
    }

    /// Returns this backing object's process-wide stable identity.
    pub fn identity(self) -> usize {
        self.identity
    }
}

impl Default for SharedFutexBacking {
    fn default() -> Self {
        Self::new()
    }
}

/// Never-reused identity of a mapping while its initialization callback runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct InitializationId(usize);

/// Virtual memory area
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VmArea {
    /// Flags describing the properties of the memory region.
    flags: VmFlags,
    /// Whether this area is backed by a file
    is_file_backed: bool,
    /// Identity and original virtual origin of shared backing, used to derive futex keys that
    /// survive virtual-address moves without aliasing unrelated shared mappings.
    shared_futex: Option<SharedFutexMapping>,
    /// Distinguishes adjacent mappings while either initialization still owns its exact range.
    initialization: Option<InitializationId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SharedFutexPosition {
    PendingOffset(usize),
    Origin(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SharedFutexMapping {
    identity: usize,
    position: SharedFutexPosition,
}

impl VmArea {
    /// Get the [flags](`VmFlags`) of this memory area.
    #[inline]
    pub(super) fn flags(self) -> VmFlags {
        self.flags
    }

    /// Check if this area is backed by a file.
    #[inline]
    pub(super) fn is_file_backed(self) -> bool {
        self.is_file_backed
    }

    /// Create a new [`VmArea`] with the given flags.
    #[inline]
    pub(super) fn new(
        flags: VmFlags,
        is_file_backed: bool,
        shared_futex_backing: Option<(SharedFutexBacking, usize)>,
    ) -> Self {
        Self {
            flags,
            is_file_backed,
            shared_futex: shared_futex_backing.map(|(backing, offset)| SharedFutexMapping {
                identity: backing.identity,
                position: SharedFutexPosition::PendingOffset(offset),
            }),
            initialization: None,
        }
    }
}

/// Virtual Memory Manager
///
/// This struct mantains the virtual memory ranges backed by a memory [backend](PageManagementProvider).
/// Each range needs to be `ALIGN`-aligned.
pub(super) struct Vmem<Platform: PageManagementProvider<ALIGN> + 'static, const ALIGN: usize> {
    /// Memory backend that provides the actual memory.
    pub(super) platform: &'static Platform,
    /// Current program break address.
    pub(super) brk: usize,
    /// Virtual memory areas.
    vmas: RangeMap<usize, VmArea>,
    /// Temporary ownership of mappings whose caller callback has not returned.
    pending_initializations: RangeMap<usize, InitializationId>,
    /// Next callback identity. Zero is never issued and identities are never reused.
    next_initialization_id: usize,
    /// Address ranges a caller has claimed as logically owned without (or no longer) having a
    /// live mapping here -- disjoint, start -> end. A flexible (non-`MAP_FIXED`) placement search
    /// treats these exactly like a live `vmas` entry: occupied, never handed out. `MAP_FIXED`
    /// requests are unaffected (see `get_unmmaped_area`'s `fixed_addr` branch), matching the
    /// narrow problem this exists for: a shared, single flat address space faking multiple guest
    /// processes by taking turns (`litebox_shim_linux`'s `SharedAddressSpace`) can have one member
    /// "parked" -- its memory copied out, its addresses momentarily absent from `vmas` -- while
    /// another member of the same family keeps running and, on `execve`, tears down and rebuilds
    /// its own (shared) `vmas` entries. Nothing stopped the fresh image's flexible placement from
    /// landing on exactly the addresses the parked member still remembers and will later try to
    /// restore into, corrupting or safely-but-fatally colliding with whatever is there by then.
    /// The park/restore machinery reserves a member's saved ranges here for exactly as long as it
    /// is parked, so a fresh placement is steered elsewhere instead.
    reserved: BTreeMap<usize, usize>,
}

impl<Platform: PageManagementProvider<ALIGN> + 'static, const ALIGN: usize> Vmem<Platform, ALIGN> {
    pub(super) const STACK_GUARD_GAP: usize = 256 << 12;

    /// Create a new [`Vmem`] instance with the given memory [backend](PageManagementProvider).
    pub(super) fn new(platform: &'static Platform) -> Self {
        let mut vmem = Self {
            vmas: RangeMap::new(),
            pending_initializations: RangeMap::new(),
            next_initialization_id: 1,
            brk: 0,
            platform,
            reserved: BTreeMap::new(),
        };
        for each in platform.reserved_pages() {
            assert!(
                each.start % ALIGN == 0 && each.end % ALIGN == 0,
                "Vmem: reserved range is not aligned to {ALIGN} bytes"
            );
            vmem.vmas.insert(
                each.start..each.end,
                VmArea {
                    flags: VmFlags::empty(),
                    is_file_backed: false,
                    shared_futex: None,
                    initialization: None,
                },
            );
        }
        vmem
    }

    /// Gets an iterator over all pairs of ([`Range<usize>`], [`VmArea`]),
    /// ordered by key range.
    pub(super) fn iter(&self) -> impl Iterator<Item = (&Range<usize>, &VmArea)> {
        self.vmas.iter()
    }

    /// Reserves a callback identity before publishing the mapping it will own.
    /// Consumed identities are deliberately not reused, including when allocation fails.
    pub(super) fn reserve_initialization_id(&mut self) -> Result<InitializationId, MappingError> {
        let identity = self.next_initialization_id;
        self.next_initialization_id = identity
            .checked_add(1)
            .ok_or(MappingError::InitializationIdentityExhausted)?;
        Ok(InitializationId(identity))
    }

    /// Marks a newly-published mapping as owned by one initialization callback.
    pub(super) fn track_initialization(
        &mut self,
        range: PageRange<ALIGN>,
        identity: InitializationId,
    ) {
        let tracked = Range::from(range);
        let mut vma = {
            let (mapped, vma) = self
                .vmas
                .get_key_value(&tracked.start)
                .expect("a newly created mapping must be tracked");
            assert!(
                mapped.end >= tracked.end,
                "a new mapping must be contiguous"
            );
            *vma
        };
        vma.initialization = Some(identity);
        self.vmas.insert(tracked.clone(), vma);
        self.pending_initializations.insert(tracked, identity);
    }

    /// Returns whether the complete range still belongs to the original callback.
    pub(super) fn owns_initialization(
        &self,
        range: PageRange<ALIGN>,
        identity: InitializationId,
    ) -> bool {
        self.pending_initializations
            .get_key_value(&range.start)
            .is_some_and(|(owned, current)| {
                *current == identity && owned.start <= range.start && owned.end >= range.end
            })
    }

    pub(super) fn has_pending_initialization(&self, range: &Range<usize>) -> bool {
        self.pending_initializations.overlaps(range)
    }

    fn clear_initialization_markers(&mut self, range: Range<usize>) {
        let pieces: Vec<(Range<usize>, VmArea)> = self
            .vmas
            .overlapping(range.clone())
            .filter(|(_, vma)| vma.initialization.is_some())
            .map(|(mapped, vma)| {
                (
                    mapped.start.max(range.start)..mapped.end.min(range.end),
                    *vma,
                )
            })
            .collect();
        for (piece, mut vma) in pieces {
            vma.initialization = None;
            self.vmas.insert(piece, vma);
        }
    }

    /// Completes a callback after its exact mapping has been finalized.
    pub(super) fn finish_initialization(
        &mut self,
        range: PageRange<ALIGN>,
        identity: InitializationId,
    ) -> bool {
        if !self.owns_initialization(range, identity) {
            return false;
        }
        let range = Range::from(range);
        self.pending_initializations.remove(range.clone());
        self.clear_initialization_markers(range);
        true
    }

    /// Removes only fragments still owned by `identity`, never a same-address replacement.
    pub(super) unsafe fn cleanup_initialization(
        &mut self,
        range: PageRange<ALIGN>,
        identity: InitializationId,
    ) -> Result<(), VmemUnmapError> {
        let requested = Range::from(range);
        let pieces: Vec<Range<usize>> = self
            .pending_initializations
            .overlapping(requested.clone())
            .filter(|(_, current)| **current == identity)
            .filter_map(|(owned, _)| {
                let piece = owned.start.max(requested.start)..owned.end.min(requested.end);
                (!piece.is_empty()).then_some(piece)
            })
            .collect();
        let mut first_error = None;
        for piece in pieces {
            match unsafe { self.platform.deallocate_pages(piece.clone()) } {
                Ok(()) => {
                    self.vmas.remove(piece.clone());
                    self.pending_initializations.remove(piece);
                }
                Err(error) => {
                    first_error.get_or_insert(VmemUnmapError::UnmapError(error));
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn invalidate_initializations(&mut self, range: Range<usize>) {
        self.pending_initializations.remove(range.clone());
        self.clear_initialization_markers(range);
    }

    /// Returns the flags for the mapping containing `address`.
    pub(super) fn flags_at(&self, address: usize) -> Option<VmFlags> {
        self.vmas
            .get_key_value(&address)
            .map(|(_, vma)| vma.flags())
    }

    /// Returns a shared-backing futex identity and byte offset for `address`.
    pub(super) fn shared_futex_key_at(&self, address: usize) -> Option<(usize, usize)> {
        let (_, vma) = self.vmas.get_key_value(&address)?;
        let shared = vma.shared_futex?;
        let SharedFutexPosition::Origin(origin) = shared.position else {
            return None;
        };
        Some((shared.identity, address.wrapping_sub(origin)))
    }

    #[allow(
        clippy::unused_self,
        reason = "instance method on the owning map for API consistency"
    )]
    fn assign_shared_futex_identity(&mut self, vma: &mut VmArea, origin: usize) {
        if !vma.flags.contains(VmFlags::VM_SHARED) {
            vma.shared_futex = None;
            return;
        }
        match vma.shared_futex {
            Some(SharedFutexMapping {
                identity,
                position: SharedFutexPosition::PendingOffset(offset),
            }) => {
                vma.shared_futex = Some(SharedFutexMapping {
                    identity,
                    position: SharedFutexPosition::Origin(origin.wrapping_sub(offset)),
                });
            }
            Some(SharedFutexMapping {
                position: SharedFutexPosition::Origin(_),
                ..
            }) => {}
            None => {
                vma.shared_futex = Some(SharedFutexMapping {
                    identity: SharedFutexBacking::new().identity,
                    position: SharedFutexPosition::Origin(origin),
                });
            }
        }
    }

    /// Insert an already-allocated region (e.g., via CoW) without calling the platform allocator.
    ///
    /// Any existing tracked mappings that overlap `range` are silently removed from tracking
    /// (without calling the platform deallocator) before inserting. Use [`Self::overlapping`] to
    /// check for overlap before running this if needed.
    pub(super) fn register_existing_mapping_overwrite(
        &mut self,
        range: PageRange<ALIGN>,
        mut vma: VmArea,
    ) {
        self.assign_shared_futex_identity(&mut vma, range.start);
        let range = Range::from(range);
        self.vmas.insert(range.clone(), vma);
        self.invalidate_initializations(range);
    }

    /// Gets an iterator over all the stored ranges that are
    /// either partially or completely overlapped by the given range.
    pub(super) fn overlapping(
        &self,
        range: Range<usize>,
    ) -> impl DoubleEndedIterator<Item = (&Range<usize>, &VmArea)> {
        self.vmas.overlapping(range)
    }

    /// Remove a range from its virtual address space, if all or any of it was present.
    ///
    /// If the range to be removed _partially_ overlaps any ranges, then those ranges will
    /// be contracted to no longer cover the removed range.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    pub(super) unsafe fn remove_mapping(
        &mut self,
        range: PageRange<ALIGN>,
    ) -> Result<(), VmemUnmapError> {
        // Trace-gated twin of `insert_mapping`'s replace log: in a
        // process-blind manager shared by several guest processes, every
        // removal is a potential cross-process teardown, and knowing exactly
        // which ranges were removed (correlated with the shim's own
        // pid/tid-stamped syscall trace) is what pins down who removed them.
        litebox_util_log::trace!(
            start:? = range.start, end:? = range.end;
            "removing mapping"
        );
        let range = Range::from(range);
        let deferred_pieces: alloc::vec::Vec<Range<usize>> = self
            .overlapping(range.clone())
            .filter(|(_, vma)| vma.flags.contains(VmFlags::VM_DEFERRED))
            .map(|(r, _)| r.clone())
            .collect();
        if deferred_pieces.is_empty() {
            unsafe {
                self.platform
                    .deallocate_pages(range.clone())
                    .map_err(VmemUnmapError::UnmapError)?;
            }
        } else {
            // Deferred (VM_DEFERRED) pieces have no platform state to tear
            // down; deallocating the whole range would ask the platform to
            // unmap pages it never mapped. Deallocate only the pieces that
            // were actually materialized.
            let pieces: alloc::vec::Vec<(Range<usize>, VmArea)> = self
                .overlapping(range.clone())
                .map(|(r, vma)| (r.clone(), *vma))
                .collect();
            for (r, vma) in pieces {
                if vma.flags.contains(VmFlags::VM_DEFERRED) {
                    continue;
                }
                let piece = r.start.max(range.start)..r.end.min(range.end);
                if piece.is_empty() {
                    continue;
                }
                unsafe {
                    self.platform
                        .deallocate_pages(piece)
                        .map_err(VmemUnmapError::UnmapError)?;
                }
            }
        }
        self.vmas.remove(range.clone());
        self.invalidate_initializations(range);
        Ok(())
    }

    /// Reset pages without removing its mapping (similar to Linux `madvise` with
    /// `MADV_DONTNEED` or `MADV_FREE`).
    ///
    /// If `anonymous_only` is true and any part of the range is non‑anonymous (i.e., file‑backed),
    /// returns `Err(VmemResetError::FileBacked)`.
    ///
    /// The current implementation effectively re-inserts the mapping with the same
    /// `VmArea` properties, which will cause the pages to be unmapped and mapped again.
    ///
    /// # Panics
    ///
    /// File-backed mapping is not supported yet.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory contents in the affected region are no longer accessed or
    /// relied upon. Any pointers or references to the previous contents become invalid.
    pub(super) unsafe fn reset_pages(
        &mut self,
        range: PageRange<ALIGN>,
        anonymous_only: bool,
    ) -> Result<(), VmemResetError> {
        let range: Range<usize> = range.into();
        // Any unmapped regions in the original range will result in this function returning `DeallocationError::AlreadyUnallocated`
        // while still resetting all of the existing vmas in the range.
        let unmapped_error = self.vmas.gaps(&range).next().is_some();
        let overlapping_ranges: Vec<(Range<usize>, VmArea)> = self
            .overlapping(range.clone())
            .map(|(r, vma)| (r.clone(), *vma))
            .collect();
        for (r, vma) in overlapping_ranges {
            if vma.is_file_backed() {
                if anonymous_only {
                    return Err(VmemResetError::FileBacked);
                }
                unimplemented!("resetting file-backed mappings is not supported yet");
            }
            if vma.flags.contains(VmFlags::VM_DEFERRED) {
                // A deferred reservation has no contents to invalidate: it is
                // still pure VA bookkeeping, exactly the state a reset would
                // restore.
                continue;
            }
            let start = r.start.max(range.start);
            let end = r.end.min(range.end);
            let new_range = PageRange::new(start, end).unwrap();
            unsafe { self.insert_mapping(new_range, vma, false, FixedAddressBehavior::Replace) }
                .expect("failed to reset pages");
        }
        if unmapped_error {
            Err(VmemResetError::AlreadyUnallocated)
        } else {
            Ok(())
        }
    }

    /// Insert a range to its virtual address space.
    ///
    /// If the inserted range partially or completely overlaps any
    /// existing range in the map, then the existing range (or ranges) will be
    /// partially or completely replaced by the inserted range.
    ///
    /// If the inserted range either overlaps or is immediately adjacent
    /// any existing range _mapping to the same value_, then the ranges
    /// will be coalesced into a single contiguous range.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is not used by any other (i.e., safe
    /// to unmap all overlapping mappings if any).
    pub(super) unsafe fn insert_mapping(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        mut vma: VmArea,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError> {
        let (start, end) = (suggested_range.start, suggested_range.end);
        if start < Platform::TASK_ADDR_MIN {
            return Err(AllocationError::BelowMinAddress);
        }
        if end > Platform::TASK_ADDR_MAX {
            return Err(AllocationError::AboveMaxAddress);
        }
        if vma.flags.contains(VmFlags::VM_DEFERRED) {
            // A deferred reservation is pure VA bookkeeping: the platform is
            // engaged only when the range is materialized (see
            // `protect_mapping`). Fresh placements arrive with no overlap by
            // `get_unmmaped_area` construction, and `reset_pages` never
            // re-inserts a deferred area, so any overlap here would mean
            // skipping a live mapping's platform teardown -- refuse it loudly
            // instead of leaking it.
            if self.vmas.overlaps(&(start..end)) {
                return Err(AllocationError::AddressInUse);
            }
            self.vmas.insert(start..end, vma);
            self.invalidate_initializations(start..end);
            return Ok(Platform::RawMutPointer::from_usize(start));
        }
        let platform_fixed_address_behavior = match fixed_address_behavior {
            FixedAddressBehavior::Hint => FixedAddressBehavior::Hint,
            FixedAddressBehavior::NoReplace => {
                // Ensure there are no mappings managed by us.
                if self.vmas.overlaps(&(start..end)) {
                    return Err(AllocationError::AddressInUse);
                }
                FixedAddressBehavior::NoReplace
            }
            FixedAddressBehavior::Replace => {
                if self.vmas.overlaps(&(start..end)) {
                    // A fixed mapping quietly destroying live mappings is the
                    // correct MAP_FIXED semantic *within one process*, but in
                    // this process-blind manager it is also how one guest
                    // process can destroy another's memory -- worth a
                    // permanent record whenever it fires.
                    litebox_util_log::debug!(
                        start:? = start, end:? = end;
                        "fixed-address mapping replaces existing mapping(s)"
                    );
                    if self.vmas.gaps(&(start..end)).next().is_some() {
                        // The range is partially overlapping with existing
                        // mappings. If we call into the platform with
                        // `Replace`, then it may overwrite external mappings
                        // that are not managed by us.
                        //
                        // FUTURE: support this case, either by splitting this
                        // into multiple allocate calls or by separating VA
                        // allocation from page backing.
                        return Err(AllocationError::AddressPartiallyInUse);
                    }
                    FixedAddressBehavior::Replace
                } else {
                    // There are no mappings managed by us, so just treat this
                    // as NoReplace.
                    FixedAddressBehavior::NoReplace
                }
            }
        };
        if vma.flags.contains(VmFlags::VM_SHARED) && vma.shared_futex.is_none() {
            vma.shared_futex = Some(SharedFutexMapping {
                identity: SharedFutexBacking::new().identity,
                position: SharedFutexPosition::PendingOffset(0),
            });
        }
        let shared_allocation = vma.shared_futex.map(|shared| {
            let offset = match shared.position {
                SharedFutexPosition::PendingOffset(offset) => offset,
                SharedFutexPosition::Origin(origin) => start.wrapping_sub(origin),
            };
            (shared.identity, offset)
        });
        let permissions: u8 = vma
            .flags
            .intersection(VmFlags::VM_ACCESS_FLAGS)
            .bits()
            .try_into()
            .unwrap();
        let max_permissions: u8 = (vma.flags.intersection(VmFlags::VM_MAY_ACCESS_FLAGS).bits()
            >> 4)
            .try_into()
            .unwrap();
        // The `max_permissions` is tracked by `VMem::protect_mapping` and thus doesn't need to be
        // passed to `allocate_pages`.
        let _ = max_permissions;
        let permissions = MemoryRegionPermissions::from_bits(permissions).unwrap();
        let suggested_range = Range::from(suggested_range);
        let suggested_len = suggested_range.len();
        let ret = if let Some((identity, offset)) = shared_allocation {
            self.platform.allocate_shared_pages(
                identity,
                offset,
                suggested_range,
                permissions,
                vma.flags.contains(VmFlags::VM_GROWSDOWN),
                populate_pages_immediately,
                platform_fixed_address_behavior,
            )
        } else {
            self.platform.allocate_pages(
                suggested_range,
                permissions,
                vma.flags.contains(VmFlags::VM_GROWSDOWN),
                populate_pages_immediately,
                platform_fixed_address_behavior,
            )
        }
        .map_err(|err| match err {
            AllocationError::AddressInUse => AllocationError::AddressInUseByPlatform,
            other => other,
        })?;
        let new_start = ret.as_usize();
        let new_end = new_start + suggested_len;
        self.assign_shared_futex_identity(&mut vma, new_start);
        let installed = new_start..new_end;
        self.vmas.insert(installed.clone(), vma);
        self.invalidate_initializations(installed);
        debug_assert!(new_start >= Platform::TASK_ADDR_MIN);
        debug_assert!(new_end <= Platform::TASK_ADDR_MAX);
        Ok(ret)
    }

    /// Create a new mapping in the virtual address space.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// Return `Some(new_addr)` if the mapping is created successfully.
    /// The returned address is `ALIGN`-aligned.
    ///
    /// # Fixed Address Behavior
    ///
    /// - [`CreatePagesFlags::FIXED_ADDR`] alone: Forces allocation at the exact address, replacing
    ///   any existing overlapping mappings. Caller must ensure overlapping mappings are not in use.
    /// - [`CreatePagesFlags::FIXED_ADDR`] with [`CreatePagesFlags::NOREPLACE`]: Forces allocation at
    ///   the exact address, but fails with [`AllocationError::AddressInUse`] if any part of the
    ///   range is already mapped. This is safe to use without checking for existing mappings first.
    /// - Without [`CreatePagesFlags::FIXED_ADDR`], the address is treated as a hint.
    ///
    /// Note: `NOREPLACE` error responses (`AddressInUse` / `EEXIST`) can be used to probe memory
    /// layout. This matches Linux kernel behavior for `MAP_FIXED_NOREPLACE`.
    ///
    /// # Safety
    ///
    /// When using [`CreatePagesFlags::FIXED_ADDR`] without [`CreatePagesFlags::NOREPLACE`], the
    /// caller must ensure any overlapping mappings are not used by any other code, as they will be
    /// unmapped.
    pub(super) unsafe fn create_mapping(
        &mut self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        vma: VmArea,
        flags: CreatePagesFlags,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError> {
        let total_length = (length
            + if flags.contains(CreatePagesFlags::ENSURE_SPACE_AFTER) {
                DEFAULT_RESERVED_SPACE_SIZE
            } else {
                0
            })
        .unwrap();
        let new_addr = self
            .get_unmmaped_area(
                suggested_address,
                total_length,
                flags.contains(CreatePagesFlags::FIXED_ADDR),
            )
            .ok_or(AllocationError::OutOfMemory)?;
        // new_addr must be ALIGN aligned
        let new_range = PageRange::new(new_addr, new_addr + length.as_usize()).unwrap();
        unsafe {
            self.insert_mapping(
                new_range,
                vma,
                flags.contains(CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY),
                if flags.contains(CreatePagesFlags::FIXED_ADDR) {
                    if flags.contains(CreatePagesFlags::NOREPLACE) {
                        FixedAddressBehavior::NoReplace
                    } else {
                        FixedAddressBehavior::Replace
                    }
                } else {
                    FixedAddressBehavior::Hint
                },
            )
        }
    }

    /// Resize a range in the virtual address space.
    /// Shrink the range if it is larger than `new_size`.
    /// Enlarge the range if it is smaller than `new_size` and will not overlap with
    /// next mapping after the expansion.
    ///
    /// It fails if it resizes more than one mapping or needs to split the current mapping
    /// (due to enlarging).
    ///
    /// See <https://elixir.bootlin.com/linux/v5.19.17/source/mm/mremap.c#L886> for reference.
    ///
    /// # Safety
    ///
    /// If it shrinks, the caller must ensure that the unmapped memory region is not used by any other.
    pub(super) unsafe fn resize_mapping(
        &mut self,
        range: PageRange<ALIGN>,
        new_size: NonZeroPageSize<ALIGN>,
    ) -> Result<(), VmemResizeError> {
        let range = range.start..range.end;
        // `cur_range` contains `range.start`
        let (cur_range, cur_vma) = self
            .vmas
            .get_key_value(&range.start)
            .ok_or(VmemResizeError::NotExist(range.start))?;

        let new_end = range.start + new_size.as_usize();
        if new_end == range.end {
            return Ok(());
        }
        if range.end > cur_range.end {
            return Err(VmemResizeError::InvalidAddr {
                range: cur_range.clone(),
                addr: range.end,
            });
        }
        if self.has_pending_initialization(&range) {
            return Err(VmemResizeError::InitializationPending(range));
        }
        if new_end < range.end {
            let removed = PageRange::new(new_end, range.end).unwrap();
            unsafe { self.remove_mapping(removed) }.map_err(VmemResizeError::UnmapError)?;
            return Ok(());
        }

        // grow
        if range.end == cur_range.end {
            // expand the current range
            let r = range.end..new_end;
            if self.vmas.overlaps(&r) {
                return Err(VmemResizeError::RangeOccupied(r));
            }
            // A private file-backed mapping grown past its original extent gets
            // anonymous zero-fill pages for the new range, exactly as Linux's own
            // `mremap` does: nothing re-reads more file content in just because the
            // mapping got bigger, and `insert_mapping` below never populates content
            // itself either way (the caller's initial `mmap` copies file bytes in as
            // a separate step; growing calls no such step). Tagging the new piece
            // `is_file_backed: false` -- instead of cloning `*cur_vma` verbatim --
            // matters beyond bookkeeping accuracy: `reset_pages`/`set_wipe_on_fork`
            // both refuse to touch a range they see as file-backed, and this tail is
            // genuinely anonymous memory now, so it must qualify for both.
            let new_piece_vma =
                if cur_vma.is_file_backed() && !cur_vma.flags.contains(VmFlags::VM_SHARED) {
                    VmArea::new(cur_vma.flags, false, None)
                } else {
                    *cur_vma
                };
            let range = PageRange::new(range.end, new_end).unwrap();
            // Try to extend the mapping. Although we checked that there are no
            // litebox mappings in this range, this may fail if there are
            // platform mappings in the way.
            match unsafe {
                self.insert_mapping(range, new_piece_vma, false, FixedAddressBehavior::NoReplace)
            } {
                Ok(_) => {}
                Err(AllocationError::OutOfMemory) => return Err(VmemResizeError::OutOfMemory),
                Err(
                    AllocationError::AddressInUse
                    | AllocationError::AddressInUseByPlatform
                    | AllocationError::AddressPartiallyInUse,
                ) => return Err(VmemResizeError::RangeOccupied(range.into())),
                Err(
                    AllocationError::Unaligned
                    | AllocationError::BelowMinAddress
                    | AllocationError::AboveMaxAddress,
                ) => unreachable!(),
            }
            return Ok(());
        }

        // has to split the current range and move it to somewhere else
        Err(VmemResizeError::RangeOccupied(range.end..cur_range.end))
    }

    /// Move a range from `old_range` to `suggested_new_range`.
    /// Use it together with [`Vmem::resize_mapping`] to achieve `mremap`.
    ///
    /// The `suggested_new_range.start` is used as a hint for the new address.
    /// If it is zero, kernel will choose a new suitable address freely.
    ///
    /// Returns `Some(new_addr)` if the range is moved successfully
    /// Otherwise, returns `None`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the given `range` is safe to be unmapped.
    ///
    /// # Panics
    ///
    /// Panics if the size of `suggested_new_range` is smaller than the size of `old_range`.
    /// Panics if the `old_range` is not covered by exactly one mapping.
    pub(super) unsafe fn move_mappings(
        &mut self,
        old_range: PageRange<ALIGN>,
        suggested_new_address: Option<NonZeroAddress<ALIGN>>,
        new_size: NonZeroPageSize<ALIGN>,
    ) -> Result<Platform::RawMutPointer<u8>, VmemMoveError> {
        assert!(new_size.as_usize() >= old_range.len());

        // Check if the given range is covered by exactly one mapping
        let (cur_range, vma) = self
            .vmas
            .get_key_value(&old_range.start)
            .expect("VMEM: range not found");
        assert!(cur_range.contains(&(old_range.end - 1)));
        if self.has_pending_initialization(&Range::from(old_range)) {
            return Err(VmemMoveError::OutOfMemory);
        }

        if vma.is_file_backed() && !vma.flags.contains(VmFlags::VM_SHARED) {
            unimplemented!("private file-backed mapping move is not supported yet");
        }
        let new_addr = self
            .get_unmmaped_area(suggested_new_address, new_size, false)
            .ok_or(VmemMoveError::OutOfMemory)?;
        let new_range = PageRange::<ALIGN>::new(new_addr, new_addr + new_size.as_usize()).unwrap();
        let shared_remap = vma.shared_futex.map(|shared| {
            let SharedFutexPosition::Origin(origin) = shared.position else {
                unreachable!("installed shared futex mappings always have an origin")
            };
            (shared.identity, old_range.start.wrapping_sub(origin))
        });
        let new_addr = unsafe {
            if let Some((identity, offset)) = shared_remap {
                self.platform.remap_shared_pages(
                    identity,
                    offset,
                    old_range.into(),
                    new_range.into(),
                    vma.flags.into(),
                )
            } else {
                self.platform
                    .remap_pages(old_range.into(), new_range.into(), vma.flags.into())
            }
        }
        .map_err(VmemMoveError::RemapError)?;

        let mut moved_vma = *vma;
        let new_start = new_addr.as_usize();
        let new_end = new_start + new_size.as_usize();
        if let Some(shared) = &mut moved_vma.shared_futex {
            let SharedFutexPosition::Origin(origin) = &mut shared.position else {
                unreachable!("installed shared futex mappings always have an origin")
            };
            let old_offset = old_range.start.wrapping_sub(*origin);
            *origin = new_start.wrapping_sub(old_offset);
        }
        let installed = new_start..new_end;
        self.vmas.insert(installed.clone(), moved_vma);
        self.vmas.remove(old_range.into());
        self.invalidate_initializations(installed);
        self.invalidate_initializations(old_range.into());
        Ok(new_addr)
    }

    fn record_protected_piece(
        &mut self,
        original: Range<usize>,
        intersection: Range<usize>,
        vma: VmArea,
        flags: VmFlags,
    ) {
        self.vmas.remove(original.clone());
        let before = original.start..intersection.start;
        let after = intersection.end..original.end;
        self.vmas.insert(
            intersection,
            VmArea {
                flags,
                is_file_backed: vma.is_file_backed,
                shared_futex: vma.shared_futex,
                initialization: vma.initialization,
            },
        );
        if !before.is_empty() {
            self.vmas.insert(before, vma);
        }
        if !after.is_empty() {
            self.vmas.insert(after, vma);
        }
    }

    /// Sets (`MADV_WIPEONFORK`) or clears (`MADV_KEEPONFORK`) [`VmFlags::VM_WIPEONFORK`] on
    /// every mapping overlapping `range`, splitting mappings at the range's edges exactly as
    /// [`Self::protect_mapping`] does for access flags.
    ///
    /// Mirrors Linux's `madvise_vma_behavior`: the flag is refused with `EINVAL` on a
    /// file-backed or shared mapping (there is no private copy to wipe), and a hole in the
    /// range is `ENOMEM`. Every mapping is validated before any is changed, so an error
    /// leaves the flags as they were. A `VM_DEFERRED` reservation can carry the flag -- it is
    /// pure bookkeeping until the reservation is materialized, and a wipe of it is a no-op
    /// because it has no contents yet.
    pub(super) fn set_wipe_on_fork(
        &mut self,
        range: PageRange<ALIGN>,
        enable: bool,
    ) -> Result<(), VmemWipeOnForkError> {
        let range = range.start..range.end;
        let pieces: Vec<(Range<usize>, Range<usize>, VmArea)> = self
            .vmas
            .overlapping(range.clone())
            .map(|(mapped, vma)| {
                (
                    mapped.clone(),
                    mapped.start.max(range.start)..mapped.end.min(range.end),
                    *vma,
                )
            })
            .collect();
        let mut covered = range.start;
        let mut holes = false;
        for (_, intersection, vma) in &pieces {
            if intersection.start != covered {
                holes = true;
            }
            covered = intersection.end;
            if enable && (vma.is_file_backed || vma.flags.contains(VmFlags::VM_SHARED)) {
                return Err(VmemWipeOnForkError::NotPrivateAnonymous(
                    intersection.clone(),
                ));
            }
        }
        if covered != range.end {
            holes = true;
        }
        for (original, intersection, vma) in pieces {
            if vma.flags.contains(VmFlags::VM_WIPEONFORK) == enable {
                continue;
            }
            let mut flags = vma.flags;
            flags.set(VmFlags::VM_WIPEONFORK, enable);
            self.record_protected_piece(original, intersection, vma, flags);
        }
        if holes {
            return Err(VmemWipeOnForkError::Unmapped(range));
        }
        Ok(())
    }

    /// Every mapping carrying [`VmFlags::VM_WIPEONFORK`], with its flags, in address order.
    pub(super) fn wipe_on_fork_ranges(&self) -> Vec<(Range<usize>, VmFlags)> {
        self.vmas
            .iter()
            .filter(|(_, vma)| vma.flags.contains(VmFlags::VM_WIPEONFORK))
            .map(|(r, vma)| (r.clone(), vma.flags))
            .collect()
    }

    /// Change the permissions ([`VmFlags::VM_ACCESS_FLAGS`]) of a range in the virtual address space.
    ///
    /// See <https://elixir.bootlin.com/linux/v5.19.17/source/mm/mprotect.c#L617> for reference.
    ///
    /// # Safety
    ///
    /// The caller must ensure it is safe to change the permissions of the given range, e.g., no more
    /// write access to the range if it is changed to read-only.
    pub(super) unsafe fn protect_mapping(
        &mut self,
        range: PageRange<ALIGN>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        // `MemoryRegionPermissions` is a subset of `VmFlags` and we only change the access flags
        let flags =
            VmFlags::from_bits(u32::from(permissions.bits())).unwrap() & VmFlags::VM_ACCESS_FLAGS;
        let range = range.start..range.end;
        let mappings_to_change: Vec<(Range<usize>, Range<usize>, VmArea)> = self
            .vmas
            .overlapping(range.clone())
            .map(|(mapped, vma)| {
                (
                    mapped.clone(),
                    mapped.start.max(range.start)..mapped.end.min(range.end),
                    *vma,
                )
            })
            .collect();
        let mut covered = range.start;
        for (_, intersection, vma) in &mappings_to_change {
            if intersection.start != covered {
                return Err(VmemProtectError::InvalidRange(range));
            }
            covered = intersection.end;
            if (!(vma.flags.bits() >> 4) & flags.bits()) & VmFlags::VM_ACCESS_FLAGS.bits() != 0 {
                return Err(VmemProtectError::NoAccess {
                    old: vma.flags,
                    new: flags,
                });
            }
        }
        if covered != range.end {
            return Err(VmemProtectError::InvalidRange(range));
        }
        if mappings_to_change
            .iter()
            .all(|(_, _, vma)| vma.flags & VmFlags::VM_ACCESS_FLAGS == flags)
        {
            return Ok(());
        }

        let any_deferred = mappings_to_change
            .iter()
            .any(|(_, _, vma)| vma.flags.contains(VmFlags::VM_DEFERRED));

        if self.platform.has_transactional_permission_updates() && !any_deferred {
            // This provider explicitly guarantees that an ordinary error means
            // no page changed; HVF uses process-abort containment after any
            // lower publication. One call therefore closes the multi-VMA
            // partial-progress boundary without assuming the same of native
            // providers with reservation or backing boundaries.
            unsafe { self.platform.update_permissions(range.clone(), permissions) }
                .map_err(VmemProtectError::ProtectError)?;
            for (original, intersection, vma) in mappings_to_change {
                if vma.flags & VmFlags::VM_ACCESS_FLAGS != flags {
                    let new_flags = (vma.flags & !VmFlags::VM_ACCESS_FLAGS) | flags;
                    self.record_protected_piece(original, intersection, vma, new_flags);
                }
            }
            return Ok(());
        }

        // Native providers retain their individual mapping boundaries. All
        // coverage and VM_MAY checks above complete before the first mutation,
        // so no deterministic validation failure can follow earlier progress.
        //
        // A deferred (VM_DEFERRED) piece has no platform state yet: it is
        // *materialized* here -- freshly allocated with the requested access --
        // rather than permission-updated. With EXECUTE in the target, the
        // allocation is made non-executable first and then updated, because
        // platforms are entitled to refuse born-executable allocations (the
        // HVF memory manager does: `HvfMemoryError::InitialExecute`).
        for (original, intersection, vma) in mappings_to_change {
            if vma.flags & VmFlags::VM_ACCESS_FLAGS == flags {
                continue;
            }
            if vma.flags.contains(VmFlags::VM_DEFERRED) {
                let wants_exec = flags.contains(VmFlags::VM_EXEC);
                let allocate_perms = if wants_exec {
                    (permissions & !crate::platform::page_mgmt::MemoryRegionPermissions::EXEC)
                        | crate::platform::page_mgmt::MemoryRegionPermissions::READ
                } else {
                    permissions
                };
                self.platform
                    .allocate_pages(
                        intersection.clone(),
                        allocate_perms,
                        false,
                        false,
                        crate::platform::page_mgmt::FixedAddressBehavior::NoReplace,
                    )
                    .map_err(VmemProtectError::DeferredAllocate)?;
                if wants_exec {
                    unsafe {
                        self.platform
                            .update_permissions(intersection.clone(), permissions)
                    }
                    .map_err(VmemProtectError::ProtectError)?;
                }
                let new_flags =
                    (vma.flags & !VmFlags::VM_ACCESS_FLAGS & !VmFlags::VM_DEFERRED) | flags;
                self.record_protected_piece(original, intersection, vma, new_flags);
                continue;
            }
            unsafe {
                self.platform
                    .update_permissions(intersection.clone(), permissions)
            }
            .map_err(VmemProtectError::ProtectError)?;
            let new_flags = (vma.flags & !VmFlags::VM_ACCESS_FLAGS) | flags;
            self.record_protected_piece(original, intersection, vma, new_flags);
        }

        Ok(())
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
    /// `perm` is the permissions to set for the created pages.
    ///
    /// # Safety
    ///
    /// Note that if the suggested address is given and [`CreatePagesFlags::FIXED_ADDR`] is set,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    ///
    /// Also, caller must ensure flags are set correctly.
    pub(super) unsafe fn create_pages(
        &mut self,
        suggested_new_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        perms: MemoryRegionPermissions,
        shared_futex_backing: Option<(SharedFutexBacking, usize)>,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        let shared = flags.contains(CreatePagesFlags::SHARED);
        let file_backed = flags.contains(CreatePagesFlags::MAP_FILE);
        // A `PROT_NONE` anonymous private mapping is a pure VA reservation:
        // Linux allocates no page-table state for it either, and deferring the
        // platform allocation keeps huge reservations (observed live: V8's
        // ~4 GiB pointer-compression cage and ~32 GiB sandbox, whose per-page
        // platform tracking exceeds what the HVF memory manager is built for)
        // working on every platform. It is materialized lazily on the first
        // `mprotect` that adds access flags (see `protect_mapping`).
        let defer = perms.is_empty()
            && !shared
            && !file_backed
            && !flags.intersects(
                CreatePagesFlags::FIXED_ADDR
                    | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY
                    | CreatePagesFlags::IS_STACK,
            );
        unsafe {
            self.create_mapping(
                suggested_new_address,
                length,
                VmArea::new(
                    VmFlags::from(perms)
                        | VmFlags::may_flags_for_mapping(shared, file_backed)
                        | if defer {
                            VmFlags::VM_DEFERRED
                        } else {
                            VmFlags::empty()
                        }
                        | if flags.contains(CreatePagesFlags::IS_STACK) {
                            VmFlags::VM_GROWSDOWN
                        } else {
                            VmFlags::empty()
                        },
                    flags.contains(CreatePagesFlags::MAP_FILE),
                    shared_futex_backing,
                ),
                flags,
            )
        }
        .map_err(MappingError::MapError)
    }

    /// Get the memory permissions of a given address range.
    ///
    /// `page_range` specifies the range of pages to check the memory permissions.
    /// This function returns `MemoryRegionPermissions` only if the range is valid.
    pub(super) fn get_memory_permissions(
        &self,
        page_range: PageRange<ALIGN>,
    ) -> Option<MemoryRegionPermissions> {
        let (range_start, range_end) = (page_range.start, page_range.end);
        let range: core::ops::Range<usize> = page_range.into();
        if let Some(iter) = self.overlapping(range).next() {
            if iter.0.start > range_start || iter.0.end < range_end {
                // partial overlap implies that the given range contains unmapped pages or
                // consists of memory pages with different permissions.
                return None;
            }
            let vmflags = iter.1.flags();
            Some(vmflags.into())
        } else {
            None
        }
    }

    /*================================Internal Functions================================ */

    /// Get an unmapped area in the virtual address space.
    /// `suggested_range` and `fixed_addr` are the hint address and MAP_FIXED flag respectively,
    /// similar to how `mmap` works.
    ///
    /// Returns `None` if no area found. Otherwise, returns the start address of a page-aligned area.
    fn get_unmmaped_area(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        fixed_addr: bool,
    ) -> Option<usize> {
        let size = length.as_usize();
        if size > Platform::TASK_ADDR_MAX {
            return None;
        }
        if let Some(suggested_address) = suggested_address {
            if fixed_addr {
                if (Platform::TASK_ADDR_MAX - size) < suggested_address.0 {
                    return None;
                }
                return Some(suggested_address.0);
            }
            // A plain (non-MAP_FIXED) hint is advisory: Linux ignores an
            // unusable hint and picks its own address rather than failing
            // the mmap, and real programs rely on exactly that -- V8's
            // GetRandomMmapAddr hands the kernel addresses randomized over a
            // wider range than any particular process can necessarily map
            // (observed live: a node:alpine guest's V8 heap-chunk hint below
            // this platform's `TASK_ADDR_MIN` was answered with `EPERM`
            // here, which V8 treats as fatal OOM during snapshot
            // deserialization). Honor the hint only when it is genuinely
            // usable; otherwise fall through to the search below, exactly as
            // if no hint had been given.
            if suggested_address.0 >= Platform::TASK_ADDR_MIN
                && (Platform::TASK_ADDR_MAX - size) >= suggested_address.0
                && !self
                    .vmas
                    .overlaps(&(suggested_address.0..(suggested_address.0 + size)))
                && !self.reserved_overlaps(&(suggested_address.0..(suggested_address.0 + size)))
            {
                return Some(suggested_address.0);
            }
        } else if fixed_addr {
            // MAP_FIXED with addr=0: return 0 so insert_mapping rejects it
            // via the TASK_ADDR_MIN check (BelowMinAddress → EPERM).
            return Some(0);
        }

        // top down
        let (low_limit, unconstrained_high_limit) = (
            Platform::TASK_ADDR_MIN,
            Platform::TASK_ADDR_MAX - length.as_usize(),
        );
        debug_assert_eq!(Platform::TASK_ADDR_MIN % ALIGN, 0);
        debug_assert_eq!(Platform::TASK_ADDR_MAX % ALIGN, 0);
        // An unusable hint is advisory (see above), but that does not mean it carries no
        // information: a caller re-probing with a *lower* hint after an earlier attempt (V8's
        // code-range/pointer-compression-cage placement does exactly this, mmap-ing the same
        // size at a descending sequence of hints until one lands where it needs) means "try
        // somewhere at or below here first" -- searching the unconstrained full range would
        // return the exact same top-of-space address on every such retry (nothing about free
        // space changed), so the caller's presumably-different constraint on *this* retry could
        // never be satisfied, and it would exhaust its own retry budget and fail outright. Bias
        // the search toward staying at or below the hint first; only if nothing fits there does
        // this fall back to the unconstrained search, exactly as if no hint had been given.
        if let Some(suggested_address) = suggested_address
            && suggested_address.0 < unconstrained_high_limit
            && let Some(found) = self.top_down_search(low_limit, suggested_address.0, size)
        {
            return Some(found);
        }
        self.top_down_search(low_limit, unconstrained_high_limit, size)
    }

    /// The unhinted top-down search `get_unmmaped_area` falls back to: the highest gap of at
    /// least `size` bytes whose start is in `[low_limit, high_limit]`. Shared by the
    /// unconstrained search and, with a smaller `high_limit`, the hint-biased search above.
    fn top_down_search(&self, low_limit: usize, high_limit: usize, size: usize) -> Option<usize> {
        // An inverted range is empty by this function's own contract (`start
        // in [low_limit, high_limit]`) and must fail cleanly. This guards a
        // real caller mistake, not a hypothetical one: `get_unmmaped_area`'s
        // hint-biased call passes the raw hint as `high_limit`, and a hint
        // below `low_limit` (observed live: a node:alpine guest's V8
        // CodeRange hint landing below `TASK_ADDR_MIN`, entirely plausible
        // since host library mappings reported by `reserved_pages` commonly
        // sit below the guest's floor) makes `high_limit < low_limit`.
        // Without this guard, the fast path below can still return that
        // too-low `high_limit` verbatim whenever some tracked range (again,
        // typically a host mapping from `reserved_pages`) starts at or below
        // it: `last_end` then defaults no higher than `low_limit` itself, so
        // `last_end <= high_limit` can hold even though `high_limit` is
        // below `low_limit` -- silently handing the caller an address
        // outside the caller's own requested floor. `insert_mapping` still
        // catches the resulting placement (`start < TASK_ADDR_MIN`), but as
        // `AllocationError::BelowMinAddress`, which the guest sees as EPERM
        // on an ordinary hinted `mmap` -- V8 treats that as fatal OOM.
        if high_limit < low_limit {
            return None;
        }
        // 1. check [last_end, high_limit]
        // The globally last (highest-addressed) tracked range is not
        // necessarily relevant here: as the loop below already accounts for,
        // a platform's `reserved_pages` can report host mappings that sit
        // entirely above `TASK_ADDR_MAX` (e.g. a `mach_vm_region` walk that
        // finds the dyld shared cache, or some other host allocation,
        // ASLR-slid above litebox's own deliberately conservative guest
        // ceiling on macOS -- see `MacOsUserland::TASK_ADDR_MAX`'s doc
        // comment). Keying this fast path off *that* range's end would make
        // it report the very top of the guest range as occupied even when
        // nothing below `high_limit` is, and -- since it never re-checks
        // `high_limit` afterwards -- skip straight to the per-gap loop below,
        // which only ever considers the gap immediately below a *tracked*
        // range, not the gap between the ceiling and the highest range that
        // is actually within bounds. So find the highest range that could
        // actually collide with a placement ending at `high_limit`.
        let last_end = self
            .vmas
            .iter()
            .rev()
            .find(|(r, _)| r.start <= high_limit)
            .map_or(low_limit, |(r, _)| r.end);
        // `last_end <= high_limit` alone is not sufficient: it only rules out
        // a tracked range that starts at or below `high_limit` extending past
        // it, not a tracked range that starts *above* `high_limit` (which the
        // `find` above deliberately skips, per this function's own doc
        // comment, so that a host mapping entirely above `TASK_ADDR_MAX`
        // doesn't shadow this fast path). That skip is only sound when
        // nothing tracked actually falls inside `[high_limit, TASK_ADDR_MAX)`
        // itself -- true for a host mapping genuinely entirely above the
        // guest's ceiling, but not for a *guest* mapping that (on a platform
        // whose `allocate_pages` cannot always place a `Hint` at the exact
        // address requested) ended up landing inside this exact window
        // despite `Vmem` believing the window was free when it computed
        // `high_limit` for it. `overlaps` re-derives the true answer directly
        // from the candidate range instead of trusting the `r.start <=
        // high_limit` proxy.
        if last_end <= high_limit
            && !self.vmas.overlaps(&(high_limit..high_limit + size))
            && !self.reserved_overlaps(&(high_limit..high_limit + size))
        {
            return Some(high_limit);
        }

        // 2. check gaps between ranges
        for (r, flags) in self.vmas.iter().rev() {
            let start = r.start.checked_sub(
                size + if flags.flags.contains(VmFlags::VM_GROWSDOWN) {
                    // If it is a stack, we need to leave enough space for the stack to grow downwards.
                    Self::STACK_GUARD_GAP << 1
                } else {
                    0
                },
            )?;
            if start < low_limit {
                return None;
            }
            if start > high_limit {
                // Note we may have pre-allocated memory that are higher than `TASK_ADDR_MAX`
                // (See [`Vmem::new`]) and thus `start` may be larger than `high_limit`.
                continue;
            }
            if !self.vmas.overlaps(&(start..start + size))
                && !self.reserved_overlaps(&(start..start + size))
            {
                return Some(start);
            }
        }

        None
    }

    /// Whether any part of `range` is covered by an externally reserved range
    /// (see [`Self::reserved`]).
    fn reserved_overlaps(&self, range: &Range<usize>) -> bool {
        self.reserved
            .range(..range.end)
            .next_back()
            .is_some_and(|(_, &end)| range.start < end)
    }

    /// Marks `range` as reserved: a flexible placement search will steer around it even though it
    /// has no live `vmas` entry. Overlapping/adjacent existing reservations are merged. See
    /// [`Self::reserved`].
    pub(super) fn reserve_external(&mut self, range: Range<usize>) {
        if range.start >= range.end {
            return;
        }
        let mut start = range.start;
        let mut end = range.end;
        let overlapping: Vec<(usize, usize)> = self
            .reserved
            .range(..=end)
            .rev()
            .take_while(|&(_, &e)| e >= start)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in overlapping {
            self.reserved.remove(&s);
            start = start.min(s);
            end = end.max(e);
        }
        self.reserved.insert(start, end);
    }

    /// Releases a reservation made by [`Self::reserve_external`]. `range` need not exactly match
    /// what was reserved (a partial release shrinks/splits the covering reservation); releasing
    /// where nothing is reserved is a no-op.
    pub(super) fn release_external(&mut self, range: Range<usize>) {
        if range.start >= range.end {
            return;
        }
        let overlapping: Vec<(usize, usize)> = self
            .reserved
            .range(..range.end)
            .rev()
            .take_while(|&(_, &e)| e > range.start)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in overlapping {
            self.reserved.remove(&s);
            if s < range.start {
                self.reserved.insert(s, range.start);
            }
            if range.end < e {
                self.reserved.insert(range.end, e);
            }
        }
    }
}

/// Error for removing mappings
#[derive(Error, Debug)]
pub enum VmemUnmapError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("failed to unmap pages: {0}")]
    UnmapError(#[from] crate::platform::page_mgmt::DeallocationError),
}

/// Error for resetting pages
#[derive(Error, Debug)]
pub enum VmemResetError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("provided range contains unallocated pages")]
    AlreadyUnallocated,
    #[error("reset file-backed mapping")]
    FileBacked,
}

/// Error for `Vmem::set_wipe_on_fork` (`madvise(MADV_WIPEONFORK|MADV_KEEPONFORK)`).
#[derive(Error, Debug)]
pub enum VmemWipeOnForkError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("the range {0:?} contains unmapped pages")]
    Unmapped(Range<usize>),
    #[error("the mapping at {0:?} is file-backed or shared, so it cannot be wiped on fork")]
    NotPrivateAnonymous(Range<usize>),
}

/// Error for [`Vmem::resize_mapping`]
#[derive(Error, Debug)]
pub(super) enum VmemResizeError {
    #[error("no mapping containing the address {0:?}")]
    NotExist(usize),
    #[error("invalid address {addr:?} exceeds range {range:?}")]
    InvalidAddr { range: Range<usize>, addr: usize },
    #[error("range {0:?} is already (partially) occupied")]
    RangeOccupied(Range<usize>),
    #[error("range {0:?} has a pending initialization")]
    InitializationPending(Range<usize>),
    #[error("failed to unmap the removed range: {0}")]
    UnmapError(#[source] VmemUnmapError),
    #[error("out of memory")]
    OutOfMemory,
}

/// Error for moving mappings
#[derive(Error, Debug)]
pub enum VmemMoveError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("out of memory")]
    OutOfMemory,
    #[error("remap failed: {0}")]
    RemapError(#[from] crate::platform::page_mgmt::RemapError),
}

/// Error for protecting mappings
#[derive(Error, Debug)]
pub enum VmemProtectError {
    #[error("the range {0:?} is not aligned")]
    UnAligned(Range<usize>),
    #[error("the range {0:?} has no mapping memory")]
    InvalidRange(Range<usize>),
    #[error("failed to change permissions from {old:?} to {new:?}")]
    NoAccess { old: VmFlags, new: VmFlags },
    #[error("mprotect failed: {0}")]
    ProtectError(#[from] crate::platform::page_mgmt::PermissionUpdateError),
    #[error("failed to materialize a deferred reservation: {0}")]
    DeferredAllocate(#[from] crate::platform::page_mgmt::AllocationError),
}

/// Error for creating mappings
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum MappingError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("not enough memory")]
    OutOfMemory,

    // Errors from mapping a file
    #[error("bad file descriptor: {0}")]
    BadFD(i32),
    #[error("file descriptor does not point to a file")]
    NotAFile,
    #[error("file not open for reading")]
    NotForReading,
    #[error("I/O error reading file: errno {0}")]
    Io(i32),

    #[error("mapping failed: {0}")]
    MapError(#[from] crate::platform::page_mgmt::AllocationError),

    /// A concurrent operation on this address space (another thread of the same
    /// `CLONE_VM` family unmapping or otherwise invalidating the range) removed a
    /// just-created mapping before its post-creation permission change could apply.
    /// See `PageManager::create_pages`'s two-phase create-then-protect
    /// sequence, which necessarily drops its lock around the caller-supplied `op`
    /// (which may itself need to re-enter the page-fault handler) between those two
    /// phases.
    #[error("mapping was concurrently removed before its permissions could be finalized")]
    ConcurrentlyRemoved,

    #[error("mapping initialization identity space is exhausted")]
    InitializationIdentityExhausted,

    #[error("mapping permission finalization failed: {0}")]
    FinalizeProtection(#[source] VmemProtectError),

    #[error("{primary}; initialization cleanup also failed: {cleanup}")]
    Cleanup {
        primary: Box<MappingError>,
        cleanup: VmemUnmapError,
    },
}

/// Enable [`super::PageManager`] to handle page faults if its platform implements this trait
pub trait VmemPageFaultHandler {
    /// Handle a page fault for the given address.
    ///
    /// # Safety
    ///
    /// This should only be called from the kernel page fault handler.
    unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        flags: VmFlags,
        error_code: u64,
    ) -> Result<(), PageFaultError>;

    /// Check if it has access to the fault address.
    fn access_error(error_code: u64, flags: VmFlags) -> bool;
}

/// Error for handling page fault
#[derive(Error, Debug)]
pub enum PageFaultError {
    #[error("no access: {0}")]
    AccessError(&'static str),
    #[error("allocation failed")]
    AllocationFailed,
    #[error("given page is part of an already mapped huge page")]
    HugePage,
}
