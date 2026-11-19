// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Installation of a guest-private dyld shared-cache instance.

use crate::syscalls::mm::permissions;
use crate::{LoadedProgram, ShimPlatform, Task};
use alloc::{sync::Arc, vec, vec::Vec};
use core::ops::Range;
use core::sync::atomic::Ordering;
use litebox::mm::page::{NonZeroAddress, NonZeroPageSize};
use litebox::platform::{
    RawConstPointer as _, RawMutPointer as _, page_mgmt::MemoryRegionPermissions as Permissions,
};
use litebox_common_linux::vmem::CreatePagesFlags;
use litebox_common_macos::{PAGE_SIZE, VmProtection, shared_cache::HostSharedCache};
use litebox_syscall_rewriter::macho::Rewriter;

mod layout;

/// Lowest guest address of a shared-cache instance: above the host shared
/// region and the `[16, 63)` GiB window that xzone malloc reserves for its
/// fixed pointer ranges.
pub const SHARED_CACHE_MIN_ADDRESS: usize = 64 << 30;

/// Why reserving or installing a shared-cache instance failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SharedCacheInstallError {
    AlreadyInstalled,
    /// Part of the range is already mapped by the guest, or the host refused the
    /// fixed range (see `layout::reserve_free_range`).
    ReservationConflict,
    /// The address range cannot be reserved for another reason.
    Reservation,
    /// The layout's range is not the reserved range, or its pieces do not
    /// tile it with page-aligned ranges whose backings allow their
    /// protections.
    InvalidCacheRange,
    /// A code region does not name exactly one file-view piece with a
    /// read-execute maximum or has invalid instruction ranges, or executable
    /// memory is not rewritten code.
    InvalidRegion,
    /// A gate island is not page-aligned, lies outside the instance, or
    /// overlaps another island, a copied piece or code.
    InvalidGateIsland,
    /// The rewriter is unavailable on this platform or cannot patch the code.
    Rewrite,
    /// No gate island with remaining capacity is within branch range of a site.
    UnreachableGates,
    /// Mapping a piece of the instance failed.
    Map,
}

impl core::fmt::Display for SharedCacheInstallError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyInstalled => "shared cache already installed",
            Self::ReservationConflict => "the shared-cache range is already in use",
            Self::Reservation => "cannot reserve the shared-cache range",
            Self::InvalidCacheRange => "invalid shared-cache range or pieces",
            Self::InvalidRegion => "invalid shared-cache code region",
            Self::InvalidGateIsland => "invalid shared-cache gate island",
            Self::Rewrite => "failed to rewrite shared-cache executable code",
            Self::UnreachableGates => "no shared-cache gate island can serve a rewrite site",
            Self::Map => "failed to map shared-cache pages",
        })
    }
}

impl core::error::Error for SharedCacheInstallError {}

/// Initial contents of one page-aligned piece of a shared-cache instance.
#[derive(Clone, Copy)]
pub(crate) enum SharedCacheBacking<'a> {
    /// Inaccessible; the reservation remains.
    Reserved,
    /// A private view of the platform's cache file bytes at this unslid
    /// address ([`HostSharedCache::map_host_cache_range`]); writes never
    /// reach the file.
    ///
    /// [`HostSharedCache::map_host_cache_range`]: litebox_common_macos::shared_cache::HostSharedCache::map_host_cache_range
    FileView(u64),
    /// Supplied by [`SharedCacheLayout::pager`] on first access, like XNU's
    /// shared-region pager, with the current recorded protection, which guest
    /// `mprotect`/`vm_protect` may have changed. Never executable.
    Paged,
    /// Anonymous memory initialized with these bytes, zero-filled after them.
    /// Never executable.
    Copy(&'a [u8]),
}

/// One page-aligned piece of a shared-cache instance and its protections.
pub(crate) struct SharedCachePiece<'a> {
    pub range: Range<usize>,
    pub backing: SharedCacheBacking<'a>,
    /// Initial protection.
    pub protection: VmProtection,
    /// Upper bound for later guest `mprotect`/`vm_protect` requests, like a
    /// VM map entry's maximum protection. Never writable and executable;
    /// executable only for rewritten code ([`SharedCacheBacking::FileView`]
    /// with a code region), and then exactly read-execute.
    pub max_protection: VmProtection,
}

/// File-view code, rewritten before it can execute.
pub(crate) struct SharedCacheCodeRegion<'a> {
    /// Index of a [`SharedCacheBacking::FileView`] piece whose maximum
    /// protection is read-execute.
    pub piece: usize,
    /// Instruction byte ranges relative to the piece start: sorted,
    /// non-overlapping and 4-byte aligned.
    pub instruction_ranges: &'a [Range<usize>],
}

/// Contents of one demand-paged page.
pub(crate) struct SharedCachePage {
    /// Exactly one page of bytes.
    pub bytes: Vec<u8>,
    /// The maximum protection of the page's cache mapping without execute;
    /// must allow the page's recorded maximum.
    pub max_protection: VmProtection,
}

/// Supplies the page at a page-aligned guest address of a
/// [`SharedCacheBacking::Paged`] piece, or `None` if it cannot. Called with
/// the instance locked, so it must not re-enter the shim.
pub(crate) type SharedCachePager = Arc<dyn Fn(usize) -> Option<SharedCachePage> + Send + Sync>;

/// Layout of a guest-private shared-cache instance.
pub(crate) struct SharedCacheLayout<'a> {
    /// The range reserved with [`LoadedProgram::reserve_shared_cache`].
    pub range: Range<usize>,
    /// Pieces in address order that exactly tile `range`.
    pub pieces: &'a [SharedCachePiece<'a>],
    pub code_regions: &'a [SharedCacheCodeRegion<'a>],
    /// Candidate gate-island pages: page-aligned ranges inside `range` that
    /// overlap no copied or executable piece and whose bytes the guest never
    /// reads. Each used candidate replaces its bytes with read-execute gates.
    /// Every rewritten site must lie within AArch64 `B` range (+-128 MiB) of
    /// a candidate with remaining capacity.
    pub gate_islands: &'a [Range<usize>],
    /// Required if any piece is [`SharedCacheBacking::Paged`].
    pub pager: Option<SharedCachePager>,
}

/// Current and maximum protection of one range of an installed instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedCacheMapping {
    pub(crate) range: Range<usize>,
    pub(crate) protection: VmProtection,
    pub(crate) max_protection: VmProtection,
    /// Not yet supplied by the pager.
    pub(crate) paged: bool,
}

/// The installed instance, for guest syscalls and fault diagnostics.
pub(crate) struct SharedCacheState {
    pub(crate) range: Range<usize>,
    /// Sorted, non-overlapping and tiling `range`. Updates merge the records
    /// they touch with equal neighbors (same protection, maximum and paged
    /// state), so repeated page-ins keep the count bounded.
    pub(crate) mappings: Vec<SharedCacheMapping>,
    pub(crate) pager: Option<SharedCachePager>,
}

impl SharedCacheState {
    /// Indices of the records overlapping `range`.
    fn overlapping(&self, range: &Range<usize>) -> Range<usize> {
        let first = self
            .mappings
            .partition_point(|mapping| mapping.range.end <= range.start);
        let count =
            self.mappings[first..].partition_point(|mapping| mapping.range.start < range.end);
        first..first + count
    }

    /// Whether `protection` is within the maximum protection of every page of
    /// `range`, which must lie inside the instance.
    pub(crate) fn allows(&self, range: &Range<usize>, protection: VmProtection) -> bool {
        range.start >= self.range.start
            && range.end <= self.range.end
            && self.mappings[self.overlapping(range)]
                .iter()
                .all(|mapping| mapping.max_protection.contains(protection))
    }

    pub(crate) fn mapping_at(&self, address: usize) -> Option<&SharedCacheMapping> {
        self.mappings
            .get(self.overlapping(&(address..address.checked_add(1)?)).start)
            .filter(|mapping| mapping.range.contains(&address))
    }

    /// Parts of `range` that still await the pager (`true`) or are mapped
    /// (`false`), in address order.
    pub(crate) fn paged_parts(&self, range: &Range<usize>) -> Vec<(Range<usize>, bool)> {
        let mut parts: Vec<(Range<usize>, bool)> = Vec::new();
        for mapping in &self.mappings[self.overlapping(range)] {
            let part = mapping.range.start.max(range.start)..mapping.range.end.min(range.end);
            match parts.last_mut() {
                Some((last, paged)) if last.end == part.start && *paged == mapping.paged => {
                    last.end = part.end;
                }
                _ => parts.push((part, mapping.paged)),
            }
        }
        parts
    }

    pub(crate) fn page_in(&mut self, page: &Range<usize>) {
        self.update(page, |mapping| mapping.paged = false);
    }

    pub(crate) fn set_protection(&mut self, range: &Range<usize>, protection: VmProtection) {
        self.update(range, |mapping| mapping.protection = protection);
    }

    fn update(&mut self, range: &Range<usize>, change: impl Fn(&mut SharedCacheMapping)) {
        let inside = self.overlapping(range);
        if inside.is_empty() {
            return;
        }
        let neighbors = inside.start.saturating_sub(1)..(inside.end + 1).min(self.mappings.len());
        let mut merged: Vec<SharedCacheMapping> = Vec::with_capacity(neighbors.len() + 2);
        for (index, mapping) in self.mappings[neighbors.clone()].iter().enumerate() {
            let inner = if inside.contains(&(neighbors.start + index)) {
                mapping.range.start.max(range.start)..mapping.range.end.min(range.end)
            } else {
                mapping.range.end..mapping.range.end
            };
            for part in [
                mapping.range.start..inner.start,
                inner.clone(),
                inner.end..mapping.range.end,
            ] {
                if part.is_empty() {
                    continue;
                }
                let mut record = SharedCacheMapping {
                    range: part,
                    ..mapping.clone()
                };
                if record.range == inner {
                    change(&mut record);
                }
                match merged.last_mut() {
                    Some(last)
                        if last.range.end == record.range.start
                            && last.protection == record.protection
                            && last.max_protection == record.max_protection
                            && last.paged == record.paged =>
                    {
                        last.range.end = record.range.end;
                    }
                    _ => merged.push(record),
                }
            }
        }
        self.mappings.splice(neighbors, merged);
    }
}

fn page_aligned(range: &Range<usize>) -> bool {
    range.start < range.end
        && range.start.is_multiple_of(PAGE_SIZE)
        && range.end.is_multiple_of(PAGE_SIZE)
}

fn overlaps(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

/// Distance from a batch of code to the next gate an island would emit.
fn gate_island_distance(code: &Range<usize>, island: &Range<usize>, cursor: usize) -> usize {
    let gate = island.start.saturating_add(cursor);
    if gate >= code.end {
        gate - code.start
    } else if gate < code.start {
        code.end - gate
    } else {
        // Islands never overlap code; keep the order total anyway.
        0
    }
}

/// `range` minus the sorted, disjoint `holes`.
fn subtract(range: &Range<usize>, holes: &[Range<usize>]) -> Vec<Range<usize>> {
    let mut parts = Vec::new();
    let mut start = range.start;
    for hole in holes.iter().filter(|hole| overlaps(hole, range)) {
        if hole.start > start {
            parts.push(start..hole.start);
        }
        start = start.max(hole.end);
    }
    if start < range.end {
        parts.push(start..range.end);
    }
    parts
}

impl<P: ShimPlatform> LoadedProgram<P> {
    /// Reserve exactly `range`, page-aligned and at or above
    /// [`SHARED_CACHE_MIN_ADDRESS`], without replacing guest or host mappings.
    pub(crate) fn reserve_shared_cache(
        &self,
        range: Range<usize>,
    ) -> Result<(), SharedCacheInstallError> {
        let task = &self.entrypoints.task;
        let mut reservation = task.global.shared_cache_reservation.lock();
        if reservation.is_some() {
            return Err(SharedCacheInstallError::AlreadyInstalled);
        }
        if !page_aligned(&range) || range.start < SHARED_CACHE_MIN_ADDRESS {
            return Err(SharedCacheInstallError::InvalidCacheRange);
        }
        let length =
            NonZeroPageSize::new(range.len()).ok_or(SharedCacheInstallError::InvalidCacheRange)?;
        // SAFETY: NOREPLACE never replaces an existing guest or host mapping.
        unsafe {
            task.global.mm.create_pages_with_permissions(
                NonZeroAddress::new(range.start),
                length,
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                Permissions::empty(),
                None,
                |_| Ok(0),
            )
        }
        .map_err(|error| {
            use litebox::platform::page_mgmt::AllocationError;
            use litebox_common_linux::vmem::MappingError;
            litebox_util_log::warn!(error:?, range:?; "cannot reserve the shared-cache range");
            match error {
                MappingError::MapError(
                    AllocationError::AddressInUse
                    | AllocationError::AddressInUseByPlatform
                    | AllocationError::AddressPartiallyInUse,
                ) => SharedCacheInstallError::ReservationConflict,
                _ => SharedCacheInstallError::Reservation,
            }
        })?;
        *reservation = Some(range);
        Ok(())
    }

    /// Install `cache` in the range reserved by [`Self::reserve_shared_cache`].
    /// No cache code may run during installation. Discard the process on
    /// error: installation is not transactional.
    pub(crate) fn install_shared_cache(
        &self,
        cache: &SharedCacheLayout<'_>,
    ) -> Result<(), SharedCacheInstallError>
    where
        P: HostSharedCache,
    {
        use SharedCacheInstallError as Error;

        let task = &self.entrypoints.task;
        if task.global.shared_cache_base.load(Ordering::Acquire) != 0 {
            return Err(Error::AlreadyInstalled);
        }
        if task.global.shared_cache_reservation.lock().as_ref() != Some(&cache.range) {
            return Err(Error::InvalidCacheRange);
        }
        validate_pieces(cache)?;
        let executable = VmProtection::READ | VmProtection::EXECUTE;
        let mut code_ranges: Vec<Option<&[Range<usize>]>> = vec![None; cache.pieces.len()];
        for region in cache.code_regions {
            let piece = cache.pieces.get(region.piece).ok_or(Error::InvalidRegion)?;
            if piece.max_protection != executable
                || code_ranges[region.piece]
                    .replace(region.instruction_ranges)
                    .is_some()
            {
                return Err(Error::InvalidRegion);
            }
        }
        if cache
            .pieces
            .iter()
            .zip(&code_ranges)
            .any(|(piece, ranges)| {
                piece.max_protection.contains(VmProtection::EXECUTE) && ranges.is_none()
            })
        {
            // Executable pieces without a code region would run unrewritten.
            return Err(Error::InvalidRegion);
        }
        // The pieces replace the reservation's pages; `SharedCacheState`
        // holds their maximum protections.
        task.forget_replaced_maximum_protections(cache.range.clone(), true);
        let mut gates: Vec<Vec<u8>> = vec![Vec::new(); cache.gate_islands.len()];
        for (piece, ranges) in cache.pieces.iter().zip(&code_ranges) {
            match (piece.backing, ranges) {
                (SharedCacheBacking::FileView(address), Some(ranges)) => task
                    .map_shared_cache_code(
                        &piece.range,
                        address,
                        piece.protection,
                        ranges,
                        cache.gate_islands,
                        &mut gates,
                    )?,
                (SharedCacheBacking::FileView(address), None) => {
                    task.map_shared_cache_view(&piece.range, address, piece.protection, |_| {
                        Ok(piece.range.len())
                    })?;
                }
                (SharedCacheBacking::Copy(bytes), _) => {
                    task.map_shared_cache_copy(&piece.range, bytes, piece.protection)?;
                }
                (SharedCacheBacking::Reserved | SharedCacheBacking::Paged, _) => {}
            }
        }
        let mut islands: Vec<Range<usize>> = cache
            .gate_islands
            .iter()
            .zip(&gates)
            .filter(|(_, gates)| !gates.is_empty())
            .map(|(island, _)| island.clone())
            .collect();
        islands.sort_by_key(|island| island.start);
        for (island, gates) in cache.gate_islands.iter().zip(&gates) {
            if !gates.is_empty() {
                litebox_util_log::debug!(
                    island:? = island,
                    bytes = gates.len();
                    "shared-cache gate island"
                );
                task.map_shared_cache_copy(island, gates, executable)?;
            }
        }
        let mut mappings = Vec::new();
        for piece in cache.pieces {
            let record = |range| SharedCacheMapping {
                range,
                protection: piece.protection,
                max_protection: piece.max_protection,
                paged: matches!(piece.backing, SharedCacheBacking::Paged),
            };
            match piece.backing {
                SharedCacheBacking::Reserved
                | SharedCacheBacking::Paged
                | SharedCacheBacking::FileView(_) => {
                    mappings.extend(subtract(&piece.range, &islands).into_iter().map(record));
                }
                SharedCacheBacking::Copy(_) => mappings.push(record(piece.range.clone())),
            }
        }
        mappings.extend(islands.iter().map(|range| SharedCacheMapping {
            range: range.clone(),
            protection: executable,
            max_protection: executable,
            paged: false,
        }));
        mappings.sort_by_key(|mapping| mapping.range.start);
        // Fail closed if any page of the instance is executable without
        // being rewritten code or a used gate island.
        let mut rewritten_ranges: Vec<Range<usize>> = cache
            .pieces
            .iter()
            .zip(&code_ranges)
            .filter(|(_, ranges)| ranges.is_some())
            .map(|(piece, _)| piece.range.clone())
            .chain(islands)
            .collect();
        rewritten_ranges.sort_by_key(|range| range.start);
        if let Some(unexpected) = task
            .executable_ranges(&cache.range)
            .iter()
            .flat_map(|range| subtract(range, &rewritten_ranges))
            .next()
        {
            litebox_util_log::error!(range:? = unexpected; "unrewritten executable shared-cache memory");
            return Err(Error::InvalidRegion);
        }
        *task.global.shared_cache.lock() = Some(SharedCacheState {
            range: cache.range.clone(),
            mappings,
            pager: cache.pager.clone(),
        });
        task.global
            .shared_cache_base
            .store(cache.range.start, Ordering::Release);
        Ok(())
    }
}

fn validate_pieces(cache: &SharedCacheLayout<'_>) -> Result<(), SharedCacheInstallError> {
    use SharedCacheInstallError as Error;

    if !page_aligned(&cache.range) {
        return Err(Error::InvalidCacheRange);
    }
    let mut next = cache.range.start;
    for piece in cache.pieces {
        if piece.range.start != next || !page_aligned(&piece.range) {
            return Err(Error::InvalidCacheRange);
        }
        next = piece.range.end;
        let executable = VmProtection::READ | VmProtection::EXECUTE;
        let valid = match piece.backing {
            SharedCacheBacking::Reserved => {
                piece.protection.is_empty() && piece.max_protection.is_empty()
            }
            SharedCacheBacking::FileView(address) => address.is_multiple_of(PAGE_SIZE as u64),
            SharedCacheBacking::Paged => cache.pager.is_some(),
            SharedCacheBacking::Copy(bytes) => bytes.len() <= piece.range.len(),
        };
        let executable_piece = piece.max_protection.contains(VmProtection::EXECUTE);
        let file_view = matches!(piece.backing, SharedCacheBacking::FileView(_));
        if !valid
            || !piece.max_protection.contains(piece.protection)
            || piece
                .max_protection
                .contains(VmProtection::WRITE | VmProtection::EXECUTE)
            || (executable_piece && (!file_view || piece.max_protection != executable))
        {
            return Err(Error::InvalidCacheRange);
        }
    }
    if next != cache.range.end {
        return Err(Error::InvalidCacheRange);
    }
    let mut sorted: Vec<&Range<usize>> = cache.gate_islands.iter().collect();
    sorted.sort_by_key(|island| island.start);
    if sorted.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Err(Error::InvalidGateIsland);
    }
    for island in cache.gate_islands {
        if !page_aligned(island)
            || island.start < cache.range.start
            || island.end > cache.range.end
            || cache.pieces.iter().any(|piece| {
                (matches!(piece.backing, SharedCacheBacking::Copy(_))
                    || piece.max_protection.contains(VmProtection::EXECUTE))
                    && overlaps(&piece.range, island)
            })
        {
            return Err(Error::InvalidGateIsland);
        }
    }
    Ok(())
}

impl<P: ShimPlatform> Task<P> {
    /// Map `bytes`, zero-filled to `range`, with `protection` over the reservation.
    fn map_shared_cache_copy(
        &self,
        range: &Range<usize>,
        bytes: &[u8],
        protection: VmProtection,
    ) -> Result<(), SharedCacheInstallError> {
        let length = NonZeroPageSize::new(range.len()).ok_or(SharedCacheInstallError::Map)?;
        // SAFETY: the range lies in this task's idle shared-cache reservation;
        // pages are written while RW and get their final protection after.
        unsafe {
            self.global.mm.create_pages_with_permissions(
                NonZeroAddress::new(range.start),
                length,
                CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                permissions(protection),
                None,
                |pointer| {
                    use litebox_common_linux::vmem::MappingError;
                    pointer
                        .copy_from_slice(0, bytes)
                        .ok_or(MappingError::MemoryAccess)?;
                    Ok(bytes.len())
                },
            )
        }
        .map(|_| ())
        .map_err(|error| {
            litebox_util_log::warn!(error:?, range:?; "failed to map shared-cache copy");
            SharedCacheInstallError::Map
        })
    }

    /// Map the cache file bytes at unslid `address` over `range`, rewriting
    /// `instruction_ranges` before the view gets `protection`.
    fn map_shared_cache_code(
        &self,
        range: &Range<usize>,
        address: u64,
        protection: VmProtection,
        instruction_ranges: &[Range<usize>],
        islands: &[Range<usize>],
        gates: &mut [Vec<u8>],
    ) -> Result<(), SharedCacheInstallError>
    where
        P: HostSharedCache,
    {
        let mut rewrite_error = None;
        let mapped = self.map_shared_cache_view(range, address, protection, |pointer| {
            use litebox_common_linux::vmem::MappingError;
            let patches = self
                .rewrite_shared_cache_code(
                    |bytes: Range<usize>| {
                        P::RawConstPointer::<u8>::from_usize(pointer.as_usize() + bytes.start)
                            .to_owned_slice(bytes.len())
                            .map(Vec::from)
                    },
                    range.len(),
                    range.start,
                    instruction_ranges,
                    islands,
                    gates,
                )
                .map_err(|error| {
                    rewrite_error = Some(error);
                    MappingError::MemoryAccess
                })?;
            for (offset, word) in patches {
                pointer
                    .copy_from_slice(offset, &word.to_le_bytes())
                    .ok_or(MappingError::MemoryAccess)?;
            }
            Ok(range.len())
        });
        match rewrite_error {
            Some(error) => Err(error),
            None => mapped,
        }
    }

    /// Map the cache file bytes at unslid `address` over `range`; `init` runs
    /// while the view is writable.
    fn map_shared_cache_view(
        &self,
        range: &Range<usize>,
        address: u64,
        protection: VmProtection,
        init: impl FnOnce(
            P::RawMutPointer<u8>,
        ) -> Result<usize, litebox_common_linux::vmem::MappingError>,
    ) -> Result<(), SharedCacheInstallError>
    where
        P: HostSharedCache,
    {
        let length = NonZeroPageSize::new(range.len()).ok_or(SharedCacheInstallError::Map)?;
        // SAFETY: the range lies in this task's idle shared-cache reservation;
        // the view replaces the pages just created there, which nothing uses,
        // and gets its final protection after `init`.
        unsafe {
            self.global.mm.create_pages_with_permissions(
                NonZeroAddress::new(range.start),
                length,
                CreatePagesFlags::FIXED_ADDR,
                permissions(protection),
                None,
                |pointer| {
                    use litebox_common_linux::vmem::MappingError;
                    self.global
                        .platform
                        .map_host_cache_range(
                            address,
                            range.len() as u64,
                            range.start,
                            Permissions::READ | Permissions::WRITE,
                        )
                        .map_err(|error| {
                            litebox_util_log::warn!(error:%; "the platform cannot map cache bytes");
                            MappingError::MemoryAccess
                        })?;
                    init(pointer)
                },
            )
        }
        .map(|_| ())
        .map_err(|error| {
            litebox_util_log::warn!(error:?, range:?; "failed to map shared-cache view");
            SharedCacheInstallError::Map
        })
    }

    /// Return the changed `(offset, word)` pairs of the `length` bytes of code
    /// that will execute at `address`. `read` takes byte ranges within
    /// `length` and returns `None` if they are unreadable. `gates[i]` holds the
    /// gate bytes of `islands[i]`; words are returned only after their gates
    /// are placed.
    pub(crate) fn rewrite_shared_cache_code(
        &self,
        read: impl Fn(Range<usize>) -> Option<Vec<u8>>,
        length: usize,
        address: usize,
        instruction_ranges: &[Range<usize>],
        islands: &[Range<usize>],
        gates: &mut [Vec<u8>],
    ) -> Result<Vec<(usize, u32)>, SharedCacheInstallError> {
        use SharedCacheInstallError as Error;
        use litebox_trampoline::aarch64::{SVC_OPCODE_BITS, SVC_OPCODE_MASK};
        const MRS_TPIDRRO_MASK: u32 = 0xffff_ffe0;
        const MRS_TPIDRRO_BITS: u32 = 0xd53b_d060;
        const MAX_BATCH_SPAN: usize = 64 * 1024;

        debug_assert_eq!(islands.len(), gates.len());
        let ranges = instruction_ranges;
        if ranges.iter().any(|range| {
            range.start >= range.end
                || range.end > length
                || !range.start.is_multiple_of(size_of::<u32>())
                || !range.end.is_multiple_of(size_of::<u32>())
        }) || ranges.windows(2).any(|pair| pair[0].end > pair[1].start)
        {
            return Err(Error::InvalidRegion);
        }
        let rewriter = Rewriter::new(crate::aarch64_rewrite_options().target_host())
            .map_err(|_| Error::Rewrite)?;
        let callback = self.global.platform.get_syscall_entry_point();
        let tls_offset = self
            .global
            .platform
            .guest_thread_pointer_offset()
            .and_then(|offset| u16::try_from(offset).ok())
            .ok_or(Error::Rewrite)?;
        let mut chunks = Vec::new();
        for range in ranges {
            let mut start = range.start;
            while start < range.end {
                let end = range.end.min(start + MAX_BATCH_SPAN);
                chunks.push(start..end);
                start = end;
            }
        }
        let mut rewritten = Vec::new();
        let mut pending = Vec::new();
        let mut first = 0;
        while first < chunks.len() {
            let batch_start = chunks[first].start;
            let mut batch_end = chunks[first].end;
            let mut last = first + 1;
            while let Some(next) = chunks.get(last)
                && next.end - batch_start <= MAX_BATCH_SPAN
                && next.start - batch_end <= PAGE_SIZE
            {
                batch_end = next.end;
                last += 1;
            }
            pending.push(chunks[first..last].to_vec());
            first = last;
        }
        pending.reverse();
        while let Some(batch_ranges) = pending.pop() {
            let batch_start = batch_ranges[0].start;
            let batch_end = batch_ranges[batch_ranges.len() - 1].end;
            let batch = read(batch_start..batch_end)
                .filter(|batch| batch.len() == batch_end - batch_start)
                .ok_or(Error::Rewrite)?;
            let mut local_ranges: Vec<_> = batch_ranges
                .iter()
                .map(|range| range.start - batch_start..range.end - batch_start)
                .collect();
            local_ranges.retain(|range| {
                batch[range.clone()].as_chunks::<4>().0.iter().any(|word| {
                    let word = u32::from_le_bytes(*word);
                    // Every SVC, so the rewriter refuses other immediates.
                    word & SVC_OPCODE_MASK == SVC_OPCODE_BITS
                        || word & MRS_TPIDRRO_MASK == MRS_TPIDRRO_BITS
                })
            });
            if local_ranges.is_empty() {
                continue;
            }
            let code_address = address.checked_add(batch_start).ok_or(Error::Rewrite)?;
            let code_range = code_address..code_address + batch.len();
            let mut candidates: Vec<_> = (0..islands.len()).collect();
            candidates.sort_by_key(|&index| {
                gate_island_distance(&code_range, &islands[index], gates[index].len())
            });
            let mut placed = None;
            let mut too_large = false;
            for index in candidates {
                let island = &islands[index];
                let Some(cursor) = gates[index]
                    .len()
                    .checked_next_multiple_of(litebox_trampoline::TRAMPOLINE_CURSOR_ALIGN)
                    .filter(|cursor| *cursor < island.len())
                else {
                    continue;
                };
                let gate_address = island.start.checked_add(cursor).ok_or(Error::Rewrite)?;
                let mut patched = batch.clone();
                let (new_gates, trapped) = rewriter
                    .patch_code_segment(
                        &mut patched,
                        code_address as u64,
                        &local_ranges,
                        gate_address as u64,
                        callback as u64,
                        tls_offset,
                    )
                    .map_err(|error| {
                        litebox_util_log::warn!(error:?; "failed to build shared-cache gates");
                        Error::Rewrite
                    })?;
                if new_gates.len() > island.len() {
                    too_large = true;
                    break;
                }
                if !trapped.is_empty() || cursor + new_gates.len() > island.len() {
                    continue;
                }
                gates[index].resize(cursor, 0);
                gates[index].extend_from_slice(&new_gates);
                placed = Some(patched);
                break;
            }
            let Some(patched) = placed else {
                let span = batch_end - batch_start;
                // TODO: also split when every reachable island lacks the remaining room for the
                // whole batch, so fragmented capacity can still serve its sites one by one.
                if too_large && span > size_of::<u32>() {
                    let middle = batch_start + (span / 2).next_multiple_of(size_of::<u32>());
                    let (mut low, mut high) = (Vec::new(), Vec::new());
                    for range in batch_ranges {
                        if range.end <= middle {
                            low.push(range);
                        } else if range.start >= middle {
                            high.push(range);
                        } else {
                            low.push(range.start..middle);
                            high.push(middle..range.end);
                        }
                    }
                    pending.extend([high, low].into_iter().filter(|half| !half.is_empty()));
                    continue;
                }
                litebox_util_log::warn!(
                    code:? = code_range,
                    islands:? = islands.len();
                    "no shared-cache gate island can serve these sites"
                );
                return Err(Error::UnreachableGates);
            };
            for local_range in local_ranges {
                let new = patched[local_range.clone()].as_chunks::<4>().0;
                let old = batch[local_range.clone()].as_chunks::<4>().0;
                for (index, (word, original)) in new.iter().zip(old).enumerate() {
                    if word != original {
                        let offset = batch_start + local_range.start + 4 * index;
                        rewritten.push((offset, u32::from_le_bytes(*word)));
                    }
                }
            }
        }
        Ok(rewritten)
    }

    /// Executable guest mappings overlapping `range`, clipped to it.
    pub(crate) fn executable_ranges(&self, range: &Range<usize>) -> Vec<Range<usize>> {
        self.global
            .mm
            .overlapping(range.clone())
            .into_iter()
            .filter(|(_, flags)| flags.contains(litebox_common_linux::vmem::VmFlags::VM_EXEC))
            .map(|(mapping, _)| mapping.start.max(range.start)..mapping.end.min(range.end))
            .collect()
    }

    /// Whether `range` overlaps the shared-cache reservation.
    // TODO: support guest unmap and replacement of cache pages like XNU, which refuses only
    // "permanent" shared-region entries (`vm_map_delete_preflight_submap`,
    // `shared_region_make_permanent`), and `set_maximum` like `vm_map_protect_preflight`.
    pub(crate) fn overlaps_shared_cache(&self, range: Range<usize>) -> bool {
        self.global
            .shared_cache_reservation
            .lock()
            .as_ref()
            .is_some_and(|cache| overlaps(cache, &range))
    }

    /// Supply a demand-paged shared-cache page for a guest data abort at
    /// `address`. Returns whether the faulting access can be retried.
    // TODO: shim user copies of a slid DATA page the pager has not supplied yet fail with EFAULT;
    // like XNU's copyin/copyout, supply the page and retry.
    pub(crate) fn page_in_shared_cache(&self, address: usize) -> bool {
        let mut cache = self.global.shared_cache.lock();
        let Some(cache) = cache.as_mut() else {
            return false;
        };
        if !cache.range.contains(&address) {
            return false;
        }
        let start = address & !(PAGE_SIZE - 1);
        let Some(end) = start.checked_add(PAGE_SIZE) else {
            return false;
        };
        let page = start..end;
        let Some(recorded) = cache
            .mapping_at(page.start)
            .filter(|mapping| mapping.paged)
            .cloned()
        else {
            return false;
        };
        if recorded.protection.is_empty() {
            return false;
        }
        let Some(supplied) = cache.pager.as_ref().and_then(|pager| pager(page.start)) else {
            litebox_util_log::warn!(page:? = page; "shared-cache pager cannot supply a page");
            return false;
        };
        if supplied.bytes.len() != PAGE_SIZE
            || !supplied.max_protection.contains(recorded.max_protection)
            || supplied.max_protection.contains(VmProtection::EXECUTE)
        {
            litebox_util_log::warn!(page:? = page; "shared-cache pager supplied an invalid page");
            return false;
        }
        if self
            .map_shared_cache_copy(&page, &supplied.bytes, recorded.protection)
            .is_err()
        {
            return false;
        }
        litebox_util_log::debug!(
            page:? = page,
            offset:% = format_args!("shared cache +{:#x}", page.start - cache.range.start);
            "shared-cache page supplied on demand"
        );
        cache.page_in(&page);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(range: Range<usize>, protection: VmProtection, paged: bool) -> SharedCacheMapping {
        SharedCacheMapping {
            range,
            protection,
            max_protection: VmProtection::READ | VmProtection::WRITE,
            paged,
        }
    }

    #[test]
    fn page_ins_and_protection_changes_merge_records() {
        const PAGES: usize = 64;
        let read = VmProtection::READ;
        let end = PAGES * PAGE_SIZE;
        let mut state = SharedCacheState {
            range: 0..end,
            mappings: vec![
                record(0..PAGE_SIZE, read, false),
                record(PAGE_SIZE..end, read, true),
            ],
            pager: None,
        };
        let page = |index: usize| index * PAGE_SIZE..(index + 1) * PAGE_SIZE;
        for index in 1..PAGES / 2 {
            state.page_in(&page(index));
            assert_eq!(state.mappings.len(), 2);
            assert!(!state.mapping_at(page(index).start).unwrap().paged);
        }
        for index in (PAGES / 2 + 1..PAGES)
            .step_by(2)
            .chain((PAGES / 2..PAGES).step_by(2))
        {
            state.page_in(&page(index));
            assert!(state.mappings.len() <= PAGES / 2 + 1);
            assert!(!state.mapping_at(page(index).start).unwrap().paged);
        }
        assert_eq!(state.mappings, [record(0..end, read, false)]);
        let write = read | VmProtection::WRITE;
        state.set_protection(&page(3), write);
        assert_eq!(state.mappings.len(), 3);
        assert_eq!(state.mapping_at(page(3).start).unwrap().protection, write);
        assert_eq!(state.mapping_at(page(4).start).unwrap().protection, read);
        state.set_protection(&page(3), read);
        assert_eq!(state.mappings, [record(0..end, read, false)]);
    }
}
