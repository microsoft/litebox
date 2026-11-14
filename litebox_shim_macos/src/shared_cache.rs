// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Installation of a guest-private dyld shared-cache instance.
//!
//! A runtime provider chooses and reserves the instance's address range with
//! [`LoadedProgram::reserve_shared_cache`], prepares its contents (slid DATA
//! pages, closure `__TEXT`), and installs it with
//! [`LoadedProgram::install_shared_cache`]. The shim rewrites every executable
//! piece in heap buffers before mapping it, places gates in islands chosen
//! from provider-supplied candidates, and maps everything else from
//! provider-owned host bytes as private copy-on-write pages. The instance is
//! tracked by the shim's `VmemManager` and released with the address space.

use crate::syscalls::mm::permissions;
use crate::{LoadedProgram, ShimPlatform, Task};
use alloc::{string::String, sync::Arc, vec, vec::Vec};
use core::ops::Range;
use core::sync::atomic::Ordering;
use litebox::mm::page::{NonZeroAddress, NonZeroPageSize};
use litebox::platform::{RawMutPointer as _, page_mgmt::MemoryRegionPermissions as Permissions};
use litebox_common_linux::vmem::CreatePagesFlags;
use litebox_common_macos::{PAGE_SIZE, VmProtection};
use litebox_syscall_rewriter::macho::Rewriter;

/// Lowest guest address of a shared-cache instance: above the host shared
/// region and the `[16, 63)` GiB window that xzone malloc reserves for its
/// fixed pointer ranges.
pub const SHARED_CACHE_MIN_ADDRESS: usize = 64 << 30;

/// Why reserving or installing a shared-cache instance failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedCacheInstallError {
    AlreadyInstalled,
    /// Part of the address range is already mapped by the guest, or the host
    /// refused the fixed range. The host reports other refusals (such as
    /// `RLIMIT_AS`) the same way, so callers confirm the range is occupied
    /// before retrying elsewhere.
    ReservationConflict,
    /// The address range cannot be reserved for another reason.
    Reservation,
    /// The layout's range is not the reserved range, or its pieces do not
    /// tile it with page-aligned, non-executable-source ranges.
    InvalidCacheRange,
    /// A code region does not name exactly one read-execute copied piece or
    /// has invalid instruction ranges, an executable piece has no code
    /// region, or unrewritten executable memory remains after mapping.
    InvalidRegion,
    /// A gate island is not page-aligned, lies outside the instance, or
    /// overlaps another island or a copied piece.
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
pub enum SharedCacheBacking<'a> {
    /// Inaccessible; the reservation remains.
    Reserved,
    /// Inaccessible until the guest touches it; each touched page is then
    /// supplied by [`SharedCacheLayout::pager`], like XNU's shared-region
    /// slide pager. The piece's protections are those of its VM map entry:
    /// guest `mprotect`/`vm_protect` change the recorded protection before
    /// the page is supplied, and a supplied page gets the recorded one.
    Paged,
    /// A private copy-on-write mapping of immutable, native-page-aligned host
    /// bytes, such as a read-only mapping of a cache file. Never executable.
    /// The bytes need only stay mapped until installation returns.
    Source(&'a [u8]),
    /// Anonymous memory initialized with these bytes, zero-filled after them.
    Copy(&'a [u8]),
}

/// One page-aligned piece of a shared-cache instance and its protections.
pub struct SharedCachePiece<'a> {
    pub range: Range<usize>,
    pub backing: SharedCacheBacking<'a>,
    /// Initial protection.
    pub protection: VmProtection,
    /// Upper bound for later guest `mprotect`/`vm_protect` requests, like a
    /// VM map entry's maximum protection. Never writable and executable;
    /// executable only for rewritten code ([`SharedCacheBacking::Copy`]
    /// with a code region), and then exactly read-execute.
    pub max_protection: VmProtection,
}

/// Executable code to rewrite before it is mapped.
pub struct SharedCacheCodeRegion<'a> {
    /// Index of a read-execute [`SharedCacheBacking::Copy`] piece.
    pub piece: usize,
    /// Instruction byte ranges relative to the piece start: sorted,
    /// non-overlapping and 4-byte aligned.
    pub instruction_ranges: &'a [Range<usize>],
}

/// Resolves a guest address inside the instance to a description, such as
/// `mapping / image / segment`, for fault diagnostics. Called with the
/// instance locked, so it must not re-enter the shim.
pub type SharedCacheAttribution = Arc<dyn Fn(usize) -> Option<String> + Send + Sync>;

/// Contents of one demand-paged page.
pub struct SharedCachePage {
    /// Exactly one page of bytes.
    pub bytes: Vec<u8>,
    /// The maximum protection of the page's cache mapping; must allow the
    /// page's recorded maximum. Never executable.
    pub max_protection: VmProtection,
}

/// Supplies the page at a page-aligned guest address of a
/// [`SharedCacheBacking::Paged`] piece, or `None` if it cannot. Called with
/// the instance locked, so it must not re-enter the shim. It must return the
/// same bytes whenever it is asked: a shim user copy may supply pages in its
/// access range before the guest touches them.
pub type SharedCachePager = Arc<dyn Fn(usize) -> Option<SharedCachePage> + Send + Sync>;

/// Layout of a guest-private shared-cache instance prepared by a runtime provider.
pub struct SharedCacheLayout<'a> {
    /// The range reserved with [`LoadedProgram::reserve_shared_cache`].
    pub range: Range<usize>,
    /// Pieces in address order that exactly tile `range`.
    pub pieces: &'a [SharedCachePiece<'a>],
    pub code_regions: &'a [SharedCacheCodeRegion<'a>],
    /// Candidate gate-island pages: page-aligned ranges inside `range` that
    /// overlap no copied piece and whose bytes the guest never reads. Each
    /// used candidate replaces its bytes with read-execute gates. Every
    /// rewritten site must lie within AArch64 `B` range (+-128 MiB) of a
    /// candidate with remaining capacity.
    pub gate_islands: &'a [Range<usize>],
    pub attribution: Option<SharedCacheAttribution>,
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
    pub(crate) attribution: Option<SharedCacheAttribution>,
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

    pub(crate) fn is_paged(&self, page: usize) -> bool {
        self.mapping_at(page).is_some_and(|mapping| mapping.paged)
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

    /// Record that `page` has been supplied by the pager.
    pub(crate) fn page_in(&mut self, page: &Range<usize>) {
        self.update(page, |mapping| mapping.paged = false);
    }

    /// Record `protection` as the current protection of `range`.
    pub(crate) fn set_protection(&mut self, range: &Range<usize>, protection: VmProtection) {
        self.update(range, |mapping| mapping.protection = protection);
    }

    /// Apply `change` to the parts of the records inside `range`, splitting
    /// the records at its ends and merging equal neighbors in place.
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
    /// Reserve an inaccessible range for a shared-cache instance at exactly
    /// `range`, which must be page-aligned, at or above
    /// [`SHARED_CACHE_MIN_ADDRESS`], and free in both the guest and the host.
    ///
    /// The caller chooses `range` because only it can see where host memory
    /// is free; occupied ranges fail without replacing anything.
    pub fn reserve_shared_cache(&self, range: Range<usize>) -> Result<(), SharedCacheInstallError> {
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

    /// Rewrite, map and register a guest-private shared-cache instance in the
    /// range reserved by [`Self::reserve_shared_cache`].
    ///
    /// Executable pieces are rewritten (SVC and `mrs tpidrro_el0`, Guest
    /// mode) before they are mapped, so no unrewritten code ever becomes
    /// executable. No cache code may run during installation. Discard the
    /// process on error: installation is not transactional.
    pub fn install_shared_cache(
        &self,
        cache: &SharedCacheLayout<'_>,
    ) -> Result<(), SharedCacheInstallError> {
        use SharedCacheInstallError as Error;

        let task = &self.entrypoints.task;
        if task.global.shared_cache_base.load(Ordering::Acquire) != 0 {
            return Err(Error::AlreadyInstalled);
        }
        if task.global.shared_cache_reservation.lock().as_ref() != Some(&cache.range) {
            return Err(Error::InvalidCacheRange);
        }
        validate_pieces(cache)?;
        let mut buffers: Vec<Option<Vec<u8>>> = cache
            .pieces
            .iter()
            .map(|piece| match piece.backing {
                SharedCacheBacking::Copy(bytes) => {
                    let mut buffer = vec![0; piece.range.len()];
                    buffer[..bytes.len()].copy_from_slice(bytes);
                    Some(buffer)
                }
                _ => None,
            })
            .collect();
        let executable = VmProtection::READ | VmProtection::EXECUTE;
        let mut rewritten = vec![false; cache.pieces.len()];
        let mut gates: Vec<Vec<u8>> = vec![Vec::new(); cache.gate_islands.len()];
        for region in cache.code_regions {
            let piece = cache.pieces.get(region.piece).ok_or(Error::InvalidRegion)?;
            if piece.max_protection != executable
                || core::mem::replace(&mut rewritten[region.piece], true)
            {
                return Err(Error::InvalidRegion);
            }
            let code = buffers[region.piece].as_mut().ok_or(Error::InvalidRegion)?;
            task.rewrite_shared_cache_code(
                code,
                piece.range.start,
                region.instruction_ranges,
                cache.gate_islands,
                &mut gates,
            )?;
        }
        if cache
            .pieces
            .iter()
            .zip(&rewritten)
            .any(|(piece, rewritten)| {
                piece.max_protection.contains(VmProtection::EXECUTE) && !rewritten
            })
        {
            // Executable pieces without a code region would run unrewritten.
            return Err(Error::InvalidRegion);
        }
        let mut islands: Vec<Range<usize>> = cache
            .gate_islands
            .iter()
            .zip(&gates)
            .filter(|(_, gates)| !gates.is_empty())
            .map(|(island, _)| island.clone())
            .collect();
        islands.sort_by_key(|island| island.start);
        // The pieces replace the reservation's pages; `SharedCacheState`
        // holds their maximum protections.
        task.forget_replaced_maximum_protections(cache.range.clone(), true);
        for (island, gates) in cache.gate_islands.iter().zip(&gates) {
            if !gates.is_empty() {
                litebox_util_log::debug!(
                    island:? = island,
                    bytes = gates.len(),
                    description:? = cache.attribution.as_ref().and_then(|attribute| attribute(island.start));
                    "shared-cache gate island"
                );
                task.map_shared_cache_copy(island, gates, executable)?;
            }
        }
        let mut mappings = Vec::new();
        for (piece, buffer) in cache.pieces.iter().zip(&buffers) {
            let record = |range| SharedCacheMapping {
                range,
                protection: piece.protection,
                max_protection: piece.max_protection,
                paged: matches!(piece.backing, SharedCacheBacking::Paged),
            };
            match piece.backing {
                SharedCacheBacking::Reserved | SharedCacheBacking::Paged => {
                    mappings.extend(subtract(&piece.range, &islands).into_iter().map(record));
                }
                SharedCacheBacking::Source(bytes) => {
                    for range in subtract(&piece.range, &islands) {
                        let offset = range.start - piece.range.start;
                        task.map_shared_cache_source(
                            &range,
                            &bytes[offset..offset + range.len()],
                            piece.protection,
                        )?;
                        mappings.push(record(range));
                    }
                }
                SharedCacheBacking::Copy(_) => {
                    let buffer = buffer.as_deref().ok_or(Error::InvalidCacheRange)?;
                    task.map_shared_cache_copy(&piece.range, buffer, piece.protection)?;
                    mappings.push(record(piece.range.clone()));
                }
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
            .zip(&rewritten)
            .filter(|(_, rewritten)| **rewritten)
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
            attribution: cache.attribution.clone(),
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
            SharedCacheBacking::Paged => cache.pager.is_some(),
            SharedCacheBacking::Source(bytes) => {
                bytes.len() == piece.range.len()
                    && !piece.max_protection.contains(VmProtection::EXECUTE)
            }
            SharedCacheBacking::Copy(bytes) => bytes.len() <= piece.range.len(),
        };
        let executable_piece = piece.max_protection.contains(VmProtection::EXECUTE);
        let copied_code = matches!(piece.backing, SharedCacheBacking::Copy(_));
        if !valid
            || !piece.max_protection.contains(piece.protection)
            || piece
                .max_protection
                .contains(VmProtection::WRITE | VmProtection::EXECUTE)
            || (executable_piece && (!copied_code || piece.max_protection != executable))
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
                matches!(piece.backing, SharedCacheBacking::Copy(_))
                    && overlaps(&piece.range, island)
            })
        {
            return Err(Error::InvalidGateIsland);
        }
    }
    Ok(())
}

impl<P: ShimPlatform> Task<P> {
    /// Map `bytes` (zero-filled to `range`) with `protection` over the reservation.
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
                    pointer
                        .copy_from_slice(0, bytes)
                        .ok_or(litebox_common_linux::vmem::MappingError::MemoryAccess)?;
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

    /// Map a private copy-on-write view of `bytes` over the reservation.
    fn map_shared_cache_source(
        &self,
        range: &Range<usize>,
        bytes: &[u8],
        protection: VmProtection,
    ) -> Result<(), SharedCacheInstallError> {
        let length = NonZeroPageSize::new(range.len()).ok_or(SharedCacheInstallError::Map)?;
        // Nothing else uses this mm between these two calls: installation borrows
        // the `LoadedProgram`, and guest code runs only through the entrypoints
        // that `LoadedProgram::into_parts` moves out.
        // SAFETY: the range lies in this task's idle shared-cache reservation.
        let mapped = unsafe {
            self.global.mm.create_pages_with_permissions(
                NonZeroAddress::new(range.start),
                length,
                CreatePagesFlags::FIXED_ADDR,
                permissions(protection),
                None,
                |_| Ok(0),
            )
        };
        let mapped = mapped.map_err(|error| {
            litebox_util_log::warn!(error:?, range:?; "failed to map shared-cache source");
            SharedCacheInstallError::Map
        })?;
        // SAFETY: the pages were just mapped and nothing else uses them.
        let replaced = unsafe {
            self.global.platform.replace_with_copy_on_write(
                range.start,
                bytes,
                permissions(protection),
            )
        };
        if let Err(error) = replaced {
            litebox_util_log::warn!(error:?, range:?; "failed to map shared-cache source");
            // SAFETY: as above.
            if let Err(error) = unsafe { self.global.mm.remove_pages(mapped, range.len()) } {
                litebox_util_log::warn!(error:?, range:?; "failed to unmap shared-cache source");
            }
            return Err(SharedCacheInstallError::Map);
        }
        Ok(())
    }

    /// Rewrite `code`, which will execute at `address`, appending each batch's
    /// gates to the nearest island that can reach it and has capacity.
    ///
    /// `gates[i]` holds the gate bytes of `islands[i]`; its length is the next
    /// free offset. A batch's code changes are applied only after its gates
    /// have been placed.
    pub(crate) fn rewrite_shared_cache_code(
        &self,
        code: &mut [u8],
        address: usize,
        instruction_ranges: &[Range<usize>],
        islands: &[Range<usize>],
        gates: &mut [Vec<u8>],
    ) -> Result<(), SharedCacheInstallError> {
        use SharedCacheInstallError as Error;
        use litebox_trampoline::aarch64::{SVC_OPCODE_BITS, SVC_OPCODE_MASK};
        const MRS_TPIDRRO_MASK: u32 = 0xffff_ffe0;
        const MRS_TPIDRRO_BITS: u32 = 0xd53b_d060;
        const MAX_BATCH_SPAN: usize = 64 * 1024;

        debug_assert_eq!(islands.len(), gates.len());
        let ranges = instruction_ranges;
        if ranges.iter().any(|range| {
            range.start >= range.end
                || range.end > code.len()
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
        // Bound batches so their gates fit in one island page; batches whose
        // gates still do not fit are split further.
        let mut chunks = Vec::new();
        for range in ranges {
            let mut start = range.start;
            while start < range.end {
                let end = range.end.min(start + MAX_BATCH_SPAN);
                chunks.push(start..end);
                start = end;
            }
        }
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
        // Process batches in address order; split ones pushed back in order.
        pending.reverse();
        while let Some(batch_ranges) = pending.pop() {
            let batch_start = batch_ranges[0].start;
            let batch_end = batch_ranges[batch_ranges.len() - 1].end;
            let batch = &code[batch_start..batch_end];
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
                let mut patched = batch.to_vec();
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
                if too_large && span > size_of::<u32>() {
                    // Split at an instruction boundary and retry both halves.
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
                code[batch_start + local_range.start..batch_start + local_range.end]
                    .copy_from_slice(&patched[local_range]);
            }
        }
        Ok(())
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

    /// Whether `range` overlaps the reserved shared-cache instance.
    pub(crate) fn overlaps_shared_cache(&self, range: Range<usize>) -> bool {
        self.global
            .shared_cache_reservation
            .lock()
            .as_ref()
            .is_some_and(|cache| overlaps(cache, &range))
    }

    /// Supply every still-paged instance page of `range` that a guest
    /// access may touch, for a failed shim user copy of `range`, like XNU's
    /// `copyin`/`copyout` faulting pages in. Returns whether `range` overlaps
    /// the instance, so that the copy is retried. It takes
    /// `shared_cache_reservation`, then `shared_cache` and `mm`: callers' user
    /// copies must not hold any of these, nor a lock under which no other shim
    /// lock is taken (such as `ipc`).
    pub(crate) fn fault_in_shared_cache(&self, range: Range<usize>) -> bool {
        let Some(cache) = self.global.shared_cache_reservation.lock().clone() else {
            return false;
        };
        let start = range.start.max(cache.start);
        let end = range.end.min(cache.end);
        if start >= end {
            return false;
        }
        for page in (start & !(PAGE_SIZE - 1)..end).step_by(PAGE_SIZE) {
            self.page_in_shared_cache(page);
        }
        true
    }

    /// Supply a demand-paged shared-cache page for a guest data abort or a
    /// shim user copy at `address`. Returns whether the faulting access can be
    /// retried.
    pub(crate) fn page_in_shared_cache(&self, address: usize) -> bool {
        let mut cache = self.global.shared_cache.lock();
        let Some(cache) = cache.as_mut() else {
            return false;
        };
        // Any guest fault address reaches here; check membership before
        // building the page range.
        if !cache.range.contains(&address) {
            return false;
        }
        let start = address & !(PAGE_SIZE - 1);
        let Some(end) = start.checked_add(PAGE_SIZE) else {
            return false;
        };
        let page = start..end;
        if !cache.is_paged(page.start) {
            return false;
        }
        let Some(recorded) = cache.mapping_at(page.start).cloned() else {
            return false;
        };
        if recorded.protection.is_empty() {
            // The guest made the page inaccessible: a real fault.
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
        // The page gets its map entry's current protection, which guest
        // mprotect/vm_protect may have changed before it was supplied.
        if self
            .map_shared_cache_copy(&page, &supplied.bytes, recorded.protection)
            .is_err()
        {
            return false;
        }
        litebox_util_log::debug!(
            page:? = page,
            description:? = cache.attribution.as_ref().and_then(|attribute| attribute(page.start));
            "shared-cache page supplied on demand"
        );
        cache.page_in(&page);
        true
    }

    /// Describe a guest address in the installed shared cache, if any.
    pub(crate) fn describe_shared_cache_address(&self, address: usize) -> Option<String> {
        let cache = self.global.shared_cache.lock();
        let cache = cache.as_ref()?;
        if !cache.range.contains(&address) {
            return None;
        }
        Some(
            cache
                .attribution
                .as_ref()
                .and_then(|attribute| attribute(address))
                .unwrap_or_else(|| {
                    alloc::format!("shared cache +{:#x}", address - cache.range.start)
                }),
        )
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
            attribution: None,
            pager: None,
        };
        let page = |index: usize| index * PAGE_SIZE..(index + 1) * PAGE_SIZE;
        // Paging in front to back keeps one supplied and one paged record.
        for index in 1..PAGES / 2 {
            state.page_in(&page(index));
            assert_eq!(state.mappings.len(), 2);
            assert!(!state.is_paged(page(index).start));
        }
        // Every other page, then the rest: never more records than the
        // alternating pattern needs, and one once every page is supplied.
        for index in (PAGES / 2 + 1..PAGES)
            .step_by(2)
            .chain((PAGES / 2..PAGES).step_by(2))
        {
            state.page_in(&page(index));
            assert!(state.mappings.len() <= PAGES / 2 + 1);
            assert!(!state.is_paged(page(index).start));
        }
        assert_eq!(state.mappings, [record(0..end, read, false)]);
        let write = read | VmProtection::WRITE;
        state.set_protection(&page(3), write);
        assert_eq!(state.mappings.len(), 3);
        assert_eq!(state.mapping_at(page(3).start).unwrap().protection, write);
        assert_eq!(state.mapping_at(page(4).start).unwrap().protection, read);
        state.set_protection(&page(3), read);
        assert_eq!(state.mappings, [record(0..end, read, false)]);
        assert!(state.allows(&(0..end), write));
        assert!(!state.allows(&(0..end + PAGE_SIZE), read));
        assert_eq!(state.mapping_at(end), None);
    }
}
