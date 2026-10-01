// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux ELF runtime and serialized islands. Published pairs are immutable: every rewrite
//! batch owns fresh host pages, even when an older island has unused slots.
//! The outer `elf_mapping_update` mutex serializes publication and VM mutation;
//! it is never acquired by signal recovery.

use super::{
    ElfPatchState, Errno, HOST_PAGE_SIZE, MapFlags, ProtFlags, ProtectionRange, Range,
    ShimPlatform, Task, UserPtrMut, Vec, VmFlags, align_down, align_up,
    prot_flags_from_permissions, subtract_ranges,
};
use litebox::utils::TruncateExt as _;
use litebox_syscall_rewriter::aarch64::island::{self, IslandPair};

#[derive(Clone, Debug)]
pub(super) struct Load {
    pub file: Range<usize>,
    pub address: Range<usize>,
}

#[derive(Clone, Debug)]
pub(super) struct FileMapping {
    pub range: Range<usize>,
    pub offset: usize,
    // Unknown/ambiguous LOAD placement never confers gap ownership.
    pub bias: Option<usize>,
    // Explicit loader identity belongs only to this mapping, not other mmap calls.
    pub loader_managed: bool,
}

#[derive(Debug)]
pub(super) struct PublishedPair {
    pub near: Range<usize>,
    pub far: Range<usize>,
    pub sites: Vec<usize>,
    /// Serialized pair identity is per load bias, never per fd alone.
    pub serialized: Option<(usize, usize)>,
    /// This file/bias acquired the near page by extending an attested DSO boundary.
    pub prefix_bias: Option<usize>,
}

/// Geometry of a validated ET_DYN whole-image file mapping (ld.so's first mmap).
#[derive(Clone, Debug)]
pub(super) struct WholeSpan {
    pub address: Range<usize>,
    pub offset: usize,
    pub align: usize,
}

#[derive(Default)]
pub(super) struct RuntimeIslands {
    pub whole_span: Option<WholeSpan>,
    /// Extra inaccessible pages explicitly reserved by a guest whole-span mmap.
    pub mmap_reservations: Vec<(usize, Range<usize>)>,
    pub loads: Vec<Load>,
    /// Guest LOAD alignment, present only if every LOAD's geometry is valid.
    /// This need not be the host granule for an explicit loader mapping.
    pub load_alignment: Option<usize>,
    pub mappings: Vec<FileMapping>,
    pub pairs: Vec<PublishedPair>,
    pub serialized: Option<litebox_syscall_rewriter::aarch64::elf_islands::ElfIslands>,
    /// Only the main/interpreter mapper can attest to anonymous reservations.
    pub loader_reservations: Vec<Range<usize>>,
}

fn overlaps(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

impl RuntimeIslands {
    pub(super) fn validate_load_mapping(
        &self,
        start: usize,
        len: usize,
        offset: usize,
        bias: usize,
    ) -> Result<(), Errno> {
        let alignment = self.load_alignment.ok_or(Errno::ENOEXEC)?;
        let file_end = offset.checked_add(len).ok_or(Errno::EOVERFLOW)?;
        let end = start.checked_add(len).ok_or(Errno::EOVERFLOW)?;
        if len == 0
            || !bias.is_multiple_of(alignment)
            || ![start, len, offset]
                .iter()
                .all(|n| n.is_multiple_of(super::PAGE_SIZE))
            || !self.loads.iter().any(|load| {
                load.file.start <= offset
                    && file_end <= load.file.end
                    && load
                        .address
                        .start
                        .checked_add(offset - load.file.start)
                        .and_then(|address| bias.checked_add(address))
                        == Some(start)
                    && bias
                        .checked_add(load.address.end)
                        .is_some_and(|limit| end <= limit)
            })
        {
            return Err(Errno::ENOEXEC);
        }
        self.load_coverage(bias)?;
        Ok(())
    }

    pub fn record_mapping(
        &mut self,
        start: usize,
        len: usize,
        offset: usize,
        load_bias: Option<usize>,
    ) -> Result<(), Errno> {
        if let Some(bias) = load_bias {
            self.validate_load_mapping(start, len, offset, bias)?;
        }
        let mut candidates: Vec<_> = self
            .loads
            .iter()
            .filter(|load| load.file.contains(&offset))
            .filter_map(|load| {
                load.address
                    .start
                    .checked_add(offset - load.file.start)
                    .and_then(|address| start.checked_sub(address))
            })
            .collect();
        candidates.sort_unstable();
        candidates.dedup();
        let known: Vec<_> = candidates
            .iter()
            .copied()
            .filter(|bias| {
                self.mappings
                    .iter()
                    .any(|m| !m.loader_managed && m.bias == Some(*bias))
            })
            .collect();
        let whole_bias = self.whole_span.as_ref().and_then(|span| {
            (span.offset == offset && span.address.len() == len)
                .then(|| start.checked_sub(span.address.start))
                .flatten()
                .filter(|bias| bias.is_multiple_of(span.align))
        });
        let bias = load_bias
            .or(whole_bias)
            .or(match (known.as_slice(), candidates.as_slice()) {
                ([bias], _) | ([], [bias]) => Some(*bias),
                // Aliased LOAD file pages can imply different object biases. Never
                // turn that ambiguity into permission to replace a numerical gap.
                _ => None,
            });
        // A LOAD can fit object-relative arithmetic yet overflow at this bias
        // (including host-page rounding). Such a mapping remains legal as data,
        // but cannot attest to gap ownership or poison other instances' coverage.
        let bias = bias.filter(|&bias| self.load_coverage(bias).is_ok());
        self.mappings.push(FileMapping {
            range: start..start.checked_add(len).ok_or(Errno::EOVERFLOW)?,
            offset,
            bias,
            loader_managed: load_bias.is_some(),
        });
        self.refresh_serialized_sites()?;
        Ok(())
    }

    fn refresh_serialized_sites(&mut self) -> Result<(), Errno> {
        let Some(payload) = &self.serialized else {
            return Ok(());
        };
        for published in &mut self.pairs {
            let Some((bias, index)) = published.serialized else {
                continue;
            };
            let pair = &payload.pairs[index];
            for index in 0..pair.slots_used() {
                let slot = island::decode_island_slot(pair.island(), pair.island_vaddr(), index)
                    .ok_or(Errno::ENOEXEC)?;
                let site = bias
                    .checked_add(usize::try_from(slot.site).map_err(|_| Errno::ENOEXEC)?)
                    .ok_or(Errno::ENOEXEC)?;
                if !slot.auxiliary
                    && self
                        .mappings
                        .iter()
                        .any(|m| m.bias == Some(bias) && m.range.contains(&site))
                    && !published.sites.contains(&site)
                {
                    published.sites.push(site);
                }
            }
        }
        Ok(())
    }

    pub fn mapping(&self, start: usize, len: usize) -> Option<&FileMapping> {
        let end = start.checked_add(len)?;
        self.mappings
            .iter()
            .find(|m| m.range.start <= start && end <= m.range.end)
    }

    pub fn owned_ranges(&self) -> impl Iterator<Item = Range<usize>> + '_ {
        self.pairs
            .iter()
            .flat_map(|p| [p.near.clone(), p.far.clone()])
    }

    /// A destructive operation may remove transport only if it also removes
    /// every site referencing that pair. Otherwise reject before VM side effects.
    pub fn permits_removal(&self, range: &Range<usize>) -> bool {
        self.pairs.iter().all(|p| {
            (!overlaps(range, &p.near) && !overlaps(range, &p.far))
                || p.sites.iter().all(|site| range.contains(site))
        })
    }

    pub fn touches(&self, range: &Range<usize>) -> bool {
        self.mappings.iter().any(|m| overlaps(&m.range, range))
            || self.owned_ranges().any(|r| overlaps(&r, range))
            || self
                .mmap_reservations
                .iter()
                .any(|(_, r)| overlaps(r, range))
    }

    /// Split mappings, retaining the exact file offset in the right fragment.
    pub fn remove(&mut self, range: &Range<usize>) -> Vec<Range<usize>> {
        let mut mappings = Vec::new();
        for m in self.mappings.drain(..) {
            for part in subtract_ranges(m.range.clone(), core::slice::from_ref(range)) {
                mappings.push(FileMapping {
                    offset: m.offset + part.start - m.range.start,
                    bias: m.bias,
                    loader_managed: m.loader_managed,
                    range: part,
                });
            }
        }
        self.mappings = mappings;
        self.loader_reservations = self
            .loader_reservations
            .drain(..)
            .flat_map(|r| subtract_ranges(r, core::slice::from_ref(range)))
            .collect();
        let mut released = Vec::new();
        self.mmap_reservations = self
            .mmap_reservations
            .drain(..)
            .flat_map(|(bias, r)| {
                let parts = subtract_ranges(r, core::slice::from_ref(range));
                if self.mappings.iter().any(|m| m.bias == Some(bias)) {
                    parts.into_iter().map(|r| (bias, r)).collect::<Vec<_>>()
                } else {
                    released.extend(parts);
                    Vec::new()
                }
            })
            .collect();
        self.pairs.retain_mut(|p| {
            p.sites.retain(|site| !range.contains(site));
            if p.sites.is_empty() {
                released.extend([p.near.clone(), p.far.clone()]);
                false
            } else {
                true
            }
        });
        released
    }

    pub(super) fn future_loads(&self) -> Result<Vec<Range<usize>>, Errno> {
        let mut biases: Vec<_> = self.mappings.iter().filter_map(|m| m.bias).collect();
        biases.sort_unstable();
        biases.dedup();
        let mut coverage = Vec::new();
        for bias in biases {
            coverage.extend(self.load_coverage(bias)?);
        }
        Ok(coverage)
    }

    fn load_coverage(&self, bias: usize) -> Result<Vec<Range<usize>>, Errno> {
        self.loads
            .iter()
            .map(|load| {
                Ok(align_down(
                    bias.checked_add(load.address.start)
                        .ok_or(Errno::EOVERFLOW)?,
                    HOST_PAGE_SIZE,
                )
                    ..bias
                        .checked_add(load.address.end)
                        .and_then(|end| end.checked_next_multiple_of(HOST_PAGE_SIZE))
                        .ok_or(Errno::EOVERFLOW)?)
            })
            .collect()
    }
}

/// An unpublished mapping and, for a replaced owned file gap, its rollback
/// image/protection. Releasing unused capacity must not punch holes in ld.so's
/// still-live whole-span file mapping.
struct StagedMapping {
    range: Range<usize>,
    previous: Option<(Vec<u8>, ProtFlags)>,
    prefix_bias: Option<usize>,
}

pub(super) struct HeapCorridor {
    pub range: Range<usize>,
    pub heap_end: usize,
    pub dso: bool,
}

struct IslandPlacement {
    preferred: usize,
    allowed: core::ops::RangeInclusive<usize>,
}

impl IslandPlacement {
    fn for_site(site: &island::UnplacedIslandSite) -> Result<Self, Errno> {
        Ok(Self {
            preferred: usize::try_from(site.site).map_err(|_| Errno::ENOEXEC)?,
            allowed: usize::try_from(*site.placement_range.start()).map_err(|_| Errno::ENOEXEC)?
                ..=usize::try_from(*site.placement_range.end()).map_err(|_| Errno::ENOEXEC)?,
        })
    }
}

/// Intersect whole host pages with the exact allowed base interval before walking.
fn island_pages(
    gap: Range<usize>,
    allowed: &core::ops::RangeInclusive<usize>,
) -> impl Iterator<Item = usize> {
    let low = gap
        .start
        .max(*allowed.start())
        .checked_next_multiple_of(HOST_PAGE_SIZE)
        .unwrap_or(usize::MAX);
    let last = gap
        .end
        .checked_sub(HOST_PAGE_SIZE)
        .map(|last| last.min(*allowed.end()));
    let end = last.filter(|&last| low <= last).map_or(low, |last| {
        align_down(last, HOST_PAGE_SIZE) + HOST_PAGE_SIZE
    });
    (low..end).step_by(HOST_PAGE_SIZE)
}

/// A private reservation, before the requested file mapping is committed.
pub(super) struct MmapEnvelope {
    pub range: Range<usize>,
    pub file_start: usize,
    pub bias: usize,
    pub islands: Vec<Range<usize>>,
}

impl<Platform: ShimPlatform> Task<Platform> {
    pub(super) fn reserve_mmap_island_envelope(
        &self,
        key: &super::ElfPatchKey,
        suggested: Option<usize>,
        len: usize,
        offset: usize,
        flags: MapFlags,
    ) -> Result<Option<MmapEnvelope>, super::MappingError> {
        // Only ordinary private mappings, plus Linux's ignored DENYWRITE and
        // EXECUTABLE bits. Fixed, shared and special allocation flags retain
        // their existing path and never acquire guessed ownership.
        if flags.bits() & !(MapFlags::MAP_PRIVATE.bits() | 0x800 | 0x1000) != 0
            || !flags.contains(MapFlags::MAP_PRIVATE)
        {
            return Ok(None);
        }
        let cache = self.global.elf_patch_cache.lock();
        let Some(state) = cache.get(key) else {
            return Ok(None);
        };
        let Some(span) = state
            .islands
            .whole_span
            .as_ref()
            .filter(|s| s.address.len() == len && s.offset == offset)
        else {
            return Ok(None);
        };
        let Some(payload) = state
            .islands
            .serialized
            .as_ref()
            .filter(|p| !p.pairs.is_empty())
        else {
            return Ok(None);
        };
        let mut low = span.address.start;
        let mut high = span.address.end;
        let mut images = Vec::new();
        for pair in &payload.pairs {
            let start = usize::try_from(pair.island_vaddr())
                .map_err(|_| super::MappingError::OutOfMemory)?;
            let end = start
                .checked_add(HOST_PAGE_SIZE)
                .ok_or(super::MappingError::OutOfMemory)?;
            low = low.min(start);
            high = high.max(end);
            images.push(start..end);
        }
        low = align_down(low, span.align);
        let size = high
            .checked_sub(low)
            .and_then(|v| v.checked_add(span.align - super::PAGE_SIZE))
            .ok_or(super::MappingError::OutOfMemory)?;
        let hint = suggested.and_then(|s| s.checked_sub(span.address.start - low));
        let reserved = self.do_mmap_anonymous(
            hint,
            size,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )?;
        let start = align_up(reserved.as_usize(), span.align);
        let Some(bias) = start.checked_sub(low) else {
            let _ = self.sys_munmap_raw(reserved, size);
            return Err(super::MappingError::OutOfMemory);
        };
        Ok(Some(MmapEnvelope {
            range: reserved.as_usize()..reserved.as_usize() + size,
            file_start: bias + span.address.start,
            bias,
            islands: images
                .into_iter()
                .map(|r| bias + r.start..bias + r.end)
                .collect(),
        }))
    }

    pub(super) fn island_removal_allowed(&self, range: Range<usize>) -> Result<(), Errno> {
        if self
            .global
            .elf_patch_cache
            .lock()
            .values()
            .all(|s| s.islands.permits_removal(&range))
        {
            Ok(())
        } else {
            Err(Errno::EBUSY)
        }
    }

    /// Mirror Vmem's range-selection and insertion checks for Replace before
    /// revoking EXEC. The caller holds elf_mapping_update across this check and
    /// the replacement, serializing guest mapping mutations with publication.
    pub(super) fn preflight_island_replacement(&self, range: &Range<usize>) -> Result<(), Errno> {
        use litebox::platform::page_mgmt::AllocationError;

        let error = if range.end > Platform::TASK_ADDR_MAX {
            // get_unmmaped_area rejects this before insert_mapping is called.
            Some(AllocationError::OutOfMemory)
        } else if range.start < Platform::TASK_ADDR_MIN {
            Some(AllocationError::BelowMinAddress)
        } else {
            let mappings: Vec<_> = self
                .global
                .mm
                .mappings()
                .into_iter()
                .map(|(r, _)| r)
                .collect();
            if mappings.iter().any(|r| overlaps(r, range))
                && !subtract_ranges(range.clone(), &mappings).is_empty()
            {
                Some(AllocationError::AddressPartiallyInUse)
            } else {
                None
            }
        };
        match error {
            Some(error) => Err(super::MappingError::MapError(error).into()),
            None => Ok(()),
        }
    }

    pub(super) fn close_island_sites_for_replacement(
        &self,
        range: &Range<usize>,
    ) -> Result<(), Errno> {
        let cache = self.global.elf_patch_cache.lock();
        let pages: alloc::collections::BTreeSet<_> = cache
            .values()
            .flat_map(|s| &s.islands.pairs)
            .flat_map(|pair| &pair.sites)
            .filter(|site| range.contains(site))
            .map(|site| align_down(*site, super::PAGE_SIZE))
            .collect();
        for page in pages {
            self.sys_mprotect_raw(
                UserPtrMut::from_usize(page),
                super::PAGE_SIZE,
                ProtFlags::PROT_READ,
            )?;
        }
        Ok(())
    }

    pub(super) fn invalidate_failed_island_replacement(&self, range: &Range<usize>) {
        for state in self.global.elf_patch_cache.lock().values_mut() {
            if state.islands.touches(range) {
                state.trampoline_invalidated = true;
            }
        }
    }

    fn rollback_island_mapping(&self, mapping: StagedMapping) -> Result<(), Errno> {
        let ptr = UserPtrMut::from_usize(mapping.range.start);
        if let Some((bytes, prot)) = mapping.previous {
            self.sys_mprotect_raw(ptr, mapping.range.len(), ProtFlags::PROT_READ_WRITE)?;
            ptr.copy_from_slice::<Platform>(0, &bytes)
                .ok_or(Errno::EFAULT)?;
            self.sys_mprotect_raw(ptr, mapping.range.len(), prot)
        } else {
            self.sys_munmap_raw(ptr, mapping.range.len())
        }
    }

    fn rollback_island_mapping_or_fatal(&self, mapping: StagedMapping) {
        // A removed reservation cannot be retried after indeterminate VM rollback.
        assert!(
            self.rollback_island_mapping(mapping).is_ok(),
            "failed to roll back unpublished island mapping"
        );
    }

    fn allocate_island(
        &self,
        state: &RuntimeIslands,
        bias: usize,
        placement: IslandPlacement,
        reserved: &[StagedMapping],
        future_loads: &[Range<usize>],
        heap: Option<&HeapCorridor>,
    ) -> Result<StagedMapping, Errno> {
        let heap_corridor = heap.map(|h| &h.range);
        let coverage = state.load_coverage(bias)?;
        let start = coverage
            .iter()
            .map(|r| r.start)
            .min()
            .ok_or(Errno::ENOEXEC)?;
        let end = coverage.iter().map(|r| r.end).max().ok_or(Errno::ENOEXEC)?;
        // The rewriter supplies the common interval for every direct edge.
        // Later slot assignments are checked independently by the emitter.
        let site = placement.preferred;
        let near_min = *placement.allowed.start();
        let near_max = (*placement.allowed.end()).min(usize::MAX - HOST_PAGE_SIZE);
        if near_min > near_max {
            return Err(Errno::ENOMEM);
        }
        let current = self.global.mm.mappings();
        let claim = |address: usize, owned: bool| {
            if address < near_min || address > near_max {
                return None;
            }
            let previous = if owned {
                let (_, flags) = current
                    .iter()
                    .find(|(r, _)| r.start <= address && address + HOST_PAGE_SIZE <= r.end)?;
                // If the gap is inaccessible, use NOREPLACE rather than read or
                // change its protection merely to establish a staging backup.
                if !flags.contains(VmFlags::VM_READ) {
                    return None;
                }
                let bytes = UserPtrMut::<u8>::from_usize(address)
                    .to_owned_slice::<Platform>(HOST_PAGE_SIZE)?
                    .into_vec();
                Some((bytes, prot_flags_from_permissions((*flags).into())))
            } else {
                None
            };
            let flags = if owned {
                MapFlags::MAP_FIXED
            } else {
                MapFlags::MAP_FIXED_NOREPLACE
            };
            self.do_mmap_anonymous(
                Some(address),
                HOST_PAGE_SIZE,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | flags,
            )
            .ok()
            .map(|p| StagedMapping {
                range: p.as_usize()..p.as_usize() + HOST_PAGE_SIZE,
                previous,
                prefix_bias: None,
            })
        };
        // Every gap, after unioning filesz AND memsz coverage at host granularity.
        // Numerical inclusion in load_span is not ownership. A whole-page live
        // file mapping from this instance is evidence; otherwise use NOREPLACE.
        let mut unavailable = coverage.clone();
        unavailable.extend_from_slice(future_loads);
        unavailable.extend(state.owned_ranges());
        unavailable.extend(reserved.iter().map(|r| r.range.clone()));
        unavailable.extend(heap_corridor.cloned());
        let owned: Vec<_> = state
            .mappings
            .iter()
            .filter(|m| m.bias == Some(bias))
            .map(|m| m.range.clone())
            .collect();
        for (range, _) in &current {
            unavailable.extend(
                subtract_ranges(range.clone(), &owned)
                    .into_iter()
                    .map(|r| align_down(r.start, HOST_PAGE_SIZE)..align_up(r.end, HOST_PAGE_SIZE)),
            );
        }
        for gap in subtract_ranges(start..end, &unavailable) {
            for address in island_pages(gap, &(near_min..=near_max)) {
                let range = address..address + HOST_PAGE_SIZE;
                let owned = state.mappings.iter().any(|m| {
                    m.bias == Some(bias) && m.range.start <= address && range.end <= m.range.end
                }) && current
                    .iter()
                    .any(|(r, _)| r.start <= address && range.end <= r.end);
                if !owned && current.iter().any(|(r, _)| overlaps(r, &range)) {
                    continue;
                }
                if let Some(address) = claim(address, owned) {
                    return Ok(address);
                }
            }
        }
        // Search both sides within B reach. Only loader-supplied main-image
        // provenance excludes the current heap corridor; DSO size/address is
        // never used as a heuristic for main-image ownership.
        let low = align_up(near_min.max(HOST_PAGE_SIZE), HOST_PAGE_SIZE);
        let high = align_down(near_max, HOST_PAGE_SIZE).saturating_add(HOST_PAGE_SIZE);
        if low < high {
            let mut occupied: Vec<_> = current
                .iter()
                .map(|(r, _)| align_down(r.start, HOST_PAGE_SIZE)..align_up(r.end, HOST_PAGE_SIZE))
                .collect();
            occupied.extend_from_slice(future_loads);
            occupied.extend(heap_corridor.cloned());
            let free = subtract_ranges(low..high, &occupied);
            // Nearest available below the site first, then above it. The core
            // checks the exact inbound and all outbound displacements.
            for range in free.iter().rev() {
                let end = range.end.min(align_down(site, HOST_PAGE_SIZE));
                if range.start >= end {
                    continue;
                }
                for address in (range.start..end).step_by(HOST_PAGE_SIZE).rev() {
                    if let Some(mapping) = claim(address, false) {
                        return Ok(mapping);
                    }
                }
            }
            for range in free {
                let start = range.start.max(align_up(site, HOST_PAGE_SIZE));
                for address in (start..range.end).step_by(HOST_PAGE_SIZE) {
                    if let Some(mapping) = claim(address, false) {
                        return Ok(mapping);
                    }
                }
            }
        }
        // Last resort: consume exactly one page below the CURRENT upper heap
        // barrier, never scan the corridor. Only this file/bias may extend its
        // DSO or a previously attested prefix; unrelated mappings fail closed.
        if let Some(heap) = heap.filter(|h| h.dso) {
            let frontier = current
                .iter()
                .map(|(r, _)| r.start)
                .filter(|&start| start >= heap.heap_end)
                .min()
                .unwrap_or(heap.range.end)
                .min(heap.range.end);
            let owned = state.mappings.iter().any(|m| {
                m.bias == Some(bias)
                    && m.range.start == frontier
                    && coverage.iter().any(|r| r.contains(&frontier))
            }) || state
                .pairs
                .iter()
                .any(|p| p.prefix_bias == Some(bias) && p.near.start == frontier)
                || reserved
                    .iter()
                    .any(|r| r.prefix_bias == Some(bias) && r.range.start == frontier);
            if let Some(address) = frontier.checked_sub(HOST_PAGE_SIZE).filter(|address| {
                owned
                    && address.is_multiple_of(HOST_PAGE_SIZE)
                    && *address >= heap.heap_end.max(heap.range.start)
            }) {
                let extent = address..frontier;
                if !future_loads
                    .iter()
                    .chain(&coverage)
                    .any(|r| overlaps(r, &extent))
                    && !current.iter().any(|(r, _)| overlaps(r, &extent))
                    && !state.owned_ranges().any(|r| overlaps(&r, &extent))
                    && !reserved.iter().any(|r| overlaps(&r.range, &extent))
                    && let Some(mut mapping) = claim(address, false)
                {
                    mapping.prefix_bias = Some(bias);
                    return Ok(mapping);
                }
            }
        }
        Err(Errno::ENOMEM)
    }

    /// Full chunks have no distance constraint. Avoid even not-yet-mapped LOADs
    /// of every tracked instance; a partial/out-of-order loader has not reserved
    /// all of those addresses in the page manager yet.
    fn allocate_chunk(
        &self,
        len: usize,
        future_loads: &[Range<usize>],
        heap_corridor: Option<&Range<usize>>,
    ) -> Result<UserPtrMut<u8>, Errno> {
        // Reserve inaccessible VA first: a guest-page allocator can return a
        // 4KiB-aligned address inside a 16KiB host page. Never make that edge RW
        // (or remove EXEC from a neighbour) merely to obtain aligned storage.
        let reserved_len = len.checked_add(HOST_PAGE_SIZE).ok_or(Errno::ENOMEM)?;
        let candidate = self
            .do_mmap_anonymous(
                None,
                reserved_len,
                ProtFlags::PROT_NONE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
            )
            .map_err(Errno::from)?;
        let start = align_up(candidate.as_usize(), HOST_PAGE_SIZE);
        let range = start..start + len;
        if !future_loads
            .iter()
            .chain(heap_corridor)
            .any(|load| overlaps(load, &range))
        {
            let result = (|| {
                if start > candidate.as_usize() {
                    self.sys_munmap_raw(candidate, start - candidate.as_usize())?;
                }
                let end = candidate.as_usize() + reserved_len;
                if range.end < end {
                    self.sys_munmap_raw(UserPtrMut::from_usize(range.end), end - range.end)?;
                }
                let ptr = UserPtrMut::from_usize(start);
                self.sys_mprotect_raw(ptr, len, ProtFlags::PROT_READ_WRITE)?;
                Ok(ptr)
            })();
            if result.is_err() {
                let _ = self.sys_munmap_raw(candidate, reserved_len);
            }
            return result;
        }
        self.sys_munmap_raw(candidate, reserved_len)?;
        let mut unavailable: Vec<_> = self
            .global
            .mm
            .mappings()
            .into_iter()
            .map(|(range, _)| {
                align_down(range.start, HOST_PAGE_SIZE)..align_up(range.end, HOST_PAGE_SIZE)
            })
            .collect();
        unavailable.extend_from_slice(future_loads);
        unavailable.extend(heap_corridor.cloned());
        for free in subtract_ranges(HOST_PAGE_SIZE..range.end, &unavailable)
            .into_iter()
            .rev()
        {
            let start = align_up(free.start, HOST_PAGE_SIZE);
            let end = align_down(free.end, HOST_PAGE_SIZE);
            if end.saturating_sub(start) < len {
                continue;
            }
            let candidates = (end - len - start) / HOST_PAGE_SIZE + 1;
            for page in (0..candidates).rev() {
                let address = start + page * HOST_PAGE_SIZE;
                if let Ok(ptr) = self.do_mmap_anonymous(
                    Some(address),
                    len,
                    ProtFlags::PROT_READ_WRITE,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED_NOREPLACE,
                ) {
                    return Ok(ptr);
                }
            }
        }
        Err(Errno::ENOMEM)
    }

    /// Shared immutable-image publication for both runtime and serialized pairs.
    fn publish_island_pair(
        &self,
        mut pair: IslandPair,
        reservations: &mut Vec<StagedMapping>,
        future_loads: &[Range<usize>],
        callback: usize,
        tls: u16,
        heap_corridor: Option<&HeapCorridor>,
    ) -> Result<PublishedPair, Errno> {
        let options = crate::aarch64_rewrite_options();
        let far_len = align_up(pair.chunk().len(), HOST_PAGE_SIZE);
        // Deliberately no distance test: a full chunk is position independent.
        let far = self.allocate_chunk(far_len, future_loads, heap_corridor.map(|h| &h.range))?;
        reservations.push(StagedMapping {
            range: far.as_usize()..far.as_usize() + far_len,
            previous: None,
            prefix_bias: None,
        });
        pair.set_chunk_vaddr(far.as_usize() as u64)
            .map_err(|_| Errno::ENOEXEC)?;
        pair.set_callback(callback as u64);
        let mut chunk = pair.chunk().to_vec();
        island::finalize_island_chunk(&mut chunk, tls, options.target_host())
            .map_err(|_| Errno::ENOEXEC)?;
        // Whole-pair validation before any site publication.
        IslandPair::from_images(
            pair.island_vaddr(),
            pair.island().to_vec(),
            chunk.clone(),
            options.target_host(),
        )
        .map_err(|_| Errno::ENOEXEC)?;
        let near = UserPtrMut::from_usize(pair.island_vaddr().trunc());
        near.copy_from_slice::<Platform>(0, pair.island())
            .ok_or(Errno::EFAULT)?;
        far.copy_from_slice::<Platform>(0, &chunk)
            .ok_or(Errno::EFAULT)?;
        self.sys_mprotect_raw(far, far_len, ProtFlags::PROT_READ | ProtFlags::PROT_EXEC)?;
        self.sys_mprotect_raw(
            near,
            HOST_PAGE_SIZE,
            ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
        )?;
        let sites = (0..pair.slots_used())
            .filter_map(|i| island::decode_island_slot(pair.island(), pair.island_vaddr(), i))
            .filter(|s| !s.auxiliary)
            .map(|s| s.site.trunc())
            .collect();
        litebox_util_log::debug!(near:? = near.as_usize(), far:? = far.as_usize(), slots:? = pair.slots_used(); "published immutable AArch64 island pair");
        Ok(PublishedPair {
            near: near.as_usize()..near.as_usize() + HOST_PAGE_SIZE,
            far: far.as_usize()..far.as_usize() + far_len,
            sites,
            serialized: None,
            prefix_bias: reservations
                .iter()
                .find(|r| r.range.start == near.as_usize())
                .and_then(|r| r.prefix_bias),
        })
    }

    /// Record loader-owned envelope pages; no numerical DSO gap implies this
    /// provenance. Called before LOAD publication, while the new image is closed.
    pub(crate) fn prepare_serialized_islands(
        &self,
        fd: &super::ElfPatchKey,
        payload: &litebox_syscall_rewriter::aarch64::elf_islands::ElfIslands,
        bias: usize,
        reserved: bool,
    ) -> Result<(), Errno> {
        payload
            .check_compatibility(crate::aarch64_rewrite_options(), HOST_PAGE_SIZE)
            .map_err(|_| Errno::ENOEXEC)?;
        self.global
            .platform
            .get_aarch64_island_entry_point()
            .filter(|p| *p != 0)
            .ok_or(Errno::ENOSYS)?;
        self.init_elf_patch_state(fd, bias, 0);
        let mut cache = self.global.elf_patch_cache.lock();
        let state = cache.get_mut(fd).ok_or(Errno::ENOEXEC)?;
        if state.trampoline_invalidated {
            return Err(Errno::ENOEXEC);
        }
        if reserved {
            for pair in &payload.pairs {
                let start = bias
                    .checked_add(usize::try_from(pair.island_vaddr()).map_err(|_| Errno::ENOEXEC)?)
                    .ok_or(Errno::ENOEXEC)?;
                state
                    .islands
                    .loader_reservations
                    .push(start..start.checked_add(HOST_PAGE_SIZE).ok_or(Errno::ENOEXEC)?);
            }
        }
        Ok(())
    }

    fn install_serialized_islands(
        &self,
        state: &mut RuntimeIslands,
        mapping: &FileMapping,
        range: &Range<usize>,
        future_loads: &[Range<usize>],
        publication: (usize, u16, Option<&HeapCorridor>),
    ) -> Result<(), Errno> {
        let (callback, tls, heap_corridor) = publication;
        let Some(payload) = state.serialized.clone() else {
            return Ok(());
        };
        if payload.pairs.is_empty() {
            return Ok(());
        }
        let bias = mapping.bias.ok_or(Errno::ENOEXEC)?;
        let mut reservations = Vec::new();
        let result = (|| {
            let mut published = Vec::new();
            for (index, image) in payload.pairs.iter().enumerate() {
                if state
                    .pairs
                    .iter()
                    .any(|p| p.serialized == Some((bias, index)))
                {
                    continue;
                }
                let near = bias
                    .checked_add(usize::try_from(image.island_vaddr()).map_err(|_| Errno::ENOEXEC)?)
                    .ok_or(Errno::ENOEXEC)?;
                let mut pair = IslandPair::from_images(
                    near as u64,
                    image.island().to_vec(),
                    image.chunk().to_vec(),
                    payload.options.target_host(),
                )
                .map_err(|_| Errno::ENOEXEC)?;
                let needed = (0..pair.slots_used())
                    .filter_map(|i| island::decode_island_slot(pair.island(), near as u64, i))
                    .any(|s| {
                        !s.auxiliary
                            && usize::try_from(s.site).is_ok_and(|site| range.contains(&site))
                    });
                if !needed {
                    continue;
                }
                let extent = near..near.checked_add(HOST_PAGE_SIZE).ok_or(Errno::ENOEXEC)?;
                let exact = (|| {
                    if future_loads.iter().any(|r| overlaps(r, &extent))
                        || state.owned_ranges().any(|r| overlaps(&r, &extent))
                        || reservations
                            .iter()
                            .any(|r: &StagedMapping| overlaps(&r.range, &extent))
                    {
                        return Err(Errno::ENOMEM);
                    }
                    let current = self.global.mm.mappings();
                    let loader_owned = state
                        .loader_reservations
                        .iter()
                        .any(|r| r.start <= near && extent.end <= r.end)
                        || state
                            .mmap_reservations
                            .iter()
                            .any(|(b, r)| *b == bias && r.start <= near && extent.end <= r.end);
                    let file_owned = state.mappings.iter().any(|m| {
                        m.bias == Some(bias) && m.range.start <= near && extent.end <= m.range.end
                    });
                    if !loader_owned
                        && !file_owned
                        && heap_corridor.is_some_and(|h| overlaps(&h.range, &extent))
                    {
                        return Err(Errno::ENOMEM);
                    }
                    let owner = current
                        .iter()
                        .find(|(r, _)| r.start <= near && extent.end <= r.end);
                    let previous = if loader_owned {
                        let (_, flags) = owner.ok_or(Errno::ENOMEM)?;
                        if flags.intersects(VmFlags::VM_ACCESS_FLAGS) {
                            return Err(Errno::ENOMEM);
                        }
                        Some((Vec::new(), ProtFlags::PROT_NONE))
                    } else if file_owned
                        && owner.is_some_and(|(_, flags)| flags.contains(VmFlags::VM_READ))
                    {
                        let (_, flags) = owner.ok_or(Errno::ENOMEM)?;
                        let bytes = UserPtrMut::<u8>::from_usize(near)
                            .to_owned_slice::<Platform>(HOST_PAGE_SIZE)
                            .ok_or(Errno::EFAULT)?
                            .into_vec();
                        Some((bytes, prot_flags_from_permissions((*flags).into())))
                    } else {
                        None
                    };
                    let flags = if previous.is_some() {
                        MapFlags::MAP_FIXED
                    } else {
                        MapFlags::MAP_FIXED_NOREPLACE
                    };
                    self.do_mmap_anonymous(
                        Some(near),
                        HOST_PAGE_SIZE,
                        ProtFlags::PROT_READ_WRITE,
                        MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | flags,
                    )
                    .map_err(Errno::from)?;
                    Ok(StagedMapping {
                        range: extent,
                        previous,
                        prefix_bias: None,
                    })
                })();
                let reservation = match exact {
                    Ok(reservation) => reservation,
                    Err(Errno::ENOMEM | Errno::EEXIST) => {
                        // A fixed ld.so mapping may sit inside an unrelated
                        // alignment probe. Never claim that probe's tail or move
                        // the requested file address: relocate only the prebuilt
                        // transport to a safely owned/free page in common reach.
                        let reach = pair.placement_range().map_err(|_| Errno::ENOEXEC)?;
                        let reservation = self.allocate_island(
                            state,
                            bias,
                            IslandPlacement {
                                preferred: near,
                                allowed: usize::try_from(*reach.start())
                                    .map_err(|_| Errno::ENOEXEC)?
                                    ..=usize::try_from(*reach.end()).map_err(|_| Errno::ENOEXEC)?,
                            },
                            &reservations,
                            future_loads,
                            heap_corridor,
                        )?;
                        let address = reservation.range.start;
                        reservations.push(reservation);
                        pair = pair
                            .relocated(address as u64, payload.options.target_host())
                            .map_err(|_| Errno::ENOEXEC)?;
                        litebox_util_log::debug!(serialized:? = near, actual:? = address, bias:? = bias, index:? = index;
                            "relocated serialized AArch64 island placement");
                        reservations.pop().expect("unpublished near reservation")
                    }
                    Err(error) => return Err(error),
                };
                reservations.push(reservation);
                let mut pair = self.publish_island_pair(
                    pair,
                    &mut reservations,
                    future_loads,
                    callback,
                    tls,
                    heap_corridor,
                )?;
                pair.serialized = Some((bias, index));
                // Only actually mapped source pages hold references. Future
                // mappings install a retired pair anew, or reuse it immutably.
                pair.sites.retain(|site| {
                    state
                        .mappings
                        .iter()
                        .any(|m| m.bias == Some(bias) && m.range.contains(site))
                });
                published.push(pair);
            }
            for pair in &published {
                state
                    .loader_reservations
                    .retain(|r| !overlaps(r, &pair.near));
                state
                    .mmap_reservations
                    .retain(|(_, r)| !overlaps(r, &pair.near));
            }
            state.pairs.extend(published);
            reservations.clear();
            Ok(())
        })();
        if let Err(error) = &result {
            litebox_util_log::error!(error:? = error, bias:? = bias, range:? = range;
                "serialized island placement/publication failed; code remains closed");
            for reservation in reservations.into_iter().rev() {
                self.rollback_island_mapping_or_fatal(reservation);
            }
        }
        result
    }

    pub(super) fn patch_exec_with_islands(
        &self,
        state: &mut ElfPatchState,
        mapped: UserPtrMut<u8>,
        len: usize,
        restore: &[ProtectionRange],
        future_loads: &[Range<usize>],
        heap_corridor: Option<&HeapCorridor>,
    ) -> Result<(), Errno> {
        if restore
            .iter()
            .any(|(_, _, prot)| prot.contains(ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC))
        {
            return Err(Errno::EACCES);
        }
        let start = mapped.as_usize();
        if state.patched_ranges.contains(&(start, len)) {
            return Ok(());
        }
        let mapping = state
            .islands
            .mapping(start, len)
            .ok_or(Errno::ENOEXEC)?
            .clone();
        let ranges = state
            .code_metadata
            .as_ref()
            .ok_or(Errno::ENOEXEC)?
            .ranges_for_mapping((mapping.offset + start - mapping.range.start) as u64, len)
            .map_err(|_| Errno::ENOEXEC)?;
        let callback = self
            .global
            .platform
            .get_aarch64_island_entry_point()
            .filter(|p| *p != 0)
            .ok_or(Errno::ENOSYS)?;
        let tls = self
            .global
            .platform
            .guest_thread_pointer_offset()
            .and_then(|o| u16::try_from(o).ok())
            .ok_or(Errno::ENOSYS)?;
        // Capture actual permissions, not the caller's requested +X for mmap.
        // A safe pre-publication failure must never expose native syscall bytes.
        let previous: Vec<_> = self
            .global
            .mm
            .mappings()
            .into_iter()
            .filter_map(|(range, flags)| {
                let low = start.max(range.start);
                let high = (start + len).min(range.end);
                (low < high).then(|| (low, high - low, prot_flags_from_permissions(flags.into())))
            })
            .collect();
        let mut reservations: Vec<StagedMapping> = Vec::new();
        let mut source_write_started = false;
        let result = (|| {
            self.install_serialized_islands(
                &mut state.islands,
                &mapping,
                &(start..start + len),
                future_loads,
                (callback, tls, heap_corridor),
            )?;
            let options = crate::aarch64_rewrite_options();
            let excluded: Vec<_> = state.islands.owned_ranges().collect();
            for part in subtract_ranges(start..start + len, &excluded) {
                self.sys_mprotect_raw(
                    UserPtrMut::from_usize(part.start),
                    part.len(),
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                )?;
            }
            let original = mapped
                .to_owned_slice::<Platform>(len)
                .ok_or(Errno::EFAULT)?
                .into_vec();
            let mut redirected = original.clone();
            if let Some(payload) = &state.islands.serialized {
                for published in &state.islands.pairs {
                    let Some((bias, index)) = published.serialized else {
                        continue;
                    };
                    if mapping.bias != Some(bias) {
                        continue;
                    }
                    let image = &payload.pairs[index];
                    let serialized = bias
                        .checked_add(image.island_vaddr().trunc())
                        .ok_or(Errno::ENOEXEC)?;
                    let pair = IslandPair::from_images(
                        serialized as u64,
                        image.island().to_vec(),
                        image.chunk().to_vec(),
                        payload.options.target_host(),
                    )
                    .and_then(|pair| {
                        pair.relocated(published.near.start as u64, payload.options.target_host())
                    })
                    .map_err(|_| Errno::ENOEXEC)?;
                    pair.redirect_inbound_branches(
                        &mut redirected,
                        start as u64,
                        serialized as u64,
                    )
                    .map_err(|_| Errno::ENOEXEC)?;
                }
            }
            let mut probe = redirected.clone();
            let sites = litebox_syscall_rewriter::patch_aarch64_code_segment_with_islands(
                &mut probe,
                start as u64,
                &ranges,
                &mut [],
                options,
            )
            .map_err(|_| Errno::ENOEXEC)?
            .unplaced_sites;
            let slots = sites.iter().try_fold(0usize, |count, site| {
                count.checked_add(site.slots).ok_or(Errno::ENOEXEC)
            })?;
            let mut pairs = Vec::with_capacity(
                state
                    .island_slot_estimate
                    .min(sites.len().saturating_mul(2))
                    .div_ceil(island::ISLAND_SLOTS),
            );
            // Runtime bytes, not pre-scan, are authoritative. Slot counting
            // includes auxiliary x18 exits. Spread placement over the batch.
            let pair_count = slots.div_ceil(island::ISLAND_SLOTS - 1);
            for index in 0..pair_count {
                let reservation = self.allocate_island(
                    &state.islands,
                    mapping.bias.ok_or(Errno::ENOEXEC)?,
                    IslandPlacement::for_site(&sites[index * sites.len() / pair_count])?,
                    &reservations,
                    future_loads,
                    heap_corridor,
                )?;
                let address = reservation.range.start;
                reservations.push(reservation);
                pairs.push(IslandPair::new(address as u64).map_err(|_| Errno::ENOEXEC)?);
            }
            let mut code = redirected.clone();
            let mut outcome = litebox_syscall_rewriter::patch_aarch64_code_segment_with_islands(
                &mut code,
                start as u64,
                &ranges,
                &mut pairs,
                options,
            )
            .map_err(|_| Errno::ENOEXEC)?;
            // Slot totals cannot prove geometric coverage (e.g. two small LOADs
            // separated by >256MiB). Try another immutable pair for each still
            // supported trapped site. Unsupported words retain BRK without
            // reserving transport they cannot use.
            for site in outcome.unplaced_sites.clone() {
                if !outcome.unplaced_sites.contains(&site) {
                    continue;
                }
                let reservation = self.allocate_island(
                    &state.islands,
                    mapping.bias.ok_or(Errno::ENOEXEC)?,
                    IslandPlacement::for_site(&site)?,
                    &reservations,
                    future_loads,
                    heap_corridor,
                )?;
                let mut expanded: Vec<_> = pairs
                    .iter()
                    .map(|p| IslandPair::new(p.island_vaddr()))
                    .collect::<Result<_, _>>()
                    .map_err(|_| Errno::ENOEXEC)?;
                expanded.push(
                    IslandPair::new(reservation.range.start as u64).map_err(|_| Errno::ENOEXEC)?,
                );
                reservations.push(reservation);
                let mut retry = redirected.clone();
                let next = litebox_syscall_rewriter::patch_aarch64_code_segment_with_islands(
                    &mut retry,
                    start as u64,
                    &ranges,
                    &mut expanded,
                    options,
                )
                .map_err(|_| Errno::ENOEXEC)?;
                if next.patched_sites > outcome.patched_sites {
                    pairs = expanded;
                    code = retry;
                    outcome = next;
                } else {
                    self.rollback_island_mapping_or_fatal(
                        reservations.pop().expect("new pair reservation"),
                    );
                }
            }
            // Unsupported words may remain BRK, but supported sites must not
            // become a cached success after a failed placement/slot assignment.
            if !outcome.unplaced_sites.is_empty() {
                return Err(Errno::ENOMEM);
            }
            let mut published = Vec::new();
            for pair in pairs {
                if pair.slots_used() == 0 {
                    let address = pair.island_vaddr().trunc();
                    let index = reservations
                        .iter()
                        .position(|r| r.range.start == address)
                        .ok_or(Errno::EINVAL)?;
                    self.rollback_island_mapping_or_fatal(reservations.remove(index));
                    continue;
                }
                published.push(self.publish_island_pair(
                    pair,
                    &mut reservations,
                    future_loads,
                    callback,
                    tls,
                    heap_corridor,
                )?);
            }
            // Only instruction words change, not ELF gaps now occupied by islands.
            // All destinations are validated, RX, and cache-synchronized first.
            for (i, (old, new)) in original
                .as_chunks::<4>()
                .0
                .iter()
                .zip(code.as_chunks::<4>().0.iter())
                .enumerate()
            {
                if old != new {
                    // Set before the fallible store: it may copy only a prefix.
                    source_write_started = true;
                    mapped
                        .copy_from_slice::<Platform>(i * 4, new)
                        .ok_or(Errno::EFAULT)?;
                }
            }
            state.islands.pairs.extend(published);
            reservations.clear(); // ownership transferred before code is executable
            let excluded: Vec<_> = state.islands.owned_ranges().collect();
            for (address, len, prot) in restore {
                for part in subtract_ranges(*address..*address + *len, &excluded) {
                    self.sys_mprotect_raw(UserPtrMut::from_usize(part.start), part.len(), *prot)?;
                }
            }
            state.patched_ranges.insert((start, len));
            state.runtime_patches_committed |= outcome.patched_sites != 0;
            if !outcome.trapped_sites.is_empty() {
                litebox_util_log::warn!(sites:? = outcome.trapped_sites; "runtime island sites failed closed with BRK");
            }
            Ok(())
        })();
        if let Err(error) = &result {
            litebox_util_log::error!(error:? = error, start:? = start, len:? = len; "island publication failed");
            // A fallible publication store may have written only part of the
            // site batch. Subsequent +X must not reinterpret those branches as
            // already-safe code after rollback of their destinations.
            state.trampoline_invalidated |= source_write_started;
            for reservation in reservations.into_iter().rev() {
                self.rollback_island_mapping_or_fatal(reservation);
            }
            if !source_write_started {
                // Installed serialized pairs are valid immutable state even if
                // runtime allocation failed; never restore permissions over them.
                let excluded: Vec<_> = state.islands.owned_ranges().collect();
                for (address, len, prot) in previous {
                    for part in subtract_ranges(address..address + len, &excluded) {
                        if let Err(error) = self.sys_mprotect_raw(
                            UserPtrMut::from_usize(part.start),
                            part.len(),
                            prot,
                        ) {
                            state.trampoline_invalidated = true;
                            return Err(error);
                        }
                    }
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests;
