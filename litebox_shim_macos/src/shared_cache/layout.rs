// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest-side layout of a private instance of the host's dyld shared cache.
//!
//! The platform supplies the host's on-disk cache build
//! ([`HostSharedCache`]); this module lays it out at a guest-private base
//! `G`:
//!
//! - native pages overlapping closure images' `__TEXT` are private views of
//!   the cache files, rewritten (with any neighbor code sharing a page)
//!   before they become executable;
//! - every other page of a mapping without slide info (other images' text,
//!   read-only data, `__LINKEDIT`) is a private view of the cache files, like
//!   XNU's shared region maps them;
//! - every page of a mapping with slide info is supplied on first access by
//!   the platform, rebased for slide `G - sharedRegionStart` like XNU's
//!   shared-region pagers;
//! - pages other than rewritten text have their mapping's protections
//!   without execute;
//! - the host's live DynamicRegion page is copied read-only.
//!
//! The closure is the launch-time initializer closure of
//! `/usr/lib/libSystem.B.dylib`, dyld-in-cache and the executable's own
//! cache dependencies, delay-initialized ones too (dyld defers only their
//! initializers, not their code). Gate islands are whole pages of the shared
//! region outside every cache mapping, or strictly inside `__TEXT,__text` of
//! cache images outside the launch set (the closure plus the delay-init links
//! of its roots); the guest never reads their bytes.
//!
//! Only native pages holding closure text are executable: other cache code
//! faults when called, and other images' `__text` may hold gate islands,
//! which only enter the shim. Making the whole launch set executable up front
//! would rewrite about 612 MiB of text instead of about 5 MiB. So images
//! reached only through a dylib outside the cache, a closure image's
//! delay-init link, or an `@rpath`-style or alias path are not closure roots.
//!
//! [`HostSharedCache`]: litebox_common_macos::shared_cache::HostSharedCache

use super::{
    SHARED_CACHE_MIN_ADDRESS, SharedCacheBacking, SharedCacheCodeRegion, SharedCacheInstallError,
    SharedCacheLayout, SharedCachePage, SharedCachePiece,
};
use crate::{LoadedProgram, ShimPlatform};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::ops::Range;
use litebox_common_macos::{
    PAGE_SIZE, VmProtection,
    shared_cache::{
        CacheDependency, CacheFile, CacheImage, CacheMapping, ClosureImage, DYNAMIC_REGION_SIZE,
        HostCache, HostSharedCache, HostSharedCacheContext as _, HostSharedCacheError,
    },
};

const PAGE: u64 = PAGE_SIZE as u64;
/// Root of the launch-time initializer closure, with dyld-in-cache.
const ROOT: &str = "/usr/lib/libSystem.B.dylib";
/// Closure code within this distance belongs to one island cluster; well
/// below the +-128 MiB branch range.
const CLUSTER_GAP: u64 = 32 << 20;
const ISLAND_SEARCH: u64 = 64 << 20;
/// AArch64 `B` reaches +-128 MiB; a gate island must be within this distance
/// of every site it serves and of the instruction after it.
const BRANCH_REACH: u64 = 128 << 20;
const ISLAND_WINDOW: u64 = 16 << 20;
/// Placement conflicts with concurrent host allocations tolerated while
/// reserving the instance.
const RESERVATION_ATTEMPTS: usize = 64;

type Result<T> = core::result::Result<T, HostSharedCacheError>;

macro_rules! ensure {
    ($condition:expr, $($message:tt)+) => {
        if !$condition {
            bail!($($message)+);
        }
    };
}

macro_rules! bail {
    ($($message:tt)+) => {
        return Err(HostSharedCacheError::new(format_args!($($message)+)))
    };
}

struct GuestCache<'a> {
    host: HostCache<'a>,
    /// Images whose code the guest can run: the initializer closure of
    /// libSystem, dyld and the executable's cache dependencies.
    closure: Vec<ClosureImage>,
    /// Header addresses of every image dyld creates a loader for at launch.
    launch_set: BTreeSet<u64>,
    /// Unique image header addresses, sorted.
    image_addresses: Vec<u64>,
}

impl<'a> GuestCache<'a> {
    fn new(host: HostCache<'a>, dependencies: &[CacheDependency]) -> Result<Self> {
        let cache = host.cache;
        let mut roots = vec![
            cache
                .image_index_by_path(ROOT)
                .with_context(|| alloc::format!("{ROOT} is not in the cache"))?,
            cache.dyld_image_index().context("the cache has no dyld")?,
        ];
        let mut indices_by_path = BTreeMap::new();
        for (index, image) in cache.images().iter().enumerate() {
            indices_by_path.entry(image.path.as_str()).or_insert(index);
        }
        // TODO: resolve `@rpath/`-style dependencies (dyld `Loader::forEachResolvedAtPathVar`)
        // and dylibs-trie aliases (`DyldSharedCache::hasImagePath`); both are skipped.
        roots.extend(
            dependencies
                .iter()
                .filter_map(|dependency| indices_by_path.get(dependency.path.as_str()).copied()),
        );
        let closure = cache
            .closure(&roots)
            .context("computing the guest cache closure")?;
        let launch_set: BTreeSet<u64> = cache
            .launch_set(&roots)
            .context("computing the guest cache launch set")?
            .iter()
            .map(|image| image.image.address)
            .collect();
        let mut image_addresses: Vec<u64> =
            cache.images().iter().map(|image| image.address).collect();
        image_addresses.sort_unstable();
        image_addresses.dedup();
        litebox_util_log::debug!(
            closure = closure.len(),
            launch_set = launch_set.len();
            "guest shared-cache closure"
        );
        Ok(Self {
            host,
            closure,
            launch_set,
            image_addresses,
        })
    }

    /// Every mapping, in address order.
    fn mappings(&self) -> Vec<&'a CacheMapping> {
        let mut mappings: Vec<_> = self
            .host
            .cache
            .files()
            .iter()
            .flat_map(CacheFile::mappings)
            .collect();
        mappings.sort_by_key(|mapping| mapping.address);
        mappings
    }

    /// Images whose `__TEXT` may overlap unslid `range`: those with a header
    /// inside it and the last one before it.
    fn images_overlapping(&self, range: &Range<u64>) -> Result<Vec<CacheImage>> {
        let first = self
            .image_addresses
            .partition_point(|address| *address < range.start)
            .saturating_sub(1);
        self.image_addresses[first..]
            .iter()
            .take_while(|address| **address < range.end)
            .map(|address| Ok(self.host.cache.parse_image(*address)?))
            .collect()
    }

    /// Unslid whole-page island candidates near `cluster`, minus `excluded`,
    /// in address order.
    fn island_candidates(
        &self,
        cluster: &Range<u64>,
        holes: &[Range<u64>],
        excluded: &[Range<u64>],
    ) -> Result<Vec<Range<u64>>> {
        let search = cluster.start.saturating_sub(ISLAND_SEARCH)..cluster.end + ISLAND_SEARCH;
        let first = self
            .image_addresses
            .partition_point(|address| *address < search.start);
        let mut pages = Vec::new();
        for address in self.image_addresses[first..]
            .iter()
            .take_while(|address| **address < search.end)
        {
            if self.launch_set.contains(address) {
                continue;
            }
            let image = self.host.cache.parse_image(*address)?;
            let Some(text) = image
                .segment("__TEXT")
                .and_then(|segment| segment.sections.iter().find(|s| s.name == "__text"))
            else {
                continue;
            };
            pages.extend(whole_pages(text.address_range.clone(), excluded));
        }
        pages.extend(hole_pages(holes, &search, excluded));
        pages.sort_by_key(|page| page.start);
        Ok(pages)
    }
}

/// Maximal runs of consecutive native pages covering `ranges`.
fn page_runs(ranges: impl IntoIterator<Item = Range<u64>>) -> Vec<Range<u64>> {
    let pages: BTreeSet<u64> = ranges
        .into_iter()
        .filter(|range| range.start < range.end)
        .flat_map(|range| ((range.start & !(PAGE - 1))..range.end).step_by(PAGE_SIZE))
        .collect();
    let mut runs: Vec<Range<u64>> = Vec::new();
    for page in pages {
        match runs.last_mut() {
            Some(run) if run.end == page => run.end += PAGE,
            _ => runs.push(page..page + PAGE),
        }
    }
    runs
}

/// Reserve the first free range of `length` bytes, retrying only when
/// `occupied` confirms a placement conflict. XNU reports occupied ranges and
/// resource limits (such as `RLIMIT_AS`) alike as `KERN_NO_SPACE`, so a
/// refusal of an unoccupied range fails at once.
fn reserve_free_range(
    length: u64,
    mut free_range: impl FnMut(u64) -> Result<Option<u64>>,
    mut occupied: impl FnMut(Range<u64>) -> Result<bool>,
    mut reserve: impl FnMut(Range<usize>) -> core::result::Result<(), SharedCacheInstallError>,
) -> Result<u64> {
    let mut from = SHARED_CACHE_MIN_ADDRESS as u64;
    for _ in 0..RESERVATION_ATTEMPTS {
        let base = free_range(from)?.with_context(|| {
            alloc::format!("no free {length:#x}-byte range for the guest cache")
        })?;
        let range = usize::try_from(base)?..usize::try_from(base + length)?;
        match reserve(range) {
            Ok(()) => return Ok(base),
            Err(SharedCacheInstallError::ReservationConflict) => {
                if !occupied(base..base + length)? {
                    bail!(
                        "reserving the guest cache at {base:#x}: the host refused \
                         {length:#x} free bytes (address space or resource limit)"
                    );
                }
                from = base + PAGE;
            }
            Err(error) => bail!("reserving the guest cache at {base:#x}: {error}"),
        }
    }
    bail!("reserving the guest cache: {RESERVATION_ATTEMPTS} placement conflicts")
}

/// Whole native pages of `range`, minus those overlapping `excluded`.
fn whole_pages(range: Range<u64>, excluded: &[Range<u64>]) -> Vec<Range<u64>> {
    let mut pages = Vec::new();
    let mut page = range.start.next_multiple_of(PAGE);
    while page + PAGE <= range.end {
        let candidate = page..page + PAGE;
        if !excluded
            .iter()
            .any(|run| run.start < candidate.end && candidate.start < run.end)
        {
            pages.push(candidate);
        }
        page += PAGE;
    }
    pages
}

/// Instruction byte ranges of `images` within `run`, relative to `run.start`.
fn instruction_ranges(images: &[CacheImage], run: &Range<u64>) -> Result<Vec<Range<usize>>> {
    let mut ranges = Vec::new();
    for image in images {
        let image_start = ranges.len();
        for segment in &image.segments {
            for section in segment.sections.iter().filter(|s| s.has_instructions()) {
                let start = section.address_range.start.max(run.start);
                let end = section.address_range.end.min(run.end);
                if start < end {
                    // Instructions are 4-byte aligned; trailing padding is not code.
                    let start = start.next_multiple_of(4);
                    let end = end & !3;
                    if start < end {
                        ranges.push(
                            usize::try_from(start - run.start)?..usize::try_from(end - run.start)?,
                        );
                    }
                }
            }
        }
        // TODO: subtract the marked data from the image's instruction ranges, like the
        // rewriter's `CodeMetadata::parse`, instead of refusing the image.
        ensure!(
            ranges.len() == image_start || !image.has_data_in_code,
            "the cache image at {:#x} marks data in its code (LC_DATA_IN_CODE)",
            image.address
        );
    }
    ranges.sort_by_key(|range| range.start);
    ensure!(
        ranges.windows(2).all(|pair| pair[0].end <= pair[1].start),
        "overlapping instruction sections near {:#x}",
        run.start
    );
    Ok(ranges)
}

/// Whole native pages of `holes` inside `search`, minus `excluded`.
fn hole_pages(
    holes: &[Range<u64>],
    search: &Range<u64>,
    excluded: &[Range<u64>],
) -> Vec<Range<u64>> {
    holes
        .iter()
        .flat_map(|hole| {
            whole_pages(
                hole.start.max(search.start)..hole.end.min(search.end),
                excluded,
            )
        })
        .collect()
}

/// The farthest distance between any byte of `page` and of `code`.
fn worst_distance(page: &Range<u64>, code: &Range<u64>) -> u64 {
    page.end.max(code.end) - page.start.min(code.start)
}

/// Split sorted `runs` into windows of at most [`ISLAND_WINDOW`], each with
/// its bytes of code.
fn code_windows(runs: &[Range<u64>]) -> Vec<(Range<u64>, u64)> {
    let mut windows: Vec<(Range<u64>, u64)> = Vec::new();
    for run in runs {
        let mut start = run.start;
        while start < run.end {
            match windows.last_mut() {
                Some((window, code)) if start - window.start < ISLAND_WINDOW => {
                    let end = run.end.min(window.start + ISLAND_WINDOW);
                    *code += end - start;
                    window.end = end;
                    start = end;
                }
                _ => {
                    let end = run.end.min(start + ISLAND_WINDOW);
                    windows.push((start..end, end - start));
                    start = end;
                }
            }
        }
    }
    windows
}

/// Select reachable gate islands for sorted `runs`; `candidates` is queried
/// per cluster.
fn select_islands(
    runs: &[Range<u64>],
    mut candidates: impl FnMut(&Range<u64>) -> Result<Vec<Range<u64>>>,
) -> Result<BTreeSet<u64>> {
    let mut clusters: Vec<Range<u64>> = Vec::new();
    for run in runs {
        match clusters.last_mut() {
            Some(cluster) if run.start - cluster.end <= CLUSTER_GAP => cluster.end = run.end,
            _ => clusters.push(run.clone()),
        }
    }
    let mut islands = BTreeSet::new();
    for cluster in &clusters {
        let pages = candidates(cluster)?;
        let cluster_runs: Vec<Range<u64>> = runs
            .iter()
            .filter(|run| run.start >= cluster.start && run.end <= cluster.end)
            .cloned()
            .collect();
        for (window, code) in code_windows(&cluster_runs) {
            let mut reachable: Vec<&Range<u64>> = pages
                .iter()
                .filter(|page| worst_distance(page, &window) < BRANCH_REACH)
                .collect();
            ensure!(
                !reachable.is_empty(),
                "no gate island candidate within branch range of {window:#x?}"
            );
            reachable.sort_by_key(|page| worst_distance(page, &window));
            // Generous: unused candidates cost nothing.
            let wanted = usize::try_from((code / 8).div_ceil(PAGE))? + 16;
            islands.extend(reachable.iter().take(wanted).map(|page| page.start));
        }
    }
    Ok(islands)
}

/// One piece of the instance, at unslid addresses.
struct Piece<'a> {
    range: Range<u64>,
    backing: SharedCacheBacking<'a>,
    protection: VmProtection,
    max_protection: VmProtection,
    /// Instruction ranges relative to `range.start` of code to rewrite.
    instruction_ranges: Option<Vec<Range<usize>>>,
}

impl<P: ShimPlatform + HostSharedCache> LoadedProgram<P> {
    /// Install `host` with the executable's cache `dependencies` as closure roots.
    pub(crate) fn install_host_shared_cache(
        &self,
        host: HostCache<'static>,
        dependencies: &[CacheDependency],
    ) -> Result<()> {
        let platform: &'static P = self.entrypoints.task.global.platform;
        let cache =
            GuestCache::new(host, dependencies).context("preparing the guest shared cache")?;
        let header = cache.host.cache.header();
        let start = header.shared_region_start;
        let size = header.shared_region_size.next_multiple_of(PAGE);
        let limit = P::TASK_ADDR_MAX as u64;
        let base = reserve_free_range(
            size,
            |from| platform.free_host_range(from, size, limit),
            |range| platform.host_range_occupied(range),
            |range| self.reserve_shared_cache(range),
        )?;
        let slide = base - start;
        litebox_util_log::debug!(base:? = base, slide:? = slide; "guest shared-cache instance");
        let slid = |address: u64| usize::try_from(address + slide).expect("64-bit addresses");

        let mappings = cache.mappings();
        // TODO: rewrite cache text on first execution, including dependencies reached through
        // non-cache dylibs and delay-init links.
        let text_runs = page_runs(cache.closure.iter().filter_map(|closure| {
            closure
                .image
                .segment("__TEXT")
                .map(|segment| segment.address_range.clone())
        }));
        for run in &text_runs {
            let (_, mapping) = cache
                .host
                .cache
                .mapping_containing(run.start, run.end - run.start)
                .with_context(|| alloc::format!("closure text {run:#x?} spans mappings"))?;
            ensure!(
                mapping.initial_protection.contains(VmProtection::EXECUTE)
                    && mapping.slide_info.is_empty(),
                "closure text {run:#x?} is not in a text mapping"
            );
        }
        let dynamic_page = header
            .dynamic_data
            .map(|(offset, _)| start + offset..start + offset + DYNAMIC_REGION_SIZE as u64);

        let mut overlays: Vec<Piece<'_>> = Vec::new();
        for run in &text_runs {
            let executable = VmProtection::READ | VmProtection::EXECUTE;
            overlays.push(Piece {
                range: run.clone(),
                backing: SharedCacheBacking::FileView(run.start),
                protection: executable,
                max_protection: executable,
                instruction_ranges: Some(instruction_ranges(&cache.images_overlapping(run)?, run)?),
            });
        }
        if let Some(page) = &dynamic_page {
            ensure!(
                cache.host.cache.mapping_containing(page.start, 1).is_none()
                    && overlays
                        .iter()
                        .all(|run| run.range.end <= page.start || page.end <= run.range.start),
                "DynamicRegion overlaps cache contents"
            );
            overlays.push(Piece {
                range: page.clone(),
                backing: SharedCacheBacking::Copy(cache.host.dynamic_region),
                protection: VmProtection::READ,
                max_protection: VmProtection::READ,
                instruction_ranges: None,
            });
        }
        overlays.sort_by_key(|overlay| overlay.range.start);

        let mut regions: Vec<(Range<u64>, Option<&CacheMapping>)> = Vec::new();
        let mut cursor = start;
        for mapping in &mappings {
            let range = mapping.address_range();
            ensure!(
                range.start >= cursor
                    && range.start.is_multiple_of(PAGE)
                    && range.end.is_multiple_of(PAGE)
                    && mapping.file_offset.is_multiple_of(PAGE),
                "cache mapping {:#x} is not page-aligned",
                mapping.address
            );
            if range.start > cursor {
                regions.push((cursor..range.start, None));
            }
            regions.push((range.clone(), Some(*mapping)));
            cursor = range.end;
        }
        ensure!(
            cursor <= start + size,
            "cache mappings exceed the shared region"
        );
        if cursor < start + size {
            regions.push((cursor..start + size, None));
        }
        let mut pieces: Vec<Piece<'_>> = Vec::new();
        let mut uncovered = |range: Range<u64>, mapping: Option<&CacheMapping>| {
            if range.start == range.end {
                return;
            }
            pieces.push(match mapping {
                // Pages keep their map entry's protections, so dyld can change
                // whole mappings before their pages are touched: it makes
                // DATA_CONST writable to patch the cache
                // (`ProcessConfig::DyldCache::makeDataConstWritable`) and
                // write-protects TPRO_CONST (`MemoryManager::writeProtect`).
                Some(mapping) => Piece {
                    backing: if mapping.slide_info.is_empty() {
                        SharedCacheBacking::FileView(range.start)
                    } else {
                        SharedCacheBacking::Paged
                    },
                    range,
                    protection: mapping.initial_protection - VmProtection::EXECUTE,
                    max_protection: mapping.max_protection - VmProtection::EXECUTE,
                    instruction_ranges: None,
                },
                None => Piece {
                    range,
                    backing: SharedCacheBacking::Reserved,
                    protection: VmProtection::empty(),
                    max_protection: VmProtection::empty(),
                    instruction_ranges: None,
                },
            });
        };
        let mut pending_overlays = overlays.into_iter().peekable();
        let mut overlay_pieces = Vec::new();
        for (region, mapping) in &regions {
            let mut position = region.start;
            while let Some(overlay) =
                pending_overlays.next_if(|overlay| overlay.range.start < region.end)
            {
                let range = &overlay.range;
                ensure!(
                    range.start >= position && range.end <= region.end,
                    "pages {range:#x?} straddle a mapping boundary"
                );
                uncovered(position..range.start, *mapping);
                position = range.end;
                overlay_pieces.push(overlay);
            }
            uncovered(position..region.end, *mapping);
        }
        ensure!(
            pending_overlays.next().is_none(),
            "pages outside the shared region"
        );
        pieces.extend(overlay_pieces);
        pieces.sort_by_key(|piece| piece.range.start);

        let holes: Vec<Range<u64>> = regions
            .iter()
            .filter(|(_, mapping)| mapping.is_none())
            .map(|(range, _)| range.clone())
            .collect();
        // Islands must not overwrite the copied DynamicRegion page.
        let mut excluded = text_runs.clone();
        excluded.extend(dynamic_page);
        let islands = select_islands(&text_runs, |cluster| {
            cache.island_candidates(cluster, &holes, &excluded)
        })?;
        let gate_islands: Vec<Range<usize>> = islands
            .iter()
            .map(|page| slid(*page)..slid(*page + PAGE))
            .collect();

        let shim_pieces: Vec<SharedCachePiece<'_>> = pieces
            .iter()
            .map(|piece| SharedCachePiece {
                range: slid(piece.range.start)..slid(piece.range.end),
                backing: piece.backing,
                protection: piece.protection,
                max_protection: piece.max_protection,
            })
            .collect();
        let code_regions: Vec<SharedCacheCodeRegion<'_>> = pieces
            .iter()
            .enumerate()
            .filter_map(|(index, piece)| {
                piece
                    .instruction_ranges
                    .as_deref()
                    .map(|ranges| SharedCacheCodeRegion {
                        piece: index,
                        instruction_ranges: ranges,
                    })
            })
            .collect();
        let count = |backing: fn(&SharedCacheBacking<'_>) -> bool| {
            pieces
                .iter()
                .filter(|piece| backing(&piece.backing))
                .count()
        };
        litebox_util_log::debug!(
            pieces = shim_pieces.len(),
            file_views = count(|backing| matches!(backing, SharedCacheBacking::FileView(_))),
            paged = count(|backing| matches!(backing, SharedCacheBacking::Paged)),
            text_runs = text_runs.len(),
            island_candidates = gate_islands.len();
            "guest shared-cache layout"
        );
        let range = slid(start)..slid(start + size);
        self.install_shared_cache(&SharedCacheLayout {
            range,
            pieces: &shim_pieces,
            code_regions: &code_regions,
            gate_islands: &gate_islands,
            pager: Some(Arc::new(move |address: usize| {
                let page = (address as u64).checked_sub(slide)?;
                platform
                    .host_cache_page(page, slide)
                    .inspect_err(|error| {
                        litebox_util_log::warn!(error:%, page:?; "cannot page in");
                    })
                    .ok()
                    .map(|page| SharedCachePage {
                        bytes: page.bytes,
                        max_protection: page.max_protection - VmProtection::EXECUTE,
                    })
            })),
        })
        .context("installing the guest shared cache")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_ranges_clip_to_the_run() {
        use litebox_common_macos::shared_cache::{CacheSection, CacheSegment};

        let image = |address: u64, text: Range<u64>, has_data_in_code| CacheImage {
            address,
            file_type: 6, // MH_DYLIB
            uuid: None,
            install_name: None,
            segments: vec![CacheSegment {
                name: "__TEXT".into(),
                address_range: address..text.end,
                max_protection: VmProtection::READ | VmProtection::EXECUTE,
                initial_protection: VmProtection::READ | VmProtection::EXECUTE,
                sections: vec![CacheSection {
                    name: "__text".into(),
                    address_range: text,
                    flags: CacheSection::INSTRUCTION_ATTRIBUTES,
                }],
            }],
            dependencies: Vec::new(),
            has_data_in_code,
        };
        let run = 0x1000..0x2000;
        let images = [
            image(0x0, 0x800..0x1000, true),
            image(0x1000, 0x1100..0x2000, false),
        ];
        // The marking neighbor contributes no code to `run`.
        assert_eq!(
            instruction_ranges(&images, &run).unwrap(),
            vec![0x100..0x1000]
        );
    }

    #[test]
    fn island_selection_uses_a_reachable_hole() {
        const MIB: u64 = 1 << 20;
        let base = 0x2_8000_0000;
        let code = base..base + 4 * PAGE;
        let runs = core::slice::from_ref(&code);
        let search = base - ISLAND_SEARCH..base + 4 * PAGE + ISLAND_SEARCH;
        // A hole far below is out of branch range; one above has a copied
        // page (excluded), a partial page and two whole pages.
        let holes = [
            base - 512 * MIB..base - 256 * MIB,
            base + 8 * MIB + PAGE / 2..base + 8 * MIB + 4 * PAGE,
        ];
        let copied_page = base + 8 * MIB + PAGE..base + 8 * MIB + 2 * PAGE;
        let copied = core::slice::from_ref(&copied_page);
        let pages = hole_pages(&holes, &search, copied);
        assert_eq!(
            pages,
            [
                base + 8 * MIB + 2 * PAGE..base + 8 * MIB + 3 * PAGE,
                base + 8 * MIB + 3 * PAGE..base + 8 * MIB + 4 * PAGE,
            ]
        );
        let islands = select_islands(runs, |cluster| {
            assert_eq!(cluster, &code);
            Ok(hole_pages(&holes, &search, copied))
        })
        .unwrap();
        assert_eq!(
            islands.into_iter().collect::<Vec<_>>(),
            [base + 8 * MIB + 2 * PAGE, base + 8 * MIB + 3 * PAGE]
        );
        assert!(select_islands(runs, |_| Ok(hole_pages(&holes[..1], &search, copied))).is_err());
    }

    #[test]
    fn island_selection_reaches_every_window_of_a_wide_cluster() {
        const MIB: u64 = 1 << 20;
        let base = 0x1_8000_0000;
        // The cluster exceeds branch reach (runs closer than `CLUSTER_GAP`), so
        // both ends need island coverage.
        let runs = [
            base..base + PAGE,
            base + 30 * MIB..base + 30 * MIB + PAGE,
            base + 60 * MIB..base + 60 * MIB + PAGE,
            base + 90 * MIB..base + 90 * MIB + PAGE,
            base + 120 * MIB..base + 120 * MIB + PAGE,
            base + 150 * MIB..base + 150 * MIB + PAGE,
            base + 180 * MIB..base + 180 * MIB + PAGE,
        ];
        let low = base - 2 * PAGE..base - PAGE;
        let mut pages: Vec<Range<u64>> = (0..64)
            .map(|index| {
                let start = base + 179 * MIB - index * PAGE;
                start..start + PAGE
            })
            .collect();
        pages.push(low.clone());
        pages.sort_by_key(|page| page.start);
        let islands = select_islands(&runs, |_| Ok(pages.clone())).unwrap();
        assert!(islands.contains(&low.start));
        for run in &runs {
            assert!(
                islands
                    .iter()
                    .any(|island| worst_distance(&(*island..*island + PAGE), run) < BRANCH_REACH),
                "{run:#x?} has no reachable island"
            );
        }
    }

    #[test]
    fn code_windows_bound_their_span() {
        const MIB: u64 = 1 << 20;
        let windows = code_windows(&[0..PAGE, 4 * MIB..5 * MIB, 20 * MIB..60 * MIB]);
        assert_eq!(
            windows,
            [
                (0..5 * MIB, PAGE + MIB),
                (20 * MIB..36 * MIB, 16 * MIB),
                (36 * MIB..52 * MIB, 16 * MIB),
                (52 * MIB..60 * MIB, 8 * MIB),
            ]
        );
    }

    #[test]
    fn reservation_retries_only_placement_conflicts() {
        let length = 4 * PAGE;
        let start = SHARED_CACHE_MIN_ADDRESS as u64;
        let mut searches = Vec::new();
        let mut attempts = 0;
        let base = reserve_free_range(
            length,
            |from| {
                searches.push(from);
                Ok(Some(from))
            },
            |_| Ok(true),
            |_| {
                attempts += 1;
                if attempts == 1 {
                    Err(SharedCacheInstallError::ReservationConflict)
                } else {
                    Ok(())
                }
            },
        )
        .unwrap();
        assert_eq!(base, start + PAGE);
        assert_eq!(searches, [start, start + PAGE]);
        for (occupied, error) in [
            (true, SharedCacheInstallError::Reservation),
            (false, SharedCacheInstallError::ReservationConflict),
        ] {
            let mut attempts = 0;
            assert!(
                reserve_free_range(
                    length,
                    |from| Ok(Some(from)),
                    |_| Ok(occupied),
                    |_| {
                        attempts += 1;
                        Err(error)
                    },
                )
                .is_err()
            );
            assert_eq!(attempts, 1);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unslid_mappings_are_file_views_and_slid_mappings_are_paged() {
        use crate::{MacosShimBuilder, tests::loaded_program, tests::task};
        use litebox_common_macos::shared_cache::HostSharedCache as _;
        use litebox_platform_macos_userland::MacosUserland;

        let platform = MacosUserland::new();
        let program = loaded_program(task(MacosShimBuilder::new(platform).build()));
        let host = platform.host_shared_cache().unwrap();
        program.install_host_shared_cache(host, &[]).unwrap();
        let state = program.entrypoints.task.global.shared_cache.lock();
        let state = state.as_ref().unwrap();
        let slide = state.range.start as u64 - host.cache.header().shared_region_start;
        let (mut views, mut paged) = (0, 0);
        for mapping in GuestCache::new(host, &[]).unwrap().mappings() {
            // The first page holds a cache file header: never closure text
            // or a gate island.
            let page = usize::try_from(mapping.address + slide).unwrap();
            let guest = litebox_common_macos::user_pointers::UserPtr::<u8>::from_usize(page)
                .to_owned_slice::<MacosUserland>(PAGE_SIZE);
            if mapping.slide_info.is_empty() {
                assert!(
                    !state.mapping_at(page).unwrap().paged,
                    "{:#x}",
                    mapping.address
                );
                assert_eq!(
                    guest.as_deref(),
                    Some(
                        &host
                            .cache
                            .read_at_address(mapping.address, PAGE_SIZE)
                            .unwrap()[..]
                    ),
                    "{:#x}",
                    mapping.address
                );
                views += 1;
            } else {
                assert!(
                    state.mapping_at(page).unwrap().paged,
                    "{:#x}",
                    mapping.address
                );
                assert_eq!(guest, None, "{:#x}", mapping.address);
                paged += 1;
            }
        }
        assert!(views > 0 && paged > 0);
    }

    #[test]
    fn page_runs_merge_shared_native_pages() {
        assert_eq!(
            page_runs([0x5000..0x6000, 0x7000..0x9000, 0x1_0000..0x1_0001]),
            [0x4000..0xc000, 0x1_0000..0x1_4000]
        );
    }
}
