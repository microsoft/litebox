// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest system runtime: a private instance of the host's dyld shared cache.
//!
//! The host runner keeps using its own live shared cache untouched. The guest
//! gets the same on-disk cache build mapped at a guest-private base `G`:
//!
//! - header, read-only, LINKEDIT and non-closure `__TEXT` pages are private
//!   copy-on-write views of the read-only cache files (readable, never
//!   executable);
//! - native pages overlapping closure images' `__TEXT` are copied and handed
//!   to the shim, which rewrites them (and any neighbor code sharing a page)
//!   before they become executable;
//! - native pages overlapping closure images' DATA-like segments are copied
//!   and rebased with slide info v5 for slide `G - sharedRegionStart`;
//! - all other DATA pages are supplied and rebased on first touch, like XNU's
//!   slide pager;
//! - the host's live DynamicRegion page is copied read-only.
//!
//! The closure is the launch-time initializer closure of
//! `/usr/lib/libSystem.B.dylib` and dyld-in-cache. Gate islands are whole
//! pages strictly inside `__TEXT,__text` of cache images outside the launch
//! set (every image dyld creates a loader for), whose bytes are never read.

use anyhow::{Context as _, Result, bail, ensure};
use litebox_common_macos::{
    VmProtection,
    shared_cache::{
        CacheFile, CacheHeader, CacheImage, CacheMapping, ClosureImage, DYNAMIC_REGION_SIZE,
        MappingFlags, PointerAuthKey, PointerSigner, SharedCache, dynamic_region_cache_path,
    },
};
use litebox_shim_macos::{
    LoadedProgram, ShimPlatform,
    shared_cache::{
        SHARED_CACHE_MIN_ADDRESS, SharedCacheBacking, SharedCacheCodeRegion, SharedCacheLayout,
        SharedCachePage, SharedCachePiece,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    ops::Range,
    os::fd::AsRawFd as _,
    sync::Arc,
};

/// Native (and cache) page size.
const PAGE: u64 = 0x4000;
const PAGE_BYTES: usize = 0x4000;
/// Images of the launch-time closure.
const ROOT: &str = "/usr/lib/libSystem.B.dylib";
/// Closure code within this distance belongs to one island cluster; well
/// below the +-128 MiB branch range.
const CLUSTER_GAP: u64 = 32 << 20;
/// Island candidates are searched within this distance of a cluster.
const ISLAND_SEARCH: u64 = 64 << 20;

unsafe extern "C" {
    fn _dyld_get_shared_cache_range(length: *mut usize) -> *const u8;
    fn mach_task_self() -> u32;
    fn mach_vm_read_overwrite(
        task: u32,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> i32;
    fn mach_vm_region(
        task: u32,
        address: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut i32,
        count: *mut u32,
        object_name: *mut u32,
    ) -> i32;
}

/// Copy live host memory without faulting on unmapped addresses.
fn read_host(address: usize, length: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    let mut copied = 0;
    // SAFETY: `bytes` is writable for `length` bytes; Mach validates the source.
    let result = unsafe {
        mach_vm_read_overwrite(
            mach_task_self(),
            address as u64,
            length as u64,
            bytes.as_mut_ptr() as u64,
            &raw mut copied,
        )
    };
    ensure!(
        result == 0 && copied == length as u64,
        "cannot read host memory at {address:#x}"
    );
    Ok(bytes)
}

/// Read-only private mappings of the cache files, unmapped on drop.
struct MappedFiles(Vec<(usize, usize)>);

impl Drop for MappedFiles {
    fn drop(&mut self) {
        for &(address, length) in &self.0 {
            // SAFETY: each mapping was created by `map`, and every borrower
            // (the parsed cache, guest pagers) is gone once this drops.
            unsafe { libc::munmap(address as *mut _, length) };
        }
    }
}

impl MappedFiles {
    /// Map a whole cache file read-only and privately.
    ///
    /// The returned bytes are valid until `self` drops; `'static` only lets
    /// them flow into APIs that copy them (copy-on-write mappings) or into
    /// values stored next to `self` in [`GuestCache`].
    fn map(&mut self, path: &str) -> Result<&'static [u8]> {
        let file = std::fs::File::open(path).with_context(|| format!("opening {path}"))?;
        let length = usize::try_from(file.metadata()?.len())?;
        ensure!(length != 0, "empty cache file {path}");
        // SAFETY: a fresh read-only private mapping; the cache files are
        // immutable system files (the live cache maps them too).
        let address = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                length,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        ensure!(address != libc::MAP_FAILED, "mapping {path}");
        self.0.push((address as usize, length));
        // SAFETY: the mapping is readable for `length` bytes until `self` drops.
        Ok(unsafe { core::slice::from_raw_parts(address.cast::<u8>(), length) })
    }
}

/// The on-disk cache matching the host's live cache, verified and parsed.
pub(crate) struct GuestCache {
    /// Borrows `files`; declared first so it drops first.
    cache: SharedCache<&'static [u8]>,
    /// The live DynamicRegion page.
    dynamic_region: Vec<u8>,
    /// Images initialized at launch (libSystem + dyld initializer closure).
    closure: Vec<ClosureImage>,
    /// Header addresses of every image dyld creates a loader for at launch.
    launch_set: BTreeSet<u64>,
    /// Unique image header addresses, sorted.
    image_addresses: Vec<u64>,
    /// Owns the mappings `cache` borrows; only its drop is used.
    _files: MappedFiles,
}

impl GuestCache {
    /// Locate the host's live cache through its DynamicRegion, then open and
    /// verify the on-disk cache files (main and subcache UUIDs, mappings,
    /// slide info v5). Fails closed on any mismatch.
    pub(crate) fn open() -> Result<Arc<Self>> {
        let mut files = MappedFiles(Vec::new());
        let mut length = 0;
        // SAFETY: `length` is writable; the call only reports the live cache range.
        let base = unsafe { _dyld_get_shared_cache_range(&raw mut length) } as usize;
        ensure!(base != 0, "the host process has no dyld shared cache");
        let live = CacheHeader::parse(&read_host(base, 0x1000)?)
            .context("parsing the live cache header")?;
        let (dynamic_offset, _) = live
            .dynamic_data
            .context("the live cache has no DynamicRegion")?;
        let dynamic_region =
            read_host(base + usize::try_from(dynamic_offset)?, DYNAMIC_REGION_SIZE)
                .context("reading the live DynamicRegion")?;
        let path = dynamic_region_cache_path(&dynamic_region)
            .context("reading the cache path from the live DynamicRegion")?
            .to_owned();
        litebox_util_log::debug!(path:%; "guest shared cache");
        let main = CacheFile::parse(files.map(&path)?).context("parsing the main cache file")?;
        ensure!(
            main.header().uuid == live.uuid,
            "on-disk cache {path} is not the live cache"
        );
        let subcaches = main
            .subcache_entries()?
            .iter()
            .map(|entry| {
                let path = format!("{path}{}", entry.file_suffix);
                CacheFile::parse(files.map(&path)?).with_context(|| format!("parsing {path}"))
            })
            .collect::<Result<_>>()?;
        let cache = SharedCache::new(main, subcaches).context("verifying the subcaches")?;
        for file in cache.files() {
            for mapping in file.mappings() {
                file.slide_info(mapping)?;
                ensure!(
                    !mapping.flags.contains(MappingFlags::TEXT_STUBS),
                    "TEXT_STUBS mappings are unsupported"
                );
            }
        }
        let roots = [
            cache
                .image_index_by_path(ROOT)
                .with_context(|| format!("{ROOT} is not in the cache"))?,
            cache.dyld_image_index().context("the cache has no dyld")?,
        ];
        let closure = cache.closure(&roots)?;
        let launch_set = cache
            .launch_set(&roots)?
            .iter()
            .map(|image| image.image.address)
            .collect();
        let mut image_addresses: Vec<u64> =
            cache.images().iter().map(|image| image.address).collect();
        image_addresses.sort_unstable();
        image_addresses.dedup();
        litebox_util_log::debug!(
            closure = closure.len(),
            launch_set = Vec::len(&cache.launch_set(&roots)?);
            "guest shared-cache closure"
        );
        Ok(Arc::new(Self {
            cache,
            dynamic_region,
            closure,
            launch_set,
            image_addresses,
            _files: files,
        }))
    }

    fn header(&self) -> &CacheHeader {
        self.cache.header()
    }

    /// Every mapping with its file's bytes, in address order.
    fn mappings(&self) -> Vec<(&CacheMapping, &'static [u8])> {
        let mut mappings: Vec<_> = self
            .cache
            .files()
            .iter()
            .flat_map(|file| {
                file.mappings()
                    .iter()
                    .map(move |mapping| (mapping, *file.reader()))
            })
            .collect();
        mappings.sort_by_key(|(mapping, _)| mapping.address);
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
            .map(|address| Ok(self.cache.parse_image(*address)?))
            .collect()
    }

    /// Instruction ranges of every image in `run`, relative to `run.start`.
    fn instruction_ranges(&self, run: &Range<u64>) -> Result<Vec<Range<usize>>> {
        let mut ranges = Vec::new();
        for image in self.images_overlapping(run)? {
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
                                usize::try_from(start - run.start)?
                                    ..usize::try_from(end - run.start)?,
                            );
                        }
                    }
                }
            }
        }
        ranges.sort_by_key(|range| range.start);
        ensure!(
            ranges.windows(2).all(|pair| pair[0].end <= pair[1].start),
            "overlapping instruction sections near {:#x}",
            run.start
        );
        Ok(ranges)
    }

    /// Whole native pages strictly inside `__TEXT,__text` of images outside
    /// the launch set, within [`ISLAND_SEARCH`] of `cluster`, nearest first,
    /// excluding `excluded` (executable runs).
    fn island_candidates(
        &self,
        cluster: &Range<u64>,
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
            let image = self.cache.parse_image(*address)?;
            let Some(text) = image
                .segment("__TEXT")
                .and_then(|segment| segment.sections.iter().find(|s| s.name == "__text"))
            else {
                continue;
            };
            let mut page = text.address_range.start.next_multiple_of(PAGE);
            while page + PAGE <= text.address_range.end {
                let candidate = page..page + PAGE;
                if !excluded
                    .iter()
                    .any(|run| run.start < candidate.end && candidate.start < run.end)
                {
                    pages.push(candidate);
                }
                page += PAGE;
            }
        }
        let distance = |page: &Range<u64>| {
            if page.start >= cluster.end {
                page.end - cluster.start
            } else {
                cluster.end - page.start
            }
        };
        pages.sort_by_key(distance);
        Ok(pages)
    }

    /// The bytes of unslid `range` in `mapping` of file `file`, rebased for
    /// `slide` like XNU's `vm_shared_region_slide_page_v5`.
    fn slid_data(
        &self,
        file: usize,
        mapping: &CacheMapping,
        range: &Range<u64>,
        slide: u64,
    ) -> Result<Vec<u8>> {
        let mut bytes = self
            .cache
            .read_at_address(range.start, usize::try_from(range.end - range.start)?)?;
        if let Some(info) = self.cache.files()[file].slide_info(mapping)? {
            let page_size = info.page_size() as u64;
            ensure!(
                range.start.is_multiple_of(page_size)
                    && (range.end - range.start).is_multiple_of(page_size),
                "slide pages larger than native pages"
            );
            for (index, page) in bytes.chunks_exact_mut(info.page_size()).enumerate() {
                let address = range.start + index as u64 * page_size;
                let page_index = usize::try_from((address - mapping.address) / page_size)?;
                info.rebase_page(page, page_index, slide, address + slide, &TaskPointerSigner)
                    .with_context(|| format!("rebasing {address:#x}"))?;
            }
        }
        Ok(bytes)
    }

    /// The slide pager: the rebased page at unslid `page` of a DATA mapping.
    fn page(&self, page: u64, slide: u64) -> Option<SharedCachePage> {
        let (file, mapping) = self.cache.mapping_containing(page, PAGE)?;
        let bytes = self
            .slid_data(file, mapping, &(page..page + PAGE), slide)
            .inspect_err(|error| {
                litebox_util_log::warn!(error:% = format_args!("{error:#}"), page:?; "cannot page in");
            })
            .ok()?;
        Some(SharedCachePage {
            bytes,
            protection: mapping.initial_protection,
            max_protection: mapping.max_protection,
        })
    }

    /// Describe unslid `address` as `file mapping / image segment` for diagnostics.
    fn describe(&self, address: u64) -> Option<String> {
        let (file, mapping) = self.cache.mapping_containing(address, 1)?;
        let mut description = format!(
            "cache file {file} mapping {:#x} (flags {:#x}, prot {:?})",
            mapping.address,
            mapping.flags.bits(),
            mapping.initial_protection
        );
        for image in &self.image_addresses {
            let Ok(parsed) = self.cache.parse_image(*image) else {
                continue;
            };
            if let Some(segment) = parsed
                .segments
                .iter()
                .find(|segment| segment.address_range.contains(&address))
                .filter(|segment| segment.name != "__LINKEDIT")
            {
                let path = self
                    .cache
                    .images()
                    .iter()
                    .find(|entry| entry.address == *image)
                    .map_or("?", |entry| entry.path.as_str());
                let closure = if self.closure.iter().any(|c| c.image.address == *image) {
                    "closure"
                } else if self.launch_set.contains(image) {
                    "delay-loaded"
                } else {
                    "not loaded"
                };
                let _ = write!(
                    description,
                    " / {path} ({closure}) {} +{:#x}",
                    segment.name,
                    address - segment.address_range.start
                );
                break;
            }
        }
        Some(description)
    }
}

/// Signs rebased authenticated pointers with this process's keys, which are
/// the guest task's keys. In a plain arm64 process pointer authentication is
/// disabled, so `pacia`/`pacda` leave values unchanged, like XNU does for a
/// task without JOP keys.
struct TaskPointerSigner;

impl PointerSigner for TaskPointerSigner {
    fn sign(&self, value: u64, key: PointerAuthKey, discriminator: u64) -> u64 {
        let mut value = value;
        // SAFETY: PACIA/PACDA only transform x16 using x17; they never fault.
        unsafe {
            match key {
                // pacia x16, x17
                PointerAuthKey::Ia => core::arch::asm!(
                    ".inst 0xdac10230",
                    inout("x16") value,
                    in("x17") discriminator,
                    options(nomem, nostack, preserves_flags, pure),
                ),
                // pacda x16, x17
                PointerAuthKey::Da => core::arch::asm!(
                    ".inst 0xdac10a30",
                    inout("x16") value,
                    in("x17") discriminator,
                    options(nomem, nostack, preserves_flags, pure),
                ),
            }
        }
        value
    }
}

/// Maximal runs of consecutive native pages covering `ranges`.
fn page_runs(ranges: impl IntoIterator<Item = Range<u64>>) -> Vec<Range<u64>> {
    let pages: BTreeSet<u64> = ranges
        .into_iter()
        .filter(|range| range.start < range.end)
        .flat_map(|range| ((range.start & !(PAGE - 1))..range.end).step_by(PAGE_BYTES))
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

/// Split `runs` at mapping boundaries and drop parts outside any mapping.
fn split_at_mappings(
    runs: Vec<Range<u64>>,
    mappings: &[(&CacheMapping, &[u8])],
) -> Vec<Range<u64>> {
    let mut split = Vec::new();
    for run in runs {
        for (mapping, _) in mappings {
            let range = mapping.address_range();
            let start = run.start.max(range.start);
            let end = run.end.min(range.end);
            if start < end {
                split.push(start..end);
            }
        }
    }
    split
}

/// Choose a free, page-aligned host range of `length` bytes at or above
/// [`SHARED_CACHE_MIN_ADDRESS`], starting the search at `from`.
fn free_host_range(from: u64, length: u64) -> Option<u64> {
    const VM_REGION_BASIC_INFO_64: i32 = 9;
    let mut candidate = from.max(SHARED_CACHE_MIN_ADDRESS as u64);
    loop {
        let mut address = candidate;
        let mut size = 0;
        let mut info = [0i32; 16];
        let mut count = 9u32;
        let mut object = 0;
        // SAFETY: all outputs are valid; VM_REGION_BASIC_INFO_64 writes 9 ints.
        let result = unsafe {
            mach_vm_region(
                mach_task_self(),
                &raw mut address,
                &raw mut size,
                VM_REGION_BASIC_INFO_64,
                info.as_mut_ptr(),
                &raw mut count,
                &raw mut object,
            )
        };
        // No region at or above `candidate`, or a large enough gap before the next one.
        if result != 0 || address >= candidate.checked_add(length)? {
            return Some(candidate);
        }
        candidate = address.checked_add(size)?.next_multiple_of(PAGE);
    }
}

/// One piece of the instance, at unslid addresses.
struct Piece {
    range: Range<u64>,
    backing: Backing,
    protection: VmProtection,
    max_protection: VmProtection,
}

/// Copied bytes of an unslid range.
struct Copied {
    range: Range<u64>,
    bytes: Vec<u8>,
    protection: VmProtection,
    max_protection: VmProtection,
    instruction_ranges: Option<Vec<Range<usize>>>,
}

/// What backs an uncopied part of the shared region.
#[derive(Clone, Copy)]
enum Region {
    /// Outside every mapping.
    Hole,
    /// A writable or slid mapping: paged in and rebased on demand.
    Data,
    /// A read-only view of a file mapping.
    View(&'static [u8]),
}

enum Backing {
    Reserved,
    Paged,
    Source(&'static [u8]),
    /// Key of the copied bytes.
    Copy(u64),
}

/// Reserve, prepare and install the guest's private cache instance. The
/// guest's pager keeps `cache` alive for the guest's lifetime.
pub(crate) fn install<P: ShimPlatform>(
    program: &LoadedProgram<P>,
    cache: &Arc<GuestCache>,
) -> Result<Range<usize>> {
    let header = cache.header();
    let start = header.shared_region_start;
    let size = header.shared_region_size.next_multiple_of(PAGE);
    let mut from = SHARED_CACHE_MIN_ADDRESS as u64;
    let base = loop {
        let base = free_host_range(from, size).context("no free range for the guest cache")?;
        let range = usize::try_from(base)?..usize::try_from(base + size)?;
        match program.reserve_shared_cache(range) {
            Ok(()) => break base,
            // Raced with a host allocation; search past it.
            Err(_) if base < u64::MAX - PAGE => from = base + PAGE,
            Err(error) => bail!("reserving the guest cache: {error}"),
        }
    };
    let slide = base - start;
    litebox_util_log::debug!(base:? = base, slide:? = slide; "guest shared-cache instance");
    let slid = |address: u64| usize::try_from(address + slide).expect("64-bit addresses");

    let mappings = cache.mappings();
    // Native pages of closure __TEXT, rewritten and made executable.
    let text_runs = page_runs(cache.closure.iter().filter_map(|closure| {
        closure
            .image
            .segment("__TEXT")
            .map(|segment| segment.address_range.clone())
    }));
    for run in &text_runs {
        let (_, mapping) = cache
            .cache
            .mapping_containing(run.start, run.end - run.start)
            .with_context(|| format!("closure text {run:#x?} spans mappings"))?;
        ensure!(
            mapping.initial_protection.contains(VmProtection::EXECUTE)
                && mapping.slide_info.is_empty(),
            "closure text {run:#x?} is not in a text mapping"
        );
    }
    // Native pages of closure DATA-like segments, rebased. TPRO_CONST
    // mappings are small and dyld changes their protection as a whole
    // (`MemoryManager::writeProtect`), so they are materialized entirely.
    let tpro_const = mappings
        .iter()
        .filter(|(mapping, ..)| mapping.flags.contains(MappingFlags::CONST_TPRO_DATA))
        .map(|(mapping, ..)| mapping.address_range());
    let data_runs = split_at_mappings(
        page_runs(
            cache
                .closure
                .iter()
                .flat_map(|closure| {
                    closure
                        .image
                        .segments
                        .iter()
                        .filter(|segment| segment.name != "__TEXT" && segment.name != "__LINKEDIT")
                        .map(|segment| segment.address_range.clone())
                        .collect::<Vec<_>>()
                })
                .chain(tpro_const),
        ),
        &mappings,
    );
    let dynamic_page = header
        .dynamic_data
        .map(|(offset, _)| start + offset..start + offset + DYNAMIC_REGION_SIZE as u64);

    let mut copies: BTreeMap<u64, Copied> = BTreeMap::new();
    let read = |range: &Range<u64>| -> Result<Vec<u8>> {
        Ok(cache
            .cache
            .read_at_address(range.start, usize::try_from(range.end - range.start)?)?)
    };
    for run in &text_runs {
        let ranges = cache.instruction_ranges(run)?;
        let executable = VmProtection::READ | VmProtection::EXECUTE;
        copies.insert(
            run.start,
            Copied {
                range: run.clone(),
                bytes: read(run)?,
                protection: executable,
                max_protection: executable,
                instruction_ranges: Some(ranges),
            },
        );
    }
    for run in &data_runs {
        let (file, mapping) = cache
            .cache
            .mapping_containing(run.start, run.end - run.start)
            .context("data run outside one mapping")?;
        ensure!(
            !mapping.initial_protection.contains(VmProtection::EXECUTE),
            "closure data {run:#x?} is in an executable mapping"
        );
        let bytes = cache.slid_data(file, mapping, run, slide)?;
        copies.insert(
            run.start,
            Copied {
                range: run.clone(),
                bytes,
                protection: mapping.initial_protection,
                max_protection: mapping.max_protection,
                instruction_ranges: None,
            },
        );
    }
    if let Some(page) = &dynamic_page {
        ensure!(
            cache.cache.mapping_containing(page.start, 1).is_none()
                && copies
                    .range(..page.end)
                    .next_back()
                    .is_none_or(|(_, copied)| copied.range.end <= page.start),
            "DynamicRegion overlaps cache contents"
        );
        copies.insert(
            page.start,
            Copied {
                range: page.clone(),
                bytes: cache.dynamic_region.clone(),
                protection: VmProtection::READ,
                max_protection: VmProtection::READ,
                instruction_ranges: None,
            },
        );
    }

    // Tile [start, start + size): every mapping is a read-only file view
    // (header, text, read-only, LINKEDIT) or demand-paged (DATA), holes are
    // inaccessible, and copied pages replace either.
    let mut regions: Vec<(Range<u64>, Region)> = Vec::new();
    let mut cursor = start;
    for (mapping, bytes) in &mappings {
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
            regions.push((cursor..range.start, Region::Hole));
        }
        let data = mapping.initial_protection.contains(VmProtection::WRITE)
            || !mapping.slide_info.is_empty();
        let region = if data {
            Region::Data
        } else {
            let file = usize::try_from(mapping.file_range().start).expect("64-bit offsets");
            Region::View(&bytes[file..file + usize::try_from(mapping.size).expect("64-bit sizes")])
        };
        regions.push((range.clone(), region));
        cursor = range.end;
    }
    ensure!(
        cursor <= start + size,
        "cache mappings exceed the shared region"
    );
    if cursor < start + size {
        regions.push((cursor..start + size, Region::Hole));
    }
    let mut pieces: Vec<Piece> = Vec::new();
    let mut uncopied = |range: Range<u64>, region: &Range<u64>, kind: Region| {
        if range.start == range.end {
            return;
        }
        pieces.push(match kind {
            Region::View(bytes) => {
                let offset = usize::try_from(range.start - region.start).expect("64-bit offsets");
                let length = usize::try_from(range.end - range.start).expect("64-bit sizes");
                Piece {
                    range,
                    // Readable, never executable: only rewritten copies execute.
                    backing: Backing::Source(&bytes[offset..offset + length]),
                    protection: VmProtection::READ,
                    max_protection: VmProtection::READ,
                }
            }
            // DATA pages are slid on first touch, like XNU's slide pager.
            Region::Data => Piece {
                range,
                backing: Backing::Paged,
                protection: VmProtection::empty(),
                max_protection: VmProtection::empty(),
            },
            Region::Hole => Piece {
                range,
                backing: Backing::Reserved,
                protection: VmProtection::empty(),
                max_protection: VmProtection::empty(),
            },
        });
    };
    let mut pending_copies = copies.values().peekable();
    let mut copied_pieces = Vec::new();
    for (region, kind) in &regions {
        let mut position = region.start;
        while let Some(copy) = pending_copies.next_if(|copy| copy.range.start < region.end) {
            let range = &copy.range;
            ensure!(
                range.start >= position && range.end <= region.end,
                "copied pages {range:#x?} straddle a mapping boundary"
            );
            uncopied(position..range.start, region, *kind);
            copied_pieces.push(Piece {
                range: range.clone(),
                backing: Backing::Copy(range.start),
                protection: copy.protection,
                max_protection: copy.max_protection,
            });
            position = range.end;
        }
        uncopied(position..region.end, region, *kind);
    }
    ensure!(
        pending_copies.next().is_none(),
        "copied pages outside the shared region"
    );
    pieces.extend(copied_pieces);
    pieces.sort_by_key(|piece| piece.range.start);

    // Island candidates per cluster of executable runs.
    let mut clusters: Vec<Range<u64>> = Vec::new();
    for run in &text_runs {
        match clusters.last_mut() {
            Some(cluster) if run.start - cluster.end <= CLUSTER_GAP => cluster.end = run.end,
            _ => clusters.push(run.clone()),
        }
    }
    let mut islands: BTreeSet<u64> = BTreeSet::new();
    for cluster in &clusters {
        let code: u64 = text_runs
            .iter()
            .filter(|run| run.start >= cluster.start && run.end <= cluster.end)
            .map(|run| run.end - run.start)
            .sum();
        // Generous: unused candidates cost nothing.
        let wanted = usize::try_from((code / 8).div_ceil(PAGE))? + 16;
        let candidates = cache.island_candidates(cluster, &text_runs)?;
        ensure!(
            !candidates.is_empty(),
            "no gate island candidates near {cluster:#x?}"
        );
        islands.extend(candidates.iter().take(wanted).map(|page| page.start));
    }
    let gate_islands: Vec<Range<usize>> = islands
        .iter()
        .map(|page| slid(*page)..slid(*page + PAGE))
        .collect();

    let shim_pieces: Vec<SharedCachePiece<'_>> = pieces
        .iter()
        .map(|piece| SharedCachePiece {
            range: slid(piece.range.start)..slid(piece.range.end),
            backing: match piece.backing {
                Backing::Reserved => SharedCacheBacking::Reserved,
                Backing::Paged => SharedCacheBacking::Paged,
                Backing::Source(bytes) => SharedCacheBacking::Source(bytes),
                Backing::Copy(key) => SharedCacheBacking::Copy(&copies[&key].bytes),
            },
            protection: piece.protection,
            max_protection: piece.max_protection,
        })
        .collect();
    let code_regions: Vec<SharedCacheCodeRegion<'_>> = pieces
        .iter()
        .enumerate()
        .filter_map(|(index, piece)| match piece.backing {
            Backing::Copy(key) => {
                copies[&key]
                    .instruction_ranges
                    .as_deref()
                    .map(|ranges| SharedCacheCodeRegion {
                        piece: index,
                        instruction_ranges: ranges,
                    })
            }
            _ => None,
        })
        .collect();
    litebox_util_log::debug!(
        pieces = shim_pieces.len(),
        text_runs = text_runs.len(),
        data_runs = data_runs.len(),
        clusters = clusters.len(),
        island_candidates = gate_islands.len();
        "guest shared-cache layout"
    );
    let range = slid(start)..slid(start + size);
    program
        .install_shared_cache(&SharedCacheLayout {
            range: range.clone(),
            pieces: &shim_pieces,
            code_regions: &code_regions,
            gate_islands: &gate_islands,
            attribution: Some({
                let cache = Arc::clone(cache);
                Arc::new(move |address: usize| cache.describe((address as u64).checked_sub(slide)?))
            }),
            pager: Some({
                let cache = Arc::clone(cache);
                Arc::new(move |address: usize| {
                    cache.page((address as u64).checked_sub(slide)?, slide)
                })
            }),
        })
        .context("installing the guest shared cache")?;
    Ok(range)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_pointer_signer_is_identity_without_pointer_authentication() {
        // This runner is a plain arm64 process, whose JOP keys are disabled.
        for key in [PointerAuthKey::Ia, PointerAuthKey::Da] {
            assert_eq!(
                TaskPointerSigner.sign(0x1_8000_1234, key, 0x1234_5678),
                0x1_8000_1234
            );
        }
    }

    #[test]
    fn page_runs_merge_shared_native_pages() {
        assert_eq!(
            page_runs([0x5000..0x6000, 0x7000..0x9000, 0x1_0000..0x1_0001]),
            [0x4000..0xc000, 0x1_0000..0x1_4000]
        );
    }
}
