// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Private in-place remapping of the inherited live host dyld shared cache.

use anyhow::{Context as _, Result, bail};
use litebox_platform_macos_userland::{
    HOST_PAGE_SIZE, MacosUserland, SharedCacheMappingError, SharedCacheWriteAlias,
};
use object::{endian::LittleEndian as LE, macho};
use std::{mem::size_of, ops::Range};

const LIBSYSTEM_KERNEL: &str = "/usr/lib/system/libsystem_kernel.dylib";
const DYLD_IMAGE: &str = "/usr/lib/dyld";
/// One MiB stays within AArch64's ±128 MiB branch reach and bounds this
/// minimal runtime to roughly 16K fixed-size SVC/TPIDRRO gates.
const CACHE_TRAMPOLINE_RESERVATION_SIZE: usize = 1024 * 1024;
/// Keep every selected site comfortably within an AArch64 direct branch from
/// the trampoline reservation immediately below the first cache mapping.
const CACHE_TRAMPOLINE_REACH: usize = 0x07e0_0000;

unsafe extern "C" {
    fn _dyld_get_shared_cache_range(size: *mut usize) -> *const core::ffi::c_void;
}

pub(crate) struct PrivateSharedCacheRegion {
    pub(crate) address: usize,
    pub(crate) code_ranges: Vec<Range<usize>>,
    pub(crate) native_tpidrro_ranges: Vec<Range<usize>>,
    pub(crate) alias: SharedCacheWriteAlias,
    pub(crate) length: usize,
}

/// Image headers, mapping permissions and ASLR slide read from the live cache.
struct LiveCacheMetadata {
    images: Vec<(String, usize)>,
    mappings: Vec<litebox_shim_macos::SharedCacheMapping>,
    slide: usize,
}

/// One ephemeral, per-execution instantiation of the live shared cache.
///
/// This stores only the state needed between inspection and publication in the
/// current fork child. It is never reused as a cached layout or rewrite plan.
pub(crate) struct PrivateSharedCacheInstance {
    pub(crate) range: Range<usize>,
    pub(crate) dyld: Vec<u8>,
    pub(crate) regions: Vec<PrivateSharedCacheRegion>,
    pub(crate) mappings: Vec<litebox_shim_macos::SharedCacheMapping>,
    pub(crate) trampoline_address: usize,
    pub(crate) trampoline: SharedCacheWriteAlias,
    pub(crate) trampoline_length: usize,
    pub(crate) tpro_ranges: Vec<Range<usize>>,
}

impl PrivateSharedCacheInstance {
    pub(crate) fn instantiate(platform: &MacosUserland) -> Result<Self> {
        let mut size = 0usize;
        // SAFETY: size is writable and the dyld API returns the current
        // process's immutable shared-cache range.
        let live_base = unsafe { _dyld_get_shared_cache_range(&raw mut size) } as usize;
        let live_end = live_base
            .checked_add(size)
            .context("shared-cache range overflow")?;
        if live_base == 0 || size == 0 {
            bail!("host dyld reported no shared cache");
        }

        let LiveCacheMetadata {
            images,
            mappings,
            slide,
        } = live_cache_metadata(platform, live_base, size)?;
        let mut text = Vec::new();
        let mut native_tpidrro_text = Vec::new();
        let mut main_thread_probes = 0;
        let mut found_kernel = false;
        let mut skipped_images = 0;
        let mut skipped_system_images = 0;
        let mut tpro_ranges = Vec::new();
        for (name, header) in images {
            if name == DYLD_IMAGE {
                // SAFETY: header comes from dyld's live cache image table; its
                // immutable Mach-O header and load commands remain mapped during setup.
                tpro_ranges.extend(unsafe { live_segment_ranges(header, slide, b"__TPRO_CONST") }?);
            }
            // SAFETY: this is a live cache image with immutable mapped load commands.
            let sections = unsafe { live_instruction_sections(header, slide) }
                .with_context(|| format!("parsing live instruction sections for {name}"))?;
            if !image_within_reach(&name, &sections, live_base)? {
                skipped_images += 1;
                if name.starts_with("/usr/lib/system/") {
                    skipped_system_images += 1;
                }
                continue;
            }
            found_kernel |= name == LIBSYSTEM_KERNEL;
            let native_tpidrro = uses_native_tpidrro(&name);
            for instructions in sections {
                // SAFETY: the image's instruction sections are live, readable and aligned.
                let (sites, probes) =
                    unsafe { host_cache_patch_sites(instructions, native_tpidrro) };
                if native_tpidrro {
                    native_tpidrro_text.extend(sites);
                } else {
                    text.extend(sites);
                }
                main_thread_probes += probes;
            }
        }
        if !found_kernel {
            bail!("libsystem_kernel is absent from the reachable live cache");
        }
        if skipped_images != 0 {
            // These count images, not unhandled patch sites. Keep this setup
            // diagnostic out of the guest's normal stderr stream.
            litebox_util_log::debug!(
                "bounded shared-cache rewrite skips {skipped_images} out-of-reach images ({skipped_system_images} system images)"
            );
        }
        if main_thread_probes != 1 {
            bail!("expected one recognizable pthread_main_np probe, found {main_thread_probes}");
        }
        if text.is_empty() && native_tpidrro_text.is_empty() {
            bail!("libSystem cache closure has no SVC or TPIDRRO sites");
        }
        text.sort_unstable_by_key(|range| range.start);
        native_tpidrro_text.sort_unstable_by_key(|range| range.start);

        let pages = patch_pages(&text, &native_tpidrro_text)?;

        let mut regions = Vec::new();
        for pages in pages {
            if pages.start < live_base || pages.end > live_end {
                bail!("libsystem_kernel TEXT lies outside the live cache");
            }
            // SAFETY: runner startup is single-threaded here, and the range was
            // derived from the current process's live dyld cache.
            let alias = unsafe {
                litebox_platform_macos_userland::prepare_shared_cache_copy(pages.clone())
            }
            .map_err(|error| anyhow::anyhow!("privatizing shared cache: {error:?}"))?;
            let code_ranges: Vec<_> = text
                .iter()
                .filter(|code| code.start < pages.end && pages.start < code.end)
                .map(|code| {
                    code.start.max(pages.start) - pages.start..code.end.min(pages.end) - pages.start
                })
                .collect();
            let native_tpidrro_ranges: Vec<_> = native_tpidrro_text
                .iter()
                .filter(|code| code.start < pages.end && pages.start < code.end)
                .map(|code| {
                    code.start.max(pages.start) - pages.start..code.end.min(pages.end) - pages.start
                })
                .collect();
            if code_ranges.is_empty() && native_tpidrro_ranges.is_empty() {
                bail!("private cache page has no code range");
            }
            regions.push(PrivateSharedCacheRegion {
                address: pages.start,
                code_ranges,
                native_tpidrro_ranges,
                length: pages.len(),
                alias,
            });
        }
        if regions
            .iter()
            .map(|region| region.code_ranges.len())
            .sum::<usize>()
            != text.len()
            || regions
                .iter()
                .map(|region| region.native_tpidrro_ranges.len())
                .sum::<usize>()
                != native_tpidrro_text.len()
        {
            bail!("shared-cache region plan dropped instruction sites");
        }
        let (trampoline_range, padding_range) = trampoline_ranges(live_base, slide)?;
        let trampoline_address = trampoline_range.start;
        let trampoline = litebox_platform_macos_userland::prepare_private_cache_mapping(
            trampoline_range.clone(),
        )
        .or_else(|error| {
            if padding_range.is_empty()
                || !matches!(error, SharedCacheMappingError::Mach(status)
                    if status == litebox_common_macos::KernReturn::from_raw(libc::KERN_NO_SPACE))
            {
                return Err(error);
            }
            // SAFETY: live_base came from dyld in this isolated fork child;
            // no other thread changes the inherited cache mappings here.
            // Only verified, inaccessible ASLR padding may be released.
            unsafe {
                litebox_platform_macos_userland::release_shared_cache_padding(
                    padding_range,
                    live_base,
                )
            }?;
            litebox_platform_macos_userland::prepare_private_cache_mapping(trampoline_range)
        })
        .map_err(|error| anyhow::anyhow!("preparing cache trampoline: {error:?}"))?;
        let tpro_ranges = tpro_ranges
            .into_iter()
            .map(|range| {
                let start = range.start & !(HOST_PAGE_SIZE - 1);
                let end = (range.end + HOST_PAGE_SIZE - 1) & !(HOST_PAGE_SIZE - 1);
                start..end
            })
            .collect();
        let mut dyld = std::fs::read("/usr/lib/dyld").context("reading host dyld")?;
        litebox_common_macos::dyld::patch_for_initialized_shared_cache(&mut dyld)
            .context("preparing host dyld for the shared cache")?;
        Ok(Self {
            range: live_base..live_end,
            dyld,
            regions,
            mappings,
            trampoline_address,
            trampoline,
            trampoline_length: CACHE_TRAMPOLINE_RESERVATION_SIZE,
            tpro_ranges,
        })
    }

    /// # Safety
    ///
    /// The caller must run in the isolated fork child with all shared-cache
    /// users quiesced until every staged region has been published.
    pub(crate) unsafe fn commit(self) -> Result<()> {
        // Dyld has already been copied into guest mappings; release its input
        // buffer before replacing any live cache code.
        drop(self.dyld);
        // SAFETY: the caller provides exclusive access to every prepared range.
        unsafe { self.trampoline.commit() }
            .map_err(|error| anyhow::anyhow!("publishing cache trampoline: {error:?}"))?;
        for region in self.regions {
            // SAFETY: the caller provides exclusive access to every prepared range.
            unsafe { region.alias.commit() }
                .map_err(|error| anyhow::anyhow!("publishing private cache: {error:?}"))?;
        }
        Ok(())
    }
}

// The reservation may straddle the shared-region boundary on a small slide.
// Only its intersection with ASLR padding can be released; the platform still
// verifies the actual submap before unmapping it, and reservation never overwrites.
fn trampoline_ranges(live_base: usize, slide: usize) -> Result<(Range<usize>, Range<usize>)> {
    if !live_base.is_multiple_of(HOST_PAGE_SIZE) || !slide.is_multiple_of(HOST_PAGE_SIZE) {
        bail!("unaligned shared-cache base or slide");
    }
    let start = live_base
        .checked_sub(CACHE_TRAMPOLINE_RESERVATION_SIZE)
        .context("no address below shared cache for trampolines")?;
    let unslid_base = live_base
        .checked_sub(slide)
        .context("invalid cache slide")?;
    Ok((start..live_base, start.max(unslid_base)..live_base))
}

fn patch_pages(text: &[Range<usize>], native: &[Range<usize>]) -> Result<Vec<Range<usize>>> {
    let mut sites = text.iter().chain(native).collect::<Vec<_>>();
    sites.sort_unstable_by_key(|range| range.start);
    let mut pages: Vec<Range<usize>> = Vec::new();
    for range in sites {
        let start = range.start & !(HOST_PAGE_SIZE - 1);
        let end = range
            .end
            .checked_add(HOST_PAGE_SIZE - 1)
            .context("TEXT alignment overflow")?
            & !(HOST_PAGE_SIZE - 1);
        if let Some(previous) = pages.last_mut()
            && start <= previous.end
        {
            previous.end = previous.end.max(end);
        } else {
            pages.push(start..end);
        }
    }
    Ok(pages)
}

// The platform reference witnesses initialization of the exception handlers
// required by fallible metadata reads; do not allocate a second platform here.
fn live_cache_metadata(
    _platform: &MacosUserland,
    live_base: usize,
    live_size: usize,
) -> Result<LiveCacheMetadata> {
    use litebox_common_macos::user_pointers::UserPtr;
    parse_cache_metadata(live_base, live_size, |address, length| {
        UserPtr::<u8>::from_usize(address)
            .to_owned_slice::<MacosUserland>(length)
            .map(Vec::from)
            .context("unreadable live cache metadata")
    })
}

fn parse_cache_metadata(
    live_base: usize,
    live_size: usize,
    mut read: impl FnMut(usize, usize) -> Result<Vec<u8>>,
) -> Result<LiveCacheMetadata> {
    use object::read::macho::DyldSubCacheSlice;
    let live_end = live_base
        .checked_add(live_size)
        .context("cache range overflow")?;
    let mut read = |address: usize, length: usize| {
        if length > 16 * 1024 * 1024
            || address < live_base
            || address.checked_add(length).is_none_or(|end| end > live_end)
        {
            bail!("cache metadata outside bounded live range");
        }
        read(address, length)
    };
    let prefix = read(live_base, HOST_PAGE_SIZE)?;
    let prefix = prefix.as_slice();
    let header = macho::DyldCacheHeader::<LE>::parse(prefix)
        .map_err(|error| anyhow::anyhow!("parsing live cache header: {error}"))?;
    let mappings = header
        .mappings(LE, prefix)
        .map_err(|error| anyhow::anyhow!("parsing live cache mappings: {error}"))?;
    let first = mappings
        .iter()
        .find(|mapping| mapping.file_offset.get(LE) == 0)
        .context("live cache has no primary mapping")?;
    let unslid_base =
        usize::try_from(first.address.get(LE)).context("live cache base address overflow")?;
    let slide = live_base
        .checked_sub(unslid_base)
        .context("live cache has a negative or inconsistent slide")?;

    let metadata_size =
        usize::try_from(first.size.get(LE)).context("live cache metadata size overflow")?;
    if metadata_size > live_size {
        bail!("live cache metadata mapping exceeds the reported cache range");
    }
    let metadata = read(live_base, metadata_size)?;
    let metadata = metadata.as_slice();
    let header = macho::DyldCacheHeader::<LE>::parse(metadata)
        .map_err(|error| anyhow::anyhow!("parsing full live cache header: {error}"))?;
    let mut caches = vec![(live_base, header.uuid)];
    let mut add_subcache = |offset: u64, uuid| -> Result<()> {
        if caches.len() > 1024 {
            bail!("too many live subcaches");
        }
        let base = live_base
            .checked_add(usize::try_from(offset)?)
            .context("subcache address overflow")?;
        if offset == 0 || !base.is_multiple_of(HOST_PAGE_SIZE) {
            bail!("invalid subcache base");
        }
        caches.push((base, uuid));
        Ok(())
    };
    match header.subcaches(LE, metadata)? {
        Some(DyldSubCacheSlice::V1(entries)) => {
            for entry in entries {
                add_subcache(entry.cache_vm_offset.get(LE), entry.uuid)?;
            }
        }
        Some(DyldSubCacheSlice::V2(entries)) => {
            for entry in entries {
                add_subcache(entry.cache_vm_offset.get(LE), entry.uuid)?;
            }
        }
        Some(_) => bail!("unsupported subcache format"),
        None => {}
    }
    let mut mapped_ranges = Vec::new();
    for (base, uuid) in caches {
        let data = read(base, HOST_PAGE_SIZE)?;
        let cache = macho::DyldCacheHeader::<LE>::parse(data.as_slice())?;
        if cache.uuid != uuid || cache.parse_magic()?.0 != object::Architecture::Aarch64 {
            bail!("live subcache identity mismatch");
        }
        let mappings = cache.mappings(LE, data.as_slice())?;
        if !mappings.iter().any(|m| {
            m.file_offset.get(LE) == 0
                && m.address.get(LE).checked_add(slide as u64) == Some(base as u64)
        }) {
            bail!("subcache header mapping does not match its live address");
        }
        for mapping in mappings {
            let start = usize::try_from(mapping.address.get(LE))?
                .checked_add(slide)
                .context("slid mapping overflow")?;
            let end = start
                .checked_add(usize::try_from(mapping.size.get(LE))?)
                .context("mapping end overflow")?;
            if start >= end
                || start < live_base
                || end > live_end
                || !start.is_multiple_of(HOST_PAGE_SIZE)
                || !end.is_multiple_of(HOST_PAGE_SIZE)
            {
                bail!("shared-cache mapping outside live range");
            }
            let protection = litebox_common_macos::VmProtection::from_bits(i32::try_from(
                mapping.init_prot.get(LE),
            )?)
            .context("invalid shared-cache mapping protection")?;
            mapped_ranges.push(litebox_shim_macos::SharedCacheMapping {
                range: start..end,
                protection,
            });
        }
    }
    mapped_ranges.sort_unstable_by_key(|mapping| mapping.range.start);
    if mapped_ranges
        .windows(2)
        .any(|pair| pair[0].range.end > pair[1].range.start)
    {
        bail!("overlapping shared-cache mappings");
    }
    let images = header
        .images(LE, metadata)
        .map_err(|error| anyhow::anyhow!("parsing live cache image table: {error}"))?;
    let mut result = Vec::with_capacity(images.len());
    for image in images {
        let path = image
            .path(LE, metadata)
            .map_err(|error| anyhow::anyhow!("parsing live cache image path: {error}"))?;
        let path = core::str::from_utf8(path).context("live cache image path is not UTF-8")?;
        let address = usize::try_from(image.address.get(LE))
            .context("live cache image address overflow")?
            .checked_add(slide)
            .context("slid live cache image overflow")?;
        if !mapped_ranges.iter().any(|mapping| {
            mapping
                .protection
                .contains(litebox_common_macos::VmProtection::READ)
                && mapping.range.contains(&address)
        }) {
            bail!("live image header outside readable cache mappings");
        }
        result.push((path.to_owned(), address));
    }
    Ok(LiveCacheMetadata {
        images: result,
        mappings: mapped_ranges,
        slide,
    })
}

// Admit or skip each image as a whole, independent of where this OS build
// happens to place its SVC/TPIDRRO instructions within the code sections.
fn image_within_reach(image: &str, sections: &[Range<usize>], live_base: usize) -> Result<bool> {
    if sections.iter().any(|section| section.start < live_base) {
        bail!("image code precedes live cache: {image}");
    }
    if sections
        .iter()
        .all(|section| section.end - live_base <= CACHE_TRAMPOLINE_REACH)
    {
        return Ok(true);
    }
    if image == LIBSYSTEM_KERNEL || uses_native_tpidrro(image) {
        bail!("required cache image is outside trampoline reach: {image}");
    }
    Ok(false)
}

fn uses_native_tpidrro(image: &str) -> bool {
    matches!(image, DYLD_IMAGE | "/usr/lib/system/libdyld.dylib")
}

/// Select only instructions that will change. Native-TSD images contribute SVCs only.
///
/// # Safety
/// `range` must cover live, immutable, readable, u32-aligned instruction storage.
unsafe fn host_cache_patch_sites(
    range: Range<usize>,
    native_tpidrro: bool,
) -> (Vec<Range<usize>>, usize) {
    const DARWIN_SVC: u32 = 0xd400_1001;
    const MRS_TPIDRRO_MASK: u32 = 0xffff_ffe0;
    const MRS_TPIDRRO_BITS: u32 = 0xd53b_d060;

    // SAFETY: the caller guarantees the range's lifetime, readability and alignment.
    let words = unsafe {
        core::slice::from_raw_parts(range.start as *const u32, range.len() / size_of::<u32>())
    };
    let mut main_thread_probes = 0;
    let sites = words
        .iter()
        .enumerate()
        .filter_map(|(index, word)| {
            let word = u32::from_le(*word);
            let native_main_thread_probe =
                word & MRS_TPIDRRO_MASK == MRS_TPIDRRO_BITS && is_pthread_main_np(&words[index..]);
            main_thread_probes += usize::from(native_main_thread_probe);
            ((word == DARWIN_SVC)
                || (!native_tpidrro
                    && word & MRS_TPIDRRO_MASK == MRS_TPIDRRO_BITS
                    && !native_main_thread_probe))
                .then(|| {
                    let start = range.start + index * size_of::<u32>();
                    start..start + size_of::<u32>()
                })
        })
        .collect();
    (sites, main_thread_probes)
}

/// `pthread_main_np` only compares the current pthread identity with
/// libpthread's process-global main-thread pointer. Leave this read native: the
/// guest executes on the runner child's real main thread, so the comparison
/// remains true without granting guest libc general access to the runner TSD.
fn is_pthread_main_np(words: &[u32]) -> bool {
    const ADRP_X9_MASK: u32 = 0x9f00_001f;
    const ADRP_X9: u32 = 0x9000_0009;
    const LDR_X9_X9_MASK: u32 = 0xffc0_03ff;
    const LDR_X9_X9: u32 = 0xf940_0129;

    let Some(words) = words.first_chunk::<7>() else {
        return false;
    };
    u32::from_le(words[0]) == 0xd53b_d068 // mrs x8, tpidrro_el0
        && u32::from_le(words[1]) == 0xd103_8108 // sub x8, x8, #0xe0
        && u32::from_le(words[2]) & ADRP_X9_MASK == ADRP_X9
        && u32::from_le(words[3]) & LDR_X9_X9_MASK == LDR_X9_X9
        && u32::from_le(words[4]) == 0xeb08_013f // cmp x9, x8
        && u32::from_le(words[5]) == 0x1a9f_17e0 // cset w0, eq
        && u32::from_le(words[6]) == 0xd65f_03c0 // ret
}

/// # Safety
/// `header` and its load commands must be live, immutable, readable and aligned.
#[allow(deprecated, reason = "libc exposes the host SDK Mach-O header layouts")]
unsafe fn live_segment_ranges(
    header: usize,
    slide: usize,
    name: &[u8],
) -> Result<Vec<Range<usize>>> {
    // SAFETY: the caller supplies a live, aligned Mach-O header.
    let header = unsafe { &*(header as *const libc::mach_header_64) };
    if header.magic != libc::MH_MAGIC_64 {
        bail!("live cache image has an invalid Mach-O header");
    }
    let commands_start = core::ptr::from_ref(header).wrapping_add(1).cast::<u8>();
    let commands_end = commands_start
        .addr()
        .checked_add(header.sizeofcmds as usize)
        .context("live Mach-O command range overflow")?;
    let mut command = commands_start;
    let mut ranges = Vec::new();
    for _ in 0..header.ncmds {
        if command
            .addr()
            .checked_add(size_of::<libc::load_command>())
            .is_none_or(|end| end > commands_end)
        {
            bail!("truncated live Mach-O load command");
        }
        // SAFETY: the bounds above cover the fixed load-command header.
        let load = unsafe { &*command.cast::<libc::load_command>() };
        let command_size = load.cmdsize as usize;
        if command_size < size_of::<libc::load_command>()
            || command
                .addr()
                .checked_add(command_size)
                .is_none_or(|end| end > commands_end)
        {
            bail!("invalid live Mach-O load command size");
        }
        if load.cmd == libc::LC_SEGMENT_64 {
            if command_size < size_of::<libc::segment_command_64>() {
                bail!("truncated live Mach-O segment command");
            }
            // SAFETY: command_size covers the segment command.
            let segment = unsafe { &*command.cast::<libc::segment_command_64>() };
            let segment_name = segment
                .segname
                .iter()
                .map(|byte| (*byte).cast_unsigned())
                .take_while(|byte| *byte != 0);
            if segment_name.eq(name.iter().copied()) {
                let start = usize::try_from(segment.vmaddr)
                    .context("live segment address overflow")?
                    .checked_add(slide)
                    .context("slid live segment overflow")?;
                let end = start
                    .checked_add(
                        usize::try_from(segment.vmsize).context("live segment size overflow")?,
                    )
                    .context("live segment range overflow")?;
                if start < end {
                    ranges.push(start..end);
                }
            }
        }
        command = command.wrapping_add(command_size);
    }
    Ok(ranges)
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Section64 {
    section_name: [u8; 16],
    segment_name: [u8; 16],
    address: u64,
    size: u64,
    offset: u32,
    alignment: u32,
    relocation_offset: u32,
    relocation_count: u32,
    flags: u32,
    reserved: [u32; 3],
}

const _: () = assert!(size_of::<Section64>() == 80);

/// # Safety
/// `header` and its load commands must be live, immutable, readable and aligned.
#[allow(deprecated, reason = "libc exposes the host SDK Mach-O header layouts")]
unsafe fn live_instruction_sections(header: usize, slide: usize) -> Option<Vec<Range<usize>>> {
    const PURE_INSTRUCTIONS: u32 = 0x8000_0000;
    const SOME_INSTRUCTIONS: u32 = 0x0000_0400;

    // SAFETY: the caller supplies a live, aligned Mach-O header.
    let header = unsafe { &*(header as *const libc::mach_header_64) };
    if header.magic != libc::MH_MAGIC_64 {
        return None;
    }
    let commands_start = core::ptr::from_ref(header).wrapping_add(1).cast::<u8>();
    let commands_end = commands_start
        .addr()
        .checked_add(header.sizeofcmds as usize)?;
    let mut command = commands_start;
    let mut ranges = Vec::new();
    for _ in 0..header.ncmds {
        if command
            .addr()
            .checked_add(size_of::<libc::load_command>())?
            > commands_end
        {
            return None;
        }
        // SAFETY: the checked bounds cover this header within the caller's load commands.
        let load = unsafe { &*command.cast::<libc::load_command>() };
        let command_size = load.cmdsize as usize;
        if command_size < size_of::<libc::load_command>()
            || command.addr().checked_add(command_size)? > commands_end
        {
            return None;
        }
        if load.cmd == libc::LC_SEGMENT_64 {
            if command_size < size_of::<libc::segment_command_64>() {
                return None;
            }
            // SAFETY: command_size covers the segment command within the live image.
            let segment = unsafe { &*command.cast::<libc::segment_command_64>() };
            let sections_size = (segment.nsects as usize).checked_mul(size_of::<Section64>())?;
            if size_of::<libc::segment_command_64>().checked_add(sections_size)? > command_size {
                return None;
            }
            let sections_address = command
                .addr()
                .checked_add(size_of::<libc::segment_command_64>())?;
            let sections = core::ptr::with_exposed_provenance::<Section64>(sections_address);
            for index in 0..segment.nsects as usize {
                // SAFETY: sections_size was checked against the containing command.
                let section = unsafe { sections.add(index).read_unaligned() };
                if section.flags & (PURE_INSTRUCTIONS | SOME_INSTRUCTIONS) == 0 {
                    continue;
                }
                let start = usize::try_from(section.address).ok()?.checked_add(slide)?;
                let end = start.checked_add(usize::try_from(section.size).ok()?)?;
                if !start.is_multiple_of(size_of::<u32>()) || !end.is_multiple_of(size_of::<u32>())
                {
                    return None;
                }
                if start < end {
                    ranges.push(start..end);
                }
            }
        }
        command = command.wrapping_add(command_size);
    }
    Some(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_pages_merge_both_site_classes_in_address_order() {
        let p = HOST_PAGE_SIZE;
        let text = [p + 4..p + 8, 3 * p..3 * p + 4, 6 * p..6 * p + 4];
        let native = [0..4, 2 * p..2 * p + 4, 3 * p + 8..3 * p + 12];
        let pages = patch_pages(&text, &native).unwrap();
        assert_eq!(pages, [0..4 * p, 6 * p..7 * p]);
        for site in text.iter().chain(&native) {
            assert_eq!(
                pages
                    .iter()
                    .filter(|page| page.start <= site.start && page.end >= site.end)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn required_images_cannot_be_silently_skipped() {
        let base = HOST_PAGE_SIZE;
        for name in [
            LIBSYSTEM_KERNEL,
            DYLD_IMAGE,
            "/usr/lib/system/libdyld.dylib",
        ] {
            assert!(
                image_within_reach(name, core::slice::from_ref(&(base..base + 4)), base).unwrap()
            );
            assert!(
                image_within_reach(
                    name,
                    core::slice::from_ref(&(base..base + CACHE_TRAMPOLINE_REACH + 4)),
                    base,
                )
                .is_err()
            );
        }
        assert!(
            !image_within_reach(
                "/usr/lib/system/libsystem_sanitizers.dylib",
                &[
                    base..base + 4,
                    base + CACHE_TRAMPOLINE_REACH - 4..base + CACHE_TRAMPOLINE_REACH + 4
                ],
                base
            )
            .unwrap()
        );
    }

    #[test]
    fn trampoline_padding_is_clipped_for_small_and_zero_slides() {
        let unslid_base = 0x1_8000_0000;
        for slide in (0..=256 * 1024 * 1024).step_by(HOST_PAGE_SIZE) {
            let base = unslid_base + slide;
            let (reservation, padding) = trampoline_ranges(base, slide).unwrap();
            assert_eq!(reservation, base - CACHE_TRAMPOLINE_RESERVATION_SIZE..base);
            assert_eq!(padding.len(), slide.min(CACHE_TRAMPOLINE_RESERVATION_SIZE));
            assert!(padding.start >= unslid_base);
            assert!(padding.start >= reservation.start);
            assert_eq!(padding.end, base);
        }
        assert!(trampoline_ranges(unslid_base + 1, 0).is_err());
        assert!(trampoline_ranges(unslid_base, 1).is_err());
        assert!(trampoline_ranges(0, 0).is_err());
        assert!(trampoline_ranges(unslid_base, unslid_base + HOST_PAGE_SIZE).is_err());
    }

    #[test]
    fn image_reach_includes_all_code_sections() {
        let base = HOST_PAGE_SIZE;
        let limit = base + CACHE_TRAMPOLINE_REACH;
        let name = "/System/Library/Frameworks/optional.framework/optional";
        assert!(image_within_reach(name, &[base..base + 4, limit - 4..limit], base).unwrap());
        // Load-command order need not be address order. Skip the whole image,
        // even if an early section is reachable and the late one has no patch sites.
        assert!(!image_within_reach(name, &[limit..limit + 4, base..base + 4], base).unwrap());
        assert!(image_within_reach(name, core::slice::from_ref(&(base - 4..base)), base).is_err());
    }

    #[test]
    fn subcache_mappings_preserve_gaps_permissions_and_identity() {
        use object::endian::{U32, U64};
        use object::pod::bytes_of;
        const BASE: usize = 0x2_8000_0000;
        const UNSLID: u64 = 0x1_8000_0000;
        const SUBCACHES: usize = 0x300;
        fn put<T: object::pod::Pod>(bytes: &mut [u8], offset: usize, value: &T) {
            bytes[offset..offset + size_of::<T>()].copy_from_slice(bytes_of(value));
        }
        fn cache(bytes: &mut [u8], offset: usize, mapping_offset: u32, uuid: u8, count: u32) {
            // SAFETY: the on-disk header consists of zero-valid integers and byte arrays.
            let mut header = unsafe { core::mem::zeroed::<macho::DyldCacheHeader<LE>>() };
            header.magic = *b"dyld_v1  arm64e\0";
            header.uuid = [uuid; 16];
            header.mapping_offset = U32::new(LE, mapping_offset);
            header.mapping_count = U32::new(LE, count);
            if offset == 0 {
                header.subcaches_offset = U32::new(LE, u32::try_from(SUBCACHES).unwrap());
                header.subcaches_count = U32::new(LE, 1);
            }
            put(bytes, offset, &header);
            for i in 0..count {
                let mapping = macho::DyldCacheMappingInfo {
                    address: U64::new(
                        LE,
                        UNSLID + offset as u64 + u64::from(i) * 2 * HOST_PAGE_SIZE as u64,
                    ),
                    size: U64::new(LE, HOST_PAGE_SIZE as u64),
                    file_offset: U64::new(LE, u64::from(i) * HOST_PAGE_SIZE as u64),
                    max_prot: U32::new(LE, if i == 0 { 1 } else { 3 }),
                    init_prot: U32::new(LE, if i == 0 { 1 } else { 3 }),
                };
                put(
                    bytes,
                    offset + mapping_offset as usize + i as usize * size_of_val(&mapping),
                    &mapping,
                );
            }
        }
        let parse = |bytes: &[u8]| {
            parse_cache_metadata(BASE, bytes.len(), |address, length| {
                let start = address.checked_sub(BASE).context("test address")?;
                bytes
                    .get(start..start + length)
                    .map(<[u8]>::to_vec)
                    .context("test metadata read")
            })
        };
        // V1 and V2 subcache entries share the UUID/VM-offset prefix.
        for mapping_offset in [0x1c8, 0x200] {
            let mut bytes = vec![0; 5 * HOST_PAGE_SIZE];
            cache(&mut bytes, 0, mapping_offset, 1, 1);
            cache(&mut bytes, 2 * HOST_PAGE_SIZE, mapping_offset, 2, 2);
            put(
                &mut bytes,
                SUBCACHES,
                &macho::DyldSubCacheEntryV2 {
                    uuid: [2; 16],
                    cache_vm_offset: U64::new(LE, 2 * HOST_PAGE_SIZE as u64),
                    file_suffix: [0; 32],
                },
            );
            let metadata = parse(&bytes).unwrap();
            let mappings: Vec<_> = metadata
                .mappings
                .iter()
                .map(|m| (m.range.clone(), m.protection.bits()))
                .collect();
            assert_eq!(
                mappings,
                [
                    (BASE..BASE + HOST_PAGE_SIZE, 1),
                    (BASE + 2 * HOST_PAGE_SIZE..BASE + 3 * HOST_PAGE_SIZE, 1),
                    (BASE + 4 * HOST_PAGE_SIZE..BASE + 5 * HOST_PAGE_SIZE, 3),
                ]
            );
            let uuid_offset =
                2 * HOST_PAGE_SIZE + core::mem::offset_of!(macho::DyldCacheHeader<LE>, uuid);
            bytes[uuid_offset] ^= 1;
            assert!(
                parse(&bytes)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("identity mismatch")
            );
            bytes[uuid_offset] ^= 1;
            let mut bad = bytes.clone();
            put(
                &mut bad,
                SUBCACHES + 16,
                &U64::new(LE, 6 * HOST_PAGE_SIZE as u64),
            );
            assert!(parse(&bad).is_err());
            let data_mapping = 2 * HOST_PAGE_SIZE
                + mapping_offset as usize
                + size_of::<macho::DyldCacheMappingInfo<LE>>();
            put(&mut bytes, data_mapping, &U64::new(LE, UNSLID));
            assert!(
                parse(&bytes)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("overlapping")
            );
        }
    }

    #[test]
    fn cache_scan_selects_tls_sites_but_preserves_the_main_thread_probe() {
        assert!(uses_native_tpidrro(DYLD_IMAGE));
        assert!(uses_native_tpidrro("/usr/lib/system/libdyld.dylib"));
        assert!(!uses_native_tpidrro("/usr/lib/system/libsystem_c.dylib"));
        let words = [
            0xd400_1001u32, // svc #0x80
            0xd53b_d069,    // mrs x9, tpidrro_el0
            0xd53b_d04a,    // mrs x10, tpidr_el0
            0xaa12_03e0,    // mov x0, x18
            0xd53b_d068,    // pthread_main_np: mrs x8, tpidrro_el0
            0xd103_8108,    // sub x8, x8, #0xe0
            0x9000_0009,    // adrp x9, __main_thread_ptr@PAGE
            0xf940_0129,    // ldr x9, [x9, #offset]
            0xeb08_013f,    // cmp x9, x8
            0x1a9f_17e0,    // cset w0, eq
            0xd65f_03c0,    // ret
        ];
        let start = words.as_ptr() as usize;
        // SAFETY: words is live, immutable and u32-aligned for this call.
        let (sites, main_thread_probes) =
            unsafe { host_cache_patch_sites(start..start + size_of_val(&words), false) };
        assert_eq!(sites, [start..start + 4, start + 4..start + 8]);
        assert_eq!(main_thread_probes, 1);
        // Dyld/libdyld preserve physical TPIDRRO. Select only their SVC sites,
        // and do not stage pages whose only candidate instructions are TLS reads.
        // SAFETY: both ranges are within the live, aligned words array above.
        let (native_sites, tls_only_sites) = unsafe {
            (
                host_cache_patch_sites(start..start + size_of_val(&words), true).0,
                host_cache_patch_sites(start + 4..start + 8, true).0,
            )
        };
        assert_eq!(native_sites, core::slice::from_ref(&(start..start + 4)));
        assert_eq!(
            patch_pages(&[], &tls_only_sites).unwrap(),
            [] as [Range<usize>; 0]
        );
    }
}
