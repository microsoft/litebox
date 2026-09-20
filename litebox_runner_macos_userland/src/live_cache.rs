// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Boot-local private instantiation of the host dyld shared cache.

use anyhow::{Context as _, Result, bail};
use litebox_platform_macos_userland::{HOST_PAGE_SIZE, SharedCacheWriteAlias};
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

/// One ephemeral, per-execution instantiation of the live shared cache.
///
/// This stores only the state needed between inspection and publication in the
/// current fork child. It is never reused as a cached layout or rewrite plan.
pub(crate) struct PrivateSharedCacheInstance {
    pub(crate) range: Range<usize>,
    pub(crate) dyld: Vec<u8>,
    pub(crate) regions: Vec<PrivateSharedCacheRegion>,
    pub(crate) trampoline_address: usize,
    pub(crate) trampoline: SharedCacheWriteAlias,
    pub(crate) trampoline_length: usize,
    pub(crate) tpro_ranges: Vec<Range<usize>>,
}

impl PrivateSharedCacheInstance {
    pub(crate) fn instantiate() -> Result<Self> {
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

        let (images, slide) = live_cache_images(live_base, size)?;
        let mut text = Vec::new();
        let mut native_tpidrro_text = Vec::new();
        let mut main_thread_probes = 0;
        let mut found_kernel = false;
        let mut tpro_ranges = Vec::new();
        for (name, header) in images {
            if name == DYLD_IMAGE {
                tpro_ranges.extend(live_segment_ranges(header, slide, b"__TPRO_CONST")?);
            }
            found_kernel |= name == LIBSYSTEM_KERNEL;
            if header.saturating_sub(live_base) >= CACHE_TRAMPOLINE_REACH {
                continue;
            }
            for instructions in live_instruction_sections(header, slide)
                .with_context(|| format!("parsing live instruction sections for {name}"))?
            {
                let (sites, probes) = host_cache_patch_sites(instructions);
                if uses_native_tpidrro(&name) {
                    native_tpidrro_text.extend(sites);
                } else {
                    text.extend(sites);
                }
                main_thread_probes += probes;
            }
        }
        if !found_kernel {
            bail!("libsystem_kernel is absent from the live host cache");
        }
        if main_thread_probes != 1 {
            bail!("expected one recognizable pthread_main_np probe, found {main_thread_probes}");
        }
        if text.is_empty() && native_tpidrro_text.is_empty() {
            bail!("libSystem cache closure has no SVC or TPIDRRO sites");
        }
        text.sort_unstable_by_key(|range| range.start);
        native_tpidrro_text.sort_unstable_by_key(|range| range.start);

        let mut pages: Vec<Range<usize>> = Vec::new();
        for range in text.iter().chain(&native_tpidrro_text) {
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
        let trampoline_address = live_base
            .checked_sub(CACHE_TRAMPOLINE_RESERVATION_SIZE)
            .context("no address below shared cache for trampolines")?
            & !(HOST_PAGE_SIZE - 1);
        let trampoline = litebox_platform_macos_userland::prepare_private_cache_mapping(
            trampoline_address..trampoline_address + CACHE_TRAMPOLINE_RESERVATION_SIZE,
        )
        .map_err(|error| anyhow::anyhow!("preparing cache trampoline: {error:?}"))?;
        let tpro_ranges = tpro_ranges
            .into_iter()
            .map(|range| {
                let start = range.start & !(HOST_PAGE_SIZE - 1);
                let end = (range.end + HOST_PAGE_SIZE - 1) & !(HOST_PAGE_SIZE - 1);
                start..end
            })
            .collect();
        let dyld = std::fs::read("/usr/lib/dyld").context("reading host dyld")?;
        Ok(Self {
            range: live_base..live_end,
            dyld,
            regions,
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
    pub(crate) unsafe fn commit(self) -> Result<Vec<u8>> {
        // SAFETY: the caller provides exclusive access to every prepared range.
        unsafe { self.trampoline.commit() }
            .map_err(|error| anyhow::anyhow!("publishing cache trampoline: {error:?}"))?;
        for region in self.regions {
            // SAFETY: the caller provides exclusive access to every prepared range.
            unsafe { region.alias.commit() }
                .map_err(|error| anyhow::anyhow!("publishing private cache: {error:?}"))?;
        }
        Ok(self.dyld)
    }
}

fn live_cache_images(live_base: usize, live_size: usize) -> Result<(Vec<(String, usize)>, usize)> {
    if live_size < HOST_PAGE_SIZE {
        bail!("live cache is smaller than its metadata page");
    }
    // SAFETY: dyld reported this first page as part of its immutable live cache.
    let prefix = unsafe { core::slice::from_raw_parts(live_base as *const u8, HOST_PAGE_SIZE) };
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
    // SAFETY: the first cache mapping starts at live_base and has metadata_size bytes.
    let metadata = unsafe { core::slice::from_raw_parts(live_base as *const u8, metadata_size) };
    let header = macho::DyldCacheHeader::<LE>::parse(metadata)
        .map_err(|error| anyhow::anyhow!("parsing full live cache header: {error}"))?;
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
        result.push((path.to_owned(), address));
    }
    Ok((result, slide))
}

fn uses_native_tpidrro(image: &str) -> bool {
    matches!(image, DYLD_IMAGE | "/usr/lib/system/libdyld.dylib")
}

fn host_cache_patch_sites(range: Range<usize>) -> (Vec<Range<usize>>, usize) {
    const DARWIN_SVC: u32 = 0xd400_1001;
    const MRS_TPIDRRO_MASK: u32 = 0xffff_ffe0;
    const MRS_TPIDRRO_BITS: u32 = 0xd53b_d060;

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
                || (word & MRS_TPIDRRO_MASK == MRS_TPIDRRO_BITS && !native_main_thread_probe))
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

#[allow(deprecated, reason = "libc exposes the host SDK Mach-O header layouts")]
fn live_segment_ranges(header: usize, slide: usize, name: &[u8]) -> Result<Vec<Range<usize>>> {
    // SAFETY: the address comes from the live cache's validated image table.
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

#[allow(deprecated, reason = "libc exposes the host SDK Mach-O header layouts")]
fn live_instruction_sections(header: usize, slide: usize) -> Option<Vec<Range<usize>>> {
    const PURE_INSTRUCTIONS: u32 = 0x8000_0000;
    const SOME_INSTRUCTIONS: u32 = 0x0000_0400;

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
                let section = unsafe { sections.add(index).read_unaligned() };
                if section.flags & (PURE_INSTRUCTIONS | SOME_INSTRUCTIONS) == 0 {
                    continue;
                }
                let start = usize::try_from(section.address).ok()?.checked_add(slide)?;
                let end = start.checked_add(usize::try_from(section.size).ok()?)?;
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
        let (sites, main_thread_probes) =
            host_cache_patch_sites(start..start + size_of_val(&words));
        assert_eq!(sites, [start..start + 4, start + 4..start + 8]);
        assert_eq!(main_thread_probes, 1);
    }
}
