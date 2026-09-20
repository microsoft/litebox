// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Boot-local private instantiation of the host dyld shared cache.

use anyhow::{Context as _, Result, bail};
use litebox_platform_macos_userland::{HOST_PAGE_SIZE, SharedCacheWriteAlias};
use std::{mem::size_of, ops::Range, path::Path};

const CACHE_DIRECTORY: &str = "/System/Cryptexes/OS/System/Library/dyld";
const CACHE_MAP: &str = "dyld_shared_cache_arm64e.map";
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

pub(crate) struct PrivateCacheRegion {
    pub(crate) address: usize,
    pub(crate) code_ranges: Vec<Range<usize>>,
    pub(crate) alias: SharedCacheWriteAlias,
    pub(crate) length: usize,
}

pub(crate) struct PrivateCache {
    pub(crate) range: Range<usize>,
    pub(crate) dyld: Vec<u8>,
    pub(crate) regions: Vec<PrivateCacheRegion>,
    pub(crate) trampoline_address: usize,
    pub(crate) trampoline: SharedCacheWriteAlias,
    pub(crate) trampoline_length: usize,
    pub(crate) tpro_ranges: Vec<Range<usize>>,
}

impl PrivateCache {
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

        let map_path = Path::new(CACHE_DIRECTORY).join(CACHE_MAP);
        let map = std::fs::read_to_string(&map_path)
            .with_context(|| format!("reading {}", map_path.display()))?;
        let unslid_base = parse_first_mapping(&map).context("cache map has no mapping")?;
        let slide = live_base
            .checked_sub(unslid_base)
            .context("host cache has a negative or inconsistent slide")?;
        // The low cache cluster contains dyld and the core libSystem closure.
        // Patch every real instruction in that closure which can enter XNU or
        // expose the runner pthread. Farther cache images need their own branch
        // islands before they can safely participate in guest execution.
        let image_text = parse_runtime_text_ranges(&map);
        if !image_text
            .iter()
            .any(|(image, _)| image == LIBSYSTEM_KERNEL)
        {
            bail!("libsystem_kernel is absent from the host cache map");
        }
        let mut text = Vec::new();
        let mut main_thread_probes = 0;
        for (_, mut range) in image_text
            .into_iter()
            .filter(|(_, range)| range.end.saturating_sub(unslid_base) < CACHE_TRAMPOLINE_REACH)
        {
            range.start = range
                .start
                .checked_add(slide)
                .context("slid TEXT overflow")?;
            range.end = range.end.checked_add(slide).context("slid TEXT overflow")?;
            for instructions in live_instruction_sections(range.start, slide).unwrap_or_default() {
                let (sites, probes) = host_cache_patch_sites(instructions);
                text.extend(sites);
                main_thread_probes += probes;
            }
        }
        if main_thread_probes != 1 {
            bail!("expected one recognizable pthread_main_np probe, found {main_thread_probes}");
        }
        if text.is_empty() {
            bail!("libSystem cache closure has no SVC or TPIDRRO sites");
        }
        text.sort_unstable_by_key(|range| range.start);

        let mut pages: Vec<Range<usize>> = Vec::new();
        for range in &text {
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
            if code_ranges.is_empty() {
                bail!("private cache page has no code range");
            }
            regions.push(PrivateCacheRegion {
                address: pages.start,
                code_ranges,
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
        let tpro_ranges = parse_segment_ranges(&map, DYLD_IMAGE, "__TPRO_CONST")
            .into_iter()
            .map(|range| {
                let start = (range.start + slide) & !(HOST_PAGE_SIZE - 1);
                let end = (range.end + slide + HOST_PAGE_SIZE - 1) & !(HOST_PAGE_SIZE - 1);
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

fn parse_first_mapping(map: &str) -> Option<usize> {
    map.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        (fields.first() == Some(&"mapping"))
            .then(|| fields.get(3).and_then(|value| parse_hex(value)))
            .flatten()
    })
}

fn parse_runtime_text_ranges(map: &str) -> Vec<(String, Range<usize>)> {
    let mut image = None;
    let mut ranges = Vec::new();
    for line in map.lines() {
        if line.starts_with('/') {
            image = Some(line.trim().to_owned());
            continue;
        }
        let Some(image) = image.as_ref() else {
            continue;
        };
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() >= 4
            && fields[0] == "__TEXT"
            && fields[2] == "->"
            && let (Some(start), Some(end)) = (parse_hex(fields[1]), parse_hex(fields[3]))
        {
            ranges.push((image.clone(), start..end));
        }
    }
    ranges
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

fn parse_segment_ranges(map: &str, image: &str, segment: &str) -> Vec<Range<usize>> {
    let mut selected = false;
    let mut ranges = Vec::new();
    for line in map.lines() {
        if line.starts_with('/') {
            selected = line.trim() == image;
            continue;
        }
        if !selected {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() >= 4
            && fields[0] == segment
            && fields[2] == "->"
            && let (Some(start), Some(end)) = (parse_hex(fields[1]), parse_hex(fields[3]))
        {
            ranges.push(start..end);
        }
    }
    ranges
}

fn parse_hex(value: &str) -> Option<usize> {
    usize::from_str_radix(value.strip_prefix("0x")?, 16).ok()
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

    #[test]
    fn parses_cache_map_addresses() {
        let map = "mapping EX 1MB 0x180000000 -> 0x180100000\n\
                   /usr/lib/system/libsystem_kernel.dylib\n\
                   \t__TEXT 0x180010000 -> 0x180020000\n";
        assert_eq!(parse_first_mapping(map), Some(0x180000000));
        let ranges = parse_segment_ranges(map, LIBSYSTEM_KERNEL, "__TEXT");
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], 0x180010000..0x180020000);
        assert_eq!(
            parse_runtime_text_ranges(map),
            [(LIBSYSTEM_KERNEL.to_owned(), 0x180010000..0x180020000)]
        );
    }
}
