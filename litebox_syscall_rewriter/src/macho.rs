// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 Mach-O rewriting for LiteBox.
//!
//! SVC callbacks receive SP decremented by [`aarch64::DARWIN_SVC_FRAME_BYTES`],
//! with saved x16 (the syscall number) at `[SP]`. They must supply Darwin's x0/x1
//! results and NZCV carry, preserve other registers, and return through the
//! outbound stub with SP still pointing to the gate frame.
//!
//! Unmarked inline data matching syscall/TLS encodings may be rewritten.
//!
//! Gates always go in sub-trampolines, each a callback header followed by gates
//! that reference only that header. Ahead-of-time rewriting places them in the
//! image; see [`hook_syscalls_in_macho_with_options`]. Load-time
//! rewriting through [`Rewriter`] splits each call's gates the same way, over
//! spaces the caller reserves; see [`GatePlacement`].

use alloc::{string::ToString as _, vec, vec::Vec};
use core::ops::Range;
use object::read::macho::{MachHeader as _, Segment as _};
use object::{LittleEndian as LE, macho};
use zerocopy::IntoBytes as _;

use crate::{
    Error, LoadSegment, MACOS_TRAMPOLINE_PAGE_SIZE, Result, RewriteOptions, TargetHost,
    TextSectionInfo,
    aarch64::{self, INSN_BYTES_U64},
    aarch64_trampoline_regions, aarch64_trampoline_spaces, append_aarch64_trampolines,
    checked_add_u64, trampoline_placement_for, unpatchable_aarch64_sites,
};

const LOAD_COMMAND_ALIGNMENT: u32 = 8;

pub struct CodeMetadata {
    code: Vec<TextSectionInfo>,
    segments: Vec<LoadSegment>,
}

impl CodeMetadata {
    /// Expects a thin Mach-O slice.
    pub fn parse(image: &[u8]) -> Result<Self> {
        parse_image(image)?
            .ok_or_else(|| Error::UnsupportedExecutable("relocatable Mach-O object".into()))
    }

    /// `file_offset` is slice-relative; returned ranges are mapping-relative.
    pub fn ranges_for_mapping(
        &self,
        file_offset: u64,
        mapping_len: usize,
    ) -> Result<Vec<Range<usize>>> {
        let mut ranges = aarch64::project_file_ranges(&self.code, file_offset, mapping_len)?;
        ranges.sort_unstable_by_key(|range| range.start);
        Ok(ranges)
    }

    /// Upper bound for rewriting this image with `options`.
    pub fn trampoline_size_upper_bound(
        &self,
        image: &[u8],
        options: RewriteOptions,
    ) -> Result<usize> {
        aarch64::macho_trampoline_size_upper_bound(image, &self.code, options)
    }
}

/// Where and how [`Rewriter`] load-time rewriting places sub-trampolines.
#[derive(Clone, Copy, Debug)]
pub struct GatePlacement<'a> {
    /// Address ranges, in preference order, that may hold sub-trampolines.
    pub spaces: &'a [aarch64::TrampolineSpace],
    /// Alignment of every sub-trampoline; no two share a `granule`. A caller
    /// that maps and protects each space as a whole may pass
    /// [`aarch64::GATE_ALIGNMENT`] to pack them.
    pub granule: u64,
    /// Written into every sub-trampoline's callback header.
    pub callback: u64,
    /// Host TSD byte offset of the guest TLS-block pointer, finalized into
    /// every gate.
    pub guest_tp_offset: u16,
}

#[derive(Clone, Copy)]
pub struct Rewriter {
    host: TargetHost,
}

impl Rewriter {
    pub fn new(host: TargetHost) -> Result<Self> {
        Ok(Self { host })
    }

    /// Returns (finalized sub-trampolines, trapped PCs). Code is unchanged on
    /// error.
    ///
    /// Ranges are sorted, non-overlapping and relative to `code`. Gates are
    /// spread over sub-trampolines in `placement.spaces`, exactly like
    /// ahead-of-time rewriting; see [`aarch64::TrampolineSpace`]. Copy each
    /// returned sub-trampoline to reserved storage at its `vaddr` and
    /// synchronize instruction caches for code and gates before execution.
    pub fn patch_code_segment(
        self,
        code: &mut [u8],
        code_vaddr: u64,
        ranges: &[Range<usize>],
        placement: GatePlacement<'_>,
    ) -> Result<(Vec<aarch64::SubTrampoline>, Vec<u64>)> {
        self.patch_code_segment_with_options(
            code,
            code_vaddr,
            ranges,
            placement,
            RewriteOptions::new(self.host, false),
        )
    }

    /// Rewrite SVC sites while leaving TPIDRRO reads on the physical pthread.
    pub fn patch_native_guest_tpidrro_code(
        self,
        code: &mut [u8],
        code_vaddr: u64,
        ranges: &[Range<usize>],
        placement: GatePlacement<'_>,
    ) -> Result<(Vec<aarch64::SubTrampoline>, Vec<u64>)> {
        self.patch_code_segment_with_options(
            code,
            code_vaddr,
            ranges,
            placement,
            RewriteOptions::native_guest_thread_pointer(self.host),
        )
    }

    /// Rewrite SVC and TPIDRRO sites in live host shared-cache code.
    /// Host-aware TPIDRRO gates retain native host TLS outside guest execution.
    pub fn patch_host_shared_cache_code(
        self,
        code: &mut [u8],
        code_vaddr: u64,
        ranges: &[Range<usize>],
        placement: GatePlacement<'_>,
    ) -> Result<(Vec<aarch64::SubTrampoline>, Vec<u64>)> {
        self.patch_code_segment_with_options(
            code,
            code_vaddr,
            ranges,
            placement,
            RewriteOptions::host_aware_thread_pointer(self.host),
        )
    }

    fn patch_code_segment_with_options(
        self,
        code: &mut [u8],
        code_vaddr: u64,
        ranges: &[Range<usize>],
        placement: GatePlacement<'_>,
        options: RewriteOptions,
    ) -> Result<(Vec<aarch64::SubTrampoline>, Vec<u64>)> {
        checked_add_u64(code_vaddr, code.len() as u64, "Mach-O mapping end")?;
        if ranges.windows(2).any(|pair| pair[0].end > pair[1].start) {
            return Err(Error::ParseError(
                "overlapping or unsorted Mach-O code ranges".into(),
            ));
        }
        let sections = crate::scan_sections(code_vaddr, ranges, code.len())?;
        let mut patched = code.to_vec();
        let Some(mut outcome) = aarch64::hook_split_macho(
            &mut patched,
            &sections,
            placement.spaces,
            placement.granule,
            placement.callback,
            options,
        )?
        else {
            return Ok((Vec::new(), Vec::new()));
        };
        for sub in &mut outcome.trampolines {
            self.finalize_trampoline_gates(&mut sub.data, placement.guest_tp_offset)?;
        }
        code.copy_from_slice(&patched);
        Ok((outcome.trampolines, outcome.trapped_sites))
    }

    /// Allocation-failure fallback for [`Self::patch_code_segment`].
    /// Synchronize the instruction cache before execution.
    pub fn trap_code_segment(
        self,
        code: &mut [u8],
        code_vaddr: u64,
        ranges: &[Range<usize>],
    ) -> Result<usize> {
        checked_add_u64(code_vaddr, code.len() as u64, "Mach-O mapping end")?;
        if ranges.windows(2).any(|pair| pair[0].end > pair[1].start) {
            return Err(Error::ParseError(
                "overlapping or unsorted Mach-O code ranges".into(),
            ));
        }
        let sections = crate::scan_sections(code_vaddr, ranges, code.len())?;
        aarch64::trap_macho_patch_sites(code, &sections)
    }

    /// Leaves the trampoline unchanged on error.
    pub fn finalize_trampoline_gates(
        self,
        trampoline: &mut [u8],
        guest_tp_offset: u16,
    ) -> Result<()> {
        aarch64::finalize_macho_trampoline(trampoline, guest_tp_offset, self.host)
    }

    /// Recovery must verify the original site's branch. SVC frame recovery uses
    /// [`aarch64::DARWIN_SVC_FRAME_BYTES`].
    pub fn classify_gate_slot(
        self,
        slot: &[u8],
        slot_vaddr: u64,
        pc: u64,
    ) -> Option<aarch64::ClassifiedGate> {
        aarch64::classify_copied_gate_slot_with_layout(
            slot,
            slot_vaddr,
            pc,
            aarch64::GateLayout::darwin(self.host.into()),
        )
    }
}

/// AOT rewriting of a thin slice. `None` leaves the callback slot for the loader.
pub fn hook_syscalls_in_macho(input: &[u8], callback: Option<u64>) -> Result<Vec<u8>> {
    hook_syscalls_in_macho_with_options(
        input,
        callback,
        RewriteOptions::new(TargetHost::MacOs, false),
    )
}

/// Gates are split into independently mapped sub-trampolines, each a callback
/// header followed by gates, placed first in holes between the image's
/// segments (largest first) and then past its last segment; see
/// [`crate::parse_aarch64_trampoline_footer`] for the appended table and footer.
/// Every sub-trampoline is 16 KiB-aligned and starts on its own 16 KiB page.
///
/// The loader must map each sub-trampoline at its recorded address plus the
/// image slide, install the callback into its first 8 bytes, finalize its TLS
/// offsets, and synchronize instruction caches. Payloads are 4 KiB
/// file-aligned; copy them if larger alignment is required. Rewriting
/// invalidates code signatures.
pub fn hook_syscalls_in_macho_with_options(
    input: &[u8],
    callback: Option<u64>,
    options: RewriteOptions,
) -> Result<Vec<u8>> {
    let Some(metadata) = parse_image(input)? else {
        return Ok(input.to_vec());
    };
    Rewriter::new(options.target_host())?;
    // A malformed or unknown trailer is an error, not an image to rewrite again.
    if aarch64_trampoline_regions(input)?.is_some() {
        return Ok(input.to_vec());
    }
    let placement = trampoline_placement_for(
        &metadata.segments,
        object::elf::EM_AARCH64,
        MACOS_TRAMPOLINE_PAGE_SIZE,
    )?;
    let spaces =
        aarch64_trampoline_spaces(&metadata.segments, MACOS_TRAMPOLINE_PAGE_SIZE, placement)?;
    let mut out = input.to_vec();
    let Some(outcome) = aarch64::hook_split_macho(
        &mut out,
        &metadata.code,
        &spaces,
        MACOS_TRAMPOLINE_PAGE_SIZE,
        callback.unwrap_or(0),
        options,
    )?
    else {
        // No patch sites: `out` is still the original image; append an empty
        // table.
        append_aarch64_trampolines(&mut out, &[])?;
        return Ok(out);
    };
    if !outcome.trapped_sites.is_empty() {
        return Err(unpatchable_aarch64_sites(&outcome.trapped_sites));
    }
    append_aarch64_trampolines(&mut out, &outcome.trampolines)?;
    Ok(out)
}

fn parse_image(input: &[u8]) -> Result<Option<CodeMetadata>> {
    if input.get(..4) != Some(macho::MH_MAGIC_64.to_le_bytes().as_slice()) {
        return Err(Error::UnsupportedExecutable(
            "expected thin little-endian AArch64 Mach-O (extract universal slices first)".into(),
        ));
    }
    // The object parser requires aligned storage.
    let mut storage = vec![0u64; input.len().div_ceil(size_of::<u64>())];
    let bytes = storage.as_mut_bytes();
    bytes[..input.len()].copy_from_slice(input);
    let bytes = &mut bytes[..input.len()];
    let header = macho::MachHeader64::<LE>::parse(&*bytes, 0).map_err(parse_error)?;
    if header.cputype(LE) != macho::CPU_TYPE_ARM64
        || !matches!(
            header.cpusubtype(LE) & !macho::CPU_SUBTYPE_MASK,
            macho::CPU_SUBTYPE_ARM64_ALL | macho::CPU_SUBTYPE_ARM64_V8 | macho::CPU_SUBTYPE_ARM64E
        )
    {
        return Err(Error::UnsupportedExecutable(
            "Mach-O requires AArch64 or arm64e".into(),
        ));
    }
    if header.filetype(LE) == macho::MH_OBJECT {
        return Ok(None);
    }
    if !matches!(
        header.filetype(LE),
        macho::MH_EXECUTE | macho::MH_DYLIB | macho::MH_DYLINKER | macho::MH_BUNDLE
    ) || header.flags(LE) & macho::MH_DYLIB_IN_CACHE != 0
    {
        return Err(Error::UnsupportedExecutable(
            "unsupported Mach-O image".into(),
        ));
    }
    let (code, segments) = code_metadata(bytes)?;
    Ok(Some(CodeMetadata { code, segments }))
}

fn parse_error(error: object::Error) -> Error {
    Error::ParseError(error.to_string())
}

fn checked_range(offset: u64, size: u64, len: usize) -> Result<Range<usize>> {
    let end = checked_add_u64(offset, size, "Mach-O file range")?;
    if end > len as u64 {
        return Err(Error::ParseError("Mach-O range extends beyond file".into()));
    }
    Ok(
        usize::try_from(offset).map_err(|_| Error::ParseError("Mach-O offset".into()))?
            ..usize::try_from(end).map_err(|_| Error::ParseError("Mach-O end".into()))?,
    )
}

fn code_metadata(bytes: &[u8]) -> Result<(Vec<TextSectionInfo>, Vec<LoadSegment>)> {
    let header = macho::MachHeader64::<LE>::parse(bytes, 0).map_err(parse_error)?;
    let mut commands = header.load_commands(LE, bytes, 0).map_err(parse_error)?;
    let mut command_bytes = 0u64;
    let commands_end =
        size_of::<macho::MachHeader64<LE>>() as u64 + u64::from(header.sizeofcmds(LE));
    let mut sections = Vec::new();
    let mut segments: Vec<LoadSegment> = Vec::new();
    let mut data_ranges = Vec::new();
    let mut file_ranges: Vec<Range<usize>> = Vec::new();
    while let Some(command) = commands.next().map_err(parse_error)? {
        if !command.cmdsize().is_multiple_of(LOAD_COMMAND_ALIGNMENT) {
            return Err(Error::ParseError("unaligned Mach-O load command".into()));
        }
        command_bytes += u64::from(command.cmdsize());
        if command.cmd() == macho::LC_ENCRYPTION_INFO_64 {
            let info = command
                .data::<macho::EncryptionInfoCommand64<LE>>()
                .map_err(parse_error)?;
            if info.cryptid.get(LE) != 0 {
                return Err(Error::UnsupportedExecutable("encrypted Mach-O".into()));
            }
        }
        if command.cmd() == macho::LC_SEGMENT {
            return Err(Error::UnsupportedExecutable(
                "32-bit segment in Mach-O64".into(),
            ));
        }
        if command.cmd() == macho::LC_ENCRYPTION_INFO {
            return Err(Error::UnsupportedExecutable(
                "32-bit Mach-O encryption command".into(),
            ));
        }
        if command.cmd() == macho::LC_DATA_IN_CODE {
            const ENTRY_BYTES: usize = size_of::<macho::DataInCodeEntry<LE>>();
            const LENGTH_OFFSET: usize = core::mem::offset_of!(macho::DataInCodeEntry<LE>, length);
            let info = command
                .data::<macho::LinkeditDataCommand<LE>>()
                .map_err(parse_error)?;
            let range = checked_range(
                u64::from(info.dataoff.get(LE)),
                u64::from(info.datasize.get(LE)),
                bytes.len(),
            )?;
            if !range.len().is_multiple_of(ENTRY_BYTES) {
                return Err(Error::ParseError(
                    "partial Mach-O data-in-code entry".into(),
                ));
            }
            for entry in bytes[range].as_chunks::<ENTRY_BYTES>().0 {
                let start = u64::from(u32::from_le_bytes(
                    entry[..size_of::<u32>()].try_into().unwrap(),
                ));
                let size = u64::from(u16::from_le_bytes(
                    entry[LENGTH_OFFSET..][..size_of::<u16>()]
                        .try_into()
                        .unwrap(),
                ));
                checked_range(start, size, bytes.len())?;
                if size != 0 {
                    data_ranges.push(
                        (start & !(INSN_BYTES_U64 - 1))
                            ..(start + size).next_multiple_of(INSN_BYTES_U64),
                    );
                }
            }
        }
        let Some((segment, section_data)) = command.segment_64().map_err(parse_error)? else {
            continue;
        };
        let vaddr = segment.vmaddr(LE);
        let memsz = segment.vmsize(LE);
        let offset = segment.fileoff(LE);
        let filesz = segment.filesize(LE);
        let end = checked_add_u64(vaddr, memsz, "Mach-O segment")?;
        let file_range = checked_range(offset, filesz, bytes.len())?;
        if filesz > memsz {
            return Err(Error::ParseError(
                "Mach-O segment file size exceeds VM size".into(),
            ));
        }
        if memsz != 0 {
            for previous in &segments {
                if vaddr < previous.vaddr + previous.memsz && previous.vaddr < end {
                    return Err(Error::ParseError("overlapping Mach-O VM segments".into()));
                }
            }
            segments.push(LoadSegment {
                vaddr,
                memsz,
                filesz,
                align: MACOS_TRAMPOLINE_PAGE_SIZE,
            });
        }
        if filesz != 0 {
            if file_ranges
                .iter()
                .any(|r| r.start < file_range.end && file_range.start < r.end)
            {
                return Err(Error::ParseError("overlapping Mach-O file segments".into()));
            }
            file_ranges.push(file_range);
        }
        for section in segment.sections(LE, section_data).map_err(parse_error)? {
            let flags = section.flags.get(LE);
            if flags & (macho::S_ATTR_PURE_INSTRUCTIONS | macho::S_ATTR_SOME_INSTRUCTIONS) == 0 {
                continue;
            }
            if segment.initprot.get(LE) & macho::VM_PROT_EXECUTE == 0
                || !matches!(
                    flags & macho::SECTION_TYPE,
                    macho::S_REGULAR | macho::S_SYMBOL_STUBS
                )
                || section.nreloc.get(LE) != 0
            {
                return Err(Error::UnsupportedExecutable(
                    "unsupported Mach-O code section".into(),
                ));
            }
            let address = section.addr.get(LE);
            let section_offset = u64::from(section.offset.get(LE));
            let size = section.size.get(LE);
            let section_end = checked_add_u64(address, size, "Mach-O section")?;
            let range = checked_range(section_offset, size, bytes.len())?;
            if address < vaddr
                || section_end > end
                || section_offset < offset
                || range.end as u64 > offset + filesz
                || address - vaddr != section_offset - offset
                || (size != 0 && section_offset < commands_end)
                || !address.is_multiple_of(INSN_BYTES_U64)
                || !section_offset.is_multiple_of(INSN_BYTES_U64)
                || !size.is_multiple_of(INSN_BYTES_U64)
            {
                return Err(Error::ParseError(
                    "invalid Mach-O code section mapping".into(),
                ));
            }
            if size != 0 {
                sections.push(TextSectionInfo {
                    vaddr: address,
                    file_offset: section_offset,
                    size,
                });
            }
        }
    }
    if command_bytes != u64::from(header.sizeofcmds(LE)) {
        return Err(Error::ParseError(
            "Mach-O load command count/size mismatch".into(),
        ));
    }
    sections.sort_unstable_by_key(|s| s.vaddr);
    for pair in sections.windows(2) {
        if pair[0].vaddr + pair[0].size > pair[1].vaddr {
            return Err(Error::ParseError("overlapping Mach-O code sections".into()));
        }
    }
    data_ranges.sort_unstable_by_key(|r| r.start);
    for range in &data_ranges {
        if !sections
            .iter()
            .any(|s| range.start >= s.file_offset && range.end <= s.file_offset + s.size)
        {
            return Err(Error::ParseError(
                "Mach-O data-in-code outside code section".into(),
            ));
        }
    }
    let mut code = Vec::new();
    for section in sections {
        let mut cursor = section.file_offset;
        let end = cursor + section.size;
        for range in &data_ranges {
            if range.end <= cursor || range.start >= end {
                continue;
            }
            if range.start > cursor {
                code.push(TextSectionInfo {
                    vaddr: section.vaddr + (cursor - section.file_offset),
                    file_offset: cursor,
                    size: range.start - cursor,
                });
            }
            cursor = cursor.max(range.end);
        }
        if cursor < end {
            code.push(TextSectionInfo {
                vaddr: section.vaddr + (cursor - section.file_offset),
                file_offset: cursor,
                size: end - cursor,
            });
        }
    }
    Ok((code, segments))
}
