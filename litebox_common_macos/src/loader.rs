// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Validated AArch64 Mach-O load plans and universal-binary selection.
//!
//! Requires static executables with `LC_UNIXTHREAD`; dynamic linking and
//! relocations are unsupported. Images slide as a unit, so guest code must
//! be position independent.

use crate::{PAGE_SIZE, VmProtection};
use alloc::{vec, vec::Vec};
use core::ops::Range;
use litebox::utils::ReinterpretSignedExt as _;
use object::{
    BigEndian as BE, LittleEndian as LE, macho,
    read::macho::{MachHeader as _, Segment as _},
};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout,
    byteorder::{LittleEndian, U32, U64},
};

const TRAMPOLINE_FILE_ALIGNMENT: usize = 4096;
pub const MACH_HEADER_SIZE: usize = size_of::<macho::MachHeader64<LE>>();
const ARM_THREAD_STATE64: u32 = 6;
const LOAD_COMMAND_ALIGNMENT: usize = size_of::<u64>();

/// Mach ARM_THREAD_STATE64 payload.
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
struct Aarch64ThreadState64 {
    x: [U64<LittleEndian>; 29],
    fp: U64<LittleEndian>,
    lr: U64<LittleEndian>,
    sp: U64<LittleEndian>,
    pc: U64<LittleEndian>,
    cpsr: U32<LittleEndian>,
    pad: U32<LittleEndian>,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
struct UnixThreadCommand64 {
    cmd: U32<LittleEndian>,
    cmdsize: U32<LittleEndian>,
    flavor: U32<LittleEndian>,
    count: U32<LittleEndian>,
    state: Aarch64ThreadState64,
}

/// Shared admission limit for runner reads, shim snapshots and parsed virtual spans.
pub const MAX_IMAGE_SIZE: usize = 256 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum MachoLoaderError {
    #[error("Mach-O file operation failed: {0}")]
    File(#[from] crate::errno::Errno),
    #[error("malformed Mach-O: {0}")]
    Invalid(&'static str),
    #[error("unsupported Mach-O: {0}")]
    Unsupported(&'static str),
    #[error("guest memory allocation or protection failed")]
    Memory,
    #[error("arguments exceed the guest stack")]
    ArgumentsTooLarge,
    #[error("invalid or incompatible Mach-O trampoline")]
    Rewrite,
    #[error("Mach-O is not rewritten; run litebox_syscall_rewriter first")]
    Unrewritten,
}

#[derive(Debug)]
pub struct Segment {
    pub virtual_range: Range<usize>,
    pub file_range: Range<usize>,
    pub protection: VmProtection,
}

#[derive(Debug)]
pub struct MachoParsedFile {
    pub segments: Vec<Segment>,
    pub virtual_range: Range<usize>,
    pub entry: usize,
    /// The image requests the system dynamic linker.
    pub uses_dyld: bool,
    /// The image itself is dyld (`MH_DYLINKER`).
    pub is_dyld: bool,
}

/// One AOT sub-trampoline described by the rewriter's table: a callback header
/// followed by gates, mapped and finalized independently of the others.
#[derive(Debug)]
pub struct TrampolineInfo {
    pub file_range: Range<usize>,
    /// Page-aligned pages the sub-trampoline occupies, unslid.
    pub virtual_range: Range<usize>,
}

/// Returns whether `data` starts with a thin, little-endian AArch64 Mach-O header.
pub fn is_thin_arm64_macho_header(data: &[u8]) -> bool {
    let Some(header_bytes) = data.get(..MACH_HEADER_SIZE) else {
        return false;
    };
    let mut storage = [0u64; MACH_HEADER_SIZE.div_ceil(size_of::<u64>())];
    storage.as_mut_bytes()[..MACH_HEADER_SIZE].copy_from_slice(header_bytes);
    let Ok(header) = macho::MachHeader64::<LE>::parse(&storage.as_bytes()[..MACH_HEADER_SIZE], 0)
    else {
        return false;
    };
    header.is_little_endian()
        && header.cputype(LE) == macho::CPU_TYPE_ARM64
        && matches!(
            header.cpusubtype(LE) & !macho::CPU_SUBTYPE_MASK,
            macho::CPU_SUBTYPE_ARM64_ALL | macho::CPU_SUBTYPE_ARM64_V8 | macho::CPU_SUBTYPE_ARM64E
        )
}

/// Cheaply classify a header that may contain a supported Mach-O image.
/// Universal-container architecture selection still requires the complete file.
pub fn may_contain_arm64_macho(data: &[u8]) -> bool {
    is_thin_arm64_macho_header(data)
        || data.get(..size_of::<u32>()).is_some_and(|magic| {
            magic == macho::FAT_MAGIC.to_be_bytes() || magic == macho::FAT_MAGIC_64.to_be_bytes()
        })
}

impl MachoParsedFile {
    /// Validate the rewriter's AOT sub-trampoline table (see
    /// [`litebox_syscall_rewriter::parse_aarch64_trampoline_footer`]) and
    /// include every sub-trampoline in the image reservation so code and gates
    /// receive the same slide. Sub-trampolines occupy pages disjoint from the
    /// segments; the table's 4 KiB page rule keeps 16 KiB-aligned regions off
    /// each other's pages. An empty list means the rewriter
    /// processed an image with no patch sites.
    pub fn parse_trampoline(
        &mut self,
        data: &[u8],
    ) -> Result<Vec<TrampolineInfo>, MachoLoaderError> {
        use litebox_syscall_rewriter::{
            AARCH64_TRAMPOLINE_FOOTER_BYTES, parse_aarch64_trampoline_footer,
            parse_aarch64_trampoline_table,
        };
        let footer = data
            .last_chunk::<AARCH64_TRAMPOLINE_FOOTER_BYTES>()
            .ok_or(MachoLoaderError::Unrewritten)?;
        let location = parse_aarch64_trampoline_footer(footer, data.len() as u64)
            .map_err(|_| MachoLoaderError::Rewrite)?
            .ok_or(MachoLoaderError::Unrewritten)?;
        // The footer check bounds the table to the file.
        let table_start =
            usize::try_from(location.file_offset).map_err(|_| MachoLoaderError::Rewrite)?;
        let regions =
            parse_aarch64_trampoline_table(&data[table_start..][..location.len], location)
                .map_err(|_| MachoLoaderError::Rewrite)?;
        if self.segments.iter().any(|s| s.file_range.end > table_start) {
            return Err(MachoLoaderError::Rewrite);
        }
        let mut trampolines = Vec::with_capacity(regions.len());
        let mut span = self.virtual_range.clone();
        for region in regions {
            let usize_of =
                |value: u64| usize::try_from(value).map_err(|_| MachoLoaderError::Rewrite);
            let file_offset = usize_of(region.file_offset)?;
            let address = usize_of(region.vaddr)?;
            let size = usize_of(region.size)?;
            let end = address
                .checked_add(size)
                .and_then(|end| end.checked_next_multiple_of(PAGE_SIZE))
                .ok_or(MachoLoaderError::Rewrite)?;
            if !file_offset.is_multiple_of(TRAMPOLINE_FILE_ALIGNMENT)
                || !address.is_multiple_of(PAGE_SIZE)
                || size < litebox_syscall_rewriter::aarch64::GATE_ALIGNMENT
                || !size.is_multiple_of(size_of::<u32>())
                || self.segments.iter().any(|s| {
                    s.file_range.end > file_offset
                        || (address < s.virtual_range.end && s.virtual_range.start < end)
                })
            {
                return Err(MachoLoaderError::Rewrite);
            }
            span = span.start.min(address)..span.end.max(end);
            trampolines.push(TrampolineInfo {
                file_range: file_offset..file_offset + size,
                virtual_range: address..end,
            });
        }
        if span.len() > MAX_IMAGE_SIZE {
            return Err(MachoLoaderError::Rewrite);
        }
        self.virtual_range = span;
        Ok(trampolines)
    }

    pub fn parse(data: &[u8]) -> Result<Self, MachoLoaderError> {
        use MachoLoaderError::{Invalid, Unsupported};
        // Reject oversized input before allocating any aligned storage.
        if data.len() > MAX_IMAGE_SIZE {
            return Err(Unsupported("file larger than 256 MiB"));
        }
        // object requires aligned storage. Only the header and load commands
        // need it; segment contents and the AOT payload need not be copied.
        let mut header_storage = [0u64; MACH_HEADER_SIZE.div_ceil(size_of::<u64>())];
        let header_bytes = data.get(..MACH_HEADER_SIZE).ok_or(Invalid("header"))?;
        header_storage.as_mut_bytes()[..MACH_HEADER_SIZE].copy_from_slice(header_bytes);
        let header =
            macho::MachHeader64::<LE>::parse(&header_storage.as_bytes()[..MACH_HEADER_SIZE], 0)
                .map_err(|_| Invalid("header"))?;
        if !header.is_little_endian()
            || header.cputype(LE) != macho::CPU_TYPE_ARM64
            || !matches!(
                header.cpusubtype(LE) & !macho::CPU_SUBTYPE_MASK,
                macho::CPU_SUBTYPE_ARM64_ALL
                    | macho::CPU_SUBTYPE_ARM64_V8
                    | macho::CPU_SUBTYPE_ARM64E
            )
            || !matches!(header.filetype(LE), macho::MH_EXECUTE | macho::MH_DYLINKER)
        {
            return Err(Unsupported(
                "unexpected file type or architecture (requires arm64/arm64e executable or dyld)",
            ));
        }
        if header.flags(LE) & macho::MH_DYLIB_IN_CACHE != 0 {
            return Err(Unsupported("shared-cache image"));
        }
        let is_dyld = header.filetype(LE) == macho::MH_DYLINKER;
        let mut uses_dyld = false;
        let metadata_len = MACH_HEADER_SIZE
            .checked_add(
                usize::try_from(header.sizeofcmds(LE)).map_err(|_| Invalid("load commands"))?,
            )
            .ok_or(Invalid("load commands"))?;
        let metadata = data.get(..metadata_len).ok_or(Invalid("load commands"))?;
        let mut aligned = vec![0u64; metadata_len.div_ceil(size_of::<u64>())];
        aligned.as_mut_bytes()[..metadata_len].copy_from_slice(metadata);
        let mut commands = header
            .load_commands(LE, &aligned.as_bytes()[..metadata_len], 0)
            .map_err(|_| Invalid("load commands"))?;
        let mut segments = Vec::new();
        let mut entry = None;
        let mut main_entry_file_offset = None;
        let mut command_bytes = 0usize;
        while let Some(command) = commands.next().map_err(|_| Invalid("load command"))? {
            let raw = command.raw_data();
            if raw.len() < size_of::<macho::LoadCommand<LE>>()
                || !raw.len().is_multiple_of(LOAD_COMMAND_ALIGNMENT)
            {
                return Err(Invalid("load command alignment"));
            }
            command_bytes = command_bytes
                .checked_add(raw.len())
                .ok_or(Invalid("load commands"))?;
            match command.cmd() {
                macho::LC_LOAD_DYLINKER => uses_dyld = true,
                macho::LC_MAIN => {
                    let command = command
                        .entry_point()
                        .map_err(|_| Invalid("LC_MAIN"))?
                        .ok_or(Invalid("LC_MAIN"))?;
                    if main_entry_file_offset
                        .replace(
                            usize::try_from(command.entryoff.get(LE))
                                .map_err(|_| Invalid("LC_MAIN entry offset"))?,
                        )
                        .is_some()
                    {
                        return Err(Invalid("multiple entry points"));
                    }
                }
                macho::LC_UNIXTHREAD => {
                    let thread = UnixThreadCommand64::read_from_bytes(command.raw_data())
                        .map_err(|_| Invalid("AArch64 thread state"))?;
                    let state_words = size_of::<Aarch64ThreadState64>() / size_of::<u32>();
                    if thread.flavor.get() != ARM_THREAD_STATE64
                        || usize::try_from(thread.count.get()).ok() != Some(state_words)
                        || entry.is_some()
                    {
                        return Err(Invalid("AArch64 thread state"));
                    }
                    entry = Some(
                        usize::try_from(thread.state.pc.get())
                            .map_err(|_| Invalid("entry address overflow"))?,
                    );
                }
                macho::LC_SEGMENT_64 => {
                    let (seg, sections) = command
                        .segment_64()
                        .map_err(|_| Invalid("segment"))?
                        .ok_or(Invalid("segment"))?;
                    if seg.segname == *b"__PAGEZERO\0\0\0\0\0\0" {
                        if seg.filesize.get(LE) != 0 || seg.initprot.get(LE) != 0 {
                            return Err(Invalid("PAGEZERO"));
                        }
                        continue;
                    }
                    for section in seg
                        .sections(LE, sections)
                        .map_err(|_| Invalid("sections"))?
                    {
                        if section.nreloc.get(LE) != 0 {
                            return Err(Unsupported("section relocations"));
                        }
                    }
                    let start =
                        usize::try_from(seg.vmaddr.get(LE)).map_err(|_| Invalid("vmaddr"))?;
                    let size =
                        usize::try_from(seg.vmsize.get(LE)).map_err(|_| Invalid("vmsize"))?;
                    let offset =
                        usize::try_from(seg.fileoff.get(LE)).map_err(|_| Invalid("fileoff"))?;
                    let file_size =
                        usize::try_from(seg.filesize.get(LE)).map_err(|_| Invalid("filesize"))?;
                    let end = start
                        .checked_add(size)
                        .ok_or(Invalid("virtual range overflow"))?;
                    let file_end = offset
                        .checked_add(file_size)
                        .ok_or(Invalid("file range overflow"))?;
                    let protection =
                        VmProtection::from_bits(seg.initprot.get(LE).reinterpret_as_signed())
                            .ok_or(Invalid("segment protection"))?;
                    if file_size > size
                        || file_end > data.len()
                        || !start.is_multiple_of(PAGE_SIZE)
                        || !size.is_multiple_of(PAGE_SIZE)
                    {
                        return Err(Invalid("segment bounds/alignment"));
                    }
                    if protection.contains(VmProtection::WRITE | VmProtection::EXECUTE) {
                        return Err(Unsupported("writable executable segment"));
                    }
                    if size != 0 {
                        segments.push(Segment {
                            virtual_range: start..end,
                            file_range: offset..file_end,
                            protection,
                        });
                    }
                }
                _ => {}
            }
        }
        if command_bytes != metadata_len - MACH_HEADER_SIZE {
            return Err(Invalid("load command count/size mismatch"));
        }
        segments.sort_unstable_by_key(|s| s.virtual_range.start);
        if segments
            .windows(2)
            .any(|s| s[0].virtual_range.end > s[1].virtual_range.start)
        {
            return Err(Invalid("overlapping segments"));
        }
        let start = segments
            .first()
            .ok_or(Invalid("no segments"))?
            .virtual_range
            .start;
        let end = segments
            .last()
            .ok_or(Invalid("no segments"))?
            .virtual_range
            .end;
        // Bound allocations driven by untrusted headers in this minimal loader.
        if end - start > MAX_IMAGE_SIZE {
            return Err(Unsupported("image larger than 256 MiB"));
        }
        if entry.is_some() && main_entry_file_offset.is_some() {
            return Err(Invalid("multiple entry point forms"));
        }
        let entry = if let Some(file_offset) = main_entry_file_offset {
            segments
                .iter()
                .find(|segment| {
                    segment.protection.contains(VmProtection::EXECUTE)
                        && segment.file_range.contains(&file_offset)
                })
                .and_then(|segment| {
                    segment
                        .virtual_range
                        .start
                        .checked_add(file_offset - segment.file_range.start)
                })
                .ok_or(Invalid("LC_MAIN entry outside executable segment"))?
        } else {
            entry.ok_or(Unsupported("missing or invalid entry point"))?
        };
        if !entry.is_multiple_of(size_of::<u32>())
            || !segments.iter().any(|s| {
                s.protection.contains(VmProtection::EXECUTE)
                    && (s.virtual_range.start..s.virtual_range.start + s.file_range.len())
                        .contains(&entry)
            })
        {
            return Err(Invalid("entry outside file-backed executable segment"));
        }
        if (is_dyld && uses_dyld)
            || (main_entry_file_offset.is_some() && !uses_dyld)
            || (!is_dyld && header.flags(LE) & macho::MH_DYLDLINK != 0 && !uses_dyld)
        {
            return Err(Invalid("inconsistent dynamic-linker commands"));
        }
        Ok(Self {
            segments,
            virtual_range: start..end,
            entry,
            uses_dyld,
            is_dyld,
        })
    }
}

/// Return the container-relative range of the selected arm64 or arm64e slice.
pub fn arm64_slice_range(data: &[u8]) -> Result<Range<usize>, MachoLoaderError> {
    let slice = arm64_slice(data)?;
    let offset = slice.as_ptr().addr() - data.as_ptr().addr();
    Ok(offset..offset + slice.len())
}

/// Select an arm64 or arm64e slice, or return thin input unchanged.
pub fn arm64_slice(data: &[u8]) -> Result<&[u8], MachoLoaderError> {
    use MachoLoaderError::{Invalid, Unsupported};
    const HEADER_SIZE: usize = size_of::<macho::FatHeader>();
    if data.len() > MAX_IMAGE_SIZE {
        return Err(Unsupported("file larger than 256 MiB"));
    }
    let magic = data.get(..size_of::<u32>()).ok_or(Invalid("header"))?;
    let wide = if magic == macho::FAT_MAGIC.to_be_bytes() {
        false
    } else if magic == macho::FAT_MAGIC_64.to_be_bytes() {
        true
    } else {
        return Ok(data);
    };
    // object requires aligned storage. Copy only the validated header/table,
    // not the images, so caller alignment and container size do not drive copies.
    let mut header_storage = [0u64; HEADER_SIZE.div_ceil(size_of::<u64>())];
    header_storage.as_mut_bytes()[..HEADER_SIZE]
        .copy_from_slice(data.get(..HEADER_SIZE).ok_or(Invalid("fat header"))?);
    let (header, _) = object::pod::from_bytes::<macho::FatHeader>(header_storage.as_bytes())
        .map_err(|()| Invalid("fat header"))?;
    let count = usize::try_from(header.nfat_arch.get(BE)).map_err(|_| Invalid("fat table"))?;
    let stride = if wide {
        size_of::<macho::FatArch64>()
    } else {
        size_of::<macho::FatArch32>()
    };
    let table_end = count
        .checked_mul(stride)
        .and_then(|n| n.checked_add(HEADER_SIZE))
        .ok_or(Invalid("fat table"))?;
    let metadata = data.get(..table_end).ok_or(Invalid("fat table"))?;
    let mut aligned = vec![0u64; table_end.div_ceil(size_of::<u64>())];
    aligned.as_mut_bytes()[..table_end].copy_from_slice(metadata);
    let metadata = &aligned.as_bytes()[..table_end];
    if wide {
        let fat = object::read::macho::MachOFatFile64::parse(metadata)
            .map_err(|_| Invalid("fat table"))?;
        if fat.arches().iter().any(|arch| arch.reserved.get(BE) != 0) {
            return Err(Invalid("fat reserved field"));
        }
        select_arm64(data, fat.arches(), table_end)
    } else {
        let fat = object::read::macho::MachOFatFile32::parse(metadata)
            .map_err(|_| Invalid("fat table"))?;
        select_arm64(data, fat.arches(), table_end)
    }
}

fn select_arm64<'a, A: object::read::macho::FatArch>(
    data: &'a [u8],
    arches: &[A],
    table_end: usize,
) -> Result<&'a [u8], MachoLoaderError> {
    use MachoLoaderError::{Invalid, Unsupported};
    let mut arm64 = None;
    let mut arm64e = None;
    let mut ambiguous_arm64 = false;
    let mut ambiguous_arm64e = false;
    for arch in arches {
        let offset = usize::try_from(arch.offset().into()).map_err(|_| Invalid("fat offset"))?;
        let size = usize::try_from(arch.size().into()).map_err(|_| Invalid("fat size"))?;
        let end = offset.checked_add(size).ok_or(Invalid("fat range"))?;
        let align = 1usize
            .checked_shl(arch.align())
            .ok_or(Invalid("fat alignment"))?;
        if offset < table_end || size == 0 || !offset.is_multiple_of(align) || end > data.len() {
            return Err(Invalid("fat slice bounds/alignment"));
        }
        if arch.cputype() != macho::CPU_TYPE_ARM64 {
            continue;
        }
        let slice = &data[offset..end];
        match arch.cpusubtype() & !macho::CPU_SUBTYPE_MASK {
            macho::CPU_SUBTYPE_ARM64_ALL | macho::CPU_SUBTYPE_ARM64_V8 => {
                ambiguous_arm64 |= arm64.replace(slice).is_some();
            }
            macho::CPU_SUBTYPE_ARM64E => {
                ambiguous_arm64e |= arm64e.replace(slice).is_some();
            }
            _ => {}
        }
    }
    if ambiguous_arm64 || (arm64.is_none() && ambiguous_arm64e) {
        return Err(Invalid("ambiguous arm64 slices"));
    }
    arm64
        .or(arm64e)
        .ok_or(Unsupported("universal binary has no supported arm64 slice"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;
    use litebox::utils::ReinterpretUnsignedExt as _;
    type Header = macho::MachHeader64<LE>;
    type SegmentCommand = macho::SegmentCommand64<LE>;
    const SEGMENT_START: usize = size_of::<Header>();
    const THREAD_START: usize = SEGMENT_START + size_of::<SegmentCommand>();
    const METADATA_END: usize = THREAD_START + size_of::<UnixThreadCommand64>();
    const FILETYPE: usize = offset_of!(Header, filetype);
    const COMMAND_COUNT: usize = offset_of!(Header, ncmds);
    const COMMAND_BYTES: usize = offset_of!(Header, sizeofcmds);
    const VMADDR: usize = SEGMENT_START + offset_of!(SegmentCommand, vmaddr);
    const VMSIZE: usize = SEGMENT_START + offset_of!(SegmentCommand, vmsize);
    const FILEOFF: usize = SEGMENT_START + offset_of!(SegmentCommand, fileoff);
    const FILESIZE: usize = SEGMENT_START + offset_of!(SegmentCommand, filesize);
    const PROTECTION: usize = SEGMENT_START + offset_of!(SegmentCommand, initprot);
    const THREAD_SIZE: usize = THREAD_START + offset_of!(UnixThreadCommand64, cmdsize);
    const THREAD_FLAVOR: usize = THREAD_START + offset_of!(UnixThreadCommand64, flavor);
    const THREAD_COUNT: usize = THREAD_START + offset_of!(UnixThreadCommand64, count);
    const THREAD_PC: usize = THREAD_START
        + offset_of!(UnixThreadCommand64, state)
        + offset_of!(Aarch64ThreadState64, pc);
    const STATE_WORDS: usize = size_of::<Aarch64ThreadState64>() / size_of::<u32>();
    const IMAGE_BASE: u64 = 0x1_0000_0000;
    const ENTRY: u64 = IMAGE_BASE + (PAGE_SIZE / 2) as u64;

    fn put32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
    }
    // A small synthetic image makes range validation testable on any host.
    fn image() -> Vec<u8> {
        let mut data = vec![0; PAGE_SIZE];
        for (offset, value) in [
            (offset_of!(Header, magic), macho::MH_MAGIC_64),
            (offset_of!(Header, cputype), macho::CPU_TYPE_ARM64),
            (FILETYPE, macho::MH_EXECUTE),
            (COMMAND_COUNT, 2), // one segment and one thread command
            (
                COMMAND_BYTES,
                u32::try_from(METADATA_END - SEGMENT_START).unwrap(),
            ),
            (
                SEGMENT_START + offset_of!(SegmentCommand, cmd),
                macho::LC_SEGMENT_64,
            ),
            (
                SEGMENT_START + offset_of!(SegmentCommand, cmdsize),
                u32::try_from(size_of::<SegmentCommand>()).unwrap(),
            ),
            (
                PROTECTION,
                (VmProtection::READ | VmProtection::EXECUTE)
                    .bits()
                    .reinterpret_as_unsigned(),
            ),
            (
                THREAD_START + offset_of!(UnixThreadCommand64, cmd),
                macho::LC_UNIXTHREAD,
            ),
            (
                THREAD_SIZE,
                u32::try_from(size_of::<UnixThreadCommand64>()).unwrap(),
            ),
            (THREAD_FLAVOR, ARM_THREAD_STATE64),
            (THREAD_COUNT, u32::try_from(STATE_WORDS).unwrap()),
        ] {
            put32(&mut data, offset, value);
        }
        for (offset, value) in [
            (VMADDR, IMAGE_BASE),
            (VMSIZE, PAGE_SIZE as u64),
            (FILESIZE, PAGE_SIZE as u64),
            (THREAD_PC, ENTRY),
        ] {
            data[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
        }
        data
    }

    fn image_with_subtype(subtype: u32) -> Vec<u8> {
        let mut data = image();
        put32(&mut data, offset_of!(Header, cpusubtype), subtype);
        data
    }

    fn fat32(subtypes: &[u32]) -> Vec<u8> {
        use object::{endian::U32, pod::bytes_of};

        let header = macho::FatHeader {
            magic: U32::new(BE, macho::FAT_MAGIC),
            nfat_arch: U32::new(BE, u32::try_from(subtypes.len()).unwrap()),
        };
        let mut fat = bytes_of(&header).to_vec();
        for (index, subtype) in subtypes.iter().copied().enumerate() {
            let offset = (index + 1) * PAGE_SIZE;
            let arch = macho::FatArch32 {
                cputype: U32::new(BE, macho::CPU_TYPE_ARM64),
                cpusubtype: U32::new(BE, subtype),
                offset: U32::new(BE, u32::try_from(offset).unwrap()),
                size: U32::new(BE, u32::try_from(PAGE_SIZE).unwrap()),
                align: U32::new(BE, PAGE_SIZE.ilog2()),
            };
            fat.extend_from_slice(bytes_of(&arch));
        }
        for subtype in subtypes {
            fat.resize(fat.len().next_multiple_of(PAGE_SIZE), 0);
            fat.extend_from_slice(&image_with_subtype(*subtype));
        }
        fat
    }

    #[test]
    fn mixed_arm64_fat_binaries_prefer_plain_arm64() {
        for subtypes in [
            [macho::CPU_SUBTYPE_ARM64E, macho::CPU_SUBTYPE_ARM64_ALL],
            [macho::CPU_SUBTYPE_ARM64_V8, macho::CPU_SUBTYPE_ARM64E],
        ] {
            let fat = fat32(&subtypes);
            let plain_index = subtypes
                .iter()
                .position(|subtype| *subtype != macho::CPU_SUBTYPE_ARM64E)
                .unwrap();
            let start = (plain_index + 1) * PAGE_SIZE;
            assert_eq!(arm64_slice_range(&fat).unwrap(), start..start + PAGE_SIZE);
        }

        assert!(matches!(
            arm64_slice(&fat32(&[
                macho::CPU_SUBTYPE_ARM64_ALL,
                macho::CPU_SUBTYPE_ARM64_V8,
            ])),
            Err(MachoLoaderError::Invalid("ambiguous arm64 slices"))
        ));
        assert!(matches!(
            arm64_slice(&fat32(&[
                macho::CPU_SUBTYPE_ARM64E,
                macho::CPU_SUBTYPE_ARM64E,
            ])),
            Err(MachoLoaderError::Invalid("ambiguous arm64 slices"))
        ));
    }

    #[test]
    fn universal_slices_are_bounded_and_architecture_specific() {
        use object::{
            endian::{U32, U64},
            pod::bytes_of,
        };
        const HEADER_SIZE: usize = size_of::<macho::FatHeader>();
        const COUNT: usize = offset_of!(macho::FatHeader, nfat_arch);
        let thin = image();
        assert_eq!(arm64_slice(&thin).unwrap(), thin);
        for wide in [false, true] {
            let header = macho::FatHeader {
                magic: U32::new(
                    BE,
                    if wide {
                        macho::FAT_MAGIC_64
                    } else {
                        macho::FAT_MAGIC
                    },
                ),
                nfat_arch: U32::new(BE, 1),
            };
            let mut fat = bytes_of(&header).to_vec();
            let (subtype, offset_field, offset_size, alignment, stride) = if wide {
                let arch = macho::FatArch64 {
                    cputype: U32::new(BE, macho::CPU_TYPE_ARM64),
                    cpusubtype: U32::new(BE, macho::CPU_SUBTYPE_ARM64_ALL),
                    offset: U64::new(BE, PAGE_SIZE as u64),
                    size: U64::new(BE, thin.len() as u64),
                    align: U32::new(BE, PAGE_SIZE.ilog2()),
                    reserved: U32::new(BE, 0),
                };
                fat.extend_from_slice(bytes_of(&arch));
                (
                    offset_of!(macho::FatArch64, cpusubtype),
                    offset_of!(macho::FatArch64, offset),
                    size_of::<u64>(),
                    offset_of!(macho::FatArch64, align),
                    size_of::<macho::FatArch64>(),
                )
            } else {
                let arch = macho::FatArch32 {
                    cputype: U32::new(BE, macho::CPU_TYPE_ARM64),
                    cpusubtype: U32::new(BE, macho::CPU_SUBTYPE_ARM64_ALL),
                    offset: U32::new(BE, u32::try_from(PAGE_SIZE).unwrap()),
                    size: U32::new(BE, u32::try_from(thin.len()).unwrap()),
                    align: U32::new(BE, PAGE_SIZE.ilog2()),
                };
                fat.extend_from_slice(bytes_of(&arch));
                (
                    offset_of!(macho::FatArch32, cpusubtype),
                    offset_of!(macho::FatArch32, offset),
                    size_of::<u32>(),
                    offset_of!(macho::FatArch32, align),
                    size_of::<macho::FatArch32>(),
                )
            };
            fat.resize(PAGE_SIZE, 0);
            fat.extend_from_slice(&thin);
            assert_eq!(arm64_slice(&fat).unwrap(), thin);
            let mut unaligned = vec![0];
            unaligned.extend_from_slice(&fat);
            assert_eq!(arm64_slice(&unaligned[1..]).unwrap(), thin);
            for len in [
                size_of::<u32>(),
                HEADER_SIZE - 1,
                HEADER_SIZE + stride - 1,
                PAGE_SIZE,
                fat.len() - 1,
            ] {
                assert!(arm64_slice(&fat[..len]).is_err());
            }
            for (offset, value) in [
                (COUNT, u32::MAX), // table multiplication / bounds
                (HEADER_SIZE + subtype, u32::MAX),
                (HEADER_SIZE + offset_field, u32::MAX), // slice past EOF
                (HEADER_SIZE + alignment, usize::BITS), // alignment shift overflow
            ] {
                let mut bad = fat.clone();
                bad[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_be_bytes());
                assert!(arm64_slice(&bad).is_err(), "wide={wide}, field={offset}");
            }
            let mut bad = fat.clone();
            let start = HEADER_SIZE + offset_field;
            bad[start..start + offset_size].fill(0); // points into header
            assert!(arm64_slice(&bad).is_err());
            if wide {
                let mut bad = fat.clone();
                let reserved = HEADER_SIZE + offset_of!(macho::FatArch64, reserved);
                bad[reserved..reserved + size_of::<u32>()].copy_from_slice(&1u32.to_be_bytes());
                assert!(arm64_slice(&bad).is_err());
            }
            fat[COUNT..COUNT + size_of::<u32>()].copy_from_slice(&2u32.to_be_bytes());
            fat.copy_within(HEADER_SIZE..HEADER_SIZE + stride, HEADER_SIZE + stride);
            assert!(arm64_slice(&fat).is_err()); // ambiguous arm64 slices
        }
    }

    #[test]
    fn lc_main_requires_dyld() {
        type EntryPointCommand = macho::EntryPointCommand<LE>;

        let mut data = image();
        data[THREAD_START..METADATA_END].fill(0);
        put32(
            &mut data,
            COMMAND_BYTES,
            u32::try_from(size_of::<SegmentCommand>() + size_of::<EntryPointCommand>()).unwrap(),
        );
        put32(
            &mut data,
            THREAD_START + offset_of!(EntryPointCommand, cmd),
            macho::LC_MAIN,
        );
        put32(
            &mut data,
            THREAD_START + offset_of!(EntryPointCommand, cmdsize),
            u32::try_from(size_of::<EntryPointCommand>()).unwrap(),
        );
        let entry_offset = THREAD_START + offset_of!(EntryPointCommand, entryoff);
        data[entry_offset..entry_offset + size_of::<u64>()]
            .copy_from_slice(&(PAGE_SIZE as u64 / 2).to_le_bytes());

        assert!(matches!(
            MachoParsedFile::parse(&data),
            Err(MachoLoaderError::Invalid(
                "inconsistent dynamic-linker commands"
            ))
        ));
    }

    #[test]
    fn segment_and_entry_validation() {
        let data = image();
        let parsed = MachoParsedFile::parse(&data).unwrap();
        assert_eq!(parsed.entry, usize::try_from(ENTRY).unwrap());
        assert_eq!(parsed.virtual_range.len(), PAGE_SIZE);
        for (offset, value) in [
            (VMADDR, u64::MAX - (PAGE_SIZE - 1) as u64), // vmaddr + vmsize overflow
            (VMSIZE, 1),                                 // unaligned vmsize
            (VMSIZE, 0),                                 // filesize > vmsize
            (FILEOFF, u64::MAX),                         // fileoff + filesize overflow
            (FILESIZE, (PAGE_SIZE + 1) as u64),          // file data past EOF
            (THREAD_PC, 0),                              // entry outside executable memory
            (THREAD_PC, ENTRY + 1),                      // unaligned PC
        ] {
            let mut bad = data.clone();
            bad[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
            assert!(
                MachoParsedFile::parse(&bad).is_err(),
                "offset={offset} value={value:#x}"
            );
        }
        for (offset, value) in [
            (THREAD_FLAVOR, 0),
            (THREAD_COUNT, u32::try_from(STATE_WORDS - 1).unwrap()),
            (THREAD_COUNT, u32::try_from(STATE_WORDS + 1).unwrap()),
            (
                THREAD_SIZE,
                u32::try_from(size_of::<UnixThreadCommand64>() - LOAD_COMMAND_ALIGNMENT).unwrap(),
            ),
            (PROTECTION, u32::MAX),
        ] {
            let mut bad = data.clone();
            put32(&mut bad, offset, value);
            assert!(
                MachoParsedFile::parse(&bad).is_err(),
                "accepted invalid field at {offset}"
            );
        }
        let mut writable_code = data;
        put32(
            &mut writable_code,
            PROTECTION,
            VmProtection::all().bits().reinterpret_as_unsigned(),
        );
        assert!(matches!(
            MachoParsedFile::parse(&writable_code),
            Err(MachoLoaderError::Unsupported(_))
        ));
    }

    #[test]
    fn load_command_copy_is_bounded_by_the_file() {
        let mut data = image();
        // A huge sizeofcmds must be rejected before allocating its claimed size.
        put32(&mut data, COMMAND_BYTES, u32::MAX);
        assert!(matches!(
            MachoParsedFile::parse(&data),
            Err(MachoLoaderError::Invalid("load commands"))
        ));

        // Segment file ranges are validated against the full input file;
        // aligned metadata contains only the header and load commands.
        let data = image();
        let mut unaligned = vec![0];
        unaligned.extend_from_slice(&data);
        let parsed = MachoParsedFile::parse(&unaligned[1..]).unwrap();
        assert_eq!(parsed.segments[0].file_range, 0..PAGE_SIZE);
        assert!(parsed.segments[0].file_range.end > METADATA_END);
        // Truncate valid metadata at header, command, and file-data boundaries.
        for len in [
            0,
            size_of::<u32>(),
            SEGMENT_START - 1,
            SEGMENT_START,
            THREAD_START - 1,
            THREAD_START,
            METADATA_END - 1,
            METADATA_END,
            data.len() - 1,
        ] {
            assert!(
                MachoParsedFile::parse(&data[..len]).is_err(),
                "accepted truncation at {len}"
            );
        }
        let mut invalid_count = data;
        for count in [1, u32::MAX] {
            put32(&mut invalid_count, COMMAND_COUNT, count);
            assert!(MachoParsedFile::parse(&invalid_count).is_err());
        }
    }

    /// Appends sub-trampolines of `size` bytes at each `vaddr`, then the
    /// table and footer, returning the table's offset.
    fn append_trampolines(data: &mut Vec<u8>, regions: &[(u64, usize)]) -> usize {
        let mut table = Vec::new();
        for &(vaddr, size) in regions {
            data.resize(data.len().next_multiple_of(TRAMPOLINE_FILE_ALIGNMENT), 0);
            for value in [data.len() as u64, vaddr, size as u64] {
                table.extend_from_slice(&value.to_le_bytes());
            }
            data.resize(data.len() + size, 0);
        }
        let table_offset = data.len();
        data.extend_from_slice(&table);
        data.extend_from_slice(litebox_syscall_rewriter::TRAMPOLINE_MAGIC);
        for value in [table_offset as u64, regions.len() as u64, 0] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        table_offset
    }

    #[test]
    fn trampoline_table_is_bounded_and_disjoint() {
        const TRAMPOLINE_BYTES: usize = litebox_syscall_rewriter::aarch64::GATE_ALIGNMENT;
        const PAGE: u64 = PAGE_SIZE as u64;
        let base = usize::try_from(IMAGE_BASE).unwrap();
        let mut data = image();
        let table = append_trampolines(
            &mut data,
            &[
                (IMAGE_BASE + 3 * PAGE, TRAMPOLINE_BYTES),
                (IMAGE_BASE + PAGE, TRAMPOLINE_BYTES * 2),
            ],
        );
        let mut plan = MachoParsedFile::parse(&data).unwrap();
        let trampolines = plan.parse_trampoline(&data).unwrap();
        assert_eq!(trampolines.len(), 2);
        assert_eq!(
            trampolines[0].file_range,
            PAGE_SIZE..PAGE_SIZE + TRAMPOLINE_BYTES
        );
        assert_eq!(
            trampolines[0].virtual_range,
            base + 3 * PAGE_SIZE..base + 4 * PAGE_SIZE
        );
        assert_eq!(
            trampolines[1].virtual_range,
            base + PAGE_SIZE..base + 2 * PAGE_SIZE
        );
        assert_eq!(plan.virtual_range, base..base + 4 * PAGE_SIZE);

        // Rules beyond the shared table format, which the rewriter's parser
        // tests cover: Mach-O pages are 16 KiB, and a region must neither
        // overlap the image's segments nor push the image past its limit.
        let entry = |index: usize, field: usize| table + index * 24 + field * 8;
        for (offset, value) in [
            // 4 KiB-aligned but not 16 KiB-aligned.
            (entry(0, 1), IMAGE_BASE + 3 * PAGE + 0x1000),
            // Inside the image's only segment.
            (entry(0, 1), IMAGE_BASE),
            // Beyond the image limit.
            (entry(0, 1), IMAGE_BASE + MAX_IMAGE_SIZE as u64),
            // File bytes inside the segment's file range.
            (entry(0, 0), 0),
            // Smaller than one gate slot.
            (entry(0, 2), (TRAMPOLINE_BYTES - 4) as u64),
        ] {
            let mut invalid = data.clone();
            invalid[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            assert!(
                MachoParsedFile::parse(&invalid)
                    .unwrap()
                    .parse_trampoline(&invalid)
                    .is_err(),
                "accepted {value:#x} at {offset:#x}"
            );
        }
        let footer = data.len() - 32;
        let mut unknown = data.clone();
        unknown[footer..footer + 8].copy_from_slice(b"LITEBOX9");
        assert!(matches!(
            MachoParsedFile::parse(&unknown)
                .unwrap()
                .parse_trampoline(&unknown),
            Err(MachoLoaderError::Rewrite)
        ));

        let raw = image();
        assert!(matches!(
            MachoParsedFile::parse(&raw).unwrap().parse_trampoline(&raw),
            Err(MachoLoaderError::Unrewritten)
        ));
        let mut empty = raw;
        append_trampolines(&mut empty, &[]);
        let mut plan = MachoParsedFile::parse(&empty).unwrap();
        assert!(plan.parse_trampoline(&empty).unwrap().is_empty());
        assert_eq!(plan.virtual_range, base..base + PAGE_SIZE);
    }
}
