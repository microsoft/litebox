// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Validated load plan for the initial static Mach-O subset.
//!
//! Parsing produces a load plan for thin AArch64 executables with LC_UNIXTHREAD.
//! Dynamic linking and relocations are unsupported.
//! Images are slid as a unit, so guest code must be position independent.

use crate::{PAGE_SIZE, VmProtection};
use alloc::{vec, vec::Vec};
use core::ops::Range;
use object::{
    LittleEndian as LE, macho,
    read::macho::{MachHeader as _, Segment as _},
};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout,
    byteorder::{LittleEndian, U32, U64},
};

const TRAMPOLINE_FILE_ALIGNMENT: usize = 4096;
const MACH_HEADER_SIZE: usize = size_of::<macho::MachHeader64<LE>>();
const ARM_THREAD_STATE64: u32 = 6;

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

/// On-disk AOT footer, with explicitly little-endian fields.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct TrampolineHeader64 {
    magic: [u8; 8],
    file_offset: U64<LittleEndian>,
    vaddr: U64<LittleEndian>,
    trampoline_size: U64<LittleEndian>,
}

/// Bound both the input file and the reserved virtual span for this subset.
const MAX_IMAGE_SIZE: usize = 256 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum MachoLoaderError {
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
}

/// AOT trampoline payload described by the rewriter's 64-bit footer.
#[derive(Debug)]
pub struct TrampolineInfo {
    pub file_range: Range<usize>,
    pub virtual_range: Range<usize>,
}

impl MachoParsedFile {
    /// Validate the rewriter's AOT footer and include the trampoline in the
    /// image reservation so code and gates receive the same slide.
    /// `None` means the rewriter processed an image with no patch sites.
    pub fn parse_trampoline(
        &mut self,
        data: &[u8],
    ) -> Result<Option<TrampolineInfo>, MachoLoaderError> {
        let footer_start = data
            .len()
            .checked_sub(size_of::<TrampolineHeader64>())
            .ok_or(MachoLoaderError::Unrewritten)?;
        let header = TrampolineHeader64::read_from_bytes(&data[footer_start..])
            .map_err(|_| MachoLoaderError::Rewrite)?;
        if header.magic != *litebox_syscall_rewriter::TRAMPOLINE_MAGIC {
            return Err(if header.magic.starts_with(b"LITEBOX") {
                MachoLoaderError::Rewrite
            } else {
                MachoLoaderError::Unrewritten
            });
        }
        let file_offset =
            usize::try_from(header.file_offset.get()).map_err(|_| MachoLoaderError::Rewrite)?;
        let address = usize::try_from(header.vaddr.get()).map_err(|_| MachoLoaderError::Rewrite)?;
        let size =
            usize::try_from(header.trampoline_size.get()).map_err(|_| MachoLoaderError::Rewrite)?;
        if self
            .segments
            .iter()
            .any(|s| s.file_range.end > footer_start)
        {
            return Err(MachoLoaderError::Rewrite);
        }
        if size == 0 {
            return if file_offset == 0 && address == 0 {
                Ok(None)
            } else {
                Err(MachoLoaderError::Rewrite)
            };
        }
        let file_end = file_offset
            .checked_add(size)
            .ok_or(MachoLoaderError::Rewrite)?;
        let end = address
            .checked_add(size)
            .and_then(|end| end.checked_next_multiple_of(PAGE_SIZE))
            .ok_or(MachoLoaderError::Rewrite)?;
        if !file_offset.is_multiple_of(TRAMPOLINE_FILE_ALIGNMENT)
            || !address.is_multiple_of(PAGE_SIZE)
            || size < litebox_syscall_rewriter::aarch64::GATE_ALIGNMENT
            || !size.is_multiple_of(size_of::<u32>())
            || file_end != footer_start
            || self.segments.iter().any(|s| {
                s.file_range.end > file_offset
                    || (address < s.virtual_range.end && s.virtual_range.start < end)
            })
        {
            return Err(MachoLoaderError::Rewrite);
        }
        let span = self.virtual_range.start.min(address)..self.virtual_range.end.max(end);
        if span.len() > MAX_IMAGE_SIZE {
            return Err(MachoLoaderError::Rewrite);
        }
        self.virtual_range = span;
        Ok(Some(TrampolineInfo {
            file_range: file_offset..file_end,
            virtual_range: address..end,
        }))
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
                header.cpusubtype(LE),
                macho::CPU_SUBTYPE_ARM64_ALL | macho::CPU_SUBTYPE_ARM64_V8
            )
            || header.filetype(LE) != macho::MH_EXECUTE
        {
            return Err(Unsupported("expected thin AArch64 MH_EXECUTE (not arm64e)"));
        }
        if header.flags(LE) & (macho::MH_DYLDLINK | macho::MH_DYLIB_IN_CACHE) != 0 {
            return Err(Unsupported("dynamically linked/shared-cache image"));
        }
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
        while let Some(command) = commands.next().map_err(|_| Invalid("load command"))? {
            match command.cmd() {
                macho::LC_LOAD_DYLINKER
                | macho::LC_LOAD_DYLIB
                | macho::LC_LOAD_WEAK_DYLIB
                | macho::LC_REEXPORT_DYLIB
                | macho::LC_DYLD_INFO
                | macho::LC_DYLD_INFO_ONLY
                | macho::LC_DYLD_CHAINED_FIXUPS
                | macho::LC_MAIN => {
                    return Err(Unsupported("dynamic linking/LC_MAIN/fixups"));
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
                    let protection = VmProtection::from_bits(seg.initprot.get(LE).cast_signed())
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
        let entry = entry.ok_or(Unsupported("missing LC_UNIXTHREAD"))?;
        if !entry.is_multiple_of(size_of::<u32>())
            || !segments.iter().any(|s| {
                s.protection.contains(VmProtection::EXECUTE)
                    && (s.virtual_range.start..s.virtual_range.start + s.file_range.len())
                        .contains(&entry)
            })
        {
            return Err(Invalid("entry outside file-backed executable segment"));
        }
        Ok(Self {
            segments,
            virtual_range: start..end,
            entry,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // A small synthetic image makes range validation testable on any host.
    fn image() -> Vec<u8> {
        let mut data = vec![0; PAGE_SIZE];
        for (offset, value) in [
            (0, macho::MH_MAGIC_64),
            (4, macho::CPU_TYPE_ARM64),
            (12, macho::MH_EXECUTE),
            (16, 2),
            (20, 72 + 288),
            (32, macho::LC_SEGMENT_64),
            (36, 72),
            (
                92,
                (VmProtection::READ | VmProtection::EXECUTE)
                    .bits()
                    .cast_unsigned(),
            ),
            (104, macho::LC_UNIXTHREAD),
            (108, 288),
            (112, 6),
            (116, 68),
        ] {
            data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [
            (56, 0x1_0000_0000u64),
            (64, PAGE_SIZE as u64),
            (80, PAGE_SIZE as u64),
            (376, 0x1_0000_1000u64),
        ] {
            data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        data
    }

    #[test]
    fn segment_and_entry_validation() {
        let data = image();
        let parsed = MachoParsedFile::parse(&data).unwrap();
        assert_eq!(parsed.entry, 0x1_0000_1000);
        assert_eq!(parsed.virtual_range.len(), PAGE_SIZE);
        for (offset, value) in [
            (56, u64::MAX - 0x3fff),      // vmaddr + vmsize overflow
            (64, 1),                      // unaligned vmsize
            (64, 0),                      // filesize > vmsize
            (72, u64::MAX),               // fileoff + filesize overflow
            (80, (PAGE_SIZE + 1) as u64), // file data past EOF
            (376, 0),                     // entry outside executable memory
            (376, 0x1_0000_1001),         // unaligned PC
        ] {
            let mut bad = data.clone();
            bad[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            assert!(
                MachoParsedFile::parse(&bad).is_err(),
                "offset={offset} value={value:#x}"
            );
        }
        for (offset, value) in [(112, 0u32), (116, 67), (116, 69), (108, 280), (92, 1 << 31)] {
            let mut bad = data.clone();
            bad[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
            assert!(
                MachoParsedFile::parse(&bad).is_err(),
                "accepted invalid field at {offset}"
            );
        }
        let mut writable_code = data;
        writable_code[92..96].copy_from_slice(&VmProtection::all().bits().to_le_bytes());
        assert!(matches!(
            MachoParsedFile::parse(&writable_code),
            Err(MachoLoaderError::Unsupported(_))
        ));
    }

    #[test]
    fn load_command_copy_is_bounded_by_the_file() {
        let mut data = image();
        // A huge sizeofcmds must be rejected before allocating its claimed size.
        data[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
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
        assert!(parsed.segments[0].file_range.end > 32 + 72 + 288);
        // Truncate valid metadata at header, command, and file-data boundaries.
        for len in [0, 4, 31, 32, 103, 104, 391, 392, data.len() - 1] {
            assert!(
                MachoParsedFile::parse(&data[..len]).is_err(),
                "accepted truncation at {len}"
            );
        }
        let mut excessive_commands = data;
        excessive_commands[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(MachoParsedFile::parse(&excessive_commands).is_err());
    }

    #[test]
    fn trampoline_footer_is_bounded_and_disjoint() {
        let mut data = image();
        let file_offset = data.len();
        data.extend_from_slice(&[0u8; 64]);
        let header = TrampolineHeader64 {
            magic: *litebox_syscall_rewriter::TRAMPOLINE_MAGIC,
            file_offset: (file_offset as u64).into(),
            vaddr: 0x1_0000_4000.into(),
            trampoline_size: 64.into(),
        };
        let footer = data.len();
        data.extend_from_slice(header.as_bytes());
        let mut plan = MachoParsedFile::parse(&data).unwrap();
        let trampoline = plan.parse_trampoline(&data).unwrap().unwrap();
        assert_eq!(trampoline.file_range, file_offset..file_offset + 64);
        assert_eq!(plan.virtual_range, 0x1_0000_0000..0x1_0000_8000);
        for invalid_header in [
            TrampolineHeader64 {
                file_offset: 1.into(),
                ..header
            },
            TrampolineHeader64 {
                file_offset: 0.into(),
                ..header
            },
            TrampolineHeader64 {
                vaddr: 0x1_0000_0000.into(),
                ..header
            },
            TrampolineHeader64 {
                vaddr: u64::MAX.into(),
                ..header
            },
            TrampolineHeader64 {
                trampoline_size: 63.into(),
                ..header
            },
            TrampolineHeader64 {
                trampoline_size: 68.into(),
                ..header
            },
            TrampolineHeader64 {
                magic: *b"LITEBOX9",
                ..header
            },
        ] {
            let mut invalid = data.clone();
            invalid[footer..].copy_from_slice(invalid_header.as_bytes());
            assert!(
                MachoParsedFile::parse(&invalid)
                    .unwrap()
                    .parse_trampoline(&invalid)
                    .is_err()
            );
        }
        let raw = image();
        assert!(matches!(
            MachoParsedFile::parse(&raw).unwrap().parse_trampoline(&raw),
            Err(MachoLoaderError::Unrewritten)
        ));
        let mut sentinel = raw;
        sentinel.extend_from_slice(
            TrampolineHeader64 {
                magic: *litebox_syscall_rewriter::TRAMPOLINE_MAGIC,
                file_offset: 0.into(),
                vaddr: 0.into(),
                trampoline_size: 0.into(),
            }
            .as_bytes(),
        );
        assert!(
            MachoParsedFile::parse(&sentinel)
                .unwrap()
                .parse_trampoline(&sentinel)
                .unwrap()
                .is_none()
        );
    }
}
