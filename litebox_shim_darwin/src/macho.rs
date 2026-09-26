// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Parsing of the x86-64 Mach-O executables this shim can load.
//!
//! Only images that need no dynamic linker are accepted: no `LC_LOAD_DYLIB`
//! family command (those need dyld and Apple's libraries, which LiteBox cannot
//! supply) and no chained fixups (whose pointer slots are encoded and must be
//! rewritten before use, even at the preferred address). An `LC_LOAD_DYLINKER`
//! naming dyld is tolerated, because the linker records one for every
//! executable; nothing is ever loaded from it.
//!
//! Images are loaded at their preferred addresses, so the rebase opcodes in
//! `LC_DYLD_INFO(_ONLY)` never need to run.

use alloc::vec::Vec;
use object::LittleEndian;
use object::macho;
use object::read::macho::{MachHeader as _, Section as _, Segment as _};
use thiserror::Error;

/// A problem with a Mach-O image that stops it from being loaded.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MachOError {
    #[error("not a little-endian 64-bit Mach-O file")]
    NotMachO64,
    #[error("Mach-O CPU type {0:#x} is not x86-64")]
    UnsupportedCpu(u32),
    #[error("Mach-O file type {0} is not an executable")]
    NotExecutable(u32),
    #[error("malformed Mach-O load commands")]
    MalformedLoadCommands,
    #[error("malformed Mach-O segment")]
    MalformedSegment,
    #[error("the image links against dynamic libraries, which need dyld")]
    NeedsDyld,
    #[error("the image uses chained fixups, which need dyld")]
    ChainedFixups,
    #[error("LC_UNIXTHREAD entry points are not supported; the image needs LC_MAIN")]
    ThreadEntry,
    #[error("the image has no LC_MAIN entry point")]
    NoEntryPoint,
    #[error("the LC_MAIN entry offset is outside every segment")]
    EntryOutsideSegments,
    #[error("the image has no loadable segments")]
    NoSegments,
}

/// One segment to map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Segment {
    pub(crate) vmaddr: u64,
    pub(crate) vmsize: u64,
    pub(crate) fileoff: u64,
    pub(crate) filesize: u64,
    /// `VM_PROT_*` bits the segment starts with.
    pub(crate) initprot: u32,
}

/// A parsed, loadable image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Image {
    /// Segments to map, excluding `__PAGEZERO` and any other empty segment.
    pub(crate) segments: Vec<Segment>,
    /// Address ranges holding instructions (sections marked
    /// `S_ATTR_PURE_INSTRUCTIONS` or `S_ATTR_SOME_INSTRUCTIONS`). Only these are
    /// scanned for `syscall`: `__TEXT` also carries strings and constants, whose
    /// bytes must not be read as code.
    pub(crate) code: Vec<core::ops::Range<u64>>,
    /// Address of the `LC_MAIN` entry point.
    pub(crate) entry: u64,
    /// The stack size `LC_MAIN` asks for; zero means the default.
    pub(crate) stack_size: u64,
}

impl Image {
    /// The lowest segment address.
    pub(crate) fn start(&self) -> u64 {
        self.segments.iter().map(|s| s.vmaddr).min().unwrap_or(0)
    }

    /// One past the highest segment address.
    pub(crate) fn end(&self) -> u64 {
        self.segments
            .iter()
            .map(|s| s.vmaddr + s.vmsize)
            .max()
            .unwrap_or(0)
    }
}

/// Parse `data` as a loadable x86-64 Mach-O executable.
pub(crate) fn parse(data: &[u8]) -> Result<Image, MachOError> {
    // `object` reads the header and load commands in place, which needs the
    // buffer aligned for their 8-byte fields. Heap buffers are; anything else
    // (an embedded `static`, say) is copied into one first.
    if data.as_ptr().align_offset(8) != 0 {
        let heap_copy = Vec::from(data);
        return parse_aligned(&heap_copy);
    }
    parse_aligned(data)
}

fn parse_aligned(data: &[u8]) -> Result<Image, MachOError> {
    let header =
        macho::MachHeader64::<LittleEndian>::parse(data, 0).map_err(|_| MachOError::NotMachO64)?;
    // `magic()` reads the field big-endian, so a little-endian image is the one
    // whose magic comes back byte-swapped (`MH_CIGAM_64`).
    if header.magic() != macho::MH_CIGAM_64 {
        return Err(MachOError::NotMachO64);
    }
    let endian = LittleEndian;
    let cputype = header.cputype(endian);
    if cputype != macho::CPU_TYPE_X86_64 {
        return Err(MachOError::UnsupportedCpu(cputype));
    }
    let filetype = header.filetype(endian);
    if filetype != macho::MH_EXECUTE {
        return Err(MachOError::NotExecutable(filetype));
    }

    let mut segments = Vec::new();
    let mut code = Vec::new();
    let mut entry = None;
    let mut commands = header
        .load_commands(endian, data, 0)
        .map_err(|_| MachOError::MalformedLoadCommands)?;
    while let Some(command) = commands
        .next()
        .map_err(|_| MachOError::MalformedLoadCommands)?
    {
        match command.cmd() {
            macho::LC_SEGMENT_64 => {
                let (segment, section_data) = command
                    .segment_64()
                    .map_err(|_| MachOError::MalformedSegment)?
                    .ok_or(MachOError::MalformedSegment)?;
                let parsed = Segment {
                    vmaddr: segment.vmaddr.get(endian),
                    vmsize: segment.vmsize.get(endian),
                    fileoff: segment.fileoff.get(endian),
                    filesize: segment.filesize.get(endian),
                    initprot: segment.initprot.get(endian),
                };
                // `__PAGEZERO` (and any other empty segment) reserves address space
                // only; there is nothing to map.
                if parsed.vmsize == 0 || (parsed.initprot == 0 && parsed.filesize == 0) {
                    continue;
                }
                let file_end = parsed
                    .fileoff
                    .checked_add(parsed.filesize)
                    .ok_or(MachOError::MalformedSegment)?;
                if parsed.filesize > parsed.vmsize
                    || file_end > data.len() as u64
                    || parsed.vmaddr.checked_add(parsed.vmsize).is_none()
                {
                    return Err(MachOError::MalformedSegment);
                }
                for section in segment
                    .sections(endian, section_data)
                    .map_err(|_| MachOError::MalformedSegment)?
                {
                    let flags = section.flags(endian);
                    if flags & (macho::S_ATTR_PURE_INSTRUCTIONS | macho::S_ATTR_SOME_INSTRUCTIONS)
                        == 0
                    {
                        continue;
                    }
                    let start = section.addr(endian);
                    let end = start
                        .checked_add(section.size(endian))
                        .ok_or(MachOError::MalformedSegment)?;
                    if start < parsed.vmaddr || end > parsed.vmaddr + parsed.vmsize {
                        return Err(MachOError::MalformedSegment);
                    }
                    if start < end {
                        code.push(start..end);
                    }
                }
                segments.push(parsed);
            }
            macho::LC_MAIN => {
                let main = command
                    .entry_point()
                    .map_err(|_| MachOError::MalformedLoadCommands)?
                    .ok_or(MachOError::MalformedLoadCommands)?;
                entry = Some((main.entryoff.get(endian), main.stacksize.get(endian)));
            }
            macho::LC_UNIXTHREAD => return Err(MachOError::ThreadEntry),
            macho::LC_LOAD_DYLIB
            | macho::LC_LOAD_WEAK_DYLIB
            | macho::LC_REEXPORT_DYLIB
            | macho::LC_LAZY_LOAD_DYLIB
            | macho::LC_LOAD_UPWARD_DYLIB => return Err(MachOError::NeedsDyld),
            macho::LC_DYLD_CHAINED_FIXUPS => return Err(MachOError::ChainedFixups),
            _ => {}
        }
    }

    if segments.is_empty() {
        return Err(MachOError::NoSegments);
    }
    let (entryoff, stack_size) = entry.ok_or(MachOError::NoEntryPoint)?;
    // `entryoff` is a file offset; the entry point is wherever that byte is mapped.
    let entry = segments
        .iter()
        .find(|s| s.fileoff <= entryoff && entryoff < s.fileoff + s.filesize)
        .map(|s| s.vmaddr + (entryoff - s.fileoff))
        .ok_or(MachOError::EntryOutsideSegments)?;

    Ok(Image {
        segments,
        code,
        entry,
        stack_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO: &[u8] = include_bytes!("../test-bins/hello.macho");

    #[test]
    fn parses_a_linked_executable() {
        let image = parse(HELLO).unwrap();
        // `__PAGEZERO` is skipped; `__TEXT` and `__LINKEDIT` remain.
        assert_eq!(image.segments.len(), 2);
        assert_eq!(image.start(), 0x1_0000_0000);
        let text = &image.segments[0];
        assert_eq!(text.fileoff, 0);
        assert_eq!(
            text.initprot,
            macho::VM_PROT_READ | macho::VM_PROT_EXECUTE,
            "__TEXT is r-x"
        );
        // The entry point lies in the one instruction section, `__text`.
        assert_eq!(image.code.len(), 1);
        assert!(image.code[0].contains(&image.entry));
        assert_eq!(image.stack_size, 0);
    }

    #[test]
    fn rejects_what_it_cannot_load() {
        assert_eq!(parse(b"\x7fELF"), Err(MachOError::NotMachO64));

        let mut arm64 = HELLO.to_vec();
        arm64[4..8].copy_from_slice(&macho::CPU_TYPE_ARM64.to_le_bytes());
        assert_eq!(
            parse(&arm64),
            Err(MachOError::UnsupportedCpu(macho::CPU_TYPE_ARM64))
        );

        let mut dylib = HELLO.to_vec();
        dylib[12..16].copy_from_slice(&macho::MH_DYLIB.to_le_bytes());
        assert_eq!(
            parse(&dylib),
            Err(MachOError::NotExecutable(macho::MH_DYLIB))
        );
    }

    #[test]
    fn rejects_images_that_need_dyld() {
        // Retag `LC_MAIN` as each command that needs dyld; the size field and payload
        // are left alone, so only the command kind changes.
        let main_at = find_command(HELLO, macho::LC_MAIN);
        for (cmd, error) in [
            (macho::LC_LOAD_DYLIB, MachOError::NeedsDyld),
            (macho::LC_LOAD_WEAK_DYLIB, MachOError::NeedsDyld),
            (macho::LC_DYLD_CHAINED_FIXUPS, MachOError::ChainedFixups),
            (macho::LC_UNIXTHREAD, MachOError::ThreadEntry),
        ] {
            let mut image = HELLO.to_vec();
            image[main_at..main_at + 4].copy_from_slice(&cmd.to_le_bytes());
            assert_eq!(parse(&image), Err(error), "command {cmd:#x}");
        }
    }

    /// The file offset of the first load command of kind `cmd`.
    fn find_command(data: &[u8], cmd: u32) -> usize {
        let header_len = core::mem::size_of::<macho::MachHeader64<LittleEndian>>();
        let ncmds = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let mut offset = header_len;
        for _ in 0..ncmds {
            let this = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            if this == cmd {
                return offset;
            }
            offset += u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;
        }
        panic!("no load command {cmd:#x}");
    }
}
