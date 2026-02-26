// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach-O loader and mapper.
//!
//! Supports parsing and mapping static x86_64 Mach-O binaries.

use alloc::string::String;
use alloc::vec::Vec;
use object::LittleEndian;
use object::macho::{
    CPU_TYPE_X86_64, LC_LOAD_DYLIB, LC_LOAD_DYLINKER, LC_LOAD_WEAK_DYLIB, LC_MAIN,
    LC_REEXPORT_DYLIB, LC_SEGMENT_64, LC_UNIXTHREAD, MH_DYLINKER, MH_EXECUTE, MachHeader64,
    SegmentCommand64,
};
use object::read::macho::MachHeader;
use thiserror::Error;

/// The result of parsing the Mach-O file headers.
///
/// Can be used to map the Mach-O into memory.
#[derive(Debug)]
pub struct MachoParsedFile {
    /// The entry point address
    entry_point: u64,
    /// Segments to load
    segments: Vec<SegmentInfo>,
    /// Optional dynamic runtime linker path (`LC_LOAD_DYLINKER`)
    runtime_linker_path: Option<String>,
    /// All required dynamic library paths (`LC_LOAD_DYLIB` variants)
    required_dylibs: Vec<String>,
}

/// Information about a segment to load
#[derive(Debug, Clone)]
pub struct SegmentInfo {
    /// Virtual memory address
    pub vmaddr: u64,
    /// Size in virtual memory
    pub vmsize: u64,
    /// Offset in file
    pub fileoff: u64,
    /// Size in file
    pub filesize: u64,
    /// Initial protection (VM_PROT_* bits)
    pub initprot: u32,
}

/// VM protection flags (from mach/vm_prot.h)
pub const VM_PROT_READ: u32 = 0x01;
pub const VM_PROT_WRITE: u32 = 0x02;
pub const VM_PROT_EXECUTE: u32 = 0x04;

/// Information about the mapped Mach-O file.
pub struct MappingInfo {
    /// The entry point, where execution begins.
    pub entry_point: usize,
    /// The program break (end of all mapped segments).
    pub brk: usize,
}

/// Errors that can occur when parsing a Mach-O file.
#[derive(Debug, Error)]
pub enum MachoParseError {
    #[error("Invalid Mach-O magic number")]
    BadMagic,
    #[error("Unsupported CPU type (expected x86_64)")]
    UnsupportedCpuType,
    #[error("Unsupported file type (expected executable)")]
    UnsupportedFileType,
    #[error("Invalid load command")]
    InvalidLoadCommand,
    #[error("No entry point found")]
    NoEntryPoint,
    #[error("Invalid load command string")]
    InvalidLoadCommandString,
    #[error("File too small")]
    FileTooSmall,
}

/// Errors that can occur when mapping a Mach-O file into memory.
#[derive(Debug, Error)]
pub enum MachoLoadError<E> {
    #[error("Memory mapping error")]
    Map(#[source] E),
    #[error("I/O error")]
    Io(#[source] E),
    #[error("Invalid segment")]
    InvalidSegment,
}

/// A trait for reading bytes at a specific offset.
pub trait ReadAt {
    /// Error type for read operations.
    type Error;
    /// Read bytes at the given offset into the buffer.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error>;
}

/// A trait for mapping memory.
pub trait MapMemory {
    /// Error type for map operations.
    type Error;

    /// Map anonymous read/write pages at a fixed address.
    fn map_anon(&mut self, addr: usize, len: usize) -> Result<*mut u8, Self::Error>;

    /// Map executable pages at a fixed address, initialized with data.
    fn map_exec(&mut self, addr: usize, len: usize, data: &[u8]) -> Result<(), Self::Error>;

    /// Map read/write pages at a fixed address, initialized with data.
    fn map_data(&mut self, addr: usize, len: usize, data: &[u8]) -> Result<(), Self::Error>;
}

impl MachoParsedFile {
    /// Parse a Mach-O file from the given data.
    pub fn parse(data: &[u8]) -> Result<Self, MachoParseError> {
        // Need at least the Mach-O header
        if data.len() < core::mem::size_of::<MachHeader64<LittleEndian>>() {
            return Err(MachoParseError::FileTooSmall);
        }

        let header =
            MachHeader64::<LittleEndian>::parse(data, 0).map_err(|_| MachoParseError::BadMagic)?;

        if !header.is_little_endian() {
            return Err(MachoParseError::BadMagic);
        }

        let endian = header.endian().map_err(|_| MachoParseError::BadMagic)?;

        // Check CPU type (must be x86_64)
        if header.cputype(endian) != CPU_TYPE_X86_64 {
            return Err(MachoParseError::UnsupportedCpuType);
        }

        // Check file type (execute image or dynamic linker image)
        let file_type = header.filetype(endian);
        if file_type != MH_EXECUTE && file_type != MH_DYLINKER {
            return Err(MachoParseError::UnsupportedFileType);
        }

        let mut segments = Vec::new();
        let mut entry_point: Option<u64> = None;
        let mut entryoff_from_lc_main: Option<u64> = None;
        let mut text_vmaddr: u64 = 0;
        let mut runtime_linker_path: Option<String> = None;
        let mut required_dylibs = Vec::new();

        // Parse load commands
        let mut load_commands = header
            .load_commands(endian, data, 0)
            .map_err(|_| MachoParseError::InvalidLoadCommand)?;

        while let Some(cmd) = load_commands
            .next()
            .map_err(|_| MachoParseError::InvalidLoadCommand)?
        {
            match cmd.cmd() {
                LC_SEGMENT_64 => {
                    let segment: &SegmentCommand64<LittleEndian> = cmd
                        .data()
                        .map_err(|_| MachoParseError::InvalidLoadCommand)?;

                    let name_bytes = segment.segname;
                    let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
                    let name = core::str::from_utf8(&name_bytes[..name_len]).unwrap_or("");

                    // Track __TEXT vmaddr for LC_MAIN offset calculation
                    if name == "__TEXT" {
                        text_vmaddr = segment.vmaddr.get(endian);
                    }

                    segments.push(SegmentInfo {
                        vmaddr: segment.vmaddr.get(endian),
                        vmsize: segment.vmsize.get(endian),
                        fileoff: segment.fileoff.get(endian),
                        filesize: segment.filesize.get(endian),
                        initprot: segment.initprot.get(endian),
                    });
                }
                LC_MAIN => {
                    // LC_MAIN provides entryoff relative to __TEXT segment.
                    // We defer conversion to a virtual address until all load commands
                    // are scanned because __TEXT may appear after LC_MAIN.
                    let entry_data = cmd
                        .data::<object::macho::EntryPointCommand<LittleEndian>>()
                        .map_err(|_| MachoParseError::InvalidLoadCommand)?;
                    entryoff_from_lc_main = Some(entry_data.entryoff.get(endian));
                }
                LC_UNIXTHREAD => {
                    // LC_UNIXTHREAD contains raw thread state with rip
                    // The thread state layout for x86_64:
                    // - flavor (4 bytes)
                    // - count (4 bytes)
                    // - thread state (register values)
                    // rip is at offset 16*8 = 128 bytes into the thread state
                    let cmd_data = cmd.raw_data();
                    // Skip the 8-byte cmd header, then read thread state
                    if cmd_data.len() >= 8 + 4 + 4 + 21 * 8 {
                        // flavor (4) + count (4) + 21 registers (168 bytes)
                        // rip is register 16 (0-indexed)
                        let thread_state_offset = 8; // skip flavor and count
                        let rip_offset = thread_state_offset + 16 * 8;
                        if cmd_data.len() >= rip_offset + 8 {
                            let rip_bytes: [u8; 8] = cmd_data[rip_offset..rip_offset + 8]
                                .try_into()
                                .map_err(|_| MachoParseError::InvalidLoadCommand)?;
                            entry_point = Some(u64::from_le_bytes(rip_bytes));
                        }
                    }
                }
                LC_LOAD_DYLINKER => {
                    runtime_linker_path = Some(parse_lc_string(cmd.raw_data())?);
                }
                LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB => {
                    required_dylibs.push(parse_lc_string(cmd.raw_data())?);
                }
                _ => {}
            }
        }

        if entry_point.is_none() {
            if let Some(entryoff) = entryoff_from_lc_main {
                entry_point = Some(text_vmaddr + entryoff);
            }
        }

        let entry_point = entry_point.ok_or(MachoParseError::NoEntryPoint)?;

        Ok(MachoParsedFile {
            entry_point,
            segments,
            runtime_linker_path,
            required_dylibs,
        })
    }

    /// Get the entry point address.
    #[must_use]
    pub fn entry_point(&self) -> u64 {
        self.entry_point
    }

    /// Get the segments.
    #[must_use]
    pub fn segments(&self) -> &[SegmentInfo] {
        &self.segments
    }

    /// Return the dynamic runtime linker path if this file is dynamically linked.
    #[must_use]
    pub fn runtime_linker_path(&self) -> Option<&str> {
        self.runtime_linker_path.as_deref()
    }

    /// Return required dylib paths for diagnostics and validation.
    #[must_use]
    pub fn required_dylibs(&self) -> &[String] {
        &self.required_dylibs
    }

    /// Load the Mach-O file into memory using the provided reader and mapper.
    pub fn load<R: ReadAt, M: MapMemory>(
        &self,
        reader: &mut R,
        mapper: &mut M,
    ) -> Result<MappingInfo, MachoLoadError<M::Error>>
    where
        M::Error: From<R::Error>,
    {
        self.load_with_slide(reader, mapper, 0)
    }

    /// Load the Mach-O file into memory with a virtual-address slide.
    pub fn load_with_slide<R: ReadAt, M: MapMemory>(
        &self,
        reader: &mut R,
        mapper: &mut M,
        slide: usize,
    ) -> Result<MappingInfo, MachoLoadError<M::Error>>
    where
        M::Error: From<R::Error>,
    {
        let page_size = 0x1000usize; // 4KB pages
        let mut brk: usize = 0;

        for segment in &self.segments {
            if segment.vmsize == 0 {
                continue;
            }

            if segment.vmaddr == 0 && segment.filesize == 0 {
                continue;
            }

            let addr = segment.vmaddr as usize + slide;
            let len = (segment.vmsize as usize).next_multiple_of(page_size);

            // Track the highest mapped address
            brk = brk.max(addr + len);

            // Read segment data from file
            let mut data = alloc::vec![0u8; segment.filesize as usize];
            if !data.is_empty() {
                reader
                    .read_at(segment.fileoff, &mut data)
                    .map_err(|e| MachoLoadError::Io(e.into()))?;
            }

            // Determine mapping type based on protection
            let is_executable = (segment.initprot & VM_PROT_EXECUTE) != 0;
            let is_writable = (segment.initprot & VM_PROT_WRITE) != 0;

            if is_executable {
                mapper
                    .map_exec(addr, len, &data)
                    .map_err(MachoLoadError::Map)?;
            } else if is_writable || !data.is_empty() {
                mapper
                    .map_data(addr, len, &data)
                    .map_err(MachoLoadError::Map)?;
            } else {
                mapper.map_anon(addr, len).map_err(MachoLoadError::Map)?;
            }
        }

        Ok(MappingInfo {
            entry_point: self.entry_point as usize + slide,
            brk,
        })
    }
}

fn parse_lc_string(raw_cmd_data: &[u8]) -> Result<String, MachoParseError> {
    if raw_cmd_data.len() < 12 {
        return Err(MachoParseError::InvalidLoadCommandString);
    }
    let name_offset = u32::from_le_bytes(
        raw_cmd_data[8..12]
            .try_into()
            .map_err(|_| MachoParseError::InvalidLoadCommandString)?,
    ) as usize;
    if name_offset >= raw_cmd_data.len() {
        return Err(MachoParseError::InvalidLoadCommandString);
    }
    let str_bytes = &raw_cmd_data[name_offset..];
    let nul_idx = str_bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or(MachoParseError::InvalidLoadCommandString)?;
    let value = core::str::from_utf8(&str_bytes[..nul_idx])
        .map_err(|_| MachoParseError::InvalidLoadCommandString)?;
    Ok(String::from(value))
}
