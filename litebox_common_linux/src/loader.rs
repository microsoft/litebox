// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ELF loader and mapper.
//!
//! Supports the following features:
//! * Parsing and mapping ELF binaries as the Linux kernel would when starting a
//!   new process, including both static and dynamic ELF binaries.
//! * Loading LiteBox trampoline code for syscall handling.

use alloc::vec::Vec;
use elf::file::FileHeader;
use litebox::{
    platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider},
    utils::{ReinterpretSignedExt as _, TruncateExt as _},
};
use thiserror::Error;
use zerocopy::FromBytes;

use crate::{HOST_PAGE_SIZE, errno::Errno, vmem::PAGE_SIZE};

type Endian = elf::endian::LittleEndian;

/// The result of parsing the ELF file headers.
///
/// Can be used to map the ELF into memory.
#[derive(Debug)]
pub struct ElfParsedFile {
    header: FileHeader<Endian>,
    phdrs: Vec<u8>,
    trampoline: Option<TrampolineInfo>,
}

/// Information about the mapped ELF file. This is used to set up the process
/// after loading the executable.
pub struct MappingInfo {
    /// The base address where the ELF file is mapped.
    pub base_addr: usize,
    /// The program break (end of all mapped segments).
    pub brk: usize,
    /// The entry point, where execution begins.
    pub entry_point: usize,
    /// The mapped address of the program headers.
    pub phdrs_addr: usize,
    /// The number of program headers.
    pub num_phdrs: usize,
}

impl MappingInfo {
    /// Returns the size of each program header entry.
    pub fn phent_size(&self) -> usize {
        match CLASS {
            elf::file::Class::ELF32 => size_of::<elf::segment::Elf32_Phdr>(),
            elf::file::Class::ELF64 => size_of::<elf::segment::Elf64_Phdr>(),
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Debug)]
struct TrampolineInfo {
    /// The virtual memory of the trampoline code.
    vaddr: usize,
    /// The file offset of the trampoline code in the ELF file.
    file_offset: u64,
    /// Size of the trampoline code in the ELF file.
    size: usize,
    /// The entry point to jump to in the trampoline.
    syscall_entry_point: usize,
}

/// An AArch64 ELF's trampoline: independently mapped sub-trampolines.
#[cfg(target_arch = "aarch64")]
#[derive(Debug)]
struct TrampolineInfo {
    /// The sub-trampolines, in file order.
    regions: Vec<TrampolineRegion>,
    /// The entry point to jump to in the trampoline.
    syscall_entry_point: usize,
}

#[cfg(target_arch = "aarch64")]
use litebox_syscall_rewriter::TrampolineRegion;

/// The pages `region` occupies when its object is loaded at `base_addr`.
#[cfg(target_arch = "aarch64")]
fn loaded_pages(region: &TrampolineRegion, base_addr: usize) -> Option<core::ops::Range<usize>> {
    let pages = region.page_range(PAGE_SIZE as u64)?;
    let start = base_addr.checked_add(usize::try_from(pages.start).ok()?)?;
    let end = base_addr.checked_add(usize::try_from(pages.end).ok()?)?;
    Some(start..end)
}

/// The magic number used to identify the LiteBox trampoline.
/// This must match `TRAMPOLINE_MAGIC` in `litebox_syscall_rewriter`.
const TRAMPOLINE_MAGIC: u64 = u64::from_le_bytes(*b"LITEBOX0");

/// Trampoline header for 64-bit: 8 (magic) + 8 (file_offset) + 8 (vaddr) + 8 (size) = 32 bytes
#[repr(C, packed)]
#[derive(FromBytes)]
pub struct TrampolineHeader64 {
    /// The format magic and version.
    pub magic: u64,
    /// The file offset of the trampoline code.
    pub file_offset: u64,
    /// The virtual address of the trampoline code.
    pub vaddr: u64,
    /// The size of the trampoline code.
    pub trampoline_size: u64,
}

/// Trampoline header for 32-bit: 8 (magic) + 4 (file_offset) + 4 (vaddr) + 4 (size) = 20 bytes
#[repr(C, packed)]
#[derive(FromBytes)]
struct TrampolineHeader32 {
    magic: u64,
    file_offset: u32,
    vaddr: u32,
    trampoline_size: u32,
}

/// Size in bytes of the trampoline header for the target pointer width.
pub const TRAMPOLINE_HEADER_SIZE: usize = if cfg!(target_pointer_width = "64") {
    size_of::<TrampolineHeader64>()
} else {
    size_of::<TrampolineHeader32>()
};

/// Location of the LiteBox trampoline code described by a validated trampoline header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrampolineLayout {
    /// File offset of the trampoline code.
    pub file_offset: u64,
    /// Virtual address of the trampoline code; relative to the load base for `ET_DYN`.
    pub vaddr: usize,
    /// Size of the trampoline code; zero if the rewriter found no syscalls to patch.
    pub size: usize,
}

/// Errors from decoding a LiteBox trampoline header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrampolineHeaderError {
    /// The header has the LiteBox prefix but an unsupported version.
    UnsupportedVersion,
    /// The header fields do not describe a valid trampoline layout.
    Malformed,
}

/// Decodes and validates a LiteBox trampoline header read from `header_offset`,
/// which must be the last [`TRAMPOLINE_HEADER_SIZE`] bytes of the file.
///
/// The expected file layout is `[ELF][padding][trampoline code][header]`.
/// Returns `Ok(None)` if the header does not carry the LiteBox magic.
pub fn parse_trampoline_header(
    header: &[u8; TRAMPOLINE_HEADER_SIZE],
    header_offset: u64,
) -> Result<Option<TrampolineLayout>, TrampolineHeaderError> {
    fn malformed<E>(_: E) -> TrampolineHeaderError {
        TrampolineHeaderError::Malformed
    }

    // Format: "LITEBOX" + version byte.
    if !header.starts_with(&TRAMPOLINE_MAGIC.to_le_bytes()) {
        return if header.starts_with(b"LITEBOX") {
            Err(TrampolineHeaderError::UnsupportedVersion)
        } else {
            Ok(None)
        };
    }

    let layout = if cfg!(target_pointer_width = "64") {
        let header = TrampolineHeader64::read_from_bytes(header).map_err(malformed)?;
        TrampolineLayout {
            file_offset: header.file_offset,
            vaddr: usize::try_from(header.vaddr).map_err(malformed)?,
            size: usize::try_from(header.trampoline_size).map_err(malformed)?,
        }
    } else {
        let header = TrampolineHeader32::read_from_bytes(header).map_err(malformed)?;
        TrampolineLayout {
            file_offset: u64::from(header.file_offset),
            vaddr: header.vaddr as usize,
            size: header.trampoline_size as usize,
        }
    };

    if layout.size == 0 {
        return Ok(Some(layout));
    }
    let valid = layout.file_offset.is_multiple_of(PAGE_SIZE as u64)
        && layout.vaddr.is_multiple_of(PAGE_SIZE)
        // The trampoline code must immediately precede the header.
        && layout.file_offset.checked_add(layout.size as u64) == Some(header_offset)
        // Reject ranges that cannot be represented so later address arithmetic cannot wrap.
        && layout
            .vaddr
            .checked_add(layout.size)
            .and_then(|end| end.checked_next_multiple_of(PAGE_SIZE))
            .is_some();
    if valid {
        Ok(Some(layout))
    } else {
        Err(TrampolineHeaderError::Malformed)
    }
}

const CLASS: elf::file::Class = if cfg!(target_pointer_width = "64") {
    elf::file::Class::ELF64
} else {
    elf::file::Class::ELF32
};

const MACHINE: u16 = if cfg!(target_arch = "x86_64") {
    elf::abi::EM_X86_64
} else if cfg!(target_arch = "aarch64") {
    elf::abi::EM_AARCH64
} else {
    panic!("unsupported arch")
};

fn page_align_down(address: usize) -> usize {
    address & !(PAGE_SIZE - 1)
}

fn page_align_up(len: usize) -> Option<usize> {
    len.checked_next_multiple_of(PAGE_SIZE)
}

/// Errors that can occur when parsing an ELF file.
#[derive(Debug, Error)]
pub enum ElfParseError<E> {
    #[error("ELF parsing error")]
    Elf(#[from] elf::parse::ParseError),
    #[error("Bad ELF format")]
    BadFormat,
    #[error("I/O error")]
    Io(#[source] E),
    #[error("Bad trampoline section")]
    BadTrampoline,
    #[error("Invalid trampoline version")]
    BadTrampolineVersion,
    #[error("Binary not patched for syscall rewriting")]
    UnpatchedBinary,
    #[error("Unsupported ELF type")]
    UnsupportedType,
    #[error("Bad interpreter")]
    BadInterp,
}

impl<E: Into<Errno>> From<ElfParseError<E>> for Errno {
    fn from(value: ElfParseError<E>) -> Self {
        match value {
            ElfParseError::Elf(_)
            | ElfParseError::BadFormat
            | ElfParseError::BadTrampoline
            | ElfParseError::BadTrampolineVersion
            | ElfParseError::UnpatchedBinary
            | ElfParseError::BadInterp
            | ElfParseError::UnsupportedType => Errno::ENOEXEC,
            ElfParseError::Io(err) => err.into(),
        }
    }
}

/// Errors that can occur when mapping an ELF file into memory.
#[derive(Debug, Error)]
pub enum ElfLoadError<E> {
    #[error("Memory mapping error")]
    Map(#[source] E),
    #[error("Invalid program header")]
    InvalidProgramHeader,
    #[error("Invalid trampoline version")]
    InvalidTrampolineVersion,
    #[error(transparent)]
    Fault(#[from] Fault),
}

impl<E: Into<Errno>> From<ElfLoadError<E>> for Errno {
    fn from(value: ElfLoadError<E>) -> Self {
        match value {
            ElfLoadError::InvalidProgramHeader | ElfLoadError::InvalidTrampolineVersion => {
                Errno::ENOEXEC
            }
            ElfLoadError::Fault(Fault) => Errno::EFAULT,
            ElfLoadError::Map(err) => err.into(),
        }
    }
}

impl ElfParsedFile {
    /// Parse an ELF file from the given file.
    pub fn parse<F: ReadAt>(file: &mut F) -> Result<Self, ElfParseError<F::Error>> {
        let mut buf = [0u8; size_of::<elf::file::Elf64_Ehdr>()];
        file.read_at(0, &mut buf).map_err(ElfParseError::Io)?;
        let ident = elf::file::parse_ident::<Endian>(&buf)?;
        if ident.1 != CLASS {
            return Err(ElfParseError::BadFormat);
        }
        let header = elf::file::FileHeader::parse_tail(ident, &buf[elf::abi::EI_NIDENT..])?;

        if header.e_type != elf::abi::ET_EXEC && header.e_type != elf::abi::ET_DYN {
            return Err(ElfParseError::UnsupportedType);
        }

        if header.e_machine != MACHINE {
            return Err(ElfParseError::UnsupportedType);
        }

        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if header.e_type != elf::abi::ET_DYN {
            // Darwin's reserved low address range cannot be replaced, so only relocatable ELFs are supported.
            return Err(ElfParseError::UnsupportedType);
        }

        // Read the program headers.
        let phent_size = if cfg!(target_pointer_width = "64") {
            size_of::<elf::segment::Elf64_Phdr>()
        } else {
            size_of::<elf::segment::Elf32_Phdr>()
        };
        if header.e_phnum == 0 || usize::from(header.e_phentsize) != phent_size {
            return Err(ElfParseError::BadFormat);
        }
        // Limit to 64KB of program headers.
        let phdr_size: u16 = header
            .e_phentsize
            .checked_mul(header.e_phnum)
            .ok_or(ElfParseError::BadFormat)?;

        let mut phdrs = alloc::vec![0u8; usize::from(phdr_size)];
        file.read_at(header.e_phoff, &mut phdrs)
            .map_err(ElfParseError::Io)?;

        // Callers use parsing as the recoverable exec preflight before replacing the old image.
        let table = elf::segment::SegmentTable::new(header.endianness, CLASS, &phdrs);
        for ph in table.iter().filter(|ph| ph.p_type == elf::abi::PT_LOAD) {
            if ph.p_filesz > ph.p_memsz
                || ph.p_vaddr.checked_add(ph.p_memsz).is_none()
                || ph.p_offset.checked_add(ph.p_filesz).is_none()
            {
                return Err(ElfParseError::BadFormat);
            }
        }

        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            // Reject LOADs that overlap after guest-page alignment.
            let mut ranges = alloc::vec::Vec::new();
            let table = elf::segment::SegmentTable::new(header.endianness, CLASS, &phdrs);
            for ph in table
                .iter()
                .filter(|ph| ph.p_type == elf::abi::PT_LOAD && ph.p_memsz != 0)
            {
                let page = PAGE_SIZE as u64;
                let end = ph
                    .p_vaddr
                    .checked_add(ph.p_memsz)
                    .and_then(|end| end.checked_next_multiple_of(page))
                    .ok_or(ElfParseError::BadFormat)?;
                let start = ph.p_vaddr & !(page - 1);
                if ph.p_offset % page != ph.p_vaddr % page
                    || ph.p_flags & (elf::abi::PF_W | elf::abi::PF_X)
                        == (elf::abi::PF_W | elf::abi::PF_X)
                    || ranges
                        .iter()
                        .any(|r: &core::ops::Range<u64>| r.start < end && start < r.end)
                {
                    return Err(ElfParseError::BadFormat);
                }
                ranges.push(start..end);
            }
        }

        Ok(ElfParsedFile {
            header,
            phdrs,
            trampoline: None,
        })
    }

    /// Returns `true` if a trampoline was parsed and will be mapped by `load()`.
    pub fn has_trampoline(&self) -> bool {
        self.trampoline.is_some()
    }

    /// The pages the trampoline occupies when this ELF is loaded at `base_addr`;
    /// a zero `base_addr` yields the load-address-relative range.
    ///
    /// `None` if the binary has no trampoline or, like [`Self::has_trampoline`],
    /// if [`Self::parse_trampoline`] has not run yet.
    #[cfg(target_arch = "x86_64")]
    pub fn trampoline_page_range(&self, base_addr: usize) -> Option<core::ops::Range<usize>> {
        let trampoline = self.trampoline.as_ref()?;
        let start = base_addr.checked_add(trampoline.vaddr)?;
        let end = start
            .checked_add(trampoline.size)?
            .checked_next_multiple_of(PAGE_SIZE)?;
        Some(start..end)
    }

    /// The independently mapped sub-trampolines of the parsed trampoline.
    #[cfg(target_arch = "aarch64")]
    pub fn trampoline_regions(&self) -> &[TrampolineRegion] {
        self.trampoline
            .as_ref()
            .map_or(&[], |trampoline| trampoline.regions.as_slice())
    }

    /// Parse the LiteBox trampoline data, if any.
    ///
    /// The trampoline header is located at the end of the file (last 32/20 bytes).
    /// The trampoline code starts at a page-aligned offset before the header.
    /// File layout: `[ELF][padding][trampoline code][header]`
    ///
    /// `syscall_entry_point` is the address of the syscall entry point to write
    /// into the trampoline at map time.
    #[cfg(target_arch = "x86_64")]
    pub fn parse_trampoline<F: ReadAt>(
        &mut self,
        file: &mut F,
        syscall_entry_point: usize,
    ) -> Result<(), ElfParseError<F::Error>> {
        if syscall_entry_point == 0 {
            // Platform running in kernel mode does not need trampoline
            // and may give zero as entry point.
            return Ok(());
        }

        let file_size = file.size().map_err(ElfParseError::Io)?;

        // File must be large enough to contain the header
        let Some(header_offset) = file_size.checked_sub(TRAMPOLINE_HEADER_SIZE as u64) else {
            // Too small for a trampoline header — binary is unpatched.
            return Err(ElfParseError::UnpatchedBinary);
        };

        // Read the header from the end of the file
        let mut header_buf = [0u8; TRAMPOLINE_HEADER_SIZE];
        file.read_at(header_offset, &mut header_buf)
            .map_err(ElfParseError::Io)?;

        let layout = match parse_trampoline_header(&header_buf, header_offset) {
            Ok(Some(layout)) => layout,
            Ok(None) => return Err(ElfParseError::UnpatchedBinary),
            Err(TrampolineHeaderError::UnsupportedVersion) => {
                return Err(ElfParseError::BadTrampolineVersion);
            }
            Err(TrampolineHeaderError::Malformed) => return Err(ElfParseError::BadTrampoline),
        };

        // A zero size means the rewriter checked this binary and found no
        // syscall instructions.
        if layout.size == 0 {
            return Ok(());
        }

        self.trampoline = Some(TrampolineInfo {
            vaddr: layout.vaddr,
            size: layout.size,
            file_offset: layout.file_offset,
            syscall_entry_point,
        });
        Ok(())
    }

    /// Parse the LiteBox trampoline data of an AArch64 ELF, if any.
    ///
    /// See [`read_trampoline_regions`] for the file layout.
    ///
    /// `syscall_entry_point` is the address of the syscall entry point to write
    /// into every sub-trampoline at map time.
    #[cfg(target_arch = "aarch64")]
    pub fn parse_trampoline<F: ReadAt>(
        &mut self,
        file: &mut F,
        syscall_entry_point: usize,
    ) -> Result<(), ElfParseError<F::Error>> {
        if syscall_entry_point == 0 {
            // Platform running in kernel mode does not need trampoline
            // and may give zero as entry point.
            return Ok(());
        }

        let segments: Vec<core::ops::Range<u64>> = self
            .pt_loads()
            .map(|ph| ph.p_vaddr..ph.p_vaddr.saturating_add(ph.p_memsz))
            .collect();
        let regions = read_trampoline_regions(file, &segments)?;
        // No regions means the rewriter checked this binary and found no
        // syscall instructions.
        if !regions.is_empty() {
            self.trampoline = Some(TrampolineInfo {
                regions,
                syscall_entry_point,
            });
        }
        Ok(())
    }

    fn program_headers(
        &self,
    ) -> elf::parse::ParsingIterator<'_, Endian, elf::segment::ProgramHeader> {
        elf::parse::ParsingIterator::new(self.header.endianness, self.header.class, &self.phdrs)
    }

    /// Read the interpreter path, if any.
    #[expect(clippy::missing_panics_doc, reason = "cannot panic")]
    pub fn interp<F: ReadAt>(
        &self,
        file: &mut F,
    ) -> Result<Option<alloc::ffi::CString>, ElfParseError<F::Error>> {
        let Some(ph) = self
            .program_headers()
            .find(|ph| ph.p_type == elf::abi::PT_INTERP)
        else {
            return Ok(None);
        };
        // Bound the interpreter length like Linux.
        let len: usize = ph.p_filesz.trunc();
        if !(2..4096).contains(&len) {
            return Err(ElfParseError::BadInterp);
        }
        let mut buf = alloc::vec![0u8; len + 1];
        file.read_at(ph.p_offset, &mut buf[..len])
            .map_err(ElfParseError::Io)?;
        buf.truncate(
            buf.iter()
                .position(|&b| b == 0)
                .expect("we null terminated it at allocation time"),
        );
        Ok(Some(
            alloc::ffi::CString::new(buf).expect("truncated away null bytes"),
        ))
    }

    fn pt_loads(&self) -> impl Iterator<Item = elf::segment::ProgramHeader> + '_ {
        self.program_headers()
            .filter(|ph| ph.p_type == elf::abi::PT_LOAD)
    }

    /// Load the ELF file into memory.
    pub fn load<M: MapMemory>(
        &self,
        mapper: &mut M,
        mem: &mut impl AccessMemory,
        reserve_trampoline: Option<usize>,
    ) -> Result<MappingInfo, ElfLoadError<M::Error>> {
        let base_addr = if self.header.e_type == elf::abi::ET_DYN {
            // Find an aligned load address that will fit all PT_LOAD segments.
            let mut min = usize::MAX;
            let mut max = 0usize;
            let mut align = PAGE_SIZE;
            for ph in self.pt_loads() {
                min = min.min(ph.p_vaddr.trunc());
                max = max.max(
                    (ph.p_vaddr
                        .checked_add(ph.p_memsz)
                        .ok_or(ElfLoadError::InvalidProgramHeader)?)
                    .trunc(),
                );
                if ph.p_align.is_power_of_two() {
                    align = align.max(ph.p_align.trunc());
                }
            }
            #[cfg(target_arch = "x86_64")]
            if let Some(trampoline) = &self.trampoline {
                min = min.min(trampoline.vaddr);
                max = max.max(
                    trampoline
                        .vaddr
                        .checked_add(trampoline.size)
                        .ok_or(ElfLoadError::InvalidProgramHeader)?,
                );
            }
            #[cfg(target_arch = "aarch64")]
            for region in self.trampoline_regions() {
                let pages = loaded_pages(region, 0).ok_or(ElfLoadError::InvalidProgramHeader)?;
                min = min.min(pages.start);
                max = max.max(pages.end);
            }
            let min = page_align_down(min);
            let max = max
                .checked_next_multiple_of(PAGE_SIZE)
                .ok_or(ElfLoadError::InvalidProgramHeader)?;
            let span = max
                .checked_sub(min)
                .ok_or(ElfLoadError::InvalidProgramHeader)?;
            if span == 0 {
                return Err(ElfLoadError::InvalidProgramHeader);
            }
            mapper.reserve(span, align).map_err(ElfLoadError::Map)?
        } else {
            // For ET_EXEC, load at the fixed addresses specified in the ELF.
            0
        };

        let checked_add =
            |a: usize, b: usize| a.checked_add(b).ok_or(ElfLoadError::InvalidProgramHeader);
        let mut brk = 0;
        let mut phdrs_addr = 0;
        for ph in self.pt_loads() {
            let p_vaddr: usize = ph.p_vaddr.trunc();
            let p_memsz: usize = ph.p_memsz.trunc();
            let p_filesz: usize = ph.p_filesz.trunc();
            if p_memsz < p_filesz
                || p_vaddr.checked_add(p_memsz).is_none()
                || ph.p_offset.checked_add(ph.p_filesz).is_none()
            {
                return Err(ElfLoadError::InvalidProgramHeader);
            }
            let prot = Protection {
                read: true,
                write: (ph.p_flags & elf::abi::PF_W) != 0,
                execute: (ph.p_flags & elf::abi::PF_X) != 0,
            };
            let adjusted_vaddr = checked_add(base_addr, p_vaddr)?;
            let load_start = page_align_down(adjusted_vaddr);
            let file_end = page_align_up(checked_add(adjusted_vaddr, p_filesz)?)
                .ok_or(ElfLoadError::InvalidProgramHeader)?;
            let load_end = page_align_up(checked_add(adjusted_vaddr, p_memsz)?)
                .ok_or(ElfLoadError::InvalidProgramHeader)?;
            if file_end > load_start {
                // Map the file-backed portion.
                // `p_offset` should be co-aligned with `p_vaddr`. If it is not,
                // then `map_file` is expected to fail.
                let offset = ph
                    .p_offset
                    .wrapping_sub((adjusted_vaddr - load_start) as u64);
                mapper
                    .map_file(load_start, file_end - load_start, offset, &prot)
                    .map_err(ElfLoadError::Map)?;
                // Zero out the remaining part of the last page.
                //
                // The behavior here is not quite what you might expect. We zero
                // the remainder of the last page, even if that's beyond
                // `p_memsz`--this is necessary because common binaries seem to
                // depend on it. But we only do this if `p_memsz` is beyond
                // `p_filesz` and the segment is writable. This matches other
                // loaders' behavior, so it should be sufficient.
                if p_memsz > p_filesz && ph.p_flags & elf::abi::PF_W != 0 {
                    let unaligned_file_end = adjusted_vaddr + p_filesz;
                    if file_end > unaligned_file_end {
                        mem.zero(unaligned_file_end, file_end - unaligned_file_end)?;
                    }
                }
            }
            if load_end > file_end {
                // Map the zero-filled portion.
                mapper
                    .map_zero(file_end, load_end - file_end, &prot)
                    .map_err(ElfLoadError::Map)?;
            }

            // Update the end address of the last PT_LOAD segment.
            brk = brk.max(load_end);

            // Track the location of the program headers in memory; this is used
            // for `AT_PHDR`.
            if ph.p_offset <= self.header.e_phoff && self.header.e_phoff < ph.p_offset + ph.p_filesz
            {
                let offset_in_segment: usize = (self.header.e_phoff - ph.p_offset).trunc();
                phdrs_addr = adjusted_vaddr + offset_in_segment;
            }
        }

        let mut info = MappingInfo {
            base_addr,
            brk,
            entry_point: base_addr.wrapping_add(self.header.e_entry.trunc()),
            phdrs_addr,
            num_phdrs: self.header.e_phnum.into(),
        };

        if self.trampoline.is_some() {
            self.load_trampoline(mapper, mem, &mut info)?;
        } else if let Some(size) = reserve_trampoline {
            // Reserve space for a runtime trampoline so brk starts past it.
            // The runtime patching path (do_mmap_file → maybe_patch_exec_segment)
            // will allocate the actual trampoline in this region via MAP_FIXED.
            // Match the runtime rewriter's native-page-aligned placement.
            info.brk = info
                .brk
                .checked_next_multiple_of(HOST_PAGE_SIZE)
                .and_then(|start| page_align_up(size).and_then(|size| start.checked_add(size)))
                .ok_or(ElfLoadError::InvalidProgramHeader)?;
        }

        // The initial writable brk heap must not share native backing with an
        // executable LOAD or trampoline. Guest mmap/mprotect still use the guest page size.
        info.brk = info.brk.next_multiple_of(HOST_PAGE_SIZE);
        Ok(info)
    }

    /// Load the LiteBox trampoline into memory.
    #[cfg(target_arch = "x86_64")]
    fn load_trampoline<M: MapMemory>(
        &self,
        mapper: &mut M,
        mem: &mut impl AccessMemory,
        info: &mut MappingInfo,
    ) -> Result<(), ElfLoadError<M::Error>> {
        let trampoline = self.trampoline.as_ref().unwrap();
        let range = self
            .trampoline_page_range(info.base_addr)
            .ok_or(ElfLoadError::InvalidProgramHeader)?;
        let trampoline_start = range.start;
        let trampoline_end = range.end;
        if M::POPULATES_TRAMPOLINE {
            info.brk = info.brk.max(trampoline_end);
            return Ok(());
        }
        debug_assert!(
            trampoline.file_offset.is_multiple_of(PAGE_SIZE as u64),
            "non-populating loaders map the trampoline directly from its file offset"
        );
        mapper
            .map_file(
                trampoline_start,
                trampoline_end - trampoline_start,
                trampoline.file_offset,
                &Protection {
                    read: true,
                    write: true,
                    execute: false,
                },
            )
            .map_err(ElfLoadError::Map)?;

        // Write the trampoline entry point at the start of the trampoline code.
        // The first 8 bytes (64-bit) or 4 bytes (32-bit) are reserved for the entry point.
        mem.write(
            trampoline_start,
            &trampoline.syscall_entry_point.to_ne_bytes(),
        )?;

        // Now that the write is done, protect the trampoline code as
        // read+execute only.
        mapper
            .protect(
                trampoline_start,
                trampoline_end - trampoline_start,
                &Protection {
                    read: true,
                    write: false,
                    execute: true,
                },
            )
            .map_err(ElfLoadError::Map)?;

        info.brk = info.brk.max(trampoline_end);
        Ok(())
    }

    /// Load an AArch64 ELF's trampoline into memory, one sub-trampoline at a
    /// time.
    #[cfg(target_arch = "aarch64")]
    fn load_trampoline<M: MapMemory>(
        &self,
        mapper: &mut M,
        mem: &mut impl AccessMemory,
        info: &mut MappingInfo,
    ) -> Result<(), ElfLoadError<M::Error>> {
        let trampoline = self.trampoline.as_ref().unwrap();
        for region in &trampoline.regions {
            let range =
                loaded_pages(region, info.base_addr).ok_or(ElfLoadError::InvalidProgramHeader)?;
            let trampoline_start = range.start;
            let trampoline_end = range.end;
            if M::POPULATES_TRAMPOLINE {
                info.brk = info.brk.max(trampoline_end);
                continue;
            }
            debug_assert!(
                region.file_offset.is_multiple_of(PAGE_SIZE as u64),
                "non-populating loaders map the trampoline directly from its file offset"
            );
            mapper
                .map_file(
                    trampoline_start,
                    trampoline_end - trampoline_start,
                    region.file_offset,
                    &Protection {
                        read: true,
                        write: true,
                        execute: false,
                    },
                )
                .map_err(ElfLoadError::Map)?;

            // Each region starts with its own callback slot.
            mem.write(
                trampoline_start,
                &trampoline.syscall_entry_point.to_ne_bytes(),
            )?;

            mapper
                .protect(
                    trampoline_start,
                    trampoline_end - trampoline_start,
                    &Protection {
                        read: true,
                        write: false,
                        execute: true,
                    },
                )
                .map_err(ElfLoadError::Map)?;

            info.brk = info.brk.max(trampoline_end);
        }
        Ok(())
    }

    /// Load the secondary LiteBox trampoline into memory whose location is relative to
    /// the based address which is the difference of `loaded_entry_point` and `e_entry`
    /// in the ELF header.
    pub fn load_secondary_trampoline<M: MapMemory>(
        &self,
        mapper: &mut M,
        mem: &mut impl AccessMemory,
        loaded_entry_point: usize,
    ) -> Result<(), ElfLoadError<M::Error>> {
        // If there's no trampoline, nothing to do.
        if self.trampoline.is_none() {
            return Ok(());
        }
        let base_addr = loaded_entry_point
            .checked_sub(self.header.e_entry.trunc())
            .ok_or(ElfLoadError::InvalidProgramHeader)?;
        let mut info = MappingInfo {
            base_addr,
            brk: 0,
            entry_point: 0,
            phdrs_addr: 0,
            num_phdrs: 0,
        };
        self.load_trampoline(mapper, mem, &mut info)
    }
}

/// Reads the sub-trampoline table the LiteBox rewriter appends to an AArch64
/// ELF; see [`litebox_syscall_rewriter::parse_aarch64_trampoline_footer`].
/// Additionally rejects any region whose pages overlap those of one of
/// `segments`, the object's `PT_LOAD` address ranges, since mapping it would
/// replace the object's own memory.
///
/// Returns the regions in file order, which is empty when nothing was patched.
///
/// # Errors
///
/// [`ElfParseError::UnpatchedBinary`] if the file carries no LiteBox trailer,
/// [`ElfParseError::BadTrampolineVersion`] for an unknown `LITEBOX` version,
/// and [`ElfParseError::BadTrampoline`] for a malformed table.
#[cfg(target_arch = "aarch64")]
pub fn read_trampoline_regions<F: ReadAt>(
    file: &mut F,
    segments: &[core::ops::Range<u64>],
) -> Result<Vec<TrampolineRegion>, ElfParseError<F::Error>> {
    use litebox_syscall_rewriter::{
        AARCH64_TRAMPOLINE_FOOTER_BYTES, TrampolineTableError, parse_aarch64_trampoline_footer,
        parse_aarch64_trampoline_table,
    };
    let table_error = |error| match error {
        TrampolineTableError::UnknownVersion => ElfParseError::BadTrampolineVersion,
        TrampolineTableError::Malformed => ElfParseError::BadTrampoline,
    };

    let file_len = file.size().map_err(ElfParseError::Io)?;
    let footer_offset = file_len
        .checked_sub(AARCH64_TRAMPOLINE_FOOTER_BYTES as u64)
        .ok_or(ElfParseError::UnpatchedBinary)?;
    let mut footer = [0u8; AARCH64_TRAMPOLINE_FOOTER_BYTES];
    file.read_at(footer_offset, &mut footer)
        .map_err(ElfParseError::Io)?;
    let location = parse_aarch64_trampoline_footer(&footer, file_len)
        .map_err(table_error)?
        .ok_or(ElfParseError::UnpatchedBinary)?;
    let mut table = alloc::vec![0u8; location.len];
    file.read_at(location.file_offset, &mut table)
        .map_err(ElfParseError::Io)?;
    let regions = parse_aarch64_trampoline_table(&table, location).map_err(table_error)?;

    let page = PAGE_SIZE as u64;
    let segment_pages = |segment: &core::ops::Range<u64>| {
        segment.start & !(page - 1)
            ..segment
                .end
                .checked_next_multiple_of(page)
                .unwrap_or(u64::MAX)
    };
    for region in &regions {
        let pages = region
            .page_range(page)
            .ok_or(ElfParseError::BadTrampoline)?;
        if loaded_pages(region, 0).is_none()
            || segments
                .iter()
                .map(segment_pages)
                .any(|segment| segment.start < pages.end && pages.start < segment.end)
        {
            return Err(ElfParseError::BadTrampoline);
        }
    }
    Ok(regions)
}

/// Trait for reading ELF binary data at specific offsets.
pub trait ReadAt {
    /// The error type for read operations.
    type Error;

    /// Read data at the specified offset into the provided buffer.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error>;

    /// Get the length of the ELF file.
    fn size(&mut self) -> Result<u64, Self::Error>;
}

pub trait MapMemory {
    type Error;

    /// When true, trampoline setup occurs outside [`ElfParsedFile::load`]; the
    /// loader only advances `brk` past the declared range.
    const POPULATES_TRAMPOLINE: bool = false;

    /// Reserve a region of memory with the given length and alignment,
    /// returning the chosen address.
    ///
    /// `align` must be a power of two. Fails if any of the parameters are not
    /// page-aligned.
    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error>;

    /// Map file data, replacing any existing mappings.
    ///
    /// Fails if any of the parameters are not page-aligned.
    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &Protection,
    ) -> Result<(), Self::Error>;

    /// Map zeroed memory, replacing any existing mappings.
    ///
    /// Fails if any of the parameters are not page-aligned.
    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &Protection,
    ) -> Result<(), Self::Error>;

    /// Change protections of a memory region.
    ///
    /// Fails if any of the parameters are not page-aligned.
    fn protect(&mut self, address: usize, len: usize, prot: &Protection)
    -> Result<(), Self::Error>;
}

/// The result of computing the head/tail trim regions for an over-sized
/// anonymous reservation made by [`MapMemory::reserve`].
///
/// See [`compute_reserved_regions`] for details.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ReservedRegions {
    /// Base address of the requested `len` bytes inside the over-sized
    /// reservation, aligned up to the `align` argument passed to
    /// [`compute_reserved_regions`].
    pub aligned_ptr: usize,
    /// `(start, len)` of the page-aligned head slice that should be
    /// released with `munmap`, or `None` if no head trim is needed.
    pub head_unmap: Option<(usize, usize)>,
    /// `(start, len)` of the page-aligned tail slice that should be
    /// released with `munmap`, or `None` if no tail trim is needed.
    pub tail_unmap: Option<(usize, usize)>,
}

/// Given an over-sized anonymous reservation `[mapping_ptr, mapping_ptr +
/// mapping_len)` returned by `mmap`, compute the `align`-aligned sub-range
/// of length `len` to keep, plus the page-aligned head and tail slices to
/// release with `munmap`.
///
/// `mmap`/`munmap` operate at page granularity, so this helper is careful
/// to round both the head slice and the tail slice to whole pages:
///
/// * `mapping_ptr` is assumed to be page-aligned (the kernel guarantees
///   this) and `align` is assumed to be a multiple of `PAGE_SIZE`, so the
///   head slice is naturally page-aligned.
/// * `len` (the caller's requested length — typically an ELF's
///   `max_vaddr - min_vaddr` span) is **not** required to be page-aligned.
///   The kernel rounds the original `mmap` allocation up to a whole number
///   of pages, so the actual mapped region extends to
///   `(mapping_ptr + mapping_len).next_multiple_of(PAGE_SIZE)`. The tail
///   slice is computed in page units: release everything from the first
///   page strictly after `aligned_ptr + len` to that page-aligned end.
///
/// Prior to this helper, callers used `(aligned_ptr + len, mapping_end -
/// (aligned_ptr + len))` directly as the tail `munmap` args. Whenever
/// `len` ended mid-page (e.g. node.js's prebuilt linux-x64 binary has a
/// PT_LOAD span of `0x6403D68`), the kernel rejected the `munmap` with
/// `EINVAL`, surfacing as `execve` → `ENOEXEC` for any guest fork+exec
/// of node.
pub fn compute_reserved_regions(
    mapping_ptr: usize,
    mapping_len: usize,
    len: usize,
    align: usize,
) -> ReservedRegions {
    let aligned_ptr = mapping_ptr.next_multiple_of(align);
    let end = aligned_ptr + len;
    let mapping_end = mapping_ptr + mapping_len;
    // The kernel rounds the mmap allocation up to a whole number of pages,
    // so the *actual* mapped region is
    // `[mapping_ptr, mapping_end.next_multiple_of(PAGE_SIZE))`.
    let mapping_end_aligned = mapping_end.next_multiple_of(PAGE_SIZE);

    let head_unmap = if aligned_ptr == mapping_ptr {
        None
    } else {
        Some((mapping_ptr, aligned_ptr - mapping_ptr))
    };

    let tail_start = end.next_multiple_of(PAGE_SIZE);
    let tail_unmap = if tail_start < mapping_end_aligned {
        Some((tail_start, mapping_end_aligned - tail_start))
    } else {
        None
    };

    ReservedRegions {
        aligned_ptr,
        head_unmap,
        tail_unmap,
    }
}

/// Trait for reading and writing memory that has been mapped via [`MapMemory`].
pub trait AccessMemory {
    /// Read from memory.
    fn read(&mut self, address: usize, buf: &mut [u8]) -> Result<usize, Fault>;

    /// Write to memory.
    fn write(&mut self, address: usize, data: &[u8]) -> Result<(), Fault>;

    /// Zero out a region of memory.
    fn zero(&mut self, address: usize, len: usize) -> Result<(), Fault>;
}

impl<Platform: RawPointerProvider> AccessMemory for &Platform {
    fn read(&mut self, address: usize, buf: &mut [u8]) -> Result<usize, Fault> {
        let addr = Platform::RawConstPointer::<u8>::from_usize(address);
        buf.copy_from_slice(&addr.to_owned_slice(buf.len()).ok_or(Fault)?);
        Ok(buf.len())
    }

    fn write(&mut self, address: usize, data: &[u8]) -> Result<(), Fault> {
        let addr = Platform::RawMutPointer::<u8>::from_usize(address);
        addr.copy_from_slice(0, data).ok_or(Fault)
    }

    fn zero(&mut self, address: usize, len: usize) -> Result<(), Fault> {
        let addr = Platform::RawMutPointer::<u8>::from_usize(address);
        // TODO: add a fill method to [`RawMutPointer`] and use it.
        for i in 0..len {
            addr.write_at_offset(i.reinterpret_as_signed(), 0)
                .ok_or(Fault)?;
        }
        Ok(())
    }
}

/// An error indicating a memory access fault.
#[derive(Debug, Error)]
#[error("Memory access fault")]
pub struct Fault;

/// Memory protection flags.
#[derive(Debug, Copy, Clone)]
pub struct Protection {
    /// Read permission.
    pub read: bool,
    /// Write permission.
    pub write: bool,
    /// Execute permission.
    pub execute: bool,
}

impl Protection {
    /// Converts the protection flags to Linux `PROT_*` flags.
    pub fn flags(&self) -> crate::ProtFlags {
        let mut flags = crate::ProtFlags::empty();
        if self.read {
            flags |= crate::ProtFlags::PROT_READ;
        }
        if self.write {
            flags |= crate::ProtFlags::PROT_WRITE;
        }
        if self.execute {
            flags |= crate::ProtFlags::PROT_EXEC;
        }
        flags
    }
}

#[cfg(test)]
mod reserve_regions_tests {
    extern crate std;
    use super::{PAGE_SIZE, ReservedRegions, compute_reserved_regions};

    /// The exact non-page-aligned PT_LOAD span observed for the prebuilt
    /// linux-x64 node.js binary in the `litebox-test` Docker image, which
    /// triggered the EINVAL fault on every guest fork+exec of node prior
    /// to commit 05b091ba.
    const NODE_LEN: usize = 0x6403D68;

    /// A non-page-aligned `mapping_len` doesn't really happen in practice
    /// (callers always pass `len + (align.max(PAGE_SIZE) - PAGE_SIZE)`),
    /// but we test the helper's tolerance to it anyway, because the kernel
    /// rounds up to whole pages and so should we.
    fn assert_page_aligned(regions: &ReservedRegions) {
        if let Some((addr, size)) = regions.head_unmap {
            assert_eq!(addr % PAGE_SIZE, 0, "head start not page-aligned");
            assert_eq!(size % PAGE_SIZE, 0, "head size not page-aligned");
        }
        if let Some((addr, size)) = regions.tail_unmap {
            assert_eq!(addr % PAGE_SIZE, 0, "tail start not page-aligned");
            assert_eq!(size % PAGE_SIZE, 0, "tail size not page-aligned");
        }
    }

    /// Reservation matches request exactly (`align == PAGE_SIZE`): no
    /// head or tail trim needed when `len` is a page multiple.
    #[test]
    fn page_aligned_len_no_trim() {
        let mapping_ptr = 0x4000_0000;
        let len = 0x10_0000; // 1 MiB, page-aligned
        let align = PAGE_SIZE;
        let mapping_len = len + (align.max(PAGE_SIZE) - PAGE_SIZE);
        let r = compute_reserved_regions(mapping_ptr, mapping_len, len, align);
        assert_eq!(r.aligned_ptr, mapping_ptr);
        assert_eq!(r.head_unmap, None);
        assert_eq!(r.tail_unmap, None);
        assert_page_aligned(&r);
    }

    /// Larger `align` than PAGE_SIZE: head trim happens when `mapping_ptr`
    /// isn't already aligned to `align`; tail trim mirrors the slack.
    #[test]
    fn larger_align_trims_head_and_tail() {
        let align = 0x10_0000; // 1 MiB
        let len = 0x1234_0000; // page-aligned
        let mapping_len = len + (align - PAGE_SIZE);
        // mapping_ptr page-aligned but not align-aligned.
        let mapping_ptr = 0x4000_0000 + PAGE_SIZE;
        let r = compute_reserved_regions(mapping_ptr, mapping_len, len, align);
        assert_eq!(r.aligned_ptr % align, 0);
        assert!(r.aligned_ptr >= mapping_ptr);
        assert!(r.aligned_ptr + len <= mapping_ptr + mapping_len);
        // Total trimmed = (align - PAGE_SIZE).
        let head = r.head_unmap.map_or(0, |(_, s)| s);
        let tail = r.tail_unmap.map_or(0, |(_, s)| s);
        assert_eq!(head + tail, align - PAGE_SIZE);
        assert_page_aligned(&r);
    }

    /// With `align == PAGE_SIZE` the over-allocation slack is zero so the
    /// old formula's `if end != mapping_end` check happened to skip the
    /// `munmap` entirely — even though `end` was non-page-aligned. The new
    /// helper reaches the same "no tail trim" conclusion the right way:
    /// `tail_start = end.next_multiple_of(PAGE_SIZE)` equals the
    /// page-rounded mapping end.
    #[test]
    fn node_align_page_size_no_tail_trim_needed() {
        let mapping_ptr = 0x4000_0000;
        let align = PAGE_SIZE;
        let len = NODE_LEN;
        let mapping_len = len + (align.max(PAGE_SIZE) - PAGE_SIZE);
        let r = compute_reserved_regions(mapping_ptr, mapping_len, len, align);
        assert_eq!(r.aligned_ptr, mapping_ptr);
        assert_eq!(r.head_unmap, None);
        assert_eq!(r.tail_unmap, None);
        assert_page_aligned(&r);
    }

    /// Stronger version of the node case: non-page-aligned `len` with a
    /// larger `align`, so the trailing slack actually does require a tail
    /// `munmap`. Under the old formula, the tail munmap start was
    /// `aligned_ptr + len` (non-page-aligned) and the kernel rejected it.
    /// Under the helper, the tail start is rounded up to the next page.
    #[test]
    fn non_page_aligned_len_with_large_align_trims_page_aligned_tail() {
        let align = 0x20_0000_usize; // 2 MiB
        let len = NODE_LEN; // ends at 0xD68 within a page
        let mapping_len = len + (align - PAGE_SIZE);
        let mapping_ptr = 0x4000_0000_usize; // page-aligned but not 2 MiB-aligned

        // Old formula tail args.
        let old_aligned_ptr = mapping_ptr.next_multiple_of(align);
        let old_end = old_aligned_ptr + len;
        let old_mapping_end = mapping_ptr + mapping_len;
        let old_tail_size = old_mapping_end - old_end;
        assert_ne!(
            old_end % PAGE_SIZE,
            0,
            "old tail start would be non-page-aligned (the EINVAL trigger)",
        );
        assert_eq!(
            old_tail_size % PAGE_SIZE,
            0,
            "old tail size happened to be page-aligned",
        );

        let r = compute_reserved_regions(mapping_ptr, mapping_len, len, align);
        assert_eq!(r.aligned_ptr, old_aligned_ptr);
        let (tail_start, tail_size) = r.tail_unmap.expect("tail trim expected with large align");
        // Tail covers everything from the page after the requested end to
        // the page-rounded end of the actual reservation.
        let page_end = (r.aligned_ptr + len).next_multiple_of(PAGE_SIZE);
        let mapping_end_aligned = old_mapping_end.next_multiple_of(PAGE_SIZE);
        assert_eq!(tail_start, page_end);
        assert_eq!(tail_size, mapping_end_aligned - tail_start);
        // The page that contains the last byte of the reserved range stays
        // mapped (the caller still owns up to byte `aligned_ptr + len`).
        assert!(tail_start >= r.aligned_ptr + len);
        assert_page_aligned(&r);
    }

    /// Head and tail trim sizes together exhaust the over-allocation slack.
    #[test]
    fn head_plus_tail_equals_slack_when_len_page_aligned() {
        let align = 0x40_0000; // 4 MiB
        let page_aligned_len = 0x80_0000;
        let mapping_len = page_aligned_len + (align - PAGE_SIZE);
        for offset_pages in 0..8 {
            let mapping_ptr = 0x4000_0000 + offset_pages * PAGE_SIZE;
            let r = compute_reserved_regions(mapping_ptr, mapping_len, page_aligned_len, align);
            assert_eq!(r.aligned_ptr % align, 0);
            let head = r.head_unmap.map_or(0, |(_, s)| s);
            let tail = r.tail_unmap.map_or(0, |(_, s)| s);
            assert_eq!(head + tail, align - PAGE_SIZE);
            assert_page_aligned(&r);
        }
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod aarch64_trampoline_footer_tests {
    use super::{ElfParseError, ReadAt, TrampolineRegion, read_trampoline_regions};
    use alloc::vec::Vec;

    struct Bytes(Vec<u8>);

    impl ReadAt for Bytes {
        type Error = ();

        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ()> {
            let start = usize::try_from(offset).map_err(|_| ())?;
            let end = start.checked_add(buf.len()).ok_or(())?;
            buf.copy_from_slice(self.0.get(start..end).ok_or(())?);
            Ok(())
        }

        fn size(&mut self) -> Result<u64, ()> {
            Ok(self.0.len() as u64)
        }
    }

    fn push_u64s(out: &mut Vec<u8>, words: &[u64]) {
        for word in words {
            out.extend_from_slice(&word.to_le_bytes());
        }
    }

    #[test]
    fn unpatched_and_unknown_versions_are_reported() {
        assert!(matches!(
            read_trampoline_regions(&mut Bytes(alloc::vec![0u8; 0x80]), &[]),
            Err(ElfParseError::UnpatchedBinary)
        ));
        let mut future = alloc::vec![0u8; 0x80];
        future.extend_from_slice(b"LITEBOX9");
        push_u64s(&mut future, &[0, 0, 0]);
        assert!(matches!(
            read_trampoline_regions(&mut Bytes(future), &[]),
            Err(ElfParseError::BadTrampolineVersion)
        ));
    }

    /// `[0x1000 bytes][sub-trampoline of `size` bytes at `vaddr`]...[table][footer]`.
    fn aarch64_file(regions: &[(u64, u64)]) -> (Vec<u8>, Vec<TrampolineRegion>) {
        let mut out = alloc::vec![0u8; 0x1000];
        let mut table = Vec::new();
        let mut expected = Vec::new();
        for &(vaddr, size) in regions {
            out.resize(out.len().next_multiple_of(0x1000), 0);
            let file_offset = out.len() as u64;
            push_u64s(&mut table, &[file_offset, vaddr, size]);
            expected.push(TrampolineRegion {
                file_offset,
                vaddr,
                size,
            });
            out.resize(out.len() + usize::try_from(size).unwrap(), 0xAA);
        }
        let table_offset = out.len() as u64;
        out.extend_from_slice(&table);
        out.extend_from_slice(b"LITEBOX0");
        push_u64s(&mut out, &[table_offset, regions.len() as u64, 0]);
        (out, expected)
    }

    #[test]
    fn aarch64_sub_trampolines_are_read_in_file_order() {
        let (file, expected) = aarch64_file(&[(0x5000, 0x1010), (0x2000, 0x40), (0x9000, 0x800)]);
        assert_eq!(
            read_trampoline_regions(&mut Bytes(file), &[0x1000..0x2000, 0x3000..0x5000]).unwrap(),
            expected
        );

        let (sentinel, _) = aarch64_file(&[]);
        assert_eq!(
            read_trampoline_regions(&mut Bytes(sentinel), &[]).unwrap(),
            []
        );
    }

    #[test]
    fn malformed_aarch64_tables_are_rejected() {
        let bad = |file: Vec<u8>| {
            matches!(
                read_trampoline_regions(&mut Bytes(file), &[]),
                Err(ElfParseError::BadTrampoline)
            )
        };
        // Sub-trampolines sharing a page.
        assert!(bad(aarch64_file(&[(0x5000, 0x1010), (0x6000, 0x40)]).0));
        // An unaligned address.
        assert!(bad(aarch64_file(&[(0x5010, 0x10), (0x8000, 0x40)]).0));
        // An empty sub-trampoline.
        assert!(bad(aarch64_file(&[(0x5000, 0), (0x8000, 0x40)]).0));

        let (good, _) = aarch64_file(&[(0x5000, 0x10), (0x8000, 0x40)]);
        let footer = good.len() - 32;
        // Nonzero reserved word.
        let mut file = good.clone();
        file[footer + 24] = 1;
        assert!(bad(file));
        // A table that does not end at the footer.
        let mut file = good.clone();
        file[footer + 16] = 1;
        assert!(bad(file));
        // Entries out of file order.
        let mut file = good.clone();
        let table = footer - 48;
        let (first, second) = file[table..footer].split_at_mut(24);
        first.swap_with_slice(second);
        assert!(bad(file));
        // An unaligned file offset.
        let mut file = good.clone();
        file[table] = 8;
        assert!(bad(file));
    }

    #[test]
    fn aarch64_sub_trampolines_must_not_overlap_segments() {
        let (file, _) = aarch64_file(&[(0x5000, 0x10), (0x8000, 0x40)]);
        let read = |segments: &[core::ops::Range<u64>]| {
            read_trampoline_regions(&mut Bytes(file.clone()), segments)
        };
        assert!(read(&[0x1000..0x5000, 0x6000..0x8000]).is_ok());
        for segment in [
            // Inside a segment.
            0x1000..0x9000,
            // Sharing a page with a segment's start or end.
            0x5800..0x7000,
            0x2000..0x8001,
        ] {
            assert!(matches!(
                read(core::slice::from_ref(&segment)),
                Err(ElfParseError::BadTrampoline)
            ));
        }
    }
}
