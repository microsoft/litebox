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
#[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
use litebox_syscall_rewriter::aarch64::elf_islands::ElfIslands;

type Endian = elf::endian::LittleEndian;

/// The result of parsing the ELF file headers.
///
/// Can be used to map the ELF into memory.
#[derive(Debug)]
pub struct ElfParsedFile {
    header: FileHeader<Endian>,
    phdrs: Vec<u8>,
    trampoline: Option<TrampolineInfo>,
    #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
    islands: Option<ElfIslands>,
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

/// The magic number used to identify the LiteBox trampoline.
/// This must match `TRAMPOLINE_MAGIC` in `litebox_syscall_rewriter`.
const TRAMPOLINE_MAGIC: u64 = u64::from_le_bytes(*b"LITEBOX0");
/// This must match `litebox_syscall_rewriter::TRAMPOLINE_FILE_ALIGNMENT`.
const TRAMPOLINE_FILE_ALIGNMENT: u64 = 4096;

/// Trampoline header for 64-bit: 8 (magic) + 8 (file_offset) + 8 (vaddr) + 8 (size) = 32 bytes
#[repr(C, packed)]
#[derive(FromBytes)]
pub struct TrampolineHeader64 {
    /// The unchanged outer format magic, `LITEBOX0`.
    pub magic: u64,
    /// File offset of legacy code or the AArch64 island descriptor.
    pub file_offset: u64,
    /// Legacy code address, or minimum object-relative AArch64 island address.
    pub vaddr: u64,
    /// Serialized bytes, not an AArch64 virtual span. Zero is the processed
    /// sentinel and requires both offset and address to be zero.
    pub trampoline_size: u64,
}

impl TrampolineHeader64 {
    /// Returns whether the header contains the supported trampoline magic.
    pub fn has_valid_magic(&self) -> bool {
        self.magic == TRAMPOLINE_MAGIC
    }
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

fn page_align_up(len: usize) -> usize {
    len.next_multiple_of(PAGE_SIZE)
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
    #[error("Loader does not support this AArch64 ELF island ABI")]
    UnsupportedIslandAbi,
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
            | ElfParseError::UnsupportedIslandAbi
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
    #[error("Loader does not support this AArch64 ELF island ABI")]
    UnsupportedIslandAbi,
    #[error(transparent)]
    Fault(#[from] Fault),
}

impl<E: Into<Errno>> From<ElfLoadError<E>> for Errno {
    fn from(value: ElfLoadError<E>) -> Self {
        match value {
            ElfLoadError::InvalidProgramHeader | ElfLoadError::UnsupportedIslandAbi => {
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
            #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
            islands: None,
        })
    }

    /// Returns `true` if a trampoline was parsed and will be mapped by `load()`.
    pub fn has_trampoline(&self) -> bool {
        #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
        if self.islands.as_ref().is_some_and(|p| !p.pairs.is_empty()) {
            return true;
        }
        self.trampoline.is_some()
    }

    /// Validated AArch64 island images, including a possible empty sentinel.
    /// Only each pair's `island_vaddr..island_vaddr+granule` is a fixed virtual
    /// extent; descriptor bytes and full chunks never enlarge the image span.
    #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
    pub fn aarch64_islands(&self) -> Option<&ElfIslands> {
        self.islands.as_ref()
    }

    /// The pages the trampoline occupies when this ELF is loaded at `base_addr`;
    /// a zero `base_addr` yields the load-address-relative range.
    ///
    /// This is the legacy contiguous range API, not an island-image envelope.
    /// Island-capable AArch64 consumers use `aarch64_islands` instead.
    /// `None` if the binary has no legacy trampoline or, like [`Self::has_trampoline`],
    /// if [`Self::parse_trampoline`] has not run yet.
    pub fn trampoline_page_range(&self, base_addr: usize) -> Option<core::ops::Range<usize>> {
        let trampoline = self.trampoline.as_ref()?;
        let start = base_addr.checked_add(trampoline.vaddr)?;
        let end = start
            .checked_add(trampoline.size)?
            .checked_next_multiple_of(PAGE_SIZE)?;
        Some(start..end)
    }

    /// Parse the LiteBox trampoline data, if any.
    ///
    /// The trampoline header is located at the end of the file (last 32/20 bytes).
    /// The trampoline code starts at a page-aligned offset before the header.
    /// File layout: `[ELF][padding][trampoline code][header]`
    ///
    /// `syscall_entry_point` is the address of the syscall entry point to write
    /// into the trampoline at map time. On AArch64, this generic entry rejects
    /// nonempty island payloads even when the callback is zero; loading them
    /// requires `aarch64_islands` and explicit delegation to a capable mapper.
    pub fn parse_trampoline<F: ReadAt>(
        &mut self,
        file: &mut F,
        syscall_entry_point: usize,
    ) -> Result<(), ElfParseError<F::Error>> {
        #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
        {
            self.parse_trampoline_with_islands(file, syscall_entry_point, false)
        }
        #[cfg(not(all(target_arch = "aarch64", feature = "aarch64_islands")))]
        {
            self.parse_trampoline_footer(file, syscall_entry_point)
        }
    }

    /// Parse with explicit delegation to an island-capable mapper. Generic
    /// loaders (including OP-TEE) must not execute the descriptor as legacy code.
    #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
    pub fn parse_trampoline_with_islands<F: ReadAt>(
        &mut self,
        file: &mut F,
        syscall_entry_point: usize,
        island_capable: bool,
    ) -> Result<(), ElfParseError<F::Error>> {
        let file_size = file.size().map_err(ElfParseError::Io)?;
        if self.header.e_machine == elf::abi::EM_AARCH64 {
            let mut read_error = None;
            let payload = ElfIslands::read(file_size, |offset, buf| {
                file.read_at(offset, buf).map_err(|error| {
                    if read_error.is_none() {
                        read_error = Some(error);
                    }
                    litebox_syscall_rewriter::Error::ParseError(alloc::string::String::from(
                        "ELF island read",
                    ))
                })
            });
            if let Some(error) = read_error {
                return Err(ElfParseError::Io(error));
            }
            let Some(payload) = payload.map_err(|_| ElfParseError::BadTrampoline)? else {
                return if syscall_entry_point == 0 {
                    Ok(())
                } else {
                    Err(ElfParseError::UnpatchedBinary)
                };
            };
            if !payload.pairs.is_empty() && !island_capable {
                return Err(ElfParseError::UnsupportedIslandAbi);
            }
            self.islands = Some(payload);
            return Ok(());
        }
        self.parse_trampoline_footer(file, syscall_entry_point)
    }

    // x86 retains its direct trampoline format and callback-zero fast path.
    // Without island support, AArch64 checks only the outer footer and refuses
    // nonempty payloads; it must never interpret a descriptor as direct code.
    fn parse_trampoline_footer<F: ReadAt>(
        &mut self,
        file: &mut F,
        syscall_entry_point: usize,
    ) -> Result<(), ElfParseError<F::Error>> {
        #[cfg(target_arch = "x86_64")]
        if syscall_entry_point == 0 {
            return Ok(());
        }
        let file_size = file.size().map_err(ElfParseError::Io)?;
        let unpatched = || {
            if syscall_entry_point == 0 {
                Ok(())
            } else {
                Err(ElfParseError::UnpatchedBinary)
            }
        };
        let header_size = TRAMPOLINE_HEADER_SIZE;

        // File must be large enough to contain the header
        if file_size < header_size as u64 {
            // Too small for a trampoline header — binary is unpatched.
            return unpatched();
        }

        // Read the header from the end of the file
        let header_offset = file_size - header_size as u64;
        let mut header_buf = [0u8; size_of::<TrampolineHeader64>()]; // Max header size
        file.read_at(header_offset, &mut header_buf[..header_size])
            .map_err(ElfParseError::Io)?;

        // LITEBOX0 is the only supported footer magic.
        let magic = u64::from_le_bytes(header_buf[0..8].try_into().unwrap());
        if magic != TRAMPOLINE_MAGIC {
            return if &header_buf[..7] == b"LITEBOX" {
                Err(ElfParseError::BadTrampoline)
            } else {
                unpatched()
            };
        }

        let (file_offset, vaddr, trampoline_size) = if cfg!(target_pointer_width = "64") {
            let header = TrampolineHeader64::read_from_bytes(&header_buf)
                .map_err(|_| ElfParseError::BadTrampoline)?;
            let vaddr: usize = header
                .vaddr
                .try_into()
                .map_err(|_| ElfParseError::BadTrampoline)?;
            let trampoline_size: usize = header
                .trampoline_size
                .try_into()
                .map_err(|_| ElfParseError::BadTrampoline)?;
            (header.file_offset, vaddr, trampoline_size)
        } else {
            let header = TrampolineHeader32::read_from_bytes(&header_buf[..header_size])
                .map_err(|_| ElfParseError::BadTrampoline)?;
            (
                u64::from(header.file_offset),
                header.vaddr as usize,
                header.trampoline_size as usize,
            )
        };

        // trampoline_size == 0 means the rewriter checked this binary and found
        // no syscall instructions.
        if trampoline_size == 0 {
            if file_offset != 0 || vaddr != 0 {
                return Err(ElfParseError::BadTrampoline);
            }
            return Ok(());
        }

        // Verify the rewriter-defined file alignment.
        if !file_offset.is_multiple_of(TRAMPOLINE_FILE_ALIGNMENT) {
            return Err(ElfParseError::BadTrampoline);
        }

        // Verify the trampoline virtual address is page-aligned
        if vaddr % PAGE_SIZE != 0 {
            return Err(ElfParseError::BadTrampoline);
        }

        // The trampoline code should immediately precede the header.
        if file_offset.checked_add(trampoline_size as u64) != Some(header_offset) {
            return Err(ElfParseError::BadTrampoline);
        }

        #[cfg(target_arch = "aarch64")]
        if self.header.e_machine == elf::abi::EM_AARCH64 {
            // Nonempty AArch64 payloads need the full island validator/mapper.
            if file_offset == 0 || trampoline_size < 64 {
                return Err(ElfParseError::BadTrampoline);
            }
            return Err(ElfParseError::UnsupportedIslandAbi);
        }

        // Reject a vaddr whose range cannot be represented, so that later
        // address arithmetic cannot wrap.
        if vaddr
            .checked_add(trampoline_size)
            .and_then(|end| end.checked_next_multiple_of(PAGE_SIZE))
            .is_none()
        {
            return Err(ElfParseError::BadTrampoline);
        }

        self.trampoline = Some(TrampolineInfo {
            vaddr,
            size: trampoline_size,
            file_offset,
            syscall_entry_point,
        });
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
        #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
        if self.islands.as_ref().is_some_and(|p| !p.pairs.is_empty())
            && !M::SUPPORTS_AARCH64_ISLANDS
        {
            return Err(ElfLoadError::UnsupportedIslandAbi);
        }
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
            if let Some(trampoline) = &self.trampoline {
                min = min.min(trampoline.vaddr);
                max = max.max(
                    trampoline
                        .vaddr
                        .checked_add(trampoline.size)
                        .ok_or(ElfLoadError::InvalidProgramHeader)?,
                );
            }
            #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
            if let Some(payload) = &self.islands {
                let granule = usize::try_from(payload.granule)
                    .map_err(|_| ElfLoadError::InvalidProgramHeader)?;
                for pair in &payload.pairs {
                    let start = usize::try_from(pair.island_vaddr())
                        .map_err(|_| ElfLoadError::InvalidProgramHeader)?;
                    min = min.min(start);
                    max = max.max(
                        start
                            .checked_add(granule)
                            .ok_or(ElfLoadError::InvalidProgramHeader)?,
                    );
                }
                align = align.max(granule);
            }
            #[cfg(not(all(target_arch = "aarch64", feature = "aarch64_islands")))]
            let granule = PAGE_SIZE;
            #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
            let granule = self
                .islands
                .as_ref()
                .filter(|p| !p.pairs.is_empty())
                .map_or(Ok(PAGE_SIZE), |p| {
                    usize::try_from(p.granule).map_err(|_| ElfLoadError::InvalidProgramHeader)
                })?;
            // Subtract an equally aligned object-relative origin so the load
            // bias, not just the reservation address, preserves PT_LOAD alignment.
            let min = min & !(align - 1);
            let max = max
                .checked_next_multiple_of(granule)
                .ok_or(ElfLoadError::InvalidProgramHeader)?;
            let span = max
                .checked_sub(min)
                .ok_or(ElfLoadError::InvalidProgramHeader)?;
            if span == 0 {
                return Err(ElfLoadError::InvalidProgramHeader);
            }
            let reserved = mapper.reserve(span, align).map_err(ElfLoadError::Map)?;
            let Some(bias) = reserved.checked_sub(min) else {
                mapper
                    .release_reservation(reserved, span)
                    .map_err(ElfLoadError::Map)?;
                return Err(ElfLoadError::InvalidProgramHeader);
            };
            bias
        } else {
            // For ET_EXEC, load at the fixed addresses specified in the ELF.
            0
        };

        let mut brk = 0;
        #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
        if let Some(payload) = &self.islands
            && !payload.pairs.is_empty()
        {
            mapper
                .prepare_aarch64_islands(payload, base_addr, self.header.e_type == elf::abi::ET_DYN)
                .map_err(ElfLoadError::Map)?;
            for pair in &payload.pairs {
                let end = usize::try_from(pair.island_vaddr())
                    .ok()
                    .and_then(|v| base_addr.checked_add(v))
                    .and_then(|v| v.checked_add(usize::try_from(payload.granule).ok()?))
                    .ok_or(ElfLoadError::InvalidProgramHeader)?;
                brk = brk.max(end);
            }
        }
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
            let adjusted_vaddr = base_addr + p_vaddr;
            let load_start = page_align_down(adjusted_vaddr);
            let file_end = page_align_up(adjusted_vaddr + p_filesz);
            let load_end = page_align_up(adjusted_vaddr + p_memsz);
            if file_end > load_start {
                // Map the file-backed portion.
                // `p_offset` should be co-aligned with `p_vaddr`. If it is not,
                // then `map_file` is expected to fail.
                let offset = ph
                    .p_offset
                    .wrapping_sub((adjusted_vaddr - load_start) as u64);
                #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
                mapper
                    .map_elf_load(load_start, file_end - load_start, offset, &prot, base_addr)
                    .map_err(ElfLoadError::Map)?;
                #[cfg(not(all(target_arch = "aarch64", feature = "aarch64_islands")))]
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
            info.brk = info.brk.next_multiple_of(HOST_PAGE_SIZE) + page_align_up(size);
        }

        // The initial writable brk heap must not share native backing with an
        // executable LOAD or trampoline. Guest mmap/mprotect still use the guest page size.
        info.brk = info.brk.next_multiple_of(HOST_PAGE_SIZE);
        Ok(info)
    }

    /// Load the LiteBox trampoline into memory.
    fn load_trampoline<M: MapMemory>(
        &self,
        mapper: &mut M,
        mem: &mut impl AccessMemory,
        info: &mut MappingInfo,
    ) -> Result<(), ElfLoadError<M::Error>> {
        let trampoline = self.trampoline.as_ref().unwrap();
        let trampoline_start = info.base_addr + trampoline.vaddr;
        let trampoline_end = page_align_up(info.base_addr + trampoline.vaddr + trampoline.size);
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

    /// Load the secondary LiteBox trampoline into memory whose location is relative to
    /// the based address which is the difference of `loaded_entry_point` and `e_entry`
    /// in the ELF header.
    pub fn load_secondary_trampoline<M: MapMemory>(
        &self,
        mapper: &mut M,
        mem: &mut impl AccessMemory,
        loaded_entry_point: usize,
    ) -> Result<(), ElfLoadError<M::Error>> {
        #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
        if self.islands.as_ref().is_some_and(|p| !p.pairs.is_empty()) {
            return Err(ElfLoadError::UnsupportedIslandAbi);
        }
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

    /// Explicit support for installing serialized pairs before any LOAD is executable.
    #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
    const SUPPORTS_AARCH64_ISLANDS: bool = false;

    /// Prepare an island image. `reserved` proves that this mapper just reserved
    /// the ET_DYN envelope, including every island extent. Full chunks are not
    /// part of that reservation. Called only for an explicitly capable mapper.
    #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
    fn prepare_aarch64_islands(
        &mut self,
        _payload: &ElfIslands,
        _base: usize,
        _reserved: bool,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Reserve a region of memory with the given length and alignment,
    /// returning the chosen address. On success the caller owns exactly
    /// `address..address + len.next_multiple_of(PAGE_SIZE)`; any alignment or
    /// placement-search slack must already have been released.
    ///
    /// `align` must be a power of two. Fails if any of the parameters are not
    /// page-aligned.
    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error>;

    /// Release an untouched reservation returned by [`Self::reserve`]. `address`
    /// and `len` identify that exact page-rounded extent, not its search slack.
    /// Called only before any LOAD or island has been installed into it.
    fn release_reservation(&mut self, address: usize, len: usize) -> Result<(), Self::Error>;

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

    /// Map a PT_LOAD at the bias chosen by this load, before publishing execute
    /// permission. Unlike arbitrary file mappings, aliased file pages have an
    /// unambiguous object identity here. The default needs no such provenance.
    #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
    fn map_elf_load(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &Protection,
        _load_bias: usize,
    ) -> Result<(), Self::Error> {
        self.map_file(address, len, offset, prot)
    }

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

#[cfg(all(test, target_arch = "aarch64", feature = "aarch64_islands"))]
mod island_tests {
    use super::*;

    struct File(Vec<u8>);
    impl ReadAt for File {
        type Error = ();
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ()> {
            let start = usize::try_from(offset).map_err(|_| ())?;
            buf.copy_from_slice(
                self.0
                    .get(start..start.checked_add(buf.len()).ok_or(())?)
                    .ok_or(())?,
            );
            Ok(())
        }
        fn size(&mut self) -> Result<u64, ()> {
            Ok(self.0.len() as u64)
        }
    }
    struct Memory;
    impl AccessMemory for Memory {
        fn read(&mut self, _: usize, _: &mut [u8]) -> Result<usize, Fault> {
            panic!("unexpected memory read")
        }
        fn write(&mut self, _: usize, _: &[u8]) -> Result<(), Fault> {
            panic!("descriptor must not be mapped as code")
        }
        fn zero(&mut self, _: usize, _: usize) -> Result<(), Fault> {
            Ok(())
        }
    }
    #[derive(Default)]
    struct Mapper<const CAPABLE: bool> {
        reservation: usize,
        reservation_align: usize,
        prepared: bool,
        mappings: Vec<Range<usize>>,
    }
    use core::ops::Range;
    impl<const CAPABLE: bool> MapMemory for Mapper<CAPABLE> {
        type Error = ();
        const SUPPORTS_AARCH64_ISLANDS: bool = CAPABLE;
        fn reserve(&mut self, len: usize, align: usize) -> Result<usize, ()> {
            self.reservation = len;
            self.reservation_align = align;
            assert_eq!(0x10000000 % align, 0);
            Ok(0x10000000)
        }
        fn release_reservation(&mut self, _: usize, _: usize) -> Result<(), ()> {
            panic!("unexpected reservation release")
        }
        fn prepare_aarch64_islands(
            &mut self,
            p: &ElfIslands,
            base: usize,
            reserved: bool,
        ) -> Result<(), ()> {
            assert!(reserved && !p.pairs.is_empty());
            for pair in &p.pairs {
                self.mappings.push(
                    base + usize::try_from(pair.island_vaddr()).unwrap()
                        ..base
                            + usize::try_from(pair.island_vaddr()).unwrap()
                            + usize::try_from(p.granule).unwrap(),
                );
            }
            self.prepared = true;
            Ok(())
        }
        fn map_file(&mut self, start: usize, len: usize, _: u64, _: &Protection) -> Result<(), ()> {
            assert!(self.prepared);
            self.mappings.push(start..start + len);
            Ok(())
        }
        fn map_zero(&mut self, _: usize, _: usize, _: &Protection) -> Result<(), ()> {
            Ok(())
        }
        fn protect(&mut self, _: usize, _: usize, _: &Protection) -> Result<(), ()> {
            panic!("legacy trampoline protect")
        }
    }
    fn file() -> File {
        let mut elf = include_bytes!("../../litebox_syscall_rewriter/tests/hello-aarch64").to_vec();
        elf[16..18].copy_from_slice(&elf::abi::ET_DYN.to_le_bytes());
        File(litebox_syscall_rewriter::hook_syscalls_in_elf(&elf, None).unwrap())
    }

    #[test]
    fn island_reservation_and_brk_exclude_serialized_chunk_file_size() {
        let mut file = file();
        let mut parsed = ElfParsedFile::parse(&mut file).unwrap();
        parsed
            .parse_trampoline_with_islands(&mut file, 1, true)
            .unwrap();
        assert!(parsed.has_trampoline());
        assert!(parsed.trampoline_page_range(0).is_none());
        let payload = parsed.aarch64_islands().unwrap();
        let mut ranges: Vec<_> = parsed
            .pt_loads()
            .map(|ph| {
                ph.p_vaddr / 4096 * 4096
                    ..ph.p_vaddr
                        .checked_add(ph.p_memsz)
                        .unwrap()
                        .next_multiple_of(4096)
            })
            .collect();
        ranges.extend(
            payload
                .pairs
                .iter()
                .map(|p| p.island_vaddr()..p.island_vaddr() + payload.granule),
        );
        let min = usize::try_from(ranges.iter().map(|r| r.start).min().unwrap()).unwrap();
        let max = usize::try_from(ranges.iter().map(|r| r.end).max().unwrap()).unwrap();
        let mut mapper = Mapper::<true>::default();
        let result = parsed.load(&mut mapper, &mut Memory, None).unwrap();
        assert_eq!(
            mapper.reservation,
            max - (min & !(mapper.reservation_align - 1))
        );
        assert_eq!(
            result.brk,
            (result.base_addr + max).next_multiple_of(HOST_PAGE_SIZE)
        );
        assert_eq!(
            mapper.mappings.len(),
            payload.pairs.len() + parsed.pt_loads().count()
        );
        let mut unsupported = Mapper::<false>::default();
        assert!(matches!(
            parsed.load(&mut unsupported, &mut Memory, None),
            Err(ElfLoadError::UnsupportedIslandAbi)
        ));
        assert_eq!(unsupported.reservation, 0);
    }

    #[test]
    fn island_below_nonzero_load_preserves_overaligned_dyn_load_bias() {
        // One over-aligned LOAD with no internal gap. Its SVC is nearest to
        // the page below the LOAD, which is not aligned to p_align.
        let mut elf = alloc::vec![0; 0x2000];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [
            (16, elf::abi::ET_DYN),
            (18, elf::abi::EM_AARCH64),
            (52, 64),
            (54, 56),
            (56, 1),
        ] {
            elf[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[64..68].copy_from_slice(&elf::abi::PT_LOAD.to_le_bytes());
        elf[68..72].copy_from_slice(&(elf::abi::PF_R | elf::abi::PF_X).to_le_bytes());
        for (at, value) in [
            (24, 0x10110u64),
            (32, 64),
            (80, 0x10000),
            (96, 0x2000),
            (104, 0x2000),
            (112, 0x10000),
        ] {
            elf[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        elf[0x110..0x114].copy_from_slice(&0xd4000001u32.to_le_bytes());
        let mut file = File(litebox_syscall_rewriter::hook_syscalls_in_elf(&elf, None).unwrap());
        let mut parsed = ElfParsedFile::parse(&mut file).unwrap();
        parsed
            .parse_trampoline_with_islands(&mut file, 1, true)
            .unwrap();
        let payload = parsed.aarch64_islands().unwrap();
        assert_eq!(payload.granule, 0x1000);
        assert_eq!(payload.pairs.len(), 1);
        assert_eq!(payload.pairs[0].island_vaddr(), 0xf000);

        let mut mapper = Mapper::<true>::default();
        let result = parsed.load(&mut mapper, &mut Memory, None).unwrap();
        assert_eq!(mapper.reservation_align, 0x10000);
        for ph in parsed.pt_loads() {
            let align = usize::try_from(ph.p_align).unwrap();
            assert_eq!(result.base_addr % align, 0);
            assert_eq!(
                (result.base_addr + usize::try_from(ph.p_vaddr).unwrap()) % align,
                usize::try_from(ph.p_offset).unwrap() % align
            );
        }
        assert_eq!(mapper.reservation, 0x12000);
        assert_eq!(result.base_addr, 0x10000000);
        for mapping in mapper.mappings {
            assert!(mapping.start >= 0x10000000);
            assert!(mapping.end <= 0x10000000 + mapper.reservation);
        }
    }

    #[test]
    fn generic_loader_rejects_island_abi_even_without_syscall_callback() {
        let mut file = file();
        for callback in [0, 1] {
            let mut parsed = ElfParsedFile::parse(&mut file).unwrap();
            assert!(matches!(
                parsed.parse_trampoline(&mut file, callback),
                Err(ElfParseError::UnsupportedIslandAbi)
            ));
        }
        // Malformed recognized metadata cannot be hidden by callback == 0.
        let end = file.0.len();
        file.0[end - 1] = 0xff;
        let mut parsed = ElfParsedFile::parse(&mut file).unwrap();
        assert!(matches!(
            parsed.parse_trampoline(&mut file, 0),
            Err(ElfParseError::BadTrampoline)
        ));
    }

    #[test]
    fn reserved_footer_prefix_is_corruption_only_at_fixed_start() {
        for machine in [elf::abi::EM_AARCH64, elf::abi::EM_X86_64] {
            for last in [b'1', b'?', 0] {
                let mut bytes =
                    include_bytes!("../../litebox_syscall_rewriter/tests/hello-aarch64").to_vec();
                // macOS admits ET_DYN only; keep footer validation host-independent.
                bytes[16..18].copy_from_slice(&elf::abi::ET_DYN.to_le_bytes());
                bytes.extend_from_slice(b"LITEBOX0");
                bytes.extend_from_slice(&[0; 24]);
                let mut file = File(bytes);
                let mut parsed = ElfParsedFile::parse(&mut file).unwrap();
                parsed.header.e_machine = machine; // Exercise both footer parsers on the native host.
                parsed
                    .parse_trampoline_with_islands(&mut file, 1, true)
                    .unwrap();
                let tail = file.0.len() - 32;
                file.0[tail + 7] = last;
                assert!(matches!(
                    parsed.parse_trampoline_with_islands(&mut file, 1, true),
                    Err(ElfParseError::BadTrampoline)
                ));
                file.0.push(0); // Displaced prefix is incidental data, not a footer.
                assert!(matches!(
                    parsed.parse_trampoline_with_islands(&mut file, 1, true),
                    Err(ElfParseError::UnpatchedBinary)
                ));
                file.0.pop();
                file.0[tail..].fill(0);
                file.0[tail + 16..tail + 24].copy_from_slice(b"LITEBOX1");
                assert!(matches!(
                    parsed.parse_trampoline_with_islands(&mut file, 1, true),
                    Err(ElfParseError::UnpatchedBinary)
                ));
                file.0[tail..tail + 8].copy_from_slice(b"LITEBOX0");
                // Exact magic with a malformed zero sentinel is still corruption.
                assert!(matches!(
                    parsed.parse_trampoline_with_islands(&mut file, 1, true),
                    Err(ElfParseError::BadTrampoline)
                ));
            }
        }
    }

    #[test]
    fn island_read_errors_preserve_errno_before_capability_checks() {
        struct FailingFile {
            file: File,
            fail_at: u64,
        }
        impl ReadAt for FailingFile {
            type Error = Errno;
            fn size(&mut self) -> Result<u64, Errno> {
                Ok(self.file.0.len() as u64)
            }
            fn read_at(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), Errno> {
                if offset == self.fail_at {
                    return Err(Errno::EIO);
                }
                self.file
                    .read_at(offset, bytes)
                    .map_err(|()| Errno::ENODATA)
            }
        }
        let bytes = file().0;
        let tail = bytes.len() - 32;
        let descriptor = usize::try_from(u64::from_le_bytes(
            bytes[tail + 8..tail + 16].try_into().unwrap(),
        ))
        .unwrap();
        let image = descriptor
            + usize::try_from(u64::from_le_bytes(
                bytes[descriptor + 72..descriptor + 80].try_into().unwrap(),
            ))
            .unwrap();
        for fail_at in [tail, descriptor, image, 0x110] {
            for (callback, capable) in [(0, false), (0, true), (1, false), (1, true)] {
                let mut file = FailingFile {
                    file: File(bytes.clone()),
                    fail_at: fail_at as u64,
                };
                let mut parsed = ElfParsedFile::parse(&mut file).unwrap();
                let error = parsed
                    .parse_trampoline_with_islands(&mut file, callback, capable)
                    .unwrap_err();
                assert!(
                    matches!(error, ElfParseError::Io(Errno::EIO)),
                    "{fail_at:#x}: {error:?}"
                );
                assert_eq!(Errno::from(error), Errno::EIO);
            }
        }
        let mut corrupt = File(bytes);
        corrupt.0[image] ^= 1;
        let mut parsed = ElfParsedFile::parse(&mut corrupt).unwrap();
        assert!(matches!(
            parsed.parse_trampoline_with_islands(&mut corrupt, 0, false),
            Err(ElfParseError::BadTrampoline)
        ));
    }

    #[test]
    fn zero_sentinel_does_not_reserve_islands() {
        let mut file = file();
        let original_len =
            include_bytes!("../../litebox_syscall_rewriter/tests/hello-aarch64").len();
        file.0.truncate(original_len);
        file.0.extend_from_slice(b"LITEBOX0");
        file.0.extend_from_slice(&[0; 24]);
        let mut parsed = ElfParsedFile::parse(&mut file).unwrap();
        parsed.parse_trampoline(&mut file, 0).unwrap();
        assert!(!parsed.has_trampoline());
        assert!(parsed.aarch64_islands().unwrap().pairs.is_empty());
    }
}

#[cfg(test)]
mod non_island_geometry_tests {
    use super::*;

    #[test]
    fn x86_dyn_nonzero_minimum_overaligned_loads_stay_in_reservation() {
        struct Mapper {
            address: usize,
            len: usize,
            loads: Vec<core::ops::Range<usize>>,
            released: Vec<(usize, usize)>,
            release_error: bool,
        }
        impl MapMemory for Mapper {
            type Error = ();
            fn reserve(&mut self, len: usize, align: usize) -> Result<usize, ()> {
                assert_eq!(align, 0x10000);
                self.len = len;
                Ok(self.address)
            }
            fn release_reservation(&mut self, address: usize, len: usize) -> Result<(), ()> {
                self.released.push((address, len));
                if self.release_error { Err(()) } else { Ok(()) }
            }
            fn map_file(
                &mut self,
                addr: usize,
                len: usize,
                offset: u64,
                _: &Protection,
            ) -> Result<(), ()> {
                assert_eq!(addr % 0x10000, usize::try_from(offset).unwrap() % 0x10000);
                self.loads.push(addr..addr + len);
                Ok(())
            }
            fn map_zero(&mut self, _: usize, _: usize, _: &Protection) -> Result<(), ()> {
                panic!("no bss")
            }
            fn protect(&mut self, _: usize, _: usize, _: &Protection) -> Result<(), ()> {
                panic!("no trampoline")
            }
        }
        struct Memory;
        impl AccessMemory for Memory {
            fn read(&mut self, _: usize, _: &mut [u8]) -> Result<usize, Fault> {
                panic!("no read")
            }
            fn write(&mut self, _: usize, _: &[u8]) -> Result<(), Fault> {
                panic!("no write")
            }
            fn zero(&mut self, _: usize, len: usize) -> Result<(), Fault> {
                assert_eq!(len, 0);
                Ok(())
            }
        }
        // Exercise x86 headers with the common mapper even on an ARM host.
        // Deliberately bypass only parse()'s native-machine admission check;
        // no instructions, memory copies, or architecture emulation are used.
        let mut bytes = alloc::vec![0; 64 + 2 * 56];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [
            (16, elf::abi::ET_DYN),
            (18, elf::abi::EM_X86_64),
            (52, 64),
            (54, 56),
            (56, 2),
        ] {
            bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        for (index, address, offset) in [(0, 0x23000u64, 0x3000u64), (1, 0x64000, 0x4000)] {
            let at = 64 + index * 56;
            bytes[at..at + 4].copy_from_slice(&elf::abi::PT_LOAD.to_le_bytes());
            bytes[at + 4..at + 8].copy_from_slice(&elf::abi::PF_R.to_le_bytes());
            for (field, value) in [
                (8, offset),
                (16, address),
                (32, 0x1000),
                (40, 0x1000),
                (48, 0x10000),
            ] {
                bytes[at + field..at + field + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        let ident = elf::file::parse_ident::<Endian>(&bytes).unwrap();
        let parsed = ElfParsedFile {
            header: FileHeader::parse_tail(ident, &bytes[16..64]).unwrap(),
            phdrs: bytes[64..].to_vec(),
            trampoline: None,
            #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
            islands: None,
        };
        let mut mapper = Mapper {
            address: 0x10000000,
            len: 0,
            loads: Vec::new(),
            released: Vec::new(),
            release_error: false,
        };
        let info = parsed.load(&mut mapper, &mut Memory, None).unwrap();
        assert_eq!(info.base_addr, 0x10000000 - 0x20000);
        assert_eq!(mapper.len, 0x65000 - 0x20000);
        assert_eq!(mapper.loads.len(), 2);
        assert!(mapper.released.is_empty());
        for r in &mapper.loads {
            assert!(r.start >= 0x10000000 && r.end <= 0x10000000 + mapper.len);
        }
        // The writable heap must start on fresh host backing even when the
        // ELF header is x86 and its LOAD/reservation ends on a guest page.
        assert_eq!(
            info.brk,
            (0x10000000 + mapper.len).next_multiple_of(HOST_PAGE_SIZE)
        );
        mapper.address = 0x10000; // Lower than the aligned object-relative origin.
        mapper.loads.clear();
        assert!(matches!(
            parsed.load(&mut mapper, &mut Memory, None),
            Err(ElfLoadError::InvalidProgramHeader)
        ));
        assert!(mapper.loads.is_empty());
        assert_eq!(mapper.released, [(0x10000, 0x45000)]);
        mapper.released.clear();
        mapper.release_error = true;
        assert!(matches!(
            parsed.load(&mut mapper, &mut Memory, None),
            Err(ElfLoadError::Map(()))
        ));
        assert_eq!(mapper.released, [(0x10000, 0x45000)]);
    }
}

#[cfg(test)]
mod trampoline_footer_tests {
    use super::*;

    struct File(Vec<u8>);
    impl ReadAt for File {
        type Error = ();
        fn read_at(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), ()> {
            let start = usize::try_from(offset).map_err(|_| ())?;
            bytes.copy_from_slice(self.0.get(start..start + bytes.len()).ok_or(())?);
            Ok(())
        }
        fn size(&mut self) -> Result<u64, ()> {
            Ok(self.0.len() as u64)
        }
    }

    fn file(machine: u16, offset: u64, address: u64, size: u64) -> (ElfParsedFile, File) {
        let mut bytes = alloc::vec![0; 0x1040];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&elf::abi::ET_DYN.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        let ident = elf::file::parse_ident::<Endian>(&bytes).unwrap();
        let parsed = ElfParsedFile {
            header: FileHeader::parse_tail(ident, &bytes[16..64]).unwrap(),
            phdrs: Vec::new(),
            trampoline: None,
            #[cfg(all(target_arch = "aarch64", feature = "aarch64_islands"))]
            islands: None,
        };
        for field in [TRAMPOLINE_MAGIC, offset, address, size] {
            bytes.extend_from_slice(&field.to_le_bytes());
        }
        (parsed, File(bytes))
    }

    #[test]
    fn x86_direct_footer_checked_arithmetic_and_zero_sentinel() {
        for (offset, address, size) in [
            (0, 0, 0),
            (0x1000, 0x2000, 64),
            (1, 0, 0),
            (0, 1, 0),
            (u64::MAX - 4095, 0x2000, 0x2040),
            (0x1000, u64::MAX - 4095, 64),
            (0x1000, 0x2000, 63),
        ] {
            let (mut parsed, mut file) = file(elf::abi::EM_X86_64, offset, address, size);
            let result = parsed.parse_trampoline_footer(&mut file, 1);
            if (offset, address, size) == (0, 0, 0) {
                result.unwrap();
                assert!(!parsed.has_trampoline());
            } else if (offset, address, size) == (0x1000, 0x2000, 64) {
                result.unwrap();
                assert_eq!(parsed.trampoline_page_range(0), Some(0x2000..0x3000));
            } else {
                assert!(matches!(result, Err(ElfParseError::BadTrampoline)));
            }
        }
    }

    #[test]
    fn x86_footer_requires_exact_magic_at_fixed_tail() {
        for last in [b'1', b'?', 0] {
            let (mut parsed, mut file) = file(elf::abi::EM_X86_64, 0, 0, 0);
            let tail = file.0.len() - 32;
            file.0[tail + 7] = last;
            assert!(matches!(
                parsed.parse_trampoline_footer(&mut file, 1),
                Err(ElfParseError::BadTrampoline)
            ));
            file.0.push(0);
            assert!(matches!(
                parsed.parse_trampoline_footer(&mut file, 1),
                Err(ElfParseError::UnpatchedBinary)
            ));
            file.0.pop();
            file.0[tail..].fill(0);
            file.0[tail + 16..tail + 24].copy_from_slice(b"LITEBOX1");
            assert!(matches!(
                parsed.parse_trampoline_footer(&mut file, 1),
                Err(ElfParseError::UnpatchedBinary)
            ));
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x86_zero_callback_does_not_query_file_size_or_read_footer() {
        struct Unreadable;
        impl ReadAt for Unreadable {
            type Error = ();
            fn read_at(&mut self, _: u64, _: &mut [u8]) -> Result<(), ()> {
                panic!("unexpected read")
            }
            fn size(&mut self) -> Result<u64, ()> {
                panic!("unexpected size query")
            }
        }
        let (mut parsed, _) = file(elf::abi::EM_X86_64, 0, 0, 0);
        parsed.parse_trampoline(&mut Unreadable, 0).unwrap();
    }

    #[cfg(all(target_arch = "aarch64", not(feature = "aarch64_islands")))]
    #[test]
    fn aarch64_feature_off_rejects_payload_without_decoding_it() {
        for callback in [0, 1] {
            // Only the outer envelope is needed to reject this ABI. No payload
            // reads, allocations, or rewriter dependency are needed to fail closed.
            let (mut parsed, mut file) = file(elf::abi::EM_AARCH64, 0x1000, 0x2000, 64);
            file.0[0x1000..0x1008].copy_from_slice(b"LBISLAND");
            assert!(matches!(
                parsed.parse_trampoline(&mut file, callback),
                Err(ElfParseError::UnsupportedIslandAbi)
            ));
            assert!(!parsed.has_trampoline());
            assert!(parsed.trampoline_page_range(0).is_none());
            let tail = file.0.len() - 32;
            file.0[tail + 7] = b'1';
            assert!(matches!(
                parsed.parse_trampoline(&mut file, callback),
                Err(ElfParseError::BadTrampoline)
            ));
            file.0[tail + 7] = b'0';
            file.0[tail + 24..].fill(0);
            assert!(matches!(
                parsed.parse_trampoline(&mut file, callback),
                Err(ElfParseError::BadTrampoline)
            ));
            file.0[tail + 8..].fill(0);
            parsed.parse_trampoline(&mut file, callback).unwrap();
            assert!(!parsed.has_trampoline());
        }
    }
}
