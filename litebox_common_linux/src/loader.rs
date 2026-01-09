// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ELF loader and mapper.
//!
//! Supports the following features:
//! * Parsing and mapping ELF binaries as the Linux kernel would when starting a
//!   new process, including both static and dynamic ELF binaries.
//! * Loading LiteBox trampoline code for syscall handling.

use alloc::vec::Vec;
use elf::{file::FileHeader, parse::ParseAt};
use litebox::{
    mm::linux::PAGE_SIZE,
    platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider},
    utils::{ReinterpretSignedExt as _, TruncateExt as _},
};
use thiserror::Error;
use zerocopy::IntoBytes as _;

use crate::errno::Errno;

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

/// The magic number used to identify the LiteBox rewriter and where we should
/// update the syscall callback pointer.
const REWRITER_MAGIC_NUMBER: u32 = u32::from_le_bytes(*b"LTBX");
const REWRITER_VERSION_NUMBER: u64 = u64::from_le_bytes(*b"LITEBOX0");

const CLASS: elf::file::Class = if cfg!(target_pointer_width = "64") {
    elf::file::Class::ELF64
} else {
    elf::file::Class::ELF32
};

const MACHINE: u16 = if cfg!(target_arch = "x86_64") {
    elf::abi::EM_X86_64
} else if cfg!(target_arch = "x86") {
    elf::abi::EM_386
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

        // Read the program headers.
        let phent_size = if cfg!(target_pointer_width = "64") {
            size_of::<elf::segment::Elf64_Phdr>()
        } else {
            size_of::<elf::segment::Elf32_Phdr>()
        };
        if usize::from(header.e_phentsize) != phent_size {
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

        Ok(ElfParsedFile {
            header,
            phdrs,
            trampoline: None,
        })
    }

    /// Parse the LiteBox trampoline section, if any.
    ///
    /// `syscall_entry_point` is the address of the syscall entry point to write
    /// into the trampoline at map time.
    pub fn parse_trampoline<F: ReadAt>(
        &mut self,
        file: &mut F,
        syscall_entry_point: usize,
    ) -> Result<(), ElfParseError<F::Error>> {
        let shent_size = if cfg!(target_pointer_width = "64") {
            size_of::<elf::section::Elf64_Shdr>()
        } else {
            size_of::<elf::section::Elf32_Shdr>()
        };

        if self.header.e_shnum == 0 || usize::from(self.header.e_shentsize) != shent_size {
            // No section headers or invalid size.
            return Ok(());
        }

        let offset = self
            .header
            .e_shoff
            .checked_add(u64::from(self.header.e_shentsize) * u64::from(self.header.e_shnum - 1))
            .ok_or(ElfParseError::BadFormat)?;
        let mut buf = [0u8; size_of::<elf::section::Elf64_Shdr>()];
        file.read_at(offset, &mut buf).map_err(ElfParseError::Io)?;
        let shdr = elf::section::SectionHeader::parse_at(
            self.header.endianness,
            self.header.class,
            &mut 0,
            &buf,
        )?;

        // Note these fields are repurposed to store our trampoline info.
        // See litebox_syscall_rewriter for details.
        let magic_number = shdr.sh_addr;
        let tramp_offset = shdr.sh_offset;
        let tramp_size = shdr.sh_entsize;
        // TODO: check section name instead of magic number
        if magic_number != REWRITER_MAGIC_NUMBER.into() || shdr.sh_size != 0 {
            // Not a trampoline section.
            return Ok(());
        }
        let size: usize = tramp_size
            .try_into()
            .map_err(|_| ElfParseError::BadTrampoline)?;
        // The trampoline is located at the end of the file.
        let file_offset = file
            .size()
            .map_err(ElfParseError::Io)?
            .checked_sub(tramp_size)
            .ok_or(ElfParseError::BadTrampoline)?;

        self.trampoline = Some(TrampolineInfo {
            vaddr: tramp_offset
                .try_into()
                .map_err(|_| ElfParseError::BadTrampoline)?,
            size,
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
        let len: usize = ph.p_filesz.truncate();
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
    ) -> Result<MappingInfo, ElfLoadError<M::Error>> {
        let base_addr = if self.header.e_type == elf::abi::ET_DYN {
            // Find an aligned load address that will fit all PT_LOAD segments.
            let mut min = usize::MAX;
            let mut max = 0usize;
            let mut align = PAGE_SIZE;
            for ph in self.pt_loads() {
                min = min.min(ph.p_vaddr.truncate());
                max = max.max(
                    (ph.p_vaddr
                        .checked_add(ph.p_memsz)
                        .ok_or(ElfLoadError::InvalidProgramHeader)?)
                    .truncate(),
                );
                if ph.p_align.is_power_of_two() {
                    align = align.max(ph.p_align.truncate());
                }
            }
            if let Some(trampoline) = &self.trampoline {
                min = min.min(trampoline.vaddr);
                max = max.max(trampoline.vaddr + trampoline.size);
            }
            let min = page_align_down(min);
            let max = page_align_up(max);
            mapper
                .reserve(max - min, align)
                .map_err(ElfLoadError::Map)?
        } else {
            // For ET_EXEC, load at the fixed addresses specified in the ELF.
            0
        };

        let mut brk = 0;
        let mut phdrs_addr = 0;
        for ph in self.pt_loads() {
            let p_vaddr: usize = ph.p_vaddr.truncate();
            let p_memsz: usize = ph.p_memsz.truncate();
            let p_filesz: usize = ph.p_filesz.truncate();
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
                let offset_in_segment: usize = (self.header.e_phoff - ph.p_offset).truncate();
                phdrs_addr = adjusted_vaddr + offset_in_segment;
            }
        }

        let mut info = MappingInfo {
            base_addr,
            brk,
            entry_point: base_addr.wrapping_add(self.header.e_entry.truncate()),
            phdrs_addr,
            num_phdrs: self.header.e_phnum.into(),
        };

        if self.trampoline.is_some() {
            self.load_trampoline(mapper, mem, &mut info)?;
        }

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

        // Validate the trampoline version number.
        let mut version = 0u64;
        mem.read(trampoline_start, version.as_mut_bytes())?;
        if version != REWRITER_VERSION_NUMBER {
            return Err(ElfLoadError::InvalidTrampolineVersion);
        }

        // Write the trampoline entry point.
        mem.write(
            trampoline_start + 8,
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
        let base_addr = loaded_entry_point
            .checked_sub(self.header.e_entry.truncate())
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
            unsafe {
                addr.write_at_offset(i.reinterpret_as_signed(), 0)
                    .ok_or(Fault)?;
            };
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
