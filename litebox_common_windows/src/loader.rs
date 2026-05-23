// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PE loader-facing parser and mapper.
//!
//! This module parses PE metadata and maps images through platform-provided traits.

use alloc::vec::Vec;
use core::cmp;
use core::mem::size_of;
use zerocopy::{FromBytes, IntoBytes};

use object::endian::LittleEndian as LE;
use object::pe;
use object::pod::Pod;
use thiserror::Error;

/// x86-64 page size used for all PE alignment and protection math.
pub const PAGE_SIZE: usize = 4096;

/// Maximum supported section count. PE limit per spec is 96.
const MAX_SECTIONS: usize = 96;

/// The result of parsing a PE32+ file.
#[derive(Debug)]
pub struct PeParsedFile {
    image: PeImageInfo,
    sections: Vec<pe::ImageSectionHeader>,
    data_directories: Vec<PeDataDirectory>,
    trampoline: Option<PeTrampolineInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeImageInfo {
    machine: u16,
    characteristics: u16,
    image_base: usize,
    entry_point_rva: usize,
    size_of_image: usize,
    size_of_headers: usize,
    section_alignment: usize,
    file_alignment: usize,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_heap_reserve: usize,
    size_of_heap_commit: usize,
}

/// Information about the mapped PE image.
pub struct MappingInfo {
    pub base_addr: usize,
    pub image_size: usize,
    pub entry_point: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeTrampolineInfo {
    rva: usize,
    size: usize,
    file_offset: u64,
    syscall_entry_point: usize,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
struct TrampolineHeader64 {
    magic: [u8; 8],
    file_offset: u64,
    rva: u64,
    trampoline_size: u64,
}

const TRAMPOLINE_MAGIC: [u8; 8] = *b"LITEBOX0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeDataDirectory {
    virtual_address: u32,
    size: u32,
}

/// Errors that can occur when parsing a PE file.
#[derive(Debug, Error)]
pub enum PeParseError<E> {
    #[error("I/O error")]
    Io(#[source] E),
    #[error("unsupported PE image")]
    UnsupportedImage,
    #[error("bad LiteBox trampoline")]
    BadTrampoline,
    /// The LiteBox trampoline magic was found but the version byte is unknown.
    #[error("invalid LiteBox trampoline version")]
    BadTrampolineVersion,
    /// A PE field overflowed the host's `usize` representation.
    #[error("PE field overflow")]
    Overflow,
}

/// Errors that can occur when mapping a PE image into memory.
#[derive(Debug, Error)]
pub enum PeLoadError<E> {
    #[error("memory mapping error")]
    Map(#[source] E),
    #[error("invalid PE image")]
    InvalidImage,
    /// The image had to be loaded away from its preferred base but has no base relocations.
    #[error("PE image requires base relocations")]
    RelocationRequired,
    #[error("unsupported PE base relocation type {0}")]
    UnsupportedRelocation(u16),
    #[error(transparent)]
    Fault(#[from] Fault),
}

macro_rules! checked_add {
    ($a:expr, $b:expr, $e:expr) => {
        $a.checked_add($b).ok_or($e)
    };
}
macro_rules! checked_add_invalid {
    ($a:expr, $b:expr) => {
        checked_add!($a, $b, PeLoadError::InvalidImage)
    };
}
macro_rules! checked_add_overflow {
    ($a:expr, $b:expr) => {
        checked_add!($a, $b, PeParseError::Overflow)
    };
}

macro_rules! checked_next_multiple_of {
    ($x:expr, $align:expr, $e:expr) => {
        $x.checked_next_multiple_of($align).ok_or($e)
    };
}

impl PeParsedFile {
    /// Parse a PE32+ x86-64 image from the given file.
    ///
    /// Only the PE headers are read into memory; section contents — including
    /// `.reloc` — are left on disk and streamed by [`MapMemory::map_file`] during
    /// [`PeParsedFile::load`]. Base relocations are then applied by reading the
    /// mapped image in place, avoiding a redundant disk read of the `.reloc` bytes.
    pub fn parse<F: ReadAt>(file: &mut F) -> Result<Self, PeParseError<F::Error>> {
        let size = file.size().map_err(PeParseError::Io)?;
        let file_size: usize = usize_from_u64(size)?;

        let (image, sections, data_directories) = parse_headers(file, file_size)?;

        Ok(PeParsedFile {
            image,
            sections,
            data_directories,
            trampoline: None,
        })
    }

    /// Returns whether the image has a parsed LiteBox syscall trampoline.
    #[must_use]
    pub fn has_trampoline(&self) -> bool {
        self.trampoline.is_some()
    }

    /// Load the PE image into memory.
    ///
    /// This maps PE headers and sections into their image locations,
    /// applies base relocations if the image was not loaded at its preferred base,
    /// and then applies section protections. Import resolution is left to the shim
    /// because it depends on the emulated Windows module environment.
    pub fn load<M: MapMemory>(
        &self,
        mapper: &mut M,
        mem: &mut impl AccessMemory,
    ) -> Result<MappingInfo, PeLoadError<M::Error>> {
        self.load_with_writable_sections(mapper, mem, &[])
    }

    /// Load the PE image into memory, keeping selected sections writable.
    ///
    /// This is intended for target-specific loader data such as ntdll's `.mrdata`.
    pub fn load_with_writable_sections<M: MapMemory>(
        &self,
        mapper: &mut M,
        mem: &mut impl AccessMemory,
        writable_section_names: &[&[u8]],
    ) -> Result<MappingInfo, PeLoadError<M::Error>> {
        let preferred_base = self.image.image_base;
        let image_size = checked_next_multiple_of!(
            self.image.size_of_image,
            PAGE_SIZE,
            PeLoadError::InvalidImage
        )?;
        if image_size == 0 {
            return Err(PeLoadError::InvalidImage);
        }
        let mapping_size = self.mapping_size::<M::Error>(image_size)?;

        let base_addr = mapper
            .reserve(preferred_base, mapping_size, PAGE_SIZE)
            .map_err(PeLoadError::Map)?;
        let image_end = checked_add_invalid!(base_addr, image_size)?;

        let headers_size = self.image.size_of_headers;

        if headers_size > image_size {
            return Err(PeLoadError::InvalidImage);
        }
        if headers_size != 0 {
            mapper
                .map_file(base_addr, headers_size, 0, &Protection::R)
                .map_err(PeLoadError::Map)?;
        }

        for section in &self.sections {
            let section_rva = section.virtual_address.get(LE) as usize;
            let virtual_size = section.virtual_size.get(LE) as usize;
            let raw_size = section.size_of_raw_data.get(LE) as usize;
            let raw_offset = section.pointer_to_raw_data.get(LE) as usize;
            let mapped_size = checked_next_multiple_of!(
                cmp::max(virtual_size, raw_size),
                PAGE_SIZE,
                PeLoadError::InvalidImage
            )?;

            if mapped_size == 0 {
                continue;
            }
            let section_start = checked_add_invalid!(base_addr, section_rva)?;
            let section_end = checked_add_invalid!(section_start, mapped_size)?;
            if section_end > image_end {
                return Err(PeLoadError::InvalidImage);
            }

            if raw_size != 0 {
                mapper
                    .map_file(section_start, raw_size, raw_offset as u64, &Protection::RW)
                    .map_err(PeLoadError::Map)?;
            }

            if mapped_size > raw_size {
                let zero_start = checked_add_invalid!(section_start, raw_size)?;
                mapper
                    .map_zero(zero_start, mapped_size - raw_size, &Protection::RW)
                    .map_err(PeLoadError::Map)?;
            }
        }

        self.apply_base_relocations::<M::Error>(base_addr, mem)?;

        for section in &self.sections {
            let section_rva: usize = section.virtual_address.get(LE) as usize;
            let virtual_size: usize = section.virtual_size.get(LE) as usize;
            let raw_size: usize = section.size_of_raw_data.get(LE) as usize;
            let mapped_size = checked_next_multiple_of!(
                cmp::max(virtual_size, raw_size),
                PAGE_SIZE,
                PeLoadError::InvalidImage
            )?;
            if mapped_size == 0 {
                continue;
            }

            let protect_start = page_align_down(checked_add_invalid!(base_addr, section_rva)?);
            let protect_end = checked_next_multiple_of!(
                base_addr
                    .checked_add(section_rva)
                    .and_then(|address| address.checked_add(mapped_size))
                    .ok_or(PeLoadError::InvalidImage)?,
                PAGE_SIZE,
                PeLoadError::InvalidImage
            )?;
            if protect_end > image_end {
                return Err(PeLoadError::InvalidImage);
            }

            mapper
                .protect(
                    protect_start,
                    protect_end - protect_start,
                    &Protection::from_section(section, writable_section_names),
                )
                .map_err(PeLoadError::Map)?;
        }

        if self.trampoline.is_some() {
            self.load_trampoline(mapper, mem, base_addr)?;
        }

        let entry_point = checked_add!(
            base_addr,
            self.image.entry_point_rva,
            PeLoadError::InvalidImage
        )?;

        Ok(MappingInfo {
            base_addr,
            image_size: mapping_size,
            entry_point,
        })
    }

    /// Parse the LiteBox PE trampoline footer, if present.
    ///
    /// The trampoline RVA is relative to the image base. The first pointer-sized
    /// word of the mapped trampoline is patched with `syscall_entry_point` when
    /// the image is loaded.
    pub fn parse_trampoline<F: ReadAt>(
        &mut self,
        file: &mut F,
        syscall_entry_point: usize,
    ) -> Result<(), PeParseError<F::Error>> {
        if syscall_entry_point == 0 {
            return Ok(());
        }

        let file_size = file.size().map_err(PeParseError::Io)?;
        let header_size = size_of::<TrampolineHeader64>();
        if file_size < header_size as u64 {
            return Ok(());
        }

        let header_offset = file_size - header_size as u64;
        let mut header_buf = [0u8; size_of::<TrampolineHeader64>()];
        file.read_at(header_offset, &mut header_buf)
            .map_err(PeParseError::Io)?;
        let header = TrampolineHeader64::read_from_bytes(&header_buf)
            .map_err(|_| PeParseError::BadTrampoline)?;
        let magic = header.magic;
        if magic != TRAMPOLINE_MAGIC {
            if &magic[0..7] == b"LITEBOX" {
                return Err(PeParseError::BadTrampolineVersion);
            }
            return Ok(());
        }

        let file_offset = header.file_offset;
        let rva = usize_from_u64(header.rva)?;
        let trampoline_size = usize_from_u64(header.trampoline_size)?;
        let image_size = checked_next_multiple_of!(
            self.image.size_of_image,
            PAGE_SIZE,
            PeParseError::BadTrampoline
        )?;

        if trampoline_size == 0
            || !file_offset.is_multiple_of(PAGE_SIZE as u64)
            || !rva.is_multiple_of(PAGE_SIZE)
            || rva < image_size
            || file_offset
                .checked_add(trampoline_size as u64)
                .ok_or(PeParseError::BadTrampoline)?
                != header_offset
        {
            return Err(PeParseError::BadTrampoline);
        }

        self.trampoline = Some(PeTrampolineInfo {
            rva,
            size: trampoline_size,
            file_offset,
            syscall_entry_point,
        });
        Ok(())
    }

    fn mapping_size<E>(&self, image_size: usize) -> Result<usize, PeLoadError<E>> {
        let Some(trampoline) = &self.trampoline else {
            return Ok(image_size);
        };

        trampoline
            .rva
            .checked_add(trampoline.size)
            .and_then(|trampoline_end| trampoline_end.checked_next_multiple_of(PAGE_SIZE))
            .map(|trampoline_end| image_size.max(trampoline_end))
            .ok_or(PeLoadError::InvalidImage)
    }

    fn load_trampoline<M: MapMemory>(
        &self,
        mapper: &mut M,
        mem: &mut impl AccessMemory,
        base_addr: usize,
    ) -> Result<(), PeLoadError<M::Error>> {
        let trampoline = self.trampoline.as_ref().unwrap();
        let trampoline_start = base_addr
            .checked_add(trampoline.rva)
            .ok_or(PeLoadError::InvalidImage)?;
        let trampoline_size =
            checked_next_multiple_of!(trampoline.size, PAGE_SIZE, PeLoadError::InvalidImage)?;
        mapper
            .map_file(
                trampoline_start,
                trampoline_size,
                trampoline.file_offset,
                &Protection {
                    read: true,
                    write: true,
                    execute: false,
                },
            )
            .map_err(PeLoadError::Map)?;

        mem.write(
            trampoline_start,
            &trampoline.syscall_entry_point.to_ne_bytes(),
        )?;

        mapper
            .protect(
                trampoline_start,
                trampoline_size,
                &Protection {
                    read: true,
                    write: false,
                    execute: true,
                },
            )
            .map_err(PeLoadError::Map)
    }

    fn apply_base_relocations<E>(
        &self,
        base_addr: usize,
        mem: &mut impl AccessMemory,
    ) -> Result<(), PeLoadError<E>> {
        let delta = base_addr.wrapping_sub(self.image.image_base);
        if delta == 0 {
            return Ok(());
        }

        // The `.reloc` directory is already mapped (the containing section was made RW above).
        let reloc_dir = self
            .data_directories
            .get(pe::IMAGE_DIRECTORY_ENTRY_BASERELOC)
            .filter(|d| d.size != 0)
            .ok_or(PeLoadError::RelocationRequired)?;

        let image_end = checked_add_invalid!(base_addr, self.image.size_of_image)?;
        let dir_addr = checked_add_invalid!(base_addr, reloc_dir.virtual_address as usize)?;
        let dir_end = checked_add_invalid!(dir_addr, reloc_dir.size as usize)?;

        // `delta` represents a possibly-negative offset via two's-complement
        // wrap in `usize`; the signed cast preserves the sign for `wrapping_add_signed`.
        let delta_i64: i64 = delta.cast_signed() as i64;

        let mut cursor = dir_addr;
        while cursor < dir_end {
            let mut header_bytes = [0u8; size_of::<pe::ImageBaseRelocation>()];
            mem.read(cursor, &mut header_bytes)?;
            let (header, _) = object::pod::from_bytes::<pe::ImageBaseRelocation>(&header_bytes)
                .map_err(|()| PeLoadError::InvalidImage)?;
            let page_rva = header.virtual_address.get(LE);
            let block_size = header.size_of_block.get(LE) as usize;
            if block_size < size_of::<pe::ImageBaseRelocation>() || !block_size.is_multiple_of(2) {
                return Err(PeLoadError::InvalidImage);
            }
            let block_end = checked_add_invalid!(cursor, block_size)?;
            if block_end > dir_end {
                return Err(PeLoadError::InvalidImage);
            }

            let mut entry_addr =
                checked_add_invalid!(cursor, size_of::<pe::ImageBaseRelocation>())?;
            while entry_addr < block_end {
                let entry = mem_read_u16(mem, entry_addr)?;
                let typ = entry >> 12;
                let entry_offset = u32::from(entry & 0x0fff);
                match typ {
                    pe::IMAGE_REL_BASED_ABSOLUTE => {}
                    pe::IMAGE_REL_BASED_DIR64 => {
                        let relocation_rva = checked_add_invalid!(page_rva, entry_offset)? as usize;
                        let relocation_address = checked_add_invalid!(base_addr, relocation_rva)?;
                        let relocation_end =
                            checked_add_invalid!(relocation_address, size_of::<u64>())?;
                        if relocation_end > image_end {
                            return Err(PeLoadError::InvalidImage);
                        }
                        let value = mem_read_u64(mem, relocation_address)?;
                        let relocated = value.wrapping_add_signed(delta_i64);
                        mem.write(relocation_address, &relocated.to_le_bytes())?;
                    }
                    typ => return Err(PeLoadError::UnsupportedRelocation(typ)),
                }
                entry_addr = checked_add_invalid!(entry_addr, size_of::<u16>())?;
            }
            cursor = block_end;
        }

        Ok(())
    }
}

fn mem_read_u16<E>(mem: &mut impl AccessMemory, address: usize) -> Result<u16, PeLoadError<E>> {
    let mut buf = [0u8; size_of::<u16>()];
    mem.read(address, &mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn mem_read_u64<E>(mem: &mut impl AccessMemory, address: usize) -> Result<u64, PeLoadError<E>> {
    let mut buf = [0u8; size_of::<u64>()];
    mem.read(address, &mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

type ParsedHeaders = (
    PeImageInfo,
    Vec<pe::ImageSectionHeader>,
    Vec<PeDataDirectory>,
);

/// Read a POD struct of type `T` from `file` at `offset`.
///
/// All `object::pe` structs have alignment 1 (their fields are
/// `#[repr(transparent)]` byte-array wrappers), so the byte buffer's alignment
/// trivially satisfies `from_bytes`'s check and the transmute happens inside
/// `object::pod` rather than here.
fn read_pod<F: ReadAt, T: Pod>(file: &mut F, offset: u64) -> Result<T, PeParseError<F::Error>> {
    let mut buf = alloc::vec![0u8; size_of::<T>()];
    file.read_at(offset, &mut buf).map_err(PeParseError::Io)?;
    let (val, _) =
        object::pod::from_bytes::<T>(&buf).map_err(|()| PeParseError::UnsupportedImage)?;
    Ok(*val)
}

/// Read `count` POD structs of type `T` from `file` starting at `offset`.
fn read_pod_vec<F: ReadAt, T: Pod>(
    file: &mut F,
    offset: u64,
    count: usize,
) -> Result<Vec<T>, PeParseError<F::Error>> {
    let bytes_len = count
        .checked_mul(size_of::<T>())
        .ok_or(PeParseError::Overflow)?;
    let mut buf = alloc::vec![0u8; bytes_len];
    file.read_at(offset, &mut buf).map_err(PeParseError::Io)?;
    let (slice, _) = object::pod::slice_from_bytes::<T>(&buf, count)
        .map_err(|()| PeParseError::UnsupportedImage)?;
    Ok(slice.to_vec())
}

fn parse_headers<F: ReadAt>(
    file: &mut F,
    file_size: usize,
) -> Result<ParsedHeaders, PeParseError<F::Error>> {
    // DOS header.
    if file_size < size_of::<pe::ImageDosHeader>() {
        return Err(PeParseError::UnsupportedImage);
    }
    let dos: pe::ImageDosHeader = read_pod(file, 0)?;
    if dos.e_magic.get(LE) != pe::IMAGE_DOS_SIGNATURE {
        return Err(PeParseError::UnsupportedImage);
    }
    let nt_offset = u64::from(dos.e_lfanew.get(LE));

    // NT headers (signature + COFF file header + 64-bit optional header).
    let nt_end = checked_add_overflow!(nt_offset, size_of::<pe::ImageNtHeaders64>() as u64)?;
    if nt_end > file_size as u64 {
        return Err(PeParseError::UnsupportedImage);
    }
    let nt: pe::ImageNtHeaders64 = read_pod(file, nt_offset)?;
    if nt.signature.get(LE) != pe::IMAGE_NT_SIGNATURE {
        return Err(PeParseError::UnsupportedImage);
    }
    if nt.optional_header.magic.get(LE) != pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        return Err(PeParseError::UnsupportedImage);
    }

    let machine = nt.file_header.machine.get(LE);
    let characteristics = nt.file_header.characteristics.get(LE);
    if machine != pe::IMAGE_FILE_MACHINE_AMD64
        || characteristics & pe::IMAGE_FILE_EXECUTABLE_IMAGE == 0
    {
        return Err(PeParseError::UnsupportedImage);
    }

    let opt = &nt.optional_header;
    // Sub-page section alignment would let consecutive sections share a page,
    // so the page-aligned protect range of one section could overwrite another's
    // (e.g. RW `.data` downgrading the last page of RX `.text`).
    if (opt.section_alignment.get(LE) as usize) < PAGE_SIZE {
        return Err(PeParseError::UnsupportedImage);
    }

    let image_base = usize_from_u64(opt.image_base.get(LE))?;
    let entry_point_rva = opt.address_of_entry_point.get(LE) as usize;
    let image = PeImageInfo {
        machine,
        characteristics,
        image_base,
        entry_point_rva,
        size_of_image: opt.size_of_image.get(LE) as usize,
        size_of_headers: opt.size_of_headers.get(LE) as usize,
        section_alignment: opt.section_alignment.get(LE) as usize,
        file_alignment: opt.file_alignment.get(LE) as usize,
        subsystem: opt.subsystem.get(LE),
        dll_characteristics: opt.dll_characteristics.get(LE),
        size_of_heap_reserve: usize_from_u64(opt.size_of_heap_reserve.get(LE))?,
        size_of_heap_commit: usize_from_u64(opt.size_of_heap_commit.get(LE))?,
    };
    if image.size_of_headers > file_size {
        return Err(PeParseError::UnsupportedImage);
    }
    if entry_point_rva >= image.size_of_image {
        return Err(PeParseError::UnsupportedImage);
    }

    // Data directories sit immediately after the optional header. `ImageNtHeaders64`
    // already covers signature + file header + 64-bit optional header, so the
    // directory array starts at `nt_offset + size_of::<ImageNtHeaders64>()`.
    let num_rva_and_sizes = opt.number_of_rva_and_sizes.get(LE) as usize;
    if num_rva_and_sizes > pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
        return Err(PeParseError::UnsupportedImage);
    }
    let raw_dirs: Vec<pe::ImageDataDirectory> = read_pod_vec(file, nt_end, num_rva_and_sizes)?;
    let data_directories: Vec<_> = raw_dirs
        .iter()
        .map(|dir| {
            let virtual_address = dir.virtual_address.get(LE);
            let size = dir.size.get(LE);
            PeDataDirectory {
                virtual_address,
                size,
            }
        })
        .collect();

    // Section headers sit at `nt_offset + 4 (signature) + size_of::<ImageFileHeader>() + size_of_optional_header`.
    let num_sections = nt.file_header.number_of_sections.get(LE) as usize;
    if num_sections > MAX_SECTIONS {
        return Err(PeParseError::UnsupportedImage);
    }
    let size_of_optional_header = u64::from(nt.file_header.size_of_optional_header.get(LE));
    let sections_offset = nt_offset
        .checked_add(4 + size_of::<pe::ImageFileHeader>() as u64)
        .and_then(|n| n.checked_add(size_of_optional_header))
        .ok_or(PeParseError::Overflow)?;
    let sections_end = checked_add_overflow!(
        sections_offset,
        (num_sections * size_of::<pe::ImageSectionHeader>()) as u64
    )?;
    if sections_end > file_size as u64 {
        return Err(PeParseError::UnsupportedImage);
    }
    let sections: Vec<pe::ImageSectionHeader> = read_pod_vec(file, sections_offset, num_sections)?;
    validate_sections(&image, &sections, file_size)?;

    Ok((image, sections, data_directories))
}

/// Verify section invariants that the loader's mapping arithmetic depends on.
///
/// The mapping pass page-aligns each section's protect range; if a hostile PE
/// places a section at a sub-`section_alignment` RVA, has sections overlap each
/// other, or has a section overlap the headers, the page-aligned protect range
/// of a later section could downgrade earlier protections (e.g. RW `.data`
/// silently making RX `.text` writable). Reject all such images at parse time.
fn validate_sections<E>(
    image: &PeImageInfo,
    sections: &[pe::ImageSectionHeader],
    file_size: usize,
) -> Result<(), PeParseError<E>> {
    let headers_end =
        checked_next_multiple_of!(image.size_of_headers, PAGE_SIZE, PeParseError::Overflow)?;
    let mut prev_end_rva: usize = 0;
    for section in sections {
        let section_rva = section.virtual_address.get(LE) as usize;
        let virtual_size = section.virtual_size.get(LE) as usize;
        let raw_size = section.size_of_raw_data.get(LE) as usize;
        let raw_offset = section.pointer_to_raw_data.get(LE) as usize;

        if !section_rva.is_multiple_of(image.section_alignment) {
            return Err(PeParseError::UnsupportedImage);
        }
        if section_rva < headers_end && (virtual_size != 0 || raw_size != 0) {
            return Err(PeParseError::UnsupportedImage);
        }
        if section_rva < prev_end_rva {
            return Err(PeParseError::UnsupportedImage);
        }
        let mapped_size = checked_next_multiple_of!(
            cmp::max(virtual_size, raw_size),
            PAGE_SIZE,
            PeParseError::Overflow
        )?;
        let section_end_rva = checked_add_overflow!(section_rva, mapped_size)?;
        if section_end_rva > image.size_of_image {
            return Err(PeParseError::UnsupportedImage);
        }

        if raw_size != 0 {
            let raw_end = checked_add_overflow!(raw_offset, raw_size)?;
            if raw_end > file_size {
                return Err(PeParseError::UnsupportedImage);
            }
        }

        prev_end_rva = section_end_rva;
    }
    Ok(())
}

fn usize_from_u64<E>(value: u64) -> Result<usize, PeParseError<E>> {
    value.try_into().map_err(|_| PeParseError::Overflow)
}

pub fn page_align_down(address: usize) -> usize {
    address & !(PAGE_SIZE - 1)
}

/// Trait for reading PE binary data at specific offsets.
pub trait ReadAt {
    type Error;

    /// Read `buf.len()` bytes at `offset`. Short reads are not permitted.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error>;

    fn size(&mut self) -> Result<u64, Self::Error>;
}

/// Trait for reserving, mapping, and protecting PE image memory.
pub trait MapMemory {
    type Error;

    /// Reserve a region of memory for the image, preferably at `preferred_base`.
    ///
    /// The returned address is the actual base address. If it differs from the
    /// preferred image base, [`PeParsedFile::load`] applies base relocations.
    fn reserve(
        &mut self,
        preferred_base: usize,
        len: usize,
        align: usize,
    ) -> Result<usize, Self::Error>;

    /// Map zero-filled memory, replacing any existing mappings in the range.
    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &Protection,
    ) -> Result<(), Self::Error>;

    /// Map file-backed data at the specified file offset.
    ///
    /// The mapper owns the backing file or equivalent byte source, including
    /// validating that the requested range exists.
    ///
    /// PE image sections are commonly file-aligned rather than page-aligned,
    /// so implementations may need to satisfy this by mapping pages and copying
    /// the requested file range into them.
    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &Protection,
    ) -> Result<(), Self::Error>;

    fn protect(&mut self, address: usize, len: usize, prot: &Protection)
    -> Result<(), Self::Error>;
}

/// Trait for reading and writing memory that has been mapped via [`MapMemory`].
pub trait AccessMemory {
    fn read(&mut self, address: usize, buf: &mut [u8]) -> Result<(), Fault>;
    fn write(&mut self, address: usize, data: &[u8]) -> Result<(), Fault>;
}

#[derive(Debug, Error)]
#[error("memory access fault")]
pub struct Fault;

/// Memory protection flags.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Protection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Protection {
    const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };

    const R: Self = Self {
        read: true,
        write: false,
        execute: false,
    };

    fn from_section(section: &pe::ImageSectionHeader, writable_section_names: &[&[u8]]) -> Self {
        let characteristics = section.characteristics.get(LE);
        let mut protection = Self {
            read: characteristics & object::pe::IMAGE_SCN_MEM_READ != 0,
            write: characteristics & object::pe::IMAGE_SCN_MEM_WRITE != 0,
            execute: characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE != 0,
        };
        if writable_section_names
            .iter()
            .any(|name| section_name_eq(section, name))
        {
            protection.write = true;
        }

        protection
    }
}

fn section_name_eq(section: &pe::ImageSectionHeader, name: &[u8]) -> bool {
    let end = section
        .name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(section.name.len());
    &section.name[..end] == name
}
