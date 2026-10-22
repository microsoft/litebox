// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Read-only parsing of an on-disk dyld shared cache.
//!
//! Layouts follow `dyld/include/mach-o/dyld_cache_format.h` and
//! `mach-o/loader.h`. All fields are read explicitly as little-endian and
//! every offset, count and size is bounds-checked: malformed input yields
//! [`SharedCacheError`], never a panic or an arithmetic overflow. Files are
//! read lazily through [`CacheFileReader`], so multi-GiB cache files need not
//! be loaded.
//!
//! Intended use: parse the main cache file with [`CacheFile::parse`], open each
//! [`CacheFile::subcache_entries`] file (main path + suffix), and combine them
//! with [`SharedCache::new`] (which verifies subcache identity and layout).

use crate::VmProtection;
use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::ops::Range;
use zerocopy::{
    FromBytes, Immutable, KnownLayout, Unaligned,
    little_endian::{U16, U32, U64},
};

/// Magic of an arm64e cache file (main cache and subcaches).
pub const CACHE_MAGIC_ARM64E: [u8; 16] = *b"dyld_v1  arm64e\0";

/// `DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE`.
pub const SLIDE_V5_PAGE_NO_REBASE: u16 = 0xffff;

/// Size of a `DyldSharedCache::DynamicRegion` reservation.
pub const DYNAMIC_REGION_SIZE: usize = 0x4000;

/// Upper bounds that reject absurd counts before allocating.
const MAX_MAPPINGS: u32 = 64;
const MAX_SUBCACHES: u32 = 1024;
const MAX_IMAGES: u32 = 1 << 20;
const MAX_LOAD_COMMAND_BYTES: u32 = 1 << 20;
const MAX_HEADER_BYTES: usize = 0x4000;
const MAX_SLIDE_INFO_BYTES: usize = 1 << 24;

// dyld_cache_header field offsets; public only for the ABI check.
#[doc(hidden)]
pub const HEADER_MAPPING_OFFSET: usize = 0x10;
#[doc(hidden)]
pub const HEADER_UUID: usize = 0x58;
#[doc(hidden)]
pub const HEADER_CACHE_TYPE: usize = 0x68;
#[doc(hidden)]
pub const HEADER_DYLD_IN_CACHE_MH: usize = 0x78;
#[doc(hidden)]
pub const HEADER_SHARED_REGION_START: usize = 0xe0;
#[doc(hidden)]
pub const HEADER_SHARED_REGION_SIZE: usize = 0xe8;
#[doc(hidden)]
pub const HEADER_MAX_SLIDE: usize = 0xf0;
#[doc(hidden)]
pub const HEADER_MAPPING_WITH_SLIDE_OFFSET: usize = 0x138;
#[doc(hidden)]
pub const HEADER_SUBCACHE_ARRAY_OFFSET: usize = 0x188;
#[doc(hidden)]
pub const HEADER_IMAGES_OFFSET: usize = 0x1c0;
#[doc(hidden)]
pub const HEADER_CACHE_SUB_TYPE: usize = 0x1c8;
#[doc(hidden)]
pub const HEADER_DYNAMIC_DATA_OFFSET: usize = 0x1f0;
#[doc(hidden)]
pub const HEADER_DYNAMIC_DATA_MAX_SIZE: usize = 0x1f8;

/// `dylib_use_command.marker`: the command's flags, not its `cmd`, select the
/// linkage kind.
pub const DYLIB_USE_MARKER: u32 = 0x1a74_1800;
/// The load commands that link a dependency.
pub const DYLIB_LOAD_COMMANDS: [u32; 4] = [
    object::macho::LC_LOAD_DYLIB,
    object::macho::LC_LOAD_WEAK_DYLIB,
    object::macho::LC_REEXPORT_DYLIB,
    object::macho::LC_LOAD_UPWARD_DYLIB,
];

// Fixed-size on-disk records. The private dyld records are public only for
// the ABI check.

/// `struct dyld_cache_mapping_and_slide_info`.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[doc(hidden)]
pub struct DyldCacheMappingAndSlideInfo {
    pub address: U64,
    pub size: U64,
    pub file_offset: U64,
    pub slide_info_file_offset: U64,
    pub slide_info_file_size: U64,
    pub flags: U64,
    pub max_prot: U32,
    pub init_prot: U32,
}

/// `struct dyld_subcache_entry`.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[doc(hidden)]
pub struct DyldSubcacheEntry {
    pub uuid: [u8; 16],
    pub cache_vm_offset: U64,
    pub file_suffix: [u8; 32],
}

/// `struct dyld_cache_image_info`.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[doc(hidden)]
pub struct DyldCacheImageInfo {
    pub address: U64,
    pub mod_time: U64,
    pub inode: U64,
    pub path_file_offset: U32,
    pub pad: U32,
}

/// The fixed part of `struct dyld_cache_slide_info5`; `page_starts` follows.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[doc(hidden)]
pub struct DyldCacheSlideInfo5 {
    pub version: U32,
    pub page_size: U32,
    pub page_starts_count: U32,
    /// C alignment padding before the 8-byte `value_add`.
    pub pad: U32,
    pub value_add: U64,
}

/// `struct mach_header_64`.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct MachHeader64 {
    pub magic: U32,
    pub cputype: U32,
    pub cpusubtype: U32,
    pub filetype: U32,
    pub ncmds: U32,
    pub sizeofcmds: U32,
    pub flags: U32,
    pub reserved: U32,
}

/// `struct load_command`.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct LoadCommand {
    pub cmd: U32,
    pub cmdsize: U32,
}

/// `struct segment_command_64`; `nsects` `section_64`s follow.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct SegmentCommand64 {
    pub cmd: U32,
    pub cmdsize: U32,
    pub segname: [u8; 16],
    pub vmaddr: U64,
    pub vmsize: U64,
    pub fileoff: U64,
    pub filesize: U64,
    pub maxprot: U32,
    pub initprot: U32,
    pub nsects: U32,
    pub flags: U32,
}

/// `struct section_64`.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct Section64 {
    pub sectname: [u8; 16],
    pub segname: [u8; 16],
    pub addr: U64,
    pub size: U64,
    pub offset: U32,
    pub align: U32,
    pub reloff: U32,
    pub nreloc: U32,
    pub flags: U32,
    pub reserved1: U32,
    pub reserved2: U32,
    pub reserved3: U32,
}

/// `struct dylib_command`, with its `struct dylib` inlined.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct DylibCommand {
    pub cmd: U32,
    pub cmdsize: U32,
    pub name_offset: U32,
    pub timestamp: U32,
    pub current_version: U32,
    pub compatibility_version: U32,
}

/// `struct dylib_use_command`.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct DylibUseCommand {
    pub cmd: U32,
    pub cmdsize: U32,
    pub nameoff: U32,
    pub marker: U32,
    pub current_version: U32,
    pub compat_version: U32,
    pub flags: U32,
}

/// `struct uuid_command`.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct UuidCommand {
    pub cmd: U32,
    pub cmdsize: U32,
    pub uuid: [u8; 16],
}

// Sizes from Apple's headers.
const _: () = assert!(size_of::<DyldCacheMappingAndSlideInfo>() == 56);
const _: () = assert!(size_of::<DyldSubcacheEntry>() == 56);
const _: () = assert!(size_of::<DyldCacheImageInfo>() == 32);
const _: () = assert!(size_of::<DyldCacheSlideInfo5>() == 24);
const _: () = assert!(size_of::<MachHeader64>() == 32);
const _: () = assert!(size_of::<LoadCommand>() == 8);
const _: () = assert!(size_of::<SegmentCommand64>() == 72);
const _: () = assert!(size_of::<Section64>() == 80);
const _: () = assert!(size_of::<DylibCommand>() == 24);
const _: () = assert!(size_of::<DylibUseCommand>() == 28);
const _: () = assert!(size_of::<UuidCommand>() == 24);

/// Why a shared cache was rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SharedCacheError {
    #[error("cannot read {length:#x} bytes at file offset {offset:#x}")]
    Read { offset: u64, length: usize },
    #[error("malformed shared cache: {0}")]
    Malformed(&'static str),
    #[error("unsupported shared cache: {0}")]
    Unsupported(&'static str),
    #[error("subcache {index} UUID does not match the main cache's subcache table")]
    SubcacheUuidMismatch { index: usize },
    #[error("no cache mapping covers {length:#x} bytes at {address:#x}")]
    Unmapped { address: u64, length: u64 },
    #[error("cannot parse the cache image at {address:#x}")]
    Image {
        address: u64,
        #[source]
        source: Box<SharedCacheError>,
    },
    /// The caller passed an argument this cache cannot describe.
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),
}

type Result<T> = core::result::Result<T, SharedCacheError>;

/// Random-access, read-only view of one cache file.
pub trait CacheFileReader {
    /// File length in bytes.
    fn file_len(&self) -> u64;
    /// Fill `buffer` from `offset`. Implementations fail rather than return
    /// short reads.
    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<()>;
}

impl CacheFileReader for [u8] {
    fn file_len(&self) -> u64 {
        self.len() as u64
    }

    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        let error = || SharedCacheError::Read {
            offset,
            length: buffer.len(),
        };
        let start = usize::try_from(offset).map_err(|_| error())?;
        let end = start.checked_add(buffer.len()).ok_or_else(error)?;
        buffer.copy_from_slice(self.get(start..end).ok_or_else(error)?);
        Ok(())
    }
}

impl CacheFileReader for Vec<u8> {
    fn file_len(&self) -> u64 {
        self.as_slice().file_len()
    }

    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        self.as_slice().read_exact_at(offset, buffer)
    }
}

impl<T: CacheFileReader + ?Sized> CacheFileReader for &T {
    fn file_len(&self) -> u64 {
        (**self).file_len()
    }

    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        (**self).read_exact_at(offset, buffer)
    }
}

fn read_vec<R: CacheFileReader + ?Sized>(
    reader: &R,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>> {
    let end = offset
        .checked_add(length as u64)
        .ok_or(SharedCacheError::Read { offset, length })?;
    if end > reader.file_len() {
        return Err(SharedCacheError::Read { offset, length });
    }
    let mut buffer = vec![0; length];
    reader.read_exact_at(offset, &mut buffer)?;
    Ok(buffer)
}

/// The record of type `T` at `offset`.
fn record<T: FromBytes + KnownLayout + Immutable + Unaligned>(
    bytes: &[u8],
    offset: usize,
) -> Result<&T> {
    bytes
        .get(offset..)
        .and_then(|bytes| T::ref_from_prefix(bytes).ok())
        .map(|(record, _)| record)
        .ok_or(SharedCacheError::Malformed("truncated structure"))
}

/// Read a table of `count` records of type `T` at `offset`.
fn read_records<T: FromBytes + KnownLayout + Immutable + Unaligned, R: CacheFileReader + ?Sized>(
    reader: &R,
    offset: u32,
    count: u32,
) -> Result<Vec<T>> {
    let bytes = read_vec(reader, u64::from(offset), count as usize * size_of::<T>())?;
    bytes
        .chunks_exact(size_of::<T>())
        .map(|chunk| {
            T::read_from_bytes(chunk)
                .map_err(|_| SharedCacheError::Malformed("truncated structure"))
        })
        .collect()
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    offset
        .checked_add(N)
        .and_then(|end| bytes.get(offset..end))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(SharedCacheError::Malformed("truncated structure"))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    field(bytes, offset).map(u32::from_le_bytes)
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    field(bytes, offset).map(u64::from_le_bytes)
}

/// A NUL-terminated UTF-8 string starting at `offset`, ending before `limit`.
fn c_string(bytes: &[u8], offset: usize, limit: usize) -> Result<&str> {
    let bytes = bytes
        .get(offset..limit.min(bytes.len()))
        .ok_or(SharedCacheError::Malformed("string offset"))?;
    let length = bytes
        .iter()
        .position(|&byte| byte == 0)
        .ok_or(SharedCacheError::Malformed("unterminated string"))?;
    core::str::from_utf8(&bytes[..length])
        .map_err(|_| SharedCacheError::Malformed("non-UTF-8 string"))
}

/// Read a NUL-terminated path at `offset` without reading past the file.
fn read_path<R: CacheFileReader + ?Sized>(reader: &R, offset: u64) -> Result<String> {
    let available = reader
        .file_len()
        .checked_sub(offset)
        .ok_or(SharedCacheError::Malformed("path offset"))?;
    let length = usize::try_from(available)
        .unwrap_or(usize::MAX)
        .min(crate::PATH_MAX);
    let bytes = read_vec(reader, offset, length)?;
    c_string(&bytes, 0, bytes.len()).map(String::from)
}

fn protection(raw: u32) -> Result<VmProtection> {
    raw.try_into()
        .ok()
        .and_then(VmProtection::from_bits)
        .ok_or(SharedCacheError::Malformed("VM protection"))
}

/// An `(offset, count)` table location from a cache header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TableLocation {
    pub offset: u32,
    pub count: u32,
}

/// The fields of `dyld_cache_header` this module reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheHeader {
    pub magic: [u8; 16],
    /// Also the header's size: fields at or beyond it are absent.
    pub mapping_offset: u32,
    pub uuid: [u8; 16],
    pub cache_type: u64,
    /// Unslid address of the in-cache dyld's Mach header, if any.
    pub dyld_in_cache_mh: u64,
    pub shared_region_start: u64,
    pub shared_region_size: u64,
    pub max_slide: u64,
    pub mappings_with_slide: TableLocation,
    pub subcaches: TableLocation,
    pub images: TableLocation,
    /// `dynamicDataOffset`/`dynamicDataMaxSize`, if the header has them.
    pub dynamic_data: Option<(u64, u64)>,
}

impl CacheHeader {
    /// Parse a header from the start of `bytes`.
    ///
    /// Only arm64e caches whose header includes `cacheSubType` (and therefore
    /// 56-byte subcache entries with file suffixes) are supported.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let magic: [u8; 16] = field(bytes, 0)?;
        if magic != CACHE_MAGIC_ARM64E {
            return Err(SharedCacheError::Unsupported(
                "cache magic is not dyld_v1  arm64e",
            ));
        }
        let mapping_offset = u32_at(bytes, HEADER_MAPPING_OFFSET)?;
        let header_size = mapping_offset as usize;
        if header_size <= HEADER_CACHE_SUB_TYPE {
            return Err(SharedCacheError::Unsupported("legacy cache header"));
        }
        if bytes.len() < header_size {
            return Err(SharedCacheError::Malformed("truncated header"));
        }
        let table = |offset| -> Result<TableLocation> {
            Ok(TableLocation {
                offset: u32_at(bytes, offset)?,
                count: u32_at(bytes, offset + 4)?,
            })
        };
        let dynamic_data = if header_size >= HEADER_DYNAMIC_DATA_MAX_SIZE + 8 {
            Some((
                u64_at(bytes, HEADER_DYNAMIC_DATA_OFFSET)?,
                u64_at(bytes, HEADER_DYNAMIC_DATA_MAX_SIZE)?,
            ))
        } else {
            None
        };
        Ok(Self {
            magic,
            mapping_offset,
            uuid: field(bytes, HEADER_UUID)?,
            cache_type: u64_at(bytes, HEADER_CACHE_TYPE)?,
            dyld_in_cache_mh: u64_at(bytes, HEADER_DYLD_IN_CACHE_MH)?,
            shared_region_start: u64_at(bytes, HEADER_SHARED_REGION_START)?,
            shared_region_size: u64_at(bytes, HEADER_SHARED_REGION_SIZE)?,
            max_slide: u64_at(bytes, HEADER_MAX_SLIDE)?,
            mappings_with_slide: table(HEADER_MAPPING_WITH_SLIDE_OFFSET)?,
            subcaches: table(HEADER_SUBCACHE_ARRAY_OFFSET)?,
            images: table(HEADER_IMAGES_OFFSET)?,
            dynamic_data,
        })
    }
}

bitflags::bitflags! {
    /// `dyld_cache_mapping_and_slide_info.flags`. Unknown bits are retained.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MappingFlags: u64 {
        const AUTH_DATA = 1 << 0;
        const DIRTY_DATA = 1 << 1;
        const CONST_DATA = 1 << 2;
        const TEXT_STUBS = 1 << 3;
        const DYNAMIC_CONFIG_DATA = 1 << 4;
        const READ_ONLY_DATA = 1 << 5;
        const CONST_TPRO_DATA = 1 << 6;
    }
}

/// One `dyld_cache_mapping_and_slide_info` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheMapping {
    /// Unslid address.
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    /// Location of this mapping's slide info in the same file; empty if none.
    pub slide_info: Range<u64>,
    pub flags: MappingFlags,
    pub max_protection: VmProtection,
    pub initial_protection: VmProtection,
}

impl CacheMapping {
    /// Unslid address range. [`CacheFile::parse`] rejects mappings whose end
    /// overflows; the end saturates for one built otherwise.
    pub fn address_range(&self) -> Range<u64> {
        self.address..self.address.saturating_add(self.size)
    }

    /// Byte range in the containing file; saturating like
    /// [`Self::address_range`].
    pub fn file_range(&self) -> Range<u64> {
        self.file_offset..self.file_offset.saturating_add(self.size)
    }

    fn parse(entry: &DyldCacheMappingAndSlideInfo, file_len: u64) -> Result<Self> {
        let address = entry.address.get();
        let size = entry.size.get();
        let file_offset = entry.file_offset.get();
        let slide_offset = entry.slide_info_file_offset.get();
        let slide_size = entry.slide_info_file_size.get();
        address
            .checked_add(size)
            .ok_or(SharedCacheError::Malformed("mapping address range"))?;
        if size == 0
            || file_offset
                .checked_add(size)
                .is_none_or(|end| end > file_len)
        {
            return Err(SharedCacheError::Malformed("mapping file range"));
        }
        let slide_end = slide_offset
            .checked_add(slide_size)
            .filter(|end| *end <= file_len)
            .ok_or(SharedCacheError::Malformed("slide info file range"))?;
        Ok(Self {
            address,
            size,
            file_offset,
            slide_info: slide_offset..slide_end,
            flags: MappingFlags::from_bits_retain(entry.flags.get()),
            max_protection: protection(entry.max_prot.get())?,
            initial_protection: protection(entry.init_prot.get())?,
        })
    }
}

/// One `dyld_subcache_entry` (the 56-byte form with a file suffix).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubcacheEntry {
    pub uuid: [u8; 16],
    /// Offset of the subcache's first mapping from the main cache's base.
    pub cache_vm_offset: u64,
    /// Appended to the main cache path to name the subcache file, e.g. `.01`.
    /// Validated to be a single file-name component.
    pub file_suffix: String,
}

impl SubcacheEntry {
    fn parse(entry: &DyldSubcacheEntry) -> Result<Self> {
        let file_suffix = c_string(&entry.file_suffix, 0, entry.file_suffix.len())?;
        if file_suffix.is_empty()
            || !file_suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || file_suffix.contains("..")
        {
            return Err(SharedCacheError::Malformed("subcache file suffix"));
        }
        Ok(Self {
            uuid: entry.uuid,
            cache_vm_offset: entry.cache_vm_offset.get(),
            file_suffix: String::from(file_suffix),
        })
    }
}

/// One cache file (main cache or subcache) and its mappings.
pub struct CacheFile<R> {
    reader: R,
    header: CacheHeader,
    mappings: Vec<CacheMapping>,
}

impl<R> core::fmt::Debug for CacheFile<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CacheFile")
            .field("header", &self.header)
            .field("mappings", &self.mappings)
            .finish_non_exhaustive()
    }
}

impl<R: CacheFileReader> CacheFile<R> {
    /// Parse and validate a cache file's header and mapping table. Mappings
    /// must be non-empty, inside the file, and sorted without overlap.
    pub fn parse(reader: R) -> Result<Self> {
        let prefix = read_vec(&reader, 0, HEADER_MAPPING_OFFSET + 4)?;
        let header_size = u32_at(&prefix, HEADER_MAPPING_OFFSET)? as usize;
        if header_size > MAX_HEADER_BYTES {
            return Err(SharedCacheError::Malformed("header size"));
        }
        let header_bytes = read_vec(&reader, 0, header_size.max(prefix.len()))?;
        let header = CacheHeader::parse(&header_bytes)?;
        let table = header.mappings_with_slide;
        if table.count == 0 || table.count > MAX_MAPPINGS {
            return Err(SharedCacheError::Malformed("mapping count"));
        }
        let file_len = reader.file_len();
        let mappings =
            read_records::<DyldCacheMappingAndSlideInfo, _>(&reader, table.offset, table.count)?
                .iter()
                .map(|entry| CacheMapping::parse(entry, file_len))
                .collect::<Result<Vec<_>>>()?;
        if mappings
            .windows(2)
            .any(|pair| pair[0].address_range().end > pair[1].address)
        {
            return Err(SharedCacheError::Malformed(
                "unsorted or overlapping mappings",
            ));
        }
        Ok(Self {
            reader,
            header,
            mappings,
        })
    }

    pub fn header(&self) -> &CacheHeader {
        &self.header
    }

    pub fn mappings(&self) -> &[CacheMapping] {
        &self.mappings
    }

    pub fn reader(&self) -> &R {
        &self.reader
    }

    /// The subcache table of a main cache file, in file order.
    pub fn subcache_entries(&self) -> Result<Vec<SubcacheEntry>> {
        let table = self.header.subcaches;
        if table.count > MAX_SUBCACHES {
            return Err(SharedCacheError::Malformed("subcache count"));
        }
        read_records::<DyldSubcacheEntry, _>(&self.reader, table.offset, table.count)?
            .iter()
            .map(SubcacheEntry::parse)
            .collect()
    }

    /// Slide info for `mapping`, which must be one of [`Self::mappings`], or
    /// `None` if the mapping has none.
    pub fn slide_info(&self, mapping: &CacheMapping) -> Result<Option<SlideInfoV5>> {
        if !self.mappings.contains(mapping) {
            return Err(SharedCacheError::InvalidArgument(
                "mapping is not one of this cache file's mappings",
            ));
        }
        if mapping.slide_info.is_empty() {
            return Ok(None);
        }
        let length = usize::try_from(mapping.slide_info.end - mapping.slide_info.start)
            .ok()
            .filter(|length| *length <= MAX_SLIDE_INFO_BYTES)
            .ok_or(SharedCacheError::Malformed("slide info size"))?;
        let bytes = read_vec(&self.reader, mapping.slide_info.start, length)?;
        let info = SlideInfoV5::parse(&bytes)?;
        if (info.page_count() as u64)
            .checked_mul(info.page_size() as u64)
            .is_none_or(|covered| covered < mapping.size)
        {
            return Err(SharedCacheError::Malformed(
                "slide info does not cover its mapping",
            ));
        }
        Ok(Some(info))
    }
}

/// One entry of the main cache's image table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheImageEntry {
    /// Unslid Mach header address. Aliases share an address.
    pub address: u64,
    pub path: String,
}

bitflags::bitflags! {
    /// How an image links a dependency (dyld's `LinkedDylibAttributes`);
    /// empty for a regular `LC_LOAD_DYLIB`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DylibAttributes: u8 {
        const WEAK = 0x01;
        const REEXPORT = 0x02;
        const UPWARD = 0x04;
        /// Mapped and bound at launch, but initialized only on first use.
        const DELAYED_INIT = 0x08;
    }
}

impl DylibAttributes {
    /// Decode like dyld's `loadCommandToDylibKind`: a `dylib_use_command`'s
    /// flags take precedence over `cmd`. Illegal combinations are fixed as in
    /// `JustInTimeLoader`: re-exports are never weak or delayed. A command
    /// too short to be a `dylib_use_command` decodes by `cmd`: its name check
    /// already rejects one whose `nameoff` claims that layout.
    fn decode(command: u32, body: &[u8]) -> Self {
        use object::macho;

        let use_command = DylibUseCommand::ref_from_prefix(body)
            .ok()
            .map(|(use_command, _)| use_command)
            .filter(|use_command| {
                use_command.marker.get() == DYLIB_USE_MARKER
                    && use_command.nameoff.get() as usize == size_of::<DylibUseCommand>()
            });
        let mut attributes = if let Some(use_command) = use_command {
            // dyld keeps the low byte (`(uint8_t)dylib2Cmd->flags`).
            Self::from_bits_retain(use_command.flags.get().to_le_bytes()[0])
        } else {
            match command {
                macho::LC_LOAD_WEAK_DYLIB => Self::WEAK,
                macho::LC_REEXPORT_DYLIB => Self::REEXPORT,
                macho::LC_LOAD_UPWARD_DYLIB => Self::UPWARD,
                _ => Self::empty(),
            }
        };
        if attributes.contains(Self::REEXPORT) {
            attributes.remove(Self::WEAK | Self::DELAYED_INIT);
        }
        attributes
    }
}

/// A dylib load command of a cache image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheDependency {
    pub path: String,
    pub attributes: DylibAttributes,
}

impl CacheDependency {
    /// Decode `LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`, `LC_REEXPORT_DYLIB` or
    /// `LC_LOAD_UPWARD_DYLIB` of a cache image (`body` is the whole command);
    /// `None` for other commands. Cache images are built by Apple's cache
    /// builder, so any malformed or non-UTF-8 name is an error.
    pub fn from_load_command(command: u32, body: &[u8]) -> Result<Option<Self>> {
        if !DYLIB_LOAD_COMMANDS.contains(&command) {
            return Ok(None);
        }
        Ok(Some(Self {
            path: String::from(dylib_name(body)?),
            attributes: DylibAttributes::decode(command, body),
        }))
    }
}

/// A `section_64` of a cache image segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheSection {
    pub name: String,
    /// Unslid address range.
    pub address_range: Range<u64>,
    /// `section_64.flags`: section type and attributes.
    pub flags: u32,
}

impl CacheSection {
    pub const INSTRUCTION_ATTRIBUTES: u32 =
        object::macho::S_ATTR_PURE_INSTRUCTIONS | object::macho::S_ATTR_SOME_INSTRUCTIONS;

    /// Whether the section contains machine instructions.
    pub fn has_instructions(&self) -> bool {
        self.flags & Self::INSTRUCTION_ATTRIBUTES != 0
    }
}

/// An `LC_SEGMENT_64` of a cache image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheSegment {
    pub name: String,
    /// Unslid address range.
    pub address_range: Range<u64>,
    pub max_protection: VmProtection,
    pub initial_protection: VmProtection,
    pub sections: Vec<CacheSection>,
}

/// The load commands of one cache image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheImage {
    /// Unslid Mach header address.
    pub address: u64,
    /// `MH_DYLIB` or `MH_DYLINKER`.
    pub file_type: u32,
    pub uuid: Option<[u8; 16]>,
    /// `LC_ID_DYLIB` name; dyld has none.
    pub install_name: Option<String>,
    pub segments: Vec<CacheSegment>,
    pub dependencies: Vec<CacheDependency>,
}

impl CacheImage {
    /// Parse a Mach header and its load commands (`bytes` starts at the header).
    fn parse(address: u64, bytes: &[u8]) -> Result<Self> {
        use object::macho;

        let header: &MachHeader64 = record(bytes, 0)?;
        if header.magic.get() != macho::MH_MAGIC_64 || header.cputype.get() != macho::CPU_TYPE_ARM64
        {
            return Err(SharedCacheError::Malformed(
                "cache image is not an arm64 Mach-O",
            ));
        }
        let file_type = header.filetype.get();
        if !matches!(file_type, macho::MH_DYLIB | macho::MH_DYLINKER) {
            return Err(SharedCacheError::Malformed(
                "cache image is not a dylib or dyld",
            ));
        }
        let command_count = header.ncmds.get();
        let commands_end = size_of::<MachHeader64>() + header.sizeofcmds.get() as usize;
        if commands_end > bytes.len() {
            return Err(SharedCacheError::Malformed(
                "load commands exceed the image",
            ));
        }
        let mut image = Self {
            address,
            file_type,
            uuid: None,
            install_name: None,
            segments: Vec::new(),
            dependencies: Vec::new(),
        };
        let mut offset = size_of::<MachHeader64>();
        for _ in 0..command_count {
            // Like dyld's forEachLoadCommand: a command must start before
            // the end of sizeofcmds.
            if offset >= commands_end {
                return Err(SharedCacheError::Malformed("load command count"));
            }
            let load_command: &LoadCommand = record(&bytes[..commands_end], offset)?;
            let command = load_command.cmd.get();
            let size = load_command.cmdsize.get() as usize;
            let end = offset
                .checked_add(size)
                .filter(|end| size >= 8 && size.is_multiple_of(8) && *end <= commands_end)
                .ok_or(SharedCacheError::Malformed("load command size"))?;
            let body = &bytes[offset..end];
            match command {
                macho::LC_SEGMENT_64 => image.segments.push(segment(body)?),
                macho::LC_UUID => {
                    let Ok((uuid, _)) = UuidCommand::ref_from_prefix(body) else {
                        return Err(SharedCacheError::Malformed("LC_UUID"));
                    };
                    if image.uuid.replace(uuid.uuid).is_some() {
                        return Err(SharedCacheError::Malformed("LC_UUID"));
                    }
                }
                macho::LC_ID_DYLIB => {
                    if image.install_name.is_some() {
                        return Err(SharedCacheError::Malformed("duplicate LC_ID_DYLIB"));
                    }
                    image.install_name = Some(String::from(dylib_name(body)?));
                }
                // Like dyld's forEachLinkedDylib, dyld itself links nothing.
                _ if file_type == macho::MH_DYLIB => {
                    image
                        .dependencies
                        .extend(CacheDependency::from_load_command(command, body)?);
                }
                _ => {}
            }
            offset = end;
        }
        if offset != commands_end {
            return Err(SharedCacheError::Malformed("load command count"));
        }
        Ok(image)
    }

    /// The segment named `name`, e.g. `__TEXT`.
    pub fn segment(&self, name: &str) -> Option<&CacheSegment> {
        self.segments.iter().find(|segment| segment.name == name)
    }
}

/// A fixed 16-byte, NUL-padded Mach-O name.
fn fixed_name(name: &[u8; 16]) -> Result<String> {
    let length = name
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(name.len());
    core::str::from_utf8(&name[..length])
        .map(String::from)
        .map_err(|_| SharedCacheError::Malformed("segment or section name"))
}

fn address_range(address: u64, size: u64) -> Result<Range<u64>> {
    Ok(address
        ..address
            .checked_add(size)
            .ok_or(SharedCacheError::Malformed("segment address range"))?)
}

fn segment(body: &[u8]) -> Result<CacheSegment> {
    let Ok((command, rest)) = SegmentCommand64::ref_from_prefix(body) else {
        return Err(SharedCacheError::Malformed("LC_SEGMENT_64 size"));
    };
    let segment_range = address_range(command.vmaddr.get(), command.vmsize.get())?;
    let Ok((sections, _)) =
        <[Section64]>::ref_from_prefix_with_elems(rest, command.nsects.get() as usize)
    else {
        return Err(SharedCacheError::Malformed("LC_SEGMENT_64 sections"));
    };
    let sections = sections
        .iter()
        .map(|section| {
            let range = address_range(section.addr.get(), section.size.get())?;
            if range.start < segment_range.start || range.end > segment_range.end {
                return Err(SharedCacheError::Malformed("section outside its segment"));
            }
            Ok(CacheSection {
                name: fixed_name(&section.sectname)?,
                address_range: range,
                flags: section.flags.get(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(CacheSegment {
        name: fixed_name(&command.segname)?,
        address_range: segment_range,
        max_protection: protection(command.maxprot.get())?,
        initial_protection: protection(command.initprot.get())?,
        sections,
    })
}

/// The `lc_str` name of a `dylib_command`.
fn dylib_name(body: &[u8]) -> Result<&str> {
    let Ok((command, _)) = DylibCommand::ref_from_prefix(body) else {
        return Err(SharedCacheError::Malformed("dylib command size"));
    };
    let offset = command.name_offset.get() as usize;
    if offset < size_of::<DylibCommand>() {
        return Err(SharedCacheError::Malformed("dylib name offset"));
    }
    c_string(body, offset, body.len())
}

/// A main cache file and its subcaches, verified to form one cache.
pub struct SharedCache<R> {
    files: Vec<CacheFile<R>>,
    images: Vec<CacheImageEntry>,
}

impl<R> core::fmt::Debug for SharedCache<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedCache")
            .field("files", &self.files)
            .field("image_count", &self.images.len())
            .finish_non_exhaustive()
    }
}

impl<R: CacheFileReader> SharedCache<R> {
    /// Combine `main` with `subcaches` in [`CacheFile::subcache_entries`] order.
    ///
    /// Verifies each subcache's UUID and placement against the main cache's
    /// subcache table, that every mapping lies inside the shared region and
    /// no two mappings overlap, and parses the image table.
    pub fn new(main: CacheFile<R>, subcaches: Vec<CacheFile<R>>) -> Result<Self> {
        let entries = main.subcache_entries()?;
        if entries.len() != subcaches.len() {
            return Err(SharedCacheError::Malformed("subcache count"));
        }
        let start = main.header.shared_region_start;
        let region = start
            ..start
                .checked_add(main.header.shared_region_size)
                .ok_or(SharedCacheError::Malformed("shared region size"))?;
        for (index, (entry, subcache)) in entries.iter().zip(&subcaches).enumerate() {
            if subcache.header.magic != main.header.magic {
                return Err(SharedCacheError::Malformed("subcache magic"));
            }
            if subcache.header.uuid != entry.uuid {
                return Err(SharedCacheError::SubcacheUuidMismatch { index });
            }
            if start.checked_add(entry.cache_vm_offset) != Some(subcache.mappings[0].address) {
                return Err(SharedCacheError::Malformed("subcache placement"));
            }
        }
        let mut files = vec![main];
        files.extend(subcaches);
        let mut ranges: Vec<_> = files
            .iter()
            .flat_map(|file| file.mappings.iter().map(CacheMapping::address_range))
            .collect();
        ranges.sort_unstable_by_key(|range| range.start);
        if ranges
            .iter()
            .any(|range| range.start < region.start || range.end > region.end)
            || ranges.windows(2).any(|pair| pair[0].end > pair[1].start)
        {
            return Err(SharedCacheError::Malformed(
                "mappings outside the region or overlapping",
            ));
        }
        let images = Self::parse_images(&files[0])?;
        Ok(Self { files, images })
    }

    fn parse_images(main: &CacheFile<R>) -> Result<Vec<CacheImageEntry>> {
        let table = main.header.images;
        if table.count > MAX_IMAGES {
            return Err(SharedCacheError::Malformed("image count"));
        }
        read_records::<DyldCacheImageInfo, _>(&main.reader, table.offset, table.count)?
            .iter()
            .map(|entry| {
                Ok(CacheImageEntry {
                    address: entry.address.get(),
                    path: read_path(&main.reader, u64::from(entry.path_file_offset.get()))?,
                })
            })
            .collect()
    }

    /// The main cache file followed by its subcaches.
    pub fn files(&self) -> &[CacheFile<R>] {
        &self.files
    }

    pub fn header(&self) -> &CacheHeader {
        &self.files[0].header
    }

    pub fn images(&self) -> &[CacheImageEntry] {
        &self.images
    }

    /// The first image table entry with exactly `path`.
    pub fn image_index_by_path(&self, path: &str) -> Option<usize> {
        self.images.iter().position(|image| image.path == path)
    }

    /// The first image table entry at unslid `address`.
    pub fn image_index_by_address(&self, address: u64) -> Option<usize> {
        self.images
            .iter()
            .position(|image| image.address == address)
    }

    /// The in-cache dyld named by `dyldInCacheMH`, if the cache has one.
    pub fn dyld_image_index(&self) -> Option<usize> {
        match self.header().dyld_in_cache_mh {
            0 => None,
            address => self.image_index_by_address(address),
        }
    }

    /// The file index and mapping containing `[address, address + length)`.
    pub fn mapping_containing(&self, address: u64, length: u64) -> Option<(usize, &CacheMapping)> {
        let end = address.checked_add(length)?;
        self.files.iter().enumerate().find_map(|(index, file)| {
            file.mappings
                .iter()
                .find(|mapping| {
                    let range = mapping.address_range();
                    range.start <= address && end <= range.end
                })
                .map(|mapping| (index, mapping))
        })
    }

    /// Read `length` bytes at unslid `address` from the file backing it.
    pub fn read_at_address(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        let unmapped = SharedCacheError::Unmapped {
            address,
            length: length as u64,
        };
        let (file, mapping) = self
            .mapping_containing(address, length as u64)
            .ok_or(unmapped)?;
        read_vec(
            &self.files[file].reader,
            mapping.file_offset + (address - mapping.address),
            length,
        )
    }

    /// Parse the load commands of the image whose Mach header is at `address`.
    /// Every failure is a [`SharedCacheError::Image`] naming `address`.
    pub fn parse_image(&self, address: u64) -> Result<CacheImage> {
        self.parse_image_inner(address)
            .map_err(|source| SharedCacheError::Image {
                address,
                source: Box::new(source),
            })
    }

    fn parse_image_inner(&self, address: u64) -> Result<CacheImage> {
        let header = self.read_at_address(address, size_of::<MachHeader64>())?;
        let commands = record::<MachHeader64>(&header, 0)?.sizeofcmds.get();
        if commands > MAX_LOAD_COMMAND_BYTES {
            return Err(SharedCacheError::Malformed("load command size"));
        }
        let bytes = self.read_at_address(address, size_of::<MachHeader64>() + commands as usize)?;
        CacheImage::parse(address, &bytes)
    }
}

/// Parsed `dyld_cache_slide_info5` for one mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlideInfoV5 {
    page_size: usize,
    value_add: u64,
    page_starts: Vec<u16>,
}

impl SlideInfoV5 {
    /// Parse a slide info blob. Versions other than 5 are rejected.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        // Every slide info version starts with its `uint32_t version`, and
        // older versions have shorter headers.
        if u32_at(bytes, 0)? != 5 {
            return Err(SharedCacheError::Unsupported(
                "slide info version other than 5",
            ));
        }
        let Ok((header, rest)) = DyldCacheSlideInfo5::ref_from_prefix(bytes) else {
            return Err(SharedCacheError::Malformed("truncated structure"));
        };
        let page_size = header.page_size.get() as usize;
        if !matches!(page_size, 0x1000 | 0x4000) {
            return Err(SharedCacheError::Malformed("slide info page size"));
        }
        let Ok((starts, _)) =
            <[U16]>::ref_from_prefix_with_elems(rest, header.page_starts_count.get() as usize)
        else {
            return Err(SharedCacheError::Malformed("slide info page starts"));
        };
        Ok(Self {
            page_size,
            value_add: header.value_add.get(),
            page_starts: starts.iter().map(|start| start.get()).collect(),
        })
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// Number of pages described; page `i` starts at mapping address + `i * page_size`.
    pub fn page_count(&self) -> usize {
        self.page_starts.len()
    }

    pub fn value_add(&self) -> u64 {
        self.value_add
    }

    /// Byte offset of the first rebase in `page_index`, or `None` for a page
    /// without rebases.
    pub fn page_start(&self, page_index: usize) -> Result<Option<u16>> {
        match self.page_starts.get(page_index) {
            None => Err(SharedCacheError::InvalidArgument(
                "slide page index beyond the slide info",
            )),
            Some(&SLIDE_V5_PAGE_NO_REBASE) => Ok(None),
            Some(&start) => Ok(Some(start)),
        }
    }
}

/// The main cache path recorded in a `DyldSharedCache::DynamicRegion`
/// (version 2 or later, magic `dyld_data    v<N>`).
pub fn dynamic_region_cache_path(region: &[u8]) -> Result<&str> {
    const MAGIC_PREFIX: &[u8; 14] = b"dyld_data    v";
    const CACHE_PATH_OFFSET: usize = 36;

    let magic: [u8; 16] = field(region, 0)?;
    if magic[..14] != MAGIC_PREFIX[..] || magic[15] != 0 {
        return Err(SharedCacheError::Malformed("dynamic region magic"));
    }
    let version = magic[14].wrapping_sub(b'0');
    if !(2..=9).contains(&version) {
        return Err(SharedCacheError::Unsupported("dynamic region version"));
    }
    let offset = u32_at(region, CACHE_PATH_OFFSET)? as usize;
    if offset == 0 {
        return Err(SharedCacheError::Malformed(
            "dynamic region has no cache path",
        ));
    }
    let limit = region.len().min(DYNAMIC_REGION_SIZE);
    c_string(region, offset, limit)
}

#[cfg(test)]
mod tests;
