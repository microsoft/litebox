// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Read-only parsing of an on-disk dyld shared cache.
//!
//! Layouts follow `dyld/include/mach-o/dyld_cache_format.h`. All fields are
//! read explicitly as little-endian and every offset, count and size is
//! bounds-checked: malformed input yields [`SharedCacheError`], never a panic
//! or an arithmetic overflow. Files are read lazily through
//! [`CacheFileReader`], so multi-GiB cache files need not be loaded.
//!
//! Intended use: parse the main cache file with [`CacheFile::parse`], open each
//! [`CacheFile::subcache_entries`] file (main path + suffix), combine them with
//! [`SharedCache::new`] (which verifies subcache identity and layout), compute
//! the libSystem closure with [`SharedCache::closure`], and rebase DATA pages
//! with [`SlideInfoV5::rebase_page`].

use crate::VmProtection;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec,
    vec::Vec,
};
use core::ops::Range;

/// Magic of an arm64e cache file (main cache and subcaches).
pub const CACHE_MAGIC_ARM64E: [u8; 16] = *b"dyld_v1  arm64e\0";

/// `DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE`.
pub const SLIDE_V5_PAGE_NO_REBASE: u16 = 0xffff;

/// Size of a `DyldSharedCache::DynamicRegion` reservation.
pub const DYNAMIC_REGION_SIZE: usize = 0x4000;

/// Longest accepted path string (Darwin `PATH_MAX`, including NUL).
const MAX_PATH_BYTES: usize = crate::PATH_MAX;
/// Upper bounds that reject absurd counts before allocating.
const MAX_MAPPINGS: u32 = 64;
const MAX_SUBCACHES: u32 = 1024;
const MAX_IMAGES: u32 = 1 << 20;
const MAX_LOAD_COMMAND_BYTES: u32 = 1 << 20;
const MAX_HEADER_BYTES: usize = 0x4000;
const MAX_SLIDE_INFO_BYTES: usize = 1 << 24;

// dyld_cache_header field offsets.
const HEADER_MAPPING_OFFSET: usize = 0x10;
const HEADER_UUID: usize = 0x58;
const HEADER_CACHE_TYPE: usize = 0x68;
const HEADER_DYLD_IN_CACHE_MH: usize = 0x78;
const HEADER_SHARED_REGION_START: usize = 0xe0;
const HEADER_SHARED_REGION_SIZE: usize = 0xe8;
const HEADER_MAX_SLIDE: usize = 0xf0;
const HEADER_MAPPING_WITH_SLIDE_OFFSET: usize = 0x138;
const HEADER_SUBCACHE_ARRAY_OFFSET: usize = 0x188;
const HEADER_IMAGES_OFFSET: usize = 0x1c0;
const HEADER_CACHE_SUB_TYPE: usize = 0x1c8;
const HEADER_DYNAMIC_DATA_OFFSET: usize = 0x1f0;
const HEADER_DYNAMIC_DATA_MAX_SIZE: usize = 0x1f8;

const MAPPING_AND_SLIDE_INFO_BYTES: usize = 56;
const SUBCACHE_ENTRY_BYTES: usize = 56;
const IMAGE_INFO_BYTES: usize = 32;
const SLIDE_INFO_V5_HEADER_BYTES: usize = 24;

const MACH_HEADER_64_BYTES: usize = 32;
const SEGMENT_COMMAND_64_BYTES: usize = 72;
const SECTION_64_BYTES: usize = 80;
const DYLIB_COMMAND_BYTES: usize = 24;
const DYLIB_USE_COMMAND_BYTES: usize = 28;
/// `dylib_use_command.marker`: the command's flags, not its `cmd`, select the
/// linkage kind.
const DYLIB_USE_MARKER: u32 = 0x1a74_1800;
const UUID_COMMAND_BYTES: usize = 24;

/// Why a shared cache was rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
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
    #[error("{image} requires {dependency}, which is not in the shared cache")]
    MissingDependency { image: String, dependency: String },
    #[error("slide chain leaves page {page_index} at offset {offset:#x}")]
    ChainOutOfPage { page_index: usize, offset: usize },
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
        .min(MAX_PATH_BYTES);
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

/// The fields of `dyld_cache_header` the guest cache instance needs.
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
    /// Unslid address range.
    pub fn address_range(&self) -> Range<u64> {
        // Validated by `CacheFile::parse`.
        self.address..self.address + self.size
    }

    /// Byte range in the containing file.
    pub fn file_range(&self) -> Range<u64> {
        self.file_offset..self.file_offset + self.size
    }

    fn parse(bytes: &[u8], file_len: u64) -> Result<Self> {
        let address = u64_at(bytes, 0)?;
        let size = u64_at(bytes, 8)?;
        let file_offset = u64_at(bytes, 16)?;
        let slide_offset = u64_at(bytes, 24)?;
        let slide_size = u64_at(bytes, 32)?;
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
            flags: MappingFlags::from_bits_retain(u64_at(bytes, 40)?),
            max_protection: protection(u32_at(bytes, 48)?)?,
            initial_protection: protection(u32_at(bytes, 52)?)?,
        })
    }
}

/// One 56-byte `dyld_subcache_entry`.
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
    fn parse(bytes: &[u8]) -> Result<Self> {
        let file_suffix = c_string(bytes, 24, SUBCACHE_ENTRY_BYTES)?;
        if file_suffix.is_empty()
            || !file_suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || file_suffix.contains("..")
        {
            return Err(SharedCacheError::Malformed("subcache file suffix"));
        }
        Ok(Self {
            uuid: field(bytes, 0)?,
            cache_vm_offset: u64_at(bytes, 16)?,
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
        let bytes = read_vec(
            &reader,
            u64::from(table.offset),
            table.count as usize * MAPPING_AND_SLIDE_INFO_BYTES,
        )?;
        let file_len = reader.file_len();
        let mappings = bytes
            .as_chunks::<MAPPING_AND_SLIDE_INFO_BYTES>()
            .0
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
        let bytes = read_vec(
            &self.reader,
            u64::from(table.offset),
            table.count as usize * SUBCACHE_ENTRY_BYTES,
        )?;
        bytes
            .as_chunks::<SUBCACHE_ENTRY_BYTES>()
            .0
            .iter()
            .map(|entry| SubcacheEntry::parse(entry))
            .collect()
    }

    /// Slide info for `mapping`, or `None` if the mapping has none.
    pub fn slide_info(&self, mapping: &CacheMapping) -> Result<Option<SlideInfoV5>> {
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
    /// `JustInTimeLoader`: re-exports are never weak or delayed.
    fn decode(command: u32, body: &[u8]) -> Result<Self> {
        use object::macho;

        let mut attributes = if u32_at(body, 12)? == DYLIB_USE_MARKER
            && u32_at(body, 8)? as usize == DYLIB_USE_COMMAND_BYTES
        {
            Self::from_bits_retain(field::<1>(body, 24)?[0])
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
        Ok(attributes)
    }
}

/// A dylib load command of a cache image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheDependency {
    pub path: String,
    pub attributes: DylibAttributes,
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
    /// `S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS`.
    const INSTRUCTION_ATTRIBUTES: u32 = 0x8000_0400;

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

        if u32_at(bytes, 0)? != macho::MH_MAGIC_64 || u32_at(bytes, 4)? != macho::CPU_TYPE_ARM64 {
            return Err(SharedCacheError::Malformed(
                "cache image is not an arm64 Mach-O",
            ));
        }
        let file_type = u32_at(bytes, 12)?;
        if !matches!(file_type, macho::MH_DYLIB | macho::MH_DYLINKER) {
            return Err(SharedCacheError::Malformed(
                "cache image is not a dylib or dyld",
            ));
        }
        let command_count = u32_at(bytes, 16)?;
        let commands_end = MACH_HEADER_64_BYTES + u32_at(bytes, 20)? as usize;
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
        let mut offset = MACH_HEADER_64_BYTES;
        for _ in 0..command_count {
            let command = u32_at(bytes, offset)?;
            let size = u32_at(bytes, offset + 4)? as usize;
            let end = offset
                .checked_add(size)
                .filter(|end| size >= 8 && size.is_multiple_of(8) && *end <= commands_end)
                .ok_or(SharedCacheError::Malformed("load command size"))?;
            let body = &bytes[offset..end];
            match command {
                macho::LC_SEGMENT_64 => image.segments.push(segment(body)?),
                macho::LC_UUID => {
                    if body.len() < UUID_COMMAND_BYTES || image.uuid.is_some() {
                        return Err(SharedCacheError::Malformed("LC_UUID"));
                    }
                    image.uuid = Some(field(body, 8)?);
                }
                macho::LC_ID_DYLIB => {
                    if image.install_name.is_some() {
                        return Err(SharedCacheError::Malformed("duplicate LC_ID_DYLIB"));
                    }
                    image.install_name = Some(String::from(dylib_name(body)?));
                }
                macho::LC_LOAD_DYLIB
                | macho::LC_LOAD_WEAK_DYLIB
                | macho::LC_REEXPORT_DYLIB
                | macho::LC_LOAD_UPWARD_DYLIB
                    // Like dyld's forEachLinkedDylib, dyld itself links nothing.
                    if file_type == macho::MH_DYLIB =>
                {
                    image.dependencies.push(CacheDependency {
                        path: String::from(dylib_name(body)?),
                        attributes: DylibAttributes::decode(command, body)?,
                    });
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
fn fixed_name(bytes: &[u8], offset: usize) -> Result<String> {
    let name: [u8; 16] = field(bytes, offset)?;
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
    if body.len() < SEGMENT_COMMAND_64_BYTES {
        return Err(SharedCacheError::Malformed("LC_SEGMENT_64 size"));
    }
    let address_range = address_range(u64_at(body, 24)?, u64_at(body, 32)?)?;
    let section_count = u32_at(body, 64)? as usize;
    if section_count
        .checked_mul(SECTION_64_BYTES)
        .and_then(|bytes| bytes.checked_add(SEGMENT_COMMAND_64_BYTES))
        .is_none_or(|needed| needed > body.len())
    {
        return Err(SharedCacheError::Malformed("LC_SEGMENT_64 sections"));
    }
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let section = SEGMENT_COMMAND_64_BYTES + index * SECTION_64_BYTES;
        let range = address_range_of_section(body, section)?;
        if range.start < address_range.start || range.end > address_range.end {
            return Err(SharedCacheError::Malformed("section outside its segment"));
        }
        sections.push(CacheSection {
            name: fixed_name(body, section)?,
            address_range: range,
            flags: u32_at(body, section + 64)?,
        });
    }
    Ok(CacheSegment {
        name: fixed_name(body, 8)?,
        address_range,
        max_protection: protection(u32_at(body, 56)?)?,
        initial_protection: protection(u32_at(body, 60)?)?,
        sections,
    })
}

/// The unslid address range of the `section_64` at `offset` in a segment command.
fn address_range_of_section(body: &[u8], offset: usize) -> Result<Range<u64>> {
    address_range(u64_at(body, offset + 32)?, u64_at(body, offset + 40)?)
}

/// The `lc_str` name of a `dylib_command`.
fn dylib_name(body: &[u8]) -> Result<&str> {
    if body.len() < DYLIB_COMMAND_BYTES {
        return Err(SharedCacheError::Malformed("dylib command size"));
    }
    let offset = u32_at(body, 8)? as usize;
    if offset < DYLIB_COMMAND_BYTES {
        return Err(SharedCacheError::Malformed("dylib name offset"));
    }
    c_string(body, offset, body.len())
}

/// One image of a dependency closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosureImage {
    /// Index of the image's first entry in [`SharedCache::images`].
    pub index: usize,
    pub image: CacheImage,
}

/// A main cache file and its subcaches, verified to form one cache.
pub struct SharedCache<R> {
    files: Vec<CacheFile<R>>,
    images: Vec<CacheImageEntry>,
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
        let bytes = read_vec(
            &main.reader,
            u64::from(table.offset),
            table.count as usize * IMAGE_INFO_BYTES,
        )?;
        bytes
            .as_chunks::<IMAGE_INFO_BYTES>()
            .0
            .iter()
            .map(|entry| {
                Ok(CacheImageEntry {
                    address: u64_at(entry, 0)?,
                    path: read_path(&main.reader, u64::from(u32_at(entry, 24)?))?,
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
    pub fn parse_image(&self, address: u64) -> Result<CacheImage> {
        let header = self.read_at_address(address, MACH_HEADER_64_BYTES)?;
        let commands = u32_at(&header, 20)?;
        if commands > MAX_LOAD_COMMAND_BYTES {
            return Err(SharedCacheError::Malformed("load command size"));
        }
        let bytes = self.read_at_address(address, MACH_HEADER_64_BYTES + commands as usize)?;
        CacheImage::parse(address, &bytes)
    }

    /// The transitive dylib closure of `roots` (image table indices): the
    /// images dyld initializes at launch. It follows regular, weak, re-export
    /// and upward links, but not [`DylibAttributes::DELAYED_INIT`] links, whose
    /// targets dyld initializes only on first use. Aliases resolve to one
    /// image, cycles are visited once, and only missing weak dependencies are
    /// tolerated. Results are sorted by address.
    pub fn closure(&self, roots: &[usize]) -> Result<Vec<ClosureImage>> {
        self.closure_with(roots, false)
    }

    /// Like [`Self::closure`], but also following
    /// [`DylibAttributes::DELAYED_INIT`] links: every image dyld creates a
    /// loader for (maps, binds and exposes to debuggers) at launch, including
    /// those whose initializers it delays.
    pub fn launch_set(&self, roots: &[usize]) -> Result<Vec<ClosureImage>> {
        self.closure_with(roots, true)
    }

    fn closure_with(
        &self,
        roots: &[usize],
        follow_delayed_init: bool,
    ) -> Result<Vec<ClosureImage>> {
        let mut pending = Vec::new();
        for &root in roots {
            pending.push(
                self.images
                    .get(root)
                    .ok_or(SharedCacheError::Malformed("closure root index"))?
                    .address,
            );
        }
        let mut visited = BTreeMap::new();
        let mut queued: BTreeSet<u64> = pending.iter().copied().collect();
        while let Some(address) = pending.pop() {
            let index = self
                .image_index_by_address(address)
                .ok_or(SharedCacheError::Malformed("closure image address"))?;
            let image = self.parse_image(address)?;
            for dependency in &image.dependencies {
                if !follow_delayed_init
                    && dependency
                        .attributes
                        .contains(DylibAttributes::DELAYED_INIT)
                {
                    continue;
                }
                let Some(target) = self.image_index_by_path(&dependency.path) else {
                    if dependency.attributes.contains(DylibAttributes::WEAK) {
                        continue;
                    }
                    return Err(SharedCacheError::MissingDependency {
                        image: self.images[index].path.clone(),
                        dependency: dependency.path.clone(),
                    });
                };
                let target = self.images[target].address;
                if queued.insert(target) {
                    pending.push(target);
                }
            }
            visited.insert(address, ClosureImage { index, image });
        }
        Ok(visited.into_values().collect())
    }
}

/// Which A key signs an authenticated pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointerAuthKey {
    /// Instruction key A (`pacia`).
    Ia,
    /// Data key A (`pacda`).
    Da,
}

/// Signs rebased authenticated pointers for the task that will use them.
pub trait PointerSigner {
    fn sign(&self, value: u64, key: PointerAuthKey, discriminator: u64) -> u64;
}

/// Leaves authenticated pointers unsigned, as XNU does for a task without
/// JOP keys (an arm64 process, where pointer authentication is disabled).
#[derive(Clone, Copy, Debug, Default)]
pub struct UnsignedPointers;

impl PointerSigner for UnsignedPointers {
    fn sign(&self, value: u64, _: PointerAuthKey, _: u64) -> u64 {
        value
    }
}

/// `__builtin_ptrauth_blend_discriminator(slot_address, diversity)`.
pub const fn blended_discriminator(slot_address: u64, diversity: u16) -> u64 {
    (slot_address & 0x0000_ffff_ffff_ffff) | ((diversity as u64) << 48)
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
        let version = u32_at(bytes, 0)?;
        if version != 5 {
            return Err(SharedCacheError::Unsupported(
                "slide info version other than 5",
            ));
        }
        let page_size = u32_at(bytes, 4)? as usize;
        if !matches!(page_size, 0x1000 | 0x4000) {
            return Err(SharedCacheError::Malformed("slide info page size"));
        }
        let count = u32_at(bytes, 8)? as usize;
        let starts = count
            .checked_mul(2)
            .and_then(|length| length.checked_add(SLIDE_INFO_V5_HEADER_BYTES))
            .and_then(|end| bytes.get(SLIDE_INFO_V5_HEADER_BYTES..end))
            .ok_or(SharedCacheError::Malformed("slide info page starts"))?;
        Ok(Self {
            page_size,
            value_add: u64_at(bytes, 16)?,
            page_starts: starts
                .as_chunks::<2>()
                .0
                .iter()
                .map(|start| u16::from_le_bytes(*start))
                .collect(),
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
            None => Err(SharedCacheError::Malformed("slide page index")),
            Some(&SLIDE_V5_PAGE_NO_REBASE) => Ok(None),
            Some(&start) => Ok(Some(start)),
        }
    }

    /// Rebase one DATA page like xnu `vm_shared_region_slide_page_v5`.
    ///
    /// `page` holds the page's file bytes, `page_index` is its index within
    /// the mapping, `slide` is the instance base minus `sharedRegionStart`, and
    /// `page_address` is the page's slid address, used for address-diversified
    /// discriminators. `page` is left unchanged on error.
    pub fn rebase_page(
        &self,
        page: &mut [u8],
        page_index: usize,
        slide: u64,
        page_address: u64,
        signer: &impl PointerSigner,
    ) -> Result<()> {
        const TARGET_MASK: u64 = 0x3_ffff_ffff;
        const AUTHENTICATED: u64 = 1 << 63;
        const ADDRESS_DIVERSIFIED: u64 = 1 << 50;
        const KEY_IS_DATA: u64 = 1 << 51;

        if page.len() != self.page_size {
            return Err(SharedCacheError::Malformed("slide page length"));
        }
        let Some(start) = self.page_start(page_index)? else {
            return Ok(());
        };
        let overflow = SharedCacheError::Malformed("rebased pointer overflows");
        let mut rebased = page.to_vec();
        let mut offset = usize::from(start);
        loop {
            let out_of_page = SharedCacheError::ChainOutOfPage { page_index, offset };
            if !offset.is_multiple_of(size_of::<u64>()) {
                return Err(out_of_page);
            }
            let slot: [u8; 8] = offset
                .checked_add(size_of::<u64>())
                .and_then(|end| rebased.get(offset..end))
                .and_then(|slot| slot.try_into().ok())
                .ok_or(out_of_page)?;
            let raw = u64::from_le_bytes(slot);
            let next = ((raw >> 52) & 0x7ff) as usize;
            let target = (raw & TARGET_MASK)
                .checked_add(self.value_add)
                .and_then(|value| value.checked_add(slide))
                .ok_or(overflow.clone())?;
            let value = if raw & AUTHENTICATED == 0 {
                let high8 = (raw << 22) & 0xff00_0000_0000_0000;
                target.checked_add(high8).ok_or(overflow.clone())?
            } else {
                let diversity = ((raw >> 34) & 0xffff) as u16;
                let discriminator = if raw & ADDRESS_DIVERSIFIED == 0 {
                    u64::from(diversity)
                } else {
                    let slot_address = page_address
                        .checked_add(offset as u64)
                        .ok_or(overflow.clone())?;
                    blended_discriminator(slot_address, diversity)
                };
                let key = if raw & KEY_IS_DATA == 0 {
                    PointerAuthKey::Ia
                } else {
                    PointerAuthKey::Da
                };
                signer.sign(target, key, discriminator)
            };
            rebased[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
            if next == 0 {
                break;
            }
            offset += next * size_of::<u64>();
        }
        page.copy_from_slice(&rebased);
        Ok(())
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
