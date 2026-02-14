// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VSM data-only types shared between platform and runner.

extern crate alloc;

use crate::error::VsmError;
use crate::heki::{HekiKernelSymbol, HekiRange, ModMemType};
use crate::mem_layout::PAGE_SIZE;
use alloc::{ffi::CString, string::String, vec::Vec};
use core::ffi::{c_char, CStr};
use core::mem;
use x86_64::{
    structures::paging::{frame::PhysFrameRange, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};
use zerocopy::{FromBytes, Immutable, KnownLayout};

#[derive(Copy, Clone, FromBytes, Immutable, KnownLayout)]
#[repr(align(4096))]
pub struct AlignedPage(pub [u8; PAGE_SIZE]);

// For now, we do not validate large kernel modules due to the VTL1's memory size limitation.
pub const MODULE_VALIDATION_MAX_SIZE: usize = 64 * 1024 * 1024;

// --- ModuleMemory types ---

pub struct ModuleMemoryMetadata {
    pub ranges: Vec<ModuleMemoryRange>,
    patch_targets: Vec<PhysAddr>,
}

impl ModuleMemoryMetadata {
    pub fn new() -> Self {
        Self {
            ranges: Vec::new(),
            patch_targets: Vec::new(),
        }
    }

    #[inline]
    pub fn insert_heki_range(&mut self, heki_range: &HekiRange) {
        let va = heki_range.va;
        let pa = heki_range.pa;
        let epa = heki_range.epa;
        self.insert_memory_range(ModuleMemoryRange::new(
            va,
            pa,
            epa,
            heki_range.mod_mem_type(),
        ));
    }

    #[inline]
    pub fn insert_memory_range(&mut self, mem_range: ModuleMemoryRange) {
        self.ranges.push(mem_range);
    }

    #[inline]
    pub fn insert_patch_target(&mut self, patch_target: PhysAddr) {
        self.patch_targets.push(patch_target);
    }

    // This function returns patch targets belonging to this module to remove them
    // from the precomputed patch data map when the module is unloaded.
    #[inline]
    pub fn get_patch_targets(&self) -> &Vec<PhysAddr> {
        &self.patch_targets
    }
}

impl Default for ModuleMemoryMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleMemoryMetadata {
    /// Returns an iterator over the memory ranges.
    pub fn iter(&self) -> core::slice::Iter<'_, ModuleMemoryRange> {
        self.ranges.iter()
    }
}

impl<'a> IntoIterator for &'a ModuleMemoryMetadata {
    type Item = &'a ModuleMemoryRange;
    type IntoIter = core::slice::Iter<'a, ModuleMemoryRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter()
    }
}

#[derive(Clone, Copy)]
pub struct ModuleMemoryRange {
    pub virt_addr: VirtAddr,
    pub phys_frame_range: PhysFrameRange<Size4KiB>,
    pub mod_mem_type: ModMemType,
}

impl ModuleMemoryRange {
    pub fn new(virt_addr: u64, phys_start: u64, phys_end: u64, mod_mem_type: ModMemType) -> Self {
        Self {
            virt_addr: VirtAddr::new(virt_addr),
            phys_frame_range: PhysFrame::range(
                PhysFrame::containing_address(PhysAddr::new(phys_start)),
                PhysFrame::containing_address(PhysAddr::new(phys_end)),
            ),
            mod_mem_type,
        }
    }
}

impl Default for ModuleMemoryRange {
    fn default() -> Self {
        Self::new(0, 0, 0, ModMemType::Unknown)
    }
}

// TODO: `ModuleMemoryMetadata` and `KexecMemoryMetadata` are similar. Consider merging them into a single structure if possible.
// --- Kexec memory types ---

pub struct KexecMemoryMetadata {
    pub ranges: Vec<KexecMemoryRange>,
}

impl KexecMemoryMetadata {
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    #[inline]
    pub fn insert_heki_range(&mut self, heki_range: &HekiRange) {
        let va = heki_range.va;
        let pa = heki_range.pa;
        let epa = heki_range.epa;
        self.insert_memory_range(KexecMemoryRange::new(va, pa, epa));
    }

    #[inline]
    pub fn insert_memory_range(&mut self, mem_range: KexecMemoryRange) {
        self.ranges.push(mem_range);
    }

    #[inline]
    pub fn clear(&mut self) {
        self.ranges.clear();
    }
}

impl Default for KexecMemoryMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl KexecMemoryMetadata {
    /// Returns an iterator over the memory ranges.
    pub fn iter(&self) -> core::slice::Iter<'_, KexecMemoryRange> {
        self.ranges.iter()
    }
}

impl<'a> IntoIterator for &'a KexecMemoryMetadata {
    type Item = &'a KexecMemoryRange;
    type IntoIter = core::slice::Iter<'a, KexecMemoryRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter()
    }
}

#[derive(Clone, Copy)]
pub struct KexecMemoryRange {
    pub virt_addr: VirtAddr,
    pub phys_frame_range: PhysFrameRange<Size4KiB>,
}

impl KexecMemoryRange {
    pub fn new(virt_addr: u64, phys_start: u64, phys_end: u64) -> Self {
        Self {
            virt_addr: VirtAddr::new(virt_addr),
            phys_frame_range: PhysFrame::range(
                PhysFrame::containing_address(PhysAddr::new(phys_start)),
                PhysFrame::containing_address(PhysAddr::new(phys_end)),
            ),
        }
    }
}

impl Default for KexecMemoryRange {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

/// Data structure for abstracting addressable paged memory ranges.
#[derive(Clone, Copy)]
pub struct MemoryRange {
    pub addr: VirtAddr,
    pub phys_addr: PhysAddr,
    pub len: u64,
}

// TODO: Use this to resolve symbols in modules
pub struct Symbol {
    _value: u64,
}

impl Symbol {
    /// Parse a symbol from a byte buffer.
    pub fn from_bytes(
        kinfo_start: usize,
        start: VirtAddr,
        bytes: &[u8],
    ) -> Result<(String, Self), VsmError> {
        let kinfo_bytes = &bytes[kinfo_start..];
        let ksym = HekiKernelSymbol::from_bytes(kinfo_bytes)?;

        let value_addr = start + mem::offset_of!(HekiKernelSymbol, value_offset) as u64;
        let value = value_addr
            .as_u64()
            .wrapping_add_signed(i64::from(ksym.value_offset));

        let name_offset = kinfo_start
            + mem::offset_of!(HekiKernelSymbol, name_offset)
            + usize::try_from(ksym.name_offset).map_err(|_| VsmError::SymbolNameOffsetInvalid)?;

        if name_offset >= bytes.len() {
            return Err(VsmError::SymbolNameOffsetInvalid);
        }
        let name_len = bytes[name_offset..]
            .iter()
            .position(|&b| b == 0)
            .ok_or(VsmError::SymbolNameNoTerminator)?;
        if name_len >= HekiKernelSymbol::KSY_NAME_LEN {
            return Err(VsmError::SymbolNameTooLong);
        }

        // SAFETY:
        // - offset is within bytes (checked above)
        // - there is a NUL terminator within bytes[offset..] (checked above)
        // - Length of name string is within spec range (checked above)
        // - bytes is still valid for the duration of this function
        let name_str = unsafe {
            let name_ptr = bytes.as_ptr().add(name_offset).cast::<c_char>();
            CStr::from_ptr(name_ptr)
        };
        let name = CString::new(
            name_str
                .to_str()
                .map_err(|_| VsmError::SymbolNameInvalidUtf8)?,
        )
        .map_err(|_| VsmError::SymbolNameInvalidUtf8)?;
        let name = name
            .into_string()
            .map_err(|_| VsmError::SymbolNameInvalidUtf8)?;
        Ok((name, Symbol { _value: value }))
    }
}
