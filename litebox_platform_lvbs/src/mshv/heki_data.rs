// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VTL0 data format and parsing
#![allow(clippy::trivially_copy_pass_by_ref)]

use modular_bitfield::{
    bitfield,
    prelude::{B16, B32},
};
use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::mshv::{
    error::VsmError,
    heki::{HekiKdataType, HekiKexecType, HekiPatchType, HekiSymbolInfoType, ModMemType},
    vtl1_mem_layout::PAGE_SIZE,
};

#[bitfield(bits = 64)]
#[derive(Debug, Clone, Copy, Default)]
#[repr(u64)]
pub struct HekiDataApiAttr {
    #[skip(setters)]
    pub data_type: HekiKdataType,
    #[skip(setters)]
    pub size: B16, // Size of data page or buffer will be < 2^16-1
    pub flags: B32, // Custom flags per api
}

/// `HekiDataRange` describes a range of VTL0 memory, its associated
/// context-specific type and memory attributes.
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct HekiDataRange {
    pub va: u64,
    pub pa: u64,
    pub size: u32,
    data_type: u16,
    pub mem_attr: u16,
}

impl core::fmt::Debug for HekiDataRange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let data_type = self.data_type;
        let va = self.va;
        let pa = self.pa;
        let size = self.size;
        let attr = self.mem_attr;
        f.debug_struct("HekiDataRange")
            .field("va", &format_args!("{va:#x}"))
            .field("pa", &format_args!("{pa:#x}"))
            .field("epa", &format_args!("{:#x}", pa + u64::from(size)))
            .field("attr", &format_args!("{attr:#x}"))
            .field("type", &format_args!("{data_type}"))
            .field("size", &format_args!("{size}"))
            .finish()
    }
}

impl HekiDataRange {
    #[inline]
    pub fn heki_symbol_info_type(&self) -> HekiSymbolInfoType {
        HekiSymbolInfoType::try_from(self.data_type).unwrap_or(HekiSymbolInfoType::Unknown)
    }

    #[inline]
    pub fn heki_kdata_type(&self) -> HekiKdataType {
        HekiKdataType::try_from(self.data_type).unwrap_or(HekiKdataType::Unknown)
    }

    #[inline]
    pub fn heki_mod_mem_type(&self) -> ModMemType {
        ModMemType::try_from(self.data_type).unwrap_or(ModMemType::Unknown)
    }

    #[inline]
    pub fn heki_kexec_type(&self) -> HekiKexecType {
        HekiKexecType::try_from(self.data_type).unwrap_or(HekiKexecType::Unknown)
    }

    #[inline]
    pub fn heki_patch_type(&self) -> HekiPatchType {
        HekiPatchType::try_from(self.data_type).unwrap_or(HekiPatchType::Unknown)
    }
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct HekiDataHdr {
    data_type: u16,
    range_count: u16,
    rsvd: u32,
    next: u64,
    next_pa: u64,
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
pub struct HekiDataPage {
    hdr: HekiDataHdr,
    range: [HekiDataRange; Self::MAX_RANGE_COUNT],
}

impl core::fmt::Debug for HekiDataPage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let data_type =
            HekiKdataType::try_from(self.hdr.data_type).unwrap_or(HekiKdataType::Unknown);
        let count = self.hdr.range_count;
        let next = self.hdr.next_pa;
        f.debug_struct("HekiDataPage")
            .field("type", &format_args!("{data_type:#?}"))
            .field("ranges", &format_args!("{count}"))
            .field("next", &format_args!("{next:#x}"))
            .finish_non_exhaustive()
    }
}

impl HekiDataPage {
    const SIZE: usize = PAGE_SIZE;
    const MAX_RANGE_COUNT: usize =
        (Self::SIZE - size_of::<HekiDataHdr>()) / size_of::<HekiDataRange>();

    pub fn try_from_bytes(bytes: &[u8]) -> Result<&Self, VsmError> {
        let (data_page, _) =
            HekiDataPage::ref_from_prefix(bytes).map_err(|_| VsmError::DataPageInvalid)?;
        Ok(data_page)
    }

    pub fn kdata_type(&self) -> HekiKdataType {
        HekiKdataType::try_from(self.hdr.data_type).unwrap_or(HekiKdataType::Unknown)
    }

    pub fn next_page_params(&self) -> Option<(u64, u64, usize)> {
        if self.hdr.next_pa != 0 {
            Some((self.hdr.next, self.hdr.next_pa, Self::SIZE))
        } else {
            None
        }
    }
}

impl<'a> IntoIterator for &'a HekiDataPage {
    type Item = (u16, &'a [HekiDataRange]);
    type IntoIter = HekiDataPageIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        HekiDataPageIter {
            range_index: 0,
            range: &self.range[0..self.hdr.range_count as usize],
        }
    }
}

pub struct HekiDataPageIter<'a> {
    range_index: usize,
    range: &'a [HekiDataRange],
}

impl<'a> Iterator for HekiDataPageIter<'a> {
    type Item = (u16, &'a [HekiDataRange]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.range_index == self.range.len() {
            None
        } else {
            let start_index = self.range_index;
            let range_type = self.range[start_index].data_type;
            let mut end_index: usize = start_index + 1;

            while end_index < self.range.len() {
                if self.range[end_index].data_type == range_type {
                    end_index += 1;
                } else {
                    break;
                }
            }
            self.range_index = end_index;
            Some((range_type, &self.range[start_index..end_index]))
        }
    }
}
