// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub use litebox_common_lvbs::heki::{
    mem_attr_to_hv_page_prot_flags, mod_mem_type_to_mem_attr, HekiKdataType, HekiKernelInfo,
    HekiKernelSymbol, HekiKexecType, HekiPage, HekiPatch, HekiRange, MemAttr, ModMemType,
    HEKI_MAX_RANGES, POKE_MAX_OPCODE_SIZE,
};

use crate::host::linux::ListHead;
use zerocopy::{FromBytes, Immutable, KnownLayout};

// --- Items that stay in platform (depend on ListHead from host/linux.rs) ---

#[derive(Default, Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum HekiPatchType {
    JumpLabel = 0,
    #[default]
    Unknown = 0xffff_ffff,
}

#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct HekiPatchInfo {
    /// Patch type stored as u32 for zerocopy compatibility (see `HekiPatchType`)
    pub typ_: u32,
    list: ListHead,
    /// *const `struct module` (stored as u64 since we don't dereference it)
    mod_: u64,
    pub patch_index: u64,
    pub max_patch_count: u64,
    // pub patch: [HekiPatch; *]
}

impl HekiPatchInfo {
    /// Creates a new `HekiPatchInfo` with a given buffer. Returns `None` if any field is invalid.
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        let info = Self::read_from_bytes(bytes).ok()?;
        if info.is_valid() {
            Some(info)
        } else {
            None
        }
    }

    pub fn is_valid(&self) -> bool {
        !(self.typ_ != HekiPatchType::JumpLabel as u32
            || self.patch_index == 0
            || self.patch_index > self.max_patch_count)
    }
}
