// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{
    host::linux::ListHead,
    mshv::{HvPageProtFlags, error::VsmError, vtl1_mem_layout::PAGE_SIZE},
};
use core::mem;
use litebox::utils::TruncateExt;
use modular_bitfield::Specifier;
use num_enum::TryFromPrimitive;
use x86_64::{
    PhysAddr,
    structures::paging::{PageSize, Size4KiB},
};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct MemAttr: u64 {
        const MEM_ATTR_READ = 1 << 0;
        const MEM_ATTR_WRITE = 1 << 1;
        const MEM_ATTR_EXEC = 1 << 2;
        const MEM_ATTR_IMMUTABLE = 1 << 3;

        const _ = !0;
    }
}

pub(crate) fn mem_attr_to_hv_page_prot_flags(attr: MemAttr) -> HvPageProtFlags {
    let mut flags = HvPageProtFlags::empty();

    if attr.contains(MemAttr::MEM_ATTR_READ) {
        flags.set(HvPageProtFlags::HV_PAGE_READABLE, true);
        flags.set(HvPageProtFlags::HV_PAGE_USER_EXECUTABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_WRITE) {
        flags.set(HvPageProtFlags::HV_PAGE_WRITABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_EXEC) {
        flags.set(HvPageProtFlags::HV_PAGE_EXECUTABLE, true);
    }

    flags
}

#[derive(Default, Debug, TryFromPrimitive, PartialEq, Specifier)]
#[bits = 16]
#[repr(u16)]
pub enum HekiKdataType {
    SystemCerts = 0,
    RevocationCerts = 1,
    BlocklistHashes = 2,
    KernelInfo = 3,
    KernelData = 4,
    PatchInfo = 5,
    KexecTrampoline = 6,
    SymbolInfo = 7,
    ModuleInfo = 8,
    PermInfo = 9,
    KexecInfo = 10,
    DataPage = 0xff,
    #[default]
    Unknown = 0xffff,
}

#[derive(Debug, TryFromPrimitive, PartialEq)]
#[repr(u16)]
pub enum HekiSymbolInfoType {
    SymbolTable = 0,
    GplSymbolTable = 1,
    SymbolStringTable = 2,
    Unknown = 0xffff,
}

#[derive(Default, Debug, TryFromPrimitive, PartialEq)]
#[repr(u16)]
pub enum HekiKexecType {
    KexecImage = 0,
    KexecKernelBlob = 1,
    KexecPages = 2,
    #[default]
    Unknown = 0xffff,
}

#[derive(Clone, Copy, Default, Debug, TryFromPrimitive, PartialEq)]
#[repr(u16)]
pub enum ModMemType {
    Text = 0,
    Data = 1,
    RoData = 2,
    RoAfterInit = 3,
    InitText = 4,
    InitData = 5,
    InitRoData = 6,
    ElfBuffer = 7,
    Patch = 8,
    #[default]
    Unknown = 0xffff,
}

pub(crate) fn mod_mem_type_to_mem_attr(mod_mem_type: ModMemType) -> MemAttr {
    let mut mem_attr = MemAttr::empty();

    match mod_mem_type {
        ModMemType::Text | ModMemType::InitText => {
            mem_attr.set(MemAttr::MEM_ATTR_READ, true);
            mem_attr.set(MemAttr::MEM_ATTR_EXEC, true);
        }
        ModMemType::Data | ModMemType::RoAfterInit | ModMemType::InitData => {
            mem_attr.set(MemAttr::MEM_ATTR_READ, true);
            mem_attr.set(MemAttr::MEM_ATTR_WRITE, true);
        }
        ModMemType::RoData | ModMemType::InitRoData => {
            mem_attr.set(MemAttr::MEM_ATTR_READ, true);
        }
        _ => {}
    }

    mem_attr
}

#[derive(Default, Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct HekiPatch {
    pub pa: [u64; 2],
    pub size: u8,
    pub code: [u8; POKE_MAX_OPCODE_SIZE],
    _padding: [u8; 2],
}
pub const POKE_MAX_OPCODE_SIZE: usize = 5;

impl HekiPatch {
    /// Creates a new `HekiPatch` with a given buffer. Returns `None` if any field is invalid.
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        let patch = Self::read_from_bytes(bytes).ok()?;
        if patch.is_valid() { Some(patch) } else { None }
    }

    pub fn is_valid(&self) -> bool {
        let Some(pa_0) = PhysAddr::try_new(self.pa[0])
            .ok()
            .filter(|&pa| !pa.is_null())
        else {
            return false;
        };
        let Some(pa_1) = PhysAddr::try_new(self.pa[1])
            .ok()
            .filter(|&pa| pa.is_null() || pa.is_aligned(Size4KiB::SIZE))
        else {
            return false;
        };
        let bytes_in_first_page = if pa_0.is_aligned(Size4KiB::SIZE) {
            core::cmp::min(PAGE_SIZE, usize::from(self.size))
        } else {
            core::cmp::min(
                (pa_0.align_up(Size4KiB::SIZE) - pa_0).truncate(),
                usize::from(self.size),
            )
        };

        !(self.size == 0
            || usize::from(self.size) > POKE_MAX_OPCODE_SIZE
            || (pa_0 == pa_1)
            || (bytes_in_first_page < usize::from(self.size) && pa_1.is_null())
            || (bytes_in_first_page == usize::from(self.size) && !pa_1.is_null()))
    }
}

#[derive(Default, Clone, Copy, Debug, PartialEq, TryFromPrimitive)]
#[repr(u16)]
pub enum HekiPatchType {
    JumpLabel = 0,
    #[default]
    Unknown = 0xffff,
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
        if info.is_valid() { Some(info) } else { None }
    }

    pub fn is_valid(&self) -> bool {
        !(self.typ_ != HekiPatchType::JumpLabel as u32
            || self.patch_index == 0
            || self.patch_index > self.max_patch_count)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C)]
#[allow(clippy::struct_field_names)]
// TODO: Account for kernel config changing the size and meaning of the field members
pub struct HekiKernelSymbol {
    pub value_offset: core::ffi::c_int,
    pub name_offset: core::ffi::c_int,
    pub namespace_offset: core::ffi::c_int,
}

impl HekiKernelSymbol {
    pub const KSYM_LEN: usize = mem::size_of::<HekiKernelSymbol>();
    pub const KSY_NAME_LEN: usize = 512;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VsmError> {
        if bytes.len() < Self::KSYM_LEN {
            return Err(VsmError::BufferTooSmall("HekiKernelSymbol"));
        }

        #[allow(clippy::cast_ptr_alignment)]
        let ksym_ptr = bytes.as_ptr().cast::<HekiKernelSymbol>();
        assert!(ksym_ptr.is_aligned(), "ksym_ptr is not aligned");

        // SAFETY: Casting from vtl0 buffer that contained the struct
        unsafe {
            Ok(HekiKernelSymbol {
                value_offset: (*ksym_ptr).value_offset,
                name_offset: (*ksym_ptr).name_offset,
                namespace_offset: (*ksym_ptr).namespace_offset,
            })
        }
    }
}
