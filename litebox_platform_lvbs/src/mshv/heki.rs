use crate::{
    host::linux::ListHead,
    mshv::{HvPageProtFlags, vtl1_mem_layout::PAGE_SIZE},
};
use core::mem;
use litebox_common_linux::errno::Errno;
use num_enum::TryFromPrimitive;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{PageSize, Size4KiB},
};

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

#[derive(Default, Debug, TryFromPrimitive, PartialEq)]
#[repr(u64)]
pub enum HekiKdataType {
    SystemCerts = 0,
    RevocationCerts = 1,
    BlocklistHashes = 2,
    KernelInfo = 3,
    KernelData = 4,
    PatchInfo = 5,
    KexecTrampoline = 6,
    #[default]
    Unknown = 0xffff_ffff_ffff_ffff,
}

#[derive(Default, Debug, TryFromPrimitive, PartialEq)]
#[repr(u64)]
pub enum HekiKexecType {
    KexecImage = 0,
    KexecKernelBlob = 1,
    KexecPages = 2,
    #[default]
    Unknown = 0xffff_ffff_ffff_ffff,
}

#[derive(Clone, Copy, Default, Debug, TryFromPrimitive, PartialEq)]
#[repr(u64)]
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
    Unknown = 0xffff_ffff_ffff_ffff,
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

/// `HekiRange` is a generic container for various types of memory ranges.
/// It has an `attributes` field which can be interpreted differently based on the context like
/// `MemAttr`, `KdataType`, `ModMemType`, or `KexecType`.
#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HekiRange {
    pub va: u64,
    pub pa: u64,
    pub epa: u64,
    pub attributes: u64,
}

impl HekiRange {
    #[inline]
    pub fn is_aligned<U>(&self, align: U) -> bool
    where
        U: Into<u64> + Copy,
    {
        let va = self.va;
        let pa = self.pa;
        let epa = self.epa;

        VirtAddr::new(va).is_aligned(align)
            && PhysAddr::new(pa).is_aligned(align)
            && PhysAddr::new(epa).is_aligned(align)
    }

    #[inline]
    pub fn mem_attr(&self) -> Option<MemAttr> {
        let attr = self.attributes;
        MemAttr::from_bits(attr)
    }

    #[inline]
    pub fn mod_mem_type(&self) -> ModMemType {
        let attr = self.attributes;
        ModMemType::try_from(attr).unwrap_or(ModMemType::Unknown)
    }

    #[inline]
    pub fn heki_kdata_type(&self) -> HekiKdataType {
        let attr = self.attributes;
        HekiKdataType::try_from(attr).unwrap_or(HekiKdataType::Unknown)
    }

    #[inline]
    pub fn heki_kexec_type(&self) -> HekiKexecType {
        let attr = self.attributes;
        HekiKexecType::try_from(attr).unwrap_or(HekiKexecType::Unknown)
    }

    pub fn is_valid(&self) -> bool {
        let va = self.va;
        let pa = self.pa;
        let epa = self.epa;
        let Ok(pa) = PhysAddr::try_new(pa) else {
            return false;
        };
        let Ok(epa) = PhysAddr::try_new(epa) else {
            return false;
        };
        !(VirtAddr::try_new(va).is_err()
            || epa < pa
            || (self.mem_attr().is_none()
                && self.heki_kdata_type() == HekiKdataType::Unknown
                && self.heki_kexec_type() == HekiKexecType::Unknown
                && self.mod_mem_type() == ModMemType::Unknown))
    }
}

#[expect(clippy::cast_possible_truncation)]
pub const HEKI_MAX_RANGES: usize =
    ((PAGE_SIZE as u32 - u64::BITS * 3 / 8) / core::mem::size_of::<HekiRange>() as u32) as usize;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct HekiPage {
    pub next: *mut HekiPage,
    pub next_pa: u64,
    pub nranges: u64,
    pub ranges: [HekiRange; HEKI_MAX_RANGES],
    pad: u64,
}

impl HekiPage {
    pub fn new() -> Self {
        HekiPage {
            next: core::ptr::null_mut(),
            ..Default::default()
        }
    }

    pub fn is_valid(&self) -> bool {
        if PhysAddr::try_new(self.next_pa).is_err() {
            return false;
        }
        let Some(nranges) = usize::try_from(self.nranges)
            .ok()
            .filter(|&n| n <= HEKI_MAX_RANGES)
        else {
            return false;
        };
        for heki_range in &self.ranges[..nranges] {
            if !heki_range.is_valid() {
                return false;
            }
        }
        true
    }
}

impl Default for HekiPage {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> IntoIterator for &'a HekiPage {
    type Item = &'a HekiRange;
    type IntoIter = core::slice::Iter<'a, HekiRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges[..usize::try_from(self.nranges).unwrap_or(0)].iter()
    }
}

#[derive(Default, Clone, Copy, Debug)]
#[repr(C)]
pub struct HekiPatch {
    pub pa: [u64; 2],
    pub size: u8,
    pub code: [u8; POKE_MAX_OPCODE_SIZE],
}
pub const POKE_MAX_OPCODE_SIZE: usize = 5;

impl HekiPatch {
    /// Creates a new `HekiPatch` with a given buffer. Returns `None` if any field is invalid.
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != core::mem::size_of::<HekiPatch>() {
            return None;
        }
        let mut patch = core::mem::MaybeUninit::<HekiPatch>::uninit();
        let patch = unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().cast::<u8>(),
                patch.as_mut_ptr().cast::<u8>(),
                core::mem::size_of::<HekiPatch>(),
            );
            patch.assume_init()
        };
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
                usize::try_from(pa_0.align_up(Size4KiB::SIZE) - pa_0).unwrap(),
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

#[derive(Default, Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum HekiPatchType {
    JumpLabel = 0,
    #[default]
    Unknown = 0xffff_ffff,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct HekiPatchInfo {
    pub typ_: HekiPatchType,
    list: ListHead,
    mod_: *const core::ffi::c_void, // *const `struct module`
    pub patch_index: u64,
    pub max_patch_count: u64,
    // pub patch: [HekiPatch; *]
}

impl HekiPatchInfo {
    /// Creates a new `HekiPatchInfo` with a given buffer. Returns `None` if any field is invalid.
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != core::mem::size_of::<HekiPatchInfo>() {
            return None;
        }
        let mut info = core::mem::MaybeUninit::<HekiPatchInfo>::uninit();
        let info = unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().cast::<u8>(),
                info.as_mut_ptr().cast::<u8>(),
                core::mem::size_of::<HekiPatchInfo>(),
            );
            info.assume_init()
        };
        if info.is_valid() { Some(info) } else { None }
    }

    pub fn is_valid(&self) -> bool {
        !(self.typ_ != HekiPatchType::JumpLabel
            || self.patch_index == 0
            || self.patch_index > self.max_patch_count)
    }
}

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

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Errno> {
        if bytes.len() < Self::KSYM_LEN {
            return Err(Errno::EINVAL);
        }
        let ksym_bytes: [u8; Self::KSYM_LEN] = (&bytes[..Self::KSYM_LEN])
            .try_into()
            .map_err(|_| Errno::EINVAL)?;

        // TODO: memory container's copy appears to be copying data into unaligned
        // address. Fix copy, then we can verify alignment or use trans____
        #[allow(clippy::cast_ptr_alignment)]
        let ksym_ptr = ksym_bytes.as_ptr().cast::<HekiKernelSymbol>();

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

#[repr(C)]
#[allow(clippy::struct_field_names)]
pub struct HekiKernelInfo {
    pub ksymtab_start: *const HekiKernelSymbol,
    pub ksymtab_end: *const HekiKernelSymbol,
    pub ksymtab_gpl_start: *const HekiKernelSymbol,
    pub ksymtab_gpl_end: *const HekiKernelSymbol,
    // Skip unused arch info
}

impl HekiKernelInfo {
    const KINFO_LEN: usize = mem::size_of::<HekiKernelInfo>();

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Errno> {
        if bytes.len() < Self::KINFO_LEN {
            return Err(Errno::EINVAL);
        }
        let kinfo_bytes: [u8; Self::KINFO_LEN] = (&bytes[..Self::KINFO_LEN])
            .try_into()
            .map_err(|_| Errno::EINVAL)?;

        // TODO: memory container's copy appears to be copying data into unaligned
        // address. Fix copy, then we can verify alignment or use trans____
        #[allow(clippy::cast_ptr_alignment)]
        let kinfo_ptr = kinfo_bytes.as_ptr().cast::<HekiKernelInfo>();

        // SAFETY: Casting from vtl0 buffer that contained the struct
        unsafe {
            Ok(HekiKernelInfo {
                ksymtab_start: (*kinfo_ptr).ksymtab_start,
                ksymtab_end: (*kinfo_ptr).ksymtab_end,
                ksymtab_gpl_start: (*kinfo_ptr).ksymtab_gpl_start,
                ksymtab_gpl_end: (*kinfo_ptr).ksymtab_gpl_end,
            })
        }
    }
}
