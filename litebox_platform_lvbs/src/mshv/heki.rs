use crate::{
    host::linux::ListHead,
    mshv::{HvPageProtFlags, vtl1_mem_layout::PAGE_SIZE},
};
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

#[derive(Default, Debug, TryFromPrimitive)]
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

#[derive(Default, Debug, TryFromPrimitive)]
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
}

impl Default for HekiPage {
    fn default() -> Self {
        Self::new()
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
    /// Creates a new `HekiPatch` with the given buffer. Returns `None` if any field is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != core::mem::size_of::<HekiPatch>() {
            return None;
        }
        let mut heki_patch = core::mem::MaybeUninit::<HekiPatch>::uninit();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().cast::<u8>(),
                heki_patch.as_mut_ptr().cast::<u8>(),
                core::mem::size_of::<HekiPatch>(),
            );
        }
        let heki_patch = unsafe { heki_patch.assume_init() };
        if heki_patch.is_valid() {
            Some(heki_patch)
        } else {
            None
        }
    }

    pub fn is_valid(&self) -> bool {
        let bytes_in_first_page = usize::try_from(
            PhysAddr::new(self.pa[0]).align_up(Size4KiB::SIZE) - PhysAddr::new(self.pa[0]),
        )
        .unwrap();

        !(usize::from(self.size) > POKE_MAX_OPCODE_SIZE
            || (self.pa[0] != 0 && self.pa[0] == self.pa[1])
            || (self.pa[1] == 0 && bytes_in_first_page < usize::from(self.size))
            || (self.pa[1] != 0 && bytes_in_first_page > usize::from(self.size)))
    }
}

#[expect(dead_code)]
#[derive(Default, Clone, Copy, Debug)]
#[repr(u32)]
pub enum HekiPatchType {
    JumpLabel = 0,
    #[default]
    Unknown = 0xffff_ffff,
}

#[expect(dead_code)]
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
