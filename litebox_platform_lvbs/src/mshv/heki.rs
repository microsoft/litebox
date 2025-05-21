use crate::mshv::{HvPageProtFlags, vtl1_mem_layout::PAGE_SIZE};

bitflags::bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct MemAttr: u64 {
        const MEM_ATTR_READ = 1 << 0;
        const MEM_ATTR_WRITE = 1 << 1;
        const MEM_ATTR_EXEC = 1 << 2;
        const MEM_ATTR_IMMUTABLE = 1 << 3;

        const _ = !0;

        const MEM_ATTR_PROT = Self::MEM_ATTR_READ.bits()
            | Self::MEM_ATTR_WRITE.bits()
            | Self::MEM_ATTR_EXEC.bits()
            | Self::MEM_ATTR_IMMUTABLE.bits();
    }
}

#[expect(dead_code)]
pub(crate) fn memattr_to_hvpageprotflags(attr: MemAttr) -> HvPageProtFlags {
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

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct HekiRange {
    pub va: u64,
    pub pa: u64,
    pub epa: u64,
    pub attributes: u64,
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
