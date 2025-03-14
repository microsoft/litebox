use litebox::mm::linux::{
    MmapError, PageRange, ProtectError, RemapError, UnmapError, VmFlags, VmemBackend,
};
use nix::sys::mman::MRemapFlags;

/// Memory backend for user space
///
/// This backend uses syscalls (e.g., mmap, munmap) to manage memory.
pub struct UserMemBackend;

/// Convert [`VmFlags`] to [`nix::sys::mman::ProtFlags`].
fn vmflags_to_prots(flags: VmFlags) -> nix::sys::mman::ProtFlags {
    let mut mmap_prot = nix::sys::mman::ProtFlags::PROT_NONE;
    if flags.contains(VmFlags::VM_READ) {
        mmap_prot |= nix::sys::mman::ProtFlags::PROT_READ;
    }
    if flags.contains(VmFlags::VM_WRITE) {
        mmap_prot |= nix::sys::mman::ProtFlags::PROT_WRITE;
    }
    if flags.contains(VmFlags::VM_EXEC) {
        mmap_prot |= nix::sys::mman::ProtFlags::PROT_EXEC;
    }
    mmap_prot
}

impl<const ALIGN: usize> VmemBackend<ALIGN> for UserMemBackend {
    type InitItem = ();

    unsafe fn new(_item: Self::InitItem) -> Self {
        Self
    }

    unsafe fn map_pages(
        &mut self,
        range: PageRange<ALIGN>,
        flags: VmFlags,
    ) -> Result<(), MmapError> {
        unsafe {
            nix::sys::mman::mmap_anonymous(
                Some(core::num::NonZeroUsize::new(range.start).expect("non null addr")),
                core::num::NonZeroUsize::new(range.len()).expect("non zero len"),
                vmflags_to_prots(flags),
                nix::sys::mman::MapFlags::MAP_PRIVATE
                    | nix::sys::mman::MapFlags::MAP_ANONYMOUS
                    | nix::sys::mman::MapFlags::MAP_FIXED,
            )
        }
        .expect("mmap failed");
        Ok(())
    }

    unsafe fn unmap_pages(&mut self, range: PageRange<ALIGN>) -> Result<(), UnmapError> {
        unsafe {
            nix::sys::mman::munmap(
                core::ptr::NonNull::new(range.start as _).expect("non null addr"),
                range.len(),
            )
        }
        .expect("munmap failed");
        Ok(())
    }

    unsafe fn remap_pages(
        &mut self,
        old_range: PageRange<ALIGN>,
        new_range: PageRange<ALIGN>,
    ) -> Result<(), RemapError> {
        let res = unsafe {
            nix::sys::mman::mremap(
                core::ptr::NonNull::new(old_range.start as _).expect("non null addr"),
                old_range.len(),
                new_range.len(),
                MRemapFlags::MREMAP_FIXED,
                Some(core::ptr::NonNull::new(new_range.start as _).expect("non null new addr")),
            )
            .expect("mremap failed")
        };
        assert_eq!(res.as_ptr() as usize, new_range.start);
        Ok(())
    }

    unsafe fn mprotect_pages(
        &mut self,
        range: PageRange<ALIGN>,
        new_flags: VmFlags,
    ) -> Result<(), ProtectError> {
        unsafe {
            nix::sys::mman::mprotect(
                core::ptr::NonNull::new(range.start as _).expect("non null addr"),
                range.len(),
                vmflags_to_prots(new_flags),
            )
        }
        .expect("mprotect failed");
        Ok(())
    }
}
