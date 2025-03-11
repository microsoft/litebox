use litebox::{
    mm::{
        mapping::MappingProvider,
        vm::{Vmem, VmemBackend},
    },
    platform::trivial_providers::TransparentMutPtr,
};
use nix::sys::mman::MRemapFlags;

struct UserMemBackend;

fn vmflags_to_prots(flags: litebox::mm::vm::VmFlags) -> nix::sys::mman::ProtFlags {
    let mut mmap_prot = nix::sys::mman::ProtFlags::PROT_NONE;
    if flags.contains(litebox::mm::vm::VmFlags::VM_READ) {
        mmap_prot |= nix::sys::mman::ProtFlags::PROT_READ;
    }
    if flags.contains(litebox::mm::vm::VmFlags::VM_WRITE) {
        mmap_prot |= nix::sys::mman::ProtFlags::PROT_WRITE;
    }
    if flags.contains(litebox::mm::vm::VmFlags::VM_EXEC) {
        mmap_prot |= nix::sys::mman::ProtFlags::PROT_EXEC;
    }
    mmap_prot
}

impl VmemBackend for UserMemBackend {
    fn map_pages(
        &mut self,
        start: usize,
        len: usize,
        flags: litebox::mm::vm::VmFlags,
    ) -> Option<usize> {
        unsafe {
            nix::sys::mman::mmap_anonymous(
                Some(core::num::NonZeroUsize::new(start).unwrap()),
                core::num::NonZeroUsize::new(len).unwrap(),
                vmflags_to_prots(flags),
                nix::sys::mman::MapFlags::MAP_PRIVATE
                    | nix::sys::mman::MapFlags::MAP_ANONYMOUS
                    | nix::sys::mman::MapFlags::MAP_FIXED,
            )
        }
        .map(|addr| addr.as_ptr() as usize)
        .ok()
    }

    unsafe fn unmap_pages(&mut self, start: usize, len: usize, _free_page: bool) {
        unsafe {
            nix::sys::mman::munmap(core::ptr::NonNull::new(start as _).unwrap(), len).unwrap();
        }
    }

    unsafe fn remap_pages(
        &mut self,
        old_addr: usize,
        new_addr: usize,
        old_len: usize,
        new_len: usize,
    ) -> Result<(), litebox::mm::vm::RemapError> {
        let res = unsafe {
            nix::sys::mman::mremap(
                core::ptr::NonNull::new(old_addr as _).unwrap(),
                old_len,
                new_len,
                MRemapFlags::MREMAP_FIXED,
                Some(core::ptr::NonNull::new(new_addr as _).unwrap()),
            )
            .unwrap()
        };
        assert_eq!(res.as_ptr() as usize, new_addr);
        Ok(())
    }

    unsafe fn mprotect_pages(
        &mut self,
        start: usize,
        len: usize,
        new_flags: litebox::mm::vm::VmFlags,
    ) -> Result<(), litebox::mm::vm::ProtectError> {
        unsafe {
            nix::sys::mman::mprotect(
                core::ptr::NonNull::new(start as _).unwrap(),
                len,
                vmflags_to_prots(new_flags),
            )
        }
        .expect("mprotect failed");
        Ok(())
    }
}

pub struct UserVmem {
    inner: Vmem<UserMemBackend>,
}

impl UserVmem {
    pub fn new() -> Self {
        Self {
            inner: Vmem::new(UserMemBackend),
        }
    }
}

impl MappingProvider<TransparentMutPtr<u8>> for UserVmem {
    fn create_executable_page<F>(
        &mut self,
        suggested_addr: Option<usize>,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, litebox::mm::mapping::MappingError>
    where
        F: FnOnce(TransparentMutPtr<u8>) -> Result<usize, litebox::mm::mapping::MappingError>,
    {
        self.inner
            .create_executable_page(suggested_addr, len, fixed_addr, op)
    }

    fn create_writable_page<F>(
        &mut self,
        suggested_addr: Option<usize>,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, litebox::mm::mapping::MappingError>
    where
        F: FnOnce(TransparentMutPtr<u8>) -> Result<usize, litebox::mm::mapping::MappingError>,
    {
        self.inner
            .create_writable_page(suggested_addr, len, fixed_addr, op)
    }

    fn create_readable_page<F>(
        &mut self,
        suggested_addr: Option<usize>,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, litebox::mm::mapping::MappingError>
    where
        F: FnOnce(TransparentMutPtr<u8>) -> Result<usize, litebox::mm::mapping::MappingError>,
    {
        self.inner
            .create_readable_page(suggested_addr, len, fixed_addr, op)
    }
}
