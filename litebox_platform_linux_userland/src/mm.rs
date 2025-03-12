use litebox::{
    mm::{
        linux::{
            PAGE_SIZE, PageRange, ProtectError, RemapError, UnmapError, VmFlags, Vmem, VmemBackend,
        },
        mapping::{MappingError, MappingProvider},
    },
    platform::trivial_providers::TransparentMutPtr,
};
use nix::sys::mman::MRemapFlags;

/// Memory backend for user space
///
/// This backend uses syscalls (e.g., mmap, munmap) to manage memory.
struct UserMemBackend;

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

impl VmemBackend for UserMemBackend {
    unsafe fn map_pages(&mut self, start: usize, len: usize, flags: VmFlags) -> Option<usize> {
        unsafe {
            nix::sys::mman::mmap_anonymous(
                Some(core::num::NonZeroUsize::new(start).expect("non null addr")),
                core::num::NonZeroUsize::new(len).expect("non zero len"),
                vmflags_to_prots(flags),
                nix::sys::mman::MapFlags::MAP_PRIVATE
                    | nix::sys::mman::MapFlags::MAP_ANONYMOUS
                    | nix::sys::mman::MapFlags::MAP_FIXED,
            )
        }
        .map(|addr| addr.as_ptr() as usize)
        .ok()
    }

    unsafe fn unmap_pages(&mut self, start: usize, len: usize) -> Result<(), UnmapError> {
        if start % PAGE_SIZE != 0 {
            return Err(UnmapError::MisAligned(start));
        }
        if len % PAGE_SIZE != 0 {
            return Err(UnmapError::MisAligned(len));
        }
        unsafe {
            nix::sys::mman::munmap(
                core::ptr::NonNull::new(start as _).expect("non null addr"),
                len,
            )
        }
        .expect("munmap failed");
        Ok(())
    }

    unsafe fn remap_pages(
        &mut self,
        old_addr: usize,
        new_addr: usize,
        old_len: usize,
        new_len: usize,
    ) -> Result<(), RemapError> {
        if old_addr % PAGE_SIZE != 0 {
            return Err(RemapError::MisAligned(old_addr));
        }
        if new_addr % PAGE_SIZE != 0 {
            return Err(RemapError::MisAligned(new_addr));
        }
        if old_len % PAGE_SIZE != 0 {
            return Err(RemapError::MisAligned(old_len));
        }
        if new_len % PAGE_SIZE != 0 {
            return Err(RemapError::MisAligned(new_len));
        }
        let res = unsafe {
            nix::sys::mman::mremap(
                core::ptr::NonNull::new(old_addr as _).expect("non null addr"),
                old_len,
                new_len,
                MRemapFlags::MREMAP_FIXED,
                Some(core::ptr::NonNull::new(new_addr as _).expect("non null new addr")),
            )
            .expect("mremap failed")
        };
        assert_eq!(res.as_ptr() as usize, new_addr);
        Ok(())
    }

    unsafe fn mprotect_pages(
        &mut self,
        start: usize,
        len: usize,
        new_flags: VmFlags,
    ) -> Result<(), ProtectError> {
        unsafe {
            nix::sys::mman::mprotect(
                core::ptr::NonNull::new(start as _).expect("non null addr"),
                len,
                vmflags_to_prots(new_flags),
            )
        }
        .expect("mprotect failed");
        Ok(())
    }
}

/// Virtual memory manager for user space
pub struct UserVmem<const ALIGN: usize = PAGE_SIZE> {
    inner: Vmem<UserMemBackend, ALIGN>,
}

impl<const ALIGN: usize> UserVmem<ALIGN> {
    pub fn new() -> Self {
        Self {
            inner: Vmem::new(UserMemBackend),
        }
    }
}

impl<const ALIGN: usize> Default for UserVmem<ALIGN> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const ALIGN: usize> MappingProvider<TransparentMutPtr<u8>, ALIGN> for UserVmem<ALIGN> {
    unsafe fn create_executable_page<F>(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(TransparentMutPtr<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.inner
                .create_executable_page(suggested_range, fixed_addr, op)
        }
    }

    unsafe fn create_writable_page<F>(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(TransparentMutPtr<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.inner
                .create_writable_page(suggested_range, fixed_addr, op)
        }
    }

    unsafe fn create_readable_page<F>(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(TransparentMutPtr<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.inner
                .create_readable_page(suggested_range, fixed_addr, op)
        }
    }
}
