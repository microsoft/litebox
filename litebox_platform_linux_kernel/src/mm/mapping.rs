//! Memory mapping functions for the Linux kernel.
//!
//! Here is an example of mmap sequences when loading a simple statically linked binary:
//! ```
//! mmap addr: 0x400000, len: 0xcd000, prot: PROT_READ, flags: MAP_PRIVATE, offset: 0x0, fd: 3
//! mmap addr: 0x401000, len: 0x97000, prot: PROT_READ | PROT_EXEC, flags: MAP_PRIVATE | MAP_FIXED, offset: 0x1000, fd: 3
//! mmap addr: 0x498000, len: 0x29000, prot: PROT_READ, flags: MAP_PRIVATE | MAP_FIXED, offset: 0x98000, fd: 3
//! mmap addr: 0x4c1000, len: 0xc000,  prot: PROT_READ | PROT_WRITE, flags: MAP_PRIVATE | MAP_FIXED, offset: 0xc0000, fd: 3
//! mmap addr: 0x4c8000, len: 0x5000,  prot: PROT_READ | PROT_WRITE, flags: MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS
//! ```
//!
//! Our current design would result in copying the entire file into the memory twice.
//!

use litebox::platform::{MappingError, MappingProvider};

use super::{
    pgtable::PageTableImpl,
    vm::{PageRange, VmFlags, Vmem, VmemProtectError},
};
use crate::{
    arch::{Page, VirtAddr},
    ptr::UserMutPtr,
};

impl<PT: PageTableImpl> Vmem<PT> {
    fn create_pages<F>(
        &mut self,
        suggested_addr: Option<usize>,
        len: usize,
        fixed_addr: bool,
        before_flags: VmFlags,
        after_flags: VmFlags,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(UserMutPtr<u8>) -> Result<usize, MappingError>,
    {
        let start_addr = VirtAddr::new(suggested_addr.unwrap_or(0) as u64);
        let start_page = Page::from_start_address(start_addr).unwrap();
        let end_page = Page::from_start_address(start_addr + len as u64).unwrap();
        let addr = self
            .create_mapping(
                PageRange::new(start_page, end_page),
                before_flags,
                fixed_addr,
            )
            .ok_or(MappingError::OutOfMemory)?;
        // call the user function with the pages
        let _ = op(UserMutPtr::<u8>::from(addr))?;
        if before_flags != after_flags {
            match self.protect_mapping(PageRange::new(start_page, end_page), after_flags) {
                Ok(_) => Ok(addr.as_u64() as usize),
                Err(VmemProtectError::AllocationFailed) => Err(MappingError::OutOfMemory),
                Err(VmemProtectError::InvalidRange(_)) | Err(VmemProtectError::NoAccess { .. }) => {
                    // This should not happen, as we just created the mapping.
                    unreachable!()
                }
            }
        } else {
            Ok(addr.as_u64() as usize)
        }
    }
}

impl<PT: PageTableImpl> MappingProvider<UserMutPtr<u8>> for Vmem<PT> {
    fn create_executable_page<F>(
        &mut self,
        suggested_addr: Option<usize>,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(UserMutPtr<u8>) -> Result<usize, MappingError>,
    {
        self.create_pages(
            suggested_addr,
            len,
            fixed_addr,
            // create READ | WRITE pages (set MAYEXEC so we can enable it later)
            VmFlags::VM_READ | VmFlags::VM_WRITE | VmFlags::VM_MAYREAD | VmFlags::VM_MAYEXEC,
            // keep VM_READ, turn off VM_WRITE and turn on VM_EXEC
            VmFlags::VM_READ | VmFlags::VM_EXEC | VmFlags::VM_MAYREAD | VmFlags::VM_MAYEXEC,
            op,
        )
    }

    fn create_writable_page<F>(
        &mut self,
        suggested_addr: Option<usize>,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, litebox::platform::MappingError>
    where
        F: FnOnce(UserMutPtr<u8>) -> Result<usize, MappingError>,
    {
        let flags =
            VmFlags::VM_READ | VmFlags::VM_WRITE | VmFlags::VM_MAYREAD | VmFlags::VM_MAYWRITE;
        self.create_pages(suggested_addr, len, fixed_addr, flags, flags, op)
    }

    fn create_readable_page<F>(
        &mut self,
        suggested_addr: Option<usize>,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, litebox::platform::MappingError>
    where
        F: FnOnce(UserMutPtr<u8>) -> Result<usize, MappingError>,
    {
        self.create_pages(
            suggested_addr,
            len,
            fixed_addr,
            VmFlags::VM_READ | VmFlags::VM_WRITE | VmFlags::VM_MAYREAD,
            VmFlags::VM_READ | VmFlags::VM_MAYREAD,
            op,
        )
    }
}
