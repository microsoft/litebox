use litebox::platform::{MappingError, MappingProvider};

use super::{
    pgtable::PageTableImpl,
    vm::{VmFlags, Vmem, VmemProtectError},
};
use crate::{
    arch::{Page, VirtAddr},
    ptr::UserMutPtr,
};

impl<PT: PageTableImpl> MappingProvider<UserMutPtr<u8>> for Vmem<PT> {
    fn create_executable_page<F>(
        &mut self,
        suggested_addr: Option<usize>,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(UserMutPtr<u8>) -> usize,
    {
        let start_addr = VirtAddr::new(suggested_addr.unwrap_or(0) as u64);
        let start_page = Page::from_start_address(start_addr).unwrap();
        let end_page = Page::from_start_address(start_addr + len as u64).unwrap();
        // VM_EXEC implies VM_READ
        let flags = VmFlags::VM_WRITE | VmFlags::VM_MAYWRITE;
        let addr = self
            .create_mapping(Page::range(start_page, end_page), flags, fixed_addr)
            .ok_or(MappingError::OutOfMemory)?;
        let _ = op(UserMutPtr::<u8>::from(addr));
        let flush = {
            #[cfg(test)]
            {
                false
            }
            #[cfg(not(test))]
            {
                true
            }
        };
        match self.protect_mapping(Page::range(start_page, end_page), flags, flush) {
            Ok(_) => Ok(addr.as_u64() as usize),
            Err(VmemProtectError::AllocationFailed) => Err(MappingError::OutOfMemory),
            _ => unreachable!(),
        }
    }

    fn create_writable_page<F>(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, litebox::platform::MappingError>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        todo!()
    }

    fn create_readable_page<F>(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, litebox::platform::MappingError>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        todo!()
    }
}
