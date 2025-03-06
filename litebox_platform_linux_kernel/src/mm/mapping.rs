use litebox::platform::MappingProvider;

use super::{pgtable::PageTableImpl, vm::Vmem};

impl<PT: PageTableImpl> MappingProvider for Vmem<PT> {
    fn create_executable_page<F>(
        &self,
        suggested_addr: Option<usize>,
        op: F,
    ) -> Result<usize, litebox::platform::MappingError>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        todo!()
    }

    fn create_writable_page<F>(
        &self,
        suggested_addr: Option<usize>,
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
        op: F,
    ) -> Result<usize, litebox::platform::MappingError>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        todo!()
    }
}
