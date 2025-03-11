use thiserror::Error;

use crate::platform::RawMutPointer;

use super::vm::{PageRange, VmArea, VmFlags, Vmem, VmemBackend};

#[non_exhaustive]
#[derive(Error, Debug)]
pub enum MappingError {
    #[error("not enough memory")]
    OutOfMemory,
    #[error("failed to read from file")]
    ReadError(#[from] crate::fs::errors::ReadError),
}

pub trait MappingProvider<P: RawMutPointer<u8> + From<usize>> {
    fn create_executable_page<F>(
        &mut self,
        suggested_addr: Option<usize>,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(P) -> Result<usize, MappingError>;

    fn create_writable_page<F>(
        &mut self,
        suggested_addr: Option<usize>,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(P) -> Result<usize, MappingError>;

    fn create_readable_page<F>(
        &mut self,
        suggested_addr: Option<usize>,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(P) -> Result<usize, MappingError>;
}

impl<Backend: VmemBackend> Vmem<Backend> {
    fn create_pages<F, P>(
        &mut self,
        suggested_addr: Option<usize>,
        len: usize,
        fixed_addr: bool,
        before_flags: VmFlags,
        after_flags: VmFlags,
        op: F,
    ) -> Result<usize, MappingError>
    where
        P: RawMutPointer<u8> + From<usize>,
        F: FnOnce(P) -> Result<usize, MappingError>,
    {
        let start_addr = suggested_addr.unwrap_or(0);
        let addr = self
            .create_mapping(
                PageRange::new(start_addr, start_addr + len),
                VmArea::new(before_flags),
                fixed_addr,
            )
            .ok_or(MappingError::OutOfMemory)?;
        // call the user function with the pages
        let _ = op(P::from(addr))?;
        if before_flags != after_flags {
            // `protect` should succeed, as we just created the mapping.
            self.protect_mapping(PageRange::new(addr, addr + len), after_flags)
                .expect("failed to protect mapping");
        }
        Ok(addr)
    }
}

impl<P: RawMutPointer<u8> + From<usize>, Backend: VmemBackend> MappingProvider<P>
    for Vmem<Backend>
{
    fn create_executable_page<F>(
        &mut self,
        suggested_addr: Option<usize>,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(P) -> Result<usize, MappingError>,
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
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(P) -> Result<usize, MappingError>,
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
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(P) -> Result<usize, MappingError>,
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
