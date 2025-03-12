//! Memory mapping provider built on top of the [virtual memory mamager](`Vmem`) to provide
//! readable, writable, or executable pages.

use thiserror::Error;

use crate::platform::RawMutPointer;

use super::linux::{PageRange, VmArea, VmFlags, Vmem, VmemBackend};

/// Error for creating mappings
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum MappingError {
    #[error("not enough memory")]
    OutOfMemory,
    #[error("failed to read from file")]
    ReadError(#[from] crate::fs::errors::ReadError),
}

pub trait MappingProvider<P: RawMutPointer<u8> + From<usize>, const ALIGN: usize> {
    /// Create readable and executable pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    unsafe fn create_executable_page<F>(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(P) -> Result<usize, MappingError>;

    /// Create readable and writable pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    unsafe fn create_writable_page<F>(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(P) -> Result<usize, MappingError>;

    /// Create read-only pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    unsafe fn create_readable_page<F>(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(P) -> Result<usize, MappingError>;
}

impl<Backend: VmemBackend, const ALIGN: usize> Vmem<Backend, ALIGN> {
    /// Create a mapping with the given flags.
    ///
    /// `suggested_range` is the range of pages to create. If the start address is not given (i.e., zero), some
    /// available memory region will be chosen. Otherwise, the range will be created at the given address if it
    /// is available.
    ///
    /// Set `fixed_addr` to `true` to force the mapping to be created at the given address, resulting in any
    /// existing overlapping mappings being removed.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// `before_flags` and `after_flags` are the flags to set before and after the call to `op`.
    ///
    /// # Safety
    ///
    /// Note that if the suggested address is given and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    ///
    /// Also, caller must ensure flags are set correctly.
    unsafe fn create_pages<F, P>(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        fixed_addr: bool,
        before_flags: VmFlags,
        after_flags: VmFlags,
        op: F,
    ) -> Result<usize, MappingError>
    where
        P: RawMutPointer<u8> + From<usize>,
        F: FnOnce(P) -> Result<usize, MappingError>,
    {
        let addr =
            unsafe { self.create_mapping(suggested_range, VmArea::new(before_flags), fixed_addr) }
                .ok_or(MappingError::OutOfMemory)?;
        // call the user function with the pages
        let _ = op(P::from(addr))?;
        if before_flags != after_flags {
            // `protect` should succeed, as we just created the mapping.
            unsafe {
                self.protect_mapping(
                    PageRange::new_unchecked(addr, addr + suggested_range.len()),
                    after_flags,
                )
            }
            .expect("failed to protect mapping");
        }
        Ok(addr)
    }
}

impl<P: RawMutPointer<u8> + From<usize>, Backend: VmemBackend, const ALIGN: usize>
    MappingProvider<P, ALIGN> for Vmem<Backend, ALIGN>
{
    unsafe fn create_executable_page<F>(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(P) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_range,
                fixed_addr,
                // create READ | WRITE pages (set MAYEXEC so we can enable it later)
                VmFlags::VM_READ | VmFlags::VM_WRITE | VmFlags::VM_MAYREAD | VmFlags::VM_MAYEXEC,
                // keep VM_READ, turn off VM_WRITE and turn on VM_EXEC
                VmFlags::VM_READ | VmFlags::VM_EXEC | VmFlags::VM_MAYREAD | VmFlags::VM_MAYEXEC,
                op,
            )
        }
    }

    unsafe fn create_writable_page<F>(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(P) -> Result<usize, MappingError>,
    {
        let flags =
            VmFlags::VM_READ | VmFlags::VM_WRITE | VmFlags::VM_MAYREAD | VmFlags::VM_MAYWRITE;
        unsafe { self.create_pages(suggested_range, fixed_addr, flags, flags, op) }
    }

    unsafe fn create_readable_page<F>(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, MappingError>
    where
        F: FnOnce(P) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_range,
                fixed_addr,
                VmFlags::VM_READ | VmFlags::VM_WRITE | VmFlags::VM_MAYREAD,
                VmFlags::VM_READ | VmFlags::VM_MAYREAD,
                op,
            )
        }
    }
}
