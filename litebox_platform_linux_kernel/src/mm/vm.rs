//! Virtual memory manager in Kernel

use core::ops::Range;

use litebox::mm::{
    linux::{PAGE_SIZE, PageRange, VmArea, VmFlags, Vmem},
    mapping::MappingProvider,
};

use crate::{
    arch::{
        Page, PageFaultErrorCode, PhysAddr, VirtAddr,
        mm::paging::{X64PageTable, vmflags_to_pteflags},
    },
    ptr::UserMutPtr,
};

use super::pgtable::{PageFaultError, PageTableImpl};

/// Virtual memory manager in Kernel that uses `PageTableImpl` as the backend.
pub struct KernelVmem<PT: PageTableImpl, const ALIGN: usize> {
    inner: Vmem<PT, ALIGN>,
}

impl<PT: PageTableImpl, const ALIGN: usize> KernelVmem<PT, ALIGN> {
    const STACK_GUARD_GAP: usize = 256 << 12;

    /// Create a new `KernelVmem` instance with the physical address of a page table.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `p` is a valid address of a top-level page table.
    pub unsafe fn new(p: PhysAddr) -> Self {
        KernelVmem {
            inner: Vmem::<PT, ALIGN>::new(unsafe { PT::init(p) }),
        }
    }

    /// Get the page table
    pub fn get_pgtable(&self) -> &PT {
        &self.inner.backend
    }

    /// Gets an iterator over the mappings in the virtual memory manager,
    /// ordered by the address of the mappings.
    pub fn iter(&self) -> impl Iterator<Item = (&Range<usize>, &VmArea)> {
        self.inner.iter()
    }

    /// Insert a range to its virtual address space.
    ///
    /// # Safety
    ///
    /// See [`Vmem::insert_mapping`] for more details.
    pub unsafe fn insert_mapping(&mut self, range: PageRange<ALIGN>, vma: VmArea) {
        unsafe { self.inner.insert_mapping(range, vma) };
    }

    /// Handle a page fault for the given address.
    pub fn handle_page_fault(
        &mut self,
        fault_addr: usize,
        error_code: PageFaultErrorCode,
    ) -> Result<(), PageFaultError> {
        let fault_addr = fault_addr & !(ALIGN - 1);
        if !(Vmem::<PT, ALIGN>::TASK_ADDR_MIN..Vmem::<PT, ALIGN>::TASK_ADDR_MAX)
            .contains(&fault_addr)
        {
            return Err(PageFaultError::AccessError("Invalid address"));
        }

        // Find the range closest to the fault address
        let (start, vma) = {
            let (r, vma) = self
                .inner
                .overlapping(fault_addr..Vmem::<PT, ALIGN>::TASK_ADDR_MAX)
                .next()
                .ok_or(PageFaultError::AccessError("no mapping"))?;
            (r.start, *vma)
        };
        if fault_addr < start {
            // address is out of range, test if it is next to a stack
            if !vma.flags().contains(VmFlags::VM_GROWSDOWN) {
                return Err(PageFaultError::AccessError("no mapping"));
            }

            if !self
                .inner
                .overlapping(Vmem::<PT, ALIGN>::TASK_ADDR_MIN..fault_addr)
                .next_back()
                .is_none_or(|(prev_range, prev_vma)| {
                    // Enforce gap between stack and other preceding non-stack mappings.
                    // Either the previous mapping is also a stack mapping w/ some access flags
                    // or the previous mapping is far enough from the fault address
                    (prev_vma.flags().contains(VmFlags::VM_GROWSDOWN)
                        && !(prev_vma.flags() & VmFlags::VM_ACCESS_FLAGS).is_empty())
                        || fault_addr - prev_range.end >= Self::STACK_GUARD_GAP
                })
            {
                return Err(PageFaultError::AllocationFailed);
            }
            unsafe {
                self.inner
                    .insert_mapping(PageRange::new_unchecked(fault_addr, start), vma)
            };
        }

        if Self::access_error(error_code, vma.flags()) {
            return Err(PageFaultError::AccessError("access error"));
        }

        unsafe {
            self.inner.backend.handle_page_fault(
                Page::containing_address(VirtAddr::new(fault_addr as u64)),
                vmflags_to_pteflags(vma.flags()),
                error_code,
            )
        }
    }

    /*================================Internal Functions================================ */

    /// Check if it has access to the fault address.
    fn access_error(error_code: PageFaultErrorCode, flags: VmFlags) -> bool {
        if error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) {
            return !flags.contains(VmFlags::VM_WRITE);
        }

        // read, present
        if error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION) {
            return true;
        }

        // read, not present
        if (flags & VmFlags::VM_ACCESS_FLAGS).is_empty() {
            return true;
        }

        false
    }
}

impl<PT: PageTableImpl, const ALIGN: usize> MappingProvider<UserMutPtr<u8>, ALIGN>
    for KernelVmem<PT, ALIGN>
{
    unsafe fn create_executable_page<F>(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        fixed_addr: bool,
        op: F,
    ) -> Result<usize, litebox::mm::mapping::MappingError>
    where
        F: FnOnce(UserMutPtr<u8>) -> Result<usize, litebox::mm::mapping::MappingError>,
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
    ) -> Result<usize, litebox::mm::mapping::MappingError>
    where
        F: FnOnce(UserMutPtr<u8>) -> Result<usize, litebox::mm::mapping::MappingError>,
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
    ) -> Result<usize, litebox::mm::mapping::MappingError>
    where
        F: FnOnce(UserMutPtr<u8>) -> Result<usize, litebox::mm::mapping::MappingError>,
    {
        unsafe {
            self.inner
                .create_readable_page(suggested_range, fixed_addr, op)
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub type KernelVmemX64 = KernelVmem<X64PageTable<'static, crate::host::SnpLinuxKenrel>, PAGE_SIZE>;
