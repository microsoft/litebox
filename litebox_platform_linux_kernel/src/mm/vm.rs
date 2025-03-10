use core::ops::Range;

use litebox::mm::vm::{PageRange, VmArea, VmFlags, Vmem};

use crate::{
    arch::{
        PAGE_SIZE, Page, PageFaultErrorCode, PhysAddr, VirtAddr,
        mm::paging::{X64PageTable, vmflags_to_pteflags},
    },
    host::SnpLinuxKenrel,
};

use super::pgtable::{PageFaultError, PageTableImpl};

/// Virtual memory manager in Kernel that uses `PageTableImpl` as the backend.
pub struct KernelVmem<PT: PageTableImpl>(Vmem<PT>);

impl<PT: PageTableImpl> KernelVmem<PT> {
    const STACK_GUARD_GAP: usize = 256 << 12;

    /// Create a new `KernelVmem` instance with the physical address of a page table.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `p` is a valid address of a top-level page table.
    pub unsafe fn new(p: PhysAddr) -> Self {
        KernelVmem(Vmem::<PT>::new(unsafe { PT::init(p) }))
    }

    pub fn get_pgtable(&self) -> &PT {
        self.0.get_inner()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Range<usize>, &VmArea)> {
        self.0.iter()
    }

    /// See [`Vmem::insert_mapping`] for details.
    pub fn insert_mapping(&mut self, range: PageRange, vma: VmArea) {
        self.0.insert_mapping(range, vma);
    }

    pub fn handle_page_fault(
        &mut self,
        fault_addr: usize,
        error_code: PageFaultErrorCode,
    ) -> Result<(), PageFaultError> {
        let fault_addr = fault_addr & !(PAGE_SIZE - 1);
        if !(Vmem::<PT>::TASK_ADDR_MIN..Vmem::<PT>::TASK_ADDR_MAX).contains(&fault_addr) {
            return Err(PageFaultError::AccessError("Invalid address"));
        }

        // Find the range closest to the fault address
        let (start, vma) = {
            let (r, vma) = self
                .0
                .overlapping(fault_addr..Vmem::<PT>::TASK_ADDR_MAX)
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
                .0
                .overlapping(Vmem::<PT>::TASK_ADDR_MIN..fault_addr)
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
            self.0
                .insert_mapping(PageRange::new(fault_addr, start), vma);
        }

        if Self::access_error(error_code, vma.flags()) {
            return Err(PageFaultError::AccessError("access error"));
        }

        unsafe {
            self.0.get_inner_mut().handle_page_fault(
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

#[cfg(target_arch = "x86_64")]
pub type KernelVmemX64 = KernelVmem<X64PageTable<'static, SnpLinuxKenrel>>;
