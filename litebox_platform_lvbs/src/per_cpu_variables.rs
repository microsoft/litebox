// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared kernel/user per-CPU state.
//!
//! A platform installs an allocation with this structure at offset zero in
//! GSBASE. Platform-specific state may follow it; the kernel never accesses
//! that extension. All assembly offsets are derived from the Rust layout.

use crate::arch::{gdt, mm::PAGE_SIZE};
use crate::mm::active::ActivePageTable;
use aligned_vec::avec;
use alloc::{boxed::Box, sync::Arc};
use core::cell::{Cell, UnsafeCell};
use core::mem::offset_of;
use litebox::utils::TruncateExt;
use litebox_common_linux::rdgsbase;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_STACK_SIZE: usize = 2 * PAGE_SIZE;
pub const EXCEPTION_STACK_SIZE: usize = PAGE_SIZE;
pub const KERNEL_STACK_SIZE: usize = 32 * PAGE_SIZE;
pub(crate) const XSAVE_ALIGNMENT: usize = 64;
pub const XSAVE_MASK: u64 = 0b11; // x87 and SSE
const XSAVE_AREA_SIZE: usize = 512 + 64;

/// Kernel state at GSBASE, independent of the platform's transition state.
#[repr(C, align(4096))]
pub struct PerCpuVariables {
    pub(crate) asm: PerCpuVariablesAsm,
    double_fault_stack: [u8; DOUBLE_FAULT_STACK_SIZE],
    // These retain the existing stack padding; they are not unmapped guards.
    _guard_page_0: [u8; PAGE_SIZE],
    exception_stack: [u8; EXCEPTION_STACK_SIZE],
    kernel_stack: [u8; KERNEL_STACK_SIZE],
    _guard_page_1: [u8; PAGE_SIZE],
    pub(crate) gdt: Cell<Option<&'static gdt::GdtWrapper>>,
    pub(crate) tls: Cell<VirtAddr>,
    active_page_table: UnsafeCell<Option<ActivePageTable>>,
}

const _: () = assert!(offset_of!(PerCpuVariables, asm) == 0);

impl PerCpuVariables {
    /// Initialize the common prefix in place, without putting the stacks on
    /// the boot stack. This does not install GSBASE or initialize stack tops.
    ///
    /// # Safety
    /// `ptr` must be aligned, writable, uninitialized storage for `Self`.
    pub unsafe fn initialize_at(ptr: *mut Self) {
        // SAFETY: the caller owns the storage. Zero is valid for all numeric,
        // byte-array and Cell fields. Initialize the Option fields explicitly
        // rather than relying on the layout of the retained Arc wrapper.
        unsafe {
            ptr.write_bytes(0, 1);
            core::ptr::addr_of_mut!((*ptr).gdt).write(Cell::new(None));
            core::ptr::addr_of_mut!((*ptr).active_page_table).write(UnsafeCell::new(None));
        }
    }

    /// Initialize stack pointers after the per-CPU allocation has reached its
    /// permanent address. Must run before loading the GDT or using these stacks.
    pub fn init_stacks(&self) {
        const STACK_ALIGNMENT: usize = 16;
        let top = |base: *const u8, len: usize| (base as usize + len - 1) & !(STACK_ALIGNMENT - 1);
        self.asm
            .kernel_stack_ptr
            .set(top(self.kernel_stack.as_ptr(), KERNEL_STACK_SIZE));
        self.asm.double_fault_stack_ptr.set(top(
            self.double_fault_stack.as_ptr(),
            DOUBLE_FAULT_STACK_SIZE,
        ));
        self.asm
            .exception_stack_ptr
            .set(top(self.exception_stack.as_ptr(), EXCEPTION_STACK_SIZE));
    }

    pub(crate) fn get_segment_selectors(&self) -> Option<(u16, u16, u16)> {
        self.gdt.get().map(gdt::GdtWrapper::get_segment_selectors)
    }

    /// Allocate kernel/user XSAVE buffers. The platform must first configure
    /// or verify XCR0 to include [`XSAVE_MASK`]. Run on the full kernel stack.
    ///
    /// # Panics
    /// Panics if the buffers were already allocated. Allocation failure aborts.
    pub fn allocate_xsave_areas(&self) {
        assert_eq!(
            self.asm.kernel_xsave_area_addr.get(),
            0,
            "XSAVE areas are already allocated"
        );
        let kernel = Box::leak(
            avec![[{ XSAVE_ALIGNMENT }] | 0u8; XSAVE_AREA_SIZE]
                .into_boxed_slice()
                .into(),
        );
        let user = Box::leak(
            avec![[{ XSAVE_ALIGNMENT }] | 0u8; XSAVE_AREA_SIZE]
                .into_boxed_slice()
                .into(),
        );
        self.asm
            .kernel_xsave_area_addr
            .set(kernel.as_ptr() as usize);
        self.asm.user_xsave_area_addr.set(user.as_ptr() as usize);
        self.asm.xsave_mask_lo.set(XSAVE_MASK.trunc());
        self.asm.xsave_mask_hi.set((XSAVE_MASK >> 32).trunc());
    }

    pub(crate) fn active_page_table<M: crate::mm::MemoryProvider>(
        &self,
        page_table_id: usize,
    ) -> Option<Arc<crate::mm::PageTable<M, PAGE_SIZE>>> {
        // SAFETY: this field is private to the current core.
        unsafe { &*self.active_page_table.get() }
            .as_ref()
            .and_then(|active| active.get(page_table_id))
    }

    /// # Safety
    /// CR3 must no longer reference the previous table. A new ID must match
    /// CR3. Interrupts must be disabled; do not call from exception context.
    pub(crate) unsafe fn set_active_page_table(&self, page_table: Option<ActivePageTable>) {
        // SAFETY: only this core accesses the field, interrupts are disabled,
        // and the update cannot fault.
        unsafe { *self.active_page_table.get() = page_table }
    }
}

/// Assembly-accessible kernel/user state at GS offset zero.
#[repr(C, align(4096))]
#[derive(Clone)]
pub struct PerCpuVariablesAsm {
    kernel_stack_ptr: Cell<usize>,
    double_fault_stack_ptr: Cell<usize>,
    exception_stack_ptr: Cell<usize>,
    scratch: Cell<usize>,
    user_rflags: Cell<usize>,
    cur_kernel_stack_ptr: Cell<usize>,
    cur_kernel_base_ptr: Cell<usize>,
    user_context_top_addr: Cell<usize>,
    kernel_xsave_area_addr: Cell<usize>,
    user_xsave_area_addr: Cell<usize>,
    xsave_mask_lo: Cell<u32>,
    xsave_mask_hi: Cell<u32>,
    /// 0: never saved; 1: saved, not restored; 2: restored (XSAVEOPT allowed).
    kernel_xsaved: Cell<u8>,
    user_xsaved: Cell<u8>,
    exception_trapno: Cell<u8>,
    is_in_user: Cell<u8>,
}

impl PerCpuVariablesAsm {
    pub fn get_double_fault_stack_ptr(&self) -> usize {
        self.double_fault_stack_ptr.get()
    }
    pub fn get_exception_stack_ptr(&self) -> usize {
        self.exception_stack_ptr.get()
    }
    pub const fn kernel_stack_ptr_offset() -> usize {
        offset_of!(Self, kernel_stack_ptr)
    }
    pub const fn double_fault_stack_ptr_offset() -> usize {
        offset_of!(Self, double_fault_stack_ptr)
    }
    pub const fn exception_stack_ptr_offset() -> usize {
        offset_of!(Self, exception_stack_ptr)
    }
    pub const fn scratch_offset() -> usize {
        offset_of!(Self, scratch)
    }
    pub const fn user_rflags_offset() -> usize {
        offset_of!(Self, user_rflags)
    }
    pub const fn cur_kernel_stack_ptr_offset() -> usize {
        offset_of!(Self, cur_kernel_stack_ptr)
    }
    pub const fn cur_kernel_base_ptr_offset() -> usize {
        offset_of!(Self, cur_kernel_base_ptr)
    }
    pub const fn user_context_top_addr_offset() -> usize {
        offset_of!(Self, user_context_top_addr)
    }
    pub const fn kernel_xsave_area_addr_offset() -> usize {
        offset_of!(Self, kernel_xsave_area_addr)
    }
    pub const fn user_xsave_area_addr_offset() -> usize {
        offset_of!(Self, user_xsave_area_addr)
    }
    pub const fn xsave_mask_lo_offset() -> usize {
        offset_of!(Self, xsave_mask_lo)
    }
    pub const fn xsave_mask_hi_offset() -> usize {
        offset_of!(Self, xsave_mask_hi)
    }
    pub const fn kernel_xsaved_offset() -> usize {
        offset_of!(Self, kernel_xsaved)
    }
    pub const fn user_xsaved_offset() -> usize {
        offset_of!(Self, user_xsaved)
    }
    pub const fn exception_trapno_offset() -> usize {
        offset_of!(Self, exception_trapno)
    }
    pub const fn is_in_user_offset() -> usize {
        offset_of!(Self, is_in_user)
    }
    pub fn get_exception(&self) -> litebox::shim::Exception {
        litebox::shim::Exception(self.exception_trapno.get())
    }
    pub fn get_user_context_top_addr(&self) -> usize {
        self.user_context_top_addr.get()
    }

    /// Invalidate XSAVEOPT tracking when another execution context may have
    /// used XRSTOR. The platform chooses the boundary at which this is needed.
    pub fn reset_xsaved(&self) {
        self.kernel_xsaved.set(0);
        self.user_xsaved.set(0);
    }
}

/// Access the current core's common state.
///
/// The platform must have installed a permanent, initialized `PerCpuVariables`
/// prefix at GSBASE, unique to this CPU. The closure cannot retain a reference.
pub fn with_per_cpu_variables<F, R>(f: F) -> R
where
    F: FnOnce(&PerCpuVariables) -> R,
    R: 'static,
{
    // SAFETY: the platform boot path establishes the per-CPU prefix invariant.
    f(unsafe { &*current_per_cpu_ptr() })
}

/// The common prefix address, also the address of the platform's enclosing
/// per-CPU allocation. Only the concrete platform may cast to its own layout.
pub(crate) fn current_per_cpu_ptr() -> *mut PerCpuVariables {
    let gsbase = unsafe { rdgsbase() };
    assert!(gsbase != 0, "GSBASE not set. Install per-CPU state first");
    let _ = VirtAddr::try_new(gsbase as u64).expect("GS contains a non-canonical address");
    gsbase as *mut PerCpuVariables
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_common_state_without_a_platform() {
        let mut storage = Box::<PerCpuVariables>::new_uninit();
        // SAFETY: storage is aligned, writable, and uninitialized.
        let cpu = unsafe {
            PerCpuVariables::initialize_at(storage.as_mut_ptr());
            storage.assume_init()
        };
        cpu.init_stacks();
        assert_eq!(cpu.asm.kernel_stack_ptr.get() % 16, 0);
        assert_eq!(
            cpu.asm.kernel_stack_ptr.get(),
            (cpu.kernel_stack.as_ptr() as usize + KERNEL_STACK_SIZE - 1) & !15
        );
        assert_eq!(
            cpu.asm.get_double_fault_stack_ptr(),
            (cpu.double_fault_stack.as_ptr() as usize + DOUBLE_FAULT_STACK_SIZE - 1) & !15
        );
        assert_eq!(
            cpu.asm.get_exception_stack_ptr(),
            (cpu.exception_stack.as_ptr() as usize + EXCEPTION_STACK_SIZE - 1) & !15
        );
        assert!(
            cpu.active_page_table::<crate::host::mock::MockMemory>(0)
                .is_none()
        );
        assert!(cpu.gdt.get().is_none());
        assert_eq!(cpu.tls.get(), VirtAddr::zero());
        cpu.asm.kernel_xsaved.set(2);
        cpu.asm.user_xsaved.set(1);
        cpu.asm.reset_xsaved();
        assert_eq!(cpu.asm.kernel_xsaved.get(), 0);
        assert_eq!(cpu.asm.user_xsaved.get(), 0);
    }

    #[test]
    fn kernel_and_user_xsave_buffers_are_independent_and_aligned() {
        let mut storage = Box::<PerCpuVariables>::new_uninit();
        // SAFETY: storage is aligned, writable, and uninitialized.
        let cpu = unsafe {
            PerCpuVariables::initialize_at(storage.as_mut_ptr());
            storage.assume_init()
        };
        // Allocation itself executes no XSAVE instructions or privileged operations.
        cpu.allocate_xsave_areas();
        let kernel = cpu.asm.kernel_xsave_area_addr.get();
        let user = cpu.asm.user_xsave_area_addr.get();
        assert_ne!(kernel, 0);
        assert_ne!(user, 0);
        assert_ne!(kernel, user);
        assert_eq!(kernel % XSAVE_ALIGNMENT, 0);
        assert_eq!(user % XSAVE_ALIGNMENT, 0);
        assert_eq!(
            u64::from(cpu.asm.xsave_mask_lo.get()) | (u64::from(cpu.asm.xsave_mask_hi.get()) << 32),
            XSAVE_MASK
        );
        assert_eq!(cpu.asm.kernel_xsaved.get(), 0);
        assert_eq!(cpu.asm.user_xsaved.get(), 0);
    }

    #[test]
    fn assembly_offsets_address_common_fields() {
        assert_eq!(offset_of!(PerCpuVariables, asm), 0);
        assert_eq!(core::mem::align_of::<PerCpuVariablesAsm>(), PAGE_SIZE);
        assert_eq!(
            [
                PerCpuVariablesAsm::kernel_stack_ptr_offset(),
                PerCpuVariablesAsm::scratch_offset(),
                PerCpuVariablesAsm::user_context_top_addr_offset(),
                PerCpuVariablesAsm::kernel_xsave_area_addr_offset(),
                PerCpuVariablesAsm::user_xsave_area_addr_offset(),
                PerCpuVariablesAsm::xsave_mask_lo_offset(),
                PerCpuVariablesAsm::xsave_mask_hi_offset(),
                PerCpuVariablesAsm::kernel_xsaved_offset(),
                PerCpuVariablesAsm::user_xsaved_offset(),
                PerCpuVariablesAsm::exception_trapno_offset(),
                PerCpuVariablesAsm::is_in_user_offset()
            ],
            [0, 24, 56, 64, 72, 80, 84, 88, 89, 90, 91],
        );
    }
}
