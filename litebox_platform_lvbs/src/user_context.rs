// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VTL1 user context
//! A user context is created for process, TA session, task, or something like that.

use crate::debug_serial_println;
use crate::{
    HostInterface, LinuxKernel, host::per_cpu_variables::with_per_cpu_variables,
    mshv::vtl1_mem_layout::PAGE_SIZE,
};
use core::arch::asm;
use hashbrown::HashMap;
use litebox_common_linux::errno::Errno;
use x86_64::{
    VirtAddr,
    registers::{control::Cr3, rflags::RFlags},
};

/// UserSpace management trait for creating and managing a separate address space for a user process, task, or session.
/// Define it as a trait because it might need to work for various configurations like different page sizes.
#[expect(dead_code)]
pub trait UserSpaceManagement {
    /// Create a new user address space (i.e., a new user page table) and context, and returns `userspace_id` for it.
    /// The page table also maps the kernel address space (the entire physical space for now, a portion of it in the future)
    /// for handling system calls.
    fn create_userspace(&self) -> Result<usize, Errno>;

    /// Delete resources associated with the userspace (`userspace_id`) including its context and page tables.
    ///
    /// # Safety
    /// The caller must ensure that any virtual address pages assigned to this userspace must be unmapped through
    /// `LiteBox::PageManager` before calling this function. Otherwise, there will be a memory leak. `PageManager`
    /// manages every virtual address page allocated through or for the Shim and apps.
    fn delete_userspace(&self, userspace_id: usize) -> Result<(), Errno>;

    /// Check whether the userspace with the given `userspace_id` exists.
    fn check_userspace(&self, userspace_id: usize) -> bool;

    /// Enter userspace with the given `userspace_id`. This function never returns.
    /// It retrieves the user context (return address, stack pointer, and rflags) from a global data
    /// structure, `UserContextMap`.
    ///
    /// # Panics
    ///
    /// Panics if `userspace_id` does not exist. The caller must ensure that `userspace_id` is valid.
    fn enter_userspace(&self, userspace_id: usize, arguments: Option<&[usize]>) -> !;

    /// Save the user context when there is user-to-kernel transition.
    /// This function is expected to be called by the system call or interrupt handler which does not
    /// know `userspace_id` of the current user context. Thus, it internally uses the current value of
    /// the CR3 register to find the corresponding user context struct.
    fn save_user_context(
        &self,
        user_ret_addr: VirtAddr,
        user_stack_ptr: VirtAddr,
        rflags: RFlags,
    ) -> Result<(), Errno>;
}

/// Data structure to hold user context information. All other registers will be stored into a user stack
/// (pointed by `rsp`) and restored by the system call or interrupt handler.
/// TODO: Since the user stack might have no space to store all registers, we can extend this structure in
/// the future to store these registers.
#[expect(dead_code)]
pub struct UserContext {
    pub page_table: crate::mm::PageTable<PAGE_SIZE>,
    pub rip: VirtAddr,
    pub rsp: VirtAddr,
    pub rflags: RFlags,
}

impl UserContext {
    /// Create a new user context with the given user page table
    #[allow(dead_code)]
    pub fn new(user_pt: crate::mm::PageTable<PAGE_SIZE>) -> Self {
        UserContext {
            page_table: user_pt,
            rip: VirtAddr::new(0),
            rsp: VirtAddr::new(0),
            rflags: RFlags::INTERRUPT_FLAG,
        }
    }
}

/// Data structure to hold a map of user contexts indexed by their ID.
#[expect(dead_code)]
pub struct UserContextMap {
    inner: spin::mutex::SpinMutex<HashMap<usize, UserContext>>,
}

impl UserContextMap {
    pub fn new() -> Self {
        UserContextMap {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }
}

impl<Host: HostInterface> UserSpaceManagement for LinuxKernel<Host> {
    fn create_userspace(&self) -> Result<usize, Errno> {
        let mut inner = self.user_contexts.inner.lock();
        let userspace_id = match inner.keys().max() {
            Some(&id) => id.checked_add(1).ok_or(Errno::ENOMEM)?,
            None => 1usize,
        };
        let user_pt = self.new_user_page_table();

        let user_ctx: UserContext = UserContext::new(user_pt);
        inner.insert(userspace_id, user_ctx);
        Ok(userspace_id)
    }

    fn delete_userspace(&self, userspace_id: usize) -> Result<(), Errno> {
        let mut inner = self.user_contexts.inner.lock();
        let user_pt = inner.get(&userspace_id).unwrap();

        unsafe {
            user_pt.page_table.clean_up();
        }

        let _ = inner.remove(&userspace_id);
        Ok(())
    }

    fn check_userspace(&self, userspace_id: usize) -> bool {
        let inner = self.user_contexts.inner.lock();
        if inner.contains_key(&userspace_id) {
            return true;
        }
        false
    }

    #[allow(clippy::similar_names)]
    fn enter_userspace(&self, userspace_id: usize, _arguments: Option<&[usize]>) -> ! {
        let rsp;
        let rip;
        let rflags;
        {
            let inner = self.user_contexts.inner.lock();
            if let Some(user_ctx) = inner.get(&userspace_id) {
                debug_serial_println!(
                    "Entering userspace(ID: {}): RIP: {:#x}, RSP: {:#x}, RFLAGS: {:#x}, CR3: {:#x}",
                    userspace_id,
                    user_ctx.rip,
                    user_ctx.rsp,
                    user_ctx.rflags,
                    user_ctx
                        .page_table
                        .get_physical_frame()
                        .start_address()
                        .as_u64()
                );
                rsp = user_ctx.rsp;
                rip = user_ctx.rip;
                rflags = user_ctx.rflags;
                user_ctx.page_table.change_address_space();
            } else {
                panic!("Userspace with ID: {} does not exist", userspace_id);
            }
        } // release the lock before entering userspace
        let Some((_, cs_idx, ds_idx)) = with_per_cpu_variables(
            crate::host::per_cpu_variables::PerCpuVariables::get_segment_selectors,
        ) else {
            panic!("GDT is not initialized");
        };

        // Currently, `litebox_platform_lvbs` uses `swapgs` to efficiently switch between
        // kernel and user GS base values during kernel-user mode transitions.
        // This `swapgs` usage can pontetially leak a kernel address to the user, so
        // we clear the `KernelGsBase` MSR before running the user thread (only for
        // the first entry).
        crate::arch::write_kernel_gsbase_msr(VirtAddr::zero());

        unsafe {
            asm!(
                "push r10",
                "push r11",
                "push r12",
                "push r13",
                "push r14",
                // clear the GS base register (as the `KernelGsBase` MSR contains 0)
                // while writing the current GS base value to `KernelGsBase`.
                "swapgs",
                "iretq",
                in("r10") ds_idx, in("r11") rsp.as_u64(), in("r12") rflags.bits(),
                in("r13") cs_idx, in("r14") rip.as_u64(),
            );
        }
        panic!("IRETQ failed to enter userspace");
    }

    fn save_user_context(
        &self,
        user_ret_addr: VirtAddr,
        user_stack_ptr: VirtAddr,
        rflags: RFlags,
    ) -> Result<(), Errno> {
        let (cr3, _) = Cr3::read_raw();
        let mut inner = self.user_contexts.inner.lock();
        // TODO: to avoid the below linear search, we can maintain CR3 to `userspace_id` mapping.
        for (id, user_ctx) in inner.iter_mut() {
            if cr3 == user_ctx.page_table.get_physical_frame() {
                user_ctx.rsp = user_stack_ptr;
                user_ctx.rip = user_ret_addr;
                user_ctx.rflags = rflags;
                debug_serial_println!(
                    "Updated user context (ID: {}): RIP={:#x}, RSP={:#x}, RFLAGS={:#x}",
                    id,
                    user_ctx.rip.as_u64(),
                    user_ctx.rsp.as_u64(),
                    user_ctx.rflags.bits(),
                );
                return Ok(());
            }
        }
        Err(Errno::EINVAL)
    }
}

// This dummy syscall function is used for testing purposes. We will remove this once the OP-TEE Shim is implemented.
#[expect(unused_assignments)]
#[expect(unused_variables)]
#[unsafe(no_mangle)]
extern "C" fn dummy_syscall_fn() {
    let sysnr: u64 = 0xdeadbeef;
    let arg0: u64 = 1;
    let arg1: u64 = 2;
    let arg2: u64 = 3;
    let arg3: u64 = 4;
    let arg4: u64 = 5;
    let arg5: u64 = 6;
    let arg6: u64 = 7;
    let arg7: u64 = 8;
    let mut ret: u64;
    unsafe {
        asm!(
            "push rbp",
            "push rbx",
            "push r15",
            "push r14",
            "push r13",
            "push r12",
            "syscall",
            "pop r12",
            "pop r13",
            "pop r14",
            "pop r15",
            "pop rbx",
            "pop rbp",
            "ret",
            in("rax") sysnr, in("rdi") arg0, in("rsi") arg1, in("rdx") arg2, in("r10") arg3,
            in("r8") arg4, in("r9") arg5, in("r12") arg6, in("r13") arg7, lateout("rax") ret,
        );
    }
}
