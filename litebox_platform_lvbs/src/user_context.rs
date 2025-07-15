//! VTL1 user context
//! A user context is created for process, TA session, task, or something like that.

use crate::debug_serial_println;
use crate::{
    HostInterface, LinuxKernel, kernel_context::get_per_core_kernel_context,
    mshv::vtl1_mem_layout::PAGE_SIZE,
};
use core::arch::asm;
use hashbrown::HashMap;
use litebox::mm::linux::{PageRange, VmFlags};
use litebox_common_linux::errno::Errno;
use x86_64::{
    VirtAddr,
    registers::{control::Cr3, rflags::RFlags},
};

// Let us confine the size of the VTL1 user space for now (1 GiB).
// This would be fine because we only run tiny programs in the VTL1 user space.
const VTL1_USER_BASE: u64 = 0x1_0000_0000;
const VTL1_USER_TOP: u64 = 0x1_4000_0000;
// fixed-size user stack for an OP-TEE TA
pub const VTL1_USER_STACK_SIZE: usize = 16 * PAGE_SIZE;

pub trait UserSpaceManagement {
    /// Global virtual address base for VTL1 user space
    const GVA_USER_BASE: VirtAddr;

    /// Global virtual address top for VTL1 user space
    const GVA_USER_TOP: VirtAddr;

    /// Base size of a VTL1 user stack
    const BASE_STACK_SIZE: usize;

    /// Create a new user address space (i.e., a new user page table) and context, and returns `userspace_id` for it.
    /// The page table also maps the kernel address space (the entire space for now, a portion of it in the future)
    /// for handling system calls.
    fn create_userspace(&self) -> Result<u32, Errno>;

    /// Delete any resources associated with the userspace (`userspace_id`).
    fn delete_userspace(&self, userspace_id: u32) -> Result<(), Errno>;

    /// Check whether the userspace with the given `userspace_id` exists.
    fn check_userspace(&self, userspace_id: u32) -> bool;

    /// Enter userspace with the given `userspace_id`. This function never returns.
    /// It retrieves the user context (return address, stack pointer, and rflags) from a global data
    /// structure, `UserContextMap`.
    ///
    /// # Panics
    ///
    /// Panics if `userspace_id` does not exist. The caller must ensure that `userspace_id` is valid.
    fn enter_userspace(&self, userspace_id: u32, arguments: Option<&[u64]>) -> !;

    /// Load a program into the userspace. Currently, it memory copies a dummy syscall function
    /// to the entry point of the userspace.
    /// TODO: Support loading a TA ELF binary.
    fn load_program(&self, userspace_id: u32, binary: &[u8]) -> Result<(), Errno>;

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

/// Data structure to hold user context information.
pub struct UserContext {
    pub page_table: crate::mm::PageTable<PAGE_SIZE>,
    pub rip: VirtAddr,
    pub rsp: VirtAddr,
    pub rflags: RFlags,
}

impl UserContext {
    /// Create a new user context with the given user page table
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
pub struct UserContextMap {
    inner: spin::mutex::SpinMutex<HashMap<u32, UserContext>>,
}

impl UserContextMap {
    pub fn new() -> Self {
        UserContextMap {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }
}

impl<Host: HostInterface> UserSpaceManagement for LinuxKernel<Host> {
    const GVA_USER_BASE: VirtAddr = x86_64::VirtAddr::new(VTL1_USER_BASE);
    const GVA_USER_TOP: VirtAddr = x86_64::VirtAddr::new(VTL1_USER_TOP);
    const BASE_STACK_SIZE: usize = VTL1_USER_STACK_SIZE;

    fn create_userspace(&self) -> Result<u32, Errno> {
        let mut inner = self.user_contexts.inner.lock();
        let userspace_id = match inner.keys().max() {
            Some(&id) => id + 1,
            None => 1,
        };
        let user_pt = self.new_user_page_table();

        let user_ctx: UserContext = UserContext::new(user_pt);
        inner.insert(userspace_id, user_ctx);
        Ok(userspace_id)
    }

    fn delete_userspace(&self, userspace_id: u32) -> Result<(), Errno> {
        let mut inner = self.user_contexts.inner.lock();
        let user_pt = inner.get(&userspace_id).unwrap();
        unsafe {
            // TODO: selectively unmap mapped pages instead of unmapping the entire user space
            user_pt
                .page_table
                .unmap_pages(
                    PageRange::<PAGE_SIZE>::new(
                        usize::try_from(Self::GVA_USER_BASE.as_u64()).unwrap(),
                        usize::try_from(Self::GVA_USER_TOP.as_u64()).unwrap(),
                    )
                    .unwrap(),
                    true,
                )
                .expect("Failed to unmap user pages");
            user_pt.page_table.clean_up();
        }

        let _ = inner.remove(&userspace_id);
        Ok(())
    }

    fn check_userspace(&self, userspace_id: u32) -> bool {
        let inner = self.user_contexts.inner.lock();
        if inner.contains_key(&userspace_id) {
            return true;
        }
        false
    }

    #[allow(clippy::similar_names)]
    fn enter_userspace(&self, userspace_id: u32, _arguments: Option<&[u64]>) -> ! {
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
                user_ctx.page_table.switch_address_space();
            } else {
                panic!("Userspace with ID: {} does not exist", userspace_id);
            }
        } // release the lock before entering userspace
        let Some((_, cs_idx, ds_idx)) = get_per_core_kernel_context().get_segment_selectors()
        else {
            panic!("GDT not initialized");
        };
        unsafe {
            asm!(
                "push r10",
                "push r11",
                "push r12",
                "push r13",
                "push r14",
                "iretq",
                in("r10") ds_idx, in("r11") rsp.as_u64(), in("r12") rflags.bits(),
                in("r13") cs_idx, in("r14") rip.as_u64(),
            );
        }
        panic!("IRETQ failed to enter userspace");
    }

    // Note. This is not a real `load_program` function which should be able to handle TA ELF.
    // It is written for testing purposes.
    fn load_program(&self, userspace_id: u32, _binary: &[u8]) -> Result<(), Errno> {
        // TODO: entry point and program size must be determined by analyzing the ELF binary.
        // For now, let us use these dummy values for testing purposes.
        let entry_point = usize::try_from(Self::GVA_USER_BASE.as_u64()).unwrap();
        let program_size = PAGE_SIZE;

        let mut inner = self.user_contexts.inner.lock();
        if let Some(user_ctx) = inner.get_mut(&userspace_id) {
            // code pages (should not be executable yet)
            let _ = user_ctx.page_table.map_pages(
                PageRange::<PAGE_SIZE>::new(entry_point, entry_point + program_size).unwrap(),
                VmFlags::VM_READ | VmFlags::VM_WRITE,
                true,
            );

            // Since we cannot copy memory pages without mapping, we use the user page table for this memory copy.
            user_ctx.page_table.switch_address_space();
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (dummy_syscall_fn as *const ()).cast::<u8>(),
                    u64::try_from(entry_point).unwrap() as *mut u8,
                    PAGE_SIZE,
                );
            }
            self.page_table.switch_address_space(); // reload the kernel page table

            // make code pages executable and non-writable
            let _ = unsafe {
                user_ctx.page_table.mprotect_pages(
                    PageRange::<PAGE_SIZE>::new(entry_point, entry_point + program_size).unwrap(),
                    VmFlags::VM_READ | VmFlags::VM_EXEC,
                )
            };
            let _ = user_ctx.page_table.map_pages(
                PageRange::<PAGE_SIZE>::new(
                    usize::try_from(Self::GVA_USER_TOP.as_u64()).unwrap() - Self::BASE_STACK_SIZE,
                    usize::try_from(Self::GVA_USER_TOP.as_u64()).unwrap(),
                )
                .unwrap(),
                VmFlags::VM_READ | VmFlags::VM_WRITE,
                true,
            );

            // initial instruction and stack pointers
            user_ctx.rip = VirtAddr::new(u64::try_from(entry_point).unwrap());
            user_ctx.rsp = VirtAddr::new(Self::GVA_USER_TOP.as_u64() & !0xf);
            Ok(())
        } else {
            Err(Errno::EINVAL)
        }
    }

    fn save_user_context(
        &self,
        user_ret_addr: VirtAddr,
        user_stack_ptr: VirtAddr,
        rflags: RFlags,
    ) -> Result<(), Errno> {
        let (cr3, _) = Cr3::read_raw();
        let mut inner = self.user_contexts.inner.lock();
        // TODO: to avoid the below linear search, we can maintain cr3 to `userspace_id` mapping.
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

// This dummy syscall function is used for testing purposes.
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
