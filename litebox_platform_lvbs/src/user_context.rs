//! VTL1 user context
//! A user context is created for process, TA session, task, or something like that.

use crate::arch::gdt;
use crate::debug_serial_println;
use crate::mshv::vtl1_mem_layout::PAGE_SIZE;
use crate::{HostInterface, LinuxKernel};
use core::arch::asm;
use hashbrown::HashMap;
use litebox::mm::linux::{PageRange, VmFlags};
use litebox_common_linux::errno::Errno;

// fixed-size user stack for an OP-TEE TA
// pub const USER_STACK_SIZE: usize = 16 * PAGE_SIZE;

pub trait UserSpace {
    fn create_userspace(&self) -> Result<u64, Errno>;

    #[expect(dead_code)]
    fn delete_userspace(&self, userspace_id: u64) -> Result<(), Errno>;

    #[expect(dead_code)]
    fn check_userspace(&self, userspace_id: u64) -> bool;

    fn enter_userspace(&self, userspace_id: u64) -> !;

    fn load_program(
        &self,
        userspace_id: u64,
        binary: &[u8],
        entry_point: usize,
    ) -> Result<(), Errno>;
}

pub struct UserContext {
    pub page_table: crate::mm::PageTable<PAGE_SIZE>,
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    // TODO: store other registers either here or in the stack
}

impl UserContext {
    pub fn new(user_pt: crate::mm::PageTable<PAGE_SIZE>) -> Self {
        UserContext {
            page_table: user_pt,
            rip: 0,
            rsp: 0,
            rflags: 0x202,
        }
    }
}

pub struct UserContextMap {
    inner: spin::mutex::SpinMutex<HashMap<u64, UserContext>>,
}

impl UserContextMap {
    pub fn new() -> Self {
        UserContextMap {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }
}

impl<Host: HostInterface> UserSpace for LinuxKernel<Host> {
    fn create_userspace(&self) -> Result<u64, Errno> {
        let mut inner = self.user_contexts.inner.lock();
        let userspace_id = match inner.keys().max() {
            Some(&id) => id + 1,
            None => 1,
        };
        let user_pt = self.new_user_page_table();

        // TODO: create a new user context
        let user_ctx: UserContext = UserContext::new(user_pt);
        inner.insert(userspace_id, user_ctx);
        Ok(userspace_id)
    }

    fn delete_userspace(&self, userspace_id: u64) -> Result<(), Errno> {
        todo!("Delete userspace with ID: {}", userspace_id);
    }

    fn check_userspace(&self, userspace_id: u64) -> bool {
        let inner = self.user_contexts.inner.lock();
        if inner.contains_key(&userspace_id) {
            return true;
        }
        false
    }

    /// Enter userspace with the given `userspace_id`. This function never returns.
    ///
    /// # Panics
    ///
    /// Panics if `userspace_id` does not exist. The caller must ensure that `userspace_id` is valid.
    fn enter_userspace(&self, userspace_id: u64) -> ! {
        let inner = self.user_contexts.inner.lock();
        if let Some(user_ctx) = inner.get(&userspace_id) {
            user_ctx.page_table.switch_address_space();
            let (cs_idx, ds_idx) = gdt::set_usermode_segs();
            debug_serial_println!("Entering userspace with ID: {}", userspace_id);
            unsafe {
                asm!(
                    "push r10",
                    "push r11",
                    "push r12",
                    "push r13",
                    "push r14",
                    "iretq",
                    in("r10") ds_idx, in("r11") user_ctx.rsp, in("r12") user_ctx.rflags,
                    in("r13") cs_idx, in("r14") user_ctx.rip
                );
            }
        }

        panic!("Userspace with ID: {} does not exist", userspace_id);
    }

    fn load_program(
        &self,
        userspace_id: u64,
        _binary: &[u8],
        entry_point: usize,
    ) -> Result<(), Errno> {
        let dummy_syscall_code = [0x0f, 0x05, 0x0f, 0x0b, 0xcc, 0xcc, 0xcc, 0xcc];
        let mut inner = self.user_contexts.inner.lock();
        if let Some(user_ctx) = inner.get_mut(&userspace_id) {
            // code page (4 KiB)
            let _ = user_ctx.page_table.map_pages(
                PageRange::<PAGE_SIZE>::new(entry_point, entry_point + PAGE_SIZE).unwrap(),
                VmFlags::VM_READ | VmFlags::VM_WRITE,
                true,
            );
            user_ctx.page_table.switch_address_space();
            unsafe {
                core::ptr::copy_nonoverlapping(
                    dummy_syscall_code.as_ptr(),
                    entry_point as *mut u8,
                    8,
                );
            }
            self.page_table.switch_address_space();
            let _ = unsafe {
                user_ctx.page_table.mprotect_pages(
                    PageRange::<PAGE_SIZE>::new(entry_point, entry_point + PAGE_SIZE).unwrap(),
                    VmFlags::VM_READ | VmFlags::VM_EXEC,
                )
            };
            // stack page (4 KiB)
            let _ = user_ctx.page_table.map_pages(
                PageRange::<PAGE_SIZE>::new(entry_point + PAGE_SIZE, entry_point + 2 * PAGE_SIZE)
                    .unwrap(),
                VmFlags::VM_READ | VmFlags::VM_WRITE,
                true,
            );

            user_ctx.rip = u64::try_from(entry_point).unwrap();
            user_ctx.rsp = u64::try_from(entry_point + 2 * PAGE_SIZE).unwrap();
            Ok(())
        } else {
            Err(Errno::EINVAL)
        }
    }
}
