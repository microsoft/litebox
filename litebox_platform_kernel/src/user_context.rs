//! User context
//! A user context is created for process, TA session, task, or something like that.

use crate::LiteBoxKernel;
use hashbrown::HashMap;
use litebox_common_linux::errno::Errno;
use x86_64::{VirtAddr, registers::rflags::RFlags};

const PAGE_SIZE: usize = 4096;

/// TODO: Let us consider how to manage multiple user contexts (do we need to maintain inside the platform?
/// can the runner manage this?) For now, this is mostly a placeholder without any meaningful functionality.
/// UserSpace management trait for creating and managing a separate address space for a user process, task, or session.
/// Define it as a trait because it might need to work for various configurations like different page sizes.
#[allow(dead_code)]
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
}

/// Data structure to hold user context information. All other registers will be stored into a user stack
/// (pointed by `rsp`) and restored by the system call or interrupt handler.
/// TODO: Since the user stack might have no space to store all registers, we can extend this structure in
/// the future to store these registers.
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

impl Default for UserContextMap {
    fn default() -> Self {
        Self::new()
    }
}

impl UserSpaceManagement for LiteBoxKernel {
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
}
