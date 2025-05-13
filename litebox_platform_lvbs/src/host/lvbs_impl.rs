//! An implementation of [`HostInterface`] for LVBS

use crate::{
    Errno, HostInterface,
    arch::ioport::serial_print_string,
    host::linux::sigset_t,
    ptr::{UserConstPtr, UserMutPtr},
};

pub type LvbsLinuxKernel = crate::LinuxKernel<HostLvbsInterface>;

#[cfg(not(test))]
mod alloc {
    use crate::HostInterface;

    const HEAP_ORDER: usize = 21;
    const PGDIR_SHIFT: u64 = 39;
    const LINUX_PAGE_OFFSET: u64 = 0xffff_8880_0000_0000;
    const VTL0_SHARED_PAGE_OFFSET: u64 = LINUX_PAGE_OFFSET + (2 << PGDIR_SHIFT);

    #[global_allocator]
    static LVBS_ALLOCATOR: litebox::mm::allocator::SafeZoneAllocator<
        'static,
        HEAP_ORDER,
        super::LvbsLinuxKernel,
    > = litebox::mm::allocator::SafeZoneAllocator::new();

    impl litebox::mm::allocator::MemoryProvider for super::LvbsLinuxKernel {
        fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)> {
            super::HostLvbsInterface::alloc(layout)
        }

        unsafe fn free(addr: usize) {
            unsafe { super::HostLvbsInterface::free(addr) }
        }
    }

    impl crate::mm::MemoryProvider for super::LvbsLinuxKernel {
        const GVA_OFFSET: x86_64::VirtAddr = x86_64::VirtAddr::new(0);
        const PRIVATE_PTE_MASK: u64 = 0;
        const VTL0_GVA_OFFSET: x86_64::VirtAddr = x86_64::VirtAddr::new(VTL0_SHARED_PAGE_OFFSET);

        fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
            LVBS_ALLOCATOR.allocate_pages(order)
        }

        unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
            unsafe {
                LVBS_ALLOCATOR.free_pages(ptr, order);
            }
        }
    }

    pub(crate) struct MemBlock {
        free_start: x86_64::VirtAddr,
        free_end: x86_64::VirtAddr,
    }

    impl MemBlock {
        pub fn new(start: x86_64::VirtAddr, end: x86_64::VirtAddr) -> Self {
            MemBlock {
                free_start: start,
                free_end: end,
            }
        }

        // One-time allocation. LiteBox allocator should deal with dynamic memory management.
        pub fn allocate(&mut self, size: usize) -> Option<x86_64::VirtAddr> {
            if self.free_start + size.try_into().unwrap() <= self.free_end {
                let addr = self.free_start;
                self.free_start += size.try_into().unwrap();
                Some(addr)
            } else {
                None
            }
        }
    }

    static MEMBLOCK: spin::Once<spin::Mutex<MemBlock>> = spin::Once::new();

    pub(crate) fn mem_block() -> &'static spin::Mutex<MemBlock> {
        MEMBLOCK
            .get()
            .expect("mem_block should be initialized before use")
    }

    pub fn set_mem_block(
        start: x86_64::VirtAddr,
        end: x86_64::VirtAddr,
    ) -> Result<(), crate::Errno> {
        let _ = MEMBLOCK.call_once(|| spin::Mutex::new(MemBlock::new(start, end)));
        Ok(())
    }
}

/// This specifies the memory block for the LVBS heap allocator which is reseerved,
/// static address range. LVBS does not dynamically obtain memory from the host.
///
/// # Safety
///
/// The caller must ensure that the memory block is valid and not used by
/// other VTL1 components including kernel code, stack, and static variables.
pub fn init_heap_mem_block(
    start: x86_64::VirtAddr,
    end: x86_64::VirtAddr,
) -> Result<(), crate::Errno> {
    alloc::set_mem_block(start, end)
}

pub struct HostLvbsInterface;

impl HostLvbsInterface {}

impl HostInterface for HostLvbsInterface {
    fn send_ip_packet(_packet: &[u8]) -> Result<usize, Errno> {
        unimplemented!()
    }

    fn receive_ip_packet(_packet: &mut [u8]) -> Result<usize, Errno> {
        unimplemented!()
    }

    fn log(msg: &str) {
        serial_print_string(msg);
    }

    fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        let size = core::cmp::max(layout.size().next_power_of_two(), 4096);

        if let Some(addr) = alloc::mem_block().lock().allocate(size) {
            crate::debug_serial_println!("Allocated {} bytes at {:x}", size, addr);
            return Some((addr.as_u64().try_into().unwrap(), size));
        }

        None
    }

    unsafe fn free(_addr: usize) {
        unimplemented!()
    }

    fn exit() -> ! {
        unimplemented!()
    }

    fn terminate(_reason_set: u64, _reason_code: u64) -> ! {
        unimplemented!()
    }

    fn rt_sigprocmask(
        _how: i32,
        _set: UserConstPtr<sigset_t>,
        _oldset: UserMutPtr<sigset_t>,
        _sigsetsize: usize,
    ) -> Result<usize, Errno> {
        unimplemented!()
    }

    fn wake_many(_mutex: &core::sync::atomic::AtomicU32, _n: usize) -> Result<usize, Errno> {
        unimplemented!()
    }

    fn block_or_maybe_timeout(
        _mutex: &core::sync::atomic::AtomicU32,
        _val: u32,
        _timeout: Option<core::time::Duration>,
    ) -> Result<(), Errno> {
        unimplemented!()
    }

    fn switch(_result: u64) -> ! {
        unimplemented!()
    }
}
