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

        fn mem_allocate_pages(_order: u32) -> Option<*mut u8> {
            unimplemented!()
        }

        unsafe fn mem_free_pages(_ptr: *mut u8, _order: u32) {
            unimplemented!()
        }
    }
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

    fn alloc(_layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        unimplemented!()
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
