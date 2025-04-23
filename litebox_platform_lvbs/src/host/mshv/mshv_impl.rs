//! An implementation of [`HostInterface`] for LVBS

use crate::host::linux::{self, sigset_t};
use crate::ptr::{UserConstPtr, UserMutPtr};
use crate::{Errno, HostInterface};
use core::arch::asm;

#[allow(unsafe_code)]
mod bindings {
    #![allow(dead_code)]
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused_imports)]
    #![allow(improper_ctypes)]
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/mshv_bindings.rs"));
}

pub type LvbsLinuxKernel = crate::LinuxKernel<HostLvbsInterface>;

#[cfg(not(test))]
mod alloc {
    impl crate::mm::MemoryProvider for super::LvbsLinuxKernel {
        const GVA_OFFSET: x86_64::VirtAddr = x86_64::VirtAddr::new(0);
        const PRIVATE_PTE_MASK: u64 = 0;

        fn mem_allocate_pages(_order: u32) -> Option<*mut u8> {
            unimplemented!()
        }

        unsafe fn mem_free_pages(_ptr: *mut u8, _order: u32) {
            unimplemented!()
        }

        fn alloc(_layout: &core::alloc::Layout) -> Result<(usize, usize), crate::Errno> {
            unimplemented!()
        }

        unsafe fn free(_addr: usize) {
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

    fn log(_msg: &str) {
        unimplemented!()
    }

    fn alloc(_layout: &core::alloc::Layout) -> Result<(usize, usize), Errno> {
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
}
