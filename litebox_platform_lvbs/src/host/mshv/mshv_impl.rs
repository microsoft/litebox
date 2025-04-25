//! An implementation of [`HostInterface`] for LVBS

use crate::host::linux::sigset_t;
use crate::ptr::{UserConstPtr, UserMutPtr};
use crate::{Errno, HostInterface, VtlCallParam};
use core::arch::asm;

#[expect(clippy::cast_lossless)]
#[expect(clippy::cast_possible_truncation)]
#[expect(clippy::cast_possible_wrap)]
#[expect(clippy::default_trait_access)]
#[expect(clippy::unnecessary_cast)]
#[expect(clippy::used_underscore_binding)]
#[expect(clippy::useless_transmute)]
#[expect(clippy::ptr_as_ptr)]
#[expect(clippy::ptr_offset_with_cast)]
#[expect(clippy::ref_as_ptr)]
#[expect(clippy::semicolon_if_nothing_returned)]
#[expect(clippy::similar_names)]
#[expect(clippy::too_many_arguments)]
#[expect(clippy::too_many_lines)]
#[expect(clippy::transmute_ptr_to_ptr)]
#[expect(clippy::trivially_copy_pass_by_ref)]
#[expect(dead_code)]
#[expect(non_camel_case_types)]
#[expect(non_snake_case)]
#[expect(non_upper_case_globals)]
#[expect(unsafe_code)]
#[expect(unsafe_op_in_unsafe_fn)]
mod bindings {
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

    fn switch(result: u64) -> VtlCallParam {
        // save VTL1 registers
        // restore VTL0 registers

        unsafe {
            asm!("vmcall", in("rax") 0x0, in("rcx") 0x12, in("r8") result);
        }

        // save VTL0 registers
        // restore VTL1 registers

        VtlCallParam {
            entry_reason: 0,
            args: [0, 0, 0, 0],
        }
    }
}
