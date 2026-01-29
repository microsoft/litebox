// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An implementation of [`HostInterface`] for LVBS

use crate::{
    Errno, HostInterface, arch::ioport::serial_print_string,
    host::per_cpu_variables::with_per_cpu_variables_mut,
};
use core::arch::x86_64::_rdseed64_step;
use drbg::{ctr::CtrDrbg, entropy::OsEntropy};
use getrandom::register_custom_getrandom;

pub type LvbsLinuxKernel = crate::LinuxKernel<HostLvbsInterface>;

/// Custom getrandom implementation using RDSEED for the custom target.
///
/// This is required because getrandom doesn't support our custom x86_64 target,
/// and the drbg crate unconditionally depends on getrandom.
///
/// Note: RDSEED is relatively slow compared to other random sources, but this
/// function is only called by CTR_DRBG for initial seeding (~48 bytes at startup)
/// and very infrequent reseeding (default interval is 2^48 generations). All
/// regular random number generation uses the fast AES-based DRBG, not RDSEED.
#[allow(clippy::unnecessary_wraps)] // Return type required by register_custom_getrandom! macro
fn rdseed_getrandom(dest: &mut [u8]) -> Result<(), getrandom::Error> {
    let mut offset = 0;
    while offset < dest.len() {
        let mut val: u64 = 0;
        // RDSEED may fail if the entropy source is exhausted.
        // We retry until it succeeds.
        // Safety: The RDSEED instruction is safe to call if the CPU
        // supports it. We assume the CPU supports RDSEED since this
        // is running on LVBS which requires modern hardware.
        let success = unsafe { _rdseed64_step(&mut val) };
        if success == 0 {
            // RDSEED returned no data, retry
            core::hint::spin_loop();
            continue;
        }
        let val_bytes = val.to_ne_bytes();
        let remaining = dest.len() - offset;
        let to_copy = remaining.min(8);
        dest[offset..offset + to_copy].copy_from_slice(&val_bytes[..to_copy]);
        offset += to_copy;
    }
    Ok(())
}

register_custom_getrandom!(rdseed_getrandom);

#[cfg(not(test))]
mod alloc {
    use crate::HostInterface;

    const HEAP_ORDER: usize = 25;

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

        fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
            LVBS_ALLOCATOR.allocate_pages(order)
        }

        unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
            unsafe {
                LVBS_ALLOCATOR.free_pages(ptr, order);
            }
        }

        unsafe fn mem_fill_pages(start: usize, size: usize) {
            unsafe { LVBS_ALLOCATOR.fill_pages(start, size) };
        }
    }
}

impl LvbsLinuxKernel {
    // TODO: replace it with actual implementation (e.g., atomically increment PID/TID)
    pub fn init_task(&self) -> litebox_common_linux::TaskParams {
        litebox_common_linux::TaskParams {
            pid: 1,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
        }
    }
}

unsafe impl litebox::platform::ThreadLocalStorageProvider for LvbsLinuxKernel {
    fn get_thread_local_storage() -> *mut () {
        let tls = with_per_cpu_variables_mut(|pcv| pcv.tls);
        tls.as_mut_ptr::<()>()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        with_per_cpu_variables_mut(|pcv| {
            let old = pcv.tls;
            pcv.tls = x86_64::VirtAddr::new(value as u64);
            old.as_u64() as *mut ()
        })
    }
}

/// Static nonce for the CTR_DRBG. This should be set once during system
/// initialization before the CRNG is used.
static DRBG_NONCE: spin::once::Once<[u8; 16]> = spin::once::Once::new();

/// Set the nonce for the CTR_DRBG. This should be called once during
/// system initialization. The nonce provides additional uniqueness to
/// the DRBG instantiation and should ideally be unique per boot.
///
/// # Panics
/// Panics if called more than once.
pub fn set_crng_nonce(nonce: &[u8; 16]) {
    DRBG_NONCE.call_once(|| *nonce);
}

/// Get the nonce for the CTR_DRBG, or a default value if not set.
fn get_crng_nonce() -> &'static [u8; 16] {
    // Use a default nonce if not explicitly set. This is not ideal for
    // security but allows the system to function if the nonce is not
    // set during initialization.
    DRBG_NONCE.call_once(|| {
        // Default nonce - should be replaced with a proper one during init
        [
            0x4d, 0x59, 0x5d, 0xf4, 0xd0, 0xf3, 0x31, 0x73, 0x13, 0x37, 0x4a, 0x41, 0x59, 0x42,
            0x13, 0x37,
        ]
    })
}

impl litebox::platform::CrngProvider for LvbsLinuxKernel {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        // Uses OsEntropy which calls getrandom(), which in turn uses our
        // custom rdseed_getrandom implementation registered above.
        static DRBG: spin::mutex::SpinMutex<Option<CtrDrbg<OsEntropy>>> =
            spin::mutex::SpinMutex::new(None);

        let mut drbg_guard = DRBG.lock();
        let drbg = drbg_guard.get_or_insert_with(|| {
            drbg::ctr::CtrBuilder::new(OsEntropy::default())
                .nonce(get_crng_nonce())
                .build()
                .expect("failed to initialize CTR_DRBG")
        });

        drbg.fill_bytes(buf, None)
            .expect("CTR_DRBG fill_bytes failed");
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

    fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        panic!(
            "dynamic memory allocation is not supported (layout = {:?})",
            layout
        );
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
