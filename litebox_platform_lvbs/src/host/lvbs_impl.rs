// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An implementation of [`HostInterface`] for LVBS

use crate::{
    Errno, HostInterface, arch::ioport::serial_print_string,
    host::per_cpu_variables::with_per_cpu_variables_mut,
};

pub type LvbsLinuxKernel = crate::LinuxKernel<HostLvbsInterface>;

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

/// DRBG module for cryptographically secure random number generation.
mod csprng_state {
    use crate::csprng::{AesCtrDrbg, NonceBuffer};

    /// Static DRBG instance, lazily initialized with hardware entropy.
    pub static DRBG: spin::mutex::SpinMutex<Option<AesCtrDrbg>> = spin::mutex::SpinMutex::new(None);

    /// Nonce buffer for additional entropy (e.g., from TPM).
    /// Must be initialized via `initialize_crng_nonce` before the CRNG can be used.
    pub static NONCE_BUFFER: spin::mutex::SpinMutex<NonceBuffer> =
        spin::mutex::SpinMutex::new(NonceBuffer::new());
}

/// Initialize the CRNG nonce buffer with data from an external source (e.g., TPM).
///
/// This **must** be called before the first use of the CRNG. The CRNG will panic
/// if `fill_bytes_crng` is called without first initializing the nonce buffer.
///
/// # Arguments
///
/// * `nonce` - Up to 32 bytes of nonce data from an external entropy source (e.g., TPM boot nonce)
pub fn initialize_crng_nonce(nonce: &[u8]) {
    let mut nonce_guard = csprng_state::NONCE_BUFFER.lock();
    nonce_guard.initialize(nonce);
}

impl litebox::platform::CrngProvider for LvbsLinuxKernel {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        use crate::csprng::{AesCtrDrbg, EntropySource, RdseedEntropySource};

        let mut drbg_guard = csprng_state::DRBG.lock();

        // Initialize DRBG on first use
        if drbg_guard.is_none() {
            // Get nonce from buffer - boot nonce MUST be initialized before using CRNG
            let nonce_guard = csprng_state::NONCE_BUFFER.lock();
            assert!(
                nonce_guard.is_initialized(),
                "CRNG boot nonce must be initialized before use. Call initialize_crng_nonce() first."
            );
            let nonce = nonce_guard.get();
            let mut nonce_buf = [0u8; 16];
            let copy_len = core::cmp::min(nonce.len(), 16);
            nonce_buf[..copy_len].copy_from_slice(&nonce[..copy_len]);
            drop(nonce_guard);

            // Gather entropy from RDSEED/RDRAND
            let entropy_source = RdseedEntropySource::new();
            let mut entropy = [0u8; 32];
            let entropy_bytes = entropy_source.get_entropy(&mut entropy);
            assert!(
                entropy_bytes >= 32,
                "Failed to gather sufficient entropy from hardware"
            );

            *drbg_guard = Some(AesCtrDrbg::new(&entropy, &nonce_buf));
        }

        // Generate random bytes
        // Safety: drbg_guard is guaranteed to be Some after the initialization above
        let drbg = drbg_guard
            .as_mut()
            .expect("DRBG should be initialized at this point");
        if !drbg.generate(buf) {
            // DRBG needs reseed - gather new entropy
            let entropy_source = RdseedEntropySource::new();
            let mut new_entropy = [0u8; 32];
            let entropy_bytes = entropy_source.get_entropy(&mut new_entropy);
            assert!(entropy_bytes >= 32, "Failed to gather entropy for reseed");
            drbg.reseed(&new_entropy);

            // Retry generate
            assert!(drbg.generate(buf), "DRBG generate failed after reseed");
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
