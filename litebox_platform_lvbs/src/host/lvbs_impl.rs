// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An implementation of [`HostInterface`] for LVBS

use crate::{
    Errno, HostInterface, arch::ioport::serial_print_string,
    host::per_cpu_variables::with_per_cpu_variables,
};
use digest::Digest;
use rand_core::{RngCore, SeedableRng};
use zeroize::Zeroizing;

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
        const GVA_OFFSET: x86_64::VirtAddr = x86_64::VirtAddr::new(crate::GVA_OFFSET);
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

#[cfg(test)]
impl crate::mm::MemoryProvider for LvbsLinuxKernel {
    const GVA_OFFSET: x86_64::VirtAddr = x86_64::VirtAddr::new(crate::GVA_OFFSET);
    const PRIVATE_PTE_MASK: u64 = 0;

    fn mem_allocate_pages(_order: u32) -> Option<*mut u8> {
        unimplemented!("not used in tests")
    }

    unsafe fn mem_free_pages(_ptr: *mut u8, _order: u32) {
        unimplemented!("not used in tests")
    }

    unsafe fn mem_fill_pages(_start: usize, _size: usize) {
        unimplemented!("not used in tests")
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
        let tls = with_per_cpu_variables(|pcv| pcv.tls.get());
        tls.as_mut_ptr::<()>()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        with_per_cpu_variables(|pcv| {
            let old = pcv.tls.get();
            pcv.tls.set(x86_64::VirtAddr::new(value as u64));
            old.as_u64() as *mut ()
        })
    }
}

impl litebox::platform::CrngProvider for LvbsLinuxKernel {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        static RANDOM: spin::mutex::SpinMutex<Option<LvbsCrng>> = spin::mutex::SpinMutex::new(None);

        let mut random = RANDOM.lock();
        random
            .get_or_insert_with(|| LvbsCrng::new(PRK_ONCE.wait(), rdrand_seed()))
            .fill_bytes(buf, rdrand_seed);
    }
}

const CRNG_RESEED_INTERVAL_BYTES: usize = 1024 * 1024;
const CRNG_RESEED_STATE_BYTES: usize = 32;

struct LvbsCrng {
    random: rand_chacha::ChaCha20Rng,
    bytes_until_reseed: usize,
    reseed_counter: usize,
}

impl LvbsCrng {
    fn new(
        prk: &[u8; PRK_LEN],
        rdrand_seed: <rand_chacha::ChaCha20Rng as SeedableRng>::Seed,
    ) -> Self {
        Self {
            random: rand_chacha::ChaCha20Rng::from_seed(crng_seed_from_prk_and_rdrand(
                prk,
                rdrand_seed,
            )),
            bytes_until_reseed: CRNG_RESEED_INTERVAL_BYTES,
            reseed_counter: 0,
        }
    }

    fn fill_bytes(
        &mut self,
        mut buf: &mut [u8],
        rdrand_seed: impl Fn() -> <rand_chacha::ChaCha20Rng as SeedableRng>::Seed,
    ) {
        while !buf.is_empty() {
            let len = buf.len().min(self.bytes_until_reseed);
            let (chunk, rest) = buf.split_at_mut(len);
            self.random.fill_bytes(chunk);
            buf = rest;
            self.bytes_until_reseed -= len;

            if self.bytes_until_reseed == 0 {
                self.reseed(rdrand_seed());
            }
        }
    }

    fn reseed(&mut self, rdrand_seed: <rand_chacha::ChaCha20Rng as SeedableRng>::Seed) {
        self.reseed_counter += 1;
        let mut current_state = Zeroizing::new([0u8; CRNG_RESEED_STATE_BYTES]);
        self.random.fill_bytes(&mut *current_state);
        self.random = rand_chacha::ChaCha20Rng::from_seed(crng_reseed_from_rdrand_and_state(
            rdrand_seed,
            self.reseed_counter,
            &current_state,
        ));
        self.bytes_until_reseed = CRNG_RESEED_INTERVAL_BYTES;
    }
}

/// Length of the Platform Root Key in bytes.
pub(crate) const PRK_LEN: usize = 32;

static PRK_ONCE: spin::Once<[u8; PRK_LEN]> = spin::Once::new();

// Do not expose a raw PRK getter (i.e., no `get_platform_root_key`).
// Consumers should provide key derivation function and context
// through `DerivedKeyProvider` so PRK access stays in this module.

/// Sets the Platform Root Key (PRK) for this platform.
///
/// This should be called once during platform initialization with a key derived
/// from hardware or a boot nonce.
///
/// # Panics
/// Panics if `key` length does not match `PRK_LEN`.
pub(crate) fn set_platform_root_key(key: &[u8]) {
    assert_eq!(key.len(), PRK_LEN, "Platform Root Key length mismatch");
    PRK_ONCE.call_once(|| {
        let mut prk = Zeroizing::new([0u8; PRK_LEN]);
        prk.copy_from_slice(key);
        *prk
    });
}

impl litebox::platform::DerivedKeyProvider for LvbsLinuxKernel {
    fn derive_key<E>(
        &self,
        kdf: Option<fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>>,
        params: litebox::platform::KDFParams,
    ) -> Result<(), litebox::platform::DerivedKeyError<E>> {
        let Some(prk) = PRK_ONCE.get() else {
            return Err(litebox::platform::DerivedKeyError::UnsupportedRebootPersistentKey);
        };
        match kdf {
            None => Err(litebox::platform::DerivedKeyError::ShimKDFRequired),
            Some(kdf) => Ok(kdf(prk, params)?),
        }
    }
}

fn rdrand_seed() -> <rand_chacha::ChaCha20Rng as SeedableRng>::Seed {
    let mut seed = <rand_chacha::ChaCha20Rng as SeedableRng>::Seed::default();
    for chunk in seed.chunks_mut(8) {
        let mut word = 0;
        loop {
            // Safety: `RDRAND` is available on the LVBS target CPUs. A false
            // carry flag means random data is temporarily unavailable.
            if unsafe { core::arch::x86_64::_rdrand64_step(&mut word) } == 1 {
                break;
            }
            core::hint::spin_loop();
        }
        chunk.copy_from_slice(&word.to_ne_bytes()[..chunk.len()]);
    }
    seed
}

fn crng_seed_from_prk_and_rdrand(
    prk: &[u8; PRK_LEN],
    rdrand_seed: <rand_chacha::ChaCha20Rng as SeedableRng>::Seed,
) -> <rand_chacha::ChaCha20Rng as SeedableRng>::Seed {
    sha2::Sha256::new()
        .chain_update(b"litebox-lvbs-crng-seed-v1")
        .chain_update(prk)
        .chain_update(rdrand_seed)
        .finalize()
        .into()
}

fn crng_reseed_from_rdrand_and_state(
    rdrand_seed: <rand_chacha::ChaCha20Rng as SeedableRng>::Seed,
    reseed_counter: usize,
    current_state: &[u8; CRNG_RESEED_STATE_BYTES],
) -> <rand_chacha::ChaCha20Rng as SeedableRng>::Seed {
    sha2::Sha256::new()
        .chain_update(b"litebox-lvbs-crng-reseed-v1")
        .chain_update(rdrand_seed)
        .chain_update(reseed_counter.to_le_bytes())
        .chain_update(current_state)
        .finalize()
        .into()
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
        panic!("dynamic memory allocation is not supported (layout = {layout:?})");
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
