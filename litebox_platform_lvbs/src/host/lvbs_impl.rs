// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An implementation of [`HostInterface`] for LVBS

use crate::{
    Errno, HostInterface, arch::ioport::serial_print_string,
    host::per_cpu_variables::with_per_cpu_variables,
};
use digest::Digest;
use litebox_common_lvbs::CRNG_SEED_LEN;
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
            .get_or_insert_with(|| {
                LvbsCrng::from_seed(crng_seed_from_rot_and_rdrand(
                    CRNG_SEED_ONCE.get().expect("CRNG seed not set"),
                    rdrand_seed().expect("RDRAND unavailable during CRNG initialization"),
                ))
            })
            .fill_bytes(buf, rdrand_seed);
    }
}

type CrngSeed = <rand_chacha::ChaCha20Rng as SeedableRng>::Seed;

const CRNG_RESEED_INTERVAL_BYTES: usize = 1024 * 1024;
const CRNG_RESEED_BACKOFF_BYTES: usize = 64 * 1024;
const CRNG_RESEED_STATE_BYTES: usize = 32;
const RDRAND_RETRY_ATTEMPTS: u32 = 10;

struct LvbsCrng {
    random: rand_chacha::ChaCha20Rng,
    bytes_until_reseed: usize,
    reseed_counter: usize,
}

impl LvbsCrng {
    fn from_seed(seed: CrngSeed) -> Self {
        Self {
            random: rand_chacha::ChaCha20Rng::from_seed(seed),
            bytes_until_reseed: CRNG_RESEED_INTERVAL_BYTES,
            reseed_counter: 0,
        }
    }

    fn fill_bytes(&mut self, mut buf: &mut [u8], rdrand_seed: impl Fn() -> Option<CrngSeed>) {
        while !buf.is_empty() {
            let len = buf.len().min(self.bytes_until_reseed);
            let (chunk, rest) = buf.split_at_mut(len);
            self.random.fill_bytes(chunk);
            buf = rest;
            self.bytes_until_reseed -= len;

            if self.bytes_until_reseed == 0 {
                match rdrand_seed() {
                    Some(seed) => self.reseed(seed),
                    None => self.bytes_until_reseed = CRNG_RESEED_BACKOFF_BYTES,
                }
            }
        }
    }

    fn reseed(&mut self, rdrand_seed: CrngSeed) {
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

// The PRK lives only in `crate::vault`. Never expose a raw PRK getter; use
// `DerivedKeyProvider`. `derive_key` uses the PRK; `compute_with_derived_key`
// supports only the per-boot key (`RootKey::PerBoot`) derived from it.
static CRNG_SEED_ONCE: spin::Once<[u8; CRNG_SEED_LEN]> = spin::Once::new();

/// Sets the trusted CRNG seed for this platform.
///
/// This should be called once during platform initialization with a seed
/// derived from a hardware root of trust (e.g., a TPM).
pub(crate) fn set_crng_seed(seed: &[u8; CRNG_SEED_LEN]) {
    CRNG_SEED_ONCE.call_once(|| {
        let mut s = Zeroizing::new([0u8; CRNG_SEED_LEN]);
        s.copy_from_slice(seed);
        *s
    });
}

impl litebox::platform::DerivedKeyProvider for LvbsLinuxKernel {
    fn derive_key<E>(
        &self,
        kdf: Option<fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>>,
        params: litebox::platform::KDFParams,
    ) -> Result<(), litebox::platform::DerivedKeyError<E>> {
        use crate::vault::{Input, Kdf};
        use litebox::platform::DerivedKeyError;

        let Some(kdf) = kdf else {
            return Err(DerivedKeyError::ShimKDFRequired);
        };
        let stage = Kdf {
            f: kdf,
            context: Input::new(params.context),
        };
        crate::vault::run(&stage, params.output).map_err(|_| DerivedKeyError::KeyUnavailable)??;
        Ok(())
    }

    fn compute_with_derived_key<E, const KEY_LEN: usize>(
        &self,
        root: litebox::platform::RootKey,
        kdf: fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>,
        key_context: &[u8],
        op: fn(&[u8], litebox::platform::ComputeParams) -> Result<(), E>,
        params: litebox::platform::ComputeParams,
    ) -> Result<(), litebox::platform::DerivedKeyError<E>> {
        use crate::vault::{Compute, Input, Kdf, Then};
        use litebox::platform::{DerivedKeyError, RootKey};

        if root != RootKey::PerBoot {
            return Err(DerivedKeyError::UnsupportedRebootPersistentKey);
        }

        // The vault derives the per-boot key from the PRK first; `kdf` is passed
        // only the per-boot key, and `op` only the derived key. Both stay on the
        // vault stack.
        let kdf_op = Then::<_, _, KEY_LEN>(
            Kdf {
                f: kdf,
                context: Input::new(key_context),
            },
            Compute {
                f: op,
                input: Input::new(params.input),
            },
        );
        let stage = Then::<_, _, PBK_LEN>(
            PerBootKey {
                nonce: per_boot_nonce(self),
            },
            kdf_op,
        );
        crate::vault::run(&stage, params.output).map_err(|_| DerivedKeyError::KeyUnavailable)??;
        Ok(())
    }
}

const PBK_LEN: usize = 32;
const PER_BOOT_NONCE_LEN: usize = 32;

/// Random per-boot nonce from which, with the PRK, the per-boot key is derived.
/// It is not secret: it reveals nothing without the PRK.
fn per_boot_nonce(platform: &LvbsLinuxKernel) -> &'static [u8; PER_BOOT_NONCE_LEN] {
    use litebox::platform::CrngProvider as _;

    static PER_BOOT_NONCE: spin::Once<[u8; PER_BOOT_NONCE_LEN]> = spin::Once::new();
    PER_BOOT_NONCE.call_once(|| {
        let mut nonce = [0u8; PER_BOOT_NONCE_LEN];
        platform.fill_bytes_crng(&mut nonce);
        nonce
    })
}

/// Vault stage deriving the per-boot key (PBK) from the PRK and the per-boot
/// nonce: PBK = SHA-256(label || PRK || nonce). Being platform code, it is
/// called directly rather than through a retpoline.
struct PerBootKey {
    /// In the kernel image, which the vault maps.
    nonce: &'static [u8; PER_BOOT_NONCE_LEN],
}

impl<E> crate::vault::Stage<E> for PerBootKey {
    unsafe fn run(&self, prk: &[u8], output: &mut [u8]) -> Result<(), E> {
        // `Then::<_, _, PBK_LEN>` sizes `output`, so this cannot panic (which
        // may be fatal inside the vault).
        debug_assert_eq!(output.len(), PBK_LEN);
        output.copy_from_slice(&per_boot_key_from_prk_and_nonce(prk, self.nonce)[..]);
        Ok(())
    }
}

fn per_boot_key_from_prk_and_nonce(
    prk: &[u8],
    nonce: &[u8; PER_BOOT_NONCE_LEN],
) -> Zeroizing<[u8; PBK_LEN]> {
    Zeroizing::new(
        sha2::Sha256::new()
            .chain_update(b"litebox-lvbs-pbk-v1")
            .chain_update(prk)
            .chain_update(nonce)
            .finalize()
            .into(),
    )
}

fn rdrand_seed() -> Option<CrngSeed> {
    let mut seed = CrngSeed::default();
    for chunk in seed.chunks_mut(8) {
        let mut word = 0;
        let mut ok = false;
        for _ in 0..RDRAND_RETRY_ATTEMPTS {
            // Safety: `RDRAND` is available on the LVBS target CPUs. A false
            // carry flag means random data is temporarily unavailable.
            if unsafe { core::arch::x86_64::_rdrand64_step(&mut word) } == 1 {
                ok = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !ok {
            return None;
        }
        chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
    }
    Some(seed)
}

fn crng_seed_from_tpm_and_rdrand(seed: &[u8], rdrand_seed: CrngSeed) -> CrngSeed {
    sha2::Sha256::new()
        .chain_update(b"litebox-lvbs-crng-seed-v1")
        .chain_update(seed)
        .chain_update(rdrand_seed)
        .finalize()
        .into()
}

fn crng_reseed_from_rdrand_and_state(
    rdrand_seed: CrngSeed,
    reseed_counter: usize,
    current_state: &[u8; CRNG_RESEED_STATE_BYTES],
) -> CrngSeed {
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

    fn alloc(_layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        // Called on OOM. Must not panic so that fallible callers see the failure.
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const TEST_ROT_SEED: [u8; CRNG_SEED_LEN] = [0x42; CRNG_SEED_LEN];
    const INIT_SEED: CrngSeed = [0xA5; 32];
    const RESEED_SEED: CrngSeed = [0x5A; 32];

    #[test]
    fn crosses_reseed_boundary_twice_with_accurate_budget() {
        let mut crng =
            LvbsCrng::from_seed(crng_seed_from_rot_and_rdrand(&TEST_ROT_SEED, INIT_SEED));
        let mut buf = vec![0u8; CRNG_RESEED_INTERVAL_BYTES * 2 + 7];
        crng.fill_bytes(&mut buf, || Some(RESEED_SEED));
        assert_eq!(crng.reseed_counter, 2);
        assert_eq!(crng.bytes_until_reseed, CRNG_RESEED_INTERVAL_BYTES - 7);
    }

    #[test]
    fn rdrand_failure_engages_backoff_without_reseed() {
        let mut crng =
            LvbsCrng::from_seed(crng_seed_from_rot_and_rdrand(&TEST_ROT_SEED, INIT_SEED));
        let mut buf = vec![0u8; CRNG_RESEED_INTERVAL_BYTES];
        crng.fill_bytes(&mut buf, || None);
        assert_eq!(crng.reseed_counter, 0);
        assert_eq!(crng.bytes_until_reseed, CRNG_RESEED_BACKOFF_BYTES);
    }
}
