// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An implementation of [`HostInterface`] for LVBS

use crate::{
    Errno, HostInterface, arch::ioport::serial_print_string,
    host::per_cpu_variables::with_per_cpu_variables,
};
use digest::Digest;
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

// The PRK lives only in `crate::vault`. Never expose a raw PRK getter; use
// `DerivedKeyProvider`. `derive_key` uses the PRK; `compute_with_derived_key`
// supports only the per-boot key (`RootKey::PerBoot`) derived from it.

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
                nonce: per_boot_nonce().ok_or(DerivedKeyError::KeyUnavailable)?,
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
fn per_boot_nonce() -> Option<&'static [u8; PER_BOOT_NONCE_LEN]> {
    static PER_BOOT_NONCE: spin::Once<[u8; PER_BOOT_NONCE_LEN]> = spin::Once::new();
    PER_BOOT_NONCE
        .try_call_once(|| {
            let mut nonce = [0u8; PER_BOOT_NONCE_LEN];
            for chunk in nonce.chunks_mut(8) {
                chunk.copy_from_slice(&rdrand_u64().ok_or(())?.to_le_bytes()[..chunk.len()]);
            }
            Ok::<_, ()>(nonce)
        })
        .ok()
}

const RDRAND_RETRY_ATTEMPTS: u32 = 10;

fn rdrand_u64() -> Option<u64> {
    for _ in 0..RDRAND_RETRY_ATTEMPTS {
        let mut word = 0;
        // Safety: `RDRAND` is available on the LVBS target CPUs. A false
        // carry flag means random data is temporarily unavailable.
        if unsafe { core::arch::x86_64::_rdrand64_step(&mut word) } == 1 {
            return Some(word);
        }
        core::hint::spin_loop();
    }
    None
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

pub struct HostLvbsInterface;

impl HostLvbsInterface {}

impl HostInterface for HostLvbsInterface {
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
