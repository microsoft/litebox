// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Concrete Hyper-V VTL1 platform implementation.
//!
//! This module owns LVBS boot policy, per-CPU composition, foreign-memory
//! access, and platform-specific providers. Hyper-V/VSM mechanisms remain in
//! [`crate::mshv`]; supporting another VM does not require generalizing the
//! cross-domain service interfaces.

pub mod boot;
pub mod bootparam;
pub mod clock;
pub mod console;
pub mod interrupts;
pub mod linux;
pub mod memory;
pub mod per_cpu_variables;
pub mod phys_memory;
pub mod timer;
pub mod tlb;

/// Anchor byte that ensures the `.hvcall_page` linker section is emitted.
#[used]
#[unsafe(link_section = ".hvcall_page")]
static HVCALL_PAGE_ANCHOR: u8 = 0;

/// Get the address of the Hyper-V hypercall code page.
///
/// The linker script gives this page a well-known, page-aligned location.
/// Hyper-V writes executable code into it via `HV_X64_MSR_HYPERCALL`.
/// VPs share this address; Hyper-V identifies the calling VP internally.
#[inline]
pub fn hv_hypercall_page_address() -> u64 {
    crate::mshv::vtl1_mem_layout::get_hvcall_page_start_address()
}

use crate::host::Host;
use digest::Digest;
use litebox_common_lvbs::PRK_LEN;
use rand_core::{RngCore, SeedableRng};
use zeroize::Zeroizing;

pub type LvbsLinuxKernel = crate::LinuxKernel<LvbsHost>;

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

impl litebox::platform::CrngProvider for LvbsHost {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        let mut random = self.random.lock();
        random
            .get_or_insert_with(|| {
                LvbsCrng::new(
                    self.root_key
                        .get()
                        .expect("Platform root key not initialized"),
                    rdrand_seed().expect("RDRAND unavailable during CRNG initialization"),
                )
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
    fn new(prk: &[u8; PRK_LEN], rdrand_seed: CrngSeed) -> Self {
        Self {
            random: rand_chacha::ChaCha20Rng::from_seed(crng_seed_from_prk_and_rdrand(
                prk,
                rdrand_seed,
            )),
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

// Do not expose a raw PRK getter (i.e., no `get_platform_root_key`).
// Consumers should provide key derivation function and context
// through `DerivedKeyProvider` so PRK access stays in this module.

impl LvbsHost {
    /// Install this host's root key once, via the VTL1 setup gate. Later
    /// derivations never expose the raw key outside this module.
    pub(crate) fn set_platform_root_key(&self, key: &[u8; PRK_LEN]) {
        self.root_key.call_once(|| {
            let mut prk = Zeroizing::new([0u8; PRK_LEN]);
            prk.copy_from_slice(key);
            *prk
        });
    }
}

impl litebox::platform::DerivedKeyProvider for LvbsHost {
    fn derive_key<E>(
        &self,
        kdf: Option<fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>>,
        params: litebox::platform::KDFParams,
    ) -> Result<(), litebox::platform::DerivedKeyError<E>> {
        let Some(prk) = self.root_key.get() else {
            return Err(litebox::platform::DerivedKeyError::UnsupportedRebootPersistentKey);
        };
        match kdf {
            None => Err(litebox::platform::DerivedKeyError::ShimKDFRequired),
            Some(kdf) => Ok(kdf(prk, params)?),
        }
    }
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

fn crng_seed_from_prk_and_rdrand(prk: &[u8; PRK_LEN], rdrand_seed: CrngSeed) -> CrngSeed {
    sha2::Sha256::new()
        .chain_update(b"litebox-lvbs-crng-seed-v1")
        .chain_update(prk)
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

pub struct LvbsHost {
    vtl1_phys_frame_range:
        x86_64::structures::paging::frame::PhysFrameRange<x86_64::structures::paging::Size4KiB>,
    end_of_boot: core::sync::atomic::AtomicBool,
    timer: timer::LvbsTimer,
    random: spin::mutex::SpinMutex<Option<LvbsCrng>>,
    root_key: spin::Once<[u8; PRK_LEN]>,
}

impl crate::console::DiagnosticOutput for LvbsHost {
    fn print(args: core::fmt::Arguments<'_>) {
        console::print(args);
    }
}

impl Host for LvbsHost {
    type Memory = memory::LvbsMemory;
    type Timer = timer::LvbsTimer;
    fn execution_timer(&self) -> &Self::Timer {
        &self.timer
    }
}

impl litebox::platform::RawMutexProvider for LvbsHost {
    type RawMutex = super::no_scheduler::NoSchedulerMutex;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const TEST_PRK: [u8; PRK_LEN] = [0x42; PRK_LEN];
    const INIT_SEED: CrngSeed = [0xA5; 32];
    const RESEED_SEED: CrngSeed = [0x5A; 32];

    #[test]
    fn root_key_is_owned_by_each_host_and_installed_once() {
        use litebox::platform::{DerivedKeyError, DerivedKeyProvider, KDFParams};
        let make = || {
            let start =
                x86_64::structures::paging::PhysFrame::containing_address(x86_64::PhysAddr::new(0));
            LvbsHost {
                vtl1_phys_frame_range: x86_64::structures::paging::PhysFrame::range(start, start),
                end_of_boot: core::sync::atomic::AtomicBool::new(false),
                timer: timer::LvbsTimer,
                random: spin::mutex::SpinMutex::new(None),
                root_key: spin::Once::new(),
            }
        };
        let first = make();
        let second = make();
        let mut output = [0; PRK_LEN];
        assert!(matches!(
            second.derive_key::<core::convert::Infallible>(
                None,
                KDFParams {
                    context: b"test",
                    output: &mut output
                }
            ),
            Err(DerivedKeyError::UnsupportedRebootPersistentKey)
        ));
        first.set_platform_root_key(&[0x11; PRK_LEN]);
        second.set_platform_root_key(&[0x22; PRK_LEN]);
        first.set_platform_root_key(&[0x33; PRK_LEN]);
        for (host, expected) in [(&first, 0x11), (&second, 0x22)] {
            host.derive_key::<core::convert::Infallible>(
                Some(|key, params| {
                    params.output.copy_from_slice(key);
                    Ok(())
                }),
                KDFParams {
                    context: b"test",
                    output: &mut output,
                },
            )
            .unwrap();
            assert_eq!(output, [expected; PRK_LEN]);
        }
    }

    #[test]
    fn crosses_reseed_boundary_twice_with_accurate_budget() {
        let mut crng = LvbsCrng::new(&TEST_PRK, INIT_SEED);
        let mut buf = vec![0u8; CRNG_RESEED_INTERVAL_BYTES * 2 + 7];
        crng.fill_bytes(&mut buf, || Some(RESEED_SEED));
        assert_eq!(crng.reseed_counter, 2);
        assert_eq!(crng.bytes_until_reseed, CRNG_RESEED_INTERVAL_BYTES - 7);
    }

    #[test]
    fn rdrand_failure_engages_backoff_without_reseed() {
        let mut crng = LvbsCrng::new(&TEST_PRK, INIT_SEED);
        let mut buf = vec![0u8; CRNG_RESEED_INTERVAL_BYTES];
        crng.fill_bytes(&mut buf, || None);
        assert_eq!(crng.reseed_counter, 0);
        assert_eq!(crng.bytes_until_reseed, CRNG_RESEED_BACKOFF_BYTES);
    }
}
