// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Thread-local storage and key derivation.

use crate::{VmKernel, per_cpu::with_per_cpu_variables};

pub const PRK_LEN: usize = 32;

// Safety: the pointer is stored per CPU, and there is one thread per CPU. It
// starts as null and is only changed by `replace_thread_local_storage`.
unsafe impl litebox::platform::ThreadLocalStorageProvider for VmKernel {
    fn get_thread_local_storage() -> *mut () {
        with_per_cpu_variables(|pcv| pcv.tls.get())
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        with_per_cpu_variables(|pcv| pcv.tls.replace(value))
    }
}

static PRK_ONCE: spin::Once<[u8; PRK_LEN]> = spin::Once::new();

/// Call before user execution; otherwise key derivation is unavailable.
/// The kernel should wipe its input copy; the stored PRK lives until reset.
///
/// # Panics
///
/// Panics if the PRK is already set.
pub fn set_platform_root_key(key: &[u8; PRK_LEN]) {
    let mut installed = false;
    PRK_ONCE.call_once(|| {
        installed = true;
        *key
    });
    assert!(installed, "the platform root key is already set");
}

impl litebox::platform::DerivedKeyProvider for VmKernel {
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

    fn compute_with_derived_key<E, const KEY_LEN: usize>(
        &self,
        root: litebox::platform::RootKey,
        _shim_kdf: fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>,
        _key_context: &[u8],
        _op: fn(&[u8], litebox::platform::ComputeParams) -> Result<(), E>,
        _params: litebox::platform::ComputeParams,
    ) -> Result<(), litebox::platform::DerivedKeyError<E>> {
        // No per-boot root key, and reboot-persistent keys are only exposed via `derive_key`.
        Err(match root {
            litebox::platform::RootKey::Persistent => {
                litebox::platform::DerivedKeyError::UnsupportedRebootPersistentKey
            }
            litebox::platform::RootKey::PerBoot => {
                litebox::platform::DerivedKeyError::UnsupportedPerBootKey
            }
        })
    }
}
