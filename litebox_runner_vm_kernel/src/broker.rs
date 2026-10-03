// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The kernel's broker core: RDRAND randomness only.

use alloc::sync::Arc;
use litebox_broker_core::{
    BrokerCore, ObjectRights, PolicyEngine,
    fs::UnsupportedFileService,
    random::{RandomProvider, RandomProviderError},
    socket::UnsupportedSocketProvider,
    timer::UnsupportedTimerProvider,
};

/// Construction requires CPUID-confirmed RDRAND support.
struct Rdrand(());

impl Rdrand {
    fn new() -> Option<Self> {
        // CPUID.1:ECX[30]
        let supported = core::arch::x86_64::__cpuid_count(1, 0).ecx & (1 << 30) != 0;
        supported.then_some(Self(()))
    }
}

impl RandomProvider for Rdrand {
    fn fill(&self, output: &mut [u8]) -> Result<(), RandomProviderError> {
        /// Intel's recommended retry budget for a transient RDRAND underflow.
        const RDRAND_RETRY_ATTEMPTS: u32 = 10;

        for chunk in output.chunks_mut(8) {
            let mut word = 0;
            // Safety: RDRAND support was checked when `self` was created.
            let ok = (0..RDRAND_RETRY_ATTEMPTS)
                .any(|_| unsafe { core::arch::x86_64::_rdrand64_step(&mut word) } == 1);
            if !ok {
                return Err(RandomProviderError);
            }
            chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

/// At most once: only one broker core may exist.
///
/// # Panics
///
/// Without RDRAND, or on a second call.
pub fn core() -> BrokerCore {
    let rdrand =
        Rdrand::new().expect("the CPU does not support RDRAND (for QEMU, use e.g. `-cpu max`)");
    BrokerCore::new(
        PolicyEngine::with_host_guaranteed_rights(ObjectRights::empty()),
        Arc::new(UnsupportedSocketProvider),
        Arc::new(rdrand),
        Arc::new(UnsupportedTimerProvider),
        Arc::new(UnsupportedFileService),
    )
    .unwrap_or_else(|error| panic!("broker core: {error:?}"))
}
