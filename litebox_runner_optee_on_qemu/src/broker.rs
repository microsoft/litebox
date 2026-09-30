// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! In-process broker. The OP-TEE shim gets randomness only through a broker;
//! this one serves RDRAND and rejects every other request.

use alloc::sync::Arc;
use litebox::LiteBox;
use litebox_broker_core::{
    BrokerCore, ObjectRights, PolicyEngine,
    fs::UnsupportedFileService,
    random::{RandomProvider, RandomProviderError},
    socket::UnsupportedSocketProvider,
    timer::UnsupportedTimerProvider,
};
use litebox_broker_host::test_support::InProcessBrokerSetup;
use litebox_broker_local::BrokerLocal;
use litebox_platform_vm_kernel::VmKernel;

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

/// Call at most once: only one broker core may exist.
///
/// # Panics
///
/// Panics if the CPU does not support RDRAND or the broker setup fails.
pub fn litebox(platform: &'static VmKernel) -> LiteBox<VmKernel> {
    let rdrand =
        Rdrand::new().expect("the CPU does not support RDRAND (for QEMU, use e.g. `-cpu max`)");
    let core = BrokerCore::new(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::empty()),
        Arc::new(UnsupportedSocketProvider),
        Arc::new(rdrand),
        Arc::new(UnsupportedTimerProvider),
        Arc::new(UnsupportedFileService),
    )
    .unwrap_or_else(|error| panic!("in-kernel broker: {error:?}"));
    let setup = InProcessBrokerSetup::new(core);
    let readiness = setup.readiness_sink();
    let (local, _startup, ()) = BrokerLocal::negotiate(setup, |setup| {
        let memory = setup.shared_memory();
        Ok((setup.activate(), memory, ()))
    })
    .unwrap_or_else(|error| panic!("in-kernel broker negotiation: {error:?}"));
    let litebox = LiteBox::new_with_broker_local(platform, local);
    readiness.attach(litebox.broker_notification_dispatcher());
    litebox
}
