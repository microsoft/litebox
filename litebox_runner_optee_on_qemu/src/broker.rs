// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! In-process broker. The OP-TEE shim gets randomness only through a broker;
//! this one serves the hardware CSPRNG and rejects every other request.

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

/// The HAL's hardware CSPRNG as the broker's randomness.
struct HardwareRandom(litebox_hal::rng::Hardware);

impl RandomProvider for HardwareRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), RandomProviderError> {
        self.0.fill(output).map_err(|_| RandomProviderError)
    }
}

/// Call at most once: only one broker core may exist.
///
/// # Panics
///
/// Panics without a hardware CSPRNG, or if the broker setup fails.
pub fn litebox(platform: &'static VmKernel) -> LiteBox<VmKernel> {
    let core = BrokerCore::new(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::empty()),
        Arc::new(UnsupportedSocketProvider),
        Arc::new(HardwareRandom(litebox_hal::rng::hardware())),
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
