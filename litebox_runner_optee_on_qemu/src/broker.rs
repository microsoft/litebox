// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! In-process broker, built with the test-broker builder that the shims' unit
//! tests use. The OP-TEE shim gets randomness only through a broker; this one
//! serves the hardware CSPRNG and rejects every other request.

use alloc::sync::Arc;
use litebox::LiteBox;
use litebox_broker_core::{
    CallerCredential, ObjectRights, PolicyEngine,
    random::{RandomProvider, RandomProviderError},
    test_support::TestBrokerBuilder,
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
    let broker = TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::empty(),
    ))
    .with_random_provider(Arc::new(HardwareRandom(litebox_hal::rng::hardware())))
    .build()
    .unwrap_or_else(|error| panic!("in-kernel broker: {error:?}"));
    let root = broker
        .create_process(CallerCredential::Unauthenticated)
        .unwrap_or_else(|error| panic!("in-kernel broker: {error:?}"));
    let setup = InProcessBrokerSetup::new(root);
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
