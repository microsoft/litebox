// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The broker core's providers: hardware randomness only.

use alloc::sync::Arc;
use litebox_broker_core::{
    BrokerCore, ObjectRights, PolicyEngine,
    fs::UnsupportedFileService,
    random::{RandomProvider, RandomProviderError},
    socket::UnsupportedSocketProvider,
    timer::UnsupportedTimerProvider,
};

/// The HAL's hardware CSPRNG as the broker's randomness.
struct HardwareRandom(litebox_hal::rng::Hardware);

impl RandomProvider for HardwareRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), RandomProviderError> {
        self.0.fill(output).map_err(|_| RandomProviderError)
    }
}

/// # Panics
///
/// Without a hardware CSPRNG, or on a second call.
pub(crate) fn core() -> BrokerCore {
    BrokerCore::new(
        PolicyEngine::with_host_guaranteed_rights(ObjectRights::empty()),
        Arc::new(UnsupportedSocketProvider),
        Arc::new(HardwareRandom(litebox_hal::rng::hardware())),
        Arc::new(UnsupportedTimerProvider),
        Arc::new(UnsupportedFileService),
    )
    .unwrap_or_else(|error| panic!("broker core: {error:?}"))
}
