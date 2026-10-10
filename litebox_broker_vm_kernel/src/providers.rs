// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The broker core's providers: hardware randomness, and `/dev` (standard
//! streams from the runner's [`StdioProvider`], `null`, `urandom`).

use alloc::sync::Arc;
use litebox_broker_core::{
    BrokerCore, ObjectRights, PolicyEngine,
    fs::{FileService, composer::Composer, devices::Devices, resolver::Resolver},
    random::{RandomProvider, RandomProviderError},
    socket::UnsupportedSocketProvider,
    stdio::StdioProvider,
    timer::UnsupportedTimerProvider,
};
use litebox_platform_vm_kernel::VmKernel;

/// The HAL's hardware CSPRNG as the broker's randomness.
struct HardwareRandom(litebox_hal::rng::Hardware);

impl RandomProvider for HardwareRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), RandomProviderError> {
        self.0.fill(output).map_err(|_| RandomProviderError)
    }
}

fn file_service(
    stdio: Arc<dyn StdioProvider>,
    random: Arc<dyn RandomProvider>,
) -> Arc<dyn FileService> {
    let devices = Composer::builder()
        .mount("/dev", |allocator| Devices::new(allocator, stdio, random))
        .build()
        .unwrap_or_else(|error| panic!("broker file service: {error:?}"));
    Arc::new(Resolver::<VmKernel, _>::new(devices))
}

/// Runner processes, which the kernel vouches for, may open and use files;
/// the only ones are the devices.
///
/// # Panics
///
/// Without a hardware CSPRNG, or on a second call.
pub(crate) fn core(stdio: Arc<dyn StdioProvider>) -> BrokerCore {
    let random: Arc<dyn RandomProvider> = Arc::new(HardwareRandom(litebox_hal::rng::hardware()));
    BrokerCore::new(
        PolicyEngine::with_host_guaranteed_rights(ObjectRights::WAIT | ObjectRights::WRITE),
        Arc::new(UnsupportedSocketProvider),
        Arc::clone(&random),
        Arc::new(UnsupportedTimerProvider),
        file_service(stdio, random),
    )
    .unwrap_or_else(|error| panic!("broker core: {error:?}"))
}
