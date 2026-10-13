// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The broker core's providers: hardware randomness, timers, `/dev` (standard
//! streams from the runner's [`StdioProvider`], `null`, `urandom`), and,
//! optionally, a read-only root from a tar.

use alloc::sync::Arc;
use litebox_broker_core::{
    BrokerCore, ObjectRights, PolicyEngine,
    fs::{FileService, composer::Composer, devices::Devices, resolver::Resolver, tar_ro::TarRo},
    random::{RandomProvider, RandomProviderError},
    socket::UnsupportedSocketProvider,
    stdio::StdioProvider,
    timer::TimerProvider,
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
    root: Option<&'static [u8]>,
    stdio: Arc<dyn StdioProvider>,
    random: Arc<dyn RandomProvider>,
) -> Arc<dyn FileService> {
    let mut composer = Composer::builder();
    if let Some(root) = root {
        composer = composer.mount("/", |allocator| TarRo::new(root.into(), allocator));
    }
    let devices = composer
        .mount("/dev", |allocator| Devices::new(allocator, stdio, random))
        .build()
        .unwrap_or_else(|error| panic!("broker file service: {error:?}"));
    Arc::new(Resolver::<VmKernel, _>::new(devices))
}

/// Runner processes, which the kernel vouches for, may open and use files:
/// the devices, and `root`'s, if any.
///
/// # Panics
///
/// Without a hardware CSPRNG, or on a second call.
pub(crate) fn core(
    root: Option<&'static [u8]>,
    stdio: Arc<dyn StdioProvider>,
    timers: Arc<dyn TimerProvider>,
) -> BrokerCore {
    let random: Arc<dyn RandomProvider> = Arc::new(HardwareRandom(litebox_hal::rng::hardware()));
    BrokerCore::new(
        PolicyEngine::with_host_guaranteed_rights(ObjectRights::WAIT | ObjectRights::WRITE),
        Arc::new(UnsupportedSocketProvider),
        Arc::clone(&random),
        timers,
        file_service(root, stdio, random),
    )
    .unwrap_or_else(|error| panic!("broker core: {error:?}"))
}
