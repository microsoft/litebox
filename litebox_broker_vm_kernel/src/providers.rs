// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The broker core's providers: hardware randomness, timers, `/dev` (standard
//! streams from the runner's [`StdioProvider`], `null`, `urandom`),
//! optionally, a read-only root from a tar, read-only host directories
//! ([`Share`]s) over 9P, and sockets.

use crate::share::{Share, ShareFs};
use alloc::sync::Arc;
use alloc::vec::Vec;
use litebox_broker_core::{
    BrokerCore, BrokerCoreLimits, CallerCredential, DestinationPortRange, DestinationRule,
    Ipv4Cidr, ObjectRights, PolicyEngine, SocketPolicy, VsockPolicy,
    fs::{FileService, composer::Composer, devices::Devices, resolver::Resolver, tar_ro::TarRo},
    random::{RandomProvider, RandomProviderError},
    socket::SocketProvider,
    stdio::StdioProvider,
    timer::TimerProvider,
    vsock::VsockProvider,
};
use litebox_broker_protocol::socket::{Ipv4Address, Port};
use litebox_platform_vm_kernel::VmKernel;

/// The HAL's hardware CSPRNG as the broker's randomness.
struct HardwareRandom(litebox_hal::rng::Hardware);

impl RandomProvider for HardwareRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), RandomProviderError> {
        self.0.fill(output).map_err(|_| RandomProviderError)
    }
}

/// # Panics
///
/// If a share cannot be mounted, as `--mount` fails userland's broker.
fn file_service(
    root: Option<&'static [u8]>,
    shares: Vec<Share>,
    stdio: Arc<dyn StdioProvider>,
    random: Arc<dyn RandomProvider>,
) -> Arc<dyn FileService> {
    let mut composer = Composer::builder();
    if let Some(root) = root {
        composer = composer.mount("/", |allocator| TarRo::new(root.into(), allocator));
    }
    composer = composer.mount("/dev", |allocator| Devices::new(allocator, stdio, random));
    for share in shares {
        composer = composer
            .try_mount(&share.path, |allocator| {
                ShareFs::new(share.transport, allocator)
            })
            .unwrap_or_else(|error| panic!("mounting a share at {}: {error}", share.path));
    }
    let devices = composer
        .build()
        .unwrap_or_else(|error| panic!("broker file service: {error:?}"));
    Arc::new(Resolver::<VmKernel, _>::new(devices))
}

/// Sockets may reach the guest network, and, if `external`, any address:
/// what is reachable is up to the network the runner's link is on.
fn socket_policy(external: bool) -> SocketPolicy {
    let policy = SocketPolicy::guest_network();
    if !external {
        return policy;
    }
    let anywhere = [DestinationRule::new(
        CallerCredential::HostGuaranteed,
        Ipv4Cidr::new(Ipv4Address([0, 0, 0, 0]), 0).expect("a canonical network"),
        DestinationPortRange::new(Port(1), Port(u16::MAX)).expect("an ordered range"),
    )];
    policy
        .with_tcp_destination_rules(&anywhere)
        .and_then(|policy| policy.with_udp_destination_rules(&anywhere))
        .expect("one rule fits")
}

/// The broker core's limits, which the network stack also applies.
pub(crate) const LIMITS: BrokerCoreLimits = BrokerCoreLimits::DEFAULT;

/// A seed for the network stack.
///
/// # Panics
///
/// Without a hardware CSPRNG.
pub(crate) fn seed() -> u64 {
    let mut seed = [0; 8];
    litebox_hal::rng::hardware()
        .fill(&mut seed)
        .unwrap_or_else(|_| panic!("hardware CSPRNG failed"));
    u64::from_ne_bytes(seed)
}

/// Runner processes, which the kernel vouches for, may open and use files: the
/// devices, `root`'s, if any, and the shares' (read-only); sockets (see
/// [`socket_policy`]); with a `vsock` provider, which this installs, vsock
/// sockets, to and on any port; and, if `allow_process_duplication`, start
/// child processes.
///
/// # Panics
///
/// Without a hardware CSPRNG, on a second call, or if a share cannot be
/// mounted.
#[allow(clippy::too_many_arguments)]
pub(crate) fn core(
    root: Option<&'static [u8]>,
    shares: Vec<Share>,
    stdio: Arc<dyn StdioProvider>,
    timers: Arc<dyn TimerProvider>,
    sockets: Arc<dyn SocketProvider>,
    external: bool,
    vsock: Option<Arc<dyn VsockProvider>>,
    allow_process_duplication: bool,
) -> BrokerCore {
    let random: Arc<dyn RandomProvider> = Arc::new(HardwareRandom(litebox_hal::rng::hardware()));
    let core = BrokerCore::new_with_limits(
        PolicyEngine::with_host_guaranteed_rights(ObjectRights::WAIT | ObjectRights::WRITE)
            .with_socket_policy(socket_policy(external))
            .with_vsock_policy(if vsock.is_some() {
                VsockPolicy::any()
            } else {
                VsockPolicy::deny()
            })
            .with_process_duplication_enabled(allow_process_duplication),
        LIMITS,
        sockets,
        Arc::clone(&random),
        timers,
        file_service(root, shares, stdio, random),
    )
    .unwrap_or_else(|error| panic!("broker core: {error:?}"));
    match vsock {
        Some(vsock) => core.with_vsock_provider(vsock),
        None => core,
    }
}
