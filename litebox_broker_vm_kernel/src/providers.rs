// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The broker core's providers: hardware randomness, timers, `/dev` (standard
//! streams from the runner's [`StdioProvider`], `null`, `urandom`),
//! optionally, a root over a tar, read-only host directories ([`Share`]s)
//! over FUSE, and sockets.

use crate::share::{self, Share};
use alloc::sync::Arc;
use alloc::vec::Vec;
use litebox_broker_core::{
    BrokerCore, BrokerCoreLimits, ObjectRights, PolicyEngine, SocketPolicy, VsockPolicy,
    fs::{
        FileService, Mode, UserInfo,
        composer::Composer,
        devices::Devices,
        in_mem::{InMem, InitialNode},
        overlay::Overlay,
        procfs::ProcFs,
        resolver::Resolver,
        tar_ro::TarRo,
    },
    pid_namespace::PidNamespace,
    random::{RandomProvider, RandomProviderError},
    socket::SocketProvider,
    stdio::StdioProvider,
    timer::TimerProvider,
    vsock_socket::VsockProvider,
};
use litebox_broker_protocol::process::PidNamespaceOptions;
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
    let mut composer = Composer::<VmKernel>::builder();
    if let Some(root) = root {
        composer = composer.mount_nestable("/", |allocators| {
            let tmp = InitialNode::Directory {
                mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
                owner: UserInfo::ROOT,
            };
            Overlay::<VmKernel>::new(
                InMem::<VmKernel>::new_initialized([("/tmp", tmp)], allocators.next()),
                TarRo::new(root.into(), allocators.next()),
                allocators.next(),
            )
        });
    }
    composer = composer
        .mount("/proc", ProcFs::new)
        .mount("/dev", |allocator| Devices::new(allocator, stdio, random));
    for Share { path, transport } in shares {
        composer = composer
            .try_mount(&path, |allocator| share::connect(transport, allocator))
            .unwrap_or_else(|error| panic!("mounting a share at {path}: FUSE: {error}"));
    }
    let devices = composer
        .build()
        .unwrap_or_else(|error| panic!("broker file service: {error:?}"));
    Arc::new(Resolver::<VmKernel, _>::new(devices))
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

/// Creates the broker core, along with the PID namespace and file service of
/// the processes the kernel starts.
///
/// Runner processes, which the kernel vouches for, may open and use files: the
/// devices, `root`'s, if any, and the shares' (read-only); sockets, to
/// `socket_policy`'s destinations; with a `vsock` provider, vsock sockets, to
/// and on any port; and, if `allow_process_duplication`, start child processes.
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
    socket_policy: &SocketPolicy,
    vsock: Option<Arc<dyn VsockProvider>>,
    allow_process_duplication: bool,
    pid_namespace: PidNamespaceOptions,
) -> (Arc<BrokerCore>, Arc<PidNamespace>, Arc<dyn FileService>) {
    let random: Arc<dyn RandomProvider> = Arc::new(HardwareRandom(litebox_hal::rng::hardware()));
    let core = BrokerCore::new(
        PolicyEngine::with_host_guaranteed_rights(ObjectRights::WAIT | ObjectRights::WRITE)
            .with_socket_policy(*socket_policy)
            .with_vsock_policy(if vsock.is_some() {
                VsockPolicy::any()
            } else {
                VsockPolicy::deny()
            })
            .with_process_duplication_enabled(allow_process_duplication),
        LIMITS,
        sockets,
        vsock,
        Arc::clone(&random),
        timers,
    )
    .unwrap_or_else(|error| panic!("broker core: {error:?}"));
    let pid_namespace = PidNamespace::with_options(&core, pid_namespace)
        .unwrap_or_else(|error| panic!("PID namespace: {error:?}"));
    let fs = file_service(root, shares, stdio, random);
    (core, Arc::new(pid_namespace), fs)
}
