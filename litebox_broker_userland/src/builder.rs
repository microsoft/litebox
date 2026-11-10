// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Structured configuration for constructing a userland broker core.
//!
//! [`BrokerCoreBuilder`] selects the platform socket provider, the
//! cross-platform getrandom-backed random provider, the thread-backed timer
//! provider, and, if given, the vsock provider, and applies whatever platform
//! setup a deployment needs before its first association is served (for
//! example, Linux lock-tracing initialization). This is what lets an
//! in-process caller construct the same [`BrokerCore`] the userland broker
//! binary does, from a structured configuration rather than from `CliArgs`.

use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Arc;

use litebox_broker_core::socket::{PublishedTcpPort, SocketProvider};
use litebox_broker_core::vsock_socket::VsockProvider;
use litebox_broker_core::{BrokerCore, BrokerCoreLimits, BrokerError, PolicyEngine};

use crate::random::UserlandRandomProvider;
use crate::timer::UserlandTimerProvider;

/// The host network of the broker's sockets, and how host clients reach the
/// guest's TCP listeners there.
///
/// A host client's connection to a published port is queued on the guest
/// listener covering the guest's address
/// ([`GUEST_IPV4_ADDRESS`](litebox_broker_core::socket::GUEST_IPV4_ADDRESS))
/// and the port's guest port, as one from the gateway. A loopback guest
/// listener stays private.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostNetworkOptions {
    /// Host addresses that the broker listens on from its start to its end,
    /// whatever the guest listens on.
    pub published_tcp_ports: Vec<PublishedTcpPort>,
    /// A host IP on which the broker publishes the port of each guest TCP
    /// listener, for as long as it listens: a guest listener covering the
    /// guest's address and `PORT` is reached at `IP:PORT`. A port the host
    /// network already uses is left unpublished.
    ///
    /// Meant for a host network of the broker's own, such as a container's,
    /// where `0.0.0.0` lets the network's port mappings reach the guest as
    /// they would reach a native process there.
    pub published_listener_ip: Option<Ipv4Addr>,
    /// The Windows network compartment, such as a container's HCN
    /// namespace's, that the broker opens its host sockets in, rather than
    /// its own. Other hosts have none: on Linux, a broker uses the network
    /// namespace it starts in.
    pub compartment: Option<u32>,
}

/// Failure constructing a userland [`BrokerCore`].
///
/// Platform setup, such as creating a socket provider or spawning timer
/// threads, fails with [`std::io::Error`]. A rejected core configuration, such
/// as attempting to construct a second broker core in one process, fails with
/// [`BrokerError`]. Keeping these distinct lets a caller decide whether a
/// failure is retryable platform trouble or a fixed configuration mistake.
#[derive(Debug)]
#[non_exhaustive]
pub enum BrokerBuildError {
    /// Platform-level setup failed.
    Io(std::io::Error),
    /// The broker core rejected the requested configuration.
    Broker(BrokerError),
}

impl fmt::Display for BrokerBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "broker platform setup failed: {error}"),
            Self::Broker(error) => write!(formatter, "broker core rejected: {error}"),
        }
    }
}

impl std::error::Error for BrokerBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Broker(error) => Some(error),
        }
    }
}

impl From<std::io::Error> for BrokerBuildError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<BrokerError> for BrokerBuildError {
    fn from(error: BrokerError) -> Self {
        Self::Broker(error)
    }
}

/// Structured configuration for building a userland [`BrokerCore`].
///
/// This is the in-process equivalent of the userland broker binary's platform
/// setup: it selects the same platform providers and applies the same
/// process-wide platform initialization, so a caller that hosts a broker core
/// directly gets the same behavior a deployment launched through the binary
/// would.
pub struct BrokerCoreBuilder {
    policy: PolicyEngine,
    limits: BrokerCoreLimits,
    vsock: Option<Arc<dyn VsockProvider>>,
    host_network: HostNetworkOptions,
}

impl BrokerCoreBuilder {
    /// Creates a builder with the given policy and default authority-state
    /// limits.
    #[must_use]
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            policy,
            limits: BrokerCoreLimits::DEFAULT,
            vsock: None,
            host_network: HostNetworkOptions::default(),
        }
    }

    /// Overrides the default authority-state limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: BrokerCoreLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Backs the guest's vsock sockets with `provider` (e.g., a hybrid-vsock
    /// bridge's). The policy must also allow them
    /// ([`PolicyEngine::with_vsock_policy`]).
    #[must_use]
    pub fn with_vsock_provider(mut self, provider: Arc<dyn VsockProvider>) -> Self {
        self.vsock = Some(provider);
        self
    }

    /// Publishes guest TCP ports on host addresses: the socket provider
    /// listens on each from [`Self::build`] on, and queues its clients'
    /// connections on the guest's listeners.
    ///
    /// Building fails if a host address is taken, or on a host without a
    /// socket provider.
    #[must_use]
    pub fn with_published_tcp_ports(mut self, ports: Vec<PublishedTcpPort>) -> Self {
        self.host_network.published_tcp_ports = ports;
        self
    }

    /// Selects the host network of the broker's sockets, and the ports
    /// published there; see [`HostNetworkOptions`]. Replaces any earlier
    /// [`Self::with_published_tcp_ports`].
    ///
    /// Building fails if a published host address is taken, if the network
    /// cannot be entered, or, unless the options are the defaults, on a host
    /// without a socket provider.
    #[must_use]
    pub fn with_host_network(mut self, options: HostNetworkOptions) -> Self {
        self.host_network = options;
        self
    }

    /// Applies platform setup and constructs the [`BrokerCore`].
    ///
    /// A broker process may construct only one broker core for its process
    /// lifetime; see [`BrokerCore::new`].
    pub fn build(self) -> Result<Arc<BrokerCore>, BrokerBuildError> {
        #[cfg(all(target_os = "linux", feature = "lock_tracing"))]
        {
            static LOCK_TRACING_PLATFORM:
                litebox_broker_platform_linux_userland::LinuxTimeProvider =
                litebox_broker_platform_linux_userland::LinuxTimeProvider;
            litebox_platform::sync::init_lock_tracing(&LOCK_TRACING_PLATFORM);
        }

        let socket_provider = platform_socket_provider(&self.limits, &self.host_network)?;
        Ok(BrokerCore::new(
            self.policy,
            self.limits,
            socket_provider,
            self.vsock,
            Arc::new(UserlandRandomProvider),
            Arc::new(UserlandTimerProvider::new()?),
        )?)
    }
}

#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
fn platform_socket_provider(
    limits: &BrokerCoreLimits,
    host_network: &HostNetworkOptions,
) -> Result<Arc<dyn SocketProvider>, BrokerBuildError> {
    Ok(Arc::new(
        crate::socket::UserlandSocketProvider::with_host_network(
            limits.max_sockets,
            limits.max_sockets_per_process,
            host_network,
        )?,
    ))
}

#[cfg(not(any(target_os = "linux", all(windows, target_arch = "x86_64"))))]
fn platform_socket_provider(
    _limits: &BrokerCoreLimits,
    host_network: &HostNetworkOptions,
) -> Result<Arc<dyn SocketProvider>, BrokerBuildError> {
    if *host_network != HostNetworkOptions::default() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "this host has no socket provider to publish TCP ports or select a network",
        )
        .into());
    }
    Ok(Arc::new(
        litebox_broker_core::socket::UnsupportedSocketProvider,
    ))
}
