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
use std::sync::Arc;

use litebox_broker_core::socket::SocketProvider;
use litebox_broker_core::vsock_socket::VsockProvider;
use litebox_broker_core::{BrokerCore, BrokerCoreLimits, BrokerError, PolicyEngine};
use litebox_broker_protocol::fs::FileUser;

use crate::random::UserlandRandomProvider;
use crate::timer::UserlandTimerProvider;

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

/// The guest user and group that root processes run as unless configured otherwise.
pub const DEFAULT_ROOT_USER: FileUser = FileUser {
    user: 1000,
    group: 1000,
};

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
    root_user: FileUser,
    vsock: Option<Arc<dyn VsockProvider>>,
}

impl BrokerCoreBuilder {
    /// Creates a builder with the given policy, default authority-state
    /// limits, and root processes that run as [`DEFAULT_ROOT_USER`].
    #[must_use]
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            policy,
            limits: BrokerCoreLimits::DEFAULT,
            root_user: DEFAULT_ROOT_USER,
            vsock: None,
        }
    }

    /// Runs root processes, and so their descendants, as `user`.
    #[must_use]
    pub const fn with_root_user(mut self, user: FileUser) -> Self {
        self.root_user = user;
        self
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

        let socket_provider = platform_socket_provider(&self.limits)?;
        Ok(BrokerCore::new(
            self.policy,
            self.limits,
            self.root_user,
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
) -> Result<Arc<dyn SocketProvider>, BrokerBuildError> {
    Ok(Arc::new(crate::socket::UserlandSocketProvider::new(
        limits.max_sockets,
        limits.max_sockets_per_process,
    )?))
}

// The `Result` return type is infallible on this cfg branch, but it must
// match the fallible branch above since callers are not cfg-gated
// themselves.
#[cfg(not(any(target_os = "linux", all(windows, target_arch = "x86_64"))))]
#[allow(clippy::unnecessary_wraps)]
fn platform_socket_provider(
    _limits: &BrokerCoreLimits,
) -> Result<Arc<dyn SocketProvider>, BrokerBuildError> {
    Ok(Arc::new(
        litebox_broker_core::socket::UnsupportedSocketProvider,
    ))
}
