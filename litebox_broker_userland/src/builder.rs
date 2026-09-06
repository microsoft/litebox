// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Structured configuration for constructing a hosted broker core.
//!
//! [`HostedBrokerBuilder`] selects the platform socket provider, the
//! cross-platform getrandom-backed random provider, and the inherited-stdio
//! provider, and applies whatever platform setup a deployment needs before its
//! first association is served (for example, Linux lock-tracing
//! initialization). This is what lets an in-process caller construct the same
//! [`BrokerCore`] the userland broker binary does, from a structured
//! configuration rather than from `CliArgs`.

use std::fmt;
use std::sync::Arc;

use litebox_broker_core::socket::SocketProvider;
use litebox_broker_core::{BrokerCore, BrokerCoreLimits, BrokerError, PolicyEngine};

use crate::random::UserlandRandomProvider;
use crate::stdio::UserlandStdioProvider;

/// Failure constructing a hosted [`BrokerCore`].
///
/// Platform setup, such as creating a socket provider or spawning stdio pump
/// threads, fails with [`std::io::Error`]. A rejected core configuration, such
/// as attempting to construct a second core in one process, fails with
/// [`BrokerError`]. Keeping these distinct lets a caller decide whether a
/// failure is retryable platform trouble or a fixed configuration mistake.
#[derive(Debug)]
#[non_exhaustive]
pub enum HostedBrokerError {
    /// Platform-level setup failed.
    Io(std::io::Error),
    /// The broker core rejected the requested configuration.
    Broker(BrokerError),
}

impl fmt::Display for HostedBrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "hosted broker platform setup failed: {error}"),
            Self::Broker(error) => write!(formatter, "hosted broker core rejected: {error}"),
        }
    }
}

impl std::error::Error for HostedBrokerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Broker(error) => Some(error),
        }
    }
}

impl From<std::io::Error> for HostedBrokerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<BrokerError> for HostedBrokerError {
    fn from(error: BrokerError) -> Self {
        Self::Broker(error)
    }
}

/// Structured configuration for building a hosted [`BrokerCore`].
///
/// This is the in-process equivalent of the userland broker binary's platform
/// setup: it selects the same platform providers and applies the same
/// process-wide platform initialization, so a caller that hosts a broker core
/// directly gets the same behavior a deployment launched through the binary
/// would.
pub struct HostedBrokerBuilder {
    policy: PolicyEngine,
    limits: BrokerCoreLimits,
}

impl HostedBrokerBuilder {
    /// Creates a builder with the given policy and default authority-state
    /// limits.
    #[must_use]
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            policy,
            limits: BrokerCoreLimits::DEFAULT,
        }
    }

    /// Overrides the default authority-state limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: BrokerCoreLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Applies platform setup and constructs the hosted [`BrokerCore`].
    ///
    /// A broker process may construct only one broker core for its process
    /// lifetime; see [`BrokerCore::new_with_limits`].
    pub fn build(self) -> Result<BrokerCore, HostedBrokerError> {
        init_platform();
        let socket_provider = platform_socket_provider(&self.limits)?;
        let broker = BrokerCore::new_with_limits(
            self.policy,
            self.limits,
            socket_provider,
            Arc::new(UserlandRandomProvider),
            Arc::new(UserlandStdioProvider::new()?),
        )?;
        Ok(broker)
    }
}

/// Applies process-wide platform setup shared by every hosted broker core.
///
/// This runs lock tracing initialization on Linux when the `lock_tracing`
/// feature is enabled, so an in-process caller gets the same platform setup
/// the userland broker binary performs before serving associations.
fn init_platform() {
    #[cfg(all(target_os = "linux", feature = "lock_tracing"))]
    {
        static LOCK_TRACING_PLATFORM: litebox_broker_platform_linux_userland::LinuxTimeProvider =
            litebox_broker_platform_linux_userland::LinuxTimeProvider;
        litebox_platform::sync::init_lock_tracing(&LOCK_TRACING_PLATFORM);
    }
}

#[cfg(target_os = "linux")]
fn platform_socket_provider(
    limits: &BrokerCoreLimits,
) -> Result<Arc<dyn SocketProvider>, HostedBrokerError> {
    Ok(Arc::new(
        litebox_broker_platform_linux_userland::LinuxSocketProvider::new(
            limits.max_sockets,
            limits.max_sockets_per_session,
        )?,
    ))
}

// The `Result` return type is infallible on this cfg branch, but it must
// match the fallible Linux branch above since callers are not cfg-gated
// themselves.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
fn platform_socket_provider(
    _limits: &BrokerCoreLimits,
) -> Result<Arc<dyn SocketProvider>, HostedBrokerError> {
    Ok(Arc::new(
        litebox_broker_core::socket::UnsupportedSocketProvider,
    ))
}
