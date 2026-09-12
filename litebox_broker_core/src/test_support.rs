// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Strict default providers for constructing broker cores in tests.

use alloc::sync::Arc;

use crate::{
    BrokerCore, BrokerCoreLimits, PolicyEngine, Result,
    fs::{FileService, UnsupportedFileService},
    random::{RandomProvider, RandomProviderError},
    socket::{SocketProvider, UnsupportedSocketProvider},
    stdio::{StdioProvider, UnsupportedStdioProvider},
};

/// Builder for a test broker core with strict providers that reject unexpected operations.
pub struct TestBrokerCoreBuilder {
    policy: PolicyEngine,
    limits: BrokerCoreLimits,
    socket_provider: Arc<dyn SocketProvider>,
    random_provider: Arc<dyn RandomProvider>,
    stdio_provider: Arc<dyn StdioProvider>,
    fs: Arc<dyn FileService>,
}

impl TestBrokerCoreBuilder {
    /// Creates a builder with the given policy, default limits, and strict providers.
    #[must_use]
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            policy,
            limits: BrokerCoreLimits::DEFAULT,
            socket_provider: Arc::new(UnsupportedSocketProvider),
            random_provider: Arc::new(FailingRandomProvider),
            stdio_provider: Arc::new(UnsupportedStdioProvider),
            fs: Arc::new(UnsupportedFileService),
        }
    }

    /// Overrides the default authority-state limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: BrokerCoreLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Installs the socket provider used by the test.
    #[must_use]
    pub fn with_socket_provider(mut self, provider: Arc<dyn SocketProvider>) -> Self {
        self.socket_provider = provider;
        self
    }

    /// Installs the random provider used by the test.
    #[must_use]
    pub fn with_random_provider(mut self, provider: Arc<dyn RandomProvider>) -> Self {
        self.random_provider = provider;
        self
    }

    /// Installs the standard-I/O provider used by the test.
    #[must_use]
    pub fn with_stdio_provider(mut self, provider: Arc<dyn StdioProvider>) -> Self {
        self.stdio_provider = provider;
        self
    }

    /// Installs the broker-authoritative file service used by the test.
    #[must_use]
    pub fn with_file_service(mut self, fs: Arc<dyn FileService>) -> Self {
        self.fs = fs;
        self
    }

    /// Constructs the broker core.
    ///
    /// A process may construct only one broker core for its lifetime; test
    /// binaries using this builder must therefore run with process-per-test
    /// isolation.
    pub fn build(self) -> Result<BrokerCore> {
        BrokerCore::new_with_limits(
            self.policy,
            self.limits,
            self.socket_provider,
            self.random_provider,
            self.stdio_provider,
            self.fs,
        )
    }
}

struct FailingRandomProvider;

impl RandomProvider for FailingRandomProvider {
    fn fill(&self, _output: &mut [u8]) -> core::result::Result<(), RandomProviderError> {
        Err(RandomProviderError)
    }
}
