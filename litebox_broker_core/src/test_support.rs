// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Strict default providers for constructing broker cores in tests.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::stdio::{StdioOutputStream, StdioStream};
use spin::Mutex;

use crate::{
    AssociationCancellation, BrokerCore, BrokerCoreLimits, BrokerProcess, CallerCredential,
    PolicyEngine, Result,
    fs::{FileService, UnsupportedFileService},
    random::{RandomProvider, RandomProviderError},
    socket::{SocketProvider, UnsupportedSocketProvider},
    stdio::{StdioProvider, StdioProviderError, UnsupportedStdioProvider},
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

/// Test-only access to low-level broker process construction.
pub trait BrokerCoreTestExt {
    /// Creates a process without allocating its initial thread.
    fn create_test_process(
        &self,
        caller_credential: CallerCredential,
        parent_id: Option<ProcessId>,
    ) -> Result<Arc<BrokerProcess>>;
}

impl BrokerCoreTestExt for BrokerCore {
    fn create_test_process(
        &self,
        caller_credential: CallerCredential,
        parent_id: Option<ProcessId>,
    ) -> Result<Arc<BrokerProcess>> {
        self.create_process(caller_credential, parent_id)
    }
}

struct FailingRandomProvider;

impl RandomProvider for FailingRandomProvider {
    fn fill(&self, _output: &mut [u8]) -> core::result::Result<(), RandomProviderError> {
        Err(RandomProviderError)
    }
}

/// Functional standard-I/O provider for tests.
///
/// Reads drain buffered input, writes and terminal queries are recorded, and
/// reads and writes fail once their association is cancelled.
pub struct TestStdioProvider {
    input: Mutex<VecDeque<u8>>,
    writes: Mutex<Vec<(StdioOutputStream, Vec<u8>)>>,
    terminal_queries: Mutex<Vec<StdioStream>>,
    stdin_terminal: bool,
    stdout_terminal: bool,
    stderr_terminal: bool,
}

impl Default for TestStdioProvider {
    fn default() -> Self {
        Self {
            input: Mutex::new(VecDeque::new()),
            writes: Mutex::new(Vec::new()),
            terminal_queries: Mutex::new(Vec::new()),
            stdin_terminal: false,
            stdout_terminal: false,
            stderr_terminal: false,
        }
    }
}

impl TestStdioProvider {
    /// Marks `stream` as connected to a terminal.
    #[must_use]
    pub const fn with_terminal(mut self, stream: StdioStream) -> Self {
        match stream {
            StdioStream::Stdin => self.stdin_terminal = true,
            StdioStream::Stdout => self.stdout_terminal = true,
            StdioStream::Stderr => self.stderr_terminal = true,
        }
        self
    }

    /// Appends bytes that subsequent standard-input reads will drain.
    pub fn push_input(&self, input: &[u8]) {
        self.input.lock().extend(input.iter().copied());
    }

    /// Returns a snapshot of the recorded standard-output writes.
    pub fn writes(&self) -> Vec<(StdioOutputStream, Vec<u8>)> {
        self.writes.lock().clone()
    }

    /// Returns a snapshot of the recorded terminal queries.
    pub fn terminal_queries(&self) -> Vec<StdioStream> {
        self.terminal_queries.lock().clone()
    }
}

impl StdioProvider for TestStdioProvider {
    fn read(
        &self,
        cancellation: &AssociationCancellation,
        output: &mut [u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        if cancellation.is_cancelled() {
            return Err(StdioProviderError::Closed);
        }
        let mut input = self.input.lock();
        let read = input.len().min(output.len());
        for (destination, source) in output.iter_mut().zip(input.drain(..read)) {
            *destination = source;
        }
        Ok(read)
    }

    fn write(
        &self,
        cancellation: &AssociationCancellation,
        stream: StdioOutputStream,
        input: &[u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        if cancellation.is_cancelled() {
            return Err(StdioProviderError::Closed);
        }
        self.writes.lock().push((stream, input.to_vec()));
        Ok(input.len())
    }

    fn is_terminal(&self, stream: StdioStream) -> core::result::Result<bool, StdioProviderError> {
        self.terminal_queries.lock().push(stream);
        Ok(match stream {
            StdioStream::Stdin => self.stdin_terminal,
            StdioStream::Stdout => self.stdout_terminal,
            StdioStream::Stderr => self.stderr_terminal,
        })
    }
}

/// Standard-I/O provider for tests that only exercise terminal detection.
///
/// Reads and writes panic so tests cannot accidentally use this as a functional
/// standard-I/O implementation.
#[derive(Default)]
pub struct TerminalOnlyStdioProvider {
    stdin_terminal: bool,
    stdout_terminal: bool,
    stderr_terminal: bool,
}

impl TerminalOnlyStdioProvider {
    /// Marks `stream` as connected to a terminal.
    #[must_use]
    pub const fn with_terminal(mut self, stream: StdioStream) -> Self {
        match stream {
            StdioStream::Stdin => self.stdin_terminal = true,
            StdioStream::Stdout => self.stdout_terminal = true,
            StdioStream::Stderr => self.stderr_terminal = true,
        }
        self
    }
}

impl StdioProvider for TerminalOnlyStdioProvider {
    fn read(
        &self,
        _cancellation: &AssociationCancellation,
        _output: &mut [u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        panic!("terminal-only test stdio must not read standard input")
    }

    fn write(
        &self,
        _cancellation: &AssociationCancellation,
        _stream: StdioOutputStream,
        _input: &[u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        panic!("terminal-only test stdio must not write standard output")
    }

    fn is_terminal(&self, stream: StdioStream) -> core::result::Result<bool, StdioProviderError> {
        Ok(match stream {
            StdioStream::Stdin => self.stdin_terminal,
            StdioStream::Stdout => self.stdout_terminal,
            StdioStream::Stderr => self.stderr_terminal,
        })
    }
}
