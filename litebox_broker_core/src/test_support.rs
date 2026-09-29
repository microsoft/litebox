// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Strict default providers for constructing broker cores in tests.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use litebox_broker_protocol::readiness::ReadinessFlags;
use spin::Mutex;

use crate::{
    BrokerCore, BrokerCoreLimits, PolicyEngine, Result,
    fs::{FileService, UnsupportedFileService},
    random::{RandomProvider, RandomProviderError},
    readiness::ReadinessRegistration,
    socket::{SocketProvider, UnsupportedSocketProvider},
    stdio::{StdioOutputStream, StdioProvider, StdioProviderError, StdioStream},
    timer::{Alarm, TimerProvider, UnsupportedTimerProvider},
};

/// Builder for a test broker core with strict providers that reject unexpected operations.
pub struct TestBrokerCoreBuilder {
    policy: PolicyEngine,
    limits: BrokerCoreLimits,
    socket_provider: Arc<dyn SocketProvider>,
    random_provider: Arc<dyn RandomProvider>,
    timer_provider: Arc<dyn TimerProvider>,
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
            timer_provider: Arc::new(UnsupportedTimerProvider),
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

    /// Installs the timer provider used by the test.
    #[must_use]
    pub fn with_timer_provider(mut self, provider: Arc<dyn TimerProvider>) -> Self {
        self.timer_provider = provider;
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
            self.timer_provider,
            self.fs,
        )
    }
}

/// Random provider whose fills always fail.
pub struct FailingRandomProvider;

impl RandomProvider for FailingRandomProvider {
    fn fill(&self, _output: &mut [u8]) -> core::result::Result<(), RandomProviderError> {
        Err(RandomProviderError)
    }
}

/// Functional standard-I/O provider for tests.
///
/// Reads drain buffered input, and writes and terminal queries are recorded.
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
    fn read(&self, output: &mut [u8]) -> core::result::Result<usize, StdioProviderError> {
        let mut input = self.input.lock();
        let read = input.len().min(output.len());
        for (destination, source) in output.iter_mut().zip(input.drain(..read)) {
            *destination = source;
        }
        Ok(read)
    }

    fn write(
        &self,
        stream: StdioOutputStream,
        input: &[u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        self.writes.lock().push((stream, input.to_vec()));
        Ok(input.len())
    }

    fn is_terminal(&self, stream: StdioStream) -> bool {
        self.terminal_queries.lock().push(stream);
        match stream {
            StdioStream::Stdin => self.stdin_terminal,
            StdioStream::Stdout => self.stdout_terminal,
            StdioStream::Stderr => self.stderr_terminal,
        }
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
    fn read(&self, _output: &mut [u8]) -> core::result::Result<usize, StdioProviderError> {
        panic!("terminal-only test stdio must not read standard input")
    }

    fn write(
        &self,
        _stream: StdioOutputStream,
        _input: &[u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        panic!("terminal-only test stdio must not write standard output")
    }

    fn is_terminal(&self, stream: StdioStream) -> bool {
        match stream {
            StdioStream::Stdin => self.stdin_terminal,
            StdioStream::Stdout => self.stdout_terminal,
            StdioStream::Stderr => self.stderr_terminal,
        }
    }
}

/// Timer provider for tests whose clock advances only through
/// [`Self::advance`].
#[derive(Default)]
pub struct ManualTimerProvider {
    state: Arc<Mutex<ManualTimerState>>,
}

#[derive(Default)]
struct ManualTimerState {
    now: Duration,
    next_alarm: u64,
    alarms: BTreeMap<u64, (Option<Duration>, ReadinessRegistration)>,
}

impl ManualTimerProvider {
    /// Advances the clock by `duration` and fires every alarm whose deadline
    /// passed.
    pub fn advance(&self, duration: Duration) {
        let fired: Vec<ReadinessRegistration> = {
            let mut state = self.state.lock();
            state.now = state.now.saturating_add(duration);
            let now = state.now;
            state
                .alarms
                .values_mut()
                .filter(|(deadline, _)| deadline.is_some_and(|deadline| deadline <= now))
                .map(|(deadline, readiness)| {
                    *deadline = None;
                    readiness.clone()
                })
                .collect()
        };
        for readiness in fired {
            let _ = readiness.republish(ReadinessFlags::READ);
        }
    }

    /// Returns the number of live alarms.
    pub fn alarm_count(&self) -> usize {
        self.state.lock().alarms.len()
    }
}

impl TimerProvider for ManualTimerProvider {
    fn now(&self) -> Duration {
        self.state.lock().now
    }

    fn create_alarm(&self, readiness: ReadinessRegistration) -> Result<Box<dyn Alarm>> {
        let mut state = self.state.lock();
        let id = state.next_alarm;
        state.next_alarm += 1;
        state.alarms.insert(id, (None, readiness));
        Ok(Box::new(ManualAlarm {
            state: Arc::clone(&self.state),
            id,
        }))
    }
}

struct ManualAlarm {
    state: Arc<Mutex<ManualTimerState>>,
    id: u64,
}

impl Alarm for ManualAlarm {
    fn set(&self, deadline: Option<Duration>) {
        if let Some(alarm) = self.state.lock().alarms.get_mut(&self.id) {
            alarm.0 = deadline;
        }
    }
}

impl Drop for ManualAlarm {
    fn drop(&mut self) {
        // Release the registration after unlocking, since dropping it may retire.
        let alarm = self.state.lock().alarms.remove(&self.id);
        drop(alarm);
    }
}
