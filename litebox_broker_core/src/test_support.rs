// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Strict default providers for constructing broker cores in tests.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::net::SocketAddrV4;
use core::time::Duration;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::FileError;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{ReceiveFlags, ReceiveFromFlags, SocketOutcome};
use litebox_broker_protocol::terminal::{
    TerminalOperation, TerminalResponse, TerminalSettings, WindowSize,
};
use litebox_platform::buffer::{Buffer, Fault, RawBytes, ReadBuffer, WriteBuffer};
use spin::Mutex;

use crate::{
    BrokerCore, BrokerCoreLimits, BrokerProcess, PolicyEngine, Result,
    fs::{FileResult, FileService, UnsupportedFileService},
    random::{RandomProvider, RandomProviderError},
    readiness::{
        ReadinessRegistration, ReadinessSource, ReadinessWatchers, SharedReadinessWatchers,
    },
    socket::{self, PlatformStreamReceive, SocketProvider, UnsupportedSocketProvider},
    stdio::{StdioOutputStream, StdioProvider, StdioProviderError, StdioStream},
    terminal::{TerminalEndpoint, TerminalEventSink},
    timer::{Alarm, TimerProvider, UnsupportedTimerProvider},
    transfer::take_from_queue,
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
/// Reads of empty input report end-of-file unless [`Self::with_open_input`]
/// keeps standard input open.
pub struct TestStdioProvider {
    input: Mutex<TestStdioInput>,
    input_watchers: Mutex<ReadinessWatchers>,
    writes: Mutex<Vec<(StdioOutputStream, Vec<u8>)>>,
    terminal_queries: Mutex<Vec<StdioStream>>,
    stdin_terminal: bool,
    stdout_terminal: bool,
    stderr_terminal: bool,
    uncontrolled_terminal: Option<StdioStream>,
    terminal: Arc<TestTerminal>,
}

impl Default for TestStdioProvider {
    fn default() -> Self {
        Self {
            input: Mutex::new(TestStdioInput {
                bytes: VecDeque::new(),
                open: false,
                blocked_reads: 0,
            }),
            input_watchers: Mutex::new(ReadinessWatchers::default()),
            writes: Mutex::new(Vec::new()),
            terminal_queries: Mutex::new(Vec::new()),
            stdin_terminal: false,
            stdout_terminal: false,
            stderr_terminal: false,
            uncontrolled_terminal: None,
            terminal: Arc::new(TestTerminal(Mutex::new((
                TerminalSettings::default(),
                WindowSize::default(),
            )))),
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

    /// Marks `stream` as connected to a terminal without an endpoint, like a
    /// host terminal the provider cannot take over.
    #[must_use]
    pub const fn with_uncontrolled_terminal(mut self, stream: StdioStream) -> Self {
        self.uncontrolled_terminal = Some(stream);
        self.with_terminal(stream)
    }

    /// Keeps standard input open, so reads of empty input fail with
    /// [`StdioProviderError::WouldBlock`] until [`Self::close_input`].
    #[must_use]
    pub fn with_open_input(self) -> Self {
        self.input.lock().open = true;
        self
    }

    /// Appends bytes that subsequent standard-input reads will drain.
    pub fn push_input(&self, input: &[u8]) {
        self.input.lock().bytes.extend(input.iter().copied());
        self.input_watchers.lock().publish(ReadinessFlags::READ);
    }

    /// Closes standard input, so reads report end-of-file once buffered input
    /// drains.
    pub fn close_input(&self) {
        self.input.lock().open = false;
        self.input_watchers.lock().publish(ReadinessFlags::READ);
    }

    /// Returns how many standard-input reads have failed with
    /// [`StdioProviderError::WouldBlock`].
    ///
    /// A waiting reader reads again after it starts listening for input, so a
    /// test that waits for this count to advance before pushing input or
    /// interrupting the reader does not depend on timing.
    pub fn blocked_input_reads(&self) -> usize {
        self.input.lock().blocked_reads
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
    fn terminal(&self, stream: StdioStream) -> Option<Arc<dyn TerminalEndpoint>> {
        let connected = match stream {
            StdioStream::Stdin => self.stdin_terminal,
            StdioStream::Stdout => self.stdout_terminal,
            StdioStream::Stderr => self.stderr_terminal,
        } && self.uncontrolled_terminal != Some(stream);
        connected.then(|| Arc::clone(&self.terminal) as Arc<dyn TerminalEndpoint>)
    }

    fn read(&self, output: &mut dyn ReadBuffer) -> core::result::Result<usize, StdioProviderError> {
        let mut input = self.input.lock();
        if input.bytes.is_empty() && input.open {
            input.blocked_reads += 1;
            return Err(StdioProviderError::WouldBlock);
        }
        let read = input.bytes.len().min(output.len());
        take_from_queue(&mut input.bytes, read, output)?;
        Ok(read)
    }

    fn write(
        &self,
        stream: StdioOutputStream,
        input: &dyn WriteBuffer,
    ) -> core::result::Result<usize, StdioProviderError> {
        let mut data = alloc::vec![0; input.len()];
        input.copy_to_slice_at(0, &mut data)?;
        self.writes.lock().push((stream, data));
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

    fn readiness(&self, stream: StdioStream) -> ReadinessFlags {
        match stream {
            StdioStream::Stdin => {
                let input = self.input.lock();
                if input.bytes.is_empty() && input.open {
                    ReadinessFlags::default()
                } else {
                    ReadinessFlags::READ
                }
            }
            StdioStream::Stdout | StdioStream::Stderr => ReadinessFlags::WRITE,
        }
    }

    fn watch(&self, stream: StdioStream, registration: &ReadinessRegistration) -> Result<()> {
        match stream {
            StdioStream::Stdin => self.input_watchers.lock().watch(registration),
            StdioStream::Stdout | StdioStream::Stderr => Ok(()),
        }
    }
}

struct TestStdioInput {
    bytes: VecDeque<u8>,
    open: bool,
    blocked_reads: usize,
}

struct TestTerminal(Mutex<(TerminalSettings, WindowSize)>);

impl ReadinessSource for TestTerminal {
    fn readiness(&self) -> ReadinessFlags {
        ReadinessFlags::WRITE
    }
    fn watch(&self, _registration: &ReadinessRegistration) -> Result<()> {
        Ok(())
    }
}

impl TerminalEndpoint for TestTerminal {
    fn attach(&self, _sink: Arc<dyn TerminalEventSink>) {}

    fn control(&self, operation: TerminalOperation) -> Result<FileResult<TerminalResponse>> {
        let mut state = self.0.lock();
        Ok(Ok(match operation {
            TerminalOperation::GetSettings => TerminalResponse::Settings(state.0),
            TerminalOperation::SetSettings { settings, .. } => {
                if settings.minimum_read > 1 {
                    return Ok(Err(FileError::InvalidTerminalControl));
                }
                state.0 = settings;
                TerminalResponse::Done
            }
            TerminalOperation::GetWindowSize => TerminalResponse::WindowSize(state.1),
            TerminalOperation::SetWindowSize(size) => {
                state.1 = size;
                TerminalResponse::Done
            }
            TerminalOperation::Flush { .. } | TerminalOperation::Drain => TerminalResponse::Done,
        }))
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
    alarms: BTreeMap<u64, (Option<Duration>, SharedReadinessWatchers)>,
}

impl ManualTimerProvider {
    /// Advances the clock by `duration` and fires every alarm whose deadline
    /// passed.
    pub fn advance(&self, duration: Duration) {
        let fired: Vec<SharedReadinessWatchers> = {
            let mut state = self.state.lock();
            state.now = state.now.saturating_add(duration);
            let now = state.now;
            state
                .alarms
                .values_mut()
                .filter(|(deadline, _)| deadline.is_some_and(|deadline| deadline <= now))
                .map(|(deadline, watchers)| {
                    *deadline = None;
                    watchers.clone()
                })
                .collect()
        };
        for watchers in fired {
            watchers.publish(ReadinessFlags::READ);
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

    fn create_alarm(&self, watchers: SharedReadinessWatchers) -> Result<Box<dyn Alarm>> {
        let mut state = self.state.lock();
        let id = state.next_alarm;
        state.next_alarm += 1;
        state.alarms.insert(id, (None, watchers));
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
        self.state.lock().alarms.remove(&self.id);
    }
}

/// A buffer of `length` bytes whose copies fault from `fault_at` on, and
/// otherwise copy nothing.
#[derive(Clone, Copy, Debug)]
pub struct FaultingBuffer {
    length: usize,
    fault_at: usize,
}

impl FaultingBuffer {
    /// Creates a buffer of `length` bytes whose copies fault from `fault_at`
    /// on.
    pub const fn new(length: usize, fault_at: usize) -> Self {
        Self { length, fault_at }
    }

    /// Checks a copy of `length` bytes at `offset`.
    ///
    /// # Panics
    ///
    /// Panics if the copy is out of bounds, as for any buffer.
    fn check(&self, offset: usize, length: usize) -> core::result::Result<(), Fault> {
        let end = offset.checked_add(length).unwrap();
        assert!(end <= self.length, "copy out of bounds");
        if end > self.fault_at {
            return Err(Fault);
        }
        Ok(())
    }
}

impl Buffer for FaultingBuffer {
    fn len(&self) -> usize {
        self.length
    }
}

impl ReadBuffer for FaultingBuffer {
    fn copy_from_slice_at(
        &mut self,
        offset: usize,
        source: &[u8],
    ) -> core::result::Result<(), Fault> {
        self.check(offset, source.len())
    }

    fn copy_from_raw_at(
        &mut self,
        offset: usize,
        source: RawBytes<'_>,
    ) -> core::result::Result<(), Fault> {
        self.check(offset, source.len())
    }
}

impl WriteBuffer for FaultingBuffer {
    fn copy_to_slice_at(
        &self,
        offset: usize,
        destination: &mut [u8],
    ) -> core::result::Result<(), Fault> {
        self.check(offset, destination.len())
    }

    fn copy_to_raw_at(
        &self,
        offset: usize,
        destination: RawBytes<'_>,
    ) -> core::result::Result<(), Fault> {
        self.check(offset, destination.len())
    }
}

/// A stream receive's result, with the bytes received.
#[derive(Debug, PartialEq, Eq)]
pub enum StreamData {
    /// The bytes received.
    Received(Vec<u8>),
    /// The peer finished sending.
    EndOfStream,
}

/// Receives up to `length` bytes with [`socket::receive`] into a new vector.
pub fn receive_data(
    process: &BrokerProcess,
    handle: ObjectHandle,
    length: usize,
    flags: ReceiveFlags,
    peek_offset: u32,
    peek_length: u32,
) -> Result<SocketOutcome<StreamData>> {
    let mut data = alloc::vec![0; length];
    let outcome = socket::receive(process, handle, &mut data, flags, peek_offset, peek_length)?;
    Ok(match outcome {
        SocketOutcome::Completed(PlatformStreamReceive::Received(received)) => {
            data.truncate(received);
            SocketOutcome::Completed(StreamData::Received(data))
        }
        SocketOutcome::Completed(PlatformStreamReceive::EndOfStream) => {
            SocketOutcome::Completed(StreamData::EndOfStream)
        }
        SocketOutcome::Failed(error) => SocketOutcome::Failed(error),
    })
}

/// A datagram receive's result, with the bytes received.
#[derive(Debug, PartialEq, Eq)]
pub struct DatagramData {
    /// The bytes received, at most the length requested.
    pub data: Vec<u8>,
    /// The datagram's full length.
    pub datagram_length: usize,
    /// Where the datagram came from.
    pub source_address: SocketAddrV4,
}

/// Receives up to `length` bytes with [`socket::receive_from`] into a new
/// vector.
pub fn receive_data_from(
    process: &BrokerProcess,
    handle: ObjectHandle,
    length: usize,
    flags: ReceiveFromFlags,
) -> Result<SocketOutcome<DatagramData>> {
    let mut data = alloc::vec![0; length];
    let outcome = socket::receive_from(process, handle, &mut data, flags)?;
    Ok(match outcome {
        SocketOutcome::Completed(received) => {
            data.truncate(received.received);
            SocketOutcome::Completed(DatagramData {
                data,
                datagram_length: received.datagram_length,
                source_address: received.source_address,
            })
        }
        SocketOutcome::Failed(error) => SocketOutcome::Failed(error),
    })
}
