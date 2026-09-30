// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Inherited host standard streams for userland brokers.

use std::collections::VecDeque;
use std::io::{Error as IoError, ErrorKind, Read, Write};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use litebox_broker_core::readiness::{ReadinessRegistration, ReadinessWatchers};
use litebox_broker_core::stdio::{
    StdioOutputStream, StdioProvider, StdioProviderError, StdioStream,
};
use litebox_broker_protocol::readiness::ReadinessFlags;

/// Largest single host standard-input read.
const INPUT_CHUNK_SIZE: usize = 64 * 1024;
/// Accepted output bytes not yet written to the host, beyond which writes
/// would block.
const OUTPUT_CAPACITY: usize = 64 * 1024;

/// Routes standard I/O for the broker's single child runner through inherited
/// streams without blocking broker requests.
///
/// Background threads perform the blocking host I/O and publish readiness as
/// it completes. The input thread reads host standard input only after a read
/// or readiness query finds no buffered input, so the broker never consumes
/// input the guest has not asked for. The output thread writes accepted bytes
/// to the host in order. Both threads start on first use and live for the rest
/// of the process, since a blocked host read cannot be interrupted.
///
/// A broker serving multiple runners will need association-specific stream
/// endpoints instead of sharing process-wide standard streams.
pub struct UserlandStdioProvider {
    input: Arc<Shared<InputState>>,
    output: Arc<Shared<OutputState>>,
}

impl Default for UserlandStdioProvider {
    fn default() -> Self {
        Self::with_host(std::io::stdin(), std::io::stdout(), std::io::stderr())
    }
}

impl UserlandStdioProvider {
    fn with_host(
        stdin: impl Read + Send + 'static,
        stdout: impl Write + Send + 'static,
        stderr: impl Write + Send + 'static,
    ) -> Self {
        Self {
            input: Arc::new(Shared::new(InputState {
                host: Some(Box::new(stdin)),
                data: VecDeque::new(),
                end: None,
                wanted: false,
                watchers: ReadinessWatchers::default(),
            })),
            output: Arc::new(Shared::new(OutputState {
                hosts: Some([Box::new(stdout), Box::new(stderr)]),
                queue: VecDeque::new(),
                queued: 0,
                errors: [None; 2],
                watchers: ReadinessWatchers::default(),
            })),
        }
    }

    /// Blocks until every accepted output byte has been written to the host
    /// or discarded after a host write failure.
    pub fn flush(&self) {
        let mut state = self.output.lock();
        while state.queued != 0 {
            state = self.output.wait(state);
        }
    }

    /// Returns whether a standard-input read would not block, first asking the
    /// input thread for more host input when none is buffered.
    fn poll_input(&self, state: &mut InputState) -> bool {
        if state.data.is_empty() && state.end.is_none() {
            state.wanted = true;
            if let Some(host) = state.host.take() {
                let input = Arc::clone(&self.input);
                let spawned = std::thread::Builder::new()
                    .name("litebox-broker-stdin".to_owned())
                    .spawn(move || read_host_input(&input, host));
                if spawned.is_err() {
                    state.end = Some(Err(StdioProviderError::Failed));
                }
            }
            self.input.changed.notify_all();
        }
        !state.data.is_empty() || state.end.is_some()
    }
}

impl StdioProvider for UserlandStdioProvider {
    fn is_terminal(&self, stream: StdioStream) -> bool {
        use std::io::IsTerminal as _;

        match stream {
            StdioStream::Stdin => std::io::stdin().is_terminal(),
            StdioStream::Stdout => std::io::stdout().is_terminal(),
            StdioStream::Stderr => std::io::stderr().is_terminal(),
        }
    }

    fn read(&self, output: &mut [u8]) -> Result<usize, StdioProviderError> {
        if output.is_empty() {
            return Ok(0);
        }
        let mut state = self.input.lock();
        if !self.poll_input(&mut state) {
            return Err(StdioProviderError::WouldBlock);
        }
        if state.data.is_empty() {
            return state.end.unwrap_or(Ok(())).map(|()| 0);
        }
        let count = output.len().min(state.data.len());
        for (output, input) in output.iter_mut().zip(state.data.drain(..count)) {
            *output = input;
        }
        Ok(count)
    }

    fn write(&self, stream: StdioOutputStream, input: &[u8]) -> Result<usize, StdioProviderError> {
        let index = output_index(stream);
        let mut state = self.output.lock();
        if let Some(error) = state.errors[index] {
            return Err(error);
        }
        if input.is_empty() {
            return Ok(0);
        }
        let count = input.len().min(OUTPUT_CAPACITY - state.queued);
        if count == 0 {
            return Err(StdioProviderError::WouldBlock);
        }
        if let Some(hosts) = state.hosts.take() {
            let output = Arc::clone(&self.output);
            let spawned = std::thread::Builder::new()
                .name("litebox-broker-stdout".to_owned())
                .spawn(move || write_host_output(&output, hosts));
            if spawned.is_err() {
                state.errors = [Some(StdioProviderError::Failed); 2];
                return Err(StdioProviderError::Failed);
            }
        }
        state.queue.push_back((index, input[..count].to_vec()));
        state.queued += count;
        self.output.changed.notify_all();
        Ok(count)
    }

    fn readiness(&self, stream: StdioStream) -> ReadinessFlags {
        let index = match stream {
            StdioStream::Stdin => {
                let mut state = self.input.lock();
                return if self.poll_input(&mut state) {
                    ReadinessFlags::READ
                } else {
                    ReadinessFlags::default()
                };
            }
            StdioStream::Stdout => output_index(StdioOutputStream::Stdout),
            StdioStream::Stderr => output_index(StdioOutputStream::Stderr),
        };
        let state = self.output.lock();
        if state.queued < OUTPUT_CAPACITY || state.errors[index].is_some() {
            ReadinessFlags::WRITE
        } else {
            ReadinessFlags::default()
        }
    }

    fn watch(
        &self,
        stream: StdioStream,
        registration: &ReadinessRegistration,
    ) -> litebox_broker_core::Result<()> {
        match stream {
            StdioStream::Stdin => self.input.lock().watchers.watch(registration),
            StdioStream::Stdout | StdioStream::Stderr => {
                self.output.lock().watchers.watch(registration)
            }
        }
    }
}

struct Shared<State> {
    state: Mutex<State>,
    changed: Condvar,
}

impl<State> Shared<State> {
    fn new(state: State) -> Self {
        Self {
            state: Mutex::new(state),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait<'guard>(&self, guard: MutexGuard<'guard, State>) -> MutexGuard<'guard, State> {
        self.changed
            .wait(guard)
            .unwrap_or_else(PoisonError::into_inner)
    }
}

struct InputState {
    /// Host standard input, until the input thread takes it.
    host: Option<Box<dyn Read + Send>>,
    /// Host input read but not yet delivered.
    data: VecDeque<u8>,
    /// Outcome once host input ends: `Ok` at end-of-file.
    end: Option<Result<(), StdioProviderError>>,
    /// Whether a reader is waiting for the input thread to read more.
    wanted: bool,
    watchers: ReadinessWatchers,
}

struct OutputState {
    /// Host standard output and error, until the output thread takes them.
    hosts: Option<[Box<dyn Write + Send>; 2]>,
    /// Accepted chunks, tagged with their stream index, in write order.
    queue: VecDeque<(usize, Vec<u8>)>,
    /// Accepted bytes not yet written, including the chunk being written.
    queued: usize,
    /// Each stream's first host write failure, which later writes report.
    errors: [Option<StdioProviderError>; 2],
    watchers: ReadinessWatchers,
}

fn read_host_input(input: &Shared<InputState>, mut host: Box<dyn Read + Send>) {
    let mut chunk = vec![0; INPUT_CHUNK_SIZE];
    loop {
        let mut state = input.lock();
        while !state.wanted {
            state = input.wait(state);
        }
        drop(state);
        let result = loop {
            match host.read(&mut chunk) {
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                result => break result,
            }
        };
        let mut state = input.lock();
        state.wanted = false;
        match result {
            Ok(0) => state.end = Some(Ok(())),
            Ok(count) => state.data.extend(&chunk[..count]),
            Err(error) => state.end = Some(Err(map_stdio_error(&error))),
        }
        state.watchers.publish(ReadinessFlags::READ);
        if state.end.is_some() {
            return;
        }
    }
}

fn write_host_output(output: &Shared<OutputState>, mut hosts: [Box<dyn Write + Send>; 2]) {
    loop {
        let mut state = output.lock();
        let (index, chunk) = loop {
            if let Some(entry) = state.queue.pop_front() {
                break entry;
            }
            state = output.wait(state);
        };
        let failed = state.errors[index].is_some();
        drop(state);
        let result = if failed {
            Ok(())
        } else {
            let host = &mut hosts[index];
            host.write_all(&chunk).and_then(|()| host.flush())
        };
        let mut state = output.lock();
        state.queued -= chunk.len();
        if let Err(error) = result {
            state.errors[index] = Some(map_stdio_error(&error));
        }
        output.changed.notify_all();
        state.watchers.publish(ReadinessFlags::WRITE);
    }
}

fn output_index(stream: StdioOutputStream) -> usize {
    match stream {
        StdioOutputStream::Stdout => 0,
        StdioOutputStream::Stderr => 1,
    }
}

fn map_stdio_error(error: &IoError) -> StdioProviderError {
    if error.kind() == ErrorKind::BrokenPipe {
        StdioProviderError::Closed
    } else {
        StdioProviderError::Failed
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Result as IoResult, Write};
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    use litebox_broker_core::stdio::StdioStream;
    use litebox_broker_core::stdio::{StdioOutputStream, StdioProvider, StdioProviderError};
    use litebox_broker_protocol::readiness::ReadinessFlags;

    use super::{OUTPUT_CAPACITY, UserlandStdioProvider};

    const TEST_TIMEOUT: Duration = Duration::from_secs(30);

    /// Host standard input fed by a channel, reaching end-of-file once the
    /// sender drops.
    struct ChannelInput(Receiver<Vec<u8>>);

    impl Read for ChannelInput {
        fn read(&mut self, output: &mut [u8]) -> IoResult<usize> {
            let Ok(input) = self.0.recv() else {
                return Ok(0);
            };
            output[..input.len()].copy_from_slice(&input);
            Ok(input.len())
        }
    }

    /// Host output that records writes to either stream in order once opened.
    #[derive(Clone, Default)]
    struct GatedOutput(Arc<(Mutex<GatedOutputState>, Condvar)>);

    #[derive(Default)]
    struct GatedOutputState {
        open: bool,
        writes: Vec<(StdioOutputStream, Vec<u8>)>,
    }

    impl GatedOutput {
        fn open(&self) {
            self.0.0.lock().unwrap().open = true;
            self.0.1.notify_all();
        }

        fn writes(&self) -> Vec<(StdioOutputStream, Vec<u8>)> {
            self.0.0.lock().unwrap().writes.clone()
        }

        fn stream(&self, stream: StdioOutputStream) -> GatedStream {
            GatedStream {
                output: self.clone(),
                stream,
            }
        }
    }

    struct GatedStream {
        output: GatedOutput,
        stream: StdioOutputStream,
    }

    impl Write for GatedStream {
        fn write(&mut self, input: &[u8]) -> IoResult<usize> {
            let (state, opened) = &*self.output.0;
            let mut state = state.lock().unwrap();
            while !state.open {
                state = opened.wait(state).unwrap();
            }
            state.writes.push((self.stream, input.to_vec()));
            Ok(input.len())
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    struct BrokenOutput;

    impl Write for BrokenOutput {
        fn write(&mut self, _input: &[u8]) -> IoResult<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    fn gated_provider(input: Receiver<Vec<u8>>, output: &GatedOutput) -> UserlandStdioProvider {
        UserlandStdioProvider::with_host(
            ChannelInput(input),
            output.stream(StdioOutputStream::Stdout),
            output.stream(StdioOutputStream::Stderr),
        )
    }

    fn wait_for_readiness(
        provider: &UserlandStdioProvider,
        stream: StdioStream,
        expected: ReadinessFlags,
    ) {
        let deadline = std::time::Instant::now() + TEST_TIMEOUT;
        while provider.readiness(stream) != expected {
            assert!(
                std::time::Instant::now() < deadline,
                "{stream:?} never ready"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn stdin_reads_host_input_on_demand_without_blocking() {
        let (sender, receiver): (Sender<Vec<u8>>, _) = channel();
        let provider = gated_provider(receiver, &GatedOutput::default());
        let mut output = [0; 4];

        assert_eq!(
            provider.read(&mut output),
            Err(StdioProviderError::WouldBlock)
        );
        assert_eq!(
            provider.readiness(StdioStream::Stdin),
            ReadinessFlags::default()
        );
        sender.send(b"hi".to_vec()).unwrap();
        wait_for_readiness(&provider, StdioStream::Stdin, ReadinessFlags::READ);
        assert_eq!(provider.read(&mut output), Ok(2));
        assert_eq!(&output[..2], b"hi");
        assert_eq!(
            provider.read(&mut output),
            Err(StdioProviderError::WouldBlock)
        );

        drop(sender);
        wait_for_readiness(&provider, StdioStream::Stdin, ReadinessFlags::READ);
        assert_eq!(provider.read(&mut output), Ok(0));
    }

    #[test]
    fn output_is_written_in_order_with_bounded_buffering() {
        let (_sender, receiver) = channel();
        let output = GatedOutput::default();
        let provider = gated_provider(receiver, &output);
        let fill = vec![b'x'; OUTPUT_CAPACITY];

        assert_eq!(provider.write(StdioOutputStream::Stdout, b"a"), Ok(1));
        assert_eq!(provider.write(StdioOutputStream::Stderr, b"b"), Ok(1));
        assert_eq!(
            provider.write(StdioOutputStream::Stdout, &fill),
            Ok(OUTPUT_CAPACITY - 2)
        );
        assert_eq!(
            provider.write(StdioOutputStream::Stderr, b"c"),
            Err(StdioProviderError::WouldBlock)
        );
        assert_eq!(
            provider.readiness(StdioStream::Stdout),
            ReadinessFlags::default()
        );

        output.open();
        provider.flush();
        assert_eq!(
            output.writes(),
            [
                (StdioOutputStream::Stdout, b"a".to_vec()),
                (StdioOutputStream::Stderr, b"b".to_vec()),
                (
                    StdioOutputStream::Stdout,
                    fill[..OUTPUT_CAPACITY - 2].to_vec()
                ),
            ]
        );
        assert_eq!(
            provider.readiness(StdioStream::Stderr),
            ReadinessFlags::WRITE
        );
    }

    #[test]
    fn host_write_failures_stick_to_their_stream() {
        let (_sender, receiver) = channel();
        let output = GatedOutput::default();
        output.open();
        let provider = UserlandStdioProvider::with_host(
            ChannelInput(receiver),
            BrokenOutput,
            output.stream(StdioOutputStream::Stderr),
        );

        assert_eq!(provider.write(StdioOutputStream::Stdout, b"a"), Ok(1));
        provider.flush();
        assert_eq!(
            provider.write(StdioOutputStream::Stdout, b"b"),
            Err(StdioProviderError::Closed)
        );
        assert_eq!(
            provider.readiness(StdioStream::Stdout),
            ReadinessFlags::WRITE
        );
        assert_eq!(provider.write(StdioOutputStream::Stderr, b"c"), Ok(1));
        provider.flush();
        assert_eq!(
            output.writes(),
            [(StdioOutputStream::Stderr, b"c".to_vec())]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stdio_devices_publish_host_readiness() {
        use litebox_broker_core::fs::composer::Composer;
        use litebox_broker_core::fs::devices::Devices;
        use litebox_broker_core::fs::in_mem::InMem;
        use litebox_broker_core::fs::resolver::Resolver;
        use litebox_broker_core::readiness::ReadinessSink;
        use litebox_broker_core::test_support::TestBrokerCoreBuilder;
        use litebox_broker_core::{BrokerError, CallerCredential, ObjectRights, PolicyEngine};
        use litebox_broker_platform_linux_userland::LinuxSyncPrimitivesProvider;
        use litebox_broker_protocol::ObjectHandle;
        use litebox_broker_protocol::fs::{FileAccessMode, FileMode, FileOpenFlags, FileUser};

        struct ChannelReadinessSink(Mutex<Sender<(ObjectHandle, ReadinessFlags)>>);

        impl ReadinessSink for ChannelReadinessSink {
            fn max_tracked_objects(&self) -> usize {
                8
            }

            fn publish(
                &self,
                handle: ObjectHandle,
                readiness: ReadinessFlags,
            ) -> litebox_broker_core::Result<()> {
                let _ = self.0.lock().unwrap().send((handle, readiness));
                Ok(())
            }

            fn republish(
                &self,
                handle: ObjectHandle,
                readiness: ReadinessFlags,
            ) -> litebox_broker_core::Result<()> {
                self.publish(handle, readiness)
            }

            fn retire(&self, _handle: ObjectHandle) {}
        }

        let (input, receiver) = channel();
        let output = GatedOutput::default();
        let provider = Arc::new(gated_provider(receiver, &output));
        let fs = Composer::builder()
            .mount("/", InMem::<LinuxSyncPrimitivesProvider>::new)
            .mount("/dev", |allocator| {
                Devices::new(
                    allocator,
                    provider.clone(),
                    Arc::new(crate::random::UserlandRandomProvider),
                )
            })
            .build()
            .unwrap();
        let process = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_file_service(Arc::new(Resolver::<LinuxSyncPrimitivesProvider, _>::new(
            fs,
        )))
        .build()
        .unwrap()
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
        let (sender, published) = channel();
        let sink: Arc<dyn ReadinessSink> = Arc::new(ChannelReadinessSink(Mutex::new(sender)));
        let open = |path, access| {
            litebox_broker_core::fs::open(
                &process,
                path,
                FileUser::ROOT,
                access,
                FileOpenFlags::NONE,
                FileMode::default(),
                &sink,
            )
            .unwrap()
            .unwrap()
        };
        let stdin = open("/dev/stdin", FileAccessMode::ReadOnly);
        let stdout = open("/dev/stdout", FileAccessMode::WriteOnly);
        let mut byte = [0];

        assert_eq!(
            litebox_broker_core::fs::read(&process, stdin, &mut byte, None),
            Err(BrokerError::WouldBlock)
        );
        input.send(b"x".to_vec()).unwrap();
        assert_eq!(
            published.recv_timeout(TEST_TIMEOUT),
            Ok((stdin, ReadinessFlags::READ))
        );
        assert_eq!(
            litebox_broker_core::fs::read(&process, stdin, &mut byte, None),
            Ok(Ok(1))
        );
        assert_eq!(&byte, b"x");

        let chunk = [b'y'; 4096];
        let mut written = 0;
        while written < OUTPUT_CAPACITY {
            written += litebox_broker_core::fs::write(&process, stdout, &chunk, None)
                .unwrap()
                .unwrap();
        }
        assert_eq!(
            litebox_broker_core::fs::write(&process, stdout, &chunk, None),
            Err(BrokerError::WouldBlock)
        );
        output.open();
        assert_eq!(
            published.recv_timeout(TEST_TIMEOUT),
            Ok((stdout, ReadinessFlags::WRITE))
        );
        assert!(
            litebox_broker_core::fs::write(&process, stdout, &chunk, None)
                .unwrap()
                .is_ok()
        );
    }
}
