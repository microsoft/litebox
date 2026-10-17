// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker terminal endpoints over raw host terminal transports.
//!
//! The broker core's engine does all line processing and a platform
//! [`TerminalTransport`] does all host I/O. A worker thread per terminal moves
//! bytes between them, so broker requests never block on the host.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use litebox_broker_core::fs::FileResult;
use litebox_broker_core::readiness::{ReadinessRegistration, ReadinessSource, ReadinessWatchers};
use litebox_broker_core::stdio::StdioProviderError;
use litebox_broker_core::terminal::{
    TerminalEndpoint, TerminalEngine, TerminalEventSink, TerminalTransport, TerminalTransportError,
};
use litebox_broker_core::transfer::{Copier, Filler, bounce_buffer};
use litebox_broker_protocol::fs::FileError;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::terminal::{
    ChangeTiming, TerminalEvents, TerminalOperation, TerminalResponse, WindowSize,
};

/// How often the worker rechecks the window size. Hosts need not report
/// resizes; Linux, for one, signals them only to the terminal's foreground
/// process group.
const RESIZE_POLL_INTERVAL: Duration = Duration::from_millis(100);

const OUTPUT_CAPACITY: usize = 64 * 1024;
const ATOMIC_WRITE_SIZE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Active,
    HungUp,
    Failed,
    Stopping,
}

struct State {
    engine: TerminalEngine,
    output: VecDeque<u8>,
    pending_input: VecDeque<u8>,
    watchers: ReadinessWatchers,
    sink: Option<Arc<dyn TerminalEventSink>>,
    size: WindowSize,
    status: Status,
    draining: bool,
    drained: bool,
    /// The readiness flags last published.
    published: ReadinessFlags,
}

impl State {
    fn readiness(&self) -> ReadinessFlags {
        let mut flags = ReadinessFlags::default();
        if self.engine.readable() || self.status != Status::Active {
            flags = flags | ReadinessFlags::READ;
        }
        if self.status != Status::Active
            || self.output.len()
                <= OUTPUT_CAPACITY - self.engine.output_expansion() * ATOMIC_WRITE_SIZE
        {
            flags = flags | ReadinessFlags::WRITE;
        }
        if self.status == Status::HungUp {
            flags = flags | ReadinessFlags::HANGUP | ReadinessFlags::CLOSED;
        }
        if self.status == Status::Failed {
            flags = flags | ReadinessFlags::ERROR;
        }
        flags
    }

    /// Wakes every watcher, even if the readiness flags are unchanged.
    fn publish(&mut self) {
        self.published = self.readiness();
        self.watchers.publish(self.published);
    }

    /// Publishes the readiness flags if they changed, so the worker's periodic
    /// resize checks do not wake watchers, including edge-triggered readiness
    /// queue entries. Guest reads and writes publish too, so a later return to
    /// the published flags is not mistaken for no change.
    fn publish_if_changed(&mut self) {
        let flags = self.readiness();
        if flags != self.published {
            self.published = flags;
            self.watchers.publish_if_changed(flags);
        }
    }

    /// Processes pending input and returns whether it discarded pending output,
    /// which the host may also be holding.
    fn process_input(&mut self) -> bool {
        let mut echo_overrun = false;
        let mut flushed = false;
        while let Some(byte) = self.pending_input.front().copied() {
            let result = self.engine.receive(&[byte]);
            if result.consumed == 0 {
                break;
            }
            self.pending_input.pop_front();
            if result.flush_output {
                self.output.clear();
                flushed = true;
            }
            // Echo is best-effort under output backpressure, as with a bounded
            // terminal-driver echo buffer. Guest writes are never discarded.
            let available = OUTPUT_CAPACITY - self.output.len();
            if result.echo.len() > available {
                echo_overrun = true;
            }
            self.output.extend(result.echo.into_iter().take(available));
            if !self.output.is_empty() {
                self.drained = false;
            }
            if let Some(sink) = &self.sink
                && !result.events.is_empty()
            {
                sink.post(result.events);
            }
        }
        if echo_overrun {
            litebox_util_log::warn!("terminal echo buffer overrun");
        }
        flushed
    }

    fn hang_up(&mut self) {
        self.status = Status::HungUp;
        self.draining = false;
        self.output.clear();
    }
}

struct Shared {
    transport: Arc<dyn TerminalTransport>,
    state: Mutex<State>,
    changed: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("terminal mutex poisoned")
    }

    fn wake(&self) {
        if let Err(error) = self.transport.wake() {
            litebox_util_log::error!(error:% = error; "waking terminal worker failed");
        }
    }

    /// Runs the worker until the terminal stops or its transport fails.
    fn run(&self) {
        loop {
            let error = match self.pump() {
                Ok(()) => return,
                Err(TerminalTransportError::WouldBlock) => continue,
                Err(TerminalTransportError::HungUp) => {
                    let mut state = self.lock();
                    if state.status == Status::Stopping {
                        return;
                    }
                    state.hang_up();
                    state.publish();
                    self.changed.notify_all();
                    continue;
                }
                Err(error) => error,
            };
            litebox_util_log::error!(error:% = error; "terminal transport failed");
            let mut state = self.lock();
            state.status = Status::Failed;
            state.draining = false;
            state.publish();
            self.changed.notify_all();
            return;
        }
    }

    /// Moves bytes between the engine and the transport until the terminal
    /// stops or the transport returns an error.
    fn pump(&self) -> Result<(), TerminalTransportError> {
        let transport = &*self.transport;
        let mut buffer = [0; 256];
        loop {
            let mut state = self.lock();
            if state.status == Status::Stopping {
                return Ok(());
            }
            // Also discard output the host has yet to send. Echo of the
            // processed input is still queued here, so it survives.
            if state.process_input() && state.status == Status::Active {
                transport.flush(false, true)?;
            }
            if state.status == Status::HungUp {
                state.publish_if_changed();
                self.changed.notify_all();
                drop(state);
                transport.wait(ReadinessFlags::default(), None)?;
                continue;
            }
            if state.draining && state.output.is_empty() {
                drop(state);
                // Only this worker drains the host terminal; broker requests
                // remain nonblocking.
                let drained = match transport.drain() {
                    Ok(()) => true,
                    Err(TerminalTransportError::WouldBlock) => false,
                    Err(error) => return Err(error),
                };
                state = self.lock();
                if drained {
                    state.drained = state.output.is_empty();
                    state.draining = !state.drained;
                    if state.drained {
                        // Draining waiters wait for writability, which was
                        // already published.
                        state.publish();
                    }
                    self.changed.notify_all();
                }
            }
            let size = transport.get_window_size()?;
            if size != state.size {
                state.size = size;
                if let Some(sink) = &state.sink {
                    sink.post(TerminalEvents::RESIZE);
                }
            }
            state.publish_if_changed();
            let mut interest = ReadinessFlags::HANGUP;
            if state.sink.is_some()
                && state.pending_input.is_empty()
                && state.engine.accepts_input()
            {
                interest = interest | ReadinessFlags::READ;
            }
            if !state.output.is_empty() && !state.engine.output_stopped() {
                interest = interest | ReadinessFlags::WRITE;
            }
            drop(state);
            let ready = transport.wait(interest, Some(RESIZE_POLL_INTERVAL))?;
            let mut state = self.lock();
            if state.status == Status::Stopping {
                return Ok(());
            }
            if ready.contains(ReadinessFlags::HANGUP) {
                state.hang_up();
            }
            if ready.contains(ReadinessFlags::READ) && state.pending_input.is_empty() {
                match transport.read(&mut buffer) {
                    Ok(0) => state.hang_up(),
                    Ok(count) => state.pending_input.extend(&buffer[..count]),
                    Err(TerminalTransportError::WouldBlock) => {}
                    Err(error) => return Err(error),
                }
            }
            if state.status == Status::Active
                && ready.contains(ReadinessFlags::WRITE)
                && !state.engine.output_stopped()
            {
                let output = state.output.make_contiguous();
                match transport.write(output) {
                    Ok(0) if !output.is_empty() => {
                        return Err(TerminalTransportError::Failed(
                            "terminal write returned zero".into(),
                        ));
                    }
                    Ok(count) => {
                        state.output.drain(..count);
                        self.changed.notify_all();
                    }
                    Err(TerminalTransportError::WouldBlock) => {}
                    Err(error) => return Err(error),
                }
            }
            state.publish_if_changed();
            self.changed.notify_all();
        }
    }
}

/// One host terminal, shared by all inherited streams referring to it.
pub(crate) struct HostTerminal {
    shared: Arc<Shared>,
    /// Set by the first `close`.
    closed: AtomicBool,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl HostTerminal {
    /// Serves the host terminal behind `transport`.
    pub(crate) fn new(transport: Arc<dyn TerminalTransport>) -> io::Result<Self> {
        let size = transport.get_window_size().map_err(io::Error::other)?;
        let shared = Arc::new(Shared {
            transport,
            state: Mutex::new(State {
                engine: TerminalEngine::default(),
                output: VecDeque::new(),
                pending_input: VecDeque::new(),
                watchers: ReadinessWatchers::default(),
                sink: None,
                size,
                status: Status::Active,
                draining: false,
                drained: true,
                published: ReadinessFlags::default(),
            }),
            changed: Condvar::new(),
        });
        let worker = {
            let shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("litebox-broker-terminal".to_owned())
                .spawn(move || shared.run())?
        };
        Ok(Self {
            shared,
            closed: AtomicBool::new(false),
            worker: Mutex::new(Some(worker)),
        })
    }

    pub(crate) fn read(
        &self,
        length: usize,
        copy: &mut Copier<'_>,
    ) -> Result<usize, StdioProviderError> {
        let mut state = self.shared.lock();
        if state.status == Status::Failed {
            return Err(StdioProviderError::Failed);
        }
        if state.status == Status::HungUp {
            state.process_input();
        }
        if let Some(count) = state.engine.read(length, copy)? {
            state.publish_if_changed();
            self.shared.wake();
            return Ok(count);
        }
        if state.status == Status::HungUp {
            return Ok(0);
        }
        Err(StdioProviderError::WouldBlock)
    }

    pub(crate) fn write(
        &self,
        length: usize,
        fill: &mut Filler<'_>,
    ) -> Result<usize, StdioProviderError> {
        let mut state = self.shared.lock();
        if state.status != Status::Active {
            return Err(StdioProviderError::Failed);
        }
        let available = (OUTPUT_CAPACITY - state.output.len()) / state.engine.output_expansion();
        if (available == 0 && length != 0) || (length <= ATOMIC_WRITE_SIZE && length > available) {
            return Err(StdioProviderError::WouldBlock);
        }
        // Output processing rewrites bytes, so stage them first.
        let mut input = bounce_buffer(length.min(available))?;
        fill(&mut input)?;
        let (consumed, bytes) = state.engine.output(&input, available);
        state.output.extend(bytes);
        state.drained = false;
        state.publish_if_changed();
        self.shared.wake();
        Ok(consumed)
    }

    pub(crate) fn flush(&self) -> io::Result<()> {
        let mut state = self.shared.lock();
        state.drained = false;
        while !state.drained && state.status == Status::Active {
            // Output such as echo can follow a completed drain before this
            // thread wakes, so drain again.
            if !state.draining {
                state.draining = true;
                self.shared.wake();
            }
            state = self
                .shared
                .changed
                .wait(state)
                .expect("terminal mutex poisoned");
        }
        if state.status == Status::Active {
            Ok(())
        } else {
            Err(io::Error::other("terminal output failed"))
        }
    }

    /// Drains output, stops the worker, and restores the host terminal. Later
    /// calls do nothing.
    pub(crate) fn close(&self) -> io::Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let flushed = self.flush();
        self.stop();
        flushed
    }

    fn stop(&self) {
        self.shared.lock().status = Status::Stopping;
        self.shared.wake();
        if let Some(worker) = self.worker.lock().expect("terminal mutex poisoned").take()
            && worker.join().is_err()
        {
            litebox_util_log::error!("terminal worker panicked");
        }
        if let Err(error) = self.shared.transport.restore() {
            litebox_util_log::error!(error:% = error; "restoring host terminal failed");
        }
    }
}

impl ReadinessSource for HostTerminal {
    fn readiness(&self) -> ReadinessFlags {
        self.shared.lock().readiness()
    }

    fn watch(&self, registration: &ReadinessRegistration) -> litebox_broker_core::Result<()> {
        self.shared.lock().watchers.watch(registration)
    }
}

impl TerminalEndpoint for HostTerminal {
    fn attach(&self, sink: Arc<dyn TerminalEventSink>) {
        let mut state = self.shared.lock();
        if state.sink.is_none() {
            state.sink = Some(sink);
            self.shared.wake();
        }
    }

    fn control(
        &self,
        operation: TerminalOperation,
    ) -> litebox_broker_core::Result<FileResult<TerminalResponse>> {
        let transport = &*self.shared.transport;
        let mut state = self.shared.lock();
        if state.status != Status::Active {
            return Ok(Err(FileError::Io));
        }
        let drain = matches!(
            operation,
            TerminalOperation::Drain
                | TerminalOperation::SetSettings {
                    timing: ChangeTiming::AfterOutput | ChangeTiming::AfterOutputAndFlushInput,
                    ..
                }
        );
        if drain && !state.drained {
            if !state.draining {
                state.draining = true;
                self.shared.wake();
            }
            return Err(litebox_broker_core::BrokerError::WouldBlock);
        }
        let response = match operation {
            TerminalOperation::GetSettings => TerminalResponse::Settings(state.engine.settings()),
            TerminalOperation::SetSettings { settings, timing } => {
                if settings.minimum_read > 1 {
                    return Ok(Err(FileError::InvalidTerminalControl));
                }
                if timing == ChangeTiming::AfterOutputAndFlushInput {
                    if transport.flush(true, false).is_err() {
                        return Ok(Err(FileError::Io));
                    }
                    state.pending_input.clear();
                    state.engine.flush_input();
                }
                if let Err(error) = state.engine.configure(settings) {
                    return Ok(Err(error));
                }
                TerminalResponse::Done
            }
            TerminalOperation::GetWindowSize => match transport.get_window_size() {
                Ok(size) => TerminalResponse::WindowSize(size),
                Err(_) => return Ok(Err(FileError::Io)),
            },
            TerminalOperation::SetWindowSize(size) => {
                if transport.set_window_size(size).is_err() {
                    return Ok(Err(FileError::Io));
                }
                if state.size != size {
                    state.size = size;
                    if let Some(sink) = &state.sink {
                        sink.post(TerminalEvents::RESIZE);
                    }
                }
                TerminalResponse::Done
            }
            TerminalOperation::Flush { input, output } => {
                if !input && !output {
                    return Ok(Err(FileError::InvalidTerminalControl));
                }
                if transport.flush(input, output).is_err() {
                    return Ok(Err(FileError::Io));
                }
                if input {
                    state.pending_input.clear();
                    state.engine.flush_input();
                }
                if output {
                    state.output.clear();
                    state.draining = false;
                    state.drained = true;
                }
                TerminalResponse::Done
            }
            TerminalOperation::Drain => TerminalResponse::Done,
        };
        state.publish();
        self.shared.changed.notify_all();
        self.shared.wake();
        Ok(Ok(response))
    }
}

impl Drop for HostTerminal {
    fn drop(&mut self) {
        if !*self.closed.get_mut() {
            self.stop();
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use litebox_broker_core::transfer::{copy_to_slice, fill_from_slice};
    use litebox_broker_platform_linux_userland::terminal::LinuxTerminal;
    use std::fs::File;
    use std::os::fd::{AsFd as _, FromRawFd as _};
    use std::time::Duration;

    impl HostTerminal {
        fn read_slice(&self, output: &mut [u8]) -> Result<usize, StdioProviderError> {
            self.read(output.len(), &mut copy_to_slice(output))
        }

        fn write_slice(&self, input: &[u8]) -> Result<usize, StdioProviderError> {
            self.write(input.len(), &mut fill_from_slice(input))
        }
    }

    /// Returns a PTY's master and a terminal served over its slave.
    fn open_terminal() -> (File, HostTerminal) {
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: the descriptors are writable and null optional arguments request defaults.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &raw mut master,
                    &raw mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        // SAFETY: openpty returned fresh descriptors, each transferred to exactly one File.
        let (master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        let transport = LinuxTerminal::open(slave.as_fd()).unwrap();
        let terminal = HostTerminal::new(Arc::new(transport)).unwrap();
        (master, terminal)
    }

    #[test]
    fn terminal_tab_expansion_stays_within_output_capacity() {
        use litebox_broker_protocol::terminal::{OutputFlags, TerminalSettings};

        let (_master, terminal) = open_terminal();
        let mut state = terminal.shared.lock();
        state.engine.receive(b"\x13");
        let settings = state.engine.settings();
        state
            .engine
            .configure(TerminalSettings {
                output: settings.output | OutputFlags::EXPAND_TABS,
                ..settings
            })
            .unwrap();
        state
            .output
            .extend(vec![b'x'; OUTPUT_CAPACITY - 4 * ATOMIC_WRITE_SIZE]);
        drop(state);
        // Writability promises room for a whole atomic write.
        let tabs = vec![b'\t'; OUTPUT_CAPACITY];
        assert!(!terminal.readiness().contains(ReadinessFlags::WRITE));
        assert_eq!(
            terminal.write_slice(&tabs[..ATOMIC_WRITE_SIZE]),
            Err(StdioProviderError::WouldBlock)
        );
        assert!(terminal.write_slice(&tabs).unwrap() > 0);
        assert!(terminal.shared.lock().output.len() <= OUTPUT_CAPACITY);
    }

    #[test]
    fn terminal_abandoned_drain_does_not_block_other_writers() {
        let (_master, terminal) = open_terminal();
        terminal.shared.lock().engine.receive(b"\x13");
        assert_eq!(terminal.write_slice(b"first"), Ok(5));
        assert_eq!(
            terminal.control(TerminalOperation::Drain),
            Err(litebox_broker_core::BrokerError::WouldBlock)
        );
        assert!(terminal.readiness().contains(ReadinessFlags::WRITE));
        assert_eq!(terminal.write_slice(b"second"), Ok(6));
        terminal.shared.lock().engine.receive(b"\x11");
        terminal.shared.wake();
        terminal.flush().unwrap();
    }

    #[test]
    fn terminal_flush_drains_output_queued_after_a_completed_drain() {
        let (_master, terminal) = open_terminal();
        let terminal = Arc::new(terminal);
        terminal.shared.lock().engine.receive(b"\x13");
        assert_eq!(terminal.write_slice(b"output"), Ok(6));
        let (sender, receiver) = std::sync::mpsc::channel();
        let flusher = Arc::clone(&terminal);
        std::thread::spawn(move || sender.send(flusher.flush().is_ok()).unwrap());
        let mut state = terminal.shared.lock();
        while !state.draining {
            drop(state);
            std::thread::sleep(Duration::from_millis(1));
            state = terminal.shared.lock();
        }
        // Act as the worker would after a drain completed just before echo
        // was queued.
        state.draining = false;
        terminal.shared.changed.notify_all();
        state.engine.receive(b"\x11");
        drop(state);
        terminal.shared.wake();
        assert_eq!(receiver.recv_timeout(Duration::from_secs(5)), Ok(true));
    }

    #[test]
    fn terminal_hangup_preserves_buffered_and_pending_input() {
        let (master, terminal) = open_terminal();
        {
            let mut state = terminal.shared.lock();
            state.engine.receive(b"buffered\n");
            state.pending_input.extend(b"tail\n");
            state.output.extend(b"pending output");
            state.drained = false;
            drop(master);
        }
        terminal.shared.wake();
        let (state, timeout) = terminal
            .shared
            .changed
            .wait_timeout_while(terminal.shared.lock(), Duration::from_secs(5), |state| {
                state.status == Status::Active
                    || (state.status == Status::HungUp && !state.pending_input.is_empty())
            })
            .unwrap();
        assert!(!timeout.timed_out());
        assert_eq!(state.status, Status::HungUp);
        assert!(
            state
                .readiness()
                .contains(ReadinessFlags::HANGUP | ReadinessFlags::CLOSED)
        );
        drop(state);
        let mut bytes = [0; 32];
        assert_eq!(terminal.read_slice(&mut bytes), Ok(9));
        assert_eq!(&bytes[..9], b"buffered\n");
        assert_eq!(terminal.read_slice(&mut bytes), Ok(5));
        assert_eq!(&bytes[..5], b"tail\n");
        assert_eq!(terminal.read_slice(&mut bytes), Ok(0));
    }

    #[test]
    fn terminal_hangup_does_not_report_eof_before_a_backpressured_tail() {
        use litebox_broker_protocol::terminal::{InputFlags, LocalFlags, TerminalSettings};

        let (_master, mut terminal) = open_terminal();
        // Keep the worker from winning the race this test exercises.
        terminal.shared.lock().status = Status::Stopping;
        terminal.shared.wake();
        terminal
            .worker
            .get_mut()
            .unwrap()
            .take()
            .unwrap()
            .join()
            .unwrap();
        for minimum_read in [0, 1] {
            let mut state = terminal.shared.lock();
            let settings = TerminalSettings {
                input: InputFlags::empty(),
                local: LocalFlags::empty(),
                minimum_read,
                ..state.engine.settings()
            };
            state.engine.configure(settings).unwrap();
            let prefix = vec![b'x'; state.engine.input_space() - 1];
            assert_eq!(state.engine.receive(&prefix).consumed, prefix.len());
            assert!(!state.engine.accepts_input());
            state.pending_input.extend(b"tail");
            state.hang_up();
            drop(state);
            let mut bytes = vec![0; prefix.len()];
            assert_eq!(terminal.read_slice(&mut bytes), Ok(prefix.len()));
            assert_eq!(bytes, prefix);
            assert_eq!(terminal.read_slice(&mut bytes), Ok(4));
            assert_eq!(&bytes[..4], b"tail");
            assert_eq!(terminal.read_slice(&mut bytes), Ok(0));
        }
    }
}
