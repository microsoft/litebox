// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux raw terminal transport. All line processing lives in the broker core.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;

use litebox_broker_core::readiness::{ReadinessRegistration, ReadinessSource, ReadinessWatchers};
use litebox_broker_core::stdio::StdioProviderError;
use litebox_broker_core::terminal::{TerminalEndpoint, TerminalEngine, TerminalEventSink};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::terminal::{
    ChangeTiming, TerminalError, TerminalEvent, TerminalOperation, TerminalResponse, WindowSize,
};

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
}

impl State {
    fn readiness(&self) -> ReadinessFlags {
        let mut flags = ReadinessFlags::default();
        if self.engine.readable() || self.status != Status::Active {
            flags = flags | ReadinessFlags::READ;
        }
        if self.status != Status::Active
            || self.output.len() <= OUTPUT_CAPACITY - 2 * ATOMIC_WRITE_SIZE
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

    fn publish(&mut self) {
        let flags = self.readiness();
        self.watchers.publish(flags);
    }

    fn hang_up(&mut self) {
        self.status = Status::HungUp;
        self.draining = false;
        self.output.clear();
    }
}

struct Shared {
    file: File,
    wake: File,
    state: Mutex<State>,
    changed: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("terminal mutex poisoned")
    }

    fn wake(&self) {
        match (&self.wake).write(&1u64.to_ne_bytes()) {
            Ok(8) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            result => litebox_util_log::error!(result:? = result; "waking terminal worker failed"),
        }
    }
}

/// One host terminal, shared by all inherited streams referring to it.
pub(crate) struct LinuxTerminal {
    shared: Arc<Shared>,
    original: libc::termios,
    worker: Option<JoinHandle<()>>,
}

impl LinuxTerminal {
    pub(crate) fn open(fd: i32) -> io::Result<Self> {
        // Reopen rather than dup: O_NONBLOCK must not change the parent's
        // inherited open file description.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open(format!("/proc/self/fd/{fd}"))?;
        // SAFETY: zero is a valid initialization for the integer-only termios structure.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: file is live and original is a writable termios.
        if unsafe { libc::tcgetattr(file.as_raw_fd(), &raw mut original) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = original;
        let wake = eventfd()?;
        let size = window_size(&file)?;
        // SAFETY: raw is a valid initialized termios.
        unsafe { libc::cfmakeraw(&raw mut raw) };
        // SAFETY: file is a terminal and raw is valid for tcsetattr.
        if unsafe { libc::tcsetattr(file.as_raw_fd(), libc::TCSANOW, &raw const raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // Construct the restoration guard before any further fallible operation.
        let mut terminal = Self {
            shared: Arc::new(Shared {
                file,
                wake,
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
                }),
                changed: Condvar::new(),
            }),
            original,
            worker: None,
        };
        let shared = Arc::clone(&terminal.shared);
        terminal.worker = Some(
            std::thread::Builder::new()
                .name("litebox-broker-terminal".to_owned())
                .spawn(move || run(&shared))?,
        );
        Ok(terminal)
    }

    pub(crate) fn read(&self, output: &mut [u8]) -> Result<usize, StdioProviderError> {
        let mut state = self.shared.lock();
        if state.status == Status::Failed {
            return Err(StdioProviderError::Failed);
        }
        if let Some(count) = state.engine.read(output) {
            self.shared.wake();
            return Ok(count);
        }
        if state.status == Status::HungUp {
            return Ok(0);
        }
        Err(StdioProviderError::WouldBlock)
    }

    pub(crate) fn write(&self, input: &[u8]) -> Result<usize, StdioProviderError> {
        let mut state = self.shared.lock();
        if state.status != Status::Active {
            return Err(StdioProviderError::Failed);
        }
        let available = (OUTPUT_CAPACITY - state.output.len()) / 2;
        if (available == 0 && !input.is_empty())
            || (input.len() <= ATOMIC_WRITE_SIZE && input.len() > available)
        {
            return Err(StdioProviderError::WouldBlock);
        }
        let (consumed, bytes) = state.engine.output(input, available);
        state.output.extend(bytes);
        state.drained = false;
        self.shared.wake();
        Ok(consumed)
    }

    pub(crate) fn flush(&self) -> io::Result<()> {
        let mut state = self.shared.lock();
        state.draining = true;
        state.drained = false;
        self.shared.wake();
        while !state.drained && state.status == Status::Active {
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
}

impl ReadinessSource for LinuxTerminal {
    fn readiness(&self) -> ReadinessFlags {
        self.shared.lock().readiness()
    }

    fn watch(&self, registration: &ReadinessRegistration) -> litebox_broker_core::Result<()> {
        self.shared.lock().watchers.watch(registration)
    }
}

impl TerminalEndpoint for LinuxTerminal {
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
    ) -> litebox_broker_core::Result<Result<TerminalResponse, TerminalError>> {
        let mut state = self.shared.lock();
        if state.status != Status::Active {
            return Ok(Err(TerminalError::Io));
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
                    return Ok(Err(TerminalError::InvalidSettings));
                }
                if timing == ChangeTiming::AfterOutputAndFlushInput {
                    // SAFETY: the file is a live terminal and TCIFLUSH takes no pointer.
                    if unsafe { libc::tcflush(self.shared.file.as_raw_fd(), libc::TCIFLUSH) } != 0 {
                        return Ok(Err(TerminalError::Io));
                    }
                    state.pending_input.clear();
                    state.engine.flush_input();
                }
                if let Err(error) = state.engine.configure(settings) {
                    return Ok(Err(error));
                }
                TerminalResponse::Done
            }
            TerminalOperation::GetWindowSize => match window_size(&self.shared.file) {
                Ok(size) => TerminalResponse::WindowSize(size),
                Err(_) => return Ok(Err(TerminalError::Io)),
            },
            TerminalOperation::SetWindowSize(size) => {
                let native = libc::winsize {
                    ws_row: size.rows,
                    ws_col: size.columns,
                    ws_xpixel: size.x_pixels,
                    ws_ypixel: size.y_pixels,
                };
                // SAFETY: native is a valid winsize and file is a live terminal.
                if unsafe {
                    libc::ioctl(
                        self.shared.file.as_raw_fd(),
                        libc::TIOCSWINSZ,
                        &raw const native,
                    )
                } != 0
                {
                    return Ok(Err(TerminalError::Io));
                }
                if state.size != size {
                    state.size = size;
                    if let Some(sink) = &state.sink {
                        sink.post(TerminalEvent::Resize);
                    }
                }
                TerminalResponse::Done
            }
            TerminalOperation::Flush { input, output } => {
                if !input && !output {
                    return Ok(Err(TerminalError::InvalidSettings));
                }
                let which = match (input, output) {
                    (true, true) => libc::TCIOFLUSH,
                    (true, false) => libc::TCIFLUSH,
                    _ => libc::TCOFLUSH,
                };
                // SAFETY: file is a live terminal and which is a valid flush selector.
                if unsafe { libc::tcflush(self.shared.file.as_raw_fd(), which) } != 0 {
                    return Ok(Err(TerminalError::Io));
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

impl Drop for LinuxTerminal {
    fn drop(&mut self) {
        self.shared.lock().status = Status::Stopping;
        self.shared.wake();
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            litebox_util_log::error!("terminal worker panicked");
        }
        // SAFETY: this guard owns the live terminal and saved its original attributes.
        if unsafe {
            libc::tcsetattr(
                self.shared.file.as_raw_fd(),
                libc::TCSANOW,
                &raw const self.original,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            litebox_util_log::error!(error:% = error; "restoring host terminal failed");
        }
    }
}

fn eventfd() -> io::Result<File> {
    use std::os::fd::FromRawFd;
    // SAFETY: eventfd takes only scalar arguments.
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: eventfd returned a fresh, owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn window_size(file: &File) -> io::Result<WindowSize> {
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: size is writable storage for the ioctl's winsize result.
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::TIOCGWINSZ, &raw mut size) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(WindowSize {
        rows: size.ws_row,
        columns: size.ws_col,
        x_pixels: size.ws_xpixel,
        y_pixels: size.ws_ypixel,
    })
}

fn run(shared: &Shared) {
    loop {
        let Err(error) = pump(shared) else {
            return;
        };
        if error.raw_os_error() == Some(libc::EIO) {
            // Closing a PTY master can race with geometry, drain, or I/O calls
            // between polls. EIO accompanied by hangup is closure, not failure.
            match transport_hung_up(&shared.file) {
                Ok(true) => {
                    let mut state = shared.lock();
                    if state.status == Status::Stopping {
                        return;
                    }
                    state.hang_up();
                    state.publish();
                    shared.changed.notify_all();
                    continue;
                }
                Ok(false) => {}
                Err(probe_error) => {
                    litebox_util_log::error!(error:% = probe_error; "checking terminal hangup failed");
                }
            }
        }
        litebox_util_log::error!(error:% = error; "terminal transport failed");
        let mut state = shared.lock();
        state.status = Status::Failed;
        state.draining = false;
        state.publish();
        shared.changed.notify_all();
        return;
    }
}

fn transport_hung_up(file: &File) -> io::Result<bool> {
    let mut fd = libc::pollfd {
        fd: file.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    loop {
        // SAFETY: fd is valid storage for one live terminal's poll descriptor.
        if unsafe { libc::poll(&raw mut fd, 1, 0) } >= 0 {
            return Ok(fd.revents & (libc::POLLHUP | libc::POLLERR) != 0);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn pump(shared: &Shared) -> io::Result<()> {
    let mut buffer = [0; 256];
    loop {
        let mut state = shared.lock();
        if state.status == Status::Stopping {
            return Ok(());
        }
        let mut input_overrun = false;
        let mut echo_overrun = false;
        while let Some(byte) = state.pending_input.front().copied() {
            let result = state.engine.receive(&[byte]);
            if result.consumed == 0 {
                break;
            }
            state.pending_input.pop_front();
            input_overrun |= result.input_overrun;
            if result.flush_output {
                state.output.clear();
            }
            // Echo is best-effort under output backpressure, as with a bounded
            // terminal-driver echo buffer. Guest writes are never discarded.
            let available = OUTPUT_CAPACITY - state.output.len();
            if result.echo.len() > available {
                echo_overrun = true;
            }
            state.output.extend(result.echo.into_iter().take(available));
            if !state.output.is_empty() {
                state.drained = false;
            }
            if let Some(sink) = &state.sink {
                for event in result.events {
                    sink.post(event);
                }
            }
            if input_overrun {
                litebox_util_log::warn!("terminal input buffer overrun");
            }
            if echo_overrun {
                litebox_util_log::warn!("terminal echo buffer overrun");
            }
        }
        if state.status == Status::HungUp {
            state.publish();
            shared.changed.notify_all();
            drop(state);
            let mut wake = [libc::pollfd {
                fd: shared.wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            // SAFETY: wake is a valid one-element pollfd array.
            if unsafe { libc::poll(wake.as_mut_ptr(), 1, -1) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let _count = (&shared.wake).read(&mut [0; 8])?;
            continue;
        }
        if state.draining && state.output.is_empty() {
            drop(state);
            // SAFETY: file is a live terminal. Only the transport thread drains
            // it; broker requests remain nonblocking.
            if unsafe { libc::tcdrain(shared.file.as_raw_fd()) } != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::WouldBlock
                    && error.kind() != io::ErrorKind::Interrupted
                {
                    return Err(error);
                }
                state = shared.lock();
            } else {
                state = shared.lock();
                state.drained = state.output.is_empty();
                state.draining = !state.drained;
                shared.changed.notify_all();
            }
        }
        let size = window_size(&shared.file)?;
        if size != state.size {
            state.size = size;
            if let Some(sink) = &state.sink {
                sink.post(TerminalEvent::Resize);
            }
        }
        state.publish();
        let input =
            state.sink.is_some() && state.pending_input.is_empty() && state.engine.accepts_input();
        let output = !state.output.is_empty() && !state.engine.output_stopped();
        drop(state);
        let mut fds = [
            libc::pollfd {
                fd: shared.file.as_raw_fd(),
                events: (if input { libc::POLLIN } else { 0 })
                    | (if output { libc::POLLOUT } else { 0 }),
                revents: 0,
            },
            libc::pollfd {
                fd: shared.wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // A PTY inherited without being our controlling terminal does not send
        // us SIGWINCH. Periodically query its geometry as well as polling I/O.
        // SAFETY: fds is a valid pollfd array for the duration of poll.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, 100) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if fds[1].revents & libc::POLLIN != 0 {
            let _count = (&shared.wake).read(&mut [0; 8])?;
        }
        let mut state = shared.lock();
        if state.status == Status::Stopping {
            return Ok(());
        }
        if fds[0].revents & libc::POLLNVAL != 0 {
            return Err(io::Error::other("terminal descriptor became invalid"));
        }
        if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            state.hang_up();
        }
        if fds[0].revents & libc::POLLIN != 0 && state.pending_input.is_empty() {
            match (&shared.file).read(&mut buffer) {
                Ok(0) => state.hang_up(),
                Ok(count) => state.pending_input.extend(&buffer[..count]),
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        if state.status == Status::Active
            && fds[0].revents & libc::POLLOUT != 0
            && !state.engine.output_stopped()
        {
            let output = state.output.make_contiguous();
            match (&shared.file).write(output) {
                Ok(0) if !output.is_empty() => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "terminal write returned zero",
                    ));
                }
                Ok(count) => {
                    state.output.drain(..count);
                    shared.changed.notify_all();
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        state.publish();
        shared.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd as _;
    use std::time::Duration;

    fn open_terminal() -> (File, LinuxTerminal) {
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
        let terminal = LinuxTerminal::open(slave.as_raw_fd()).unwrap();
        (master, terminal)
    }

    #[test]
    fn terminal_abandoned_drain_does_not_block_other_writers() {
        let (_master, terminal) = open_terminal();
        terminal.shared.lock().engine.receive(b"\x13");
        assert_eq!(terminal.write(b"first"), Ok(5));
        assert_eq!(
            terminal.control(TerminalOperation::Drain),
            Err(litebox_broker_core::BrokerError::WouldBlock)
        );
        assert!(terminal.readiness().contains(ReadinessFlags::WRITE));
        assert_eq!(terminal.write(b"second"), Ok(6));
        terminal.shared.lock().engine.receive(b"\x11");
        terminal.shared.wake();
        terminal.flush().unwrap();
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
        assert_eq!(terminal.read(&mut bytes), Ok(9));
        assert_eq!(&bytes[..9], b"buffered\n");
        assert_eq!(terminal.read(&mut bytes), Ok(5));
        assert_eq!(&bytes[..5], b"tail\n");
        assert_eq!(terminal.read(&mut bytes), Ok(0));
    }
}
