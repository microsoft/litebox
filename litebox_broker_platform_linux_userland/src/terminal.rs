// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux host terminal transport.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Mutex;
use std::time::Duration;

use litebox_broker_core::terminal::{TerminalTransport, TerminalTransportError};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::terminal::WindowSize;
use rustix::event::{EventfdFlags, PollFd, PollFlags, Timespec};
use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::Errno;
use rustix::termios::{OptionalActions, QueueSelector, Termios, Winsize};

/// Opens this process's controlling terminal in raw mode for the guest,
/// returning it with whether each of standard input, output, and error, in
/// that order, refers to it.
///
/// Returns `None` unless the terminal is this process's to emulate alone:
/// this process must be verifiably in the terminal's foreground process
/// group, which a shell gives the job it runs in the foreground, and no
/// standard stream may be a pipe or socket, since every member of a shell
/// pipeline has one. A process without a controlling terminal, such as one
/// started by `setsid`, has none to open.
pub fn open_controlling_terminal() -> io::Result<Option<(LinuxTerminal, [bool; 3])>> {
    let (stdin, stdout, stderr) = (io::stdin(), io::stdout(), io::stderr());
    let mut views = [false; 3];
    for (view, fd) in views
        .iter_mut()
        .zip([stdin.as_fd(), stdout.as_fd(), stderr.as_fd()])
    {
        let status = match rustix::fs::fstat(fd) {
            Ok(status) => status,
            Err(Errno::BADF) => continue,
            Err(error) => return Err(error.into()),
        };
        match FileType::from_raw_mode(status.st_mode) {
            FileType::Fifo | FileType::Socket => return Ok(None),
            FileType::CharacterDevice => *view = is_controlling_terminal(fd, status.st_rdev),
            _ => {}
        }
    }
    // Opened only now, since a closed standard stream's descriptor could
    // otherwise come to refer to it.
    let file = match rustix::fs::open(
        "/dev/tty",
        OFlags::RDWR | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => file,
        Err(Errno::NXIO) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let foreground = match rustix::termios::tcgetpgrp(&file) {
        Ok(group) => group.as_raw_nonzero().get() == process_group(),
        // The foreground group lies outside this PID namespace, so it cannot
        // be verified to be this process's group.
        Err(Errno::OPNOTSUPP) => false,
        Err(error) => return Err(error.into()),
    };
    if !foreground {
        return Ok(None);
    }
    Ok(Some((LinuxTerminal::new(file)?, views)))
}

/// Whether `fd`, a character device numbered `device`, is this process's
/// controlling terminal, the only terminal whose foreground process group
/// Linux reports to it.
fn is_controlling_terminal(fd: BorrowedFd<'_>, device: u64) -> bool {
    // Except through a PTY master (`/dev/ptmx` or a legacy BSD master), which
    // reports its slave's group without checking.
    let (major, minor) = (rustix::fs::major(device), rustix::fs::minor(device));
    let master = (major, minor) == (5, 2) || major == 2;
    !master
        && matches!(
            rustix::termios::tcgetpgrp(fd),
            Ok(_) | Err(Errno::OPNOTSUPP)
        )
}

/// This process's group ID, or 0, which matches no foreground group, if the
/// group lies outside this process's PID namespace, as under
/// `unshare --pid --fork`. Rustix's nonzero `Pid` cannot represent the latter.
fn process_group() -> libc::pid_t {
    // SAFETY: getpgrp has no preconditions and cannot fail.
    unsafe { libc::getpgrp() }
}

/// A Linux host terminal in raw mode.
///
/// Dropping the transport restores the terminal's original attributes if
/// [`restore`](TerminalTransport::restore) has not already.
pub struct LinuxTerminal {
    file: OwnedFd,
    /// An eventfd that ends `wait`.
    wake: OwnedFd,
    /// Attributes to restore, taken by the first `restore`.
    original: Mutex<Option<Termios>>,
}

impl LinuxTerminal {
    /// Switches the terminal `file` refers to into raw mode. `file` must be
    /// nonblocking and its open file description not shared with other
    /// processes.
    pub fn new(file: OwnedFd) -> io::Result<Self> {
        let original = rustix::termios::tcgetattr(&file)?;
        let wake = rustix::event::eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)?;
        let mut raw = original.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(&file, OptionalActions::Now, &raw)?;
        Ok(Self {
            file,
            wake,
            original: Mutex::new(Some(original)),
        })
    }

    fn error(&self, error: Errno) -> TerminalTransportError {
        match error {
            Errno::AGAIN | Errno::INTR => TerminalTransportError::WouldBlock,
            // Closing a PTY master can race with calls between waits. EIO
            // accompanied by hangup is closure, not failure.
            Errno::IO if self.hung_up() => TerminalTransportError::HungUp,
            error => failed(error),
        }
    }

    fn hung_up(&self) -> bool {
        let mut fds = [PollFd::new(&self.file, PollFlags::empty())];
        let now = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        loop {
            match rustix::event::poll(&mut fds, Some(&now)) {
                Ok(_) => return fds[0].revents().intersects(PollFlags::HUP | PollFlags::ERR),
                Err(Errno::INTR) => {}
                Err(_) => return false,
            }
        }
    }
}

fn failed(error: Errno) -> TerminalTransportError {
    TerminalTransportError::Failed(Box::new(io::Error::from(error)))
}

impl TerminalTransport for LinuxTerminal {
    fn read(&self, buffer: &mut [u8]) -> Result<usize, TerminalTransportError> {
        rustix::io::read(&self.file, buffer).map_err(|error| self.error(error))
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, TerminalTransportError> {
        rustix::io::write(&self.file, buffer).map_err(|error| self.error(error))
    }

    fn wait(
        &self,
        interest: ReadinessFlags,
        timeout: Option<Duration>,
    ) -> Result<ReadinessFlags, TerminalTransportError> {
        let timeout = timeout
            .map(Timespec::try_from)
            .transpose()
            .map_err(|error| TerminalTransportError::Failed(Box::new(error)))?;
        let mut events = PollFlags::empty();
        if interest.contains(ReadinessFlags::READ) {
            events |= PollFlags::IN;
        }
        if interest.contains(ReadinessFlags::WRITE) {
            events |= PollFlags::OUT;
        }
        // Linux reports hangup without being asked, and a hung-up terminal
        // stays hung up, so an empty interest must not poll the terminal.
        let watched = if interest == ReadinessFlags::default() {
            1
        } else {
            2
        };
        let mut fds = [
            PollFd::new(&self.wake, PollFlags::IN),
            PollFd::new(&self.file, events),
        ];
        match rustix::event::poll(&mut fds[..watched], timeout.as_ref()) {
            Ok(_) => {}
            Err(Errno::INTR) => return Ok(ReadinessFlags::default()),
            Err(error) => return Err(failed(error)),
        }
        if fds[0].revents().contains(PollFlags::IN) {
            match rustix::io::read(&self.wake, &mut [0; 8]) {
                Ok(_) | Err(Errno::AGAIN) => {}
                Err(error) => return Err(failed(error)),
            }
        }
        let mut ready = ReadinessFlags::default();
        if watched == 2 {
            let revents = fds[1].revents();
            if revents.contains(PollFlags::NVAL) {
                return Err(TerminalTransportError::Failed(
                    "terminal descriptor became invalid".into(),
                ));
            }
            if revents.intersects(PollFlags::HUP | PollFlags::ERR) {
                ready = ready | ReadinessFlags::HANGUP;
            }
            if revents.contains(PollFlags::IN) {
                ready = ready | ReadinessFlags::READ;
            }
            if revents.contains(PollFlags::OUT) {
                ready = ready | ReadinessFlags::WRITE;
            }
        }
        Ok(ready)
    }

    fn wake(&self) -> Result<(), TerminalTransportError> {
        match rustix::io::write(&self.wake, &1u64.to_ne_bytes()) {
            // A saturated counter already wakes the waiter.
            Ok(_) | Err(Errno::AGAIN) => Ok(()),
            Err(error) => Err(failed(error)),
        }
    }

    fn get_window_size(&self) -> Result<WindowSize, TerminalTransportError> {
        let size = rustix::termios::tcgetwinsize(&self.file).map_err(|error| self.error(error))?;
        Ok(WindowSize {
            rows: size.ws_row,
            columns: size.ws_col,
            x_pixels: size.ws_xpixel,
            y_pixels: size.ws_ypixel,
        })
    }

    fn set_window_size(&self, size: WindowSize) -> Result<(), TerminalTransportError> {
        let size = Winsize {
            ws_row: size.rows,
            ws_col: size.columns,
            ws_xpixel: size.x_pixels,
            ws_ypixel: size.y_pixels,
        };
        rustix::termios::tcsetwinsize(&self.file, size).map_err(|error| self.error(error))
    }

    fn flush(&self, input: bool, output: bool) -> Result<(), TerminalTransportError> {
        let queues = match (input, output) {
            (true, true) => QueueSelector::IOFlush,
            (true, false) => QueueSelector::IFlush,
            (false, true) => QueueSelector::OFlush,
            (false, false) => return Ok(()),
        };
        rustix::termios::tcflush(&self.file, queues).map_err(|error| self.error(error))
    }

    fn drain(&self) -> Result<(), TerminalTransportError> {
        rustix::termios::tcdrain(&self.file).map_err(|error| self.error(error))
    }

    fn restore(&self) -> Result<(), TerminalTransportError> {
        let Some(original) = self
            .original
            .lock()
            .expect("terminal mutex poisoned")
            .take()
        else {
            return Ok(());
        };
        rustix::termios::tcsetattr(&self.file, OptionalActions::Now, &original).map_err(failed)
    }
}

impl Drop for LinuxTerminal {
    fn drop(&mut self) {
        // Owners restore explicitly to observe failures. This covers a
        // transport dropped without that, such as on an early error.
        let _ = self.restore();
    }
}
