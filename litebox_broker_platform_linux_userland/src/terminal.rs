// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux host terminal transport.

use std::ffi::c_uint;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use litebox_broker_core::terminal::{TerminalTransport, TerminalTransportError};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::terminal::WindowSize;
use rustix::event::{EventfdFlags, PollFd, PollFlags, Timespec};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use rustix::termios::{OptionalActions, QueueSelector, Termios, Winsize};

/// Identifies a terminal: its device number and, unless it is the caller's
/// controlling terminal, the filesystem holding its device node, since
/// separate devpts instances may reuse device numbers.
type Identity = (c_uint, Option<u64>);

/// Opens the host terminals behind the inherited standard input, output, and
/// error, in that order. Redirected streams yield `None`, and streams referring
/// to the same terminal share one transport.
pub fn open_stdio_terminals() -> io::Result<[Option<Arc<LinuxTerminal>>; 3]> {
    let (stdin, stdout, stderr) = (io::stdin(), io::stdout(), io::stderr());
    let mut terminals: [Option<(Identity, Arc<LinuxTerminal>)>; 3] = Default::default();
    for (index, fd) in [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()]
        .into_iter()
        .enumerate()
    {
        if !rustix::termios::isatty(fd) {
            continue;
        }
        let identity = identity(fd)?;
        // Opening one terminal twice would save its raw attributes as the
        // original ones.
        let existing = terminals[..index]
            .iter()
            .flatten()
            .find(|(other, _)| *other == identity)
            .map(|(_, terminal)| Arc::clone(terminal));
        let terminal = match existing {
            Some(terminal) => terminal,
            None => Arc::new(LinuxTerminal::open(fd)?),
        };
        terminals[index] = Some((identity, terminal));
    }
    Ok(terminals.map(|terminal| terminal.map(|(_, terminal)| terminal)))
}

fn identity(fd: BorrowedFd<'_>) -> io::Result<Identity> {
    const TIOCGDEV: rustix::ioctl::Opcode = rustix::ioctl::opcode::read::<c_uint>(b'T', 0x32);
    // SAFETY: TIOCGDEV is `_IOR('T', 0x32, unsigned int)`, so the kernel
    // writes exactly the getter's `c_uint` output.
    let device =
        unsafe { rustix::ioctl::ioctl(fd, rustix::ioctl::Getter::<TIOCGDEV, c_uint>::new()) }?;
    let mount = match rustix::termios::tcgetsid(fd) {
        // /dev/tty and its direct device node can live on different mounts.
        // A process has only one controlling terminal, so both aliases agree.
        Ok(_) => None,
        Err(Errno::NOTTY) => {
            Some(std::fs::metadata(format!("/proc/self/fd/{}", fd.as_raw_fd()))?.dev())
        }
        Err(error) => return Err(error.into()),
    };
    Ok((device, mount))
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
    /// Switches the terminal `fd` refers to into raw mode.
    pub fn open(fd: BorrowedFd<'_>) -> io::Result<Self> {
        // Reopen rather than dup: O_NONBLOCK must not change the inherited
        // open file description.
        let file = rustix::fs::open(
            format!("/proc/self/fd/{}", fd.as_raw_fd()),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
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

    fn window_size(&self) -> Result<WindowSize, TerminalTransportError> {
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
        // transport dropped first, such as when a later stream fails to open.
        let _ = self.restore();
    }
}
