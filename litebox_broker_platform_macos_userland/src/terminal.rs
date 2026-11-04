// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS host terminal transport.

use std::ffi::{CStr, OsStr};
use std::io;
use std::os::fd::{AsFd, AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use litebox_broker_core::terminal::{TerminalTransport, TerminalTransportError};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::terminal::WindowSize;
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::Errno;
use rustix::termios::{OptionalActions, QueueSelector, Termios, Winsize};

// SAFETY: the declaration matches `devname_r` in macOS's `<stdlib.h>`, which
// libSystem exports.
unsafe extern "C" {
    /// `devname_r(3)`: writes the name under `/dev` of the device `dev` of
    /// file type `kind` to `buffer`, which holds `len` bytes, and returns
    /// `buffer`, or null if no such device is known or the name does not fit.
    fn devname_r(
        dev: libc::dev_t,
        kind: libc::mode_t,
        buffer: *mut libc::c_char,
        len: libc::c_int,
    ) -> *mut libc::c_char;
}

/// The `e_tdev` of a process without a controlling terminal: `NODEV`,
/// `(dev_t)-1`.
const NO_DEVICE: u32 = u32::MAX;

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
///
/// The terminal is opened by its device's own path rather than `/dev/tty`,
/// whose descriptors macOS cannot wait on with `poll` or kqueue.
pub fn open_controlling_terminal() -> io::Result<Option<(MacosTerminal, [bool; 3])>> {
    let Some(device) = controlling_terminal_device()? else {
        return Ok(None);
    };
    // I/O through `/dev/tty`, a clone device, reaches the controlling
    // terminal of the process performing it, so a standard stream that is
    // the clone device is this process's terminal.
    let alias = rustix::fs::stat("/dev/tty")?.st_rdev;
    let (stdin, stdout, stderr) = (io::stdin(), io::stdout(), io::stderr());
    let fds = [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()];
    let mut is_terminal = [false; 3];
    for (stream_is_terminal, fd) in is_terminal.iter_mut().zip(fds) {
        let status = match rustix::fs::fstat(fd) {
            Ok(status) => status,
            Err(Errno::BADF) => continue,
            Err(error) => return Err(error.into()),
        };
        match FileType::from_raw_mode(status.st_mode) {
            FileType::Fifo | FileType::Socket => return Ok(None),
            // Device numbers identify the terminal, so neither another
            // terminal nor a pseudo-terminal manager matches, unlike with
            // `tcgetpgrp`, which macOS answers for any manager.
            FileType::CharacterDevice => {
                *stream_is_terminal = status.st_rdev == device || status.st_rdev == alias;
            }
            _ => {}
        }
    }
    let Some(path) = device_path(device) else {
        return Ok(None);
    };
    // Opened only now, since a closed standard stream's descriptor could
    // otherwise come to refer to it.
    let file = match rustix::fs::open(
        &path,
        OFlags::RDWR | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => file,
        // The device went away, as a pseudo-terminal's does once its manager
        // closes.
        Err(Errno::NOENT | Errno::NXIO) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    // A device name can be reused, so the device opened must be the one this
    // process's controlling terminal was.
    if rustix::fs::fstat(&file)?.st_rdev != device {
        return Ok(None);
    }
    let foreground = match rustix::termios::tcgetpgrp(&file) {
        Ok(group) => group == rustix::process::getpgrp(),
        // The terminal is no longer this process's controlling terminal.
        Err(Errno::NOTTY) => false,
        Err(error) => return Err(error.into()),
    };
    if !foreground {
        return Ok(None);
    }
    Ok(Some((MacosTerminal::new(file)?, is_terminal)))
}

/// Returns the device number of this process's controlling terminal, or
/// `None` if it has none.
fn controlling_terminal_device() -> io::Result<Option<libc::dev_t>> {
    // SAFETY: `proc_bsdinfo` holds only integers and integer arrays, for which
    // all zeros is a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size =
        libc::c_int::try_from(size_of::<libc::proc_bsdinfo>()).expect("proc_bsdinfo fits in c_int");
    let pid = rustix::process::getpid().as_raw_nonzero().get();
    // SAFETY: `info` is writable storage of `size` bytes, the size the
    // `PROC_PIDTBSDINFO` flavor writes.
    let written =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }
    if written != size {
        return Err(io::Error::other(
            "proc_pidinfo returned a short proc_bsdinfo",
        ));
    }
    if info.e_tdev == NO_DEVICE {
        return Ok(None);
    }
    Ok(Some(info.e_tdev.cast_signed()))
}

/// Returns the path of the character device `device`, or `None` if `/dev`
/// does not name it.
fn device_path(device: libc::dev_t) -> Option<PathBuf> {
    let mut name = vec![0u8; usize::try_from(libc::PATH_MAX).expect("PATH_MAX is positive")];
    // SAFETY: `name` is writable for `PATH_MAX` bytes, the length passed.
    let found = unsafe {
        devname_r(
            device,
            libc::S_IFCHR,
            name.as_mut_ptr().cast(),
            libc::PATH_MAX,
        )
    };
    if found.is_null() {
        return None;
    }
    let name = CStr::from_bytes_until_nul(&name).ok()?;
    Some(Path::new("/dev").join(OsStr::from_bytes(name.to_bytes())))
}

/// The kqueue identifier of the wake event, an `EVFILT_USER` event, whose
/// identifiers are separate from descriptors'.
const WAKE_IDENT: usize = 0;

/// How a [`MacosTerminal`] watches the terminal's input.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadFilter {
    Off,
    /// Reports while input is queued, and from hangup on.
    Level,
    /// `EV_CLEAR`: reports each arrival of input and the hangup once, so a
    /// wait for hangup alone returns early only when input arrives.
    Edge,
}

/// The terminal's filters registered with a [`MacosTerminal`]'s kqueue.
struct Filters {
    read: ReadFilter,
    /// Whether a level-triggered write filter is registered.
    write: bool,
}

/// A macOS host terminal in raw mode.
///
/// Dropping the transport restores the terminal's original attributes if
/// [`restore`](TerminalTransport::restore) has not already.
pub struct MacosTerminal {
    file: OwnedFd,
    /// Watches the terminal and the wake event.
    kqueue: OwnedFd,
    /// The terminal's filters registered with `kqueue`, which each wait
    /// changes to match its interest.
    filters: Mutex<Filters>,
    /// Whether a wait saw the terminal hang up, which it stays. An
    /// edge-triggered read filter reports the hangup only once.
    hangup_seen: AtomicBool,
    /// Attributes to restore, taken by the first `restore`.
    original: Mutex<Option<Termios>>,
}

impl MacosTerminal {
    /// Switches the terminal `file` refers to into raw mode. `file` must be
    /// nonblocking and its open file description not shared with other
    /// processes.
    pub fn new(file: OwnedFd) -> io::Result<Self> {
        let original = rustix::termios::tcgetattr(&file)?;
        let kqueue = new_kqueue()?;
        apply_changes(
            &kqueue,
            &mut [change(
                WAKE_IDENT,
                libc::EVFILT_USER,
                libc::EV_ADD | libc::EV_CLEAR,
                0,
            )],
        )?;
        let mut raw = original.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(&file, OptionalActions::Now, &raw)?;
        Ok(Self {
            file,
            kqueue,
            filters: Mutex::new(Filters {
                read: ReadFilter::Off,
                write: false,
            }),
            hangup_seen: AtomicBool::new(false),
            original: Mutex::new(Some(original)),
        })
    }

    fn ident(&self) -> usize {
        usize::try_from(self.file.as_raw_fd()).expect("descriptors are nonnegative")
    }

    /// Registers the terminal's filters for `interest`, changing only those
    /// that differ from the registered ones. A filter keeps the mode it was
    /// added with, so a filter changing mode is deleted and added again;
    /// adding a filter reports a state already present.
    ///
    /// Once hangup is seen, `wait` reports it without the terminal's filters,
    /// so none is registered again: a revoked terminal accepts none.
    fn watch(&self, interest: ReadinessFlags) -> Result<(), Errno> {
        let hung_up = self.hangup_seen.load(Ordering::Relaxed);
        let read = if hung_up {
            ReadFilter::Off
        } else if interest.contains(ReadinessFlags::READ) {
            ReadFilter::Level
        } else if interest.contains(ReadinessFlags::HANGUP) {
            ReadFilter::Edge
        } else {
            ReadFilter::Off
        };
        let write = !hung_up && interest.contains(ReadinessFlags::WRITE);
        let ident = self.ident();
        let mut filters = self.filters.lock().expect("terminal mutex poisoned");
        let mut changes = Vec::with_capacity(3);
        if read != filters.read {
            if filters.read != ReadFilter::Off {
                changes.push(change(ident, libc::EVFILT_READ, libc::EV_DELETE, 0));
            }
            match read {
                ReadFilter::Off => {}
                ReadFilter::Level => {
                    changes.push(change(ident, libc::EVFILT_READ, libc::EV_ADD, 0));
                }
                ReadFilter::Edge => changes.push(change(
                    ident,
                    libc::EVFILT_READ,
                    libc::EV_ADD | libc::EV_CLEAR,
                    0,
                )),
            }
        }
        if write != filters.write {
            let flags = if write { libc::EV_ADD } else { libc::EV_DELETE };
            changes.push(change(ident, libc::EVFILT_WRITE, flags, 0));
        }
        if !changes.is_empty() {
            // Filters a failed change left registered are unknown, so a later
            // wait could report readiness outside its interest; the caller
            // treats the failure as the transport's.
            apply_changes(&self.kqueue, &mut changes)?;
            *filters = Filters { read, write };
        }
        Ok(())
    }

    fn error(&self, error: Errno) -> TerminalTransportError {
        match error {
            Errno::AGAIN | Errno::INTR => TerminalTransportError::WouldBlock,
            // Closing a PTY manager can race with calls between waits. EIO
            // accompanied by hangup is closure, not failure.
            // A terminal revoked when its session leader exits fails
            // terminal requests with ENOTTY.
            Errno::IO | Errno::NOTTY if self.hung_up() => TerminalTransportError::HungUp,
            error => failed(error),
        }
    }

    /// Whether the terminal hung up or was revoked; `poll` reports the latter
    /// as an invalid descriptor, since a revoked terminal's descriptor
    /// refers to no device.
    fn hung_up(&self) -> bool {
        // macOS reports a terminal's hangup to `poll` only alongside a
        // requested event.
        let mut fds = [PollFd::new(&self.file, PollFlags::IN)];
        let now = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        loop {
            match rustix::event::poll(&mut fds, Some(&now)) {
                Ok(_) => {
                    return fds[0]
                        .revents()
                        .intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL);
                }
                Err(Errno::INTR) => {}
                Err(_) => return false,
            }
        }
    }
}

/// Creates a kqueue. macOS creates every kqueue close-on-exec and never lets
/// a child process inherit one, so no runner spawned meanwhile can.
fn new_kqueue() -> io::Result<OwnedFd> {
    // SAFETY: `kqueue` takes no arguments.
    let fd = unsafe { libc::kqueue() };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `kqueue` returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Returns a kqueue change for `ident` and `filter`.
fn change(ident: usize, filter: i16, flags: u16, filter_flags: u32) -> libc::kevent {
    libc::kevent {
        ident,
        filter,
        flags,
        fflags: filter_flags,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}

/// Applies `changes`, each with a receipt, and returns the first error. A
/// deletion of a filter already gone succeeds: kqueue removes a terminal's
/// filters itself when it reports the terminal revoked.
fn apply_changes(kqueue: &OwnedFd, changes: &mut [libc::kevent]) -> Result<(), Errno> {
    for change in changes.iter_mut() {
        change.flags |= libc::EV_RECEIPT;
    }
    let count = libc::c_int::try_from(changes.len()).map_err(|_| Errno::INVAL)?;
    let receipts = changes.as_mut_ptr();
    let now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `changes` outlives the call, which reads `count` changes from it
    // and, each change asking for a receipt, writes as many receipts back to
    // it, and `now` outlives the call. A zero timeout never sleeps, so the
    // call is not interrupted after applying some changes.
    let result = unsafe {
        libc::kevent(
            kqueue.as_raw_fd(),
            receipts,
            count,
            receipts,
            count,
            &raw const now,
        )
    };
    if result < 0 {
        return Err(Errno::from_io_error(&io::Error::last_os_error()).unwrap_or(Errno::IO));
    }
    for receipt in changes.iter() {
        // A receipt reports success as error 0.
        if receipt.flags & libc::EV_ERROR != 0
            && receipt.data != 0
            && !(receipt.flags & libc::EV_DELETE != 0
                && receipt.data == libc::ENOENT as libc::intptr_t)
        {
            let error = i32::try_from(receipt.data).map_err(|_| Errno::INVAL)?;
            return Err(Errno::from_raw_os_error(error));
        }
    }
    Ok(())
}

fn failed(error: Errno) -> TerminalTransportError {
    TerminalTransportError::Failed(Box::new(io::Error::from(error)))
}

impl TerminalTransport for MacosTerminal {
    fn read(&self, buffer: &mut [u8]) -> Result<usize, TerminalTransportError> {
        rustix::io::read(&self.file, buffer).map_err(|error| self.error(error))
    }

    fn write(&self, buffer: &[u8]) -> Result<usize, TerminalTransportError> {
        rustix::io::write(&self.file, buffer).map_err(|error| self.error(error))
    }

    /// Waits for the terminal with kqueue. Each call registers only the
    /// filters its `interest` needs and reports only readiness in it, so
    /// waits must not overlap, as those of a terminal's one worker do not.
    ///
    /// The read filter reports hangup, so it watches an interest of only
    /// [`HANGUP`](ReadinessFlags::HANGUP) too, then edge-triggered: such a
    /// wait returns empty readiness at each arrival of input rather than at
    /// none. Hangup, once seen, is reported to every later wait for it.
    fn wait(
        &self,
        interest: ReadinessFlags,
        timeout: Option<Duration>,
    ) -> Result<ReadinessFlags, TerminalTransportError> {
        let timeout = timeout
            .map(|timeout| {
                Ok::<_, std::num::TryFromIntError>(libc::timespec {
                    tv_sec: libc::time_t::try_from(timeout.as_secs())?,
                    tv_nsec: libc::c_long::from(timeout.subsec_nanos()),
                })
            })
            .transpose()
            .map_err(|error| TerminalTransportError::Failed(Box::new(error)))?;
        self.watch(interest).map_err(failed)?;
        let hung_up =
            interest.contains(ReadinessFlags::HANGUP) && self.hangup_seen.load(Ordering::Relaxed);
        let now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let timeout = if hung_up { Some(now) } else { timeout };
        let mut events = [change(0, 0, 0, 0); 3];
        let capacity = libc::c_int::try_from(events.len()).expect("three events fit in c_int");
        // SAFETY: `events` outlives the call, which writes at most `capacity`
        // events to it, and `timeout`, if any, outlives the call.
        let count = unsafe {
            libc::kevent(
                self.kqueue.as_raw_fd(),
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                capacity,
                timeout
                    .as_ref()
                    .map_or(std::ptr::null(), |timeout| &raw const *timeout),
            )
        };
        let Ok(count) = usize::try_from(count) else {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::EINTR) => Ok(ReadinessFlags::default()),
                _ => Err(TerminalTransportError::Failed(Box::new(error))),
            };
        };
        let ident = self.ident();
        let mut ready = if hung_up {
            ReadinessFlags::HANGUP
        } else {
            ReadinessFlags::default()
        };
        for event in &events[..count] {
            if event.filter == libc::EVFILT_USER || event.ident != ident {
                continue;
            }
            if event.flags & libc::EV_ERROR != 0 {
                let error = i32::try_from(event.data).unwrap_or(libc::EIO);
                return Err(failed(Errno::from_raw_os_error(error)));
            }
            if event.flags & libc::EV_EOF != 0 {
                self.hangup_seen.store(true, Ordering::Relaxed);
                if interest.contains(ReadinessFlags::HANGUP) {
                    ready = ready | ReadinessFlags::HANGUP;
                }
            }
            if event.filter == libc::EVFILT_READ && interest.contains(ReadinessFlags::READ) {
                ready = ready | ReadinessFlags::READ;
            }
            if event.filter == libc::EVFILT_WRITE && interest.contains(ReadinessFlags::WRITE) {
                ready = ready | ReadinessFlags::WRITE;
            }
        }
        Ok(ready)
    }

    fn wake(&self) -> Result<(), TerminalTransportError> {
        apply_changes(
            &self.kqueue,
            &mut [change(WAKE_IDENT, libc::EVFILT_USER, 0, libc::NOTE_TRIGGER)],
        )
        .map_err(failed)
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

impl Drop for MacosTerminal {
    fn drop(&mut self) {
        // Owners restore explicitly to observe failures. This covers a
        // transport dropped without being restored, such as when
        // `HostTerminal::new` fails.
        let _ = self.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::termios::{LocalModes, SpecialCodeIndex};
    use std::fs::File;
    use std::io::{Read as _, Write as _};
    use std::time::Instant;

    const SHORT: Duration = Duration::from_millis(50);

    /// Returns a PTY's manager and its nonblocking subsidiary.
    fn open_pty() -> (File, OwnedFd) {
        let mut manager = -1;
        let mut subsidiary = -1;
        // SAFETY: the descriptors are writable and null optional arguments
        // request defaults.
        let result = unsafe {
            libc::openpty(
                &raw mut manager,
                &raw mut subsidiary,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(result, 0, "{}", io::Error::last_os_error());
        // SAFETY: openpty returned fresh descriptors, each transferred to
        // exactly one owner.
        let (manager, subsidiary) =
            unsafe { (File::from_raw_fd(manager), OwnedFd::from_raw_fd(subsidiary)) };
        rustix::fs::fcntl_setfl(&subsidiary, OFlags::NONBLOCK).unwrap();
        (manager, subsidiary)
    }

    /// Returns a PTY's manager and a transport over its subsidiary, with a
    /// second descriptor for the subsidiary.
    fn open_terminal() -> (File, MacosTerminal, OwnedFd) {
        let (manager, subsidiary) = open_pty();
        let observer = subsidiary.try_clone().unwrap();
        (manager, MacosTerminal::new(subsidiary).unwrap(), observer)
    }

    /// The settings of `attributes` that `restore` must return, excluding
    /// `PENDIN`, which macOS sets whenever canonical mode is turned on.
    fn modes(attributes: &Termios) -> impl PartialEq + std::fmt::Debug {
        (
            attributes.input_modes,
            attributes.output_modes,
            attributes.control_modes,
            attributes.local_modes - LocalModes::PENDIN,
            attributes.special_codes[SpecialCodeIndex::VMIN],
            attributes.special_codes[SpecialCodeIndex::VTIME],
        )
    }

    fn read_exact(terminal: &MacosTerminal, count: usize) -> Vec<u8> {
        let mut bytes = vec![0; count];
        let mut filled = 0;
        while filled < count {
            terminal
                .wait(ReadinessFlags::READ, Some(Duration::from_secs(5)))
                .unwrap();
            match terminal.read(&mut bytes[filled..]) {
                Ok(read) => filled += read,
                Err(TerminalTransportError::WouldBlock) => {}
                Err(error) => panic!("{error}"),
            }
        }
        bytes
    }

    #[test]
    fn controlling_terminal_device_presence_matches_dev_tty() {
        let device = controlling_terminal_device().unwrap();
        match rustix::fs::open("/dev/tty", OFlags::RDWR | OFlags::NOCTTY, Mode::empty()) {
            Err(Errno::NXIO) => {
                assert_eq!(device, None);
                assert!(open_controlling_terminal().unwrap().is_none());
            }
            Ok(_) => assert!(device.is_some()),
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn device_path_names_a_pty_subsidiary() {
        let (_manager, subsidiary) = open_pty();
        let device = rustix::fs::fstat(&subsidiary).unwrap().st_rdev;
        let name = rustix::termios::ttyname(&subsidiary, Vec::new()).unwrap();
        assert_eq!(
            device_path(device).unwrap(),
            Path::new(OsStr::from_bytes(name.to_bytes()))
        );
        assert_eq!(device_path(0x7fff_1234), None);
    }

    #[test]
    fn raw_mode_is_set_and_restored_once() {
        let (_manager, subsidiary) = open_pty();
        let observer = subsidiary.try_clone().unwrap();
        let original = rustix::termios::tcgetattr(&observer).unwrap();
        let terminal = MacosTerminal::new(subsidiary).unwrap();
        let mut raw = original.clone();
        raw.make_raw();
        let current = rustix::termios::tcgetattr(&observer).unwrap();
        assert_eq!(modes(&current), modes(&raw));
        assert_ne!(modes(&current), modes(&original));
        terminal.restore().unwrap();
        assert_eq!(
            modes(&rustix::termios::tcgetattr(&observer).unwrap()),
            modes(&original)
        );
        // Later restores, including the drop's, leave settings made since.
        rustix::termios::tcsetattr(&observer, OptionalActions::Now, &raw).unwrap();
        terminal.restore().unwrap();
        drop(terminal);
        assert_eq!(
            modes(&rustix::termios::tcgetattr(&observer).unwrap()),
            modes(&raw)
        );
    }

    #[test]
    fn drop_restores_an_unrestored_terminal() {
        let (_manager, subsidiary) = open_pty();
        let observer = subsidiary.try_clone().unwrap();
        let original = rustix::termios::tcgetattr(&observer).unwrap();
        drop(MacosTerminal::new(subsidiary).unwrap());
        assert_eq!(
            modes(&rustix::termios::tcgetattr(&observer).unwrap()),
            modes(&original)
        );
    }

    #[test]
    fn read_and_write_round_trip() {
        let (mut manager, terminal, _observer) = open_terminal();
        assert!(matches!(
            terminal.read(&mut [0; 4]),
            Err(TerminalTransportError::WouldBlock)
        ));
        manager.write_all(b"in\n").unwrap();
        assert_eq!(read_exact(&terminal, 3), b"in\n");
        assert_eq!(terminal.write(b"out\n").unwrap(), 4);
        let mut bytes = [0; 4];
        manager.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"out\n");
    }

    #[test]
    fn wait_reports_only_requested_readiness() {
        let (mut manager, terminal, _observer) = open_terminal();
        assert_eq!(
            terminal.wait(ReadinessFlags::READ, Some(SHORT)).unwrap(),
            ReadinessFlags::default()
        );
        assert_eq!(
            terminal
                .wait(ReadinessFlags::WRITE | ReadinessFlags::HANGUP, Some(SHORT))
                .unwrap(),
            ReadinessFlags::WRITE
        );
        manager.write_all(b"x").unwrap();
        assert_eq!(
            terminal
                .wait(ReadinessFlags::READ | ReadinessFlags::HANGUP, Some(SHORT))
                .unwrap(),
            ReadinessFlags::READ
        );
        assert_eq!(
            terminal
                .wait(ReadinessFlags::READ | ReadinessFlags::WRITE, Some(SHORT))
                .unwrap(),
            ReadinessFlags::READ | ReadinessFlags::WRITE
        );
    }

    /// Readiness that an earlier wait's interest watched does not end a later
    /// wait without that interest.
    #[test]
    fn wait_interest_does_not_leak_between_calls() {
        let (mut manager, terminal, _observer) = open_terminal();
        manager.write_all(b"x").unwrap();
        assert_eq!(
            terminal
                .wait(ReadinessFlags::READ | ReadinessFlags::WRITE, Some(SHORT))
                .unwrap(),
            ReadinessFlags::READ | ReadinessFlags::WRITE
        );
        for interest in [ReadinessFlags::default(), ReadinessFlags::HANGUP] {
            // Adding the edge-triggered filter reports queued input once.
            let _ = terminal.wait(interest, Some(SHORT)).unwrap();
            let start = Instant::now();
            assert_eq!(
                terminal.wait(interest, Some(SHORT)).unwrap(),
                ReadinessFlags::default()
            );
            assert!(start.elapsed() >= SHORT);
        }
        assert_eq!(
            terminal.wait(ReadinessFlags::READ, Some(SHORT)).unwrap(),
            ReadinessFlags::READ
        );
    }

    #[test]
    fn wake_ends_a_blocking_wait_once() {
        let (_manager, terminal, _observer) = open_terminal();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(SHORT);
                terminal.wake().unwrap();
            });
            assert_eq!(
                terminal.wait(ReadinessFlags::READ, None).unwrap(),
                ReadinessFlags::default()
            );
        });
        terminal.wake().unwrap();
        terminal.wake().unwrap();
        assert_eq!(
            terminal.wait(ReadinessFlags::default(), None).unwrap(),
            ReadinessFlags::default()
        );
        let start = Instant::now();
        terminal
            .wait(ReadinessFlags::default(), Some(SHORT))
            .unwrap();
        assert!(start.elapsed() >= SHORT);
    }

    #[test]
    fn hangup_is_reported_and_an_empty_interest_still_waits() {
        let (manager, terminal, _observer) = open_terminal();
        drop(manager);
        for _ in 0..2 {
            assert_eq!(
                terminal
                    .wait(ReadinessFlags::HANGUP, Some(Duration::from_secs(5)))
                    .unwrap(),
                ReadinessFlags::HANGUP
            );
        }
        let start = Instant::now();
        assert_eq!(
            terminal
                .wait(ReadinessFlags::default(), Some(SHORT))
                .unwrap(),
            ReadinessFlags::default()
        );
        assert!(start.elapsed() >= SHORT);
        let ready = terminal
            .wait(
                ReadinessFlags::READ | ReadinessFlags::HANGUP,
                Some(Duration::from_secs(5)),
            )
            .unwrap();
        assert!(ready.contains(ReadinessFlags::HANGUP));
        assert_eq!(terminal.read(&mut [0; 4]).unwrap(), 0);
        assert!(matches!(
            terminal.write(b"x"),
            Err(TerminalTransportError::HungUp)
        ));
        terminal.restore().unwrap();
    }

    #[test]
    fn revoked_terminal_hangs_up() {
        use std::os::unix::process::CommandExt as _;

        let (manager, subsidiary) = open_pty();
        let path = device_path(rustix::fs::fstat(&subsidiary).unwrap().st_rdev).unwrap();
        let file = rustix::fs::open(
            &path,
            OFlags::RDWR | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let terminal = MacosTerminal::new(file).unwrap();
        let controlling = subsidiary.as_raw_fd();
        let mut command = std::process::Command::new("/bin/sleep");
        command.arg("30");
        // SAFETY: the child calls only the async-signal-safe `setsid` and
        // `ioctl` before exec, and `controlling` stays open until exec.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0 || libc::ioctl(controlling, libc::TIOCSCTTY.into(), 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut leader = command.spawn().unwrap();
        drop(subsidiary);
        let leader_group = i32::try_from(leader.id()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        // The manager reports its subsidiary's foreground group once the
        // subsidiary is the leader's controlling terminal.
        while rustix::termios::tcgetpgrp(&manager).map(|group| group.as_raw_nonzero().get())
            != Ok(leader_group)
        {
            assert!(Instant::now() < deadline, "leader never took the terminal");
            std::thread::sleep(Duration::from_millis(1));
        }
        let interest = ReadinessFlags::READ | ReadinessFlags::WRITE | ReadinessFlags::HANGUP;
        terminal.wait(interest, Some(SHORT)).unwrap();
        // The leader's exit revokes the terminal.
        leader.kill().unwrap();
        leader.wait().unwrap();
        assert!(matches!(
            terminal.get_window_size(),
            Err(TerminalTransportError::HungUp)
        ));
        assert!(
            terminal
                .wait(interest, Some(Duration::from_secs(5)))
                .unwrap()
                .contains(ReadinessFlags::HANGUP)
        );
        let start = Instant::now();
        assert_eq!(
            terminal
                .wait(ReadinessFlags::default(), Some(SHORT))
                .unwrap(),
            ReadinessFlags::default()
        );
        assert!(start.elapsed() >= SHORT);
        assert_eq!(
            terminal.wait(interest, Some(SHORT)).unwrap(),
            ReadinessFlags::HANGUP
        );
        assert!(matches!(
            terminal.write(b"x"),
            Err(TerminalTransportError::HungUp)
        ));
        drop(manager);
    }

    #[test]
    fn window_size_round_trips() {
        let (_manager, terminal, _observer) = open_terminal();
        let size = WindowSize {
            rows: 37,
            columns: 101,
            x_pixels: 3,
            y_pixels: 4,
        };
        terminal.set_window_size(size).unwrap();
        assert_eq!(terminal.get_window_size().unwrap(), size);
    }

    #[test]
    fn flush_discards_input() {
        let (mut manager, terminal, _observer) = open_terminal();
        manager.write_all(b"discard").unwrap();
        terminal
            .wait(ReadinessFlags::READ, Some(Duration::from_secs(5)))
            .unwrap();
        terminal.flush(true, true).unwrap();
        terminal.flush(false, false).unwrap();
        assert!(matches!(
            terminal.read(&mut [0; 8]),
            Err(TerminalTransportError::WouldBlock)
        ));
        terminal.drain().unwrap();
    }

    #[test]
    fn kqueue_is_close_on_exec() {
        let (_manager, terminal, _observer) = open_terminal();
        assert!(
            rustix::io::fcntl_getfd(&terminal.kqueue)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
    }
}
