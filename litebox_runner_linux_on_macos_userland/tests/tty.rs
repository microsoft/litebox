// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The host terminal behind the userland broker, emulated for AArch64 Linux guests.
//!
//! `tests/test-bins/tty` is a glibc PIE built from `litebox_runner_linux_userland/tests/tty.c`
//! with `zig cc -target aarch64-linux-gnu.2.36 -O2 -UNDEBUG -fno-sanitize=all -fPIE -pie -s
//! -include tests/glibc_speeds.h -o tty tty.c`. `-UNDEBUG` keeps the fixture's `assert` checks,
//! which `-O2` alone compiles out, and `glibc_speeds.h` matches its speed constants to the glibc
//! in `tests/test-bins`.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod common;

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Terminal attributes: input, output, control, and local modes, and control characters.
type Attributes = (
    libc::tcflag_t,
    libc::tcflag_t,
    libc::tcflag_t,
    libc::tcflag_t,
    [libc::cc_t; libc::NCCS],
);

/// A PTY whose manager the test reads and writes as a terminal emulator would.
struct Pty {
    manager: File,
    subsidiary: File,
    /// The subsidiary's device path.
    path: PathBuf,
}

impl Pty {
    fn open() -> Self {
        let mut manager = -1;
        let mut subsidiary = -1;
        // macOS PTY names fit in 128 bytes, as `openpty` requires.
        let mut name = [0u8; 128];
        // SAFETY: the descriptors and name are writable, and null optional arguments request
        // defaults.
        let result = unsafe {
            libc::openpty(
                &raw mut manager,
                &raw mut subsidiary,
                name.as_mut_ptr().cast(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(result, 0, "openpty: {}", std::io::Error::last_os_error());
        for (fd, flags) in [(manager, libc::O_NONBLOCK), (subsidiary, 0)] {
            // SAFETY: openpty returned `fd`, which only this test uses. Only the streams a test
            // chooses may reach its children.
            unsafe {
                assert_eq!(libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC), 0);
                assert_eq!(libc::fcntl(fd, libc::F_SETFL, flags), 0);
            }
        }
        // SAFETY: openpty returned fresh descriptors, each transferred to exactly one owner.
        let (manager, subsidiary) =
            unsafe { (File::from_raw_fd(manager), File::from_raw_fd(subsidiary)) };
        let name = std::ffi::CStr::from_bytes_until_nul(&name).unwrap();
        Self {
            manager,
            subsidiary,
            path: PathBuf::from(name.to_str().unwrap()),
        }
    }

    fn subsidiary_stdio(&self) -> Stdio {
        Stdio::from(self.subsidiary.try_clone().unwrap())
    }

    /// The subsidiary's attributes, without `PENDIN`, which macOS sets whenever canonical mode
    /// is turned on.
    ///
    /// The attributes are read through a new descriptor: when the leader of the session that the
    /// terminal controls exits, macOS revokes every descriptor for the terminal, but keeps its
    /// attributes.
    fn attributes(&self) -> Attributes {
        let terminal = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(&self.path)
            .unwrap();
        // SAFETY: termios contains only integer fields.
        let mut attributes: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `terminal` is live and `attributes` is writable storage for its attributes.
        assert_eq!(
            unsafe { libc::tcgetattr(terminal.as_raw_fd(), &raw mut attributes) },
            0,
            "tcgetattr: {}",
            std::io::Error::last_os_error()
        );
        (
            attributes.c_iflag,
            attributes.c_oflag,
            attributes.c_cflag,
            attributes.c_lflag & !libc::PENDIN,
            attributes.c_cc,
        )
    }

    fn set_window_size(&self, rows: u16, columns: u16) {
        let size = libc::winsize {
            ws_row: rows,
            ws_col: columns,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: the manager is a live PTY and `size` is a valid winsize.
        assert_eq!(
            unsafe { libc::ioctl(self.manager.as_raw_fd(), libc::TIOCSWINSZ, &raw const size) },
            0
        );
    }

    fn write_all(&mut self, bytes: &[u8]) {
        self.manager.write_all(bytes).unwrap();
    }

    fn wait_for_output(&mut self, output: &mut Vec<u8>, needle: &[u8]) {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            self.read_available(output);
            if output.windows(needle.len()).any(|window| window == needle) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {:?}; output so far:\n{}",
                String::from_utf8_lossy(needle),
                String::from_utf8_lossy(output)
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Reads the terminal's output until `child` exits, since a macOS PTY completes a drain only
    /// as its manager reads.
    fn wait_for_child_exit(&mut self, child: &mut Child, output: &mut Vec<u8>) -> ExitStatus {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            self.read_available(output);
            if let Some(status) = child.try_wait().unwrap() {
                self.read_available(output);
                return status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "timed out waiting for the broker to exit; output so far:\n{}",
                    String::from_utf8_lossy(output)
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn read_available(&mut self, output: &mut Vec<u8>) {
        let mut buffer = [0; 4096];
        loop {
            match self.manager.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => output.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                Err(error) => panic!("failed to read from the PTY: {error}"),
            }
        }
    }
}

/// Packs `tty` with the dynamic loader and glibc into `directory`.
fn guest_archive(directory: &Path) -> PathBuf {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/test-bins");
    let root = directory.join("root");
    for (source, destination) in [
        ("tty", "bin/tty"),
        ("ld-linux-aarch64.so.1", "lib/ld-linux-aarch64.so.1"),
        ("libc.so.6", "lib/aarch64-linux-gnu/libc.so.6"),
    ] {
        let path = root.join(destination);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::copy(fixtures.join(source), &path).unwrap();
    }
    let archive = directory.join("root.tar");
    let tar = Command::new("tar")
        .env("COPYFILE_DISABLE", "1")
        .args(["--format=ustar", "-cf"])
        .arg(&archive)
        .arg("-C")
        .arg(&root)
        .args(["bin", "lib"])
        .output()
        .unwrap();
    assert!(
        tar.status.success(),
        "{}",
        String::from_utf8_lossy(&tar.stderr)
    );
    archive
}

/// Starts the broker running `tty` with `mode` as the leader of a new session whose controlling
/// terminal is `terminal`, as a terminal emulator starts a shell. With `stderr_alias`, standard
/// error instead reopens the terminal through `/dev/tty`.
fn spawn_with_controlling_terminal(
    archive: &Path,
    mode: Option<&str>,
    terminal: &File,
    streams: [Stdio; 3],
    stderr_alias: bool,
) -> Child {
    let runner = common::runner_binary();
    let mut command = Command::new(common::broker_binary(&runner));
    command
        .args([
            "--unstable",
            "--allow-process-duplication",
            "--fs-initial-files",
        ])
        .arg(archive)
        .arg("--runner")
        .arg(&runner)
        .args([
            "--",
            "--env",
            "LD_LIBRARY_PATH=/lib/aarch64-linux-gnu",
            "/bin/tty",
        ])
        .args(mode)
        .env_remove("LITEBOX_DISABLE_NATIVE_FORK");
    let [stdin, stdout, stderr] = streams;
    command.stdin(stdin).stdout(stdout).stderr(stderr);
    let terminal = terminal.as_raw_fd();
    // SAFETY: the child only calls async-signal-safe functions before exec. `terminal` stays open
    // in the child until exec; the path is a static NUL-terminated string.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0
                || libc::ioctl(terminal, libc::c_ulong::from(libc::TIOCSCTTY), 0) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if !stderr_alias {
                return Ok(());
            }
            let fd = libc::open(c"/dev/tty".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let result = libc::dup2(fd, libc::STDERR_FILENO);
            let error = std::io::Error::last_os_error();
            libc::close(fd);
            if result < 0 {
                return Err(error);
            }
            Ok(())
        });
    }
    command.spawn().unwrap()
}

/// Opens a temporary file holding `contents` for reading and writing, already unlinked so that
/// it never outlives the test.
fn unlinked_test_file(directory: &Path, name: &str, contents: &[u8]) -> File {
    let path = directory.join(name);
    std::fs::write(&path, contents).unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    file
}

#[test]
fn tty_line_discipline() {
    check_line_discipline(false);
}

#[test]
fn tty_alias() {
    check_line_discipline(true);
}

fn check_line_discipline(alias: bool) {
    let directory = tempfile::tempdir().unwrap();
    let archive = guest_archive(directory.path());
    let mut pty = Pty::open();
    let original = pty.attributes();
    // SAFETY: the subsidiary is a live descriptor and F_GETFL takes no argument.
    let flags = unsafe { libc::fcntl(pty.subsidiary.as_raw_fd(), libc::F_GETFL) };
    let streams = [
        pty.subsidiary_stdio(),
        pty.subsidiary_stdio(),
        pty.subsidiary_stdio(),
    ];
    let mut child =
        spawn_with_controlling_terminal(&archive, None, &pty.subsidiary, streams, alias);
    let mut output = Vec::new();
    for (prompt, input) in [
        (
            b"CANONICAL READY".as_slice(),
            b"hellx\x7fo\nsecond\n".as_slice(),
        ),
        (b"EOF READY", b"\x04"),
        (b"POLL READY", b"half"),
        (b"POLL BLOCKED", b"\n"),
        (b"RAW READY", b"\r\x03\x04"),
        (b"INTERRUPT READY", b"\x03"),
        (b"QUIT READY", b"\x1c"),
    ] {
        pty.wait_for_output(&mut output, prompt);
        pty.write_all(input);
    }
    pty.wait_for_output(&mut output, b"RESIZE READY");
    pty.set_window_size(37, 101);
    let status = pty.wait_for_child_exit(&mut child, &mut output);
    assert!(
        status.success(),
        "TTY fixture failed with {status}:\n{}",
        String::from_utf8_lossy(&output)
    );
    assert!(output.windows(8).any(|bytes| bytes == b"TTY DONE"));
    assert!(output.windows(11).any(|bytes| bytes == b"a       b\r\n"));
    assert_eq!(pty.attributes(), original);
    // SAFETY: the subsidiary is still live; F_GETFL takes no argument.
    assert_eq!(
        unsafe { libc::fcntl(pty.subsidiary.as_raw_fd(), libc::F_GETFL) },
        flags
    );
}

/// The session moves the terminal's events to its foreground process group.
#[test]
fn tty_job_control() {
    let directory = tempfile::tempdir().unwrap();
    let archive = guest_archive(directory.path());
    let mut pty = Pty::open();
    let streams = [
        pty.subsidiary_stdio(),
        pty.subsidiary_stdio(),
        pty.subsidiary_stdio(),
    ];
    let mut child =
        spawn_with_controlling_terminal(&archive, Some("jobs"), &pty.subsidiary, streams, false);
    let mut output = Vec::new();
    pty.wait_for_output(&mut output, b"JOB READY");
    pty.write_all(b"\x03");
    let status = pty.wait_for_child_exit(&mut child, &mut output);
    assert!(
        status.success(),
        "job-control TTY fixture failed with {status}:\n{}",
        String::from_utf8_lossy(&output)
    );
    assert!(output.windows(9).any(|bytes| bytes == b"JOBS DONE"));
}

/// A piped standard stream leaves the terminal to the host: the guest has none.
#[test]
fn tty_with_piped_stdout() {
    let directory = tempfile::tempdir().unwrap();
    let archive = guest_archive(directory.path());
    let mut pty = Pty::open();
    let original = pty.attributes();
    let streams = [
        pty.subsidiary_stdio(),
        Stdio::piped(),
        pty.subsidiary_stdio(),
    ];
    let mut child =
        spawn_with_controlling_terminal(&archive, Some("pipe"), &pty.subsidiary, streams, false);
    let mut output = Vec::new();
    pty.wait_for_output(&mut output, b"PIPE READY");
    assert_eq!(
        pty.attributes(),
        original,
        "the broker took over a terminal shared with a pipe"
    );
    pty.write_all(b"input\n");
    let status = pty.wait_for_child_exit(&mut child, &mut output);
    assert!(
        status.success(),
        "piped TTY fixture failed with {status}:\n{}",
        String::from_utf8_lossy(&output)
    );
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    assert_eq!(stdout, b"pipe\n");
}

/// With standard input from a file, the guest keeps the terminal, behind `/dev/tty` and the
/// other standard streams.
#[test]
fn tty_with_file_stdin() {
    let directory = tempfile::tempdir().unwrap();
    let archive = guest_archive(directory.path());
    let input = unlinked_test_file(directory.path(), "stdin", b"file\n");
    let mut pty = Pty::open();
    let original = pty.attributes();
    let streams = [input.into(), pty.subsidiary_stdio(), pty.subsidiary_stdio()];
    let mut child =
        spawn_with_controlling_terminal(&archive, Some("file"), &pty.subsidiary, streams, false);
    let mut output = Vec::new();
    pty.wait_for_output(&mut output, b"FILE READY");
    pty.write_all(b"keys\n");
    let status = pty.wait_for_child_exit(&mut child, &mut output);
    assert!(
        status.success(),
        "file-input TTY fixture failed with {status}:\n{}",
        String::from_utf8_lossy(&output)
    );
    assert!(output.windows(9).any(|bytes| bytes == b"FILE DONE"));
    assert_eq!(pty.attributes(), original);
}

/// The terminal signals the guest even when no standard stream refers to it and the guest has
/// not opened it.
#[test]
fn tty_signals_without_terminal_streams() {
    let directory = tempfile::tempdir().unwrap();
    let archive = guest_archive(directory.path());
    let log = unlinked_test_file(directory.path(), "stdout", b"");
    let read_log = || {
        let mut contents = [0; 64];
        let len = log.read_at(&mut contents, 0).unwrap();
        contents[..len].to_vec()
    };
    let mut pty = Pty::open();
    let original = pty.attributes();
    let streams = [
        Stdio::null(),
        log.try_clone().unwrap().into(),
        Stdio::null(),
    ];
    let mut child = spawn_with_controlling_terminal(
        &archive,
        Some("detached"),
        &pty.subsidiary,
        streams,
        false,
    );
    let mut output = Vec::new();
    let deadline = Instant::now() + TIMEOUT;
    while read_log() != b"DETACHED READY\n" {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("timed out waiting for the fixture");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    pty.write_all(b"\x03");
    let status = pty.wait_for_child_exit(&mut child, &mut output);
    assert!(
        status.success(),
        "detached TTY fixture failed with {status}:\n{}",
        String::from_utf8_lossy(&output)
    );
    assert_eq!(read_log(), b"DETACHED READY\nDETACHED DONE\n");
    assert_eq!(pty.attributes(), original);
}
