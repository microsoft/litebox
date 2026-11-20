// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs test programs natively on the host, to check that what a test expects of LiteBox holds on
//! Linux.
//!
//! A test program is written for LiteBox's sandbox, where a mistake such as `kill(-1, SIGKILL)`
//! after a failed `fork` stays in the sandbox. Natively it would reach every process of the user,
//! so each program runs in a user and PID namespace of its own, as the second process of a
//! namespace whose first process only waits for it. The program keeps the user's ID, which the
//! namespace maps to itself. When the program exits, the namespace ends with its first process,
//! which kills anything the program left running.

use std::ffi::{CStr, OsStr};
use std::io::{self, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};

/// Runs a program natively, as [`super::runner::Runner`] runs one in LiteBox: with only `HOME=/`
/// and the variables given with [`Native::env`] in its environment, no standard input, and
/// standard error passed through. Its working directory is a new, empty one, which ends with the
/// `Native`, and `TMPDIR` names it, so that a program that uses `TMPDIR`, rather than `/tmp`, keeps
/// its files out of the host's.
#[allow(dead_code, reason = "not used by every test binary")]
pub(crate) struct Native {
    command: Command,
    directory: tempfile::TempDir,
}

#[allow(dead_code, reason = "not used by every test binary")]
impl Native {
    /// Prepares to run `program`, or returns `None`, after reporting why, if the host doesn't let
    /// unprivileged users create the namespaces it runs in (see [`namespaces_available`]).
    pub(crate) fn new(program: &Path) -> Option<Self> {
        if !namespaces_available() {
            return None;
        }
        println!("Running `{}` natively", program.display());
        let mut command = isolated(program);
        let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        command
            .env_clear()
            .env("HOME", "/")
            .env("TMPDIR", directory.path())
            .current_dir(directory.path())
            .stdin(Stdio::null())
            .stderr(Stdio::inherit());
        Some(Self { command, directory })
    }

    pub(crate) fn arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.command.arg(arg);
        self
    }

    pub(crate) fn env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> &mut Self {
        self.command.env(key, value);
        self
    }

    /// Runs the program, asserting that it succeeds, and returns its standard output.
    pub(crate) fn output(&mut self) -> String {
        let output = self
            .command
            .output()
            .unwrap_or_else(|error| panic!("failed to run {:?}: {error}", self.command));
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "{:?} failed natively: {}\nstdout:\n{stdout}",
            self.command,
            output.status
        );
        stdout
    }
}

/// Returns whether the host lets unprivileged users create the user and PID namespaces a program
/// runs in, after reporting why not if it doesn't. Panics if it doesn't under CI, which must, or if
/// running a program fails for any other reason.
fn namespaces_available() -> bool {
    let error = match isolated("true").status() {
        Ok(status) if status.success() => return true,
        Ok(status) => panic!("failed to run `true` natively: {status}"),
        Err(error) => error,
    };
    // Creating the namespaces fails with these when they're off limits, and writing the ID maps
    // with the last two when a security module restricts them.
    let unavailable = [libc::ENOSPC, libc::EUSERS, libc::EPERM, libc::EACCES];
    assert!(
        error
            .raw_os_error()
            .is_some_and(|errno| unavailable.contains(&errno)),
        "failed to run `true` natively: {error}"
    );
    assert!(
        std::env::var_os("CI").is_none(),
        "CI runner must let unprivileged users create user and PID namespaces: {error}"
    );
    eprintln!("skipped: no unprivileged user and PID namespaces: {error}");
    false
}

/// Returns a command that runs `program` natively, in namespaces of its own, as the second process
/// of its PID namespace. The command's exit status is the program's.
fn isolated(program: impl AsRef<OsStr>) -> Command {
    // SAFETY: `getuid` and `getgid` cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    // The child may not allocate, so the maps are formatted here.
    let uid_map = format!("{uid} {uid} 1");
    let gid_map = format!("{gid} {gid} 1");
    let parent = std::process::id();
    let mut command = Command::new(program);
    // SAFETY: `isolate` only makes async-signal-safe system calls and allocates nothing, and the
    // processes it forks never return from it, except the one that goes on to run the program.
    unsafe {
        command.pre_exec(move || isolate(parent, uid_map.as_bytes(), gid_map.as_bytes()));
    }
    command
}

/// Forks the first process of new user and PID namespaces, mapping the user and group IDs in
/// `uid_map` and `gid_map` in them, and has it fork the process that returns to run the program.
/// PID 1 relays the wait status to the outer supervisor, which exits as the program does.
///
/// This process, which stays in the user namespace of the test, writes the maps: Ubuntu's
/// `kernel.apparmor_restrict_unprivileged_userns` denies a process in a new namespace that right.
fn isolate(parent: u32, uid_map: &[u8], gid_map: &[u8]) -> io::Result<()> {
    // Ends the namespace if the test running the program ends early, e.g. on a timeout.
    // SAFETY: setting the parent-death signal affects only this process.
    check(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) })?;
    // SAFETY: `getppid` has no preconditions. Parent death before `prctl` is not signalled.
    if unsafe { libc::getppid() }.cast_unsigned() != parent {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    let (mut mapper, mut init) = UnixStream::pair()?;
    let [status_reader, status_writer] = pipe()?;
    let first = fork(libc::CLONE_NEWUSER | libc::CLONE_NEWPID)?;
    if first != 0 {
        drop(init);
        // SAFETY: this process no longer needs the descriptors.
        unsafe {
            libc::close(status_writer);
        }
        let mapped = mapper
            .read_exact(&mut [0])
            .and_then(|()| write_proc_file(first, b"setgroups", b"deny"))
            .and_then(|()| write_proc_file(first, b"uid_map", uid_map))
            .and_then(|()| write_proc_file(first, b"gid_map", gid_map))
            .and_then(|()| mapper.write_all(&[0]));
        if let Err(error) = mapped {
            // SAFETY: `first` is this process's child, which is waiting for its maps.
            unsafe {
                libc::kill(first, libc::SIGKILL);
                libc::waitpid(first, core::ptr::null_mut(), 0);
            }
            return Err(error);
        }
        drop(mapper);
        keep_only_standard_streams_and(status_reader);
        // SAFETY: `first` is this process's child.
        unsafe { libc::waitpid(first, core::ptr::null_mut(), 0) };
        let mut status: libc::c_int = 0;
        // SAFETY: `status` has room for the bytes read.
        let size = unsafe {
            libc::read(
                status_reader,
                (&raw mut status).cast(),
                size_of::<libc::c_int>(),
            )
        };
        if size != size_of::<libc::c_int>().cast_signed() {
            fail(
                b"the namespace's first process ended before reporting the program's status",
                0,
            )
        }
        exit_as(status)
    }

    // This is the namespace's first process.
    drop(mapper);
    // SAFETY: setting the parent-death signal affects only this process.
    check(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) })?;
    // Its parent is outside this PID namespace, so getppid() cannot tell if it died before
    // prctl. A reply to this post-prctl handshake proves the mapper was still alive.
    init.write_all(&[0])?;
    init.read_exact(&mut [0])?;
    drop(init);
    // SAFETY: this process no longer needs the descriptor.
    unsafe { libc::close(status_reader) };
    let program = match fork(0) {
        Ok(program) => program,
        Err(error) => fail(b"forking the program", error.raw_os_error().unwrap_or(0)),
    };
    if program == 0 {
        // SAFETY: the program doesn't need the descriptor.
        unsafe { libc::close(status_writer) };
        // Like LiteBox's initial process, the program starts with only the standard streams, not
        // whatever the test inherited, and leads its own process group and session.
        // SAFETY: marking this process's descriptors close-on-exec affects nothing else.
        let marked = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        };
        check(i32::try_from(marked).unwrap_or(-1))?;
        // SAFETY: `setsid` affects only this process, which leads no group yet.
        return check(unsafe { libc::setsid() });
    }
    keep_only_standard_streams_and(status_writer);
    loop {
        let mut status = 0;
        // SAFETY: `status` has room for a wait status.
        let reaped = unsafe { libc::waitpid(-1, &raw mut status, 0) };
        if reaped == program {
            // SAFETY: `status` holds the bytes written.
            unsafe {
                libc::write(
                    status_writer,
                    (&raw const status).cast(),
                    size_of::<libc::c_int>(),
                );
            }
            exit(0)
        }
        if reaped < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                fail(
                    b"waiting for the program",
                    error.raw_os_error().unwrap_or(0),
                )
            }
        }
    }
}

fn pipe() -> io::Result<[libc::c_int; 2]> {
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for the two descriptors `pipe2` returns.
    check(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;
    Ok(fds)
}

/// Writes `contents` to `/proc/<pid>/<name>`, formatting the path without allocating.
fn write_proc_file(pid: libc::pid_t, name: &[u8], contents: &[u8]) -> io::Result<()> {
    let mut path = [0u8; 64];
    let mut length = 0;
    let mut push = |bytes: &[u8]| {
        path[length..length + bytes.len()].copy_from_slice(bytes);
        length += bytes.len();
    };
    push(b"/proc/");
    push(decimal(pid.cast_unsigned(), &mut [0; 10]));
    push(b"/");
    push(name);
    let path = CStr::from_bytes_until_nul(&path).map_err(|_| io::ErrorKind::InvalidInput)?;
    write_file(path, contents)
}

/// Formats `value` in `digits`, returning the digits used.
fn decimal(mut value: u32, digits: &mut [u8; 10]) -> &[u8] {
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + u8::try_from(value % 10).unwrap_or(0);
        value /= 10;
        if value == 0 {
            break;
        }
    }
    &digits[start..]
}

fn check(result: libc::c_int) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn write_file(path: &CStr, contents: &[u8]) -> io::Result<()> {
    // SAFETY: `path` is a NUL-terminated string.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    check(fd)?;
    // SAFETY: `contents` is valid for reads of its length.
    let written = unsafe { libc::write(fd, contents.as_ptr().cast(), contents.len()) };
    let result = if written < 0 {
        Err(io::Error::last_os_error())
    } else if written.cast_unsigned() != contents.len() {
        Err(io::ErrorKind::WriteZero.into())
    } else {
        Ok(())
    };
    // SAFETY: `fd` is open, and nothing else uses it.
    unsafe { libc::close(fd) };
    result
}

/// Forks, into the new namespaces in `namespaces`, without running `fork` handlers, which may take
/// locks that another thread of the test held when the test forked this process.
fn fork(namespaces: libc::c_int) -> io::Result<libc::pid_t> {
    // SAFETY: a `clone` with only namespace flags and an exit signal creates a copy of this
    // single-threaded process, which only makes system calls until it runs the program or exits.
    let pid = unsafe { libc::syscall(libc::SYS_clone, namespaces | libc::SIGCHLD, 0, 0, 0, 0) };
    if pid < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(libc::pid_t::try_from(pid).unwrap_or(-1))
    }
}

/// Closes every descriptor but the standard streams and `fd`, including the one that tells the
/// test the program started, so that it isn't held open until the program ends.
fn keep_only_standard_streams_and(fd: libc::c_int) {
    let fd = fd.cast_unsigned();
    // SAFETY: closing descriptors this process doesn't use affects nothing else.
    unsafe {
        libc::syscall(libc::SYS_close_range, 3, fd - 1, 0);
        libc::syscall(libc::SYS_close_range, fd + 1, u32::MAX, 0);
    }
}

/// Reports on standard error, without allocating, that running the program failed at `what`, with
/// error number `errno` unless it is 0, and exits with 127.
fn fail(what: &[u8], errno: libc::c_int) -> ! {
    write_stderr(b"native run failed: ");
    write_stderr(what);
    if errno != 0 {
        write_stderr(b": errno ");
        write_stderr(decimal(errno.cast_unsigned(), &mut [0; 10]));
    }
    write_stderr(b"\n");
    exit(127)
}

fn write_stderr(bytes: &[u8]) {
    // SAFETY: `bytes` is valid for reads of its length.
    unsafe { libc::write(libc::STDERR_FILENO, bytes.as_ptr().cast(), bytes.len()) };
}

fn exit(code: libc::c_int) -> ! {
    // SAFETY: `_exit` ends this process without running any of its handlers.
    unsafe { libc::_exit(code) }
}

/// Ends this process as the program did, with wait status `status`.
fn exit_as(status: libc::c_int) -> ! {
    if libc::WIFSIGNALED(status) {
        let signal = libc::WTERMSIG(status);
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: a `sigset_t` is plain data, for which all zeros is valid.
        let mut signals: libc::sigset_t = unsafe { core::mem::zeroed() };
        // SAFETY: these calls only change this process's own limits and signal state, so that the
        // signal ends it, as it ended the program, without leaving a second core dump.
        unsafe {
            libc::setrlimit(libc::RLIMIT_CORE, &raw const no_core);
            libc::signal(signal, libc::SIG_DFL);
            libc::sigemptyset(&raw mut signals);
            libc::sigaddset(&raw mut signals, signal);
            libc::sigprocmask(libc::SIG_UNBLOCK, &raw const signals, core::ptr::null_mut());
            libc::kill(libc::getpid(), signal);
        }
        exit(128 + signal)
    }
    exit(libc::WEXITSTATUS(status))
}
