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
use std::io;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};

/// Runs a program natively, as [`super::runner::Runner`] runs one in LiteBox: with the environment
/// LiteBox gives the guest, no standard input, and standard error passed through. Its working
/// directory is a new, empty one, which ends with the `Native`, and `TMPDIR` names it, so that a
/// program that uses `TMPDIR`, rather than `/tmp`, keeps its files out of the host's.
pub(crate) struct Native {
    command: Command,
    directory: tempfile::TempDir,
}

impl Native {
    /// Prepares to run `program`, or returns `None`, after reporting why, if the host doesn't let
    /// it run in a namespace of its own (see [`command`]).
    pub(crate) fn new(program: &Path) -> Option<Self> {
        let mut command = command(program)?;
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

/// Returns a command that runs `program` natively in a namespace of its own, or `None`, after
/// reporting why, if the host doesn't let unprivileged users create one.
///
/// The command's exit status is the program's. Natively, a program runs as the second process of
/// its PID namespace, with the namespace's first process as its parent, and leads its own session.
fn command(program: &Path) -> Option<Command> {
    match isolated("true").status() {
        Ok(status) if status.success() => (),
        result => {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI runner must let unprivileged users create user and PID namespaces: {result:?}"
            );
            eprintln!("skipped: no unprivileged user and PID namespaces: {result:?}");
            return None;
        }
    }
    println!("Running `{}` natively", program.display());
    Some(isolated(program))
}

fn isolated(program: impl AsRef<OsStr>) -> Command {
    // SAFETY: `getuid` and `getgid` cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    // The child may not allocate, so the maps are formatted here.
    let uid_map = format!("{uid} {uid} 1");
    let gid_map = format!("{gid} {gid} 1");
    let mut command = Command::new(program);
    // SAFETY: `isolate` only makes async-signal-safe system calls and allocates nothing, and the
    // processes it forks never return from it, except the one that goes on to run the program.
    unsafe {
        command.pre_exec(move || isolate(uid_map.as_bytes(), gid_map.as_bytes()));
    }
    command
}

/// Forks the first process of new user and PID namespaces, mapping the user and group IDs in
/// `uid_map` and `gid_map` in them, and has it fork the process that returns to run the program.
/// Neither of the other two returns: each exits as the program does.
///
/// This process, which stays in the user namespace of the test, writes the maps: Ubuntu's
/// `kernel.apparmor_restrict_unprivileged_userns` denies a process in a new namespace that right.
fn isolate(uid_map: &[u8], gid_map: &[u8]) -> io::Result<()> {
    // Ends the namespace if the test running the program ends early, e.g. on a timeout.
    // SAFETY: setting the parent-death signal affects only this process.
    check(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) })?;
    let [mapped_reader, mapped_writer] = pipe()?;
    let [status_reader, status_writer] = pipe()?;
    let first = fork(libc::CLONE_NEWUSER | libc::CLONE_NEWPID)?;
    if first != 0 {
        // SAFETY: this process no longer needs the descriptors.
        unsafe {
            libc::close(mapped_reader);
            libc::close(status_writer);
        }
        let mapped = write_proc_file(first, b"setgroups", b"deny")
            .and_then(|()| write_proc_file(first, b"uid_map", uid_map))
            .and_then(|()| write_proc_file(first, b"gid_map", gid_map));
        if let Err(error) = mapped {
            // SAFETY: `first` is this process's child, which is waiting for its maps.
            unsafe {
                libc::kill(first, libc::SIGKILL);
                libc::waitpid(first, core::ptr::null_mut(), 0);
            }
            return Err(error);
        }
        // SAFETY: the byte is valid for reads, and nothing else uses the descriptor.
        unsafe {
            libc::write(mapped_writer, [0u8].as_ptr().cast(), 1);
            libc::close(mapped_writer);
        }
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
            // The first process ended before reporting the program's status.
            exit(127)
        }
        exit_as(status)
    }

    // This is the namespace's first process.
    // SAFETY: setting the parent-death signal affects only this process.
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
    let mut mapped = 0u8;
    // SAFETY: `mapped` has room for the byte read, and the descriptors are this process's.
    let size = unsafe {
        libc::close(mapped_writer);
        libc::close(status_reader);
        libc::read(mapped_reader, (&raw mut mapped).cast(), 1)
    };
    if size != 1 {
        exit(127)
    }
    // SAFETY: this process no longer needs the descriptor.
    unsafe { libc::close(mapped_reader) };
    let Ok(program) = fork(0) else { exit(127) };
    if program == 0 {
        // SAFETY: the program doesn't need the descriptor.
        unsafe { libc::close(status_writer) };
        // Like LiteBox's initial process, the program starts with only the standard streams, not
        // whatever the test inherited, and leads its own process group and session.
        // SAFETY: marking this process's descriptors close-on-exec affects nothing else, and
        // `setsid` affects only this process, which leads no group yet.
        unsafe {
            check(libc::syscall(
                libc::SYS_close_range,
                3,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) as libc::c_int)?;
            return check(libc::setsid());
        }
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
        if reaped < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            exit(127)
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
    let mut digits = [0u8; 10];
    let mut start = digits.len();
    let mut rest = pid.cast_unsigned();
    loop {
        start -= 1;
        digits[start] = b'0' + u8::try_from(rest % 10).unwrap_or(0);
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    push(&digits[start..]);
    push(b"/");
    push(name);
    let path = CStr::from_bytes_until_nul(&path).map_err(|_| io::ErrorKind::InvalidInput)?;
    write_file(path, contents)
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
        let mut signals = core::mem::MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: these calls only change this process's own limits and signal state, so that the
        // signal ends it, as it ended the program, without leaving a second core dump.
        unsafe {
            libc::setrlimit(libc::RLIMIT_CORE, &raw const no_core);
            libc::signal(signal, libc::SIG_DFL);
            libc::sigemptyset(signals.as_mut_ptr());
            libc::sigaddset(signals.as_mut_ptr(), signal);
            libc::sigprocmask(libc::SIG_UNBLOCK, signals.as_ptr(), core::ptr::null_mut());
            libc::kill(libc::getpid(), signal);
        }
        exit(128 + signal)
    }
    exit(libc::WEXITSTATUS(status))
}
