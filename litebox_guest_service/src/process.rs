// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Spawning processes, their standard streams, and waiting for them.

use std::ffi::{CString, c_char, c_int, c_uint};
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use litebox_guest_service_protocol::guest_service::Process;
use ttrpc::Code;

/// The search path when the environment has none, as runc's.
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// A failed request, as ttrpc answers it.
pub fn status(code: Code, message: impl ToString) -> ttrpc::Error {
    ttrpc::Error::RpcStatus(ttrpc::get_status(code, message))
}

fn os_error(what: &str, error: &io::Error) -> ttrpc::Error {
    status(Code::INTERNAL, format!("{what}: {error}"))
}

/// The host ends of a process's standard streams, non-blocking; a terminal's manager is its
/// stdin and stdout.
pub struct Streams {
    pub stdin: Option<File>,
    pub stdout: File,
    pub stderr: Option<File>,
}

/// The ends of its standard streams that a process gets.
pub enum ChildStdio {
    Pipes([OwnedFd; 3]),
    /// The path of a terminal's subsidiary.
    Terminal(PathBuf),
}

impl Streams {
    /// New pipes, or a new terminal if `process` asks for one.
    pub fn new(process: &Process) -> Result<(Self, ChildStdio), ttrpc::Error> {
        if process.terminal {
            return open_terminal(process)
                .map_err(|error| os_error("cannot open a terminal", &error));
        }
        let pipe = |host_reads: bool| -> io::Result<(File, OwnedFd)> {
            let (reader, writer) = io::pipe()?;
            let (host, child) = if host_reads {
                (OwnedFd::from(reader), OwnedFd::from(writer))
            } else {
                (OwnedFd::from(writer), OwnedFd::from(reader))
            };
            set_nonblocking(host.as_raw_fd())?;
            Ok((File::from(host), child))
        };
        let pipes = (|| Ok::<_, io::Error>((pipe(false)?, pipe(true)?, pipe(true)?)))()
            .map_err(|error| os_error("pipe", &error))?;
        let ((stdin, child_stdin), (stdout, child_stdout), (stderr, child_stderr)) = pipes;
        let streams = Self {
            stdin: Some(stdin),
            stdout,
            stderr: Some(stderr),
        };
        Ok((
            streams,
            ChildStdio::Pipes([child_stdin, child_stdout, child_stderr]),
        ))
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFL and F_SETFL take only integers.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn open_terminal(process: &Process) -> io::Result<(Streams, ChildStdio)> {
    let manager = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
        .open("/dev/ptmx")?;
    let unlocked: c_int = 0;
    let mut index: c_uint = 0;
    // SAFETY: TIOCSPTLCK reads an int, and TIOCGPTN writes an unsigned int, at valid pointers.
    if unsafe { libc::ioctl(manager.as_raw_fd(), libc::TIOCSPTLCK, &raw const unlocked) } < 0
        || unsafe { libc::ioctl(manager.as_raw_fd(), libc::TIOCGPTN, &raw mut index) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    set_window_size(&manager, process.rows, process.columns)?;
    let subsidiary = PathBuf::from(format!("/dev/pts/{index}"));
    let streams = Streams {
        stdin: Some(manager.try_clone()?),
        stdout: manager,
        stderr: None,
    };
    Ok((streams, ChildStdio::Terminal(subsidiary)))
}

/// Sets the size of the terminal of `manager`, which signals its foreground process group.
pub fn set_window_size(manager: &File, rows: u32, columns: u32) -> io::Result<()> {
    let size = libc::winsize {
        ws_row: u16::try_from(rows).unwrap_or(u16::MAX),
        ws_col: u16::try_from(columns).unwrap_or(u16::MAX),
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ reads a `winsize` at a valid pointer.
    if unsafe { libc::ioctl(manager.as_raw_fd(), libc::TIOCSWINSZ, &raw const size) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Waits up to 100 ms until `file` is ready for `events`, so that callers can check whether to
/// stop. Sleeps instead while it only reports a hang-up, which a terminal's manager does while no
/// file is open on its subsidiary.
pub fn wait_ready(file: &File, events: libc::c_short) {
    let mut fd = libc::pollfd {
        fd: file.as_raw_fd(),
        events,
        revents: 0,
    };
    // SAFETY: `fd` is one valid pollfd.
    let ready = unsafe { libc::poll(&raw mut fd, 1, 100) };
    if ready > 0 && fd.revents & events == 0 {
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Resolves `program` as `execvp` does, relative to `cwd`, to an executable file.
fn resolve(program: &str, env: &[String], cwd: &str) -> Option<PathBuf> {
    let cwd = Path::new(cwd);
    // As the guest service's user, as `execve` would check.
    let executable = |path: &PathBuf| {
        let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: `c_path` is a NUL-terminated string.
        std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
            && unsafe { libc::access(c_path.as_ptr(), libc::X_OK) } == 0
    };
    if program.contains('/') {
        return Some(cwd.join(program)).filter(executable);
    }
    let search = env
        .iter()
        .find_map(|var| var.strip_prefix("PATH="))
        .unwrap_or(DEFAULT_PATH);
    search
        .split(':')
        .map(|directory| cwd.join(directory).join(program))
        .find(executable)
}

/// The steps of the child that can fail, as it reports them.
const STAGES: [&str; 4] = [
    "setting up the terminal",
    "redirecting stdio",
    "chdir",
    "execve",
];

/// Forks and execs `process` with `stdio`, and returns its pid once `execve` succeeded. Every
/// descriptor of the guest service is close-on-exec, so the process gets only its stdio.
pub fn spawn(process: &Process, stdio: &ChildStdio) -> Result<libc::pid_t, ttrpc::Error> {
    let invalid = |what: &str| status(Code::INVALID_ARGUMENT, format!("{what} holds a NUL byte"));
    let program = process
        .args
        .first()
        .ok_or_else(|| status(Code::INVALID_ARGUMENT, "no args"))?;
    let path = resolve(program, &process.env, &process.cwd).ok_or_else(|| {
        status(
            Code::NOT_FOUND,
            format!("{program:?}: executable file not found"),
        )
    })?;
    let path = CString::new(path.into_os_string().into_vec()).map_err(|_| invalid("the path"))?;
    let strings = |values: &[String], what| {
        values
            .iter()
            .map(|value| CString::new(value.as_bytes()).map_err(|_| invalid(what)))
            .collect::<Result<Vec<_>, _>>()
    };
    let (arg_strings, env_strings) = (
        strings(&process.args, "args")?,
        strings(&process.env, "env")?,
    );
    let cwd = CString::new(process.cwd.as_bytes()).map_err(|_| invalid("cwd"))?;
    let pointers = |strings: &[CString]| -> Vec<*const c_char> {
        strings
            .iter()
            .map(|s| s.as_ptr())
            .chain([std::ptr::null()])
            .collect()
    };
    let (argv, envp) = (pointers(&arg_strings), pointers(&env_strings));
    let (fds, terminal) = match stdio {
        ChildStdio::Pipes(fds) => (fds.each_ref().map(AsRawFd::as_raw_fd), None),
        ChildStdio::Terminal(path) => {
            let terminal = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOCTTY)
                .open(path)
                .map_err(|error| os_error("cannot open the terminal", &error))?;
            ([terminal.as_raw_fd(); 3], Some(terminal))
        }
    };
    let (mut report, report_writer) = io::pipe().map_err(|error| os_error("pipe", &error))?;
    // SAFETY: the child makes only async-signal-safe calls on data prepared above, then execs or
    // exits.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        child(
            &path,
            &argv,
            &envp,
            &cwd,
            fds,
            terminal.is_some(),
            report_writer.as_raw_fd(),
        );
    }
    if pid < 0 {
        return Err(os_error("fork", &io::Error::last_os_error()));
    }
    drop(report_writer);
    // The report pipe ends at `execve`, being close-on-exec, or carries the failed stage.
    let mut failure = Vec::new();
    let _ = report.read_to_end(&mut failure);
    match *failure {
        [] => Ok(pid),
        [stage, e0, e1, e2, e3, ..] => Err(os_error(
            STAGES.get(usize::from(stage)).copied().unwrap_or("setup"),
            &io::Error::from_raw_os_error(i32::from_ne_bytes([e0, e1, e2, e3])),
        )),
        _ => Err(status(Code::INTERNAL, "a truncated start report")),
    }
}

/// The forked child: async-signal-safe calls only.
fn child(
    path: &CString,
    argv: &[*const c_char],
    envp: &[*const c_char],
    cwd: &CString,
    fds: [RawFd; 3],
    terminal: bool,
    report: RawFd,
) -> ! {
    // SAFETY: these calls take valid pointers to data that outlives them, or integers.
    unsafe {
        let fail = |stage: u8| -> ! {
            let errno = (*libc::__errno_location()).to_ne_bytes();
            let message = [stage, errno[0], errno[1], errno[2], errno[3]];
            libc::write(report, message.as_ptr().cast(), message.len());
            libc::_exit(127)
        };
        if terminal {
            if libc::setsid() < 0 || libc::ioctl(fds[0], libc::TIOCSCTTY, 0) < 0 {
                fail(0);
            }
        } else if libc::setpgid(0, 0) < 0 {
            fail(1);
        }
        for (target, fd) in fds.into_iter().enumerate() {
            if libc::dup2(fd, c_int::try_from(target).unwrap_or_default()) < 0 {
                fail(1);
            }
        }
        // The guest service ignores `SIGPIPE`, as Rust programs do, which `execve` would keep.
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(libc::SIGPIPE, &raw const action, std::ptr::null_mut());
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &raw const empty, std::ptr::null_mut());
        if libc::chdir(cwd.as_ptr()) < 0 {
            fail(2);
        }
        libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        fail(3)
    }
}

/// Waits for any child to end, without blocking if `block` is unset; returns its pid and its
/// status (the exit code, or 128 plus the signal's number), `None` if none ended yet.
pub fn wait_any(block: bool) -> io::Result<Option<(libc::pid_t, i32)>> {
    let mut status: c_int = 0;
    let options = if block { 0 } else { libc::WNOHANG };
    // SAFETY: `status` is a valid, writable int.
    let pid = unsafe { libc::waitpid(-1, &raw mut status, options) };
    match pid {
        0 => Ok(None),
        pid if pid < 0 => Err(io::Error::last_os_error()),
        pid if libc::WIFSIGNALED(status) => Ok(Some((pid, 128 + libc::WTERMSIG(status)))),
        pid => Ok(Some((pid, libc::WEXITSTATUS(status)))),
    }
}

/// Sends `signal` to `pid`; -1 is every guest process but the guest service, LiteBox's process 1.
pub fn kill(pid: libc::pid_t, signal: c_int) -> io::Result<()> {
    // SAFETY: kill takes only integers.
    if unsafe { libc::kill(pid, signal) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A vsock listener on `port`, close-on-exec and non-blocking, as ttrpc's server takes it.
pub fn vsock_listen(port: u32) -> io::Result<OwnedFd> {
    // SAFETY: socket takes only integers; the address is valid for its length.
    unsafe {
        let fd = libc::socket(
            libc::AF_VSOCK,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = OwnedFd::from_raw_fd(fd);
        let mut address: libc::sockaddr_vm = std::mem::zeroed();
        address.svm_family = libc::sa_family_t::try_from(libc::AF_VSOCK).expect("it fits");
        address.svm_port = port;
        address.svm_cid = libc::VMADDR_CID_ANY;
        let length = libc::socklen_t::try_from(size_of::<libc::sockaddr_vm>()).expect("it fits");
        if libc::bind(fd, (&raw const address).cast(), length) < 0 || libc::listen(fd, 1) < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }
}
