// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Pipe bridge tests — extra pipe/socketpair fds across fork+exec, plus
//! pipe non-blocking, pipe pair-id, and non-PIE pipe chain tests.
//!
//! **Test families hosted here:**
//!
//! - `PB.*` — extra pipe/socketpair fd bridging across fork+exec.
//!   Tests the VS Code `child_process.fork()` pattern where extra pipes
//!   beyond stdio (fds 0-2) must survive exec.  In litebox, non-PIE exec
//!   goes through `exec_on_remote_host`, which currently only bridges
//!   unix socket fds.  Regular pipe fds are NOT bridged, causing the
//!   parent to block forever (the code-server ↔ ptyHost IPC bug).
//!
//! - `PN.*` — pipe non-blocking: `O_NONBLOCK` flag, `EAGAIN` on empty
//!   read, data-available read, EOF after writer close, and the
//!   cross-process (dropbear) pattern.
//!
//! - `PID.*` — monotonic pipe pair-id: verifies that successive
//!   `pipe(2)` calls never reuse the same inode after all fds are
//!   closed, catching the litebox ghost-fd pool regression.
//!
//! - `NPIPE.*` — non-PIE pipe chain integrity: sequential and
//!   interleaved PIE+nonPIE `fork`+`exec` whose stdout flows through a
//!   pipe to the parent.
//!
//! - `BPIPE.*` — per-binary-type pipe chain: extends `NPIPE` to all
//!   five `BinaryType` legs.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::agents::{AgentName, SpawnKind};
use super::matrix::{EXEC, ExecArgs};
use super::registry::Registry;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::protocol::Response;
use crate::{register_handler, register_leaf_subcommand};

#[derive(Serialize, Deserialize, Debug)]
struct BashArgs {
    cmd: String,
    timeout_ms: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct BashOut {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

const BASH: HandlerToken<BashArgs, BashOut> = HandlerToken::new("pipe_bridge.bash");

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PipeBridgeOut {
    pub(crate) detail: String,
}

#[derive(Serialize, Deserialize)]
struct ExtraPipeMultiArgs {
    count: usize,
}

#[derive(Serialize, Deserialize)]
struct ExtraSocketpairArgs {}

#[derive(Serialize, Deserialize)]
struct ExtraStdioSocketpairArgs {}

#[derive(Serialize, Deserialize)]
struct EpollPipeBridgeArgs {
    delay_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct EpollSocketpairBridgeArgs {
    delay_ms: u64,
}

const EXTRA_PIPE_MULTI: HandlerToken<ExtraPipeMultiArgs, PipeBridgeOut> =
    HandlerToken::new("pipe_bridge.extra_pipe_multi");
const EXTRA_SOCKETPAIR: HandlerToken<ExtraSocketpairArgs, PipeBridgeOut> =
    HandlerToken::new("pipe_bridge.extra_socketpair");
const EXTRA_STDIO_SOCKETPAIR: HandlerToken<ExtraStdioSocketpairArgs, PipeBridgeOut> =
    HandlerToken::new("pipe_bridge.extra_stdio_socketpair");
/// Phase F bisection: socketpair + fork + parent↔child data, NO exec.
/// Isolates "fork-snapshot restore of broker socketpair endpoint" from
/// "exec_on_remote_host bridge-spec install of broker socketpair endpoint".
/// If PB.sp fails but SP.fork_no_exec passes for the same bt, the bug is in
/// the exec install path; if both fail, the bug is in restore_process.
const FORK_NO_EXEC_SOCKETPAIR: HandlerToken<(), PipeBridgeOut> =
    HandlerToken::new("pipe_bridge.fork_no_exec_socketpair");
const EPOLL_PIPE_BRIDGE: HandlerToken<EpollPipeBridgeArgs, PipeBridgeOut> =
    HandlerToken::new("pipe_bridge.epoll_pipe_bridge");
const EPOLL_SOCKETPAIR_BRIDGE: HandlerToken<EpollSocketpairBridgeArgs, PipeBridgeOut> =
    HandlerToken::new("pipe_bridge.epoll_socketpair_bridge");
pub(crate) const BIDIRECTIONAL: HandlerToken<(), PipeBridgeOut> =
    HandlerToken::new("pipe_bridge.bidirectional");

#[derive(Serialize, Deserialize)]
struct HostFdAttachArgs {
    scenario: HostFdAttachScenario,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HostFdAttachScenario {
    Read,
    Write,
    StdioNoClose,
    ScmRightsFailure,
}

impl HostFdAttachScenario {
    const fn id(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::StdioNoClose => "stdio_no_close",
            Self::ScmRightsFailure => "scm_rights_failure",
        }
    }

    const fn expected(self) -> &'static str {
        match self {
            Self::Read => "HOST_FD_ATTACH_READ_OK",
            Self::Write => "HOST_FD_ATTACH_WRITE_OK",
            Self::StdioNoClose => "HOST_FD_ATTACH_STDIO_OK",
            Self::ScmRightsFailure => "HOST_FD_ATTACH_SCM_RIGHTS_FAILURE_OK",
        }
    }
}

const HOST_FD_ATTACH: HandlerToken<HostFdAttachArgs, PipeBridgeOut> =
    HandlerToken::new("pipe_bridge.host_fd_attach");

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

pub(crate) const fn fork_binary_label(bt: crate::BinaryType) -> &'static str {
    match bt {
        crate::BinaryType::PieGlibc => "self",
        crate::BinaryType::NonPieGlibc => "nonpie",
        crate::BinaryType::StaticPieGlibc => "static-pie-glibc",
        crate::BinaryType::StaticPieMusl => "static-pie-musl",
        crate::BinaryType::NonPieStaticMusl => "non-pie-static-musl",
    }
}

fn label_fragment(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn current_exe_string() -> Result<String, HandlerError> {
    Ok(std::env::current_exe()
        .map_err(|e| HandlerError(format!("current_exe: {e}")))?
        .to_str()
        .ok_or_else(|| HandlerError("current_exe is not UTF-8".into()))?
        .to_string())
}

fn read_with_poll_timeout(fd: i32, timeout_secs: u64) -> (Vec<u8>, bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut all_data = Vec::new();
    let mut buf = [0u8; 4096];
    let mut got_eof = false;

    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout_ms = remaining.as_millis().min(1000) as i32;
        // Safety: pfd points to one valid pollfd and timeout_ms is bounded.
        let poll_ret = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };

        if poll_ret == 0 {
            continue;
        }
        if poll_ret < 0 {
            break;
        }

        // Safety: buf is valid and fd is a test-owned pipe/socket fd.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n == 0 {
            got_eof = true;
            break;
        }
        if n < 0 {
            break;
        }
        all_data.extend_from_slice(&buf[..n as usize]);
    }
    (all_data, got_eof)
}

fn wait_child(pid: i32) -> i32 {
    let mut status = 0i32;
    // Safety: pid is a child pid returned by fork in these tests.
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        99
    }
}

struct PreparedExecv {
    c_exe: std::ffi::CString,
    c_args: Vec<std::ffi::CString>,
    argv_ptrs: Vec<*const libc::c_char>,
}

impl PreparedExecv {
    fn exec(&self) -> ! {
        // Keep the backing CString storage live while execv reads argv.
        let _keepalive = (&self.c_exe, &self.c_args);
        // Safety: c_exe and argv_ptrs are valid nul-terminated C strings.
        unsafe { libc::execv(self.c_exe.as_ptr(), self.argv_ptrs.as_ptr()) };
        // Safety: execv failed; exit without running inherited destructors.
        unsafe { libc::_exit(127) };
    }
}

fn prepare_execv(exe: &str, args: &[&str]) -> PreparedExecv {
    let c_exe = std::ffi::CString::new(exe).unwrap();
    let c_args: Vec<std::ffi::CString> = args
        .iter()
        .map(|a| std::ffi::CString::new(*a).unwrap())
        .collect();
    let mut argv_ptrs: Vec<*const libc::c_char> = Vec::new();
    argv_ptrs.push(c_exe.as_ptr());
    for a in &c_args {
        argv_ptrs.push(a.as_ptr());
    }
    argv_ptrs.push(core::ptr::null());
    PreparedExecv {
        c_exe,
        c_args,
        argv_ptrs,
    }
}

async fn handle_extra_pipe_multi(
    args: ExtraPipeMultiArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    let exe = current_exe_string()?;
    Ok(PipeBridgeOut {
        detail: test_extra_pipe_multi(&exe, args.count),
    })
}

async fn handle_extra_socketpair(
    _args: ExtraSocketpairArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    let exe = current_exe_string()?;
    Ok(PipeBridgeOut {
        detail: test_extra_socketpair(&exe),
    })
}

async fn handle_extra_stdio_socketpair(
    _args: ExtraStdioSocketpairArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    let exe = current_exe_string()?;
    Ok(PipeBridgeOut {
        detail: test_extra_stdio_socketpair(&exe),
    })
}

async fn handle_fork_no_exec_socketpair(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    Ok(PipeBridgeOut {
        detail: test_fork_no_exec_socketpair(),
    })
}

async fn handle_epoll_pipe_bridge(
    args: EpollPipeBridgeArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    let exe = current_exe_string()?;
    Ok(PipeBridgeOut {
        detail: test_epoll_pipe_bridge(&exe, args.delay_ms),
    })
}

async fn handle_epoll_socketpair_bridge(
    args: EpollSocketpairBridgeArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    let exe = current_exe_string()?;
    Ok(PipeBridgeOut {
        detail: test_epoll_socketpair_bridge(&exe, args.delay_ms),
    })
}

async fn handle_bidirectional(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    Ok(PipeBridgeOut {
        detail: test_bidirectional(),
    })
}

async fn handle_host_fd_attach(
    args: HostFdAttachArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    let detail = tokio::task::spawn_blocking(move || test_host_fd_attach(args.scenario))
        .await
        .map_err(|e| HandlerError(format!("host_fd_attach task join: {e}")))?;
    Ok(PipeBridgeOut { detail })
}

fn test_host_fd_attach(scenario: HostFdAttachScenario) -> String {
    match scenario {
        HostFdAttachScenario::Read => test_host_fd_attach_read(),
        HostFdAttachScenario::Write => test_host_fd_attach_write(),
        HostFdAttachScenario::StdioNoClose => test_host_fd_attach_stdio_no_close(),
        HostFdAttachScenario::ScmRightsFailure => test_host_fd_attach_scm_rights_failure(),
    }
}

fn test_host_fd_attach_read() -> String {
    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe_fds points to two writable fd slots.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return format!("HOST_FD_ATTACH_READ_PIPE_FAIL:{}", errno());
    }
    let [rd, wr] = pipe_fds;
    let msg = b"host-fd-attach-read";
    // SAFETY: wr is a live pipe fd and msg is initialized.
    let n = unsafe { libc::write(wr, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
    // SAFETY: parent no longer needs wr.
    unsafe { libc::close(wr) };
    if n != msg.len() as isize {
        // SAFETY: rd is still live and owned here.
        unsafe { libc::close(rd) };
        return format!("HOST_FD_ATTACH_READ_WRITE_FAIL:n={n},errno={}", errno());
    }

    // SAFETY: fork duplicates the single-threaded blocking probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // SAFETY: rd is still live and owned here.
        unsafe { libc::close(rd) };
        return format!("HOST_FD_ATTACH_READ_FORK_FAIL:{}", errno());
    }
    if pid == 0 {
        let mut buf = [0u8; 64];
        // SAFETY: rd is inherited into the child and buf is writable.
        let got = unsafe { libc::read(rd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        let ok = got == msg.len() as isize && &buf[..got as usize] == msg;
        // SAFETY: child exits without running inherited async runtime destructors.
        unsafe { libc::_exit(i32::from(!ok)) };
    }
    // SAFETY: parent releases its read fd after the child inherited it.
    unsafe { libc::close(rd) };
    let exit = wait_child(pid);
    if exit == 0 {
        "HOST_FD_ATTACH_READ_OK".to_string()
    } else {
        format!("HOST_FD_ATTACH_READ_FAIL:exit={exit}")
    }
}

fn test_host_fd_attach_write() -> String {
    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe_fds points to two writable fd slots.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return format!("HOST_FD_ATTACH_WRITE_PIPE_FAIL:{}", errno());
    }
    let [rd, wr] = pipe_fds;
    let msg = b"host-fd-attach-write";
    // SAFETY: fork duplicates the single-threaded blocking probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // SAFETY: cleanup fds owned here.
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
        return format!("HOST_FD_ATTACH_WRITE_FORK_FAIL:{}", errno());
    }
    if pid == 0 {
        // SAFETY: child does not read from rd.
        unsafe { libc::close(rd) };
        // SAFETY: wr is inherited into the child and msg is initialized.
        let n = unsafe { libc::write(wr, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        // SAFETY: child is done with wr.
        unsafe { libc::close(wr) };
        let ok = n == msg.len() as isize;
        // SAFETY: child exits without running inherited async runtime destructors.
        unsafe { libc::_exit(i32::from(!ok)) };
    }
    // SAFETY: parent reads only from rd.
    unsafe { libc::close(wr) };
    let mut buf = [0u8; 64];
    // SAFETY: rd is live and buf is writable.
    let got = unsafe { libc::read(rd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    // SAFETY: parent is done with rd.
    unsafe { libc::close(rd) };
    let exit = wait_child(pid);
    if got == msg.len() as isize && &buf[..got as usize] == msg && exit == 0 {
        "HOST_FD_ATTACH_WRITE_OK".to_string()
    } else {
        format!(
            "HOST_FD_ATTACH_WRITE_FAIL:n={got},exit={exit},errno={}",
            errno()
        )
    }
}

fn test_host_fd_attach_stdio_no_close() -> String {
    let before = [0, 1, 2].map(fd_is_open);
    if before.iter().any(|open| !open) {
        return format!("HOST_FD_ATTACH_STDIO_PRE_CLOSED:{before:?}");
    }
    // SAFETY: fork duplicates the single-threaded blocking probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return format!("HOST_FD_ATTACH_STDIO_FORK_FAIL:{}", errno());
    }
    if pid == 0 {
        let ok = [0, 1, 2].into_iter().all(fd_is_open);
        // SAFETY: child exits without running inherited async runtime destructors.
        unsafe { libc::_exit(i32::from(!ok)) };
    }
    let exit = wait_child(pid);
    let after = [0, 1, 2].map(fd_is_open);
    if exit == 0 && after.iter().all(|open| *open) {
        "HOST_FD_ATTACH_STDIO_OK".to_string()
    } else {
        format!("HOST_FD_ATTACH_STDIO_FAIL:exit={exit},before={before:?},after={after:?}")
    }
}

fn fd_is_open(fd: i32) -> bool {
    // SAFETY: fcntl(F_GETFD) has no pointer arguments and does not consume fd.
    (unsafe { libc::fcntl(fd, libc::F_GETFD) }) >= 0
}

fn test_host_fd_attach_scm_rights_failure() -> String {
    let mut sp = [0i32; 2];
    // SAFETY: sp points to two writable fd slots.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sp.as_mut_ptr()) } != 0 {
        return format!("HOST_FD_ATTACH_SCM_SOCKETPAIR_FAIL:{}", errno());
    }
    let result = send_bogus_scm_rights(sp[0], -1);
    let ok = result.is_err();
    let probe = b"still-alive";
    // SAFETY: sp[0] is a live socket and probe is initialized.
    let wrote = unsafe { libc::write(sp[0], probe.as_ptr().cast::<libc::c_void>(), probe.len()) };
    let mut buf = [0u8; 32];
    // SAFETY: sp[1] is a live socket and buf is writable.
    let read = unsafe { libc::read(sp[1], buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    // SAFETY: cleanup owned socketpair fds.
    unsafe {
        libc::close(sp[0]);
        libc::close(sp[1]);
    }
    if ok
        && wrote == probe.len() as isize
        && read == probe.len() as isize
        && &buf[..read as usize] == probe
    {
        "HOST_FD_ATTACH_SCM_RIGHTS_FAILURE_OK".to_string()
    } else {
        format!(
            "HOST_FD_ATTACH_SCM_RIGHTS_FAILURE_FAIL:send={result:?},wrote={wrote},read={read},errno={}",
            errno()
        )
    }
}

fn send_bogus_scm_rights(sock: i32, bogus_fd: i32) -> Result<(), i32> {
    let byte = [b'X'];
    let mut iov = libc::iovec {
        iov_base: byte.as_ptr().cast::<libc::c_void>().cast_mut(),
        iov_len: byte.len(),
    };
    let mut control = [0u8; 64];
    // SAFETY: zeroed msghdr is filled before sendmsg.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = control.len().try_into().unwrap();
    // SAFETY: msg/control form a valid SCM_RIGHTS control buffer.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(libc::EINVAL);
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as _;
        libc::CMSG_DATA(cmsg).cast::<i32>().write(bogus_fd);
        msg.msg_controllen = (*cmsg).cmsg_len;
        let rc = libc::sendmsg(sock, &raw const msg, 0);
        if rc == -1 { Err(errno()) } else { Ok(()) }
    }
}

fn test_extra_pipe_multi(exe: &str, count: usize) -> String {
    let mut pipes: Vec<[i32; 2]> = Vec::new();
    for i in 0..count {
        let mut fds = [0i32; 2];
        // Safety: fds points to two valid i32 slots for pipe to fill.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return format!("PB_MULTI_PIPE_FAIL:pipe={i},errno={}", errno());
        }
        pipes.push(fds);
    }
    let write_fds: Vec<String> = pipes.iter().map(|fds| fds[1].to_string()).collect();
    let fd_list = write_fds.join(",");
    let child_exec = prepare_execv(exe, &["pipe-test", "write-on-fd", &fd_list]);

    // Safety: this test process is single-threaded for this fork/exec probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return format!("PB_MULTI_FORK_FAIL:{}", errno());
    }

    if pid == 0 {
        for fds in &pipes {
            // Safety: fds[0] is a valid fd returned by pipe.
            unsafe { libc::close(fds[0]) };
        }
        child_exec.exec();
    }

    for fds in &pipes {
        // Safety: fds[1] is a valid fd returned by pipe.
        unsafe { libc::close(fds[1]) };
    }

    let mut ok_count = 0;
    for fds in &pipes {
        let (data, _got_eof) = read_with_poll_timeout(fds[0], 15);
        // Safety: fds[0] is a valid fd returned by pipe.
        unsafe { libc::close(fds[0]) };
        let text = String::from_utf8_lossy(&data);
        if text.contains("PB_CHILD_WROTE") {
            ok_count += 1;
        }
    }

    let exit_code = wait_child(pid);
    if ok_count == count && exit_code == 0 {
        format!("PB_MULTI_OK:{count}")
    } else {
        format!("PB_MULTI_FAIL:ok={ok_count}/{count},exit={exit_code}")
    }
}

fn test_extra_socketpair(exe: &str) -> String {
    let mut fds = [0i32; 2];
    // Safety: fds points to two valid i32 slots for socketpair to fill.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
        return format!("PB_SP_SOCKETPAIR_FAIL:{}", errno());
    }
    let fd_str = fds[1].to_string();
    let child_exec = prepare_execv(exe, &["pipe-test", "echo-on-fd", &fd_str]);

    // Safety: this test process is single-threaded for this fork/exec probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return format!("PB_SP_FORK_FAIL:{}", errno());
    }

    if pid == 0 {
        // Safety: fds[0] is a valid fd returned by socketpair.
        unsafe { libc::close(fds[0]) };
        child_exec.exec();
    }

    // Safety: fds[1] is a valid fd returned by socketpair.
    unsafe { libc::close(fds[1]) };

    let msg = b"PB_SP_PING";
    // Safety: fds[0] is valid and msg points to initialized bytes.
    let written = unsafe { libc::write(fds[0], msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
    if written < 0 {
        return format!("PB_SP_WRITE_FAIL:{}", errno());
    }

    let (data, _) = read_with_poll_timeout(fds[0], 15);
    // Safety: fds[0] is a valid fd returned by socketpair.
    unsafe { libc::close(fds[0]) };

    let exit_code = wait_child(pid);
    let text = String::from_utf8_lossy(&data);

    if text.contains("PB_SP_PING") && exit_code == 0 {
        "PB_SP_OK".to_string()
    } else if data.is_empty() {
        format!("PB_SP_FAIL:no_data,exit={exit_code}")
    } else {
        format!("PB_SP_FAIL:exit={exit_code},data={text}")
    }
}

fn test_extra_stdio_socketpair(exe: &str) -> String {
    let mut stdin_pair = [0i32; 2];
    let mut stdout_pair = [0i32; 2];
    let mut stderr_pair = [0i32; 2];
    for (name, pair) in [
        ("stdin", &mut stdin_pair),
        ("stdout", &mut stdout_pair),
        ("stderr", &mut stderr_pair),
    ] {
        // Safety: pair points to two valid i32 slots for socketpair to fill.
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) } != 0
        {
            return format!("PB_STDIO_SP_SOCKETPAIR_FAIL:{name}:{}", errno());
        }
    }
    let child_exec = prepare_execv(exe, &["pipe-test", "stdio-echo"]);

    // Safety: this test process is single-threaded for this fork/exec probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return format!("PB_STDIO_SP_FORK_FAIL:{}", errno());
    }

    if pid == 0 {
        // Safety: close parent ends, dup child ends onto stdio, then exec.
        unsafe {
            libc::close(stdin_pair[0]);
            libc::close(stdout_pair[0]);
            libc::close(stderr_pair[0]);
            if libc::dup2(stdin_pair[1], 0) < 0
                || libc::dup2(stdout_pair[1], 1) < 0
                || libc::dup2(stderr_pair[1], 2) < 0
            {
                libc::_exit(126);
            }
            for fd in [stdin_pair[1], stdout_pair[1], stderr_pair[1]] {
                if fd > 2 {
                    libc::close(fd);
                }
            }
        }
        child_exec.exec();
    }

    // Safety: parent owns the fd 0 ends after fork.
    unsafe {
        libc::close(stdin_pair[1]);
        libc::close(stdout_pair[1]);
        libc::close(stderr_pair[1]);
    }

    let input = b"PB_STDIO_SOCKETPAIR_IN";
    // Safety: stdin_pair[0] is live and input is initialized.
    let written = unsafe {
        libc::write(
            stdin_pair[0],
            input.as_ptr().cast::<libc::c_void>(),
            input.len(),
        )
    };
    // Safety: shutting down writes on the parent end lets the child see EOF after input.
    unsafe { libc::shutdown(stdin_pair[0], libc::SHUT_WR) };
    if written != input.len() as isize {
        return format!("PB_STDIO_SP_WRITE_FAIL:n={written},errno={}", errno());
    }

    let (stdout_data, _) = read_with_poll_timeout(stdout_pair[0], 15);
    let (stderr_data, _) = read_with_poll_timeout(stderr_pair[0], 15);
    // Safety: parent is done with its socket ends.
    unsafe {
        libc::close(stdin_pair[0]);
        libc::close(stdout_pair[0]);
        libc::close(stderr_pair[0]);
    }
    let exit_code = wait_child(pid);
    let stdout_text = String::from_utf8_lossy(&stdout_data);
    let stderr_text = String::from_utf8_lossy(&stderr_data);
    if exit_code == 0
        && stdout_text.contains("PB_STDIO_SOCKETPAIR_OUT:PB_STDIO_SOCKETPAIR_IN")
        && stderr_text.contains("PB_STDIO_SOCKETPAIR_ERR")
    {
        "PB_STDIO_SOCKETPAIR_OK".to_string()
    } else {
        format!(
            "PB_STDIO_SOCKETPAIR_FAIL:exit={exit_code},stdout={stdout_text:?},stderr={stderr_text:?}"
        )
    }
}

/// Phase F bisection: socketpair + fork + parent↔child data, **NO execve**.
/// Returns "SP_FORK_NO_EXEC_OK" on success, else a structured failure
/// string identifying which step broke (socketpair, fork, read, write,
/// or echo-mismatch). Failure modes:
///
/// * `SP_FNE_SOCKETPAIR_FAIL:<errno>` — initial socketpair() failed.
/// * `SP_FNE_FORK_FAIL:<errno>` — fork() failed.
/// * `SP_FNE_PARENT_WRITE_FAIL:<errno>` — parent write returned -1 (EIO etc).
/// * `SP_FNE_PARENT_WRITE_SHORT:<n>` — write returned partial count.
/// * `SP_FNE_PARENT_READ_FAIL:<n_or_errno>` — parent read failed/timed out.
/// * `SP_FNE_CHILD_EXIT:<code>` — child exited non-zero (its read/write failed).
/// * `SP_FNE_MISMATCH:<actual>` — data round-trip data didn't match.
fn test_fork_no_exec_socketpair() -> String {
    let mut fds = [0i32; 2];
    // Safety: fds points to two valid i32 slots for socketpair to fill.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
        return format!("SP_FNE_SOCKETPAIR_FAIL:{}", errno());
    }

    // Safety: this test process is single-threaded for this fork probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return format!("SP_FNE_FORK_FAIL:{}", errno());
    }

    if pid == 0 {
        // Child: close parent's end, read PING, write PONG, exit.
        // No execve — child re-enters the test_fork_no_exec_socketpair
        // function context after fork, but since this is the child it
        // hits this branch and exits cleanly.
        // Safety: fds[0] is a valid fd returned by socketpair.
        unsafe { libc::close(fds[0]) };
        let mut buf = [0u8; 16];
        // Safety: fds[1] is valid, buf is initialized.
        let n = unsafe { libc::read(fds[1], buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n != 4 {
            // Safety: process exit.
            unsafe { libc::_exit(10) };
        }
        if &buf[..4] != b"PING" {
            // Safety: process exit.
            unsafe { libc::_exit(11) };
        }
        let msg = b"PONG";
        // Safety: fds[1] valid, msg initialized.
        let n = unsafe { libc::write(fds[1], msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        if n != 4 {
            // Safety: process exit.
            unsafe { libc::_exit(12) };
        }
        // Safety: process exit.
        unsafe { libc::_exit(0) };
    }

    // Parent: close child's end, write PING, read PONG, wait child.
    // Safety: fds[1] is a valid fd returned by socketpair.
    unsafe { libc::close(fds[1]) };
    let msg = b"PING";
    // Safety: fds[0] valid, msg initialized.
    let written = unsafe { libc::write(fds[0], msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
    if written < 0 {
        return format!("SP_FNE_PARENT_WRITE_FAIL:{}", errno());
    }
    if written != 4 {
        return format!("SP_FNE_PARENT_WRITE_SHORT:{written}");
    }
    let (data, _eof) = read_with_poll_timeout(fds[0], 10);
    // Safety: fds[0] is a valid fd returned by socketpair.
    unsafe { libc::close(fds[0]) };
    let exit_code = wait_child(pid);
    if exit_code != 0 {
        return format!("SP_FNE_CHILD_EXIT:{exit_code}");
    }
    if data.len() < 4 {
        return format!("SP_FNE_PARENT_READ_FAIL:{}", data.len());
    }
    if &data[..4] != b"PONG" {
        let text = String::from_utf8_lossy(&data[..data.len().min(16)]);
        return format!("SP_FNE_MISMATCH:{text}");
    }
    "SP_FORK_NO_EXEC_OK".to_string()
}

fn test_epoll_pipe_bridge(exe: &str, delay_ms: u64) -> String {
    let mut pipe_fds = [0i32; 2];
    // Safety: pipe_fds points to two valid i32 slots for pipe to fill.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return format!("EPOLL_BRIDGE_PIPE_FAIL:{}", errno());
    }
    let wfd_str = pipe_fds[1].to_string();
    let delay = delay_ms.to_string();
    let child_exec = prepare_execv(exe, &["pipe-test", "delayed-write-on-fd", &wfd_str, &delay]);

    // Safety: this test process is single-threaded for this fork/exec probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return format!("EPOLL_BRIDGE_FORK_FAIL:{}", errno());
    }

    if pid == 0 {
        // Safety: pipe_fds[0] is a valid fd returned by pipe.
        unsafe { libc::close(pipe_fds[0]) };
        child_exec.exec();
    }

    // Safety: pipe_fds[1] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[1]) };

    // Safety: pipe_fds[0] is valid; fcntl gets/sets status flags.
    unsafe {
        let flags = libc::fcntl(pipe_fds[0], libc::F_GETFL);
        libc::fcntl(pipe_fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    // Safety: epoll_create1 is called with valid flags.
    let epfd = unsafe { libc::epoll_create1(0) };
    if epfd < 0 {
        return format!("EPOLL_BRIDGE_EPOLL_FAIL:{}", errno());
    }

    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: pipe_fds[0] as u64,
    };
    // Safety: epfd, pipe_fds[0], and ev are valid.
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, pipe_fds[0], &raw mut ev) } != 0 {
        return format!("EPOLL_BRIDGE_CTL_FAIL:{}", errno());
    }

    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let t0 = std::time::Instant::now();
    // Safety: epfd is valid and events has capacity for one event.
    let nev = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 1, 10_000) };
    let elapsed_ms = t0.elapsed().as_millis();

    // Safety: epfd is a valid fd.
    unsafe { libc::close(epfd) };

    if nev > 0 && (events[0].events & libc::EPOLLIN as u32) != 0 {
        let mut buf = [0u8; 256];
        // Safety: pipe_fds[0] is valid and buf is initialized writable memory.
        let n = unsafe {
            libc::read(
                pipe_fds[0],
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        // Safety: pipe_fds[0] is a valid fd.
        unsafe { libc::close(pipe_fds[0]) };
        wait_child(pid);

        let data = if n > 0 {
            String::from_utf8_lossy(&buf[..n as usize]).to_string()
        } else {
            String::new()
        };

        if data.contains("PB_DELAYED_WRITE") && elapsed_ms < 5000 {
            format!("EPOLL_BRIDGE_OK:{elapsed_ms}ms")
        } else {
            format!(
                "EPOLL_BRIDGE_FAIL:data={},elapsed={elapsed_ms}ms",
                data.trim()
            )
        }
    } else if nev == 0 {
        // Safety: pipe_fds[0] is a valid fd.
        unsafe { libc::close(pipe_fds[0]) };
        wait_child(pid);
        format!("EPOLL_BRIDGE_TIMEOUT:epoll_wait returned 0 after {elapsed_ms}ms (wakeup broken)")
    } else {
        // Safety: pipe_fds[0] is a valid fd.
        unsafe { libc::close(pipe_fds[0]) };
        wait_child(pid);
        format!("EPOLL_BRIDGE_ERROR:epoll_wait={nev},errno={}", errno())
    }
}

fn test_epoll_socketpair_bridge(exe: &str, delay_ms: u64) -> String {
    let mut fds = [0i32; 2];
    // Safety: fds points to two valid i32 slots for socketpair to fill.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
        return format!("EPOLL_SP_SOCKETPAIR_FAIL:{}", errno());
    }
    let fd_str = fds[1].to_string();
    let delay = delay_ms.to_string();
    let child_exec = prepare_execv(exe, &["pipe-test", "delayed-write-on-fd", &fd_str, &delay]);

    // Safety: this test process is single-threaded for this fork/exec probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return format!("EPOLL_SP_FORK_FAIL:{}", errno());
    }

    if pid == 0 {
        // Safety: fds[0] is a valid fd returned by socketpair.
        unsafe { libc::close(fds[0]) };
        child_exec.exec();
    }

    // Safety: fds[1] is a valid fd returned by socketpair.
    unsafe { libc::close(fds[1]) };

    // Safety: fds[0] is valid; fcntl gets/sets status flags.
    unsafe {
        let flags = libc::fcntl(fds[0], libc::F_GETFL);
        libc::fcntl(fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    // Safety: epoll_create1 is called with valid flags.
    let epfd = unsafe { libc::epoll_create1(0) };
    if epfd < 0 {
        return format!("EPOLL_SP_EPOLL_FAIL:{}", errno());
    }

    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: fds[0] as u64,
    };
    // Safety: epfd, fds[0], and ev are valid.
    if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fds[0], &raw mut ev) } != 0 {
        return format!("EPOLL_SP_CTL_FAIL:{}", errno());
    }

    let mut spin_count: u32 = 0;
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let t0 = std::time::Instant::now();
    let deadline = t0 + std::time::Duration::from_secs(10);

    loop {
        let remaining_ms = deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis()
            .min(1000) as i32;
        if remaining_ms == 0 {
            break;
        }

        // Safety: epfd is valid and events has capacity for one event.
        let nev = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 1, remaining_ms) };

        if nev > 0 && (events[0].events & libc::EPOLLIN as u32) != 0 {
            let elapsed_ms = t0.elapsed().as_millis();
            let mut buf = [0u8; 256];
            // Safety: fds[0] is valid and buf is initialized writable memory.
            let n =
                unsafe { libc::read(fds[0], buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            // Safety: fds[0] and epfd are valid fds.
            unsafe {
                libc::close(fds[0]);
                libc::close(epfd);
            }
            wait_child(pid);
            let data = if n > 0 {
                String::from_utf8_lossy(&buf[..n as usize]).to_string()
            } else {
                String::new()
            };
            if data.contains("PB_DELAYED_WRITE") && elapsed_ms < 5000 && spin_count < 50 {
                return format!("EPOLL_SP_OK:{elapsed_ms}ms,spins={spin_count}");
            }
            return format!(
                "EPOLL_SP_FAIL:elapsed={elapsed_ms}ms,spins={spin_count},data={}",
                data.trim()
            );
        } else if nev == 0 {
            spin_count += 1;
        } else {
            break;
        }
    }

    // Safety: fds[0] and epfd are valid fds.
    unsafe {
        libc::close(fds[0]);
        libc::close(epfd);
    }
    wait_child(pid);
    let elapsed_ms = t0.elapsed().as_millis();
    format!("EPOLL_SP_TIMEOUT:elapsed={elapsed_ms}ms,spins={spin_count} (wakeup broken)")
}

fn test_bidirectional() -> String {
    let sock_path = "/tmp/litebox-us3-test.sock";
    let _ = std::fs::remove_file(sock_path);

    // Safety: this test process is single-threaded for this fork probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return format!("US3_FORK_FAIL:{}", errno());
    }

    if pid == 0 {
        let listener = match UnixListener::bind(sock_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[US3-server] bind: {e}");
                std::process::exit(1);
            }
        };
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buf = [0u8; 64];
                let n = stream.read(&mut buf).unwrap_or(0);
                let _ = stream.write_all(b"SERVER_DATA");
                let msg = std::str::from_utf8(&buf[..n]).unwrap_or("?");
                std::process::exit(if msg == "CLIENT_DATA" { 0 } else { 2 });
            }
            Err(_) => std::process::exit(3),
        }
    }

    std::thread::sleep(std::time::Duration::from_millis(200));
    let mut stream = None;
    for _ in 0..10 {
        if let Ok(s) = UnixStream::connect(sock_path) {
            stream = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let Some(mut stream) = stream else {
        let _ = wait_child(pid);
        return "US3_CONNECT_FAIL".to_string();
    };

    let _ = stream.write_all(b"CLIENT_DATA");
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).unwrap_or(0);
    let reply = std::str::from_utf8(&buf[..n]).unwrap_or("?").to_string();
    drop(stream);

    let exit_code = wait_child(pid);
    let _ = std::fs::remove_file(sock_path);

    if reply == "SERVER_DATA" && exit_code == 0 {
        "US3_BIDI_OK".to_string()
    } else {
        format!("US3_BIDI_FAIL:reply={reply},exit={exit_code}")
    }
}

async fn handle_bash(args: BashArgs, _ctx: &mut HandlerCtx<'_>) -> Result<BashOut, HandlerError> {
    let output = tokio::time::timeout(
        Duration::from_millis(u64::from(args.timeout_ms)),
        tokio::process::Command::new("bash")
            .arg("-c")
            .arg(&args.cmd)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| HandlerError(format!("bash timed out after {} ms", args.timeout_ms)))??;

    Ok(BashOut {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code().unwrap_or(-1),
    })
}

fn bash_cmd(args: &[String]) -> String {
    args.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'='))
    {
        return arg.to_string();
    }

    format!("'{}'", arg.replace('\'', "'\\''"))
}

fn timeout_ms(seconds: u64) -> u32 {
    seconds.saturating_mul(1000).min(u64::from(u32::MAX)) as u32
}

/// Agents for pipe bridge tests.  Includes depths 1-2 and the
/// non-PIE worker agent (NP) to test nested worker-exec.
const PB_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2];

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_pipe_bridge(reg: &mut Registry<'_>) {
    register_handler!(BASH, handle_bash);
    register_handler!(EXTRA_PIPE_MULTI, handle_extra_pipe_multi);
    register_handler!(EXTRA_SOCKETPAIR, handle_extra_socketpair);
    register_handler!(EXTRA_STDIO_SOCKETPAIR, handle_extra_stdio_socketpair);
    register_handler!(FORK_NO_EXEC_SOCKETPAIR, handle_fork_no_exec_socketpair);
    register_handler!(EPOLL_PIPE_BRIDGE, handle_epoll_pipe_bridge);
    register_handler!(EPOLL_SOCKETPAIR_BRIDGE, handle_epoll_socketpair_bridge);
    register_handler!(BIDIRECTIONAL, handle_bidirectional);
    register_handler!(HOST_FD_ATTACH, handle_host_fd_attach);
    register_leaf_subcommand!("pipe-test", subcmd_pipe_test);
    // Also expose `bidirectional` as an argv subcommand for the
    // US3 test family. The leaf-agent form (via run_leaf on
    // BIDIRECTIONAL) times out under litebox for PIE-glibc — the
    // test internally does libc::fork inside the leaf agent's
    // handler, which interacts poorly with the litebox shim for
    // some binary types. The argv form preserves the pre-wave-8
    // semantics (test runs in a fresh exec'd subcommand child).
    register_leaf_subcommand!("bidirectional", |_args: &[String]| -> i32 {
        let out = test_bidirectional();
        println!("{out}");
        if out == "US3_BIDI_OK" { 0 } else { 1 }
    });

    reg.test(
        "xworker",
        "pipe_bridge",
        "PB.stdio_sp_lockstep.nonpie-glibc.dpg1",
    )
    .timeout(90)
    .build(|cx| {
        let leaf = cx.declare_ephemeral(
            AgentName::Dpg1,
            "Pb_stdio_sp_lockstep_nonpie",
            SpawnKind::Fork {
                binary: "nonpie",
                inherit_listen_ports: vec![],
            },
        );
        Box::new(move |run| {
            Box::pin(async move {
                let detail = run
                    .run_leaf(&leaf, &EXTRA_STDIO_SOCKETPAIR, ExtraStdioSocketpairArgs {})
                    .await
                    .map(|out| out.detail);
                let pass = matches!(&detail, Ok(s) if s == "PB_STDIO_SOCKETPAIR_OK");
                super::TestOutcome::new("dpg1", pass, format!("{detail:?}"))
            })
        })
    });

    for scenario in [
        HostFdAttachScenario::Read,
        HostFdAttachScenario::Write,
        HostFdAttachScenario::StdioNoClose,
        HostFdAttachScenario::ScmRightsFailure,
    ] {
        for &agent in NPIPE_AGENTS {
            let agent_s = agent.to_string();
            let id = format!("PB.host_fd_attach.{}.{agent}", scenario.id());
            reg.test("xworker", "pipe_bridge", id)
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        Box::pin(async move {
                            let result = run
                                .send_named_typed(
                                    &handle,
                                    &HOST_FD_ATTACH,
                                    HostFdAttachArgs { scenario },
                                )
                                .await;
                            let pass =
                                matches!(&result, Ok(out) if out.detail == scenario.expected());
                            super::TestOutcome::new(&a, pass, format!("{result:?}"))
                        })
                    })
                });
        }
    }

    struct PbCase {
        mode: &'static str,
        subcmd: &'static str,
        extra_args: &'static [&'static str],
        expected: &'static str,
        agents: &'static [AgentName],
        timeout: u64,
    }

    const XWORKER_AGENTS: &[AgentName] = &[AgentName::Dpg1Dng];

    let cases: &[PbCase] = &[
        PbCase {
            mode: "c2p",
            subcmd: "extra-pipe-c2p",
            extra_args: &[],
            expected: "PB_C2P_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "p2c",
            subcmd: "extra-pipe-p2c",
            extra_args: &[],
            expected: "PB_P2C_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "multi",
            subcmd: "extra-pipe-multi",
            extra_args: &["3"],
            expected: "PB_MULTI_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "sp",
            subcmd: "extra-socketpair",
            extra_args: &[],
            expected: "PB_SP_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "c2p.xworker",
            subcmd: "extra-pipe-c2p",
            extra_args: &[],
            expected: "PB_C2P_OK",
            agents: XWORKER_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "many",
            subcmd: "extra-pipe-multi",
            extra_args: &["10"],
            expected: "PB_MULTI_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "epoll",
            subcmd: "epoll-pipe-bridge",
            extra_args: &["200"],
            expected: "EPOLL_BRIDGE_OK",
            agents: PB_AGENTS,
            timeout: 15,
        },
        PbCase {
            mode: "epoll_sp",
            subcmd: "epoll-socketpair-bridge",
            extra_args: &["500"],
            expected: "EPOLL_SP_OK",
            agents: PB_AGENTS,
            timeout: 15,
        },
    ];

    for case in cases {
        for &bt in crate::BinaryType::ALL {
            let bt_label = bt.label();
            for &agent in case.agents {
                let id = format!("PB.{}.{bt_label}.{agent}", case.mode);
                let subcmd = case.subcmd.to_string();
                let extra: Vec<String> = case
                    .extra_args
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                let expected = case.expected.to_string();
                let timeout = case.timeout;
                let agent_label = agent.to_string();

                reg.test("xworker", "pipe_bridge", id)
                    .timeout(90)
                    .build(move |cx| {
                        let migrated = matches!(
                            subcmd.as_str(),
                            "extra-pipe-multi"
                                | "extra-socketpair"
                                | "epoll-pipe-bridge"
                                | "epoll-socketpair-bridge"
                        );
                        let handle = (!migrated).then(|| cx.require(agent));
                        let leaf = migrated.then(|| {
                            cx.declare_ephemeral(
                                agent,
                                format!("Pb_{}_{}", label_fragment(&case.mode), bt.short_label()),
                                SpawnKind::Fork {
                                    binary: fork_binary_label(bt),
                                    inherit_listen_ports: vec![],
                                },
                            )
                        });
                        Box::new(move |run| {
                            let extra = extra.clone();
                            let agent_label = agent_label.clone();
                            let handle = handle.clone();
                            let leaf = leaf.clone();
                            Box::pin(async move {
                                let detail = match subcmd.as_str() {
                                    "extra-pipe-multi" => {
                                        let count =
                                            extra.first().and_then(|s| s.parse().ok()).unwrap_or(3);
                                        run.run_leaf(
                                            leaf.as_ref().expect("migrated leaf"),
                                            &EXTRA_PIPE_MULTI,
                                            ExtraPipeMultiArgs { count },
                                        )
                                        .await
                                        .map(|out| out.detail)
                                    }
                                    "extra-socketpair" => run
                                        .run_leaf(
                                            leaf.as_ref().expect("migrated leaf"),
                                            &EXTRA_SOCKETPAIR,
                                            ExtraSocketpairArgs {},
                                        )
                                        .await
                                        .map(|out| out.detail),
                                    "epoll-pipe-bridge" => {
                                        let delay_ms = extra
                                            .first()
                                            .and_then(|s| s.parse().ok())
                                            .unwrap_or(200);
                                        run.run_leaf(
                                            leaf.as_ref().expect("migrated leaf"),
                                            &EPOLL_PIPE_BRIDGE,
                                            EpollPipeBridgeArgs { delay_ms },
                                        )
                                        .await
                                        .map(|out| out.detail)
                                    }
                                    "epoll-socketpair-bridge" => {
                                        let delay_ms = extra
                                            .first()
                                            .and_then(|s| s.parse().ok())
                                            .unwrap_or(500);
                                        run.run_leaf(
                                            leaf.as_ref().expect("migrated leaf"),
                                            &EPOLL_SOCKETPAIR_BRIDGE,
                                            EpollSocketpairBridgeArgs { delay_ms },
                                        )
                                        .await
                                        .map(|out| out.detail)
                                    }
                                    _ => {
                                        let self_exe = run.self_exe().to_string();
                                        let child_bin = crate::binary_path(bt, &self_exe);
                                        let mut args =
                                            vec![self_exe, "pipe-test".into(), subcmd, child_bin];
                                        args.extend(extra);
                                        run.send_named_typed(
                                            handle.as_ref().expect("argv handle"),
                                            &BASH,
                                            BashArgs {
                                                cmd: bash_cmd(&args),
                                                timeout_ms: timeout_ms(timeout),
                                            },
                                        )
                                        .await
                                        .map(|out| {
                                            if out.exit_code == 0 {
                                                out.stdout
                                            } else {
                                                format!(
                                                    "exit={} stdout={} stderr={}",
                                                    out.exit_code, out.stdout, out.stderr
                                                )
                                            }
                                        })
                                        .map_err(|e| format!("{e:?}"))
                                    }
                                };
                                let pass = matches!(&detail, Ok(s) if s.contains(&*expected));
                                super::TestOutcome::new(&agent_label, pass, format!("{detail:?}"))
                            })
                        })
                    });
            }
        }
    }

    for &(mode, subcmd, expected) in &[
        ("sibling_dual.c2p", "extra-pipe-c2p", "PB_C2P_OK"),
        ("sibling_dual.p2c", "extra-pipe-p2c", "PB_P2C_OK"),
        ("sibling_dual.sp", "extra-socketpair", "PB_SP_OK"),
    ] {
        let id = format!("PB.{mode}");
        reg.test("xworker", "pipe_bridge", id)
            .timeout(90)
            .build(move |cx| {
                let migrated = subcmd == "extra-socketpair";
                let left = (!migrated).then(|| cx.require(AgentName::Dpg1Dpg1));
                let right = (!migrated).then(|| cx.require(AgentName::Dpg1Dpg2));
                let left_leaf = migrated.then(|| {
                    cx.declare_ephemeral(
                        AgentName::Dpg1Dpg1,
                        format!("Pb_{}_left", label_fragment(mode)),
                        SpawnKind::Fork {
                            binary: "self",
                            inherit_listen_ports: vec![],
                        },
                    )
                });
                let right_leaf = migrated.then(|| {
                    cx.declare_ephemeral(
                        AgentName::Dpg1Dpg2,
                        format!("Pb_{}_right", label_fragment(mode)),
                        SpawnKind::Fork {
                            binary: "self",
                            inherit_listen_ports: vec![],
                        },
                    )
                });
                Box::new(move |run| {
                    let left = left.clone();
                    let right = right.clone();
                    let left_leaf = left_leaf.clone();
                    let right_leaf = right_leaf.clone();
                    Box::pin(async move {
                        if migrated {
                            let left_resp = run
                                .run_leaf(
                                    left_leaf.as_ref().expect("left leaf"),
                                    &EXTRA_SOCKETPAIR,
                                    ExtraSocketpairArgs {},
                                )
                                .await
                                .map(|out| out.detail);
                            let right_resp = run
                                .run_leaf(
                                    right_leaf.as_ref().expect("right leaf"),
                                    &EXTRA_SOCKETPAIR,
                                    ExtraSocketpairArgs {},
                                )
                                .await
                                .map(|out| out.detail);
                            let left_ok = matches!(&left_resp, Ok(out) if out.trim() == expected);
                            let right_ok = matches!(&right_resp, Ok(out) if out.trim() == expected);
                            return super::TestOutcome::new(
                                "AA+AB",
                                left_ok && right_ok,
                                format!("left={left_resp:?} right={right_resp:?}"),
                            );
                        }

                        let self_exe = run.self_exe().to_string();
                        let args = |subcmd: &str| {
                            vec![
                                self_exe.clone(),
                                "pipe-test".into(),
                                subcmd.to_string(),
                                self_exe.clone(),
                            ]
                        };
                        let left_args = args(subcmd);
                        let left_resp = run
                            .send_named_typed(
                                left.as_ref().expect("left argv handle"),
                                &BASH,
                                BashArgs {
                                    cmd: bash_cmd(&left_args),
                                    timeout_ms: timeout_ms(20),
                                },
                            )
                            .await;
                        let right_args = args(subcmd);
                        let right_resp = run
                            .send_named_typed(
                                right.as_ref().expect("right argv handle"),
                                &BASH,
                                BashArgs {
                                    cmd: bash_cmd(&right_args),
                                    timeout_ms: timeout_ms(20),
                                },
                            )
                            .await;
                        let left_ok = matches!(
                            &left_resp,
                            Ok(out) if out.exit_code == 0 && out.stdout.trim() == expected
                        );
                        let right_ok = matches!(
                            &right_resp,
                            Ok(out) if out.exit_code == 0 && out.stdout.trim() == expected
                        );
                        super::TestOutcome::new(
                            "AA+AB",
                            left_ok && right_ok,
                            format!("left={left_resp:?} right={right_resp:?}"),
                        )
                    })
                })
            });
    }
}

/// `pipe-test` remains an argv leaf dispatcher for fd-inheritance helpers and
/// pipe EOF probes: these subcommands intentionally inherit non-protocol fds or
/// stdio across a raw exec, which a handler-dispatched agent must not own.
fn subcmd_pipe_test(args: &[String]) -> i32 {
    match args.get(2).map_or("help", String::as_str) {
        "eof-fork" => subcmd_eof_fork(),
        "eof-exec" => subcmd_eof_exec(args),
        "echo-exit" => {
            println!("PIPE_CHILD_DATA");
            0
        }
        "extra-pipe-c2p" => subcmd_extra_pipe_c2p(args),
        "extra-pipe-p2c" => subcmd_extra_pipe_p2c(args),
        "write-on-fd" => subcmd_write_on_fd(args),
        "read-on-fd" => subcmd_read_on_fd(args),
        "echo-on-fd" => subcmd_echo_on_fd(args),
        "stdio-echo" => subcmd_stdio_echo(),
        "delayed-write-on-fd" => subcmd_delayed_write_on_fd(args),
        "nonblock-fork" => subcmd_nonblock_fork(args),
        other => {
            eprintln!("unknown pipe-test: {other}");
            1
        }
    }
}

fn subcmd_default_exe(args: &[String]) -> String {
    args.get(3).cloned().unwrap_or_else(|| {
        std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    })
}

fn subcmd_eof_fork() -> i32 {
    let mut pipe_fds = [0i32; 2];
    // Safety: pipe_fds points to two valid i32 slots for pipe to fill.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        println!("P1_PIPE_FAIL:{}", errno());
        return 1;
    }

    // Safety: this argv leaf is single-threaded for the fork probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("P1_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Safety: pipe_fds are valid fds returned by pipe.
        unsafe {
            libc::close(pipe_fds[0]);
            let msg = b"P1_CHILD_DATA\n";
            let _ = libc::write(pipe_fds[1], msg.as_ptr().cast::<libc::c_void>(), msg.len());
            libc::close(pipe_fds[1]);
        }
        std::process::exit(0);
    }

    // Safety: pipe_fds[1] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[1]) };
    let (data, _) = read_with_poll_timeout(pipe_fds[0], 15);
    // Safety: pipe_fds[0] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[0]) };
    let _ = wait_child(pid);
    let data = String::from_utf8_lossy(&data);
    if data.contains("P1_CHILD_DATA") {
        println!("P1_EOF_OK");
        0
    } else {
        println!("P1_EOF_FAIL:data={data}");
        1
    }
}

/// `nonblock-fork <r_nb:0|1> <w_nb:0|1>` — verify that O_NONBLOCK is
/// preserved per-end across a `fork()`.
///
/// Parent: creates a pipe, applies the requested NONBLOCK setting via
/// `fcntl(F_SETFL)` on each end independently, forks, then closes both
/// of its own ends so that the child inherits the *only* references to
/// the pipe. Under litebox's delayed-fork model this drives the
/// runner's child-only-local-pipe code path (the Phase 2 BrokerPipe
/// migration target).
///
/// Child: re-reads `F_GETFL` on both inherited fds and compares the
/// `O_NONBLOCK` bit against what the parent set. Also performs a
/// functional check: with NONBLOCK on the read end, an empty read must
/// return `EAGAIN` (not block); without NONBLOCK and a closed write
/// end, the read must return 0 (EOF). Reports the verdict by exit
/// code (0 = OK).
///
/// Naming convention for the parent harness output: `PFLG_NB_OK` on
/// success, `PFLG_NB_FAIL:<detail>` on failure.
fn subcmd_nonblock_fork(args: &[String]) -> i32 {
    let r_nb = matches!(args.get(3).map(String::as_str), Some("1"));
    let w_nb = matches!(args.get(4).map(String::as_str), Some("1"));

    let mut pipe_fds = [0i32; 2];
    // Safety: pipe_fds points to two valid i32 slots for pipe to fill.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        println!("PFLG_NB_FAIL:pipe:{}", errno());
        return 1;
    }
    let rfd = pipe_fds[0];
    let wfd = pipe_fds[1];

    // Apply per-end NONBLOCK before fork so that the snapshot the
    // delayed-fork machinery captures contains the desired flags.
    if let Err(e) = set_nonblock(rfd, r_nb) {
        println!("PFLG_NB_FAIL:setfl_r:{e}");
        return 1;
    }
    if let Err(e) = set_nonblock(wfd, w_nb) {
        println!("PFLG_NB_FAIL:setfl_w:{e}");
        return 1;
    }

    // Safety: single-threaded argv leaf.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("PFLG_NB_FAIL:fork:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Child: verify inherited flags and pipe functionality, then
        // exit with status code 0 on success, 1..=4 on specific
        // failure modes. Stdout is captured separately so the child's
        // diagnostic line is visible to the parent harness.
        let got_r = match fcntl_getfl(rfd) {
            Ok(f) => f,
            Err(e) => {
                println!("PFLG_NB_FAIL:child_getfl_r:{e}");
                std::process::exit(1);
            }
        };
        let got_w = match fcntl_getfl(wfd) {
            Ok(f) => f,
            Err(e) => {
                println!("PFLG_NB_FAIL:child_getfl_w:{e}");
                std::process::exit(1);
            }
        };
        let r_actual_nb = (got_r & libc::O_NONBLOCK) != 0;
        let w_actual_nb = (got_w & libc::O_NONBLOCK) != 0;
        if r_actual_nb != r_nb || w_actual_nb != w_nb {
            println!(
                "PFLG_NB_FAIL:flags_mismatch:r_want={r_nb},r_got={r_actual_nb},\
                 w_want={w_nb},w_got={w_actual_nb}"
            );
            std::process::exit(2);
        }

        // Functional check on the read end. With NONBLOCK and an empty
        // pipe whose write end is still open, read must return EAGAIN.
        let mut buf = [0u8; 16];
        if r_nb {
            // Safety: rfd is a valid fd, buf is a valid mutable slice.
            let n = unsafe { libc::read(rfd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            if n != -1 || (errno() != libc::EAGAIN && errno() != libc::EWOULDBLOCK) {
                println!("PFLG_NB_FAIL:read_should_eagain:n={n},errno={}", errno());
                std::process::exit(3);
            }
        }

        // Round-trip a byte to confirm the pipe is wired up correctly.
        let msg = b"X";
        // Safety: wfd is valid, msg is valid initialised memory.
        let wn = unsafe { libc::write(wfd, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        if wn != 1 {
            println!("PFLG_NB_FAIL:roundtrip_write:n={wn},errno={}", errno());
            std::process::exit(4);
        }
        // Safety: rfd is valid, buf has room for one byte.
        let rn = unsafe { libc::read(rfd, buf.as_mut_ptr().cast::<libc::c_void>(), 1) };
        if rn != 1 || buf[0] != b'X' {
            println!("PFLG_NB_FAIL:roundtrip_read:n={rn},b0={}", buf[0]);
            std::process::exit(4);
        }

        println!("PFLG_NB_CHILD_OK:r_nb={r_nb},w_nb={w_nb}");
        std::process::exit(0);
    }

    // Parent: close both ends so the child holds the only references
    // (this matches the litebox local-pipes fork-restore shape).
    // Safety: rfd and wfd are valid fds returned by pipe.
    unsafe {
        libc::close(rfd);
        libc::close(wfd);
    }
    let exit_code = wait_child(pid);
    if exit_code == 0 {
        println!("PFLG_NB_OK:r_nb={r_nb},w_nb={w_nb}");
        0
    } else {
        println!("PFLG_NB_FAIL:child_exit={exit_code}");
        1
    }
}

/// Apply or clear `O_NONBLOCK` on `fd` via `fcntl(F_GETFL)` +
/// `fcntl(F_SETFL)`. Returns the errno string on failure.
fn set_nonblock(fd: i32, nb: bool) -> Result<(), String> {
    let cur = fcntl_getfl(fd)?;
    let new = if nb {
        cur | libc::O_NONBLOCK
    } else {
        cur & !libc::O_NONBLOCK
    };
    // Safety: fd is a valid fd and F_SETFL takes a plain int argument.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, new) };
    if rc < 0 {
        return Err(format!("setfl:{}", errno()));
    }
    Ok(())
}

fn fcntl_getfl(fd: i32) -> Result<i32, String> {
    // Safety: fd is a valid fd and F_GETFL takes no argument.
    let f = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if f < 0 {
        Err(format!("getfl:{}", errno()))
    } else {
        Ok(f)
    }
}

fn subcmd_eof_exec(args: &[String]) -> i32 {
    let exe = subcmd_default_exe(args);
    let mut pipe_fds = [0i32; 2];
    // Safety: pipe_fds points to two valid i32 slots for pipe to fill.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        println!("P2_PIPE_FAIL:{}", errno());
        return 1;
    }
    let child_exec = prepare_execv(&exe, &["pipe-test", "echo-exit"]);

    // Safety: this argv leaf is single-threaded for the fork/exec probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("P2_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Safety: pipe_fds are valid; dup2 redirects stdout to the pipe write end.
        unsafe {
            libc::close(pipe_fds[0]);
            libc::dup2(pipe_fds[1], 1);
            libc::close(pipe_fds[1]);
        }
        child_exec.exec();
    }

    // Safety: pipe_fds[1] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[1]) };
    let (data, _) = read_with_poll_timeout(pipe_fds[0], 15);
    // Safety: pipe_fds[0] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[0]) };
    let exit_code = wait_child(pid);
    let data = String::from_utf8_lossy(&data);
    if data.contains("PIPE_CHILD_DATA") && exit_code == 0 {
        println!("P2_EOF_OK");
        0
    } else {
        println!("P2_EOF_FAIL:exit={exit_code},data={data}");
        1
    }
}

fn subcmd_extra_pipe_c2p(args: &[String]) -> i32 {
    let exe = subcmd_default_exe(args);
    let mut pipe_fds = [0i32; 2];
    // Safety: pipe_fds points to two valid i32 slots for pipe to fill.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        println!("PB_C2P_PIPE_FAIL:{}", errno());
        return 1;
    }
    let wfd_str = pipe_fds[1].to_string();
    let child_exec = prepare_execv(&exe, &["pipe-test", "write-on-fd", &wfd_str]);

    // Safety: this argv leaf is single-threaded for the fork/exec probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("PB_C2P_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Safety: pipe_fds[0] is a valid fd returned by pipe.
        unsafe { libc::close(pipe_fds[0]) };
        child_exec.exec();
    }

    // Safety: pipe_fds[1] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[1]) };
    let (data, _) = read_with_poll_timeout(pipe_fds[0], 15);
    // Safety: pipe_fds[0] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[0]) };
    let exit_code = wait_child(pid);
    let text = String::from_utf8_lossy(&data);
    if text.contains("PB_CHILD_WROTE") && exit_code == 0 {
        println!("PB_C2P_OK");
        0
    } else if data.is_empty() {
        println!(
            "PB_C2P_FAIL:no_data (pipe fd likely not bridged to child worker), exit={exit_code}"
        );
        1
    } else {
        println!("PB_C2P_FAIL:exit={exit_code},data={text}");
        1
    }
}

fn subcmd_extra_pipe_p2c(args: &[String]) -> i32 {
    let exe = subcmd_default_exe(args);
    let mut pipe_fds = [0i32; 2];
    // Safety: pipe_fds points to two valid i32 slots for pipe to fill.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        println!("PB_P2C_PIPE_FAIL:{}", errno());
        return 1;
    }
    let rfd_str = pipe_fds[0].to_string();
    let child_exec = prepare_execv(&exe, &["pipe-test", "read-on-fd", &rfd_str]);

    // Safety: this argv leaf is single-threaded for the fork/exec probe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("PB_P2C_FORK_FAIL:{}", errno());
        return 1;
    }

    if pid == 0 {
        // Safety: pipe_fds[1] is a valid fd returned by pipe.
        unsafe { libc::close(pipe_fds[1]) };
        child_exec.exec();
    }

    // Safety: pipe_fds[0] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[0]) };
    let msg = b"PB_PARENT_WROTE\n";
    // Safety: pipe_fds[1] is valid and msg points to initialized bytes.
    let written =
        unsafe { libc::write(pipe_fds[1], msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
    // Safety: pipe_fds[1] is a valid fd returned by pipe.
    unsafe { libc::close(pipe_fds[1]) };
    if written < 0 {
        println!("PB_P2C_WRITE_FAIL:{}", errno());
        return 1;
    }
    let exit_code = wait_child(pid);
    if exit_code == 0 {
        println!("PB_P2C_OK");
        0
    } else {
        println!("PB_P2C_FAIL:exit={exit_code}");
        1
    }
}

fn subcmd_write_on_fd(args: &[String]) -> i32 {
    let fd_arg = args.get(3).map_or("3", String::as_str);
    let fds: Vec<i32> = fd_arg.split(',').filter_map(|s| s.parse().ok()).collect();
    if fds.is_empty() {
        eprintln!("[write-on-fd] no valid fds in: {fd_arg}");
        return 1;
    }
    let mut ok = true;
    for &fd in &fds {
        let msg = format!("PB_CHILD_WROTE:fd={fd}\n");
        // Safety: fd is inherited from the parent test process and msg is valid.
        let n = unsafe { libc::write(fd, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        if n < 0 {
            eprintln!(
                "[write-on-fd] write(fd={fd}) failed: {}",
                std::io::Error::last_os_error()
            );
            ok = false;
        }
        // Safety: fd is an inherited test fd that this helper owns.
        unsafe { libc::close(fd) };
    }
    i32::from(!ok)
}

fn subcmd_read_on_fd(args: &[String]) -> i32 {
    let fd: i32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
    let (data, _) = read_with_poll_timeout(fd, 10);
    // Safety: fd is an inherited test fd that this helper owns.
    unsafe { libc::close(fd) };
    let text = String::from_utf8_lossy(&data);
    if text.contains("PB_PARENT_WROTE") {
        eprintln!("[read-on-fd] got: {text}");
        0
    } else {
        eprintln!("[read-on-fd] expected PB_PARENT_WROTE, got: {text}");
        1
    }
}

fn subcmd_echo_on_fd(args: &[String]) -> i32 {
    let fd: i32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
    let mut buf = [0u8; 4096];
    // Safety: fd is inherited from the parent test process and buf is valid.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n <= 0 {
        eprintln!(
            "[echo-on-fd] read failed: {}",
            std::io::Error::last_os_error()
        );
        // Safety: fd is an inherited test fd that this helper owns.
        unsafe { libc::close(fd) };
        return 1;
    }
    let n = n as usize;
    // Safety: fd is valid and buf[..n] contains bytes just read.
    let w = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), n) };
    // Safety: fd is an inherited test fd that this helper owns.
    unsafe { libc::close(fd) };
    i32::from(w < 0)
}

fn subcmd_stdio_echo() -> i32 {
    let mut buf = [0u8; 256];
    // Safety: fd 0 is the inherited stdin socket for this leaf helper.
    let n = unsafe { libc::read(0, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n <= 0 {
        return 1;
    }
    let input = String::from_utf8_lossy(&buf[..n as usize]);
    let stdout_msg = format!("PB_STDIO_SOCKETPAIR_OUT:{input}\n");
    let stderr_msg = b"PB_STDIO_SOCKETPAIR_ERR\n";
    // Safety: fds 1 and 2 are the inherited stdout/stderr sockets.
    let out = unsafe {
        libc::write(
            1,
            stdout_msg.as_ptr().cast::<libc::c_void>(),
            stdout_msg.len(),
        )
    };
    // Safety: fd 2 is the inherited stderr socket.
    let err = unsafe {
        libc::write(
            2,
            stderr_msg.as_ptr().cast::<libc::c_void>(),
            stderr_msg.len(),
        )
    };
    i32::from(out < 0 || err < 0)
}

fn subcmd_delayed_write_on_fd(args: &[String]) -> i32 {
    let fd_arg = args.get(3).map_or("3", String::as_str);
    let delay_ms: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(500);
    let fds: Vec<i32> = fd_arg.split(',').filter_map(|s| s.parse().ok()).collect();
    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
    let mut ok = true;
    for &fd in &fds {
        let msg = format!("PB_DELAYED_WRITE:fd={fd}\n");
        // Safety: fd is inherited from the parent test process and msg is valid.
        let n = unsafe { libc::write(fd, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        if n < 0 {
            eprintln!(
                "[delayed-write] write(fd={fd}) failed: {}",
                std::io::Error::last_os_error()
            );
            ok = false;
        }
        // Safety: fd is an inherited test fd that this helper owns.
        unsafe { libc::close(fd) };
    }
    i32::from(!ok)
}

// ═══════════════════════════════════════════════════════════════════
// Shared helpers for lifted PN / PID / NPIPE / BPIPE families.
// ═══════════════════════════════════════════════════════════════════

/// Agents common to PN.* and PID.* tests.
const AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2];

/// Depth-1 and depth-2 PIE-glibc agents; used by PN.child.* and BPIPE.*.
const DEPTH_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1];

/// Repetition counts for NPIPE/BPIPE pipe-chain stress.
const NPIPE_REPS: &[usize] = &[1, 5, 10];

/// Pipe-bridge churn ("npipe") fan-out parents.  Each entry is a
/// long-lived agent whose binary type exercises a different parent-side
/// bridge / pipe-host code path.
const NPIPE_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,       // PIE-glibc
    AgentName::Dpg1Dpg1,   // PIE-glibc, depth-2
    AgentName::Dpg2,       // PIE-glibc, sibling subtree
    AgentName::Dpg1Dng,    // non-PIE-glibc (node form)
    AgentName::Dpg1DngDng, // bash → bash recursion (VS Code hot path)
    AgentName::Dpg1DngSpm, // bash → cli (VS Code hot path)
    AgentName::Dpg1Spg,    // static-PIE-glibc (still uses ld.so)
    AgentName::Dpg1Spm,    // static-PIE-musl (no ld.so) — cli form
    AgentName::Dpg1SpmDng, // cli → node (VS Code's signature transition)
    AgentName::Dpg1Snm,    // non-PIE-static-musl
];

/// Convenience: build an `ExecArgs` with just an argv and sensible defaults.
fn exec_args_default(args: Vec<String>) -> ExecArgs {
    ExecArgs {
        args,
        timeout_secs: None,
        stdin: None,
        background: false,
        env: vec![],
    }
}

// ═══════════════════════════════════════════════════════════════════
// PID: monotonic pipe pair_id (fix c2d0abdc)
// ═══════════════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Debug)]
struct PipePairIdArgs {
    count: u32,
}

const PIPE_PAIR_ID: HandlerToken<PipePairIdArgs, PipeBridgeOut> =
    HandlerToken::new("platform_fixes.pipe_pair_id");

async fn handle_pipe_pair_id(
    args: PipePairIdArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    use std::collections::HashSet;
    let mut first_batch = HashSet::new();
    let mut fds = Vec::new();
    for _ in 0..args.count {
        let mut pipe_fds = [0i32; 2];
        // SAFETY: pipe writes two fresh fds into pipe_fds on success.
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(HandlerError(format!(
                "pipe: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: zeroed stat is a valid output buffer for fstat.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: pipe_fds[0] is a live fd and stat is writable.
        if unsafe { libc::fstat(pipe_fds[0], &raw mut stat) } == 0 {
            first_batch.insert(stat.st_ino);
        }
        fds.push(pipe_fds);
    }
    for pipe_fds in fds.drain(..) {
        // SAFETY: fds were created by this handler and are still owned here.
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
    }
    let mut collisions = 0u32;
    for _ in 0..args.count {
        let mut pipe_fds = [0i32; 2];
        // SAFETY: pipe writes two fresh fds into pipe_fds on success.
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(HandlerError(format!(
                "pipe: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: zeroed stat is a valid output buffer for fstat.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: pipe_fds[0] is a live fd and stat is writable.
        if unsafe { libc::fstat(pipe_fds[0], &raw mut stat) } == 0
            && first_batch.contains(&stat.st_ino)
        {
            collisions += 1;
        }
        // SAFETY: fds were created by this handler and are still owned here.
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
    }
    if collisions == 0 {
        Ok(PipeBridgeOut {
            detail: "unique".to_string(),
        })
    } else {
        Err(HandlerError(format!(
            "collision: {collisions}/{} ids reused",
            args.count
        )))
    }
}

pub(crate) fn register_pipe_pair_id_tests(reg: &mut Registry<'_>) {
    register_handler!(PIPE_PAIR_ID, handle_pipe_pair_id);
    register_handler!(BPIPE_BASIC_IO, handle_bpipe_basic_io);
    register_handler!(BPIPE_FORK_IO, handle_bpipe_fork_io);
    register_handler!(BPIPE_EXEC_NO_CAPTURE, handle_bpipe_exec_no_capture);
    register_handler!(BPIPE_EXEC_CAPTURED, handle_bpipe_exec_captured);
    for &agent in AGENTS {
        let agent_s = agent.to_string();
        reg.test("matrix", "pipe_pair_id", format!("PID.{agent}"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = agent_s.clone();
                    Box::pin(async move {
                        let result = run
                            .send_named_typed(&handle, &PIPE_PAIR_ID, PipePairIdArgs { count: 100 })
                            .await;
                        let pass = matches!(&result, Ok(out) if out.detail == "unique");
                        super::TestOutcome::new(&a, pass, format!("{result:?}"))
                    })
                })
            });
    }
    // BPIPE.basic_io: minimal capability test for the broker-pipe
    // activation path. A single agent (Dpg1) creates a pipe via
    // libc::pipe2, writes 8 bytes to the writer end, reads them back
    // from the reader end, closes both. Native should always pass.
    // With `eager_broker=true` in sys_pipe2, this exercises the broker
    // pipe data plane (create_pipe RPC, read/write subscriptions, close).
    // If this fails under litebox while PB.c2p also fails, the broker-pipe
    // bug is in basic I/O, not fork+exec stdio handoff.
    reg.test("matrix", "broker_pipe_basic", "EPIPE.basic_io")
        .timeout(30)
        .build(|cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let result = run
                        .send_named_typed(&handle, &BPIPE_BASIC_IO, BpipeBasicIoArgs {})
                        .await;
                    let pass = matches!(&result, Ok(out) if out.detail == "ok");
                    super::TestOutcome::new("EPIPE.basic_io", pass, format!("{result:?}"))
                })
            })
        });
    // EPIPE.fork_io: one level above EPIPE.basic_io — pipe2 + fork +
    // child writes / parent reads + waitpid. No exec. Isolates broker-
    // pipe cross-process inheritance from spawn-time stdio handoff.
    reg.test("matrix", "broker_pipe_basic", "EPIPE.fork_io")
        .timeout(30)
        .build(|cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let result = run
                        .send_named_typed(&handle, &BPIPE_FORK_IO, BpipeForkIoArgs {})
                        .await;
                    let pass = matches!(&result, Ok(out) if out.detail == "ok");
                    super::TestOutcome::new("EPIPE.fork_io", pass, format!("{result:?}"))
                })
            })
        });
    // EPIPE.exec_no_capture: fork+exec without stdio piping. Uses
    // std::process::Command::status() which inherits parent stdio
    // rather than allocating new pipes. Tests the spawn path in the
    // presence of broker-backed eventfd (Tokio's I/O waker) without
    // exercising broker-backed pipe2() for stdio capture. If this
    // passes but EPIPE.exec_captured fails, the bug is specifically
    // in the stdio-capture pipe path.
    reg.test("matrix", "broker_pipe_basic", "EPIPE.exec_no_capture")
        .timeout(30)
        .build(|cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let result = run
                        .send_named_typed(&handle, &BPIPE_EXEC_NO_CAPTURE, BpipeExecArgs {})
                        .await;
                    let pass = matches!(&result, Ok(out) if out.detail == "ok");
                    super::TestOutcome::new("EPIPE.exec_no_capture", pass, format!("{result:?}"))
                })
            })
        });
    // EPIPE.exec_captured: fork+exec WITH stdio captured via pipes.
    // Uses std::process::Command::output() which creates pipes for
    // child's stdout/stderr. With eager_broker=true those pipes are
    // broker-backed. This is the PB.c2p shape but stripped to one
    // capability.
    reg.test("matrix", "broker_pipe_basic", "EPIPE.exec_captured")
        .timeout(30)
        .build(|cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let result = run
                        .send_named_typed(&handle, &BPIPE_EXEC_CAPTURED, BpipeExecArgs {})
                        .await;
                    let pass = matches!(&result, Ok(out) if out.detail == "ok");
                    super::TestOutcome::new("EPIPE.exec_captured", pass, format!("{result:?}"))
                })
            })
        });
}

// ─── BPIPE.basic_io: minimal broker-pipe activation test ───────────

#[derive(Serialize, Deserialize, Debug)]
struct BpipeBasicIoArgs {}

const BPIPE_BASIC_IO: HandlerToken<BpipeBasicIoArgs, PipeBridgeOut> =
    HandlerToken::new("platform_fixes.bpipe_basic_io");

async fn handle_bpipe_basic_io(
    _args: BpipeBasicIoArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe2 writes two fresh fds into pipe_fds on success.
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), 0) } != 0 {
        return Err(HandlerError(format!(
            "pipe2: {}",
            std::io::Error::last_os_error()
        )));
    }
    let [rd, wr] = pipe_fds;
    let msg = b"hello-bp";
    // SAFETY: wr is a live fd; we own it for the duration of this fn.
    let n = unsafe { libc::write(wr, msg.as_ptr() as *const _, msg.len()) };
    if n != msg.len() as isize {
        // SAFETY: closing fds we own.
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
        return Err(HandlerError(format!(
            "write: rc={n} err={}",
            std::io::Error::last_os_error()
        )));
    }
    let mut buf = [0u8; 8];
    // SAFETY: rd is a live fd; buf is writable.
    let m = unsafe { libc::read(rd, buf.as_mut_ptr() as *mut _, buf.len()) };
    if m != msg.len() as isize {
        // SAFETY: closing fds we own.
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
        return Err(HandlerError(format!(
            "read: rc={m} err={}",
            std::io::Error::last_os_error()
        )));
    }
    if &buf[..m as usize] != msg {
        // SAFETY: closing fds we own.
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
        return Err(HandlerError(format!(
            "data mismatch: wrote {msg:?} read {:?}",
            &buf[..m as usize]
        )));
    }
    // SAFETY: closing fds we own.
    unsafe {
        libc::close(rd);
        libc::close(wr);
    }
    Ok(PipeBridgeOut {
        detail: "ok".to_string(),
    })
}

// ─── EPIPE.fork_io: pipe2 + fork + IPC, no exec ────────────────────
//
// Parent calls pipe2; forks; child writes to write end; parent reads
// from read end; parent reaps child. No exec. With `eager_broker=true`
// in sys_pipe2 this exercises the broker pipe's cross-process
// inheritance + refcount via on_dup on fork's fd table clone, without
// any of the spawn-time stdio handoff complexity that PB.c2p hits.

#[derive(Serialize, Deserialize, Debug)]
struct BpipeForkIoArgs {}

const BPIPE_FORK_IO: HandlerToken<BpipeForkIoArgs, PipeBridgeOut> =
    HandlerToken::new("platform_fixes.bpipe_fork_io");

async fn handle_bpipe_fork_io(
    _args: BpipeForkIoArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe2 writes two fresh fds.
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), 0) } != 0 {
        return Err(HandlerError(format!(
            "pipe2: {}",
            std::io::Error::last_os_error()
        )));
    }
    let [rd, wr] = pipe_fds;
    let msg = b"hello-fk";
    // SAFETY: fork().
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // SAFETY: closing fds we own.
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
        return Err(HandlerError(format!(
            "fork: {}",
            std::io::Error::last_os_error()
        )));
    }
    if pid == 0 {
        // Child: close read end, write msg, exit.
        // SAFETY: closing child copy of rd.
        unsafe {
            libc::close(rd);
        }
        // SAFETY: wr is a live fd in child copy of fd table.
        let n = unsafe { libc::write(wr, msg.as_ptr() as *const _, msg.len()) };
        let exit_code = if n == msg.len() as isize { 0 } else { 1 };
        // SAFETY: closing wr; then _exit avoids destructors.
        unsafe {
            libc::close(wr);
            libc::_exit(exit_code);
        }
    }
    // Parent: close write end, read msg, reap child.
    // SAFETY: closing parent's wr.
    unsafe {
        libc::close(wr);
    }
    let mut buf = [0u8; 8];
    // SAFETY: rd live, buf writable.
    let m = unsafe { libc::read(rd, buf.as_mut_ptr() as *mut _, buf.len()) };
    // SAFETY: closing rd.
    unsafe {
        libc::close(rd);
    }
    let mut status: libc::c_int = 0;
    // SAFETY: waitpid on a child we forked.
    let w = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    if w != pid {
        return Err(HandlerError(format!(
            "waitpid: rc={w} err={}",
            std::io::Error::last_os_error()
        )));
    }
    if m != msg.len() as isize {
        return Err(HandlerError(format!(
            "read: rc={m} err={}",
            std::io::Error::last_os_error()
        )));
    }
    if &buf[..m as usize] != msg {
        return Err(HandlerError(format!(
            "data mismatch: wrote {msg:?} read {:?}",
            &buf[..m as usize]
        )));
    }
    // WIFEXITED / WEXITSTATUS are pure macros over the status int.
    let exited_normally = libc::WIFEXITED(status);
    let exit_code = libc::WEXITSTATUS(status);
    if !exited_normally || exit_code != 0 {
        return Err(HandlerError(format!(
            "child exit: WIFEXITED={exited_normally} WEXITSTATUS={exit_code}"
        )));
    }
    Ok(PipeBridgeOut {
        detail: "ok".to_string(),
    })
}

// ─── EPIPE.exec_no_capture: spawn child with inherited stdio ───────

#[derive(Serialize, Deserialize, Debug)]
struct BpipeExecArgs {}

const BPIPE_EXEC_NO_CAPTURE: HandlerToken<BpipeExecArgs, PipeBridgeOut> =
    HandlerToken::new("platform_fixes.bpipe_exec_no_capture");

const BPIPE_EXEC_CAPTURED: HandlerToken<BpipeExecArgs, PipeBridgeOut> =
    HandlerToken::new("platform_fixes.bpipe_exec_captured");

async fn handle_bpipe_exec_no_capture(
    _args: BpipeExecArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    // Spawn /bin/true with inherited stdio (no pipes for capture).
    // This exercises the spawn path without allocating broker pipes
    // for stdout/stderr.
    let status = std::process::Command::new("/bin/true")
        .status()
        .map_err(|e| HandlerError(format!("spawn /bin/true: {e}")))?;
    if !status.success() {
        return Err(HandlerError(format!("/bin/true: {status:?}")));
    }
    Ok(PipeBridgeOut {
        detail: "ok".to_string(),
    })
}

async fn handle_bpipe_exec_captured(
    _args: BpipeExecArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    // Spawn /bin/true with stdio captured. std::process::Command::output()
    // creates pipes for child's stdout/stderr; with eager_broker=true
    // those are broker-backed pipes.
    let out = std::process::Command::new("/bin/true")
        .output()
        .map_err(|e| HandlerError(format!("spawn /bin/true: {e}")))?;
    if !out.status.success() {
        return Err(HandlerError(format!("/bin/true: {:?}", out.status)));
    }
    Ok(PipeBridgeOut {
        detail: "ok".to_string(),
    })
}

#[derive(Serialize, Deserialize, Debug)]
struct PipeNonblockArgs {}

#[derive(Serialize, Deserialize, Debug)]
struct PipeChildNonblockArgs {}

const PIPE_NONBLOCK: HandlerToken<PipeNonblockArgs, PipeBridgeOut> =
    HandlerToken::new("platform_fixes.pipe_nonblock");
const PIPE_CHILD_NONBLOCK: HandlerToken<PipeChildNonblockArgs, PipeBridgeOut> =
    HandlerToken::new("platform_fixes.pipe_child_nonblock");

async fn handle_pipe_nonblock(
    _args: PipeNonblockArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    let detail = (|| -> Result<String, String> {
        let mut out = Vec::new();
        let mut fds = [0i32; 2];
        // SAFETY: pipe initializes two fds on success.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(format!("pipe: {}", std::io::Error::last_os_error()));
        }
        let read_fd = fds[0];
        let write_fd = fds[1];
        // SAFETY: read_fd is a valid pipe fd.
        let flags = unsafe { libc::fcntl(read_fd, libc::F_GETFL) };
        // SAFETY: read_fd is valid and flags are from F_GETFL.
        let ret = unsafe { libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        out.push(format!(
            "PIPE_NB_SETFL={}",
            if ret == 0 { "OK" } else { "FAIL" }
        ));
        let mut buf = [0u8; 64];
        // SAFETY: read_fd is valid and buf is writable.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
        // SAFETY: errno is thread-local and read just failed or returned.
        let errno = unsafe { *libc::__errno_location() };
        if n == -1 && (errno == libc::EAGAIN || errno == libc::EWOULDBLOCK) {
            out.push("PIPE_NB_EMPTY=EAGAIN".into());
        } else {
            out.push(format!("PIPE_NB_EMPTY=UNEXPECTED n={n} errno={errno}"));
        }
        let msg = b"HELLO";
        // SAFETY: write_fd is valid and msg points to readable bytes.
        unsafe { libc::write(write_fd, msg.as_ptr().cast(), msg.len()) };
        // SAFETY: read_fd is valid and buf is writable.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
        out.push(if n == 5 {
            "PIPE_NB_DATA=OK".into()
        } else {
            format!("PIPE_NB_DATA=UNEXPECTED n={n}")
        });
        // SAFETY: write_fd is a valid fd and is no longer used after close.
        unsafe { libc::close(write_fd) };
        // SAFETY: read_fd is valid and buf is writable.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n == 0 {
            out.push("PIPE_NB_EOF=OK".into());
        } else {
            // SAFETY: errno is thread-local and read just returned unexpectedly.
            let errno = unsafe { *libc::__errno_location() };
            out.push(format!("PIPE_NB_EOF=UNEXPECTED n={n} errno={errno}"));
        }
        // SAFETY: read_fd is a valid fd and is no longer used after close.
        unsafe { libc::close(read_fd) };
        Ok(out.join("\n"))
    })()?;
    Ok(PipeBridgeOut { detail })
}

async fn handle_pipe_child_nonblock(
    _args: PipeChildNonblockArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PipeBridgeOut, HandlerError> {
    let detail = (|| -> Result<String, String> {
        let mut out = Vec::new();
        let mut fds = [0i32; 2];
        // SAFETY: pipe initializes two fds on success.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(format!("pipe: {}", std::io::Error::last_os_error()));
        }
        let read_fd = fds[0];
        let write_fd = fds[1];
        // SAFETY: fork duplicates the current process; child exits below.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: child owns these fds after fork.
            unsafe { libc::close(read_fd) };
            std::thread::sleep(Duration::from_millis(500));
            let msg = b"X";
            // SAFETY: write_fd is valid and msg is readable.
            unsafe { libc::write(write_fd, msg.as_ptr().cast(), 1) };
            // SAFETY: child is done with write_fd.
            unsafe { libc::close(write_fd) };
            std::process::exit(0);
        }
        if pid < 0 {
            return Err(format!("fork: {}", std::io::Error::last_os_error()));
        }
        // SAFETY: parent is done with write_fd.
        unsafe { libc::close(write_fd) };
        // SAFETY: read_fd is a valid pipe fd.
        let flags = unsafe { libc::fcntl(read_fd, libc::F_GETFL) };
        // SAFETY: read_fd is valid and flags are from F_GETFL.
        unsafe { libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        let mut buf = [0u8; 1];
        // SAFETY: read_fd is valid and buf is writable.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), 1) };
        // SAFETY: errno is thread-local and read just returned.
        let errno = unsafe { *libc::__errno_location() };
        if n == -1 && (errno == libc::EAGAIN || errno == libc::EWOULDBLOCK) {
            out.push("PCHILD_INITIAL=EAGAIN".into());
        } else {
            out.push(format!("PCHILD_INITIAL=UNEXPECTED n={n} errno={errno}"));
        }
        std::thread::sleep(Duration::from_secs(1));
        // SAFETY: read_fd is valid and buf is writable.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), 1) };
        if n == 1 {
            out.push("PCHILD_DATA=OK".into());
        } else {
            // SAFETY: errno is thread-local and read just returned unexpectedly.
            let errno = unsafe { *libc::__errno_location() };
            out.push(format!("PCHILD_DATA=UNEXPECTED n={n} errno={errno}"));
        }
        // SAFETY: read_fd is valid and buf is writable.
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), 1) };
        if n == 0 {
            out.push("PCHILD_EOF=OK".into());
        } else {
            // SAFETY: errno is thread-local and read just returned unexpectedly.
            let errno = unsafe { *libc::__errno_location() };
            out.push(format!("PCHILD_EOF=UNEXPECTED n={n} errno={errno}"));
        }
        // SAFETY: cleanup live fd and reap the child pid.
        unsafe { libc::close(read_fd) };
        // SAFETY: pid is a child process from fork.
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        Ok(out.join("\n"))
    })()?;
    Ok(PipeBridgeOut { detail })
}

pub(crate) fn register_pipe_nonblock_tests(reg: &mut Registry<'_>) {
    register_handler!(PIPE_NONBLOCK, handle_pipe_nonblock);
    register_handler!(PIPE_CHILD_NONBLOCK, handle_pipe_child_nonblock);
    // Part 1: basic pipe non-blocking (single process)
    for &agent in AGENTS {
        for &(suffix, marker) in &[
            ("setfl", "PIPE_NB_SETFL=OK"),
            ("empty_eagain", "PIPE_NB_EMPTY=EAGAIN"),
            ("data", "PIPE_NB_DATA=OK"),
            ("eof", "PIPE_NB_EOF=OK"),
        ] {
            let agent_s = agent.to_string();
            let marker_s: String = marker.into();
            reg.test("matrix", "pipe_nonblock", format!("PN.{agent}.{suffix}"))
                .timeout(60)
                .build(move |cx| {
                    let leaf = cx.declare_ephemeral(
                        agent,
                        format!("PipeNonblock_{agent}_{suffix}"),
                        SpawnKind::Fork {
                            binary: "self",
                            inherit_listen_ports: vec![],
                        },
                    );
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let m = marker_s.clone();
                        Box::pin(async move {
                            let result = run
                                .run_leaf(&leaf, &PIPE_NONBLOCK, PipeNonblockArgs {})
                                .await;
                            let pass = matches!(&result, Ok(out) if out.detail.contains(&*m));
                            super::TestOutcome::new(&a, pass, format!("{result:?}"))
                        })
                    })
                });
        }
    }

    // Part 2: cross-process pipe non-blocking (dropbear pattern)
    for &agent in DEPTH_AGENTS {
        for &(suffix, marker) in &[
            ("eagain", "PCHILD_INITIAL=EAGAIN"),
            ("data", "PCHILD_DATA=OK"),
            ("eof", "PCHILD_EOF=OK"),
        ] {
            let agent_s = agent.to_string();
            let marker_s: String = marker.into();
            reg.test(
                "matrix",
                "pipe_nonblock",
                format!("PN.child.{agent}.{suffix}"),
            )
            .timeout(60)
            .build(move |cx| {
                let leaf = cx.declare_ephemeral(
                    agent,
                    format!("PipeChildNonblock_{agent}_{suffix}"),
                    SpawnKind::Fork {
                        binary: "self",
                        inherit_listen_ports: vec![],
                    },
                );
                Box::new(move |run| {
                    let a = agent_s.clone();
                    let m = marker_s.clone();
                    Box::pin(async move {
                        let result = run
                            .run_leaf(&leaf, &PIPE_CHILD_NONBLOCK, PipeChildNonblockArgs {})
                            .await;
                        let pass = matches!(&result, Ok(out) if out.detail.contains(&*m));
                        super::TestOutcome::new(&a, pass, format!("{result:?}"))
                    })
                })
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// NPIPE: non-PIE pipe chain integrity (fix febc3e41)
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_nonpie_pipe_chain_tests(reg: &mut Registry<'_>) {
    for &reps in NPIPE_REPS {
        for &agent in NPIPE_AGENTS {
            let agent_s = agent.to_string();
            // Sequential non-PIE pattern.
            reg.test(
                "fork",
                "nonpie_pipe_chain",
                format!("NPIPE.seq.x{reps}.{agent}"),
            )
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = agent_s.clone();
                    let _self_exe = run.self_exe().to_string();
                    Box::pin(async move {
                        let nonpie = crate::nonpie_binary();
                        let mut all_clean = true;
                        let mut detail = String::new();
                        for i in 0..reps {
                            let tag = format!("seq_{a}_{i}");
                            let resp = run
                                .typed_or_error(
                                    &handle,
                                    &EXEC,
                                    exec_args_default(vec![
                                        nonpie.clone(),
                                        "write-known".into(),
                                        tag.clone(),
                                    ]),
                                )
                                .await;
                            let expected = format!("PIPEDATA:{tag}");
                            let ok = matches!(
                                &resp,
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.trim() == expected
                            );
                            if !ok {
                                all_clean = false;
                                detail = format!("iter {i}: expected '{expected}', got {resp:?}");
                                break;
                            }
                        }
                        if all_clean {
                            detail = format!("{reps} sequential non-PIE execs all clean");
                        }
                        super::TestOutcome::new(&a, all_clean, detail)
                    })
                })
            });

            // Interleaved PIE + non-PIE pattern.
            let agent_s2 = agent.to_string();
            reg.test(
                "fork",
                "nonpie_pipe_chain",
                format!("NPIPE.interleaved.x{reps}.{agent}"),
            )
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = agent_s2.clone();
                    let self_exe = run.self_exe().to_string();
                    Box::pin(async move {
                        let nonpie = crate::nonpie_binary();
                        let mut all_clean = true;
                        let mut detail = String::new();
                        for i in 0..reps {
                            let np_tag = format!("np_{a}_{i}");
                            let resp = run
                                .typed_or_error(
                                    &handle,
                                    &EXEC,
                                    exec_args_default(vec![
                                        nonpie.clone(),
                                        "write-known".into(),
                                        np_tag.clone(),
                                    ]),
                                )
                                .await;
                            let expected = format!("PIPEDATA:{np_tag}");
                            let ok = matches!(
                                &resp,
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.trim() == expected
                            );
                            if !ok {
                                all_clean = false;
                                detail =
                                    format!("iter {i} nonpie: expected '{expected}', got {resp:?}");
                                break;
                            }
                            let resp = run
                                .typed_or_error(
                                    &handle,
                                    &EXEC,
                                    exec_args_default(vec![self_exe.clone(), "echo-test".into()]),
                                )
                                .await;
                            let ok = matches!(
                                &resp,
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.trim() == "ECHO_TEST_OK"
                            );
                            if !ok {
                                all_clean = false;
                                detail =
                                    format!("iter {i} pie: expected 'ECHO_TEST_OK', got {resp:?}");
                                break;
                            }
                        }
                        if all_clean {
                            detail = format!("{reps} interleaved PIE+nonPIE execs all clean");
                        }
                        super::TestOutcome::new(&a, all_clean, detail)
                    })
                })
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// BPIPE: per-binary-type pipe chain integrity (extends NPIPE)
//
// NPIPE above covers the non-PIE-glibc leg as a singleton matrix.
// BPIPE expands the same patterns (sequential and interleaved
// fork+execs whose stdout flows through a pipe to the parent) to the
// other four legs of `BinaryType` so the platform's pipe-chain
// integrity is exercised across every binary mode the shim might
// dispatch differently:
//
//   BPIPE.{pie-glibc,static-pie-glibc,
//          static-pie-musl,non-pie-static-musl}
//        .{seq,interleaved}
//        .x{reps}
//        .{A,AA}
//
// `interleaved` alternates the under-test leg with the always-PIE-glibc
// `self_exe` so the test catches pollution between legs.
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_bpipe_tests(reg: &mut Registry<'_>) {
    // Exercise every binary type with uniform per-leg IDs.
    for &bt in crate::BinaryType::ALL {
        let leg_label = bt.label();
        for &reps in NPIPE_REPS {
            for &agent in DEPTH_AGENTS {
                let agent_s = agent.to_string();
                reg.test(
                    "fork",
                    "bpipe",
                    format!("BPIPE.{leg_label}.seq.x{reps}.{agent}"),
                )
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let self_exe = run.self_exe().to_string();
                        Box::pin(async move {
                            let target = crate::binary_path(bt, &self_exe);
                            let mut all_clean = true;
                            let mut detail = String::new();
                            for i in 0..reps {
                                let tag = format!("seq_{leg_label}_{a}_{i}");
                                let resp = run
                                    .typed_or_error(
                                        &handle,
                                        &EXEC,
                                        exec_args_default(vec![
                                            target.clone(),
                                            "write-known".into(),
                                            tag.clone(),
                                        ]),
                                    )
                                    .await;
                                let expected = format!("PIPEDATA:{tag}");
                                let ok = matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if stdout.trim() == expected
                                );
                                if !ok {
                                    all_clean = false;
                                    detail =
                                        format!("iter {i}: expected '{expected}', got {resp:?}");
                                    break;
                                }
                            }
                            if all_clean {
                                detail = format!("{reps} sequential {leg_label} execs all clean");
                            }
                            super::TestOutcome::new(&a, all_clean, detail)
                        })
                    })
                });

                let agent_s2 = agent.to_string();
                reg.test(
                    "fork",
                    "bpipe",
                    format!("BPIPE.{leg_label}.interleaved.x{reps}.{agent}"),
                )
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s2.clone();
                        let self_exe = run.self_exe().to_string();
                        Box::pin(async move {
                            let target = crate::binary_path(bt, &self_exe);
                            let mut all_clean = true;
                            let mut detail = String::new();
                            for i in 0..reps {
                                let tag = format!("itr_{leg_label}_{a}_{i}");
                                let resp = run
                                    .typed_or_error(
                                        &handle,
                                        &EXEC,
                                        exec_args_default(vec![
                                            target.clone(),
                                            "write-known".into(),
                                            tag.clone(),
                                        ]),
                                    )
                                    .await;
                                let expected = format!("PIPEDATA:{tag}");
                                let ok = matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if stdout.trim() == expected
                                );
                                if !ok {
                                    all_clean = false;
                                    detail = format!(
                                        "iter {i} {leg_label}: expected '{expected}', got {resp:?}"
                                    );
                                    break;
                                }
                                let resp = run
                                    .typed_or_error(
                                        &handle,
                                        &EXEC,
                                        exec_args_default(vec![
                                            self_exe.clone(),
                                            "echo-test".into(),
                                        ]),
                                    )
                                    .await;
                                let ok = matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if stdout.trim() == "ECHO_TEST_OK"
                                );
                                if !ok {
                                    all_clean = false;
                                    detail = format!(
                                        "iter {i} pie-glibc: expected 'ECHO_TEST_OK', got {resp:?}"
                                    );
                                    break;
                                }
                            }
                            if all_clean {
                                detail = format!(
                                    "{reps} interleaved {leg_label}+pie-glibc execs all clean"
                                );
                            }
                            super::TestOutcome::new(&a, all_clean, detail)
                        })
                    })
                });
            }
        }
    }
}
