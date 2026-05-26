// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fork/exec test matrix — multi-dimensional coverage via loops.
//!
//! Dimensions:
//! - Shell pattern × agent depth
//! - Exec binary type {`SelfExe`, Node} × agent depth
//! - Exec method {`ScriptFile`, `NestedBash`, `ExecInScript`, ...}
//! - Delayed fork: trigger × binary × invocation × depth × nesting
//! - Stress exec: mode × spawn method
//! - Non-PIE invocation method
//! - Contamination pattern (non-PIE then PIE, various depths)
//!
//! Hosted test-ID prefixes:
//! `X*`, `BSF`, `PIF`, `SXF` (original fork-matrix families),
//! `BASH.*` (bash fork/exec), `FWE.*` (fork+exec from non-PIE worker-exec
//! hosts), `SK.*` (SIGKILL subtree teardown).

use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

use super::agents::{AgentHandle, AgentName, SpawnKind};
use super::matrix::{EXEC, ExecArgs};
use super::registry::Registry;
use super::run_context::RunContext;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::protocol::{Command as InfraCommand, Response};
use crate::register_handler;
use crate::register_leaf_subcommand;

#[derive(Clone, Serialize, Deserialize)]
struct BashArgs {
    cmd: String,
    timeout_secs: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ExecBinArgs {
    argv: Vec<String>,
    timeout_secs: Option<u64>,
}

const BASH: HandlerToken<BashArgs, Response> = HandlerToken::new("fork_matrix.bash");
const EXEC_BIN: HandlerToken<ExecBinArgs, Response> = HandlerToken::new("fork_matrix.exec_bin");

async fn handle_bash(args: BashArgs, _ctx: &mut HandlerCtx<'_>) -> Result<Response, HandlerError> {
    Ok(run_exec_argv(
        vec!["bash".into(), "-c".into(), args.cmd],
        args.timeout_secs,
    )
    .await)
}

async fn handle_exec_bin(
    args: ExecBinArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, HandlerError> {
    Ok(run_exec_argv(args.argv, args.timeout_secs).await)
}

async fn dispatch_bash(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    cmd: String,
    timeout_secs: Option<u64>,
) -> Response {
    run.send_named_typed(handle, &BASH, BashArgs { cmd, timeout_secs })
        .await
        .unwrap_or_else(|error| Response::Error { error })
}

async fn dispatch_exec_bin(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    argv: Vec<String>,
    timeout_secs: Option<u64>,
) -> Response {
    run.send_named_typed(handle, &EXEC_BIN, ExecBinArgs { argv, timeout_secs })
        .await
        .unwrap_or_else(|error| Response::Error { error })
}

async fn run_exec_argv(argv: Vec<String>, timeout_secs: Option<u64>) -> Response {
    if argv.is_empty() {
        return Response::Error {
            error: "exec: empty argv".into(),
        };
    }

    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Response::Error {
                error: format!("exec spawn: {e}"),
            };
        }
    };

    let mut child_stdout = child.stdout.take().expect("stdout was piped");
    let mut child_stderr = child.stderr.take().expect("stderr was piped");
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(10));
    let result = tokio::time::timeout(timeout, async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let (stdout_result, stderr_result, status) = tokio::join!(
            child_stdout.read_to_end(&mut out),
            child_stderr.read_to_end(&mut err),
            child.wait(),
        );
        let _ = stdout_result;
        let _ = stderr_result;
        (out, err, status)
    })
    .await;

    match result {
        Ok((out, err, Ok(status))) => Response::ExecResult {
            exit_code: status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out).to_string(),
            stderr: String::from_utf8_lossy(&err).to_string(),
        },
        Ok((_, _, Err(e))) => Response::Error {
            error: format!("exec wait: {e}"),
        },
        Err(_) => {
            let _ = child.start_kill();
            Response::ExecTimeout {
                stderr: format!(
                    "process timed out after {}s (likely deadlocked)",
                    timeout.as_secs()
                ),
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct BufferedScmForkArgs {
    child_target: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct BufferedScmForkOut {
    detail: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct SocketpairForkCrossArgs {
    child_target: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct SocketpairForkCrossOut {
    detail: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct PidfdInheritForkArgs {
    child_target: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PidfdInheritForkOut {
    detail: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct StressExecArgs {
    count: usize,
    mode: String,
    use_tokio: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct StressExecOut {
    detail: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct TriggerDelayedForkArgs {
    cmd: String,
    args: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct TriggerDelayedForkOut {
    detail: String,
}

const BUFFERED_SCM_FORK: HandlerToken<BufferedScmForkArgs, BufferedScmForkOut> =
    HandlerToken::new("fork_matrix.buffered_scm_fork");
const SOCKETPAIR_FORK_CROSS: HandlerToken<SocketpairForkCrossArgs, SocketpairForkCrossOut> =
    HandlerToken::new("fork_matrix.socketpair_fork_cross");
const PIDFD_INHERIT_FORK: HandlerToken<PidfdInheritForkArgs, PidfdInheritForkOut> =
    HandlerToken::new("fork_matrix.pidfd_inherit_fork");
const STRESS_EXEC: HandlerToken<StressExecArgs, StressExecOut> =
    HandlerToken::new("fork_matrix.stress_exec");
const TRIGGER_DELAYED_FORK: HandlerToken<TriggerDelayedForkArgs, TriggerDelayedForkOut> =
    HandlerToken::new("fork_matrix.trigger_delayed_fork");
const TRIGGER_DELAYED_FORK_THREAD: HandlerToken<TriggerDelayedForkArgs, TriggerDelayedForkOut> =
    HandlerToken::new("fork_matrix.trigger_delayed_fork_thread");

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

const fn fork_binary_label(bt: crate::BinaryType) -> &'static str {
    match bt {
        crate::BinaryType::PieGlibc => "self",
        crate::BinaryType::NonPieGlibc => "nonpie",
        crate::BinaryType::StaticPieGlibc => "static-pie-glibc",
        crate::BinaryType::StaticPieMusl => "static-pie-musl",
        crate::BinaryType::NonPieStaticMusl => "non-pie-static-musl",
    }
}

fn wait_exit_code(pid: libc::pid_t) -> i32 {
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        99
    }
}

async fn handle_buffered_scm_fork(
    args: BufferedScmForkArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<BufferedScmForkOut, HandlerError> {
    Ok(BufferedScmForkOut {
        detail: buffered_scm_fork(&args.child_target),
    })
}

async fn handle_socketpair_fork_cross(
    args: SocketpairForkCrossArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<SocketpairForkCrossOut, HandlerError> {
    Ok(SocketpairForkCrossOut {
        detail: socketpair_fork_cross(&args.child_target),
    })
}

async fn handle_pidfd_inherit_fork(
    args: PidfdInheritForkArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PidfdInheritForkOut, HandlerError> {
    Ok(PidfdInheritForkOut {
        detail: pidfd_inherit_fork(&args.child_target),
    })
}

async fn handle_stress_exec(
    args: StressExecArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<StressExecOut, HandlerError> {
    let self_exe =
        std::env::current_exe().map_err(|e| HandlerError::from(format!("current_exe: {e}")))?;
    let self_exe = self_exe.to_string_lossy().to_string();
    let mode = args.mode.as_str();
    let nonpie_bin: String = if matches!(mode, "nonpie" | "mixed") {
        crate::nonpie_binary()
    } else {
        String::new()
    };
    let mut failures = 0;
    let mut detail = format!(
        "STRESS_START mode={} count={} tokio={}\n",
        args.mode, args.count, args.use_tokio
    );

    if args.use_tokio {
        for i in 0..args.count {
            let (cmd, cmd_args, expected): (&str, &[&str], &str) = match mode {
                "nonpie" => (&nonpie_bin, &["echo-test"], "ECHO_TEST_OK"),
                "mixed" if i % 2 == 0 => (&self_exe, &["echo-test"], "ECHO_TEST_OK"),
                "mixed" => (&nonpie_bin, &["echo-test"], "ECHO_TEST_OK"),
                _ => (&self_exe, &["echo-test"], "ECHO_TEST_OK"),
            };
            let result = tokio::process::Command::new(cmd)
                .args(cmd_args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await;
            match result {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if stdout == expected {
                        detail.push_str(&format!("i={i} ok={stdout}\n"));
                    } else {
                        detail.push_str(&format!(
                            "i={i} FAIL: expected={expected:?} got={stdout:?} exit={}\n",
                            out.status
                        ));
                        failures += 1;
                    }
                }
                Err(e) => {
                    detail.push_str(&format!("i={i} FAIL: spawn error: {e}\n"));
                    failures += 1;
                }
            }
        }
    } else {
        for i in 0..args.count {
            let (cmd, cmd_args, expected): (&str, &[&str], &str) = match mode {
                "nonpie" => (&nonpie_bin, &["echo-test"], "ECHO_TEST_OK"),
                "mixed" if i % 2 == 0 => (&self_exe, &["echo-test"], "ECHO_TEST_OK"),
                "mixed" => (&nonpie_bin, &["echo-test"], "ECHO_TEST_OK"),
                _ => (&self_exe, &["echo-test"], "ECHO_TEST_OK"),
            };
            let result = std::process::Command::new(cmd)
                .args(cmd_args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output();
            match result {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if stdout == expected {
                        detail.push_str(&format!("i={i} ok={stdout}\n"));
                    } else {
                        detail.push_str(&format!(
                            "i={i} FAIL: expected={expected:?} got={stdout:?} exit={}\n",
                            out.status
                        ));
                        failures += 1;
                    }
                }
                Err(e) => {
                    detail.push_str(&format!("i={i} FAIL: spawn error: {e}\n"));
                    failures += 1;
                }
            }
        }
    }

    detail.push_str(&format!("STRESS_END failures={failures}"));
    Ok(StressExecOut { detail })
}

async fn handle_trigger_delayed_fork(
    args: TriggerDelayedForkArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<TriggerDelayedForkOut, HandlerError> {
    let trigger: Vec<u8> = vec![0u8; 64 * 1024];
    assert_eq!(trigger[0], 0);
    run_trigger_command(args).await
}

async fn handle_trigger_delayed_fork_thread(
    args: TriggerDelayedForkArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<TriggerDelayedForkOut, HandlerError> {
    let handle = std::thread::spawn(|| {});
    handle
        .join()
        .map_err(|_| HandlerError::from("thread join failed"))?;
    run_trigger_command(args).await
}

async fn run_trigger_command(
    args: TriggerDelayedForkArgs,
) -> Result<TriggerDelayedForkOut, HandlerError> {
    let output = tokio::process::Command::new(&args.cmd)
        .args(&args.args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| HandlerError::from(format!("nested fork+exec failed: {e}")))?;
    if !output.status.success() {
        return Err(HandlerError::from(format!(
            "nested fork+exec exit={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(TriggerDelayedForkOut {
        detail: String::from_utf8_lossy(&output.stdout).to_string(),
    })
}

fn buffered_scm_fork(child_exe: &str) -> String {
    if child_exe.is_empty() {
        return "BSF_USAGE: buffered-scm-fork <child_exe>".into();
    }
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        return format!("BSF_SOCKETPAIR_FAIL:{}", errno());
    }
    let s_send = fds[0];
    let s_recv = fds[1];

    let ev = unsafe { libc::eventfd(0, 0) };
    if ev < 0 {
        return format!("BSF_EVENTFD_FAIL:{}", errno());
    }

    let payload = b"BSF";
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut cmsg_buf = [0u8; 32];
    let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = cmsg_buf.len() as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(core::mem::size_of::<i32>() as u32) as _;
        let data = libc::CMSG_DATA(cmsg).cast::<i32>();
        data.write_unaligned(ev);
        msg.msg_controllen = libc::CMSG_SPACE(core::mem::size_of::<i32>() as u32) as _;
    }
    let n = unsafe { libc::sendmsg(s_send, &raw const msg, 0) };
    if n < 0 {
        return format!("BSF_SENDMSG_FAIL:{}", errno());
    }

    unsafe {
        libc::close(s_send);
        libc::close(ev);
        libc::fcntl(s_recv, libc::F_SETFD, 0);
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return format!("BSF_FORK_FAIL:{}", errno());
    }

    if pid == 0 {
        let fd_str = s_recv.to_string();
        let c_exe = std::ffi::CString::new(child_exe).unwrap();
        let c_a1 = std::ffi::CString::new("buffered-scm-fork-child").unwrap();
        let c_a2 = std::ffi::CString::new(fd_str.as_str()).unwrap();
        let argv = [
            c_exe.as_ptr(),
            c_a1.as_ptr(),
            c_a2.as_ptr(),
            core::ptr::null(),
        ];
        unsafe { libc::execv(c_exe.as_ptr(), argv.as_ptr()) };
        eprintln!("[BSF-child] execv failed: {}", errno());
        std::process::exit(127);
    }

    unsafe { libc::close(s_recv) };
    let exit_code = wait_exit_code(pid);
    if exit_code == 0 {
        "BSF_OK".into()
    } else {
        format!("BSF_FAIL:exit={exit_code}")
    }
}

fn socketpair_fork_cross(child_exe: &str) -> String {
    if child_exe.is_empty() {
        return "SXF_USAGE: socketpair-fork-cross <child_exe>".into();
    }
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        return format!("SXF_SOCKETPAIR_FAIL:{}", errno());
    }
    let parent_fd = fds[0];
    let child_fd = fds[1];
    unsafe { libc::fcntl(child_fd, libc::F_SETFD, 0) };

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return format!("SXF_FORK_FAIL:{}", errno());
    }
    if pid == 0 {
        unsafe { libc::close(parent_fd) };
        let fd_str = child_fd.to_string();
        let c_exe = std::ffi::CString::new(child_exe).unwrap();
        let c_a1 = std::ffi::CString::new("socketpair-fork-cross-child").unwrap();
        let c_a2 = std::ffi::CString::new(fd_str.as_str()).unwrap();
        let argv = [
            c_exe.as_ptr(),
            c_a1.as_ptr(),
            c_a2.as_ptr(),
            core::ptr::null(),
        ];
        unsafe { libc::execv(c_exe.as_ptr(), argv.as_ptr()) };
        eprintln!("[SXF-child] execv failed: {}", errno());
        std::process::exit(127);
    }
    unsafe { libc::close(child_fd) };

    let tv = libc::timeval {
        tv_sec: 10,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            parent_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast::<libc::c_void>(),
            core::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let ping = b"SXF_PING";
    let w = unsafe { libc::write(parent_fd, ping.as_ptr().cast::<libc::c_void>(), ping.len()) };
    if w != ping.len() as isize {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        return format!("SXF_WRITE_FAIL:n={w} errno={}", errno());
    }
    let mut buf = [0u8; 32];
    let n = unsafe {
        libc::read(
            parent_fd,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
        )
    };
    unsafe { libc::close(parent_fd) };
    let exit_code = wait_exit_code(pid);
    if n <= 0 {
        return format!("SXF_READ_FAIL:n={n},errno={},exit={exit_code}", errno());
    }
    let reply = core::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
    if reply == "SXF_PONG" && exit_code == 0 {
        "SXF_OK".into()
    } else {
        format!("SXF_FAIL:reply={reply},exit={exit_code}")
    }
}

fn pidfd_inherit_fork(child_exe: &str) -> String {
    if child_exe.is_empty() {
        return "PIF_USAGE: pidfd-inherit-fork <child_exe>".into();
    }
    let gpid = unsafe { libc::fork() };
    if gpid < 0 {
        return format!("PIF_GRANDCHILD_FORK_FAIL:{}", errno());
    }
    if gpid == 0 {
        unsafe { libc::sleep(2) };
        std::process::exit(0);
    }

    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, gpid, 0) } as i32;
    if pidfd < 0 {
        unsafe { libc::kill(gpid, libc::SIGKILL) };
        return format!("PIF_PIDFD_OPEN_FAIL:{}", errno());
    }
    unsafe { libc::fcntl(pidfd, libc::F_SETFD, 0) };

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe { libc::kill(gpid, libc::SIGKILL) };
        return format!("PIF_FORK_FAIL:{}", errno());
    }
    if pid == 0 {
        let fd_str = pidfd.to_string();
        let gpid_str = gpid.to_string();
        let c_exe = std::ffi::CString::new(child_exe).unwrap();
        let c_a1 = std::ffi::CString::new("pidfd-inherit-child").unwrap();
        let c_a2 = std::ffi::CString::new(fd_str.as_str()).unwrap();
        let c_a3 = std::ffi::CString::new(gpid_str.as_str()).unwrap();
        let argv = [
            c_exe.as_ptr(),
            c_a1.as_ptr(),
            c_a2.as_ptr(),
            c_a3.as_ptr(),
            core::ptr::null(),
        ];
        unsafe { libc::execv(c_exe.as_ptr(), argv.as_ptr()) };
        eprintln!("[PIF-child] execv failed: {}", errno());
        std::process::exit(127);
    }
    unsafe { libc::close(pidfd) };

    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    let child_exit = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        99
    };
    unsafe { libc::waitpid(gpid, &raw mut status, libc::WNOHANG) };

    if child_exit == 0 {
        "PIF_OK".into()
    } else {
        format!("PIF_FAIL:exit={child_exit}")
    }
}

mod leaf_subcmd {
    pub(super) fn subcmd_buffered_scm_fork_child(args: &[String]) -> i32 {
        let fd: i32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(-1);
        if fd < 0 {
            eprintln!("[BSF-child] bad fd arg");
            return 1;
        }
        let mut buf = [0u8; 32];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: buf.len(),
        };
        let mut cmsg_buf = [0u8; 64];
        let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = cmsg_buf.len() as _;
        let n = unsafe { libc::recvmsg(fd, &raw mut msg, 0) };
        if n < 0 {
            eprintln!("[BSF-child] recvmsg failed: {}", super::errno());
            return 2;
        }
        let mut got_ev: i32 = -1;
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let data = libc::CMSG_DATA(cmsg).cast::<i32>();
                    got_ev = data.read_unaligned();
                    break;
                }
                cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
            }
        }
        if got_ev < 0 {
            eprintln!("[BSF-child] no SCM_RIGHTS in recvmsg result");
            return 3;
        }
        let v: u64 = 0x4243_5f4f_4b21;
        let w = unsafe { libc::write(got_ev, (&raw const v).cast::<libc::c_void>(), 8) };
        if w != 8 {
            eprintln!(
                "[BSF-child] write to ev failed: w={w} errno={}",
                super::errno()
            );
            return 4;
        }
        let mut r: u64 = 0;
        let rn = unsafe { libc::read(got_ev, (&raw mut r).cast::<libc::c_void>(), 8) };
        unsafe {
            libc::close(got_ev);
            libc::close(fd);
        }
        if rn != 8 || r != v {
            eprintln!("[BSF-child] read mismatch: rn={rn} r={r:#x} expected={v:#x}");
            return 5;
        }
        0
    }

    pub(super) fn subcmd_socketpair_fork_cross_child(args: &[String]) -> i32 {
        let fd: i32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(-1);
        if fd < 0 {
            eprintln!("[SXF-child] bad fd arg");
            return 1;
        }
        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast::<libc::c_void>(),
                core::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
        let mut buf = [0u8; 32];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n <= 0 {
            eprintln!("[SXF-child] read failed: n={n} errno={}", super::errno());
            return 2;
        }
        let msg = core::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
        if msg != "SXF_PING" {
            eprintln!("[SXF-child] unexpected msg: {msg}");
            return 3;
        }
        let pong = b"SXF_PONG";
        let w = unsafe { libc::write(fd, pong.as_ptr().cast::<libc::c_void>(), pong.len()) };
        unsafe { libc::close(fd) };
        if w == pong.len() as isize { 0 } else { 4 }
    }

    pub(super) fn subcmd_pidfd_inherit_child(args: &[String]) -> i32 {
        let pidfd: i32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(-1);
        let gpid: i32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(-1);
        if pidfd < 0 || gpid < 0 {
            eprintln!("[PIF-child] bad args");
            return 1;
        }
        let mut pfd = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&raw mut pfd, 1, 10_000) };
        unsafe { libc::close(pidfd) };
        if rc <= 0 {
            eprintln!("[PIF-child] poll failed: rc={rc} errno={}", super::errno());
            return 2;
        }
        if pfd.revents & libc::POLLIN == 0 {
            eprintln!("[PIF-child] no POLLIN: revents={}", pfd.revents);
            return 3;
        }
        let _ = gpid;
        0
    }

    /// `fork-exec-pie` — drives the FWE test family.
    ///
    /// Stays as an argv subcommand because the test specifically exercises
    /// the legacy two-level fork+exec path: agent → subcommand-dispatched
    /// child (this fn) → grandchild of the target binary type. Converting
    /// the child to a leaf agent changed the test surface to "agent → leaf
    /// agent → grandchild", which exercises a different code path that hit
    /// timeouts in the litebox shim.
    ///
    /// Usage: `fork-exec-pie <binary> [subcommand]`
    /// Forks a child that exec's the given binary with the given subcommand
    /// (default `echo-test`), waits up to 15 s, prints
    /// `FORK_EXEC_PIE_OK` or `FORK_EXEC_PIE_FAIL:reason`.
    pub(super) fn subcmd_fork_exec_pie(args: &[String]) -> i32 {
        let binary = args.get(2).map_or_else(
            || {
                for p in ["/opt/litebox/litebox_test_harness"] {
                    if std::path::Path::new(p).exists() {
                        return p;
                    }
                }
                "/opt/litebox/litebox_test_harness"
            },
            String::as_str,
        );
        let sub = args.get(3).map_or("echo-test", String::as_str);
        eprintln!(
            "[fork-exec-pie] pid={} forking child to exec {binary} {sub}",
            std::process::id()
        );

        // SAFETY: libc::fork() takes no arguments and returns child pid (0 in child).
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            eprintln!(
                "[fork-exec-pie] fork failed: {}",
                std::io::Error::last_os_error()
            );
            println!("FORK_EXEC_PIE_FAIL:fork");
            return 1;
        }
        if pid == 0 {
            use std::ffi::CString;
            let bin = CString::new(binary).expect("binary has no NUL");
            let arg_sub = CString::new(sub).expect("sub has no NUL");
            let exec_argv = [bin.as_ptr(), arg_sub.as_ptr(), core::ptr::null()];
            // SAFETY: NUL-terminated argv; execv replaces the process image.
            unsafe { libc::execv(bin.as_ptr(), exec_argv.as_ptr()) };
            let err = std::io::Error::last_os_error();
            eprintln!("[fork-exec-pie] child execv failed: {err}");
            std::process::exit(127);
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut status = 0i32;
        loop {
            // SAFETY: waitpid takes a live child pid and a writable status pointer.
            let ret = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
            if ret > 0 {
                if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                    println!("FORK_EXEC_PIE_OK");
                    return 0;
                }
                println!("FORK_EXEC_PIE_FAIL:exit={status}");
                return 1;
            }
            if std::time::Instant::now() >= deadline {
                // SAFETY: pid is the child being timed out.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                // SAFETY: reap the child after SIGKILL.
                unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
                println!("FORK_EXEC_PIE_FAIL:timeout");
                return 1;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// SHELL PATTERNS × DEPTH
// ═══════════════════════════════════════════════════════════════════

struct ShellPattern {
    name: &'static str,
    cmd: &'static str,
    expected: &'static str, // empty = just check non-empty stdout + exit 0
}

const SHELL_PATTERNS: &[ShellPattern] = &[
    ShellPattern {
        name: "echo",
        cmd: "echo hello_from_bash",
        expected: "hello_from_bash",
    },
    ShellPattern {
        name: "cmd_substitution",
        cmd: "echo $(echo inner_value)",
        expected: "inner_value",
    },
    ShellPattern {
        name: "pipe_in_subshell",
        cmd: "echo $(echo pipe_data | cat)",
        expected: "pipe_data",
    },
    ShellPattern {
        name: "process_substitution",
        cmd: "cat <(echo proc_sub_data)",
        expected: "proc_sub_data",
    },
    ShellPattern {
        name: "simple_pipe",
        cmd: "echo pipe_two_stage | cat",
        expected: "pipe_two_stage",
    },
    ShellPattern {
        name: "three_stage_pipe",
        cmd: "echo three_stage | cat | cat",
        expected: "three_stage",
    },
    ShellPattern {
        name: "background_wait",
        cmd: "sleep 0 & wait; echo bg_done",
        expected: "bg_done",
    },
    ShellPattern {
        name: "multi_background",
        cmd: "echo bg_a & echo bg_b & wait",
        expected: "bg_a",
    },
    ShellPattern {
        name: "subshell_exit_code",
        cmd: "(exit 42); echo $?",
        expected: "42",
    },
    ShellPattern {
        name: "sequential_cmds",
        cmd: "echo seq_a && echo seq_b && echo seq_c",
        expected: "seq_a",
    },
    ShellPattern {
        name: "nested_subshell",
        cmd: "echo $(echo $(echo deep_nested))",
        expected: "deep_nested",
    },
    ShellPattern {
        name: "heredoc",
        cmd: "cat <<'EOF'\nheredoc_line\nEOF",
        expected: "heredoc_line",
    },
    ShellPattern {
        name: "herestring",
        cmd: "cat <<< 'herestring_data'",
        expected: "herestring_data",
    },
    ShellPattern {
        name: "pipe_grep",
        cmd: "echo -e 'alpha\\nbeta\\ngamma' | grep beta",
        expected: "beta",
    },
    ShellPattern {
        name: "subshell_pipe_wc",
        cmd: "echo $(echo 'line1\\nline2\\nline3' | wc -l)",
        expected: "",
    },
    ShellPattern {
        name: "backtick_subst",
        cmd: "echo `echo backtick_val`",
        expected: "backtick_val",
    },
    ShellPattern {
        name: "pipe_while_read",
        cmd: "echo -e 'a\\nb\\nc' | while read line; do echo \"got_$line\"; done",
        expected: "got_a",
    },
    ShellPattern {
        name: "xargs",
        cmd: "echo -e 'p\\nq\\nr' | xargs -I{} echo xargs_{}",
        expected: "xargs_p",
    },
];

const DEPTH_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,
    AgentName::Dpg1Dpg1,
    AgentName::Dpg1Dpg1Dpg1,
];

// ═══════════════════════════════════════════════════════════════════
// EXEC BINARY × DEPTH
// ═══════════════════════════════════════════════════════════════════

/// Binary type for direct exec tests.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum ExecBinary {
    Node,
}

#[allow(dead_code)]
impl ExecBinary {
    fn suffix(self) -> &'static str {
        match self {
            Self::Node => "node",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// EXEC METHOD (script files, nested bash, etc.)
// ═══════════════════════════════════════════════════════════════════

struct ExecMethodCase {
    name: &'static str,
    /// Bash -c command. {`self_exe`} is replaced with the test binary path.
    cmd_template: &'static str,
    expected: &'static str,
}

const EXEC_METHODS: &[ExecMethodCase] = &[
    ExecMethodCase {
        name: "script_echo",
        cmd_template: "echo '#!/usr/bin/bash' > /tmp/xm.sh && echo 'echo script_echo_ok' >> /tmp/xm.sh && chmod +x /tmp/xm.sh && /tmp/xm.sh; EXIT=$?; rm -f /tmp/xm.sh; exit $EXIT",
        expected: "script_echo_ok",
    },
    ExecMethodCase {
        name: "script_node",
        cmd_template: "echo '#!/usr/bin/bash' > /tmp/xm.sh && echo '/usr/local/bin/node -e \"console.log(\\\"script_node_ok\\\")\"' >> /tmp/xm.sh && chmod +x /tmp/xm.sh && /tmp/xm.sh; EXIT=$?; rm -f /tmp/xm.sh; exit $EXIT",
        expected: "script_node_ok",
    },
    ExecMethodCase {
        name: "script_env_shebang",
        cmd_template: "echo '#!/usr/bin/env bash' > /tmp/xm.sh && echo 'echo script_env_ok' >> /tmp/xm.sh && chmod +x /tmp/xm.sh && /tmp/xm.sh; EXIT=$?; rm -f /tmp/xm.sh; exit $EXIT",
        expected: "script_env_ok",
    },
    ExecMethodCase {
        name: "script_cat_pipe",
        cmd_template: "echo '#!/usr/bin/bash' > /tmp/xm.sh && echo 'echo cat_input | cat' >> /tmp/xm.sh && chmod +x /tmp/xm.sh && /tmp/xm.sh; EXIT=$?; rm -f /tmp/xm.sh; exit $EXIT",
        expected: "cat_input",
    },
    ExecMethodCase {
        name: "nested_bash_node",
        cmd_template: "bash -c '/usr/local/bin/node -e \"console.log(\\\"nested_ok\\\")\"'",
        expected: "nested_ok",
    },
    ExecMethodCase {
        name: "script_exec_node",
        cmd_template: "echo '#!/usr/bin/bash' > /tmp/xm.sh && echo 'exec /usr/local/bin/node -e \"console.log(\\\"exec_ok\\\")\"' >> /tmp/xm.sh && chmod +x /tmp/xm.sh && /tmp/xm.sh; EXIT=$?; rm -f /tmp/xm.sh; exit $EXIT",
        expected: "exec_ok",
    },
];

// ═══════════════════════════════════════════════════════════════════
// DELAYED FORK: trigger × binary × invocation × depth × nesting
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy)]
enum DfTrigger {
    Mmap,
    Thread,
}

impl DfTrigger {
    fn suffix(self) -> &'static str {
        match self {
            Self::Mmap => "mmap",
            Self::Thread => "thread",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum DfBinary {
    Harness(crate::BinaryType),
    Node,
}

impl DfBinary {
    fn suffix(self) -> &'static str {
        match self {
            Self::Harness(bt) => bt.label(),
            Self::Node => "node",
        }
    }
    fn expected(self) -> &'static str {
        match self {
            Self::Harness(_) => "ECHO_TEST_OK",
            Self::Node => "df_node_ok",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum DfInvocation {
    Direct,
    ScriptFile,
}

impl DfInvocation {
    fn suffix(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::ScriptFile => "script",
        }
    }
}

const DF_TRIGGERS: &[DfTrigger] = &[DfTrigger::Mmap, DfTrigger::Thread];
const DF_BINARIES: &[DfBinary] = &[
    DfBinary::Harness(crate::BinaryType::PieGlibc),
    DfBinary::Harness(crate::BinaryType::NonPieGlibc),
    DfBinary::Harness(crate::BinaryType::StaticPieGlibc),
    DfBinary::Harness(crate::BinaryType::StaticPieMusl),
    DfBinary::Harness(crate::BinaryType::NonPieStaticMusl),
    DfBinary::Node,
];
const DF_INVOCATIONS: &[DfInvocation] = &[DfInvocation::Direct, DfInvocation::ScriptFile];
const DF_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1];

// ═══════════════════════════════════════════════════════════════════
// STRESS EXEC: mode × spawn method
// ═══════════════════════════════════════════════════════════════════

const STRESS_MODES: &[&str] = &["pie", "nonpie", "mixed"];
const SPAWN_METHODS: &[(&str, &[&str])] = &[("sync", &[]), ("tokio", &["tokio"])];

// ═══════════════════════════════════════════════════════════════════
// NON-PIE INVOCATION METHOD
// ═══════════════════════════════════════════════════════════════════

struct NonPieCase {
    name: &'static str,
    /// Bash command (None = direct exec of /nonpie-echo).
    bash_cmd: Option<&'static str>,
}

const NONPIE_CASES: &[NonPieCase] = &[
    NonPieCase {
        name: "direct",
        bash_cmd: None,
    },
    NonPieCase {
        name: "script",
        bash_cmd: Some(
            "if [ -x /nonpie-bin ]; then \
             echo '#!/usr/bin/bash' > /tmp/xnp.sh && \
             echo '/nonpie-cmd' >> /tmp/xnp.sh && \
             chmod +x /tmp/xnp.sh && /tmp/xnp.sh; \
             EXIT=$?; rm -f /tmp/xnp.sh; exit $EXIT; \
             else echo SKIP; fi",
        ),
    },
    NonPieCase {
        name: "bash_inline",
        bash_cmd: Some("if [ -x /nonpie-bin ]; then /nonpie-cmd; else echo SKIP; fi"),
    },
];

// ═══════════════════════════════════════════════════════════════════
// CONTAMINATION PATTERNS
// ═══════════════════════════════════════════════════════════════════

struct ContaminationCase {
    name: &'static str,
    /// Bash command template. {`self_exe`} is replaced. None = special init-level test.
    bash_template: Option<&'static str>,
    expected: &'static str,
}

const CONTAMINATION_CASES: &[ContaminationCase] = &[
    ContaminationCase {
        name: "child_clean",
        bash_template: Some(
            "if [ -x /nonpie-bin ]; then \
             /nonpie-cmd >/dev/null 2>&1; echo CHILD_CLEAN; \
             else echo SKIP; fi",
        ),
        expected: "CHILD_CLEAN",
    },
    ContaminationCase {
        name: "child_sequential",
        bash_template: Some(
            "if [ -x /nonpie-bin ]; then \
             FIRST=$(/nonpie-cmd); SECOND=$({self_exe} echo-test); \
             echo \"first=$FIRST\"; echo \"second=$SECOND\"; \
             else echo SKIP; fi",
        ),
        expected: "second=ECHO_TEST_OK",
    },
    ContaminationCase {
        name: "grandchild_nonpie",
        bash_template: Some(
            "if [ -x /nonpie-bin ]; then bash -c '/nonpie-cmd'; else echo SKIP; fi",
        ),
        expected: "ECHO_TEST_OK",
    },
    ContaminationCase {
        name: "depth2_clean",
        bash_template: Some(
            "if [ -x /nonpie-bin ]; then \
             bash -c '/nonpie-cmd >/dev/null; {self_exe} echo-test'; \
             else echo SKIP; fi",
        ),
        expected: "ECHO_TEST_OK",
    },
];

// ═══════════════════════════════════════════════════════════════════
// RUNNER
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_fork_matrix(reg: &mut Registry<'_>) {
    register_handler!(BASH, handle_bash);
    register_handler!(EXEC_BIN, handle_exec_bin);
    register_handler!(BUFFERED_SCM_FORK, handle_buffered_scm_fork);
    register_handler!(SOCKETPAIR_FORK_CROSS, handle_socketpair_fork_cross);
    register_handler!(PIDFD_INHERIT_FORK, handle_pidfd_inherit_fork);
    register_handler!(STRESS_EXEC, handle_stress_exec);
    register_handler!(TRIGGER_DELAYED_FORK, handle_trigger_delayed_fork);
    register_handler!(
        TRIGGER_DELAYED_FORK_THREAD,
        handle_trigger_delayed_fork_thread
    );
    register_leaf_subcommand!(
        "buffered-scm-fork-child",
        leaf_subcmd::subcmd_buffered_scm_fork_child
    );
    register_leaf_subcommand!(
        "socketpair-fork-cross-child",
        leaf_subcmd::subcmd_socketpair_fork_cross_child
    );
    register_leaf_subcommand!(
        "pidfd-inherit-child",
        leaf_subcmd::subcmd_pidfd_inherit_child
    );

    // Shell patterns x depth
    for &agent in DEPTH_AGENTS {
        for pat in SHELL_PATTERNS {
            let id = format!("XB.{}.{agent}", pat.name);
            let agent_label = agent.to_string();
            let expected = pat.expected.to_string();
            let cmd_str = pat.cmd.to_string();

            reg.test("fork", "fork_matrix", id)
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        Box::pin(async move {
                            let resp = dispatch_bash(run, &handle, cmd_str, None).await;
                            let pass = if expected.is_empty() {
                                matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if !stdout.trim().is_empty()
                                )
                            } else {
                                matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if stdout.contains(&*expected)
                                )
                            };
                            let timeout = matches!(
                                &resp,
                                Response::ExecTimeout { stderr } if !stderr.is_empty()
                            );
                            super::TestOutcome::new(
                                &agent_label,
                                pass,
                                format!("timeout={timeout} {resp:?}"),
                            )
                        })
                    })
                });
        }
    }

    // Exec binary: Node x depth
    for &agent in DEPTH_AGENTS {
        let id = format!("X.node.{agent}");
        let agent_label = agent.to_string();
        reg.test("fork", "fork_matrix", id)
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    Box::pin(async move {
                        let expected = format!("node_{agent_label}_ok");
                        let resp = dispatch_exec_bin(
                            run,
                            &handle,
                            vec![
                                "/usr/local/bin/node".into(),
                                "-e".into(),
                                format!("console.log('node_{agent_label}_ok')"),
                            ],
                            None,
                        )
                        .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.contains(&expected)
                        );
                        super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                    })
                })
            });
    }

    // Node.js process.stdout.write
    reg.test("fork", "fork_matrix", "X.node_stdout_write.A")
        .timeout(60)
        .build(move |cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let resp = dispatch_exec_bin(
                        run,
                        &handle,
                        vec![
                            "/usr/local/bin/node".into(),
                            "-e".into(),
                            "process.stdout.write('stdout_write_ok\\n')".into(),
                        ],
                        None,
                    )
                    .await;
                    let pass = matches!(
                        &resp,
                        Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("stdout_write_ok")
                    );
                    super::TestOutcome::new("A", pass, format!("{resp:?}"))
                })
            })
        });

    // Exec method tests
    for em in EXEC_METHODS {
        let bts: &[Option<crate::BinaryType>] = if em.cmd_template.contains("{self_exe}") {
            &[
                Some(crate::BinaryType::PieGlibc),
                Some(crate::BinaryType::NonPieGlibc),
                Some(crate::BinaryType::StaticPieGlibc),
                Some(crate::BinaryType::StaticPieMusl),
                Some(crate::BinaryType::NonPieStaticMusl),
            ]
        } else {
            &[None]
        };
        for &bt_opt in bts {
            let id = match bt_opt {
                Some(bt) => format!("XM.{}.{}", bt.label(), em.name),
                None => format!("XM.{}", em.name),
            };
            let template = em.cmd_template.to_string();
            let expected = em.expected.to_string();
            let agent = AgentName::Dpg1;
            let agent_label = agent.to_string();
            reg.test("fork", "fork_matrix", id)
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let template = template.clone();
                        let expected = expected.clone();
                        let agent_label = agent_label.clone();
                        Box::pin(async move {
                            let self_exe = run.self_exe().to_string();
                            let target = match bt_opt {
                                Some(bt) => crate::binary_path(bt, &self_exe),
                                None => self_exe,
                            };
                            let cmd_str = template.replace("{self_exe}", &target);
                            let resp = dispatch_bash(run, &handle, cmd_str, None).await;
                            let pass = matches!(
                                &resp,
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.trim() == expected
                            );
                            super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }

    // XM.node_networkInterfaces — blockers-added family.
    // Doesn't take a BinaryType axis: the binary is the system node, not self_exe.
    for &(agent, suffix) in &[
        (AgentName::Dpg1, ""),
        (AgentName::Dpg1Dpg1, ".AA"),
        (AgentName::Dpg2, ".B"),
        (AgentName::Dpg1Dng, ".dpg1_dng"),
    ] {
        let id = format!("XM.node_networkInterfaces{suffix}");
        let agent_label = agent.to_string();
        reg.test("fork", "fork_matrix", id)
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let agent_label = agent_label.clone();
                    Box::pin(async move {
                        let resp = dispatch_exec_bin(
                            run,
                            &handle,
                            vec![
                                "/usr/local/bin/node".into(),
                                "-e".into(),
                                "try { const r = require('os').networkInterfaces(); \
                                 console.log('NETIF_OK:' + Object.keys(r).length); } \
                                 catch(e) { console.log('NETIF_ERR:' + e.code); }"
                                    .into(),
                            ],
                            Some(30),
                        )
                        .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout
                                    .lines()
                                    .find_map(|l| l.strip_prefix("NETIF_OK:"))
                                    .and_then(|s| s.trim().parse::<u32>().ok())
                                    .is_some_and(|n| n > 0)
                        );
                        super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                    })
                })
            });
    }

    // Delayed fork matrix
    for &trigger in DF_TRIGGERS {
        for &binary in DF_BINARIES {
            for &invocation in DF_INVOCATIONS {
                for &agent in DF_AGENTS {
                    let id = format!(
                        "XDF.{}.{}.{}.{agent}",
                        binary.suffix(),
                        trigger.suffix(),
                        invocation.suffix()
                    );
                    let agent_label = agent.to_string();
                    let binary_expected = binary.expected().to_string();

                    reg.test("fork", "fork_matrix", id)
                        .timeout(60)
                        .build(move |cx| {
                            let leaf = cx.declare_ephemeral(
                                agent,
                                format!(
                                    "XDF_{}_{}_{}_{agent}",
                                    binary.suffix(),
                                    trigger.suffix(),
                                    invocation.suffix()
                                ),
                                SpawnKind::Fork {
                                    binary: "self",
                                    inherit_listen_ports: vec![],
                                },
                            );
                            Box::new(move |run| {
                                let leaf = leaf.clone();
                                let agent_label = agent_label.clone();
                                let binary_expected = binary_expected.clone();
                                Box::pin(async move {
                                    let self_exe = run.self_exe().to_string();
                                    let (inner_cmd, inner_args): (String, Vec<String>) = match binary {
                                        DfBinary::Harness(bt) => {
                                            (crate::binary_path(bt, &self_exe), vec!["echo-test".into()])
                                        }
                                        DfBinary::Node => (
                                            "/usr/local/bin/node".into(),
                                            vec!["-e".into(), "console.log('df_node_ok')".into()],
                                        ),
                                    };
                                    let token = match trigger {
                                        DfTrigger::Mmap => &TRIGGER_DELAYED_FORK,
                                        DfTrigger::Thread => &TRIGGER_DELAYED_FORK_THREAD,
                                    };
                                    let result = run
                                        .run_leaf(
                                            &leaf,
                                            token,
                                            TriggerDelayedForkArgs {
                                                cmd: inner_cmd,
                                                args: inner_args,
                                            },
                                        )
                                        .await;
                                    let pass = matches!(&result, Ok(out) if out.detail.contains(&*binary_expected));
                                    super::TestOutcome::new(&agent_label, pass, format!("{result:?}"))
                                })
                            })
                        });
                }
            }
        }
    }

    // BSF.<bt> — buffered-SCM-fork. Validates p4-fork-restore-tokens:
    // parent buffers an eventfd in a socketpair's recv queue via
    // sendmsg(SCM_RIGHTS), then fork+execs into `bt`. When `bt` is a
    // different binary type from the parent (Dpg1), the cross-host
    // bridge in `commit_delayed_fork` must serialize the buffered
    // SCM_RIGHTS fd via a `BrokerFdToken` for the child to recvmsg
    // a working fd. Native: all binaries pass (real kernel keeps the
    // buffered fd live across fork). Litebox today: returns ENOSYS
    // when buffered_fds is non-empty for a cross-worker bridge.
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test("fork", "fork_matrix", format!("BSF.{bt_label}"))
            .timeout(60)
            .build(move |cx| {
                let leaf = cx.declare_ephemeral(
                    AgentName::Dpg1,
                    format!("BSF_{bt_label}"),
                    SpawnKind::Fork {
                        binary: "self",
                        inherit_listen_ports: vec![],
                    },
                );
                Box::new(move |run| {
                    let leaf = leaf.clone();
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let child_target = crate::binary_path(bt, &self_exe);
                        let result = run
                            .run_leaf(
                                &leaf,
                                &BUFFERED_SCM_FORK,
                                BufferedScmForkArgs { child_target },
                            )
                            .await;
                        let pass = matches!(&result, Ok(out) if out.detail.contains("BSF_OK"));
                        super::TestOutcome::new("A", pass, format!("{result:?}"))
                    })
                })
            });
    }

    // SXF.<bt> — socketpair-fork-cross. Validates p1-socketpair-fork:
    // parent socketpair → fork+execv into <bt> child → PING/PONG over
    // the inherited endpoint. When <bt> differs from the parent's
    // binary type (Dpg1), commit_delayed_fork must bridge both
    // endpoints across host workers. Today the bridge replaces the
    // unix socket with a external fd; the basic byte round-trip survives
    // but AF_UNIX semantics (SCM_RIGHTS, SO_PEERCRED, abstract names)
    // are lost — the BSF.<bt> test pins the SCM-loss subset.
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test("fork", "fork_matrix", format!("SXF.{bt_label}"))
            .timeout(60)
            .build(move |cx| {
                let leaf = cx.declare_ephemeral(
                    AgentName::Dpg1,
                    format!("SXF_{bt_label}"),
                    SpawnKind::Fork {
                        binary: "self",
                        inherit_listen_ports: vec![],
                    },
                );
                Box::new(move |run| {
                    let leaf = leaf.clone();
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let child_target = crate::binary_path(bt, &self_exe);
                        let result = run
                            .run_leaf(
                                &leaf,
                                &SOCKETPAIR_FORK_CROSS,
                                SocketpairForkCrossArgs { child_target },
                            )
                            .await;
                        let pass = matches!(&result, Ok(out) if out.detail.contains("SXF_OK"));
                        super::TestOutcome::new("A", pass, format!("{result:?}"))
                    })
                })
            });
    }

    // PIF.<bt> — pidfd-inherit-fork. Validates p1-pidfd-inherit:
    // parent spawns a grandchild, pidfd_open's it, fork+execvs into
    // <bt> child that poll+waitid's on the inherited pidfd. When <bt>
    // differs from the parent's binary type, commit_delayed_fork must
    // migrate the pidfd to the child's worker — there is currently no
    // broker-side pidfd state, so the migration may drop the pidfd or
    // fail outright.
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test("fork", "fork_matrix", format!("PIF.{bt_label}"))
            .timeout(60)
            .build(move |cx| {
                let leaf = cx.declare_ephemeral(
                    AgentName::Dpg1,
                    format!("PIF_{bt_label}"),
                    SpawnKind::Fork {
                        binary: "self",
                        inherit_listen_ports: vec![],
                    },
                );
                Box::new(move |run| {
                    let leaf = leaf.clone();
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let child_target = crate::binary_path(bt, &self_exe);
                        let result = run
                            .run_leaf(
                                &leaf,
                                &PIDFD_INHERIT_FORK,
                                PidfdInheritForkArgs { child_target },
                            )
                            .await;
                        let pass = matches!(&result, Ok(out) if out.detail.contains("PIF_OK"));
                        super::TestOutcome::new("A", pass, format!("{result:?}"))
                    })
                })
            });
    }

    // XDF.triple_nesting
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test(
            "fork",
            "fork_matrix",
            format!("XDF.{bt_label}.triple_nesting"),
        )
        .timeout(60)
        .build(move |cx| {
            let leaf = cx.declare_ephemeral(
                AgentName::Dpg1,
                format!("XDF_triple_{bt_label}"),
                SpawnKind::Fork {
                    binary: fork_binary_label(bt),
                    inherit_listen_ports: vec![],
                },
            );
            Box::new(move |run| {
                let leaf = leaf.clone();
                Box::pin(async move {
                    let self_exe = run.self_exe().to_string();
                    let target = crate::binary_path(bt, &self_exe);
                    let result = run
                        .run_leaf(
                            &leaf,
                            &TRIGGER_DELAYED_FORK,
                            TriggerDelayedForkArgs {
                                cmd: target,
                                args: vec!["echo-test".into()],
                            },
                        )
                        .await;
                    let pass = matches!(&result, Ok(out) if out.detail.contains("ECHO_TEST_OK"));
                    super::TestOutcome::new("A", pass, format!("{result:?}"))
                })
            })
        });
    }

    // Stress exec matrix
    for &mode in STRESS_MODES {
        for &(spawn_name, spawn_args) in SPAWN_METHODS {
            for &bt in crate::BinaryType::ALL {
                let bt_label = bt.label();
                let id = format!("XS.{bt_label}.{mode}.{spawn_name}");
                let mode_s = mode.to_string();
                let use_tokio = spawn_args.contains(&"tokio");
                reg.test("fork", "fork_matrix", id)
                    .timeout(60)
                    .build(move |cx| {
                        let leaf = cx.declare_ephemeral(
                            AgentName::Dpg1,
                            format!("XS_{bt_label}_{mode}_{spawn_name}"),
                            SpawnKind::Fork {
                                binary: fork_binary_label(bt),
                                inherit_listen_ports: vec![],
                            },
                        );
                        Box::new(move |run| {
                            let leaf = leaf.clone();
                            let mode_s = mode_s.clone();
                            Box::pin(async move {
                                let result = run
                                    .run_leaf(
                                        &leaf,
                                        &STRESS_EXEC,
                                        StressExecArgs {
                                            count: 10,
                                            mode: mode_s,
                                            use_tokio,
                                        },
                                    )
                                    .await;
                                let pass = matches!(
                                    &result,
                                    Ok(out) if out.detail.contains("STRESS_START")
                                        && out.detail.contains("STRESS_END failures=0")
                                );
                                super::TestOutcome::new("A", pass, format!("{result:?}"))
                            })
                        })
                    });
            }
        }
    }

    // Binary invocation tests
    for nc in NONPIE_CASES {
        for &bt in crate::BinaryType::ALL {
            let bt_label = bt.label();
            let id = format!("XNP.{bt_label}.{}", nc.name);
            let bash_cmd = nc.bash_cmd.map(std::string::ToString::to_string);
            reg.test("fork", "fork_matrix", id)
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(AgentName::Dpg1);
                    Box::new(move |run| {
                        let bash_cmd = bash_cmd.clone();
                        Box::pin(async move {
                            let self_exe = run.self_exe().to_string();
                            let target_bin = crate::binary_path(bt, &self_exe);
                            let resp = match &bash_cmd {
                                None => {
                                    dispatch_exec_bin(
                                        run,
                                        &handle,
                                        vec![target_bin.clone(), "echo-test".into()],
                                        None,
                                    )
                                    .await
                                }
                                Some(cmd) => {
                                    let resolved = cmd
                                        .replace("/nonpie-bin", &target_bin)
                                        .replace("/nonpie-cmd", &format!("{target_bin} echo-test"));
                                    dispatch_bash(run, &handle, resolved, None).await
                                }
                            };
                            let not_found =
                                matches!(&resp, Response::ExecResult { exit_code: 127, .. })
                                    || matches!(&resp, Response::Error { .. });
                            let skipped = matches!(
                                &resp,
                                Response::ExecResult { stdout, .. }
                                    if stdout.contains("SKIP")
                            );
                            if not_found || skipped {
                                return super::TestOutcome::new(
                                    "A",
                                    false,
                                    "FAIL: binary not found",
                                );
                            }
                            let pass = matches!(
                                &resp,
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.contains("ECHO_TEST_OK")
                            );
                            super::TestOutcome::new("A", pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }

    // XC.init_level
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test("fork", "fork_matrix", format!("XC.{bt_label}.init_level"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(AgentName::Dpg1);
                Box::new(move |run| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let nonpie_bin = crate::nonpie_binary();
                        let target = crate::binary_path(bt, &self_exe);
                        let resp = dispatch_exec_bin(
                            run,
                            &handle,
                            vec![nonpie_bin, "echo-test".into()],
                            None,
                        )
                        .await;
                        let not_found =
                            matches!(&resp, Response::ExecResult { exit_code: 127, .. })
                                || matches!(&resp, Response::Error { .. });
                        if not_found {
                            return super::TestOutcome::new(
                                "A",
                                false,
                                "FAIL: nonpie binary not found",
                            );
                        }
                        let resp2 =
                            dispatch_exec_bin(run, &handle, vec![target, "echo-test".into()], None)
                                .await;
                        let pass = matches!(
                            &resp2,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.trim() == "ECHO_TEST_OK"
                        );
                        super::TestOutcome::new("A", pass, format!("{resp2:?}"))
                    })
                })
            });
    }

    // Contamination pattern cases
    for cc in CONTAMINATION_CASES {
        let bts: &[Option<crate::BinaryType>] = if cc.bash_template.unwrap().contains("{self_exe}")
        {
            &[
                Some(crate::BinaryType::PieGlibc),
                Some(crate::BinaryType::NonPieGlibc),
                Some(crate::BinaryType::StaticPieGlibc),
                Some(crate::BinaryType::StaticPieMusl),
                Some(crate::BinaryType::NonPieStaticMusl),
            ]
        } else {
            &[None]
        };
        for &bt_opt in bts {
            let id = match bt_opt {
                Some(bt) => format!("XC.{}.{}", bt.label(), cc.name),
                None => format!("XC.{}", cc.name),
            };
            let template = cc.bash_template.unwrap().to_string();
            let expected = cc.expected.to_string();
            reg.test("fork", "fork_matrix", id)
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(AgentName::Dpg1);
                    Box::new(move |run| {
                        let template = template.clone();
                        let expected = expected.clone();
                        Box::pin(async move {
                            let self_exe = run.self_exe().to_string();
                            let nonpie_bin = crate::nonpie_binary();
                            let target = match bt_opt {
                                Some(bt) => crate::binary_path(bt, &self_exe),
                                None => self_exe,
                            };
                            let nonpie_cmd = format!("{nonpie_bin} echo-test");
                            let cmd_str = template
                                .replace("{self_exe}", &target)
                                .replace("/nonpie-bin", &nonpie_bin)
                                .replace("/nonpie-cmd", &nonpie_cmd);
                            let resp = dispatch_bash(run, &handle, cmd_str, None).await;
                            let skipped = matches!(
                                &resp,
                                Response::ExecResult { stdout, .. }
                                    if stdout.contains("SKIP")
                            );
                            if skipped {
                                return super::TestOutcome::new(
                                    "A",
                                    false,
                                    "FAIL: nonpie binary not found",
                                );
                            }
                            let pass = matches!(
                                &resp,
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.contains(&*expected)
                            );
                            super::TestOutcome::new("A", pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}

/// Convenience: build an `ExecArgs` with just an argv and sensible defaults.
fn exec_args(args: Vec<String>) -> ExecArgs {
    ExecArgs {
        args,
        timeout_secs: None,
        stdin: None,
        background: false,
        env: vec![],
    }
}

// ═══════════════════════════════════════════════════════════════════
// BASH: bash fork/exec tests (bash fork/exec tests)
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_bash_fork_exec_tests(reg: &mut Registry<'_>) {
    for &agent in &[AgentName::Dpg1, AgentName::Dpg2] {
        let agent_s = agent.to_string();

        // BASH.fork_ls: bash -c running ls
        let a = agent_s.clone();
        reg.test("fork", "bash_fork_exec", format!("BASH.fork_ls.{agent}"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = a.clone();
                    Box::pin(async move {
                        let resp = run
                            .typed_or_error(
                                &handle,
                                &EXEC,
                                exec_args(vec![
                                    "bash".into(),
                                    "-c".into(),
                                    "ls / > /dev/null && echo LS_OK".into(),
                                ]),
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.contains("LS_OK")
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });

        // BASH.fork_subst: bash -c with command substitution
        let a = agent_s.clone();
        reg.test("fork", "bash_fork_exec", format!("BASH.fork_subst.{agent}"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = a.clone();
                    Box::pin(async move {
                        let resp = run
                            .typed_or_error(
                                &handle,
                                &EXEC,
                                exec_args(vec![
                                    "bash".into(),
                                    "-c".into(),
                                    "echo HOST=$(cat /etc/hostname)".into(),
                                ]),
                            )
                            .await;
                        // Substituted hostname must be non-empty (the substitution
                        // actually ran). `hostname -I` worked above on the same
                        // container, so /etc/hostname is non-empty.
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.starts_with("HOST=")
                                    && stdout.trim_end().len() > "HOST=".len()
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });

        // BASH.fork_bg_fg: bash -c with background + foreground
        let a = agent_s.clone();
        reg.test("fork", "bash_fork_exec", format!("BASH.fork_bg_fg.{agent}"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = a.clone();
                    Box::pin(async move {
                        let resp = run
                            .typed_or_error(
                                &handle,
                                &EXEC,
                                exec_args(vec![
                                    "bash".into(),
                                    "-c".into(),
                                    // The bg subshell must actually run and emit
                                    // BG_DONE; the fg leg must run too. Wait for
                                    // bg before printing FG_DONE so output
                                    // ordering is deterministic.
                                    "(sleep 0.05 && echo BG_DONE) & \
                                     cat /etc/hostname > /dev/null; \
                                     wait; \
                                     echo FG_DONE"
                                        .into(),
                                ]),
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.contains("BG_DONE") && stdout.contains("FG_DONE")
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });
    }
}

// ═══════════════════════════════════════════════════════════════════
// FWE: fork+exec from non-PIE worker-exec hosts
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_fork_from_worker_exec_tests(reg: &mut Registry<'_>) {
    // Register the `fork-exec-pie` leaf subcommand. This stays as an
    // argv subcommand (not a handler) because the test specifically
    // verifies the legacy two-level fork+exec path: agent →
    // subcommand-dispatched child (fork-exec-pie) → grandchild of
    // the target binary type. Converting the child to a leaf agent
    // would change the test surface to "agent → leaf agent → grandchild",
    // which exercises a different code path that hit timeouts in the
    // litebox shim. Body lives in `mod leaf_subcmd` at the bottom of
    // this file.
    crate::register_leaf_subcommand!("fork-exec-pie", leaf_subcmd::subcmd_fork_exec_pie);
    // FWE matrix:
    //   - launcher = init   (agent A, PIE) ─► fork+execv each BinaryType
    //   - launcher = NP     (worker-exec host, non-PIE) ─► same
    //
    // Both arms use the `fork-exec-pie` subcommand (which is plain
    // fork+execv with no PIE-specific logic; the historical name is
    // kept for backwards compatibility). The binary executed is
    // resolved per `BinaryType` via `binary_path()`.
    for &bt in crate::BinaryType::ALL {
        for (launcher_label, launcher_agent, sub_timeout) in [
            ("from_init", AgentName::Dpg1, 20_u64),
            ("from_worker_exec", AgentName::Dpg1Dng, 30_u64),
        ] {
            let bt_label = bt.label();
            let test_id = format!("FWE.{bt_label}.{launcher_label}");
            let outcome_label = format!("{launcher_agent}");
            reg.test("fork", "fork_from_worker_exec", test_id.clone())
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(launcher_agent);
                    Box::new(move |run| {
                        let outcome_label = outcome_label.clone();
                        let self_exe = run.self_exe().to_string();
                        Box::pin(async move {
                            let target = crate::binary_path(bt, &self_exe);
                            // The launcher binary depends on which
                            // agent we're running on: agent A is PIE,
                            // agent NP is non-PIE.
                            let launcher_bin = match launcher_agent {
                                AgentName::Dpg1 => self_exe.clone(),
                                AgentName::Dpg1Dng => crate::nonpie_binary(),
                                _ => unreachable!(),
                            };
                            let resp = run
                                .typed_or_error(
                                    &handle,
                                    &EXEC,
                                    ExecArgs {
                                        args: vec![
                                            launcher_bin,
                                            "fork-exec-pie".into(),
                                            target,
                                            "echo-test".into(),
                                        ],
                                        timeout_secs: Some(sub_timeout),
                                        stdin: None,
                                        background: false,
                                        env: vec![],
                                    },
                                )
                                .await;
                            let pass = matches!(
                                &resp,
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.contains("FORK_EXEC_PIE_OK")
                            );
                            super::TestOutcome::new(&outcome_label, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// SK: SIGKILL of a parent agent whose subtree contains SpawnRemote
// (non-PIE) descendants. Reproduces the production hang we hit in
// `cargo test -- 'litebox::PN.B.eof'`: the harness coordinator
// SIGKILLs agent A in teardown, but A's vfork-child stub thread that
// did `wait_worker_host(NP_host_pid)` blocks A's process from being
// reaped because the non-PIE host worker (NP) is never sent a signal.
// The cascading effect is that the coordinator's `Child::wait()` for A
// can hang indefinitely, plus orphan host workers remain alive after
// container shutdown.
//
// Each test spawns its own fresh agent E — independent of the global
// matrix — builds the suspect subtree shape, then SIGKILLs E and
// asserts that the wait completes within a small wall-clock budget.
// On native this is sub-second; under litebox with the platform bug
// unfixed the wait will not return and these tests time out (FAIL).
//
// No expected-fail annotation is recorded: a real FAIL on litebox
// is the desired signal that the underlying platform bug needs
// fixing. The test harness's own teardown is wrapped in a 10-s
// timeout (commit f99cac06), so a FAIL here does not stall the
// docker container.
// ═══════════════════════════════════════════════════════════════════

/// Wall-clock budget for `Child::wait()` after SIGKILL. Native
/// completes in < 50 ms; we give 5 s to absorb tokio scheduling
/// jitter under heavy parallelism without masking real hangs.
const SK_WAIT_BUDGET_SECS: u64 = 5;

/// Per-test outer budget. Must exceed `SpawnRemote` setup cost
/// (the broker rewrites a 124 MB binary on first use, plus the
/// well-known `spawn_nonpie_subtree` 30-s timeout under litebox).
const SK_TEST_TIMEOUT_SECS: u64 = 90;

pub(crate) fn register_subtree_kill_tests(reg: &mut Registry<'_>) {
    // SK.subtree.direct — SIGKILL E whose immediate child is a
    // non-PIE worker spawned via SpawnRemote. Reproduces the exact
    // shape that hung the PN.B.eof teardown.
    reg.test("matrix", "subtree_kill", "SK.subtree.direct".to_string())
        .timeout(SK_TEST_TIMEOUT_SECS)
        .build(move |cx| {
            let e = cx.require(AgentName::Dpg3);
            let npx = cx.declare_ephemeral(AgentName::Dpg3, "NPx", SpawnKind::NonPie);
            Box::new(move |run| {
                let e = e.clone();
                let npx = npx.clone();
                Box::pin(async move {
                    let _ = crate::nonpie_binary();
                    let r = run.spawn_ephemeral(&npx).await;
                    if !super::ok_spawned_response(&r) {
                        return super::TestOutcome::new(
                            "E",
                            false,
                            format!("setup: spawn_ephemeral(NPx) failed: {r:?}"),
                        );
                    }
                    run_subtree_kill(run, &e).await
                })
            })
        });

    // SK.subtree.deep — SIGKILL E whose subtree is
    // E → EE → NPx (non-PIE leaf). Generalizes the depth axis: tests
    // that the wait4 stub at the *grandchild* level still propagates
    // back when the *root* is SIGKILLed.
    reg.test("matrix", "subtree_kill", "SK.subtree.deep".to_string())
        .timeout(SK_TEST_TIMEOUT_SECS)
        .build(move |cx| {
            let e = cx.require(AgentName::Dpg3);
            let _ee = cx.require(AgentName::Dpg3Dpg);
            // NPx is a non-PIE child of EE, two levels below E.
            let npx = cx.declare_ephemeral(AgentName::Dpg3Dpg, "NPx", SpawnKind::NonPie);
            Box::new(move |run| {
                let e = e.clone();
                let npx = npx.clone();
                Box::pin(async move {
                    let _ = crate::nonpie_binary();
                    // EE was already spawned under E by spawn_tree when
                    // the test declared AgentName::Dpg3Dpg. Ask EE to spawn
                    // its own non-PIE descendant.
                    let r = run.spawn_ephemeral(&npx).await;
                    if !super::ok_spawned_response(&r) {
                        return super::TestOutcome::new(
                            "E",
                            false,
                            format!("setup: spawn_ephemeral(NPx via EE) failed: {r:?}"),
                        );
                    }
                    run_subtree_kill(run, &e).await
                })
            })
        });

    // SK.subtree.exit_then_kill — cooperative Exit on the non-PIE
    // descendant first, then SIGKILL the root. Inverts the timing
    // relative to direct_nonpie: by the time the root is killed, the
    // wait_worker_host stub thread has already seen its host worker
    // exit. SIGKILL+wait should be especially fast. If this also
    // hangs, the bug is in stub-thread cleanup itself, not in
    // worker-exit-signal propagation.
    reg.test(
        "matrix",
        "subtree_kill",
        "SK.subtree.exit_then_kill".to_string(),
    )
    .timeout(SK_TEST_TIMEOUT_SECS)
    .build(move |cx| {
        let e = cx.require(AgentName::Dpg3);
        let npx = cx.declare_ephemeral(AgentName::Dpg3, "NPx", SpawnKind::NonPie);
        Box::new(move |run| {
            let e = e.clone();
            let npx = npx.clone();
            Box::pin(async move {
                let _ = crate::nonpie_binary();
                let r = run.spawn_ephemeral(&npx).await;
                if !super::ok_spawned_response(&r) {
                    return super::TestOutcome::new(
                        "E",
                        false,
                        format!("setup: spawn_ephemeral(NPx) failed: {r:?}"),
                    );
                }
                // Cooperative shutdown of the non-PIE descendant
                // before we kill the root. Forward(Exit) reaches NPx
                // via E. If the response stream desyncs we ignore —
                // the goal is just to make NPx exit.
                let _ = run.forward(&npx, InfraCommand::Exit).await;
                run_subtree_kill(run, &e).await
            })
        })
    });
}

/// SIGKILL the static `E` agent and time how long the wait takes.
/// Returns pass=true iff wait completes within `SK_WAIT_BUDGET_SECS`.
async fn run_subtree_kill(cx: &mut RunContext<'_>, e: &AgentHandle) -> super::TestOutcome {
    let budget = Duration::from_secs(SK_WAIT_BUDGET_SECS);
    let result = cx.kill_and_wait(e, budget).await;
    let (pass, detail) = match result {
        Ok(elapsed) => (
            true,
            format!(
                "kill_and_wait Ok elapsed={}ms budget={}s",
                elapsed.as_millis(),
                SK_WAIT_BUDGET_SECS,
            ),
        ),
        Err(elapsed) => (
            false,
            format!(
                "kill_and_wait TIMEOUT elapsed={}ms budget={}s",
                elapsed.as_millis(),
                SK_WAIT_BUDGET_SECS,
            ),
        ),
    };
    super::TestOutcome::new("E", pass, detail)
}
