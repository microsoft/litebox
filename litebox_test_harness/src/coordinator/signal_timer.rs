// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Focused signalfd / timerfd / pidfd audit tests for async-runtime
//! process supervision primitives.
//!
//! These tests intentionally use the kernel-facing syscalls directly so
//! native Linux is the gold standard and Litebox failures document the
//! current shim/broker contract.

use serde::{Deserialize, Serialize};

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::{BinaryType, register_handler, register_leaf_subcommand};

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;

const SIGFD_BASIC: HandlerToken<(), AuditOut> = HandlerToken::new("signal_timer.sigfd_basic");
const SIGFD_FORK_RESTORE: HandlerToken<ChildBinaryArgs, AuditOut> =
    HandlerToken::new("signal_timer.sigfd_fork_restore");
const TFD_BASIC: HandlerToken<(), AuditOut> = HandlerToken::new("signal_timer.tfd_basic");
const TFD_FORK_RESTORE: HandlerToken<ChildBinaryArgs, AuditOut> =
    HandlerToken::new("signal_timer.tfd_fork_restore");
const PIDFD_OPEN_WAITID: HandlerToken<(), AuditOut> =
    HandlerToken::new("signal_timer.pidfd_open_waitid");
const PIDFD_SEND_SIGNAL: HandlerToken<(), AuditOut> =
    HandlerToken::new("signal_timer.pidfd_send_signal");
const PIDFD_FORK_RESTORE: HandlerToken<ChildBinaryArgs, AuditOut> =
    HandlerToken::new("signal_timer.pidfd_fork_restore");

#[derive(Debug, Serialize, Deserialize)]
struct AuditOut {
    detail: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChildBinaryArgs {
    child_binary: String,
}

pub(crate) fn register_signal_timer_tests(reg: &mut Registry<'_>) {
    register_handler!(SIGFD_BASIC, handle_sigfd_basic);
    register_handler!(SIGFD_FORK_RESTORE, handle_sigfd_fork_restore);
    register_handler!(TFD_BASIC, handle_tfd_basic);
    register_handler!(TFD_FORK_RESTORE, handle_tfd_fork_restore);
    register_handler!(PIDFD_OPEN_WAITID, handle_pidfd_open_waitid);
    register_handler!(PIDFD_SEND_SIGNAL, handle_pidfd_send_signal);
    register_handler!(PIDFD_FORK_RESTORE, handle_pidfd_fork_restore);
    register_leaf_subcommand!("signal-timer-audit", leaf_subcmd::run);

    reg.single_agent_handler_test(
        "vscode",
        "signal_timer",
        "SIGFD.basic_block_and_read",
        AgentName::Dpg1,
        &SIGFD_BASIC,
        pass_detail,
    );
    register_child_binary_test(
        reg,
        "SIGFD.fork_restore_inherit",
        &SIGFD_FORK_RESTORE,
        "inherited signalfd survived fork+exec and read post-fork SIGUSR1",
    );
    reg.single_agent_handler_test(
        "vscode",
        "signal_timer",
        "TFD.basic_arm_and_read",
        AgentName::Dpg1,
        &TFD_BASIC,
        pass_detail,
    );
    register_child_binary_test(
        reg,
        "TFD.fork_restore_inherit",
        &TFD_FORK_RESTORE,
        "inherited timerfd survived fork+exec and reported one expiration",
    );
    reg.single_agent_handler_test(
        "vscode",
        "signal_timer",
        "PIDFD.open_and_waitid",
        AgentName::Dpg1,
        &PIDFD_OPEN_WAITID,
        pass_detail,
    );
    reg.single_agent_handler_test(
        "vscode",
        "signal_timer",
        "PIDFD.send_signal",
        AgentName::Dpg1,
        &PIDFD_SEND_SIGNAL,
        pass_detail,
    );
    // Native Linux only permits waitid(P_PIDFD) for a child of the
    // calling process; a fork+exec sibling inheriting its parent's
    // pidfd gets ECHILD. `PIDFD.open_and_waitid` covers waitid proper,
    // while this inheritance test uses poll(POLLIN), the pidfd state
    // query that is valid across an inherited sibling fd.
    register_child_binary_test(
        reg,
        "PIDFD.fork_restore_inherit",
        &PIDFD_FORK_RESTORE,
        "inherited pidfd survived fork+exec and reported target exit via poll",
    );
}

fn pass_detail(out: &AuditOut) -> Result<String, String> {
    Ok(out.detail.clone())
}

fn register_child_binary_test(
    reg: &mut Registry<'_>,
    id: &'static str,
    token: &'static HandlerToken<ChildBinaryArgs, AuditOut>,
    success: &'static str,
) {
    reg.test("vscode", "signal_timer", id)
        .timeout(30)
        .build(move |cx| {
            let agent = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let child_binary = crate::binary_path(BinaryType::NonPieGlibc, run.self_exe());
                    match run
                        .send_named_typed(&agent, token, ChildBinaryArgs { child_binary })
                        .await
                    {
                        Ok(out) => TestOutcome::new("Dpg1->nonpie-glibc", true, out.detail),
                        Err(e) => TestOutcome::new(
                            "Dpg1->nonpie-glibc",
                            false,
                            format!("{success}: handler error: {e}"),
                        ),
                    }
                })
            })
        });
}

async fn handle_sigfd_basic(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<AuditOut, HandlerError> {
    block_signal(libc::SIGUSR1).map_err(|e| HandlerError(format!("block SIGUSR1: {e}")))?;
    let mask = signal_set(libc::SIGUSR1);
    // SAFETY: mask is initialized; signalfd returns a fresh descriptor or -1.
    let fd = unsafe { libc::signalfd(-1, std::ptr::from_ref(&mask), libc::SFD_CLOEXEC) };
    let sfd = owned_fd(fd, "signalfd")?;
    // SAFETY: SIGUSR1 is blocked in this thread, so raise queues it for signalfd consumption.
    if unsafe { libc::raise(libc::SIGUSR1) } != 0 {
        return Err(HandlerError(format!(
            "raise(SIGUSR1): {}",
            std::io::Error::last_os_error()
        )));
    }
    let signo = read_signalfd_signo(sfd.as_raw_fd())?;
    if signo != libc::SIGUSR1.cast_unsigned() {
        return Err(HandlerError(format!(
            "signalfd signo mismatch: got {signo} expected {}",
            libc::SIGUSR1
        )));
    }
    Ok(AuditOut {
        detail: format!("read signalfd_siginfo signo={signo}"),
    })
}

async fn handle_sigfd_fork_restore(
    args: ChildBinaryArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<AuditOut, HandlerError> {
    block_signal(libc::SIGUSR1).map_err(|e| HandlerError(format!("block SIGUSR1: {e}")))?;
    let mask = signal_set(libc::SIGUSR1);
    // SAFETY: mask is initialized; signalfd returns a fresh descriptor or -1.
    let fd = unsafe { libc::signalfd(-1, std::ptr::from_ref(&mask), 0) };
    let sfd = owned_fd(fd, "signalfd")?;
    clear_cloexec(sfd.as_raw_fd())?;

    let mut child = Command::new(&args.child_binary)
        .args([
            "signal-timer-audit",
            "sigfd-read",
            &sfd.as_raw_fd().to_string(),
            &libc::SIGUSR1.to_string(),
            "5000",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;
    std::thread::sleep(Duration::from_millis(50));
    // SAFETY: child.id() names the just-spawned child process; SIGUSR1 is a valid signal.
    if unsafe { libc::kill(child.id().cast_signed(), libc::SIGUSR1) } != 0 {
        let err = std::io::Error::last_os_error();
        let _ = child.kill();
        let _ = child.wait();
        return Err(HandlerError(format!("kill child SIGUSR1: {err}")));
    }
    let output = wait_output_timeout(child, Duration::from_secs(6))?;
    expect_child_success(output, "sigfd-read")
}

async fn handle_tfd_basic(_args: (), _ctx: &mut HandlerCtx<'_>) -> Result<AuditOut, HandlerError> {
    let tfd = timerfd_create()?;
    arm_timerfd(tfd.as_raw_fd(), Duration::from_millis(50))?;
    let expirations = read_timerfd_count(tfd.as_raw_fd())?;
    if expirations != 1 {
        return Err(HandlerError(format!(
            "timerfd expiration mismatch: got {expirations} expected 1"
        )));
    }
    Ok(AuditOut {
        detail: "timerfd one-shot read expiration_count=1".to_string(),
    })
}

async fn handle_tfd_fork_restore(
    args: ChildBinaryArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<AuditOut, HandlerError> {
    let tfd = timerfd_create()?;
    clear_cloexec(tfd.as_raw_fd())?;
    arm_timerfd(tfd.as_raw_fd(), Duration::from_millis(50))?;
    let child = Command::new(&args.child_binary)
        .args([
            "signal-timer-audit",
            "tfd-read",
            &tfd.as_raw_fd().to_string(),
            "5000",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;
    let output = wait_output_timeout(child, Duration::from_secs(6))?;
    expect_child_success(output, "tfd-read")
}

async fn handle_pidfd_open_waitid(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<AuditOut, HandlerError> {
    let child = fork_exit_after(Duration::from_millis(20), 42)?;
    let pidfd = match pidfd_open(child) {
        Ok(pidfd) => pidfd,
        Err(e) => {
            kill_and_reap(child);
            return Err(e);
        }
    };
    let status = match waitid_pidfd_status(pidfd.as_raw_fd()) {
        Ok(status) => status,
        Err(e) => {
            kill_and_reap(child);
            return Err(e);
        }
    };
    if status != 42 {
        return Err(HandlerError(format!(
            "waitid(P_PIDFD) status mismatch: got {status} expected 42"
        )));
    }
    Ok(AuditOut {
        detail: format!("pidfd_open child={child}; waitid(P_PIDFD) status={status}"),
    })
}

async fn handle_pidfd_send_signal(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<AuditOut, HandlerError> {
    // SAFETY: fork creates a child; the child only pauses and then exits if unexpectedly resumed.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(HandlerError(format!(
            "fork: {}",
            std::io::Error::last_os_error()
        )));
    }
    if child == 0 {
        // SAFETY: child waits for a signal; _exit terminates without running Rust destructors.
        unsafe {
            libc::pause();
            libc::_exit(99);
        }
    }
    let pidfd = match pidfd_open(child) {
        Ok(pidfd) => pidfd,
        Err(e) => {
            kill_and_reap(child);
            return Err(e);
        }
    };
    // SAFETY: raw syscall is invoked with an owned pidfd, a valid signal, and null siginfo/flags.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGTERM,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        kill_and_reap(child);
        return Err(HandlerError(format!("pidfd_send_signal(SIGTERM): {err}")));
    }
    let status = wait_terminated_timeout(child, Duration::from_secs(2))?;
    Ok(AuditOut {
        detail: format!(
            "pidfd_send_signal terminated local fork child={child}; raw status={status:#x}"
        ),
    })
}

async fn handle_pidfd_fork_restore(
    args: ChildBinaryArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<AuditOut, HandlerError> {
    let target = fork_exit_after(Duration::from_millis(250), 0)?;
    let pidfd = match pidfd_open(target) {
        Ok(pidfd) => pidfd,
        Err(e) => {
            kill_and_reap(target);
            return Err(e);
        }
    };
    clear_cloexec(pidfd.as_raw_fd())?;
    let child = Command::new(&args.child_binary)
        .args([
            "signal-timer-audit",
            "pidfd-poll",
            &pidfd.as_raw_fd().to_string(),
            "5000",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;
    let output = wait_output_timeout(child, Duration::from_secs(6))?;
    let out = expect_child_success(output, "pidfd-poll")?;
    let mut status = 0;
    // SAFETY: target is the known child pid returned by fork.
    let waited = unsafe { libc::waitpid(target, std::ptr::from_mut(&mut status), 0) };
    if waited != target {
        return Err(HandlerError(format!(
            "waitpid target {target} returned {waited}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(AuditOut {
        detail: format!("{}; reaped target={target}", out.detail),
    })
}

fn signal_set(signo: i32) -> libc::sigset_t {
    // SAFETY: sigset_t is a plain old data bitset; zeroed is a valid starting value.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: mask is initialized and signo is supplied by callers as a valid signal constant.
    unsafe {
        libc::sigemptyset(std::ptr::from_mut(&mut mask));
        libc::sigaddset(std::ptr::from_mut(&mut mask), signo);
    }
    mask
}

fn block_signal(signo: i32) -> Result<(), std::io::Error> {
    let mask = signal_set(signo);
    // SAFETY: mask is initialized; SIG_BLOCK is a valid pthread_sigmask operation.
    let rc = unsafe {
        libc::pthread_sigmask(
            libc::SIG_BLOCK,
            std::ptr::from_ref(&mask),
            std::ptr::null_mut(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(rc))
    }
}

fn owned_fd(fd: RawFd, context: &str) -> Result<OwnedFd, HandlerError> {
    if fd < 0 {
        return Err(HandlerError(format!(
            "{context}: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fd was freshly returned by a successful fd-creating syscall.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn clear_cloexec(fd: RawFd) -> Result<(), HandlerError> {
    // SAFETY: fcntl operates on a live fd owned by the current process.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } == 0 {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "fcntl(F_SETFD, 0) fd={fd}: {}",
            std::io::Error::last_os_error()
        )))
    }
}

fn read_signalfd_signo(fd: RawFd) -> Result<u32, HandlerError> {
    let mut buf = [0_u8; 128];
    loop {
        // SAFETY: buf is valid writable storage for one signalfd_siginfo record.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n == 128 {
            return Ok(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(HandlerError(format!("signalfd read n={n}: {err}")));
    }
}

fn timerfd_create() -> Result<OwnedFd, HandlerError> {
    // SAFETY: timerfd_create is called with constant clock/flag values; errors are checked.
    let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC) };
    owned_fd(fd, "timerfd_create(CLOCK_MONOTONIC)")
}

fn arm_timerfd(fd: RawFd, duration: Duration) -> Result<(), HandlerError> {
    let spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: duration.as_secs().try_into().unwrap_or(i64::MAX),
            tv_nsec: duration.subsec_nanos().into(),
        },
    };
    // SAFETY: spec is initialized and fd is expected to refer to a live timerfd.
    if unsafe { libc::timerfd_settime(fd, 0, std::ptr::from_ref(&spec), std::ptr::null_mut()) } == 0
    {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "timerfd_settime fd={fd}: {}",
            std::io::Error::last_os_error()
        )))
    }
}

fn read_timerfd_count(fd: RawFd) -> Result<u64, HandlerError> {
    let mut value = 0_u64;
    loop {
        // SAFETY: value is valid writable storage for one timerfd expiration count.
        let n = unsafe { libc::read(fd, std::ptr::from_mut(&mut value).cast::<libc::c_void>(), 8) };
        if n == 8 {
            return Ok(value);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(HandlerError(format!("timerfd read n={n}: {err}")));
    }
}

fn pidfd_open(pid: libc::pid_t) -> Result<OwnedFd, HandlerError> {
    // SAFETY: pidfd_open syscall takes a pid and flags; errors are checked below.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        return Err(HandlerError(format!(
            "pidfd_open({pid}): {}",
            std::io::Error::last_os_error()
        )));
    }
    let fd = i32::try_from(raw).map_err(|e| HandlerError(format!("pidfd fd range: {e}")))?;
    owned_fd(fd, "pidfd_open")
}

fn fork_exit_after(delay: Duration, code: i32) -> Result<libc::pid_t, HandlerError> {
    // SAFETY: fork creates a child; child uses sleep plus _exit and does not resume Rust code.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(HandlerError(format!(
            "fork: {}",
            std::io::Error::last_os_error()
        )));
    }
    if child == 0 {
        std::thread::sleep(delay);
        // SAFETY: child process terminates without running Rust destructors.
        unsafe { libc::_exit(code) };
    }
    Ok(child)
}

fn kill_and_reap(pid: libc::pid_t) {
    // SAFETY: best-effort cleanup for a known pid returned by fork.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, std::ptr::from_mut(&mut status), 0);
    }
}

fn waitid_pidfd_status(pidfd: RawFd) -> Result<i32, HandlerError> {
    const P_PIDFD: libc::idtype_t = 3;
    // SAFETY: siginfo_t is a POD out-buffer for waitid.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: pidfd is a live pidfd; info points to writable siginfo_t storage.
    let rc = unsafe {
        libc::waitid(
            P_PIDFD,
            pidfd.cast_unsigned(),
            std::ptr::from_mut(&mut info),
            libc::WEXITED,
        )
    };
    if rc != 0 {
        return Err(HandlerError(format!(
            "waitid(P_PIDFD, fd={pidfd}): {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: waitid initialized info for a CLD_EXITED child.
    Ok(unsafe { info.si_status() })
}

fn wait_terminated_timeout(pid: libc::pid_t, timeout: Duration) -> Result<i32, HandlerError> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut status = 0;
        // SAFETY: waitpid on a known child pid returned by fork.
        let waited = unsafe { libc::waitpid(pid, std::ptr::from_mut(&mut status), libc::WNOHANG) };
        if waited == pid {
            return Ok(status);
        }
        if waited < 0 {
            return Err(HandlerError(format!(
                "waitpid({pid}, WNOHANG): {}",
                std::io::Error::last_os_error()
            )));
        }
        if Instant::now() >= deadline {
            kill_and_reap(pid);
            return Err(HandlerError(format!(
                "waitpid({pid}) timed out after {timeout:?}"
            )));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_output_timeout(mut child: Child, timeout: Duration) -> Result<Output, HandlerError> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|e| HandlerError(format!("wait_with_output: {e}")));
            }
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let output = child
                    .wait_with_output()
                    .map_err(|e| HandlerError(format!("wait_with_output after kill: {e}")))?;
                return Err(HandlerError(format!(
                    "child timeout after {:?}; stdout={:?} stderr={:?}",
                    timeout,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => return Err(HandlerError(format!("try_wait: {e}"))),
        }
    }
}

fn expect_child_success(output: Output, context: &str) -> Result<AuditOut, HandlerError> {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.status.success() {
        Ok(AuditOut {
            detail: format!("{context}: {stdout}"),
        })
    } else {
        Err(HandlerError(format!(
            "{context}: exit={} stdout={stdout:?} stderr={stderr:?}",
            output.status.code().unwrap_or(-1)
        )))
    }
}

mod leaf_subcmd {
    use super::{poll_fd, read_signalfd_signo, read_timerfd_count};
    use std::os::fd::RawFd;

    pub(super) fn run(args: &[String]) -> i32 {
        match args.get(2).map(String::as_str) {
            Some("sigfd-read") => sigfd_read(args),
            Some("tfd-read") => tfd_read(args),
            Some("pidfd-poll") => pidfd_poll(args),
            Some(other) => {
                eprintln!("signal-timer-audit: unknown subcommand {other}");
                2
            }
            None => {
                eprintln!("signal-timer-audit: missing subcommand");
                2
            }
        }
    }

    fn sigfd_read(args: &[String]) -> i32 {
        let Some(fd) = args.get(3).and_then(|s| s.parse::<RawFd>().ok()) else {
            eprintln!("sigfd-read: bad fd");
            return 2;
        };
        let Some(expected) = args.get(4).and_then(|s| s.parse::<u32>().ok()) else {
            eprintln!("sigfd-read: bad expected signo");
            return 2;
        };
        let Some(timeout_ms) = args.get(5).and_then(|s| s.parse::<i32>().ok()) else {
            eprintln!("sigfd-read: bad timeout");
            return 2;
        };
        if poll_fd(fd, libc::POLLIN, timeout_ms, "sigfd-read poll") != 0 {
            return 1;
        }
        match read_signalfd_signo(fd) {
            Ok(signo) if signo == expected => {
                println!("signo={signo}");
                0
            }
            Ok(signo) => {
                eprintln!("sigfd-read: signo mismatch got {signo} expected {expected}");
                1
            }
            Err(e) => {
                eprintln!("sigfd-read: {}", e.0);
                1
            }
        }
    }

    fn tfd_read(args: &[String]) -> i32 {
        let Some(fd) = args.get(3).and_then(|s| s.parse::<RawFd>().ok()) else {
            eprintln!("tfd-read: bad fd");
            return 2;
        };
        let Some(timeout_ms) = args.get(4).and_then(|s| s.parse::<i32>().ok()) else {
            eprintln!("tfd-read: bad timeout");
            return 2;
        };
        if poll_fd(fd, libc::POLLIN, timeout_ms, "tfd-read poll") != 0 {
            return 1;
        }
        match read_timerfd_count(fd) {
            Ok(1) => {
                println!("expirations=1");
                0
            }
            Ok(value) => {
                eprintln!("tfd-read: expiration mismatch got {value} expected 1");
                1
            }
            Err(e) => {
                eprintln!("tfd-read: {}", e.0);
                1
            }
        }
    }

    fn pidfd_poll(args: &[String]) -> i32 {
        let Some(fd) = args.get(3).and_then(|s| s.parse::<RawFd>().ok()) else {
            eprintln!("pidfd-poll: bad fd");
            return 2;
        };
        let Some(timeout_ms) = args.get(4).and_then(|s| s.parse::<i32>().ok()) else {
            eprintln!("pidfd-poll: bad timeout");
            return 2;
        };
        if poll_fd(fd, libc::POLLIN, timeout_ms, "pidfd-poll") == 0 {
            println!("pidfd_poll_ready=1");
            0
        } else {
            1
        }
    }
}

fn poll_fd(fd: RawFd, events: i16, timeout_ms: i32, context: &str) -> i32 {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    loop {
        // SAFETY: pfd points to one initialized pollfd and nfds matches.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        if rc > 0 && pfd.revents & events != 0 {
            return 0;
        }
        if rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        eprintln!(
            "{context}: rc={} revents={} err={}",
            rc,
            pfd.revents,
            std::io::Error::last_os_error()
        );
        return 1;
    }
}
