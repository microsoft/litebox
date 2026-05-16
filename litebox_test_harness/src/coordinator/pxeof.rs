// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Cross-worker pipe EOF coordinator tests.
//!
//! These tests probe whether the litebox `Pipe` reader sees EOF when
//! the writer side closes. Within a single worker the existing `PB.*`,
//! `BPipe.*`, and `PN.B.eof` families cover that. **This family
//! exercises specifically the cross-worker boundary**: the parent
//! holds the pipe read end in worker A; the child is migrated to
//! worker B via `exec_on_remote_host`; the child writes (or doesn't)
//! and exits; the parent's read should return 0 (EOF).
//!
//! ## Bug under test
//!
//! When the writer-worker host exits, the litebox `Pipe` object's
//! `is_shutdown` flag is set within the writer's own shim (its
//! `Arc<WriteEnd>` drops), but that signal does not propagate to the
//! reader-worker's view of the pipe. So the reader's `Pollee::wait`
//! blocks indefinitely waiting for `Events::IN | Events::HUP` that
//! never fire. See `plan.pidalloc-done.md` for the gdb-confirmed root
//! cause.
//!
//! ## Scenarios
//!
//! See the README-style table in this module; each scenario tests a
//! different axis: pipe direction, termination mode, reader wait
//! mode, inheritance shape. The `pie-glibc` control variant of each
//! scenario stays in dpg1's worker (no cross-bt migration) and is
//! expected to PASS today; the cross-bt variants (nonpie-glibc,
//! static-pie-musl, non-pie-static-musl) are expected to FAIL until
//! the pipe-shutdown propagation bug is fixed. The failing set IS
//! the bug signature.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;

// ─── Scenario discriminator ─────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    StdoutEmpty,
    StdoutOneline,
    StdoutLargeBuf,
    StderrSimple,
    StdinClose,
    SignalKill,
    ExecFailure,
    PollHup,
    EpollRdhup,
    DepthTwo,
    SharedWriter,
    /// Spawn child binary; child forks a grandchild that immediately
    /// exits; child waits for grandchild via waitpid; child exits.
    /// Parent agent captures the child's stdout (which is empty) and
    /// must observe EOF — exercises the same pattern as
    /// `PIDF.exit_self` minus the pidfd_open / poll(POLLIN) dance,
    /// so a failure here isolates the bug to broker-pipe EOF
    /// propagation in the presence of an inner fork (rather than
    /// pidfd-specific code paths).
    InnerForkExit,
}

impl Scenario {
    fn label(self) -> &'static str {
        match self {
            Self::StdoutEmpty => "stdout_empty",
            Self::StdoutOneline => "stdout_oneline",
            Self::StdoutLargeBuf => "stdout_largebuf",
            Self::StderrSimple => "stderr_simple",
            Self::StdinClose => "stdin_close",
            Self::SignalKill => "signal_kill",
            Self::ExecFailure => "exec_failure",
            Self::PollHup => "poll_hup",
            Self::EpollRdhup => "epoll_rdhup",
            Self::DepthTwo => "depth_two",
            Self::SharedWriter => "shared_writer",
            Self::InnerForkExit => "inner_fork_exit",
        }
    }
}

const ALL_SCENARIOS: &[Scenario] = &[
    Scenario::StdoutEmpty,
    Scenario::StdoutOneline,
    Scenario::StdoutLargeBuf,
    Scenario::StderrSimple,
    Scenario::StdinClose,
    Scenario::SignalKill,
    Scenario::ExecFailure,
    Scenario::PollHup,
    Scenario::EpollRdhup,
    Scenario::DepthTwo,
    Scenario::SharedWriter,
    Scenario::InnerForkExit,
];

// ─── Handler protocol ──────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct PxeofArgs {
    scenario: Scenario,
    /// Path to the leaf binary (`Command::new(child_bin)`). bt-specific.
    child_bin: String,
    /// For `DepthTwo`, the path to the grandchild binary (also a
    /// litebox_test_harness build, possibly a different bt).
    grandchild_bin: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PxeofOut {
    /// `true` = scenario invariants observed; `false` = bug observed.
    /// In both cases the `detail` field carries diagnostic info.
    passed: bool,
    detail: String,
}

const PXEOF: HandlerToken<PxeofArgs, PxeofOut> = HandlerToken::new("pxeof.run");

// ─── Per-scenario timeout (used for blocking reads) ────────────────

const READ_TIMEOUT: Duration = Duration::from_secs(10);
const LARGE_READ_TIMEOUT: Duration = Duration::from_secs(30);

// ─── Handler dispatch ──────────────────────────────────────────────

async fn handle_pxeof(
    args: PxeofArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PxeofOut, HandlerError> {
    let r = match args.scenario {
        Scenario::StdoutEmpty => run_stdout_n(&args.child_bin, 0),
        Scenario::StdoutOneline => run_stdout_n(&args.child_bin, ONELINE_BYTES),
        Scenario::StdoutLargeBuf => run_stdout_large(&args.child_bin),
        Scenario::StderrSimple => run_stderr_oneline(&args.child_bin),
        Scenario::StdinClose => run_stdin_close(&args.child_bin),
        Scenario::SignalKill => run_signal_kill(&args.child_bin),
        Scenario::ExecFailure => run_exec_failure(&args.child_bin),
        Scenario::PollHup => run_poll_hup(&args.child_bin),
        Scenario::EpollRdhup => run_epoll_rdhup(&args.child_bin),
        Scenario::DepthTwo => run_depth_two(&args.child_bin, args.grandchild_bin.as_deref()),
        Scenario::SharedWriter => run_shared_writer(&args.child_bin),
        Scenario::InnerForkExit => run_inner_fork_exit(&args.child_bin),
    };
    Ok(match r {
        Ok(detail) => PxeofOut {
            passed: true,
            detail,
        },
        Err(detail) => PxeofOut {
            passed: false,
            detail,
        },
    })
}

const ONELINE_BYTES: usize = 64;
const LARGE_BYTES: usize = 1024 * 1024; // 1 MiB

// ─── Bounded-read helper ───────────────────────────────────────────

/// Read from `child`'s stdout (or stderr) until EOF or the timeout
/// expires. Returns the bytes collected or a timeout error.
///
/// Uses non-blocking + poll, so we have a hard deadline. Without
/// this, a hung pipe would hang the test for the full per-test
/// 30s timeout, making it hard to attribute failures.
fn read_to_eof_or_timeout(
    child_stdio: &mut dyn std::io::Read,
    fd: i32,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    // Set fd nonblocking so reads don't hang past the deadline.
    set_nonblock(fd, true)?;
    loop {
        match child_stdio.read(&mut tmp) {
            Ok(0) => {
                set_nonblock(fd, false).ok();
                return Ok(buf);
            }
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    set_nonblock(fd, false).ok();
                    return Err(format!(
                        "timeout after {} bytes (no EOF within deadline)",
                        buf.len()
                    ));
                }
                wait_pollin_or_hup(fd, remaining.min(Duration::from_millis(500)))?;
            }
            Err(e) => {
                set_nonblock(fd, false).ok();
                return Err(format!("read error after {} bytes: {e}", buf.len()));
            }
        }
    }
}

fn set_nonblock(fd: i32, on: bool) -> Result<(), String> {
    // SAFETY: fcntl(F_GETFL) is async-signal-safe; the fd is owned by
    // the caller (it's the child's stdout/stderr ChildStdout / ChildStderr).
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(format!(
            "fcntl(F_GETFL, {fd}): {}",
            std::io::Error::last_os_error()
        ));
    }
    let new = if on {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFL, new) } < 0 {
        return Err(format!(
            "fcntl(F_SETFL, {fd}): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// `poll(fd, POLLIN | POLLHUP, timeout)` — block up to `timeout`
/// waiting for the fd to become readable or hang up.
fn wait_pollin_or_hup(fd: i32, timeout: Duration) -> Result<i16, String> {
    let mut pfd = libc::pollfd {
        fd,
        events: (libc::POLLIN | libc::POLLHUP) as i16,
        revents: 0,
    };
    let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if rc < 0 {
        return Err(format!("poll({fd}): {}", std::io::Error::last_os_error()));
    }
    Ok(pfd.revents)
}

// ─── Scenario bodies ───────────────────────────────────────────────

fn run_stdout_n(child_bin: &str, bytes: usize) -> Result<String, String> {
    let mut cmd = Command::new(child_bin);
    cmd.args([
        "pxeof-leaf",
        "ROLE=write-and-exit",
        "STREAM=stdout",
        &format!("BYTES={bytes}"),
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let mut out = child.stdout.take().ok_or("no stdout")?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&out);
    let deadline = Instant::now() + READ_TIMEOUT;
    let received = read_to_eof_or_timeout(&mut out, fd, deadline)?;
    drop(out);
    let status = child.wait().map_err(|e| format!("wait: {e}"))?;
    if !status.success() {
        return Err(format!("child exited non-zero: {status:?}"));
    }
    if received.len() != bytes {
        return Err(format!("expected {bytes} bytes, got {}", received.len()));
    }
    Ok(format!("read {} bytes + EOF", received.len()))
}

fn run_stdout_large(child_bin: &str) -> Result<String, String> {
    let mut cmd = Command::new(child_bin);
    cmd.args([
        "pxeof-leaf",
        "ROLE=write-and-exit",
        "STREAM=stdout",
        &format!("BYTES={LARGE_BYTES}"),
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let mut out = child.stdout.take().ok_or("no stdout")?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&out);
    let deadline = Instant::now() + LARGE_READ_TIMEOUT;
    let received = read_to_eof_or_timeout(&mut out, fd, deadline)?;
    drop(out);
    let status = child.wait().map_err(|e| format!("wait: {e}"))?;
    if !status.success() {
        return Err(format!("child exited non-zero: {status:?}"));
    }
    if received.len() != LARGE_BYTES {
        return Err(format!(
            "expected {LARGE_BYTES} bytes, got {}",
            received.len()
        ));
    }
    Ok(format!("read {LARGE_BYTES} bytes + EOF"))
}

fn run_stderr_oneline(child_bin: &str) -> Result<String, String> {
    let mut cmd = Command::new(child_bin);
    cmd.args([
        "pxeof-leaf",
        "ROLE=write-and-exit",
        "STREAM=stderr",
        &format!("BYTES={ONELINE_BYTES}"),
        "MARKER=1",
    ])
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let mut err = child.stderr.take().ok_or("no stderr")?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&err);
    let deadline = Instant::now() + READ_TIMEOUT;
    let received = read_to_eof_or_timeout(&mut err, fd, deadline)?;
    drop(err);
    let status = child.wait().map_err(|e| format!("wait: {e}"))?;
    if !status.success() {
        return Err(format!("child exited non-zero: {status:?}"));
    }
    // The test harness prints banner lines to stderr at startup; extract
    // the leaf's payload via marker sentinels.
    let text = String::from_utf8_lossy(&received);
    let start = text
        .find(PXEOF_LEAF_MARKER_START)
        .ok_or_else(|| format!("no START marker in stderr: {text:?}"))?
        + PXEOF_LEAF_MARKER_START.len();
    let end = text[start..]
        .find(PXEOF_LEAF_MARKER_END)
        .ok_or_else(|| format!("no END marker in stderr: {text:?}"))?;
    let payload = &text[start..start + end];
    if payload.len() != ONELINE_BYTES {
        return Err(format!(
            "expected {ONELINE_BYTES} bytes of payload between markers, got {}",
            payload.len()
        ));
    }
    Ok(format!(
        "read {} payload bytes + EOF on stderr",
        payload.len()
    ))
}

const PXEOF_LEAF_MARKER_START: &str = "PXEOF_LEAF_OUT_START\n";
const PXEOF_LEAF_MARKER_END: &str = "PXEOF_LEAF_OUT_END\n";

fn run_stdin_close(child_bin: &str) -> Result<String, String> {
    let mut cmd = Command::new(child_bin);
    cmd.args(["pxeof-leaf", "ROLE=read-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    // Close the stdin pipe immediately (write end drop = EOF for child reader).
    drop(child.stdin.take());
    // Child should print "BYTES=0\n" and exit 0.
    let mut out = child.stdout.take().ok_or("no stdout")?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&out);
    let deadline = Instant::now() + READ_TIMEOUT;
    let received = read_to_eof_or_timeout(&mut out, fd, deadline)?;
    drop(out);
    let status = child.wait().map_err(|e| format!("wait: {e}"))?;
    if !status.success() {
        return Err(format!("child exited non-zero: {status:?}"));
    }
    let text = String::from_utf8_lossy(&received);
    if !text.contains("BYTES=0") {
        return Err(format!("expected 'BYTES=0' in child stdout, got: {text:?}"));
    }
    Ok(format!("child observed stdin EOF: {}", text.trim()))
}

fn run_signal_kill(child_bin: &str) -> Result<String, String> {
    let mut cmd = Command::new(child_bin);
    cmd.args(["pxeof-leaf", "ROLE=sleep-then-exit", "MILLIS=30000"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let child_pid = child.id();
    // Give the child a moment to settle into its sleep.
    std::thread::sleep(Duration::from_millis(500));
    // SAFETY: kill(2) takes a pid_t and a signal int. child_pid is a
    // valid Linux pid for our spawned child.
    let rc = unsafe { libc::kill(child_pid as i32, libc::SIGKILL) };
    if rc != 0 {
        return Err(format!(
            "kill(SIGKILL): {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut out = child.stdout.take().ok_or("no stdout")?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&out);
    let deadline = Instant::now() + READ_TIMEOUT;
    let received = read_to_eof_or_timeout(&mut out, fd, deadline)?;
    drop(out);
    let status = child.wait().map_err(|e| format!("wait: {e}"))?;
    // Child was SIGKILLed; status should be signal-based.
    if status.success() {
        return Err(format!("expected signal-terminated child, got {status:?}"));
    }
    Ok(format!(
        "received {} bytes + EOF after SIGKILL; child status={status:?}",
        received.len()
    ))
}

fn run_exec_failure(child_bin: &str) -> Result<String, String> {
    let mut cmd = Command::new(child_bin);
    cmd.args(["pxeof-leaf", "ROLE=exec-failure"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let mut out = child.stdout.take().ok_or("no stdout")?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&out);
    let deadline = Instant::now() + READ_TIMEOUT;
    let received = read_to_eof_or_timeout(&mut out, fd, deadline)?;
    drop(out);
    let status = child.wait().map_err(|e| format!("wait: {e}"))?;
    // Exec failed so the child should exit non-zero.
    if status.success() {
        return Err("expected child to exit non-zero after exec failure".into());
    }
    Ok(format!(
        "child exec failed, observed {} bytes + EOF; status={status:?}",
        received.len()
    ))
}

fn run_poll_hup(child_bin: &str) -> Result<String, String> {
    let mut cmd = Command::new(child_bin);
    cmd.args([
        "pxeof-leaf",
        "ROLE=write-and-exit",
        "STREAM=stdout",
        "BYTES=0",
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let out = child.stdout.take().ok_or("no stdout")?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&out);
    let revents = wait_pollin_or_hup(fd, READ_TIMEOUT)?;
    drop(out);
    let _ = child.wait();
    if revents & (libc::POLLHUP as i16) == 0 {
        return Err(format!(
            "expected POLLHUP, got revents={:#x}",
            revents as u16
        ));
    }
    Ok(format!("POLLHUP fired (revents={:#x})", revents as u16))
}

fn run_epoll_rdhup(child_bin: &str) -> Result<String, String> {
    let mut cmd = Command::new(child_bin);
    cmd.args([
        "pxeof-leaf",
        "ROLE=write-and-exit",
        "STREAM=stdout",
        "BYTES=0",
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let out = child.stdout.take().ok_or("no stdout")?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&out);
    // SAFETY: epoll_create1 + epoll_ctl + epoll_wait are stateless syscalls.
    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        return Err(format!(
            "epoll_create1: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut ev = libc::epoll_event {
        events: (libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLHUP) as u32,
        u64: 0,
    };
    let rc = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(epfd) };
        return Err(format!("epoll_ctl: {e}"));
    }
    let timeout_ms = i32::try_from(READ_TIMEOUT.as_millis()).unwrap_or(i32::MAX);
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), events.len() as i32, timeout_ms) };
    unsafe { libc::close(epfd) };
    drop(out);
    let _ = child.wait();
    if n < 0 {
        return Err(format!("epoll_wait: {}", std::io::Error::last_os_error()));
    }
    if n == 0 {
        return Err("epoll_wait timed out — no HUP/RDHUP".into());
    }
    let got = events[0].events;
    // For a fully-closed pipe (writer fully gone), Linux signals
    // POLLHUP. POLLRDHUP is reserved for half-shutdown (e.g.
    // SHUT_WR on a socket). We accept either as evidence that the
    // EOF was observed by epoll.
    let hup_mask = (libc::EPOLLHUP | libc::EPOLLRDHUP) as u32;
    if got & hup_mask == 0 {
        return Err(format!(
            "expected EPOLLHUP or EPOLLRDHUP, got events={got:#x}"
        ));
    }
    Ok(format!("EPOLL HUP/RDHUP fired (events={got:#x})"))
}

fn run_depth_two(child_bin: &str, grandchild_bin: Option<&str>) -> Result<String, String> {
    let grand = grandchild_bin.ok_or("depth_two requires grandchild_bin")?;
    let mut cmd = Command::new(child_bin);
    cmd.args([
        "pxeof-leaf",
        "ROLE=forward",
        &format!("BINARY={grand}"),
        &format!("BYTES={ONELINE_BYTES}"),
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let mut out = child.stdout.take().ok_or("no stdout")?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&out);
    let deadline = Instant::now() + READ_TIMEOUT;
    let received = read_to_eof_or_timeout(&mut out, fd, deadline)?;
    drop(out);
    let status = child.wait().map_err(|e| format!("wait: {e}"))?;
    if !status.success() {
        return Err(format!("middle child exit non-zero: {status:?}"));
    }
    if received.len() != ONELINE_BYTES {
        return Err(format!(
            "expected {ONELINE_BYTES} bytes through 2 hops, got {}",
            received.len()
        ));
    }
    Ok(format!("2-hop EOF OK: {} bytes", received.len()))
}

fn run_shared_writer(child_bin: &str) -> Result<String, String> {
    let mut cmd = Command::new(child_bin);
    cmd.args(["pxeof-leaf", "ROLE=shared-writer-fork"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let mut out = child.stdout.take().ok_or("no stdout")?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&out);
    let deadline = Instant::now() + READ_TIMEOUT;
    let received = read_to_eof_or_timeout(&mut out, fd, deadline)?;
    drop(out);
    let status = child.wait().map_err(|e| format!("wait: {e}"))?;
    if !status.success() {
        return Err(format!("child exit non-zero: {status:?}"));
    }
    let text = String::from_utf8_lossy(&received);
    if !text.contains("SHARED_WRITER_DONE") {
        return Err(format!("expected SHARED_WRITER_DONE marker; got: {text:?}"));
    }
    Ok(format!("shared-writer EOF OK: {}", text.trim()))
}

fn run_inner_fork_exit(child_bin: &str) -> Result<String, String> {
    // Child binary does: fork → grandchild sleeps briefly + exits;
    // child waits via waitpid; child exits. No pidfd, no inner poll.
    // Parent captures stdout (empty — child writes nothing) and must
    // observe EOF. Isolates the broker-pipe EOF-propagation behavior
    // in the presence of an inner fork from the pidfd code paths
    // exercised by `PIDF.exit_self`.
    let mut cmd = Command::new(child_bin);
    cmd.args(["pxeof-leaf", "ROLE=inner-fork-exit"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let mut out = child.stdout.take().ok_or("no stdout")?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&out);
    let deadline = Instant::now() + READ_TIMEOUT;
    let received = read_to_eof_or_timeout(&mut out, fd, deadline)?;
    drop(out);
    let status = child.wait().map_err(|e| format!("wait: {e}"))?;
    if !status.success() {
        return Err(format!("child exit non-zero: {status:?}"));
    }
    if !received.is_empty() {
        return Err(format!(
            "expected empty stdout, got {} bytes: {:?}",
            received.len(),
            String::from_utf8_lossy(&received)
        ));
    }
    Ok("inner-fork-exit: EOF observed, child exited cleanly".to_string())
}

// ─── Test registration ─────────────────────────────────────────────

/// Binary-type variants per scenario. `pie-glibc` is the same-bt
/// control (no migration); the others trigger `exec_on_remote_host`.
const BT_VARIANTS: &[(crate::BinaryType, &str)] = &[
    (crate::BinaryType::PieGlibc, "pie-glibc"),
    (crate::BinaryType::NonPieGlibc, "nonpie-glibc"),
    (crate::BinaryType::StaticPieMusl, "static-pie-musl"),
    (crate::BinaryType::NonPieStaticMusl, "non-pie-static-musl"),
];

pub(crate) fn register_pxeof_tests(reg: &mut Registry<'_>) {
    register_handler!(PXEOF, handle_pxeof);
    crate::register_leaf_subcommand!("pxeof-leaf", |args: &[String]| -> i32 {
        leaf_subcmd::run(args)
    });

    for &scenario in ALL_SCENARIOS {
        for &(bt, bt_label) in BT_VARIANTS {
            let scen = scenario;
            let id = format!("PXEOF.{}.{bt_label}", scen.label());
            // depth_two requires a grandchild binary in addition to the child.
            // For simplicity, the grandchild uses the SAME bt as the child.
            let needs_grandchild = matches!(scen, Scenario::DepthTwo);
            let per_test_timeout = if matches!(scen, Scenario::StdoutLargeBuf) {
                60
            } else {
                30
            };
            reg.test("matrix", "pxeof", id)
                .timeout(per_test_timeout)
                .build(move |cx| {
                    let agent = cx.require(AgentName::Dpg1);
                    Box::new(move |run| {
                        Box::pin(async move {
                            let self_exe = run.self_exe().to_string();
                            let child_bin = crate::binary_path(bt, &self_exe);
                            let grandchild_bin = if needs_grandchild {
                                Some(crate::binary_path(bt, &self_exe))
                            } else {
                                None
                            };
                            let args = PxeofArgs {
                                scenario: scen,
                                child_bin,
                                grandchild_bin,
                            };
                            match run.send_named_typed(&agent, &PXEOF, args).await {
                                Ok(out) => TestOutcome::new("Dpg1", out.passed, out.detail),
                                Err(e) => {
                                    TestOutcome::new("Dpg1", false, format!("handler error: {e}"))
                                }
                            }
                        })
                    })
                });
        }
    }
}

// ─── Leaf subcommand: `pxeof-leaf ROLE=R KEY=V ...` ────────────────

mod leaf_subcmd {
    use std::io::Read as _;
    use std::time::Duration;

    pub(super) fn run(args: &[String]) -> i32 {
        let role = match kv(args, "ROLE=") {
            Some(r) => r,
            None => {
                eprintln!("pxeof-leaf: missing ROLE=");
                return 2;
            }
        };
        match role.as_str() {
            "write-and-exit" => role_write_and_exit(args),
            "sleep-then-exit" => role_sleep_then_exit(args),
            "exec-failure" => role_exec_failure(),
            "read-stdin" => role_read_stdin(),
            "forward" => role_forward(args),
            "shared-writer-fork" => role_shared_writer_fork(),
            "inner-fork-exit" => role_inner_fork_exit(),
            other => {
                eprintln!("pxeof-leaf: unknown ROLE={other}");
                2
            }
        }
    }

    fn kv(args: &[String], prefix: &str) -> Option<String> {
        args.iter()
            .find_map(|a| a.strip_prefix(prefix).map(|s| s.to_string()))
    }

    fn role_write_and_exit(args: &[String]) -> i32 {
        let bytes: usize = kv(args, "BYTES=").and_then(|s| s.parse().ok()).unwrap_or(0);
        let stream = kv(args, "STREAM=").unwrap_or_else(|| "stdout".into());
        let marker = kv(args, "MARKER=").is_some_and(|v| v == "1");
        let payload = vec![b'A'; bytes];
        let mut sink: Box<dyn Write> = match stream.as_str() {
            "stdout" => Box::new(std::io::stdout().lock()),
            "stderr" => Box::new(std::io::stderr().lock()),
            other => {
                eprintln!("pxeof-leaf: unknown STREAM={other}");
                return 2;
            }
        };
        if marker {
            let _ = sink.write_all(b"PXEOF_LEAF_OUT_START\n");
        }
        if let Err(e) = sink.write_all(&payload) {
            eprintln!("pxeof-leaf: write failed: {e}");
            return 1;
        }
        if marker {
            let _ = sink.write_all(b"PXEOF_LEAF_OUT_END\n");
        }
        let _ = sink.flush();
        drop(sink);
        0
    }

    fn role_sleep_then_exit(args: &[String]) -> i32 {
        let millis: u64 = kv(args, "MILLIS=")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000);
        std::thread::sleep(Duration::from_millis(millis));
        0
    }

    fn role_exec_failure() -> i32 {
        // Replace this process with a binary that doesn't exist. execve
        // returns ENOENT; we exit with non-zero so the test can verify.
        use std::os::unix::process::CommandExt as _;
        let err = std::process::Command::new("/no/such/binary-path-pxeof").exec();
        eprintln!("pxeof-leaf: exec failed as expected: {err}");
        // After exec failure the current process continues; exit non-zero.
        13
    }

    fn role_read_stdin() -> i32 {
        let mut stdin = std::io::stdin().lock();
        let mut buf = Vec::new();
        match stdin.read_to_end(&mut buf) {
            Ok(_) => {
                println!("BYTES={}", buf.len());
                0
            }
            Err(e) => {
                eprintln!("pxeof-leaf: read_to_end failed: {e}");
                1
            }
        }
    }

    fn role_forward(args: &[String]) -> i32 {
        let grand_bin = match kv(args, "BINARY=") {
            Some(b) => b,
            None => {
                eprintln!("pxeof-leaf forward: missing BINARY=");
                return 2;
            }
        };
        let bytes: usize = kv(args, "BYTES=").and_then(|s| s.parse().ok()).unwrap_or(0);
        // Spawn a grandchild; the grandchild writes BYTES to its stdout
        // and exits. Forward its stdout to our stdout, then exit.
        let mut cmd = std::process::Command::new(&grand_bin);
        cmd.args([
            "pxeof-leaf",
            "ROLE=write-and-exit",
            "STREAM=stdout",
            &format!("BYTES={bytes}"),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("pxeof-leaf forward: spawn {grand_bin}: {e}");
                return 1;
            }
        };
        let mut out = match child.stdout.take() {
            Some(s) => s,
            None => {
                eprintln!("pxeof-leaf forward: no grand stdout");
                let _ = child.wait();
                return 1;
            }
        };
        let mut buf = Vec::new();
        if let Err(e) = out.read_to_end(&mut buf) {
            eprintln!("pxeof-leaf forward: read grand stdout: {e}");
            let _ = child.wait();
            return 1;
        }
        drop(out);
        let _ = child.wait();
        if let Err(e) = std::io::stdout().lock().write_all(&buf) {
            eprintln!("pxeof-leaf forward: write to own stdout: {e}");
            return 1;
        }
        0
    }

    fn role_shared_writer_fork() -> i32 {
        // Create a host pipe via libc::pipe2. Fork; both halves hold
        // the write end. Sequence:
        //   1. parent (this process) writes "PARENT" then closes own write end.
        //   2. child writes "CHILD" then sleeps 100ms then exits.
        // The reader (our test handler) should see "PARENT" + "CHILD"
        // + EOF (not "PARENT" + EOF before child writes).
        //
        // We forward read end to our OWN stdout for the test handler to
        // observe. This means we run a small pump thread.
        use std::os::unix::io::FromRawFd;
        let mut fds = [0i32; 2];
        // SAFETY: pipe2 has no preconditions.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if rc != 0 {
            eprintln!(
                "pxeof-leaf shared-writer-fork: pipe2 failed: {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        let read_fd = fds[0];
        let write_fd = fds[1];

        // Fork. Both halves keep write_fd.
        // SAFETY: fork() is async-signal-safe; we don't do anything in the
        // child that requires the parent's runtime invariants beyond stdio.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            eprintln!(
                "pxeof-leaf shared-writer-fork: fork failed: {}",
                std::io::Error::last_os_error()
            );
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return 1;
        }

        if pid == 0 {
            // CHILD.
            unsafe { libc::close(read_fd) };
            let mut f = unsafe { std::fs::File::from_raw_fd(write_fd) };
            let _ = f.write_all(b"CHILD\n");
            let _ = f.flush();
            // Hold the write end briefly so the parent's "PARENT" + close
            // doesn't EOF the reader prematurely.
            std::thread::sleep(Duration::from_millis(100));
            drop(f);
            std::process::exit(0);
        }

        // PARENT.
        unsafe { libc::close(read_fd) };
        // Convert write_fd to OwnedFd so we can write then drop.
        let mut writer = unsafe { std::fs::File::from_raw_fd(write_fd) };
        let _ = writer.write_all(b"PARENT\n");
        let _ = writer.flush();
        drop(writer);
        // Wait for child.
        let mut wstatus = 0i32;
        // SAFETY: waitpid takes a child pid and an output i32 pointer.
        unsafe { libc::waitpid(pid, &mut wstatus, 0) };
        // The reader (handler) reads from our stdout, not from the pipe
        // pair above (that pair is internal to this leaf). Print the
        // marker line that the handler asserts on.
        println!("SHARED_WRITER_DONE");
        0
    }

    /// Mirrors `PIDF.exit_self`'s child-binary shape but without
    /// pidfd/poll. Forks a grandchild that exits immediately, waits
    /// for it via waitpid, then exits cleanly. Parent observes
    /// closed stdout (empty payload + EOF) since this leaf writes
    /// nothing to stdout.
    fn role_inner_fork_exit() -> i32 {
        // SAFETY: fork() is async-signal-safe; the child branch only
        // calls `_exit(0)` which is also async-signal-safe.
        let grandchild = unsafe { libc::fork() };
        if grandchild < 0 {
            eprintln!(
                "pxeof-leaf inner-fork-exit: fork failed: {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        if grandchild == 0 {
            // SAFETY: _exit on a known status.
            unsafe { libc::_exit(0) };
        }
        // SAFETY: waitpid on the known pid; null status pointer accepted.
        let waited = unsafe { libc::waitpid(grandchild, core::ptr::null_mut(), 0) };
        if waited != grandchild {
            eprintln!(
                "pxeof-leaf inner-fork-exit: waitpid returned {waited}, expected {grandchild}"
            );
            return 1;
        }
        // Exit cleanly. We deliberately don't write to stdout — the
        // handler asserts on empty stdout + EOF.
        0
    }

    use std::io::Write;
}
