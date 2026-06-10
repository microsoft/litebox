// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `WORKER_READY_RACE.*`: stress-test the asymmetry between
//! `spawn_worker_host_for_exec` (which returns to the parent
//! immediately after `posix_spawn` completes — *before* the worker
//! process has called `install_broker_fd_bridge_spec` for each
//! inherited broker-backed fd) and `spawn_worker_host_for_fork_restore`
//! (which blocks on an ack from the worker before returning).
//! See `litebox_platform_linux_userland/src/lib.rs:1287` vs
//! `litebox_platform_linux_userland/src/lib.rs:1929`.
//!
//! The race window is the interval between the parent's
//! `spawn_worker_host_for_exec` returning and the worker actually
//! installing each `--broker-fd-bridge` spec. If the parent performs
//! syscalls against one of the bridged fds during that window, the
//! shim may observe inconsistent broker state (EBADF, hang, mismatched
//! payload). The held fix on branch `wportnoy/wave-cleanup-inherit`
//! (commit `65a9ae87`) adds a one-byte `--worker-ready-fd` pipe
//! barrier in the parent.
//!
//! Test shape: parent (handler on a leaf of `parent_bt`) opens a
//! broker-backed fd of `fd_kind`, repeatedly fork+execs a non-PIE
//! child binary (`child_bt`), and immediately after each spawn
//! performs `race_pattern` operations on the fd before waiting for
//! the child to complete. A test FAILs if any iteration times out
//! or returns wrong data; the detail includes the failing iteration
//! number and failure mode (statistical detection).
//!
//! Test ID shape:
//!   `WORKER_READY_RACE.<fd_kind>.<race_pattern>.<parent_bt>.<child_bt>`
//!
//! `child_bt` is restricted to `NonPieGlibc` and `NonPieStaticMusl` —
//! these are the only binary types that force the
//! `spawn_worker_host_for_exec` path. PIE children take the
//! local-exec path and do not exercise the race.

#![allow(clippy::wildcard_enum_match_arm)]

use serde::{Deserialize, Serialize};
use std::os::fd::RawFd;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::eventfd::EventFd;
use crate::os::pidfd::Pidfd;
use crate::{BinaryType, register_handler};

// ─── Axes ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum FdKind {
    /// Broker-backed eventfd (semaphore mode), inherited via
    /// `--broker-fd-bridge` on the non-PIE worker exec.
    Eventfd,
    /// Broker-backed pidfd on a transient sibling sleeper, inherited
    /// via `--broker-fd-bridge` on the non-PIE worker exec.
    Pidfd,
}

impl FdKind {
    const fn suffix(self) -> &'static str {
        match self {
            Self::Eventfd => "eventfd",
            Self::Pidfd => "pidfd",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum RacePattern {
    /// Immediately after spawn returns, perform the natural op on
    /// the fd: write for eventfd, `poll(POLLIN, 0)` for pidfd.
    ImmediateOp,
    /// Immediately after spawn returns, register the fd in a fresh
    /// epoll set and call `epoll_wait(..., 0)` once. Exercises the
    /// broker's epoll-add path on a freshly-bridged fd.
    ImmediatePoll,
    /// Immediately after spawn returns, spin tightly issuing
    /// `fcntl(F_GETFD)` and `fcntl(F_GETFL)` on the fd 256 times to
    /// maximize broker-table contention during the worker's bridge
    /// install.
    TightLoop,
}

impl RacePattern {
    const fn suffix(self) -> &'static str {
        match self {
            Self::ImmediateOp => "immediate_op",
            Self::ImmediatePoll => "immediate_poll",
            Self::TightLoop => "tight_loop",
        }
    }
}

const RACE_PATTERNS: &[RacePattern] = &[
    RacePattern::ImmediateOp,
    RacePattern::ImmediatePoll,
    RacePattern::TightLoop,
];

const FD_KINDS: &[FdKind] = &[FdKind::Eventfd, FdKind::Pidfd];

/// Parent leg covers the full five-way binary-type cross-product;
/// child leg is restricted to non-PIE binaries (the only path that
/// triggers `spawn_worker_host_for_exec`).
const PARENT_BTS: &[BinaryType] = &[
    BinaryType::PieGlibc,
    BinaryType::NonPieGlibc,
    BinaryType::StaticPieGlibc,
    BinaryType::StaticPieMusl,
    BinaryType::NonPieStaticMusl,
];

const CHILD_BTS: &[BinaryType] = &[BinaryType::NonPieGlibc, BinaryType::NonPieStaticMusl];

/// Number of inner iterations per test. Each iteration spawns a
/// non-PIE worker, so the wall-clock cost is N × (worker spawn ms).
/// 50 keeps tests comfortably under the 60s outer timeout while
/// providing meaningful statistical coverage of the race window.
const DEFAULT_ITERATIONS: u32 = 50;

/// Tight-loop iteration count used by `RacePattern::TightLoop`.
const TIGHT_LOOP_ITERS: u32 = 256;

/// Per-iteration timeout (covers child spawn + race ops + reap).
const ITER_TIMEOUT_MS: u64 = 2500;

// ─── Handler I/O ────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct WorkerReadyRaceArgs {
    fd_kind: FdKind,
    race_pattern: RacePattern,
    child_binary: String,
    iterations: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct WorkerReadyRaceOut {
    iterations_run: u32,
    successes: u32,
    /// Populated only on failure; first iteration's failure detail.
    first_failure: Option<String>,
}

const WORKER_READY_RACE: HandlerToken<WorkerReadyRaceArgs, WorkerReadyRaceOut> =
    HandlerToken::new("worker_ready_race.run");

// ─── Race-pattern primitives ────────────────────────────────────────

/// Immediately exercise the bridged fd from the parent side. Returns
/// an error string if the operation reported a broker/kernel error;
/// returns `Ok(())` whether or not data was actually observed
/// (semantics are defined per fd_kind by the inner test loop).
fn run_race_pattern(fd: RawFd, fd_kind: FdKind, pattern: RacePattern) -> Result<(), String> {
    match pattern {
        RacePattern::ImmediateOp => match fd_kind {
            FdKind::Eventfd => write_eventfd_value(fd, 1),
            FdKind::Pidfd => poll_fd_once(fd, libc::POLLIN, 0).map(|_| ()),
        },
        RacePattern::ImmediatePoll => {
            // Build a fresh epoll set, add the fd, do one non-blocking
            // wait, then close the epoll fd. This routes through the
            // broker's epoll-add path on a freshly bridged fd.
            // SAFETY: epoll_create1 / epoll_ctl / epoll_wait / close
            // all operate on fds we just acquired or were passed.
            unsafe {
                let ep = libc::epoll_create1(libc::EPOLL_CLOEXEC);
                if ep < 0 {
                    return Err(format!(
                        "epoll_create1: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                let mut ev = libc::epoll_event {
                    events: u32::try_from(libc::EPOLLIN).unwrap_or(0),
                    u64: 0,
                };
                if libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &raw mut ev) != 0 {
                    let e = std::io::Error::last_os_error();
                    libc::close(ep);
                    return Err(format!("epoll_ctl ADD fd={fd}: {e}"));
                }
                let mut out = libc::epoll_event { events: 0, u64: 0 };
                let _ = libc::epoll_wait(ep, &raw mut out, 1, 0);
                libc::close(ep);
            }
            Ok(())
        }
        RacePattern::TightLoop => {
            for _ in 0..TIGHT_LOOP_ITERS {
                // SAFETY: fcntl with F_GETFD / F_GETFL is read-only.
                let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                if rc < 0 {
                    return Err(format!(
                        "fcntl(F_GETFD) fd={fd}: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                let rc = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                if rc < 0 {
                    return Err(format!(
                        "fcntl(F_GETFL) fd={fd}: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
            Ok(())
        }
    }
}

fn write_eventfd_value(fd: RawFd, value: u64) -> Result<(), String> {
    let bytes = value.to_ne_bytes();
    // SAFETY: write to a u64-sized buffer on an eventfd.
    let rc = unsafe {
        libc::write(
            fd,
            bytes.as_ptr().cast::<libc::c_void>(),
            core::mem::size_of::<u64>(),
        )
    };
    if rc == isize::try_from(core::mem::size_of::<u64>()).unwrap_or(8) {
        Ok(())
    } else if rc < 0 {
        Err(format!(
            "eventfd write fd={fd}: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Err(format!("eventfd short write fd={fd}: rc={rc}"))
    }
}

fn poll_fd_once(fd: RawFd, events: i16, timeout_ms: i32) -> Result<i32, String> {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    // SAFETY: pfd is a single live pollfd struct.
    let rc = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
    if rc < 0 {
        Err(format!("poll fd={fd}: {}", std::io::Error::last_os_error()))
    } else {
        Ok(rc)
    }
}

fn clear_cloexec(fd: RawFd) -> Result<(), String> {
    // SAFETY: fcntl(F_SETFD) operates on a live fd; errors are checked.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    if rc != 0 {
        return Err(format!(
            "fcntl(F_SETFD, 0) fd={fd}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

// ─── Per-iteration execution ────────────────────────────────────────

/// Run one iteration of the race. Returns `Ok(())` on success,
/// `Err(reason)` on any failure (timeout, wrong child output,
/// race-pattern syscall error, spawn error).
fn run_iteration(
    fd_kind: FdKind,
    race_pattern: RacePattern,
    child_binary: &str,
) -> Result<(), String> {
    match fd_kind {
        FdKind::Eventfd => run_eventfd_iteration(race_pattern, child_binary),
        FdKind::Pidfd => run_pidfd_iteration(race_pattern, child_binary),
    }
}

fn run_eventfd_iteration(race_pattern: RacePattern, child_binary: &str) -> Result<(), String> {
    // Reuse inherit-matrix eventfd-child semantics: semaphore-mode
    // eventfd, parent pre-writes 1, child does one read → expects 1.
    let ev =
        EventFd::open(0, "nonblock|semaphore|cloexec").map_err(|e| format!("eventfd open: {e}"))?;
    let fd = ev.as_raw_fd();
    clear_cloexec(fd)?;
    ev.write(1).map_err(|e| format!("pre-write: {e}"))?;

    let mut cmd = Command::new(child_binary);
    cmd.args([
        "inherit-matrix",
        "eventfd-child",
        "read",
        "1",
        &ITER_TIMEOUT_MS.to_string(),
    ])
    .env("LITEBOX_INHERIT_FD", fd.to_string())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let child = cmd
        .spawn()
        .map_err(|e| format!("spawn {child_binary}: {e}"))?;

    // CRITICAL: no yield/sleep here. This is the race window.
    let race_result = run_race_pattern(fd, FdKind::Eventfd, race_pattern);

    let output = wait_with_timeout(child, Duration::from_millis(ITER_TIMEOUT_MS + 1000))?;

    race_result?;

    if !output.status.success() {
        return Err(format!(
            "child exit={:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim(),
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout != "1" {
        return Err(format!(
            "stdout={stdout:?} (expected \"1\") stderr={}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn run_pidfd_iteration(race_pattern: RacePattern, child_binary: &str) -> Result<(), String> {
    // Fork a short-lived sleeper, open a pidfd on it, hand to child.
    // SAFETY: child path uses only async-signal-safe libc.
    let target_pid = unsafe { libc::fork() };
    if target_pid < 0 {
        return Err(format!("target fork: {}", std::io::Error::last_os_error()));
    }
    if target_pid == 0 {
        // SAFETY: usleep/_exit are async-signal-safe.
        unsafe {
            libc::usleep(400 * 1000);
            libc::_exit(0);
        }
    }

    let target_pid_u32 = u32::try_from(target_pid).map_err(|e| format!("target pid: {e}"))?;
    let pidfd = match Pidfd::open(target_pid_u32) {
        Ok(p) => p,
        Err(e) => {
            // SAFETY: best-effort reap on failure path.
            unsafe {
                let mut s = 0;
                libc::waitpid(target_pid, &raw mut s, 0);
            }
            return Err(format!("pidfd_open({target_pid_u32}): {e}"));
        }
    };
    let fd = pidfd.as_raw_fd();
    clear_cloexec(fd)?;

    let mut cmd = Command::new(child_binary);
    cmd.args([
        "inherit-matrix",
        "pidfd-child",
        "poll",
        &ITER_TIMEOUT_MS.to_string(),
    ])
    .env("LITEBOX_INHERIT_FD", fd.to_string())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            // SAFETY: best-effort reap on failure path.
            unsafe {
                let mut s = 0;
                libc::waitpid(target_pid, &raw mut s, 0);
            }
            return Err(format!("spawn {child_binary}: {e}"));
        }
    };

    // CRITICAL: no yield/sleep here. This is the race window.
    let race_result = run_race_pattern(fd, FdKind::Pidfd, race_pattern);

    let output = wait_with_timeout(child, Duration::from_millis(ITER_TIMEOUT_MS + 2000));

    // Reap sleeper unconditionally.
    // SAFETY: target_pid is a child of this process.
    unsafe {
        let mut s = 0;
        let _ = libc::waitpid(target_pid, &raw mut s, libc::WNOHANG);
        let _ = libc::waitpid(target_pid, &raw mut s, 0);
    }

    let output = output?;
    race_result?;

    if !output.status.success() {
        return Err(format!(
            "child exit={:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim(),
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout != "ready" {
        return Err(format!(
            "stdout={stdout:?} (expected \"ready\") stderr={}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().map_err(|e| format!("wait: {e}")),
            Ok(None) => {}
            Err(e) => return Err(format!("try_wait: {e}")),
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("timeout waiting for child".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ─── Handler ────────────────────────────────────────────────────────

async fn handle_worker_ready_race(
    args: WorkerReadyRaceArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<WorkerReadyRaceOut, HandlerError> {
    let mut successes = 0_u32;
    let mut first_failure: Option<String> = None;
    let mut iterations_run = 0_u32;

    for i in 0..args.iterations {
        iterations_run = i + 1;
        match run_iteration(args.fd_kind, args.race_pattern, &args.child_binary) {
            Ok(()) => successes += 1,
            Err(e) => {
                if first_failure.is_none() {
                    first_failure = Some(format!("iter={i} {e}"));
                }
                // Keep going so we get a fuller statistical picture.
            }
        }
    }

    Ok(WorkerReadyRaceOut {
        iterations_run,
        successes,
        first_failure,
    })
}

// ─── Registration ───────────────────────────────────────────────────

const fn parent_agent(bt: BinaryType) -> AgentName {
    match bt {
        BinaryType::PieGlibc => AgentName::Dpg1,
        BinaryType::NonPieGlibc => AgentName::Dpg1Dng,
        BinaryType::StaticPieGlibc => AgentName::Dpg1Spg,
        BinaryType::StaticPieMusl => AgentName::Dpg1Spm,
        BinaryType::NonPieStaticMusl => AgentName::Dpg1Snm,
    }
}

pub(crate) fn register_worker_ready_race(reg: &mut Registry<'_>) {
    register_handler!(WORKER_READY_RACE, handle_worker_ready_race);

    for &fd_kind in FD_KINDS {
        for &race_pattern in RACE_PATTERNS {
            for &parent_bt in PARENT_BTS {
                for &child_bt in CHILD_BTS {
                    let id = format!(
                        "WORKER_READY_RACE.{}.{}.{}.{}",
                        fd_kind.suffix(),
                        race_pattern.suffix(),
                        parent_bt.short_label(),
                        child_bt.short_label(),
                    );
                    let parent = parent_agent(parent_bt);

                    reg.test("vscode", "worker_ready_race", id)
                        .timeout(60)
                        .build(move |cx| {
                            let parent_handle = cx.require(parent);
                            Box::new(move |run| {
                                Box::pin(async move {
                                    let self_exe = run.self_exe().to_string();
                                    let child_binary = crate::binary_path(child_bt, &self_exe);
                                    let result = run
                                        .send_named_typed(
                                            &parent_handle,
                                            &WORKER_READY_RACE,
                                            WorkerReadyRaceArgs {
                                                fd_kind,
                                                race_pattern,
                                                child_binary,
                                                iterations: DEFAULT_ITERATIONS,
                                            },
                                        )
                                        .await;
                                    match result {
                                        Ok(out) => {
                                            let pass = out.first_failure.is_none()
                                                && out.successes == out.iterations_run;
                                            let detail = format!(
                                                "iters={} ok={} first_failure={:?}",
                                                out.iterations_run,
                                                out.successes,
                                                out.first_failure
                                            );
                                            TestOutcome::new(parent.name(), pass, detail)
                                        }
                                        Err(e) => TestOutcome::new(parent.name(), false, e),
                                    }
                                })
                            })
                        });
                }
            }
        }
    }
}
