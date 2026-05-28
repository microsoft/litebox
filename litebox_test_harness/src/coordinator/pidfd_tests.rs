// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Handler-native pidfd cross-process / cross-binary-type tests.
//!
//! Mirrors the structure of [`crate::coordinator::eventfd`] but for
//! pidfd. Each test family follows the **fix-first** pattern: native
//! is the gold standard (must pass); litebox failures are real
//! product gaps that should be fixed in subsequent product work
//! (see `litebox_test_harness/CLAUDE.md` "Investigating a failure").
//!
//! # Families
//!
//! - `PIDF.exit_self.<bt>` (5 variants over [`BinaryType::ALL`]):
//!   Single-agent self-test — fork+execv into a `<bt>` child that
//!   does the full pidfd dance internally. Validates the basic
//!   capability works for each binary type.
//!
//! - `PIDF.exit_inherit.<bt>` (5 variants): The
//!   cross-process-across-binary-type test. The driving handler
//!   running on a `Dpg1` (PieGlibc) agent forks a sleep-grandchild,
//!   `pidfd_open`s it, then fork+execvs into a `<bt>` child binary
//!   which inherits the pidfd at a known fd number. The child polls
//!   the inherited pidfd. Native: 5/5 pass (kernel preserves fd
//!   across fork+exec). Litebox today: PIE-glibc legs pass; non-PIE
//!   legs fail with the delayed-fork-bridge gap that legacy
//!   `PIF.<bt>` non-PIE also hits — pinning the next product fix.
//!
//! - `PIDF.spawn_and_open` (single, framework-only): the
//!   handler-native sanity test that an agent can `pidfd_open` a
//!   grandchild it just forked and observe its exit via poll. Same
//!   role as the legacy `PIFH.basic` test from the cwfd-p2-pidfd
//!   branch.
//!
//! - `PIDFI.*`: focused pidfd inheritance edge cases. These extend
//!   `PIDF.exit_inherit` with representative parent/child binary-type
//!   transitions, explicit `FD_CLOEXEC` survival/non-survival checks,
//!   and dup-to-specific-fd inheritance.

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::pidfd::Pidfd;
use crate::register_handler;

use super::TestOutcome;
use super::agents::{AgentName, SpawnKind};
use super::registry::Registry;

// ─── Outputs ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct SpawnAndOpenOut {
    child_pid: u32,
    pidfd_raw: i32,
    fired: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct ExitSelfArgs {
    /// Path to the `<bt>` child binary the test execs into.
    child_binary: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ExitSelfOut {
    /// Wait status from the child fork+exec process.
    exit_code: i32,
    /// Stderr the child binary emitted (for failure diagnostics).
    stderr: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ExitInheritArgs {
    /// Path to the `<bt>` child binary that inherits the pidfd.
    child_binary: String,
    /// Timeout in ms the child gives the poll. Must exceed the
    /// grandchild's `sleep(1)` plus exec startup time. Default 5000.
    timeout_ms: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct ExitInheritOut {
    /// Wait status from the child process (0 = POLLIN fired).
    exit_code: i32,
    /// Child stderr (poll-failure diagnostics if exit_code != 0).
    stderr: String,
    /// Whether the grandchild process was successfully reaped.
    grandchild_reaped: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct PidfiInheritArgs {
    child_binary: String,
    timeout_ms: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct PidfiInheritOut {
    exit_code: i32,
    stderr: String,
    grandchild_reaped: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct PidfiCloexecOut {
    clear_exit_code: i32,
    clear_stderr: String,
    cloexec_exit_code: i32,
    cloexec_stderr: String,
    grandchild_reaped: bool,
}

// ─── Typed handler tokens ──────────────────────────────────────────

const SPAWN_AND_OPEN: HandlerToken<(), SpawnAndOpenOut> = HandlerToken::new("pidfd.spawn_and_open");
const EXIT_SELF: HandlerToken<ExitSelfArgs, ExitSelfOut> = HandlerToken::new("pidfd.exit_self");
const EXIT_INHERIT: HandlerToken<ExitInheritArgs, ExitInheritOut> =
    HandlerToken::new("pidfd.exit_inherit");
const PIDFI_BASIC: HandlerToken<PidfiInheritArgs, PidfiInheritOut> =
    HandlerToken::new("pidfd_inherit.basic");
const PIDFI_CLOEXEC: HandlerToken<PidfiInheritArgs, PidfiCloexecOut> =
    HandlerToken::new("pidfd_inherit.cloexec");
const PIDFI_DUP: HandlerToken<PidfiInheritArgs, PidfiInheritOut> =
    HandlerToken::new("pidfd_inherit.dup_then_exec");
const POLL_READY_AFTER_EXIT: HandlerToken<PollReadyArgs, PollReadyOut> =
    HandlerToken::new("pidfd.poll_ready_after_exit");

#[derive(Serialize, Deserialize, Debug)]
struct PollReadyArgs {
    /// How many fork-exit-poll iterations to run.
    iterations: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct PollReadyOut {
    iterations_run: u32,
    /// Number of iterations where poll(pidfd, POLLIN, 0) NEVER returned
    /// ready within `MAX_SPIN_POLLS` even though `waitpid(WNOHANG)`
    /// confirmed the child had been reaped. Each such iteration is a
    /// cache-staleness observation: the broker definitively knows the
    /// target exited (waitpid wouldn't have succeeded otherwise), but
    /// the shim's local readiness query disagrees.
    stale_observations: u32,
    /// Worst-case spin count observed across all iterations. Useful for
    /// diagnosing how wide the cache-lag window is when the bug fires.
    max_spin_polls: u32,
}

// ─── Handlers ───────────────────────────────────────────────────────

async fn handle_spawn_and_open(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<SpawnAndOpenOut, HandlerError> {
    // SAFETY: fork creates a child process. The child performs only
    // async-signal-safe libc sleep followed by _exit; the parent
    // continues Rust execution.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(HandlerError(format!(
            "fork: {}",
            std::io::Error::last_os_error()
        )));
    }
    if child == 0 {
        // SAFETY: child process terminates directly after sleeping.
        unsafe {
            libc::sleep(1);
            libc::_exit(0);
        }
    }
    let child_pid = u32::try_from(child).map_err(|e| HandlerError(e.to_string()))?;
    let pidfd = Pidfd::open(child_pid).map_err(|e| HandlerError(format!("pidfd_open: {e}")))?;
    let fired = pidfd
        .poll_exit_in(5000)
        .map_err(|e| HandlerError(format!("pidfd poll: {e}")))?;
    let mut status = 0;
    // SAFETY: waiting for the child pid returned by fork.
    let waited = unsafe { libc::waitpid(child, std::ptr::from_mut(&mut status), 0) };
    if waited != child {
        return Err(HandlerError(format!(
            "waitpid({child}) returned {waited}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(SpawnAndOpenOut {
        child_pid,
        pidfd_raw: pidfd.as_raw_fd(),
        fired,
    })
}

async fn handle_exit_self(
    args: ExitSelfArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ExitSelfOut, HandlerError> {
    // Pure capability sanity: child binary runs `pidfd-test
    // self-raise SIGUSR1`-style flow but for pidfd. Actually for
    // PIDF.exit_self.<bt> we run the same fork+pidfd_open+poll dance
    // entirely within the child process. The child needs to do its
    // own fork to get a target — we just delegate by execing
    // `pidfd-test self-test` (no inherited fd needed).
    //
    // Implementation: spawn child binary via std::process::Command,
    // collect stdout/stderr/exit_code. This is single-process self-
    // test of the *child binary*; the driving agent is just the
    // launcher.
    let out = std::process::Command::new(&args.child_binary)
        .args(["pidfd-test", "self-test"])
        .output()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;
    Ok(ExitSelfOut {
        exit_code: out.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

async fn handle_exit_inherit(
    args: ExitInheritArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ExitInheritOut, HandlerError> {
    // 1) fork a sleep-grandchild. The grandchild will be the target
    //    of the pidfd; it sleeps long enough for the child binary's
    //    exec to complete and its poll to begin.
    let grandchild = unsafe { libc::fork() };
    if grandchild < 0 {
        return Err(HandlerError(format!(
            "fork grandchild: {}",
            std::io::Error::last_os_error()
        )));
    }
    if grandchild == 0 {
        // SAFETY: child process terminates after sleeping.
        unsafe {
            libc::sleep(2);
            libc::_exit(0);
        }
    }
    let grandchild_pid = u32::try_from(grandchild).map_err(|e| HandlerError(e.to_string()))?;

    // 2) pidfd_open(grandchild_pid). This is the local pidfd path —
    //    the grandchild is a child of this process so it's known to
    //    the local process registry on litebox.
    let pidfd = Pidfd::open(grandchild_pid).map_err(|e| {
        // Make sure we reap the grandchild on failure so we don't
        // leak a zombie.
        // SAFETY: waitpid on the known pid.
        unsafe {
            libc::kill(grandchild, libc::SIGKILL);
            let mut s = 0;
            libc::waitpid(grandchild, std::ptr::from_mut(&mut s), 0);
        }
        HandlerError(format!("pidfd_open: {e}"))
    })?;

    // 3) Clear CLOEXEC on the pidfd so it survives fork+execv.
    let pidfd_raw = pidfd.as_raw_fd();
    // SAFETY: fcntl on a live fd we own.
    let fc = unsafe { libc::fcntl(pidfd_raw, libc::F_SETFD, 0) };
    if fc != 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::kill(grandchild, libc::SIGKILL);
            let mut s = 0;
            libc::waitpid(grandchild, std::ptr::from_mut(&mut s), 0);
        }
        return Err(HandlerError(format!("fcntl(F_SETFD, 0): {err}")));
    }

    // 4) Fork+execv the <bt> child binary which inherits the pidfd
    //    at the same fd number and runs `pidfd-test poll-inherited`.
    //    We use std::process::Command to manage stdout/stderr; the
    //    pidfd fd is inherited because CLOEXEC was cleared above.
    let fd_arg = pidfd_raw.to_string();
    let timeout_arg = args.timeout_ms.to_string();
    let out = std::process::Command::new(&args.child_binary)
        .args(["pidfd-test", "poll-inherited", &fd_arg, &timeout_arg])
        .output();

    // 5) Reap the grandchild regardless of child outcome.
    let mut s = 0;
    // SAFETY: waiting for the known grandchild pid.
    let waited = unsafe { libc::waitpid(grandchild, std::ptr::from_mut(&mut s), 0) };
    let grandchild_reaped = waited == grandchild;

    // 6) Return the child binary's verdict.
    let out = out.map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;
    Ok(ExitInheritOut {
        exit_code: out.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        grandchild_reaped,
    })
}

fn fork_sleep_target(seconds: u32) -> Result<i32, HandlerError> {
    // SAFETY: fork creates a child process. The child only sleeps and exits.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(HandlerError(format!(
            "fork target: {}",
            std::io::Error::last_os_error()
        )));
    }
    if child == 0 {
        // SAFETY: child process terminates directly after sleeping.
        unsafe {
            libc::sleep(seconds);
            libc::_exit(0);
        }
    }
    Ok(child)
}

fn reap_child(pid: i32) -> bool {
    let mut status = 0;
    // SAFETY: waiting for a known child pid returned by fork.
    unsafe { libc::waitpid(pid, std::ptr::from_mut(&mut status), 0) == pid }
}

fn kill_and_reap_child(pid: i32) {
    // SAFETY: best-effort cleanup for a known child pid.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, std::ptr::from_mut(&mut status), 0);
    }
}

fn set_fd_cloexec(fd: i32, cloexec: bool) -> Result<(), HandlerError> {
    let flags = if cloexec { libc::FD_CLOEXEC } else { 0 };
    // SAFETY: fcntl on a live descriptor owned by this process.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags) };
    if rc == 0 {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "fcntl(F_SETFD, {flags:#x}) on fd {fd}: {}",
            std::io::Error::last_os_error()
        )))
    }
}

fn pidfd_open_for_child(pid: i32) -> Result<Pidfd, HandlerError> {
    let child_pid = u32::try_from(pid).map_err(|e| HandlerError(e.to_string()))?;
    Pidfd::open(child_pid).map_err(|e| HandlerError(format!("pidfd_open({child_pid}): {e}")))
}

fn output_exit_code(out: &std::process::Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

async fn handle_pidfi_basic(
    args: PidfiInheritArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PidfiInheritOut, HandlerError> {
    let target = fork_sleep_target(2)?;
    let pidfd = match pidfd_open_for_child(target) {
        Ok(pidfd) => pidfd,
        Err(e) => {
            kill_and_reap_child(target);
            return Err(e);
        }
    };
    if let Err(e) = set_fd_cloexec(pidfd.as_raw_fd(), false) {
        kill_and_reap_child(target);
        return Err(e);
    }

    let fd_arg = pidfd.as_raw_fd().to_string();
    let timeout_arg = args.timeout_ms.to_string();
    let out = std::process::Command::new(&args.child_binary)
        .args(["pidfd-test", "poll-inherited", &fd_arg, &timeout_arg])
        .output();
    let grandchild_reaped = reap_child(target);
    let out = out.map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;
    Ok(PidfiInheritOut {
        exit_code: output_exit_code(&out),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        grandchild_reaped,
    })
}

async fn handle_pidfi_cloexec(
    args: PidfiInheritArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PidfiCloexecOut, HandlerError> {
    let target = fork_sleep_target(2)?;
    let clear_pidfd = match pidfd_open_for_child(target) {
        Ok(pidfd) => pidfd,
        Err(e) => {
            kill_and_reap_child(target);
            return Err(e);
        }
    };
    let cloexec_pidfd = match pidfd_open_for_child(target) {
        Ok(pidfd) => pidfd,
        Err(e) => {
            kill_and_reap_child(target);
            return Err(e);
        }
    };
    if let Err(e) = set_fd_cloexec(clear_pidfd.as_raw_fd(), false) {
        kill_and_reap_child(target);
        return Err(e);
    }
    if let Err(e) = set_fd_cloexec(cloexec_pidfd.as_raw_fd(), true) {
        kill_and_reap_child(target);
        return Err(e);
    }

    let cloexec_fd_arg = cloexec_pidfd.as_raw_fd().to_string();
    let cloexec_out = std::process::Command::new(&args.child_binary)
        .args(["pidfd-test", "expect-closed", &cloexec_fd_arg])
        .output()
        .map_err(|e| HandlerError(format!("spawn expect-closed {}: {e}", args.child_binary)))?;

    let clear_fd_arg = clear_pidfd.as_raw_fd().to_string();
    let timeout_arg = args.timeout_ms.to_string();
    let clear_out = std::process::Command::new(&args.child_binary)
        .args(["pidfd-test", "poll-inherited", &clear_fd_arg, &timeout_arg])
        .output()
        .map_err(|e| HandlerError(format!("spawn poll-inherited {}: {e}", args.child_binary)))?;

    let grandchild_reaped = reap_child(target);
    Ok(PidfiCloexecOut {
        clear_exit_code: output_exit_code(&clear_out),
        clear_stderr: String::from_utf8_lossy(&clear_out.stderr).into_owned(),
        cloexec_exit_code: output_exit_code(&cloexec_out),
        cloexec_stderr: String::from_utf8_lossy(&cloexec_out.stderr).into_owned(),
        grandchild_reaped,
    })
}

async fn handle_pidfi_dup(
    args: PidfiInheritArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PidfiInheritOut, HandlerError> {
    let target = fork_sleep_target(2)?;
    let pidfd = match pidfd_open_for_child(target) {
        Ok(pidfd) => pidfd,
        Err(e) => {
            kill_and_reap_child(target);
            return Err(e);
        }
    };
    // SAFETY: fcntl duplicates a live fd to a process-owned descriptor >= 50.
    let dup_fd = unsafe { libc::fcntl(pidfd.as_raw_fd(), libc::F_DUPFD, 50) };
    if dup_fd < 0 {
        let err = std::io::Error::last_os_error();
        kill_and_reap_child(target);
        return Err(HandlerError(format!("fcntl(F_DUPFD): {err}")));
    }
    if let Err(e) = set_fd_cloexec(dup_fd, false) {
        // SAFETY: dup_fd was returned by F_DUPFD and is owned by this process.
        unsafe { libc::close(dup_fd) };
        kill_and_reap_child(target);
        return Err(e);
    }

    let fd_arg = dup_fd.to_string();
    let timeout_arg = args.timeout_ms.to_string();
    let out = std::process::Command::new(&args.child_binary)
        .args(["pidfd-test", "poll-inherited", &fd_arg, &timeout_arg])
        .output();
    // SAFETY: dup_fd was returned by F_DUPFD and is owned by this process.
    unsafe { libc::close(dup_fd) };
    let grandchild_reaped = reap_child(target);
    let out = out.map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;
    Ok(PidfiInheritOut {
        exit_code: output_exit_code(&out),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        grandchild_reaped,
    })
}

/// Pidfd cache-staleness regression probe — parallel to the Phase H
/// PTY bug fix (commit `bdd1d234`). For each of `args.iterations`:
///
/// 1. Fork a child that immediately `_exit(0)`s.
/// 2. Open a pidfd on the child.
/// 3. Tight loop: alternate `poll(pidfd, POLLIN, 0)` with
///    `waitpid(child, WNOHANG)`. Stop as soon as either poll reports
///    ready or waitpid reaps the child.
/// 4. If waitpid reaped the child (broker-truth proof: the child's exit
///    has fully propagated to the parent-side wait machinery) but the
///    poll that ran just before NEVER observed ready, count one
///    `stale_observations` — the shim's local pidfd readiness query
///    lagged the broker.
///
/// On a correct broker-as-source-of-truth implementation this counter
/// stays 0: `poll(pidfd, POLLIN, 0)` synchronously asks the broker, so
/// any time the broker would say "exited" the local poll also reports
/// ready. The probe is deliberately tight-loop / no-sleep so the
/// dispatcher-vs-main-thread race window is wide if a cache exists.
async fn handle_poll_ready_after_exit(
    args: PollReadyArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PollReadyOut, HandlerError> {
    const MAX_SPIN_POLLS: u32 = 100_000;
    let mut stale_observations: u32 = 0;
    let mut max_spin_polls: u32 = 0;
    for _ in 0..args.iterations {
        // SAFETY: fork() — child does only async-signal-safe _exit(0);
        // parent continues Rust execution.
        let child = unsafe { libc::fork() };
        if child < 0 {
            return Err(HandlerError(format!(
                "fork: {}",
                std::io::Error::last_os_error()
            )));
        }
        if child == 0 {
            // SAFETY: terminate child immediately.
            unsafe { libc::_exit(0) };
        }
        let pidfd = match Pidfd::open(child as u32) {
            Ok(p) => p,
            Err(e) => {
                let _ = reap_child(child);
                return Err(HandlerError(format!("pidfd_open({child}): {e}")));
            }
        };
        let mut spin: u32 = 0;
        let mut ever_ready = false;
        let mut reaped = false;
        while spin < MAX_SPIN_POLLS {
            spin += 1;
            // SAFETY: pidfd is owned; pollfd points to one valid entry.
            let mut pfd = libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, 0) };
            if pfd.revents & libc::POLLIN != 0 {
                ever_ready = true;
                break;
            }
            // Broker-truth oracle: if waitpid reaps the child the
            // broker has fully processed the exit (the runner's reap
            // path drives waitpid through MarkProcessExited).
            let mut status: libc::c_int = 0;
            // SAFETY: child is a valid pid; status is one i32.
            let waited = unsafe {
                libc::waitpid(child, std::ptr::from_mut(&mut status), libc::WNOHANG)
            };
            if waited == child {
                reaped = true;
                // One last poll — observers fire immediately when the
                // broker side updates, but the dispatcher may need this
                // last instant if it was scheduled out.
                let mut last = libc::pollfd {
                    fd: pidfd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: as above.
                unsafe { libc::poll(std::ptr::from_mut(&mut last), 1, 0) };
                if last.revents & libc::POLLIN != 0 {
                    ever_ready = true;
                }
                break;
            }
        }
        if spin > max_spin_polls {
            max_spin_polls = spin;
        }
        if reaped && !ever_ready {
            stale_observations += 1;
        }
        if !reaped {
            let _ = reap_child(child);
        }
    }
    Ok(PollReadyOut {
        iterations_run: args.iterations,
        stale_observations,
        max_spin_polls,
    })
}

// ─── Registration ──────────────────────────────────────────────────

pub(crate) fn register_pidfd_tests(reg: &mut Registry<'_>) {
    register_handler!(SPAWN_AND_OPEN, handle_spawn_and_open);
    register_handler!(EXIT_SELF, handle_exit_self);
    register_handler!(EXIT_INHERIT, handle_exit_inherit);
    register_handler!(PIDFI_BASIC, handle_pidfi_basic);
    register_handler!(PIDFI_CLOEXEC, handle_pidfi_cloexec);
    register_handler!(PIDFI_DUP, handle_pidfi_dup);
    register_handler!(POLL_READY_AFTER_EXIT, handle_poll_ready_after_exit);
    // pidfd-test argv subcommand: the PIDF.* tests invoke
    // `<target_bt> pidfd-test self-test|poll-inherited …` directly via
    // tokio::process::Command (not through a handler) to exercise the
    // fresh-process loader/libc path. Body lives in `mod leaf_subcmd`
    // at the bottom of this file.
    crate::register_leaf_subcommand!("pidfd-test", |args: &[String]| -> i32 {
        let sub = args.get(2).map_or("help", String::as_str);
        leaf_subcmd::run(sub, args)
    });

    // PIDF.spawn_and_open — single-agent sanity (was legacy PIFH.basic)
    reg.test("vscode", "pidfd", "PIDF.spawn_and_open")
        .timeout(20)
        .build(|cx| {
            let agent = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    match run.send_named_typed(&agent, &SPAWN_AND_OPEN, ()).await {
                        Ok(out) if out.fired => TestOutcome::new(
                            "Dpg1",
                            true,
                            format!(
                                "pidfd fd={} fired for child {}",
                                out.pidfd_raw, out.child_pid
                            ),
                        ),
                        Ok(out) => TestOutcome::new(
                            "Dpg1",
                            false,
                            format!(
                                "pidfd fd={} did not fire for child {}",
                                out.pidfd_raw, out.child_pid
                            ),
                        ),
                        Err(e) => TestOutcome::new("Dpg1", false, format!("handler error: {e}")),
                    }
                })
            })
        });

    // PIDF.poll_ready_after_exit — pidfd cache-staleness regression
    // probe. Phase H proved that broker-held readiness reads must NOT
    // go through a shim-side mirror (commit bdd1d234). This test runs
    // the parallel invariant on the pidfd path: after a child has
    // definitely exited (waitpid reaped it), `poll(pidfd, POLLIN, 0)`
    // must report ready. Tight-loop probe with 32 iterations to widen
    // the dispatcher race window.
    reg.test("vscode", "pidfd", "PIDF.poll_ready_after_exit")
        .timeout(30)
        .build(|cx| {
            let agent = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let args = PollReadyArgs { iterations: 32 };
                    match run
                        .send_named_typed(&agent, &POLL_READY_AFTER_EXIT, args)
                        .await
                    {
                        Ok(out) if out.stale_observations == 0 => TestOutcome::new(
                            "Dpg1",
                            true,
                            format!(
                                "no stale observations across {} iterations (worst spin={})",
                                out.iterations_run, out.max_spin_polls
                            ),
                        ),
                        Ok(out) => TestOutcome::new(
                            "Dpg1",
                            false,
                            format!(
                                "{} stale observations across {} iterations (worst spin={}): \
                                 broker reported child reaped but poll(pidfd, POLLIN, 0) never \
                                 saw ready — shim-side cache leads broker by a dispatcher gap",
                                out.stale_observations, out.iterations_run, out.max_spin_polls
                            ),
                        ),
                        Err(e) => TestOutcome::new("Dpg1", false, format!("handler error: {e}")),
                    }
                })
            })
        });

    // PIDF.exit_self.<bt> — single-process capability sanity for
    // each binary type. The child binary runs the entire dance
    // internally (fork sleeper + pidfd_open + poll + reap).
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test("vscode", "pidfd", format!("PIDF.exit_self.{bt_label}"))
            .timeout(20)
            .build(move |cx| {
                let agent = cx.require(AgentName::Dpg1);
                Box::new(move |run| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let child_binary = crate::binary_path(bt, &self_exe);
                        let result = run
                            .send_named_typed(&agent, &EXIT_SELF, ExitSelfArgs { child_binary })
                            .await;
                        match result {
                            Ok(out) if out.exit_code == 0 => {
                                TestOutcome::new("Dpg1", true, "child self-test pidfd dance OK")
                            }
                            Ok(out) => TestOutcome::new(
                                "Dpg1",
                                false,
                                format!("exit_code={} stderr={:?}", out.exit_code, out.stderr),
                            ),
                            Err(e) => TestOutcome::new("Dpg1", false, format!("handler: {e}")),
                        }
                    })
                })
            });
    }

    // PIDF.exit_inherit.<bt> — the cross-process-across-binary-type
    // transition test. Native: 5/5 pass. Litebox: PIE-glibc passes;
    // non-PIE legs hit the delayed-fork-bridge gap.
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test("vscode", "pidfd", format!("PIDF.exit_inherit.{bt_label}"))
            .timeout(30)
            .build(move |cx| {
                let agent = cx.require(AgentName::Dpg1);
                Box::new(move |run| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let child_binary = crate::binary_path(bt, &self_exe);
                        let result = run
                            .send_named_typed(
                                &agent,
                                &EXIT_INHERIT,
                                ExitInheritArgs {
                                    child_binary,
                                    timeout_ms: 5000,
                                },
                            )
                            .await;
                        match result {
                            Ok(out) if out.exit_code == 0 && out.grandchild_reaped => {
                                TestOutcome::new(
                                    "Dpg1",
                                    true,
                                    "child polled+exit 0; reaped grandchild",
                                )
                            }
                            Ok(out) => TestOutcome::new(
                                "Dpg1",
                                false,
                                format!(
                                    "exit_code={} reaped={} stderr={:?}",
                                    out.exit_code, out.grandchild_reaped, out.stderr
                                ),
                            ),
                            Err(e) => {
                                TestOutcome::new("Dpg1", false, format!("handler error: {e}"))
                            }
                        }
                    })
                })
            });
    }

    register_pidfi_tests(reg);
}

fn pidfi_inherit_pass(out: &PidfiInheritOut) -> bool {
    out.exit_code == 0 && out.grandchild_reaped
}

fn pidfi_inherit_failure(out: &PidfiInheritOut) -> String {
    format!(
        "exit_code={} reaped={} stderr={:?}",
        out.exit_code, out.grandchild_reaped, out.stderr
    )
}

fn register_pidfi_tests(reg: &mut Registry<'_>) {
    reg.test("vscode", "pidfd", "PIDFI.basic.pie-glibc")
        .timeout(30)
        .build(|cx| {
            let agent = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let self_exe = run.self_exe().to_string();
                    let child_binary = crate::binary_path(crate::BinaryType::PieGlibc, &self_exe);
                    let result = run
                        .send_named_typed(
                            &agent,
                            &PIDFI_BASIC,
                            PidfiInheritArgs {
                                child_binary,
                                timeout_ms: 5000,
                            },
                        )
                        .await;
                    match result {
                        Ok(out) if pidfi_inherit_pass(&out) => TestOutcome::new(
                            "Dpg1",
                            true,
                            "child polled inherited pidfd after exec",
                        ),
                        Ok(out) => TestOutcome::new("Dpg1", false, pidfi_inherit_failure(&out)),
                        Err(e) => TestOutcome::new("Dpg1", false, format!("handler: {e}")),
                    }
                })
            })
        });

    const CROSS_BT: &[(crate::BinaryType, crate::BinaryType)] = &[
        (
            crate::BinaryType::NonPieGlibc,
            crate::BinaryType::StaticPieMusl,
        ),
        (
            crate::BinaryType::StaticPieMusl,
            crate::BinaryType::NonPieGlibc,
        ),
        (
            crate::BinaryType::NonPieStaticMusl,
            crate::BinaryType::StaticPieGlibc,
        ),
    ];
    for &(parent_bt, child_bt) in CROSS_BT {
        let parent_label = parent_bt.label();
        let child_label = child_bt.label();
        reg.test(
            "vscode",
            "pidfd",
            format!("PIDFI.cross_bt.{parent_label}.{child_label}"),
        )
        .timeout(45)
        .build(move |cx| {
            let parent = cx.declare_ephemeral(
                AgentName::Dpg1,
                format!(
                    "PidfiCross_{}_{}",
                    parent_bt.short_label(),
                    child_bt.short_label()
                ),
                SpawnKind::Fork {
                    binary: super::pipe_bridge::fork_binary_label(parent_bt),
                    inherit_listen_ports: vec![],
                },
            );
            Box::new(move |run| {
                Box::pin(async move {
                    let self_exe = run.self_exe().to_string();
                    let child_binary = crate::binary_path(child_bt, &self_exe);
                    let result = run
                        .run_leaf(
                            &parent,
                            &PIDFI_BASIC,
                            PidfiInheritArgs {
                                child_binary,
                                timeout_ms: 5000,
                            },
                        )
                        .await;
                    let label = format!("{parent_label}->{child_label}");
                    match result {
                        Ok(out) if pidfi_inherit_pass(&out) => TestOutcome::new(
                            &label,
                            true,
                            "parent-bt child-bt fork+exec preserved pidfd",
                        ),
                        Ok(out) => TestOutcome::new(&label, false, pidfi_inherit_failure(&out)),
                        Err(e) => TestOutcome::new(&label, false, format!("handler: {e}")),
                    }
                })
            })
        });
    }

    for &bt in &[
        crate::BinaryType::PieGlibc,
        crate::BinaryType::NonPieGlibc,
        crate::BinaryType::StaticPieMusl,
    ] {
        let bt_label = bt.label();
        reg.test(
            "vscode",
            "pidfd",
            format!("PIDFI.cloexec_clear.{bt_label}"),
        )
        .timeout(45)
        .build(move |cx| {
            let agent = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let self_exe = run.self_exe().to_string();
                    let child_binary = crate::binary_path(bt, &self_exe);
                    let result = run
                        .send_named_typed(
                            &agent,
                            &PIDFI_CLOEXEC,
                            PidfiInheritArgs {
                                child_binary,
                                timeout_ms: 5000,
                            },
                        )
                        .await;
                    match result {
                        Ok(out)
                            if out.clear_exit_code == 0
                                && out.cloexec_exit_code == 0
                                && out.grandchild_reaped =>
                        {
                            TestOutcome::new(
                                "Dpg1",
                                true,
                                "clear fd survived exec; cloexec fd was closed",
                            )
                        }
                        Ok(out) => TestOutcome::new(
                            "Dpg1",
                            false,
                            format!(
                                "clear_exit={} cloexec_exit={} reaped={} clear_stderr={:?} cloexec_stderr={:?}",
                                out.clear_exit_code,
                                out.cloexec_exit_code,
                                out.grandchild_reaped,
                                out.clear_stderr,
                                out.cloexec_stderr
                            ),
                        ),
                        Err(e) => TestOutcome::new("Dpg1", false, format!("handler: {e}")),
                    }
                })
            })
        });
    }

    reg.test("vscode", "pidfd", "PIDFI.dup_then_exec.non-pie-static-musl")
        .timeout(30)
        .build(|cx| {
            let agent = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let self_exe = run.self_exe().to_string();
                    let child_binary =
                        crate::binary_path(crate::BinaryType::NonPieStaticMusl, &self_exe);
                    let result = run
                        .send_named_typed(
                            &agent,
                            &PIDFI_DUP,
                            PidfiInheritArgs {
                                child_binary,
                                timeout_ms: 5000,
                            },
                        )
                        .await;
                    match result {
                        Ok(out) if pidfi_inherit_pass(&out) => TestOutcome::new(
                            "Dpg1",
                            true,
                            "dup fd inherited by exec child and polled target exit",
                        ),
                        Ok(out) => TestOutcome::new("Dpg1", false, pidfi_inherit_failure(&out)),
                        Err(e) => TestOutcome::new("Dpg1", false, format!("handler: {e}")),
                    }
                })
            })
        });
}

mod leaf_subcmd {
    pub(super) fn run(sub: &str, args: &[String]) -> i32 {
        match sub {
            "self-test" => self_test(),
            "poll-inherited" => poll_inherited(args),
            "expect-closed" => expect_closed(args),
            other => {
                eprintln!("pidfd-test: unknown subcommand: {other}");
                2
            }
        }
    }

    /// Self-contained pidfd dance for `PIDF.exit_self.<bt>`: fork a
    /// 1-second sleep grandchild, `pidfd_open` it, poll for POLLIN
    /// up to 5 s, waitpid to reap. Exits 0 on POLLIN fired.
    fn self_test() -> i32 {
        // SAFETY: fork; child execs only async-signal-safe libc.
        let child = unsafe { libc::fork() };
        if child < 0 {
            eprintln!(
                "pidfd-test self-test: fork: {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        if child == 0 {
            // SAFETY: child terminates immediately after sleeping.
            unsafe {
                libc::sleep(1);
                libc::_exit(0);
            }
        }
        // SAFETY: pidfd_open syscall on a real pid.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child as libc::pid_t, 0) } as i32;
        if pidfd < 0 {
            eprintln!(
                "pidfd-test self-test: pidfd_open: {}",
                std::io::Error::last_os_error()
            );
            // SAFETY: kill+waitpid on the known pid.
            unsafe {
                libc::kill(child, libc::SIGKILL);
                let mut s = 0;
                libc::waitpid(child, std::ptr::from_mut(&mut s), 0);
            }
            return 1;
        }
        let mut pfd = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a live initialised pollfd; len 1 matches.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, 5000) };
        // SAFETY: pidfd was returned by pidfd_open and is owned by us.
        unsafe {
            libc::close(pidfd);
        }
        if rc <= 0 || pfd.revents & libc::POLLIN == 0 {
            eprintln!(
                "pidfd-test self-test: poll rc={} revents={}",
                rc, pfd.revents
            );
            // SAFETY: waitpid on the known pid to clean up.
            unsafe {
                let mut s = 0;
                libc::waitpid(child, std::ptr::from_mut(&mut s), 0);
            }
            return 1;
        }
        // SAFETY: waitpid on the known pid.
        let mut status = 0;
        let waited = unsafe { libc::waitpid(child, std::ptr::from_mut(&mut status), 0) };
        if waited != child {
            eprintln!(
                "pidfd-test self-test: waitpid({child}) returned {waited}: {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        0
    }

    fn poll_inherited(args: &[String]) -> i32 {
        let fd: i32 = match args.get(3).and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => {
                eprintln!("pidfd-test poll-inherited: bad fd arg");
                return 2;
            }
        };
        let timeout_ms: i32 = match args.get(4).and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => {
                eprintln!("pidfd-test poll-inherited: bad timeout_ms arg");
                return 2;
            }
        };
        // poll(pidfd, POLLIN, timeout). On pidfd this fires when the
        // target process exits. We don't waitid here — pidfd's child
        // may be a sibling of this child, not its own child, so
        // waitid would ECHILD. Polling for POLLIN is the canonical
        // exit-detection probe.
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a live initialised pollfd; len 1 matches.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        if rc < 0 {
            eprintln!(
                "pidfd-test poll-inherited: poll failed: {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        if rc == 0 {
            eprintln!(
                "pidfd-test poll-inherited: timeout (revents={})",
                pfd.revents
            );
            return 1;
        }
        if pfd.revents & libc::POLLIN == 0 {
            eprintln!(
                "pidfd-test poll-inherited: poll returned but no POLLIN (revents={})",
                pfd.revents
            );
            return 1;
        }
        0
    }

    fn expect_closed(args: &[String]) -> i32 {
        let fd: i32 = match args.get(3).and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => {
                eprintln!("pidfd-test expect-closed: bad fd arg");
                return 2;
            }
        };
        // SAFETY: fcntl probes the descriptor number; no ownership is taken.
        let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
            return 0;
        }
        if rc >= 0 {
            eprintln!("pidfd-test expect-closed: fd {fd} unexpectedly open flags={rc:#x}");
        } else {
            eprintln!(
                "pidfd-test expect-closed: expected EBADF, got {}",
                std::io::Error::last_os_error()
            );
        }
        1
    }
}
