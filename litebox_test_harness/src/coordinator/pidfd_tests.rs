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

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::pidfd::Pidfd;
use crate::register_handler;

use super::TestOutcome;
use super::agents::AgentName;
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

// ─── Typed handler tokens ──────────────────────────────────────────

const SPAWN_AND_OPEN: HandlerToken<(), SpawnAndOpenOut> = HandlerToken::new("pidfd.spawn_and_open");
const EXIT_SELF: HandlerToken<ExitSelfArgs, ExitSelfOut> = HandlerToken::new("pidfd.exit_self");
const EXIT_INHERIT: HandlerToken<ExitInheritArgs, ExitInheritOut> =
    HandlerToken::new("pidfd.exit_inherit");

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

// ─── Registration ──────────────────────────────────────────────────

pub(crate) fn register_pidfd_tests(reg: &mut Registry<'_>) {
    register_handler!(SPAWN_AND_OPEN, handle_spawn_and_open);
    register_handler!(EXIT_SELF, handle_exit_self);
    register_handler!(EXIT_INHERIT, handle_exit_inherit);
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
}
mod leaf_subcmd {
    pub(super) fn run(sub: &str, args: &[String]) -> i32 {
        match sub {
            "self-test" => self_test(),
            "poll-inherited" => poll_inherited(args),
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
}
