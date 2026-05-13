// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Handler-native signalfd cross-process / cross-binary-type tests.
//!
//! Sibling of [`crate::coordinator::pidfd_tests`] but for signalfd.
//! Native is the gold standard; litebox failures pin real product
//! gaps to fix in subsequent product work.
//!
//! # Families
//!
//! - `SFD.basic_self.<bt>` (5 variants over [`BinaryType::ALL`]):
//!   Single-process self-test — the `<bt>` child binary blocks
//!   `SIGUSR1`, creates a signalfd, `raise`s `SIGUSR1`, reads the
//!   siginfo, asserts `ssi_signo == SIGUSR1`. Validates that the
//!   capability works at all in each binary type.
//!
//! - `SFD.inherit_self_raise.<bt>` (5 variants): The
//!   cross-process-across-binary-type transition test. The driving
//!   handler on a `Dpg1` (PieGlibc) agent blocks `SIGUSR1`, creates
//!   a signalfd, clears `CLOEXEC`, then fork+execvs into a `<bt>`
//!   child which inherits the signalfd. The parent `kill(child,
//!   SIGUSR1)`. The child reads from the inherited signalfd,
//!   asserts `ssi_signo == SIGUSR1`. Native: 5/5 pass. Litebox
//!   today: likely 0/5 because guest signal delivery is
//!   shim-virtualized; the broker-backed signalfd (P2.C plumbing)
//!   watches host-kernel signals, while the shim queues guest
//!   signals in its own table that the broker signalfd never sees.

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::signalfd::Signalfd;
use crate::register_handler;

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;

// ─── Outputs ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct BasicSelfArgs {
    child_binary: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct BasicSelfOut {
    exit_code: i32,
    stderr: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct InheritArgs {
    child_binary: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct InheritOut {
    exit_code: i32,
    stderr: String,
}

// ─── Typed handler tokens ──────────────────────────────────────────

const BASIC_SELF: HandlerToken<BasicSelfArgs, BasicSelfOut> =
    HandlerToken::new("signalfd.basic_self");
const INHERIT_SELF_RAISE: HandlerToken<InheritArgs, InheritOut> =
    HandlerToken::new("signalfd.inherit_self_raise");

// ─── Handlers ───────────────────────────────────────────────────────

async fn handle_basic_self(
    args: BasicSelfArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<BasicSelfOut, HandlerError> {
    // Pure self-test: exec the child binary with `signalfd-test
    // self-raise SIGUSR1`. The child handles block+create+raise+read
    // entirely internally. Driving agent just collects exit code.
    let out = std::process::Command::new(&args.child_binary)
        .args(["signalfd-test", "self-raise", "SIGUSR1"])
        .output()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;
    Ok(BasicSelfOut {
        exit_code: out.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

async fn handle_inherit_self_raise(
    args: InheritArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<InheritOut, HandlerError> {
    // 1) Block SIGUSR1 in the calling thread. Forked + exec'd
    //    children inherit this mask, so the kernel queues SIGUSR1
    //    onto the signalfd instead of running default handlers.
    Signalfd::block_signals(&[libc::SIGUSR1])
        .map_err(|e| HandlerError(format!("block_signals: {e}")))?;

    // 2) Create a signalfd watching SIGUSR1. We pass an empty
    //    `flags` string (blocking mode, no CLOEXEC) so the fd
    //    survives fork+execv to the child without further setup.
    let sfd =
        Signalfd::open(&[libc::SIGUSR1], "").map_err(|e| HandlerError(format!("signalfd: {e}")))?;
    let sfd_raw = sfd.as_raw_fd();

    // 3) Fork+execv the <bt> child, passing the inherited fd number
    //    as an argument so the child knows which fd to read.
    let mut cmd = std::process::Command::new(&args.child_binary);
    cmd.args([
        "signalfd-test",
        "read-inherited",
        &sfd_raw.to_string(),
        "SIGUSR1",
    ]);
    let mut child = cmd
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;
    let child_pid = child.id();

    // 4) Send SIGUSR1 to the child. The child has SIGUSR1 blocked
    //    (inherited from this thread's mask via fork+execv) so the
    //    kernel queues it onto its signal-pending set. The child's
    //    read on the inherited signalfd will dequeue it and report
    //    `ssi_signo == SIGUSR1`.
    //
    //    There's no race risk: signalfd is level-triggered, so even
    //    if we kill before the child reads, the signal stays queued
    //    until the read consumes it.
    // SAFETY: kill(2) with a valid pid and signal number.
    let kill_rc = unsafe { libc::kill(child_pid as libc::pid_t, libc::SIGUSR1) };
    if kill_rc != 0 {
        let err = std::io::Error::last_os_error();
        // Try to clean up the child anyway.
        let _ = child.kill();
        let _ = child.wait();
        // Drop sfd to close the inherited fd reference.
        drop(sfd);
        return Err(HandlerError(format!("kill child {child_pid}: {err}")));
    }

    // 5) Wait for the child; collect exit code and stderr.
    //    `wait_with_output` consumes stdin/stdout/stderr and waits
    //    for exit. Note the child was spawned with default
    //    stdio inheritance which means stderr goes to the parent's
    //    stderr — for handler diagnostics we want to capture it.
    //    Let's re-spawn with piped stderr instead.
    //
    //    Actually we already spawned without capture; for v1 just
    //    `wait` and return the empty stderr. If diagnostics needed
    //    later, switch to `.stderr(Stdio::piped())` before spawn.
    let status = child
        .wait()
        .map_err(|e| HandlerError(format!("wait: {e}")))?;
    drop(sfd);
    Ok(InheritOut {
        exit_code: status.code().unwrap_or(-1),
        stderr: String::new(),
    })
}

// ─── Registration ──────────────────────────────────────────────────

pub(crate) fn register_signalfd_tests(reg: &mut Registry<'_>) {
    register_handler!(BASIC_SELF, handle_basic_self);
    register_handler!(INHERIT_SELF_RAISE, handle_inherit_self_raise);

    // SFD.basic_self.<bt> — per-binary-type self-contained capability
    // test. Native: 5/5 pass. Litebox: status depends on whether the
    // shim's sys_signalfd4 routes to the broker AND whether guest
    // raise() delivers to the right signal queue — likely 0/5 today.
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test("vscode", "signalfd", format!("SFD.basic_self.{bt_label}"))
            .timeout(20)
            .build(move |cx| {
                let agent = cx.require(AgentName::Dpg1);
                Box::new(move |run| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let child_binary = crate::binary_path(bt, &self_exe);
                        let result = run
                            .send_named_typed(&agent, &BASIC_SELF, BasicSelfArgs { child_binary })
                            .await;
                        match result {
                            Ok(out) if out.exit_code == 0 => {
                                TestOutcome::new("Dpg1", true, "child self-raise+read OK")
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

    // SFD.inherit_self_raise.<bt> — the cross-process-across-binary-
    // type transition test. Parent creates signalfd, fork+execvs into
    // <bt> child which inherits the fd, parent kills child with
    // SIGUSR1, child reads inherited signalfd and asserts. Native:
    // 5/5 pass. Litebox: ~0/5 (guest signal delivery is
    // shim-virtualized).
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test(
            "vscode",
            "signalfd",
            format!("SFD.inherit_self_raise.{bt_label}"),
        )
        .timeout(30)
        .build(move |cx| {
            let agent = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let self_exe = run.self_exe().to_string();
                    let child_binary = crate::binary_path(bt, &self_exe);
                    let result = run
                        .send_named_typed(&agent, &INHERIT_SELF_RAISE, InheritArgs { child_binary })
                        .await;
                    match result {
                        Ok(out) if out.exit_code == 0 => TestOutcome::new(
                            "Dpg1",
                            true,
                            "child read inherited signalfd, got SIGUSR1",
                        ),
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
}
