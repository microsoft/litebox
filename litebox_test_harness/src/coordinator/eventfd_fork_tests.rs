// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Handler-native broker-eventfd cross-binary-type fork inheritance tests.
//!
//! Companion to [`crate::coordinator::pidfd_tests`] and
//! [`crate::coordinator::signalfd_tests`]. Each family exercises the
//! Linux contract that a file descriptor with shared state survives
//! `fork()` + `execve()` into a child of any binary type, and that
//! reads in the child continue to see writes from the parent.
//!
//! On native, eventfd state is kernel-shared and these tests pass
//! unconditionally. On litebox, `sys_eventfd2` returns a
//! broker-backed `EventFile` when the runner has installed the
//! broker provider (Phase B), so cross-worker survival depends on
//! the fork-snapshot carrying the broker handle id. Today that
//! handle id is *not* carried, so the child receives an invalid fd
//! and these tests fail with a "child read 0 / poll timeout"
//! signature — Phase 2.F's generic broker-handle inheritance is the
//! fix.
//!
//! Native must pass (gold standard); litebox failures pin the
//! product gap and become the regression gate when Phase 2.F lands.
//!
//! # Test families
//!
//! - `EV.fork_inherit.<bt>` × 5: parent creates an eventfd, clears
//!   CLOEXEC, fork+execvs into a `<bt>` child binary which inherits
//!   the eventfd at a known fd. Parent writes a sentinel value;
//!   child reads and asserts.
//!
//! - `EV.fork_inherit_poll.<bt>` × 5: same shape but child epoll-
//!   waits on the inherited fd *before* parent writes — validates
//!   that cross-worker poll wake-up survives the fork-snapshot. The
//!   broker's `SubscriptionList` must re-arm for the child's
//!   subscription after fork+exec inheritance.

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::eventfd::EventFd;
use crate::register_handler;

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;

// ─── Outputs ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct ForkInheritArgs {
    child_binary: String,
    /// Sentinel value parent writes to the eventfd after exec.
    sentinel: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct ForkInheritPollArgs {
    child_binary: String,
    sentinel: u64,
    /// Child's epoll_wait timeout in ms.
    timeout_ms: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct ForkInheritOut {
    exit_code: i32,
    stderr: String,
}

// ─── Typed handler tokens ──────────────────────────────────────────

const FORK_INHERIT: HandlerToken<ForkInheritArgs, ForkInheritOut> =
    HandlerToken::new("eventfd.fork_inherit");
const FORK_INHERIT_POLL: HandlerToken<ForkInheritPollArgs, ForkInheritOut> =
    HandlerToken::new("eventfd.fork_inherit_poll");

// ─── Handlers ───────────────────────────────────────────────────────

async fn handle_fork_inherit(
    args: ForkInheritArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ForkInheritOut, HandlerError> {
    // 1) Create the eventfd. Initial counter 0; no flags so the fd
    //    survives fork+exec by default (no CLOEXEC).
    let ev = EventFd::open(0, "").map_err(|e| HandlerError(format!("eventfd open: {e}")))?;
    let ev_raw = ev.as_raw_fd();

    // 2) Belt-and-suspenders: clear CLOEXEC explicitly so the child
    //    binary inherits this fd. (No flags above already means
    //    CLOEXEC isn't set, but kernel default for libc::eventfd
    //    leaves this clear too.)
    // SAFETY: fcntl on a live fd we own.
    let fc = unsafe { libc::fcntl(ev_raw, libc::F_SETFD, 0) };
    if fc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(HandlerError(format!("fcntl(F_SETFD, 0): {err}")));
    }

    // 3) Fork+execv the <bt> child binary. The child uses
    //    `eventfd-test read-inherited <fd> <expected>` to assert
    //    that reading from the inherited fd returns `sentinel`.
    let fd_arg = ev_raw.to_string();
    let sentinel_arg = args.sentinel.to_string();
    let mut cmd = std::process::Command::new(&args.child_binary);
    cmd.args(["eventfd-test", "read-inherited", &fd_arg, &sentinel_arg])
        .stderr(std::process::Stdio::piped());
    let child = cmd
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;

    // 4) Write the sentinel value to the eventfd. The child is
    //    racing to call read(); eventfd is level-triggered, so even
    //    if the write happens before the read, the read will return
    //    the value as soon as it's issued.
    ev.write(args.sentinel)
        .map_err(|e| HandlerError(format!("ev.write: {e}")))?;

    // 5) Wait for the child to complete and collect stderr.
    let output = child
        .wait_with_output()
        .map_err(|e| HandlerError(format!("wait: {e}")))?;
    Ok(ForkInheritOut {
        exit_code: output.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

async fn handle_fork_inherit_poll(
    args: ForkInheritPollArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ForkInheritOut, HandlerError> {
    // Same setup as fork_inherit, but the child polls first.
    let ev = EventFd::open(0, "").map_err(|e| HandlerError(format!("eventfd open: {e}")))?;
    let ev_raw = ev.as_raw_fd();
    // SAFETY: fcntl on a live fd we own.
    let fc = unsafe { libc::fcntl(ev_raw, libc::F_SETFD, 0) };
    if fc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(HandlerError(format!("fcntl(F_SETFD, 0): {err}")));
    }

    let fd_arg = ev_raw.to_string();
    let timeout_arg = args.timeout_ms.to_string();
    let sentinel_arg = args.sentinel.to_string();
    let mut cmd = std::process::Command::new(&args.child_binary);
    cmd.args([
        "eventfd-test",
        "read-inherited-poll",
        &fd_arg,
        &timeout_arg,
        &sentinel_arg,
    ])
    .stderr(std::process::Stdio::piped());
    let child = cmd
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;

    // Brief sleep so the child reaches epoll_wait before we write.
    // Without this, the parent's write usually beats the child's
    // poll setup, making the test indistinguishable from
    // fork_inherit (level-triggered reads return immediately). The
    // delay is conservative — child reaches poll within a few ms.
    std::thread::sleep(std::time::Duration::from_millis(100));

    ev.write(args.sentinel)
        .map_err(|e| HandlerError(format!("ev.write: {e}")))?;

    let output = child
        .wait_with_output()
        .map_err(|e| HandlerError(format!("wait: {e}")))?;
    Ok(ForkInheritOut {
        exit_code: output.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

// ─── Registration ──────────────────────────────────────────────────

pub(crate) fn register_eventfd_fork_tests(reg: &mut Registry<'_>) {
    register_handler!(FORK_INHERIT, handle_fork_inherit);
    register_handler!(FORK_INHERIT_POLL, handle_fork_inherit_poll);

    // eventfd-test argv subcommand: the EV.fork_inherit.<bt> tests
    // invoke the child binary directly to exercise the fresh-process
    // loader/libc path. Body lives in `mod leaf_subcmd` at the
    // bottom of this file.
    crate::register_leaf_subcommand!("eventfd-test", |args: &[String]| -> i32 {
        let sub = args.get(2).map_or("help", String::as_str);
        leaf_subcmd::run(sub, args)
    });

    // EV.fork_inherit.<bt> — basic cross-binary-type fork inheritance.
    // Parent writes sentinel; child reads from inherited eventfd.
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test("vscode", "eventfd", format!("EV.fork_inherit.{bt_label}"))
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
                                &FORK_INHERIT,
                                ForkInheritArgs {
                                    child_binary,
                                    sentinel: 0xA5A5_A5A5_A5A5_A5A5,
                                },
                            )
                            .await;
                        match result {
                            Ok(out) if out.exit_code == 0 => TestOutcome::new(
                                "Dpg1",
                                true,
                                "child read inherited eventfd, got sentinel",
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

    // EV.fork_inherit_poll.<bt> — cross-worker poll wake-up survives
    // fork-snapshot inheritance.
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test(
            "vscode",
            "eventfd",
            format!("EV.fork_inherit_poll.{bt_label}"),
        )
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
                            &FORK_INHERIT_POLL,
                            ForkInheritPollArgs {
                                child_binary,
                                sentinel: 0x5A5A_5A5A_5A5A_5A5A,
                                timeout_ms: 5000,
                            },
                        )
                        .await;
                    match result {
                        Ok(out) if out.exit_code == 0 => TestOutcome::new(
                            "Dpg1",
                            true,
                            "child polled+read inherited eventfd, got sentinel",
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

mod leaf_subcmd {
    /// Dispatcher for `eventfd-test <subcommand>` argv invocations.
    /// Called from `register_leaf_subcommand!("eventfd-test", ...)`.
    pub(super) fn run(sub: &str, args: &[String]) -> i32 {
        match sub {
            "read-inherited" => read_inherited(args),
            "read-inherited-poll" => read_inherited_poll(args),
            other => {
                eprintln!("eventfd-test: unknown subcommand: {other}");
                2
            }
        }
    }

    /// `eventfd-test read-inherited <fd> <expected>`
    ///
    /// Reads one u64 from the inherited eventfd. Asserts the value
    /// matches `expected` (decimal). Exits 0 on match, 1 on
    /// mismatch / I/O error, 2 on argument-parse error.
    fn read_inherited(args: &[String]) -> i32 {
        let fd: i32 = match args.get(3).and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => {
                eprintln!("eventfd-test read-inherited: bad fd arg");
                return 2;
            }
        };
        let expected: u64 = match args.get(4).and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => {
                eprintln!("eventfd-test read-inherited: bad expected arg");
                return 2;
            }
        };
        let mut value: u64 = 0;
        // SAFETY: value is a live 8-byte buffer; fd was inherited.
        let n = unsafe { libc::read(fd, std::ptr::from_mut(&mut value).cast::<libc::c_void>(), 8) };
        if n != 8 {
            eprintln!(
                "eventfd-test read-inherited: short read: n={n} ({})",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        if value != expected {
            eprintln!(
                "eventfd-test read-inherited: value mismatch: got {value:#x} expected {expected:#x}"
            );
            return 1;
        }
        0
    }

    /// `eventfd-test read-inherited-poll <fd> <timeout_ms> <expected>`
    ///
    /// `poll`s the inherited eventfd for POLLIN with the given
    /// timeout, then reads. Asserts the value matches `expected`.
    /// Exits 0 on POLLIN fired + value matches, 1 on timeout /
    /// mismatch / I/O error, 2 on argument-parse error.
    fn read_inherited_poll(args: &[String]) -> i32 {
        let fd: i32 = match args.get(3).and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => {
                eprintln!("eventfd-test read-inherited-poll: bad fd arg");
                return 2;
            }
        };
        let timeout_ms: i32 = match args.get(4).and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => {
                eprintln!("eventfd-test read-inherited-poll: bad timeout_ms arg");
                return 2;
            }
        };
        let expected: u64 = match args.get(5).and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => {
                eprintln!("eventfd-test read-inherited-poll: bad expected arg");
                return 2;
            }
        };
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a live initialised pollfd; len 1 matches.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        if rc <= 0 || pfd.revents & libc::POLLIN == 0 {
            eprintln!(
                "eventfd-test read-inherited-poll: poll rc={} revents={}",
                rc, pfd.revents
            );
            return 1;
        }
        let mut value: u64 = 0;
        // SAFETY: value is a live 8-byte buffer.
        let n = unsafe { libc::read(fd, std::ptr::from_mut(&mut value).cast::<libc::c_void>(), 8) };
        if n != 8 {
            eprintln!(
                "eventfd-test read-inherited-poll: short read: n={n} ({})",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        if value != expected {
            eprintln!(
                "eventfd-test read-inherited-poll: value mismatch: got {value:#x} expected {expected:#x}"
            );
            return 1;
        }
        0
    }
}
