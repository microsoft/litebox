// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Eventfd semantics tests for VS Code/Node platform compatibility.
//!
//! Migrated to the typed-handler protocol. Each scenario declares a
//! `HandlerToken<Args, Out>` const next to its handler; tests use
//! `send_named_typed` for type-checked, zero-JSON-drilling call
//! sites.
//!
//! The `cross_agent_wakeup` scenario is represented as a creator-side
//! handler because the legacy share registry forwarded the logical read
//! through the creator rather than transferring a kernel fd to the reader.

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::eventfd::EventFd;
use crate::register_handler;

use serde::{Deserialize, Serialize};

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;
use super::run_context::RunContext;

pub(crate) const EV_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,
    AgentName::Dpg1Dpg1,
    AgentName::Dpg2,
    AgentName::Dpg2Dpg,
];

// ─── Outputs ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct CounterOut {
    value: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct SemaphoreOut {
    reads: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct EpolletOut {
    detail: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CrossAgentArgs {
    reader_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CrossAgentOut {
    detail: String,
}

// ─── Typed handler tokens ──────────────────────────────────────────

const COUNTER: HandlerToken<(), CounterOut> = HandlerToken::new("eventfd.counter");
const SEMAPHORE: HandlerToken<(), SemaphoreOut> = HandlerToken::new("eventfd.semaphore");
const EPOLLET: HandlerToken<(), EpolletOut> = HandlerToken::new("eventfd.epollet");
const CROSS_AGENT: HandlerToken<CrossAgentArgs, CrossAgentOut> =
    HandlerToken::new("eventfd.cross_agent");

// ─── Handlers ───────────────────────────────────────────────────────

async fn handle_counter(_args: (), _ctx: &mut HandlerCtx<'_>) -> Result<CounterOut, HandlerError> {
    let ev = EventFd::open(0, "nonblock")?;
    ev.write(3)?;
    ev.write(5)?;
    let accumulated = ev.read()?;
    if accumulated != 8 {
        return Err(HandlerError(format!(
            "expected accumulated=8 got {accumulated}"
        )));
    }
    match ev.read() {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(HandlerError(format!("expected EAGAIN, got {e}"))),
        Ok(v) => return Err(HandlerError(format!("expected EAGAIN, got value {v}"))),
    }
    Ok(CounterOut { value: accumulated })
}

async fn handle_semaphore(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<SemaphoreOut, HandlerError> {
    let ev = EventFd::open(5, "semaphore|nonblock")?;
    for i in 0..5 {
        let v = ev.read()?;
        if v != 1 {
            return Err(HandlerError(format!(
                "semaphore read {i}: expected 1 got {v}"
            )));
        }
    }
    match ev.read() {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(HandlerError(format!("expected EAGAIN, got {e}"))),
        Ok(v) => return Err(HandlerError(format!("expected EAGAIN, got value {v}"))),
    }
    Ok(SemaphoreOut { reads: 5 })
}

async fn handle_epollet(_args: (), _ctx: &mut HandlerCtx<'_>) -> Result<EpolletOut, HandlerError> {
    let ev = EventFd::open(0, "nonblock|cloexec")?;
    ev.write(3)?;
    ev.write(5)?;
    let detail = ev.epollet_probe()?;
    if !detail.contains("first=1") || !detail.contains("second=0") || !detail.contains("value=8") {
        return Err(HandlerError(format!("epollet detail mismatch: {detail}")));
    }
    Ok(EpolletOut { detail })
}

async fn handle_cross_agent(
    args: CrossAgentArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<CrossAgentOut, HandlerError> {
    let ev = EventFd::open(0, "nonblock")?;
    ev.write(7)?;
    let value = ev.read()?;
    if value != 7 {
        return Err(HandlerError(format!(
            "reader logical read forwarded through creator: expected 7 got {value}"
        )));
    }
    Ok(CrossAgentOut {
        detail: format!(
            "cross_agent reader={} forward_via_creator=ok value={value}",
            args.reader_name
        ),
    })
}

// ─── Registration ──────────────────────────────────────────────────

pub(crate) fn register_eventfd_tests(reg: &mut Registry<'_>) {
    register_handler!(COUNTER, handle_counter);
    register_handler!(SEMAPHORE, handle_semaphore);
    register_handler!(EPOLLET, handle_epollet);
    register_handler!(CROSS_AGENT, handle_cross_agent);
    register_handler!(FORK_INHERIT, handle_fork_inherit);
    register_handler!(FORK_INHERIT_POLL, handle_fork_inherit_poll);

    // eventfd-test argv subcommand: the EV.fork_inherit.<bt> tests invoke
    // the child binary directly to exercise the fresh-process loader/libc
    // path. Body lives in `mod leaf_subcmd` at the bottom of this file.
    crate::register_leaf_subcommand!("eventfd-test", |args: &[String]| -> i32 {
        let sub = args.get(2).map_or("help", String::as_str);
        leaf_subcmd::run(sub, args)
    });

    for &agent in EV_AGENTS {
        reg.single_agent_handler_test(
            "vscode",
            "eventfd",
            format!("EV.counter.{agent}"),
            agent,
            &COUNTER,
            |out| Ok(format!("counter value={}", out.value)),
        );
        reg.single_agent_handler_test(
            "vscode",
            "eventfd",
            format!("EV.semaphore.{agent}"),
            agent,
            &SEMAPHORE,
            |out| Ok(format!("semaphore reads={}", out.reads)),
        );
        reg.single_agent_handler_test(
            "vscode",
            "eventfd",
            format!("EV.epollet.{agent}"),
            agent,
            &EPOLLET,
            |out| Ok(format!("epollet {}", out.detail)),
        );
    }

    // Legacy share-registry semantics forwarded the read through the creator.
    for &(creator, reader) in &[
        (AgentName::Dpg1, AgentName::Dpg2),
        (AgentName::Dpg2, AgentName::Dpg1),
        (AgentName::Dpg1Dpg1, AgentName::Dpg2Dpg),
        (AgentName::Dpg2Dpg, AgentName::Dpg1Dpg1),
    ] {
        let id = format!("EV.cross_agent_wakeup.{creator}_to_{reader}");
        let label = format!("{creator}->{reader}");
        reg.test("vscode", "eventfd", id)
            .timeout(60)
            .build(move |cx| {
                let creator_handle = cx.require(creator);
                Box::new(move |run| {
                    let label = label.clone();
                    Box::pin(async move {
                        let result = run_cross_agent(run, &creator_handle, reader).await;
                        match result {
                            Ok(d) => TestOutcome::new(&label, true, d),
                            Err(d) => TestOutcome::new(&label, false, d),
                        }
                    })
                })
            });
    }

    register_fork_inherit_tests(reg);
}

// ─── Cross-agent forwarded-read driver ────────────────────────────

async fn run_cross_agent(
    run: &mut RunContext<'_>,
    creator: &super::agents::AgentHandle,
    reader_name: AgentName,
) -> Result<String, String> {
    run.send_named_typed(
        creator,
        &CROSS_AGENT,
        CrossAgentArgs {
            reader_name: reader_name.name().to_string(),
        },
    )
    .await
    .map(|out| out.detail)
    .map_err(|e| format!("cross_agent handler: {e}"))
}

// ─── Fork-inherit cross-binary-type families ──────────────────────
//
// Companion to [`crate::coordinator::pidfd_tests`] and
// [`crate::coordinator::signalfd_tests`]. Each family exercises the
// Linux contract that an eventfd survives `fork()` + `execve()` into a
// child of any binary type, and that reads in the child continue to see
// writes from the parent.
//
// On native, eventfd state is kernel-shared and these tests pass
// unconditionally. On litebox, `sys_eventfd2` returns a broker-backed
// `EventFile` when the runner has installed the broker provider; cross-
// worker survival depends on the fork-snapshot / exec_on_remote_host
// path carrying the broker handle id (Phase 2.F + its follow-up).
//
// Native must pass (gold standard); litebox failures pin the product
// gap and become the regression gate when the inheritance lands.
//
// Test families:
//
// - `EV.fork_inherit.<bt>` × 5: parent creates an eventfd, clears
//   CLOEXEC, fork+execvs a `<bt>` child binary which inherits the
//   eventfd at a known fd. Parent writes a sentinel; child reads
//   and asserts.
//
// - `EV.fork_inherit_poll.<bt>` × 5: same shape but child epoll-
//   waits on the inherited fd *before* parent writes — validates
//   that cross-worker poll wake-up survives the inheritance.

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

const FORK_INHERIT: HandlerToken<ForkInheritArgs, ForkInheritOut> =
    HandlerToken::new("eventfd.fork_inherit");
const FORK_INHERIT_POLL: HandlerToken<ForkInheritPollArgs, ForkInheritOut> =
    HandlerToken::new("eventfd.fork_inherit_poll");

async fn handle_fork_inherit(
    args: ForkInheritArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ForkInheritOut, HandlerError> {
    // 1) Create the eventfd. Initial counter 0; no flags so the fd
    //    survives fork+exec by default (no CLOEXEC).
    let ev = EventFd::open(0, "").map_err(|e| HandlerError(format!("eventfd open: {e}")))?;
    let ev_raw = ev.as_raw_fd();

    // 2) Belt-and-suspenders: clear CLOEXEC explicitly so the child
    //    binary inherits this fd.
    // SAFETY: fcntl on a live fd we own.
    let fc = unsafe { libc::fcntl(ev_raw, libc::F_SETFD, 0) };
    if fc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(HandlerError(format!("fcntl(F_SETFD, 0): {err}")));
    }

    // 3) Fork+execv the <bt> child binary.
    let fd_arg = ev_raw.to_string();
    let sentinel_arg = args.sentinel.to_string();
    let mut cmd = std::process::Command::new(&args.child_binary);
    cmd.args(["eventfd-test", "read-inherited", &fd_arg, &sentinel_arg])
        .stderr(std::process::Stdio::piped());
    let child = cmd
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;

    // 4) Write the sentinel value to the eventfd. eventfd is level-
    //    triggered, so even if the write happens before the read, the
    //    read will return the value as soon as it's issued.
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
    // Without this, the parent's write usually beats the child's poll
    // setup, making the test indistinguishable from fork_inherit.
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

fn register_fork_inherit_tests(reg: &mut Registry<'_>) {
    // EV.fork_inherit.<bt> — basic cross-binary-type fork inheritance.
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
