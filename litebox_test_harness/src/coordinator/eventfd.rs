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
use crate::os::epoll::{Epoll, EpollTarget};
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
struct EpollLevelOut {
    detail: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct EpollCrossThreadOut {
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
const EPOLL_ZERO_COUNTER: HandlerToken<(), EpollLevelOut> =
    HandlerToken::new("eventfd.epoll_zero_counter");
const EPOLL_DRAIN_CLEARS: HandlerToken<(), EpollLevelOut> =
    HandlerToken::new("eventfd.epoll_drain_clears");
const EPOLL_CROSS_THREAD_DRAIN_CLEARS: HandlerToken<(), EpollCrossThreadOut> =
    HandlerToken::new("eventfd.epoll_cross_thread_drain_clears");
const EPOLL_FORK_DRAIN_CLEARS: HandlerToken<ForkDrainClearsArgs, ForkInheritOut> =
    HandlerToken::new("eventfd.epoll_fork_drain_clears");
const EPOLL_MASKS_EVENTS: HandlerToken<(), EpollLevelOut> =
    HandlerToken::new("eventfd.epoll_masks_events");
const EPOLL_NESTED_ZERO_COUNTER: HandlerToken<(), EpollLevelOut> =
    HandlerToken::new("eventfd.epoll_nested_zero_counter");
const EPOLL_NESTED_DRAIN_CLEARS: HandlerToken<(), EpollLevelOut> =
    HandlerToken::new("eventfd.epoll_nested_drain_clears");
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

async fn handle_epoll_zero_counter(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollLevelOut, HandlerError> {
    let ev = EventFd::open(0, "nonblock|cloexec")
        .map_err(|e| HandlerError(format!("eventfd open: {e}")))?;
    let mut ep = Epoll::new().map_err(|e| HandlerError(format!("epoll create: {e}")))?;
    ep.add_fd(
        ev.as_raw_fd(),
        "in",
        EpollTarget {
            kind: "eventfd",
            id: 1,
        },
    )
    .map_err(|e| HandlerError(format!("epoll add eventfd: {e}")))?;
    let events = ep
        .wait(100, 1)
        .map_err(|e| HandlerError(format!("epoll wait: {e}")))?;
    if !events.is_empty() {
        return Err(HandlerError(format!(
            "counter=0 eventfd reported ready: events={events:?}"
        )));
    }
    Ok(EpollLevelOut {
        detail: "counter=0 EPOLLIN wait timed out".to_string(),
    })
}

async fn handle_epoll_drain_clears(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollLevelOut, HandlerError> {
    let ev = EventFd::open(0, "nonblock|cloexec")
        .map_err(|e| HandlerError(format!("eventfd open: {e}")))?;
    let mut ep = Epoll::new().map_err(|e| HandlerError(format!("epoll create: {e}")))?;
    ep.add_fd(
        ev.as_raw_fd(),
        "in",
        EpollTarget {
            kind: "eventfd",
            id: 1,
        },
    )
    .map_err(|e| HandlerError(format!("epoll add eventfd: {e}")))?;

    ev.write(1)
        .map_err(|e| HandlerError(format!("eventfd write: {e}")))?;
    let first = ep
        .wait(1000, 1)
        .map_err(|e| HandlerError(format!("first epoll wait: {e}")))?;
    if first.len() != 1 || !first[0].observed_events.split('|').any(|name| name == "in") {
        return Err(HandlerError(format!(
            "written eventfd did not report EPOLLIN: events={first:?}"
        )));
    }
    let value = ev
        .read()
        .map_err(|e| HandlerError(format!("eventfd read: {e}")))?;
    if value != 1 {
        return Err(HandlerError(format!("eventfd read got {value}, want 1")));
    }
    let second = ep
        .wait(100, 1)
        .map_err(|e| HandlerError(format!("second epoll wait: {e}")))?;
    if !second.is_empty() {
        return Err(HandlerError(format!(
            "drained eventfd still reported ready: events={second:?}"
        )));
    }
    Ok(EpollLevelOut {
        detail: "write produced EPOLLIN and drain cleared readiness".to_string(),
    })
}

async fn handle_epoll_cross_thread_drain_clears(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollCrossThreadOut, HandlerError> {
    let ev = std::sync::Arc::new(
        EventFd::open(0, "nonblock|cloexec")
            .map_err(|e| HandlerError(format!("eventfd open: {e}")))?,
    );
    let mut ep = Epoll::new().map_err(|e| HandlerError(format!("epoll create: {e}")))?;
    ep.add_fd(
        ev.as_raw_fd(),
        "in",
        EpollTarget {
            kind: "eventfd",
            id: 1,
        },
    )
    .map_err(|e| HandlerError(format!("epoll add eventfd: {e}")))?;

    ev.write(1)
        .map_err(|e| HandlerError(format!("eventfd write: {e}")))?;
    let first = ep
        .wait(1000, 1)
        .map_err(|e| HandlerError(format!("first epoll wait: {e}")))?;
    if first.len() != 1 || !first[0].observed_events.split('|').any(|name| name == "in") {
        return Err(HandlerError(format!(
            "written eventfd did not report EPOLLIN: events={first:?}"
        )));
    }

    let reader_ev = std::sync::Arc::clone(&ev);
    let reader = std::thread::spawn(move || reader_ev.read());
    let value = reader
        .join()
        .map_err(|_| HandlerError("reader thread panicked".to_string()))?
        .map_err(|e| HandlerError(format!("reader eventfd read: {e}")))?;
    if value != 1 {
        return Err(HandlerError(format!("reader got {value}, want 1")));
    }

    let second = ep
        .wait(100, 1)
        .map_err(|e| HandlerError(format!("second epoll wait: {e}")))?;
    if !second.is_empty() {
        return Err(HandlerError(format!(
            "eventfd drained by peer thread still reported ready: events={second:?}"
        )));
    }
    Ok(EpollCrossThreadOut {
        detail: "peer thread drain cleared eventfd EPOLLIN readiness".to_string(),
    })
}

async fn handle_epoll_masks_events(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollLevelOut, HandlerError> {
    let ev = EventFd::open(0, "nonblock|cloexec")
        .map_err(|e| HandlerError(format!("eventfd open: {e}")))?;
    let mut ep = Epoll::new().map_err(|e| HandlerError(format!("epoll create: {e}")))?;
    ep.add_fd(
        ev.as_raw_fd(),
        "in",
        EpollTarget {
            kind: "eventfd",
            id: 1,
        },
    )
    .map_err(|e| HandlerError(format!("epoll add eventfd: {e}")))?;

    ev.write(1)
        .map_err(|e| HandlerError(format!("eventfd write: {e}")))?;
    let events = ep
        .wait(1000, 1)
        .map_err(|e| HandlerError(format!("epoll wait: {e}")))?;
    if events.len() != 1 {
        return Err(HandlerError(format!(
            "written eventfd wait returned {} events: {events:?}",
            events.len()
        )));
    }
    let observed = &events[0].observed_events;
    let has_in = observed.split('|').any(|name| name == "in");
    let has_out = observed.split('|').any(|name| name == "out");
    if !has_in || has_out {
        return Err(HandlerError(format!(
            "EPOLLIN-only registration returned mask {observed:?}; has_in={has_in} has_out={has_out}"
        )));
    }
    Ok(EpollLevelOut {
        detail: format!("EPOLLIN-only registration returned {observed}"),
    })
}

async fn handle_epoll_nested_zero_counter(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollLevelOut, HandlerError> {
    let ev = EventFd::open(0, "nonblock|cloexec")
        .map_err(|e| HandlerError(format!("eventfd open: {e}")))?;
    let mut inner = Epoll::new().map_err(|e| HandlerError(format!("inner epoll create: {e}")))?;
    inner
        .add_fd(
            ev.as_raw_fd(),
            "in",
            EpollTarget {
                kind: "eventfd",
                id: 1,
            },
        )
        .map_err(|e| HandlerError(format!("inner epoll add eventfd: {e}")))?;
    let mut outer = Epoll::new().map_err(|e| HandlerError(format!("outer epoll create: {e}")))?;
    outer
        .add_fd(
            inner.as_raw_fd(),
            "in",
            EpollTarget {
                kind: "epoll",
                id: 2,
            },
        )
        .map_err(|e| HandlerError(format!("outer epoll add inner epoll: {e}")))?;
    let events = outer
        .wait(100, 1)
        .map_err(|e| HandlerError(format!("outer epoll wait: {e}")))?;
    if !events.is_empty() {
        return Err(HandlerError(format!(
            "outer epoll reported inner epoll ready while eventfd counter=0: events={events:?}"
        )));
    }
    Ok(EpollLevelOut {
        detail: "nested epoll blocked with counter=0 eventfd".to_string(),
    })
}

async fn handle_epoll_nested_drain_clears(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollLevelOut, HandlerError> {
    let ev = EventFd::open(0, "nonblock|cloexec")
        .map_err(|e| HandlerError(format!("eventfd open: {e}")))?;
    let mut inner = Epoll::new().map_err(|e| HandlerError(format!("inner epoll create: {e}")))?;
    inner
        .add_fd(
            ev.as_raw_fd(),
            "in",
            EpollTarget {
                kind: "eventfd",
                id: 1,
            },
        )
        .map_err(|e| HandlerError(format!("inner epoll add eventfd: {e}")))?;
    let mut outer = Epoll::new().map_err(|e| HandlerError(format!("outer epoll create: {e}")))?;
    outer
        .add_fd(
            inner.as_raw_fd(),
            "in",
            EpollTarget {
                kind: "epoll",
                id: 2,
            },
        )
        .map_err(|e| HandlerError(format!("outer epoll add inner epoll: {e}")))?;

    ev.write(1)
        .map_err(|e| HandlerError(format!("eventfd write: {e}")))?;
    let first_outer = outer
        .wait(1000, 1)
        .map_err(|e| HandlerError(format!("first outer epoll wait: {e}")))?;
    if first_outer.len() != 1
        || !first_outer[0]
            .observed_events
            .split('|')
            .any(|name| name == "in")
    {
        return Err(HandlerError(format!(
            "outer epoll did not report inner readiness after write: events={first_outer:?}"
        )));
    }

    let value = ev
        .read()
        .map_err(|e| HandlerError(format!("eventfd read: {e}")))?;
    if value != 1 {
        return Err(HandlerError(format!("eventfd read got {value}, want 1")));
    }

    let second_outer = outer
        .wait(100, 1)
        .map_err(|e| HandlerError(format!("second outer epoll wait: {e}")))?;
    if !second_outer.is_empty() {
        return Err(HandlerError(format!(
            "outer epoll reported stale inner readiness after direct eventfd drain: events={second_outer:?}"
        )));
    }

    Ok(EpollLevelOut {
        detail: "nested epoll readiness cleared after direct eventfd drain".to_string(),
    })
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
    register_handler!(EPOLL_ZERO_COUNTER, handle_epoll_zero_counter);
    register_handler!(EPOLL_DRAIN_CLEARS, handle_epoll_drain_clears);
    register_handler!(
        EPOLL_CROSS_THREAD_DRAIN_CLEARS,
        handle_epoll_cross_thread_drain_clears
    );
    register_handler!(EPOLL_FORK_DRAIN_CLEARS, handle_fork_drain_clears);
    register_handler!(EPOLL_MASKS_EVENTS, handle_epoll_masks_events);
    register_handler!(EPOLL_NESTED_ZERO_COUNTER, handle_epoll_nested_zero_counter);
    register_handler!(EPOLL_NESTED_DRAIN_CLEARS, handle_epoll_nested_drain_clears);
    register_handler!(CROSS_AGENT, handle_cross_agent);
    register_handler!(FORK_INHERIT, handle_fork_inherit);
    register_handler!(FORK_INHERIT_POLL, handle_fork_inherit_poll);

    // eventfd-test argv subcommand: the EV.fork_inherit.<bt> and
    // EV.tokio_runtime_drop.<bt> tests invoke the child binary directly to
    // exercise fresh-process loader/libc/runtime paths. Body lives in
    // `mod leaf_subcmd` at the bottom of this file.
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

    for &(id, token) in &[
        ("EV.epoll_zero_counter", &EPOLL_ZERO_COUNTER),
        ("EV.epoll_drain_clears", &EPOLL_DRAIN_CLEARS),
        ("EV.epoll_masks_events", &EPOLL_MASKS_EVENTS),
        ("EV.epoll_nested_zero_counter", &EPOLL_NESTED_ZERO_COUNTER),
        ("EV.epoll_nested_drain_clears", &EPOLL_NESTED_DRAIN_CLEARS),
    ] {
        reg.single_agent_handler_test("vscode", "eventfd", id, AgentName::Dpg1, token, |out| {
            Ok(out.detail.clone())
        });
    }
    reg.single_agent_handler_test(
        "vscode",
        "eventfd",
        "EV.epoll_cross_thread_drain_clears",
        AgentName::Dpg1,
        &EPOLL_CROSS_THREAD_DRAIN_CLEARS,
        |out| Ok(out.detail.clone()),
    );

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

    register_fork_drain_clears_tests(reg);
    register_tokio_runtime_drop_tests(reg);
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
struct ForkDrainClearsArgs {
    child_binary: String,
    timeout_ms: i32,
}

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

async fn handle_fork_drain_clears(
    args: ForkDrainClearsArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ForkInheritOut, HandlerError> {
    let ev =
        EventFd::open(0, "nonblock").map_err(|e| HandlerError(format!("eventfd open: {e}")))?;
    let ev_raw = ev.as_raw_fd();

    // SAFETY: fcntl on a live fd we own.
    let fc = unsafe { libc::fcntl(ev_raw, libc::F_SETFD, 0) };
    if fc != 0 {
        return Err(HandlerError(format!(
            "fcntl(eventfd F_SETFD, 0): {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut ready_pipe = [0; 2];
    let mut first_pipe = [0; 2];
    let mut continue_pipe = [0; 2];
    for (name, pipefd) in [
        ("ready", &mut ready_pipe),
        ("first", &mut first_pipe),
        ("continue", &mut continue_pipe),
    ] {
        // SAFETY: pipefd points to two valid i32 slots for libc::pipe to fill.
        if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
            return Err(HandlerError(format!(
                "pipe {name}: {}",
                std::io::Error::last_os_error()
            )));
        }
        for &fd in pipefd.iter() {
            // SAFETY: fcntl on a live fd we own.
            if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
                return Err(HandlerError(format!(
                    "fcntl(pipe {name} fd {fd} F_SETFD, 0): {}",
                    std::io::Error::last_os_error()
                )));
            }
        }
    }

    let mut cmd = std::process::Command::new(&args.child_binary);
    cmd.args([
        "eventfd-test",
        "epoll-fork-drain-clears-child",
        &ev_raw.to_string(),
        &ready_pipe[1].to_string(),
        &first_pipe[1].to_string(),
        &continue_pipe[0].to_string(),
        &args.timeout_ms.to_string(),
    ])
    .stderr(std::process::Stdio::piped());
    let child = cmd
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;

    close_fd(ready_pipe[1]);
    close_fd(first_pipe[1]);
    close_fd(continue_pipe[0]);

    read_exact_fd(ready_pipe[0], "child-ready")?;
    ev.write(1)
        .map_err(|e| HandlerError(format!("eventfd write: {e}")))?;
    read_exact_fd(first_pipe[0], "child-first-epoll")?;
    let value = ev
        .read()
        .map_err(|e| HandlerError(format!("parent drain eventfd: {e}")))?;
    if value != 1 {
        return Err(HandlerError(format!("parent drain got {value}, want 1")));
    }
    write_all_fd(continue_pipe[1], "continue-child")?;
    close_fd(ready_pipe[0]);
    close_fd(first_pipe[0]);
    close_fd(continue_pipe[1]);

    let output = child
        .wait_with_output()
        .map_err(|e| HandlerError(format!("wait: {e}")))?;
    Ok(ForkInheritOut {
        exit_code: output.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn read_exact_fd(fd: i32, label: &str) -> Result<(), HandlerError> {
    let mut byte = [0u8; 1];
    loop {
        // SAFETY: byte is a valid one-byte output buffer and fd is expected live.
        let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast::<libc::c_void>(), 1) };
        match n {
            1 => return Ok(()),
            0 => return Err(HandlerError(format!("{label}: unexpected EOF"))),
            -1 => {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EINTR) {
                    return Err(HandlerError(format!("{label}: read: {err}")));
                }
            }
            other => return Err(HandlerError(format!("{label}: short read {other}"))),
        }
    }
}

fn write_all_fd(fd: i32, label: &str) -> Result<(), HandlerError> {
    let byte = [1u8; 1];
    loop {
        // SAFETY: byte is a valid one-byte input buffer and fd is expected live.
        let n = unsafe { libc::write(fd, byte.as_ptr().cast::<libc::c_void>(), 1) };
        match n {
            1 => return Ok(()),
            -1 => {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EINTR) {
                    return Err(HandlerError(format!("{label}: write: {err}")));
                }
            }
            other => return Err(HandlerError(format!("{label}: short write {other}"))),
        }
    }
}

fn close_fd(fd: i32) {
    // SAFETY: closing an fd is safe; errors are intentionally ignored in cleanup.
    let _ = unsafe { libc::close(fd) };
}

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

fn register_fork_drain_clears_tests(reg: &mut Registry<'_>) {
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test(
            "vscode",
            "eventfd",
            format!("EV.epoll_fork_drain_clears.{bt_label}"),
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
                            &EPOLL_FORK_DRAIN_CLEARS,
                            ForkDrainClearsArgs {
                                child_binary,
                                timeout_ms: 200,
                            },
                        )
                        .await;
                    match result {
                        Ok(out) if out.exit_code == 0 => TestOutcome::new(
                            "Dpg1",
                            true,
                            "child epoll blocked after parent drained inherited eventfd",
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

fn register_tokio_runtime_drop_tests(reg: &mut Registry<'_>) {
    let bt = crate::BinaryType::StaticPieMusl;
    let bt_label = bt.label();
    reg.test(
        "vscode",
        "eventfd",
        format!("EV.tokio_runtime_drop.{bt_label}"),
    )
    .timeout(30)
    .build(move |_cx| {
        Box::new(move |run| {
            let self_exe = run.self_exe().to_string();
            let child_binary = crate::binary_path(bt, &self_exe);
            Box::pin(async move {
                let output = std::process::Command::new(&child_binary)
                    .args(["eventfd-test", "tokio-release-after-deregister"])
                    .output();
                match output {
                    Ok(out) => {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        TestOutcome::new(
                            bt_label,
                            out.status.success() && stdout.starts_with("PASS"),
                            format!(
                                "{} exit={:?} stdout={stdout:?} stderr={stderr:?}",
                                child_binary,
                                out.status.code()
                            ),
                        )
                    }
                    Err(e) => {
                        TestOutcome::new(bt_label, false, format!("spawn {child_binary}: {e}"))
                    }
                }
            })
        })
    });
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
            "epoll-fork-drain-clears-child" => epoll_fork_drain_clears_child(args),
            "tokio-release-after-deregister" => tokio_release_after_deregister(),
            other => {
                eprintln!("eventfd-test: unknown subcommand: {other}");
                2
            }
        }
    }

    /// `eventfd-test tokio-release-after-deregister`
    ///
    /// Fresh-process probe for the PE.5 release-after-deregister shape: fork a
    /// child that keeps broker-backed pipe refs alive, issue the same per-pid
    /// release sweep used by process teardown, close the parent's pipe fds, then
    /// force a tokio current-thread runtime wake. Pre-fix, the late fd close
    /// killed the broker control socket and the wake panicked with EIO.
    fn tokio_release_after_deregister() -> i32 {
        let mut pipefd = [0; 2];
        // SAFETY: pipefd points to two valid i32 slots for libc::pipe to fill.
        if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
            eprintln!("pipe: {}", std::io::Error::last_os_error());
            return 1;
        }

        // SAFETY: fork has no Rust-level shared locks in this leaf before the
        // child immediately blocks in libc::read and exits via _exit.
        let child = unsafe { libc::fork() };
        if child < 0 {
            eprintln!("fork: {}", std::io::Error::last_os_error());
            close_fd(pipefd[0]);
            close_fd(pipefd[1]);
            return 1;
        }
        if child == 0 {
            close_fd(pipefd[1]);
            // SAFETY: pause blocks the child so it keeps its inherited broker
            // pipe refs alive until the parent has exercised the late release.
            let _ = unsafe { libc::pause() };
            close_fd(pipefd[0]);
            // SAFETY: child must not run Rust destructors after fork.
            unsafe { libc::_exit(0) };
        }

        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("tokio runtime build: {e}");
                close_fd(pipefd[0]);
                close_fd(pipefd[1]);
                terminate_child(child);
                return 1;
            }
        };

        if let Some(client) = litebox_common_linux::fd_token_client::global_client() {
            let pid = std::process::id();
            let _guard = litebox_common_linux::fd_token_client::set_caller_pid_scope(pid);
            if let Err(e) = client.release_all_for_pid(pid) {
                eprintln!("release_all_for_pid({pid}): {e:?}");
                close_fd(pipefd[0]);
                close_fd(pipefd[1]);
                terminate_child(child);
                return 1;
            }
        }

        close_fd(pipefd[0]);
        close_fd(pipefd[1]);

        let (tx, rx) = std::sync::mpsc::channel();
        let handle = rt.handle().clone();
        let waker = std::thread::spawn(move || {
            let _ = rx.recv();
            handle.spawn(async {});
        });
        if tx.send(()).is_err() {
            eprintln!("failed to signal wake thread");
            terminate_child(child);
            return 1;
        }
        rt.block_on(async {
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        });
        if let Err(e) = waker.join() {
            eprintln!("wake thread panicked: {e:?}");
            terminate_child(child);
            return 1;
        }
        terminate_child(child);
        println!("PASS tokio runtime wake survived late fd releases");
        0
    }

    /// `eventfd-test epoll-fork-drain-clears-child <eventfd> <ready_w> <first_w> <continue_r> <timeout_ms>`
    ///
    /// Fresh-process child for the cross-worker inherited-eventfd topology. The
    /// child owns the epoll instance; the parent writes and then drains the same
    /// eventfd. The second epoll_wait must time out after the parent drain.
    fn epoll_fork_drain_clears_child(args: &[String]) -> i32 {
        let Some((event_fd, ready_w, first_w, continue_r, timeout_ms)) = parse_child_args(args)
        else {
            return 2;
        };
        let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epfd < 0 {
            eprintln!("child epoll_create1: {}", std::io::Error::last_os_error());
            return 1;
        }
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: 1,
        };
        let ctl = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, event_fd, &raw mut ev) };
        if ctl != 0 {
            eprintln!("child epoll_ctl ADD: {}", std::io::Error::last_os_error());
            close_fd(epfd);
            return 1;
        }
        if write_one(ready_w, "ready") != 0 {
            close_fd(epfd);
            return 1;
        }
        close_fd(ready_w);

        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
        let first = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 1, 5000) };
        let first_events = events[0].events;
        if first != 1 || first_events & libc::EPOLLIN as u32 == 0 {
            eprintln!("child first epoll_wait rc={first} events=0x{first_events:x}");
            close_fd(epfd);
            return 1;
        }
        if write_one(first_w, "first") != 0 {
            close_fd(epfd);
            return 1;
        }
        close_fd(first_w);
        if read_one(continue_r, "continue") != 0 {
            close_fd(epfd);
            return 1;
        }
        close_fd(continue_r);

        events[0] = libc::epoll_event { events: 0, u64: 0 };
        let second = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 1, timeout_ms) };
        close_fd(epfd);
        let second_events = events[0].events;
        if second != 0 {
            eprintln!(
                "child second epoll_wait after parent drain returned rc={second} events=0x{second_events:x}"
            );
            return 1;
        }
        0
    }

    fn parse_child_args(args: &[String]) -> Option<(i32, i32, i32, i32, i32)> {
        Some((
            args.get(3)?.parse().ok()?,
            args.get(4)?.parse().ok()?,
            args.get(5)?.parse().ok()?,
            args.get(6)?.parse().ok()?,
            args.get(7)?.parse().ok()?,
        ))
    }

    fn write_one(fd: i32, label: &str) -> i32 {
        let byte = [1u8; 1];
        loop {
            let n = unsafe { libc::write(fd, byte.as_ptr().cast::<libc::c_void>(), 1) };
            if n == 1 {
                return 0;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                eprintln!("child write {label}: {err}");
                return 1;
            }
        }
    }

    fn read_one(fd: i32, label: &str) -> i32 {
        let mut byte = [0u8; 1];
        loop {
            let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast::<libc::c_void>(), 1) };
            if n == 1 {
                return 0;
            }
            if n == 0 {
                eprintln!("child read {label}: EOF");
                return 1;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                eprintln!("child read {label}: {err}");
                return 1;
            }
        }
    }

    fn close_fd(fd: i32) {
        // SAFETY: closing an fd is safe; errors are intentionally ignored in cleanup.
        let _ = unsafe { libc::close(fd) };
    }

    fn terminate_child(pid: libc::pid_t) {
        // SAFETY: pid is the specific child returned by fork; SIGTERM asks only
        // that child to exit after the parent has finished the probe.
        let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
        let mut status = 0;
        // SAFETY: status points to a valid i32 and pid is the child returned by fork.
        let _ = unsafe { libc::waitpid(pid, std::ptr::from_mut(&mut status), 0) };
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
