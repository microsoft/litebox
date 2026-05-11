// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Eventfd semantics tests for VS Code/Node platform compatibility.
//!
//! Migrated to the typed-handler protocol. Each scenario declares a
//! `HandlerToken<Args, Out>` const next to its handler; tests use
//! `send_named_typed` for type-checked, zero-JSON-drilling call
//! sites.
//!
//! The `cross_agent_wakeup` scenario stays on the legacy protocol
//! because it exercises the agent-internal layer-1 share-registry
//! abstraction (not real cross-process kernel behavior). Reframing
//! as a true `SCM_RIGHTS` layer-2 test is future work.

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::eventfd::EventFd;
use crate::protocol::{Command, Response};
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

// ─── Typed handler tokens ──────────────────────────────────────────

const COUNTER: HandlerToken<(), CounterOut> = HandlerToken::new("eventfd.counter");
const SEMAPHORE: HandlerToken<(), SemaphoreOut> = HandlerToken::new("eventfd.semaphore");
const EPOLLET: HandlerToken<(), EpolletOut> = HandlerToken::new("eventfd.epollet");

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

// ─── Registration ──────────────────────────────────────────────────

pub(crate) fn register_eventfd_tests(reg: &mut Registry<'_>) {
    register_handler!(COUNTER, handle_counter);
    register_handler!(SEMAPHORE, handle_semaphore);
    register_handler!(EPOLLET, handle_epollet);

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

    // Cross-agent share-registry tests stay on the legacy protocol.
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
                let reader_handle = cx.require(reader);
                Box::new(move |run| {
                    let label = label.clone();
                    Box::pin(async move {
                        let result =
                            run_cross_agent_legacy(run, &creator_handle, &reader_handle, reader)
                                .await;
                        match result {
                            Ok(d) => TestOutcome::new(&label, true, d),
                            Err(d) => TestOutcome::new(&label, false, d),
                        }
                    })
                })
            });
    }
}

// ─── Legacy cross-agent driver (kept) ──────────────────────────────

async fn run_cross_agent_legacy(
    run: &mut RunContext<'_>,
    creator: &super::agents::AgentHandle,
    reader: &super::agents::AgentHandle,
    reader_name: AgentName,
) -> Result<String, String> {
    let reader_pid = run.send(reader, Command::GetPid).await;
    if !matches!(reader_pid, Response::Ok { data: Some(_) }) {
        return Err(format!("reader readiness failed: {reader_pid:?}"));
    }
    let id = eventfd_open_legacy(run, creator, 7, "nonblock").await?;
    let share = run
        .send(
            creator,
            Command::EventfdShare {
                id,
                target: reader_name.name().to_string(),
            },
        )
        .await;
    let share_detail = expect_ok_data(share, "share")?;
    expect_eventfd_value(
        run.send(
            creator,
            Command::EventfdReadShared {
                id,
                reader: reader_name.name().to_string(),
            },
        )
        .await,
        7,
        "reader logical read forwarded through creator",
    )?;
    expect_closed(
        run.send(creator, Command::EventfdClose { id }).await,
        "close",
    )?;
    Ok(format!(
        "cross_agent id={id} reader={} forward_via_creator=ok {share_detail}",
        reader_name.name()
    ))
}

async fn eventfd_open_legacy(
    run: &mut RunContext<'_>,
    agent: &super::agents::AgentHandle,
    initval: u64,
    flags: &str,
) -> Result<u64, String> {
    match run
        .send(
            agent,
            Command::EventfdOpen {
                initval,
                flags: flags.to_string(),
            },
        )
        .await
    {
        Response::EventfdHandle { id } => Ok(id),
        other => Err(format!("eventfd_open({initval}, {flags:?}) got {other:?}")),
    }
}

fn expect_closed(resp: Response, label: &str) -> Result<(), String> {
    match resp {
        Response::Closed => Ok(()),
        other => Err(format!("{label}: expected Closed, got {other:?}")),
    }
}

fn expect_ok_data(resp: Response, label: &str) -> Result<String, String> {
    match resp {
        Response::Ok { data: Some(data) } => Ok(data),
        other => Err(format!("{label}: expected Ok data, got {other:?}")),
    }
}

fn expect_eventfd_value(resp: Response, expected: u64, label: &str) -> Result<(), String> {
    match resp {
        Response::EventfdValue { value } if value == expected => Ok(()),
        Response::EventfdValue { value } => Err(format!(
            "{label}: expected EventfdValue {expected}, got {value}"
        )),
        other => Err(format!("{label}: expected EventfdValue, got {other:?}")),
    }
}
