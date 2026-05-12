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
