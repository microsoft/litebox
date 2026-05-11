// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Multi-agent scenario driver for the handler-refactor protocol.
//!
//! For Class 1 tests (state-with-rendezvous), the coord can't just
//! issue independent `Command::Run` calls because handlers on
//! different agents need to synchronize mid-flight via
//! `ctx.checkpoint(tag)`. This module owns the per-test driver:
//!
//! 1. The caller builds the invocation via `RunContext::run_multi()`
//!    + `.assign(...)` + `.phase(tag)`.
//! 2. `.run()` lifts each participating agent's pipes out of
//!    `runner.children`, spawns one driver task per agent.
//! 3. Each driver task writes `Command::Run` then reads its agent's
//!    response stream. It forwards `Response::Checkpoint` events to
//!    a central coordinator task; the coordinator tracks per-tag
//!    arrival sets and writes `Command::Resume` back when a phase
//!    quora.
//! 4. When an agent emits `Response::Result`, the driver task ends
//!    and returns the agent's pipe + outcome.
//! 5. Pipes are restored into `runner.children` so subsequent tests
//!    on the same runner aren't blocked.

use std::collections::{HashMap, HashSet};

use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout};

use crate::protocol::{Command, Response};

use super::Child;
use super::TestRunner;
use super::agents::AgentHandle;

/// Per-agent assignment in a multi-run invocation.
struct PendingAssignment {
    wire: String,
    handler: String,
    args: Value,
}

/// Declared phase rendezvous. `members = None` means "all assigned
/// agents," resolved at `.run()` time.
struct PhaseSpec {
    tag: String,
    members: Option<Vec<String>>,
}

/// Per-agent result after the run completes.
#[derive(Debug, Clone)]
#[allow(dead_code)] // `error` is read via Debug derive.
pub struct AgentRunResult {
    pub agent: String,
    pub ok: bool,
    pub data: Value,
    pub error: Option<String>,
}

/// Builder for a multi-agent invocation. Returned by
/// `RunContext::run_multi`.
pub struct Invocation<'r, 'a> {
    runner: &'r mut TestRunner,
    assignments: Vec<PendingAssignment>,
    phase_specs: Vec<PhaseSpec>,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'r> Invocation<'r, '_> {
    pub(super) fn new(runner: &'r mut TestRunner) -> Self {
        Self {
            runner,
            assignments: Vec::new(),
            phase_specs: Vec::new(),
            _marker: std::marker::PhantomData,
        }
    }

    /// Add an agent + handler + args to this invocation.
    pub fn assign(mut self, handle: &AgentHandle, handler: &str, args: Value) -> Self {
        let wire = handle.name().name().to_string();
        self.runner.contacted_agents.insert(wire.clone());
        self.assignments.push(PendingAssignment {
            wire,
            handler: handler.to_string(),
            args,
        });
        self
    }

    /// Declare a phase rendezvous tag. Membership defaults to all
    /// assigned agents.
    pub fn phase(mut self, tag: &str) -> Self {
        self.phase_specs.push(PhaseSpec {
            tag: tag.to_string(),
            members: None,
        });
        self
    }

    /// Declare a phase with explicit member subset.
    #[allow(dead_code)] // Public API; not yet used by any test.
    pub fn phase_with_members(mut self, tag: &str, members: &[&AgentHandle]) -> Self {
        self.phase_specs.push(PhaseSpec {
            tag: tag.to_string(),
            members: Some(
                members
                    .iter()
                    .map(|h| h.name().name().to_string())
                    .collect(),
            ),
        });
        self
    }

    /// Drive the invocation to completion. Pipes are lifted out of
    /// `runner.children`, the driver tasks run, pipes are restored.
    pub async fn run(self) -> InvocationResults {
        run_invocation(self).await
    }
}

/// Aggregate results of an invocation.
#[derive(Debug)]
pub struct InvocationResults {
    by_agent: HashMap<String, AgentRunResult>,
    top_level_error: Option<String>,
}

impl InvocationResults {
    /// Top-level driver error (undeclared phase tag, setup failure)
    /// if any.
    #[must_use]
    pub fn top_level_error(&self) -> Option<&str> {
        self.top_level_error.as_deref()
    }

    /// Untyped result for an agent.
    #[must_use]
    pub fn raw(&self, handle: &AgentHandle) -> Option<&AgentRunResult> {
        self.by_agent.get(handle.name().name())
    }

    /// Typed result for an agent — deserialize `data` into `O`.
    ///
    /// # Errors
    /// Returns Err on missing result, agent-side failure, or
    /// deserialization failure.
    #[allow(dead_code)] // Public API; not yet used by any test.
    pub fn typed<O>(&self, handle: &AgentHandle) -> Result<O, String>
    where
        O: DeserializeOwned,
    {
        let wire = handle.name().name();
        let r = self
            .by_agent
            .get(wire)
            .ok_or_else(|| format!("no result for agent {wire}"))?;
        if !r.ok {
            return Err(r.error.clone().unwrap_or_else(|| "handler failed".into()));
        }
        serde_json::from_value(r.data.clone()).map_err(|e| format!("typed deserialize: {e}"))
    }
}

// ─── Internals ──────────────────────────────────────────────────────

struct AgentPipe {
    agent_name: String,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

enum DriveEvent {
    Checkpoint { agent: String, tag: String },
    Result(AgentRunResult),
    DriverError { agent: String, error: String },
}

#[allow(clippy::too_many_lines)]
async fn run_invocation(inv: Invocation<'_, '_>) -> InvocationResults {
    use tokio::sync::mpsc;

    let Invocation {
        runner,
        assignments,
        phase_specs,
        ..
    } = inv;

    let assigned_wires: Vec<String> = assignments.iter().map(|a| a.wire.clone()).collect();

    // Lift pipes out of runner.children.
    let mut pipes: Vec<AgentPipe> = Vec::new();
    let mut processes: HashMap<String, tokio::process::Child> = HashMap::new();
    let mut setup_error: Option<String> = None;

    for a in &assignments {
        let Some(child) = runner.children.remove(&a.wire) else {
            setup_error = Some(format!("agent {} not in runner.children", a.wire));
            break;
        };
        pipes.push(AgentPipe {
            agent_name: a.wire.clone(),
            stdin: child.stdin,
            stdout: child.stdout,
        });
        processes.insert(a.wire.clone(), child.process);
    }

    if let Some(err) = setup_error {
        // Restore whatever we took before bailing.
        for pipe in pipes {
            if let Some(process) = processes.remove(&pipe.agent_name) {
                runner.children.insert(
                    pipe.agent_name.clone(),
                    Child {
                        stdin: pipe.stdin,
                        stdout: pipe.stdout,
                        process,
                    },
                );
            }
        }
        return InvocationResults {
            by_agent: HashMap::new(),
            top_level_error: Some(err),
        };
    }

    // Spawn one driver task per agent.
    let (event_tx, mut event_rx) = mpsc::channel::<DriveEvent>(32);
    let mut resume_txs: HashMap<String, mpsc::Sender<String>> = HashMap::new();
    let mut driver_handles: Vec<tokio::task::JoinHandle<AgentPipe>> = Vec::new();

    for (pipe, assignment) in pipes.into_iter().zip(assignments.iter()) {
        let (resume_tx, resume_rx) = mpsc::channel::<String>(8);
        resume_txs.insert(pipe.agent_name.clone(), resume_tx);
        let handle = tokio::spawn(drive_agent(
            pipe,
            assignment.handler.clone(),
            assignment.args.clone(),
            resume_rx,
            event_tx.clone(),
        ));
        driver_handles.push(handle);
    }
    drop(event_tx);

    // Resolve phase membership.
    let phases: Vec<(String, HashSet<String>)> = phase_specs
        .into_iter()
        .map(|p| {
            let members: HashSet<String> = p
                .members
                .unwrap_or_else(|| assigned_wires.clone())
                .into_iter()
                .collect();
            (p.tag, members)
        })
        .collect();

    let mut arrivals: HashMap<String, HashSet<String>> = HashMap::new();
    let mut results: Vec<AgentRunResult> = Vec::new();
    let mut top_level_error: Option<String> = None;

    while let Some(ev) = event_rx.recv().await {
        match ev {
            DriveEvent::Checkpoint { agent, tag } => {
                let entry = arrivals.entry(tag.clone()).or_default();
                entry.insert(agent.clone());
                let mut matched_phase = false;
                for (phase_tag, members) in &phases {
                    if phase_tag != &tag {
                        continue;
                    }
                    matched_phase = true;
                    if members.is_subset(entry) {
                        for member in members {
                            if let Some(tx) = resume_txs.get(member) {
                                let _ = tx.send(tag.clone()).await;
                            }
                        }
                    }
                }
                if !matched_phase && top_level_error.is_none() {
                    top_level_error = Some(format!("undeclared phase tag '{tag}' from {agent}"));
                }
            }
            DriveEvent::Result(r) => results.push(r),
            DriveEvent::DriverError { agent, error } => {
                results.push(AgentRunResult {
                    agent,
                    ok: false,
                    data: Value::Null,
                    error: Some(error),
                });
            }
        }
    }

    // Reap drivers + restore pipes.
    let mut restored: HashMap<String, AgentPipe> = HashMap::new();
    for h in driver_handles {
        if let Ok(pipe) = h.await {
            restored.insert(pipe.agent_name.clone(), pipe);
        }
    }
    for (wire, pipe) in restored {
        if let Some(process) = processes.remove(&wire) {
            runner.children.insert(
                wire,
                Child {
                    stdin: pipe.stdin,
                    stdout: pipe.stdout,
                    process,
                },
            );
        }
    }

    let by_agent = results.into_iter().map(|r| (r.agent.clone(), r)).collect();
    InvocationResults {
        by_agent,
        top_level_error,
    }
}

async fn drive_agent(
    mut pipe: AgentPipe,
    handler: String,
    args: Value,
    mut resume_rx: tokio::sync::mpsc::Receiver<String>,
    event_tx: tokio::sync::mpsc::Sender<DriveEvent>,
) -> AgentPipe {
    // Kickoff.
    let cmd = Command::Run { handler, args };
    if let Err(e) = write_command(&mut pipe.stdin, &cmd).await {
        let _ = event_tx
            .send(DriveEvent::DriverError {
                agent: pipe.agent_name.clone(),
                error: format!("kickoff: {e}"),
            })
            .await;
        return pipe;
    }

    let mut line = String::new();
    loop {
        line.clear();
        tokio::select! {
            biased;

            maybe_tag = resume_rx.recv() => {
                let Some(tag) = maybe_tag else { break; };
                if let Err(e) = write_command(&mut pipe.stdin, &Command::Resume { tag }).await {
                    let _ = event_tx.send(DriveEvent::DriverError {
                        agent: pipe.agent_name.clone(),
                        error: format!("resume write: {e}"),
                    }).await;
                    return pipe;
                }
            }

            read = pipe.stdout.read_line(&mut line) => {
                match read {
                    Ok(0) => {
                        let _ = event_tx.send(DriveEvent::DriverError {
                            agent: pipe.agent_name.clone(),
                            error: "agent stdout EOF before result".into(),
                        }).await;
                        return pipe;
                    }
                    Err(e) => {
                        let _ = event_tx.send(DriveEvent::DriverError {
                            agent: pipe.agent_name.clone(),
                            error: format!("stdout read: {e}"),
                        }).await;
                        return pipe;
                    }
                    Ok(_) => {}
                }
                let trimmed = line.trim();
                if trimmed.is_empty() { continue; }
                let resp: Response = match serde_json::from_str(trimmed) {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = event_tx.send(DriveEvent::DriverError {
                            agent: pipe.agent_name.clone(),
                            error: format!("response parse: {e}; line={trimmed}"),
                        }).await;
                        return pipe;
                    }
                };
                match resp {
                    Response::Checkpoint { tag } => {
                        let _ = event_tx.send(DriveEvent::Checkpoint {
                            agent: pipe.agent_name.clone(),
                            tag,
                        }).await;
                    }
                    Response::Result { ok, data, error } => {
                        let _ = event_tx.send(DriveEvent::Result(AgentRunResult {
                            agent: pipe.agent_name.clone(),
                            ok, data, error,
                        })).await;
                        return pipe;
                    }
                    other => {
                        let _ = event_tx.send(DriveEvent::DriverError {
                            agent: pipe.agent_name.clone(),
                            error: format!("unexpected response during Run: {other:?}"),
                        }).await;
                        return pipe;
                    }
                }
            }
        }
    }
    pipe
}

async fn write_command(stdin: &mut ChildStdin, cmd: &Command) -> Result<(), String> {
    let json = serde_json::to_string(cmd).map_err(|e| format!("serialize: {e}"))?;
    stdin
        .write_all(format!("{json}\n").as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    stdin.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(())
}
