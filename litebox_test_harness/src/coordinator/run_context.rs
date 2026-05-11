// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Run-time context for a registered test.
//!
//! `RunContext` is what the closure registered via the typed
//! [`crate::coordinator::registry::Registry`] API receives. Its only
//! way to identify an agent is through an [`AgentHandle`] obtained at
//! registration time via `RegistrationContext::require`. There is no
//! `&str`-based send overload, no `name()` getter on `AgentHandle`,
//! and no public method to construct an `AgentHandle` from outside
//! the registration framework.
//!
//! Internally, `RunContext` is a thin wrapper around the
//! coordinator's existing [`super::TestRunner`]; the
//! `AgentHandle -> &'static str` mapping is private to this module
//! and is the only place the wire-level name is materialized.

use std::time::Duration;

use crate::protocol::{Command, Response};

use super::TestRunner;
use super::agents::{AgentHandle, EphemeralHandle, SpawnKind};

/// Run-time access for a registered test. Borrows the underlying
/// [`TestRunner`] for the duration of one test's execution.
///
/// All commands routed through agent handles use the wire-level name
/// derived from the handle's typed identifier; tests cannot bypass
/// this by passing a string because no string-typed `send` is exposed.
pub struct RunContext<'a> {
    runner: &'a mut TestRunner,
    /// Direct top-level pipes that currently have a `Command::Run`
    /// in flight (handler running on the agent or one of its
    /// descendants, awaiting a terminal `Response::Result`). Used
    /// by `run_write` to refuse a second concurrent Run on the same
    /// direct pipe — that would corrupt the wire because Forward and
    /// the agent's main loop can't multiplex two in-flight handlers
    /// on one stdin/stdout pair.
    in_flight_directs: std::collections::HashSet<String>,
}

impl<'a> RunContext<'a> {
    pub(super) fn new(runner: &'a mut TestRunner) -> Self {
        Self {
            runner,
            in_flight_directs: std::collections::HashSet::new(),
        }
    }

    /// Path to the self-executable that test code can pass to its
    /// `Exec` commands as the binary to spawn.
    pub fn self_exe(&self) -> &str {
        &self.runner.self_exe
    }

    /// Send a protocol command to the agent identified by `handle`,
    /// returning its response.
    pub async fn send(&mut self, handle: &AgentHandle, cmd: Command) -> Response {
        let wire = handle.name().name();
        // Track contact for the over-spawn validator. Init bypasses
        // `runner.send()` (it goes straight to `exec_local`), so we
        // record it explicitly here.
        self.runner.contacted_agents.insert(wire.to_string());
        if wire == "init" {
            return self.runner.exec_local(&cmd).await;
        }
        self.runner.send(wire, cmd).await
    }

    /// Spawn the ephemeral child agent identified by `handle` under
    /// its declared parent. Sends `Spawn` / `SpawnRemote` / `Fork` to
    /// the parent depending on the handle's [`SpawnKind`]. Returns
    /// the parent's response (typically `Ok` with a count).
    pub async fn spawn_ephemeral(&mut self, handle: &EphemeralHandle) -> Response {
        let parent = handle.parent().name();
        let label = handle.label().to_string();
        let cmd = match handle.kind() {
            SpawnKind::Pie => Command::Spawn {
                children: vec![label],
            },
            SpawnKind::NonPie => Command::SpawnRemote {
                children: vec![label],
            },
            SpawnKind::Fork {
                binary,
                inherit_listen_ports,
            } => Command::Fork {
                name: label,
                binary: (*binary).to_string(),
                inherit_listen_ports: inherit_listen_ports.clone(),
            },
        };
        self.runner.send(parent, cmd).await
    }

    /// Send `inner` to the ephemeral child agent identified by
    /// `handle` by wrapping it as
    /// `Forward { target: label, inner }` to the parent. The
    /// wire-level label is private to the handle; tests cannot
    /// construct a `Forward` to an unrelated string target.
    pub async fn forward(&mut self, handle: &EphemeralHandle, inner: Command) -> Response {
        let parent = handle.parent().name();
        let target = handle.label().to_string();
        self.runner
            .send(
                parent,
                Command::Forward {
                    target,
                    inner: Box::new(inner),
                },
            )
            .await
    }

    /// SIGKILL the process backing `handle` and time how long the
    /// subsequent `wait()` takes. Returns `Ok(elapsed)` if the wait
    /// completes within `budget`, or `Err(elapsed_at_timeout)` if the
    /// wait was abandoned at the budget. Removes the agent from the
    /// runner's tracked set so future routing through it returns a
    /// clear error rather than blocking.
    ///
    /// Returns `Err(Duration::ZERO)` if the agent is no longer
    /// tracked (e.g., already `SIGKILLed` by the runner's poisoning
    /// machinery after a prior command timed out). The test is
    /// expected to surface that as a setup failure rather than
    /// silently treating it as a kill-success.
    ///
    /// Used by `SK.subtree.*` tests to assert that SIGKILL of an
    /// agent with non-PIE descendants completes promptly.
    pub async fn kill_and_wait(
        &mut self,
        handle: &AgentHandle,
        budget: Duration,
    ) -> Result<Duration, Duration> {
        let wire = handle.name().name();
        // Pull the Child out of the runner so we own its lifecycle.
        // Note: leave `spawned_agents` intact — it's a historical
        // record of which agents `spawn_tree` brought up, used by
        // `validate_lazy_matrix`. The test killing an agent doesn't
        // un-spawn it for accounting purposes.
        let Some(mut child) = self.runner.children.remove(wire) else {
            return Err(Duration::ZERO);
        };
        let _ = child.process.start_kill();
        let start = std::time::Instant::now();
        match tokio::time::timeout(budget, child.process.wait()).await {
            Ok(_) => Ok(start.elapsed()),
            Err(_) => Err(start.elapsed()),
        }
    }

    /// Invoke a registered handler on the agent and return its
    /// `Result` data (untyped). Single round-trip — no checkpoint
    /// routing. Use [`Self::run_multi`] for multi-agent tests that
    /// need cross-agent rendezvous via `ctx.checkpoint(tag)`.
    ///
    /// # Errors
    /// Returns Err if the agent returns a non-`Result` response or a
    /// `Result { ok: false }`.
    pub async fn send_named(
        &mut self,
        handle: &AgentHandle,
        handler: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let cmd = Command::Run {
            handler: handler.to_string(),
            args,
        };
        match self.send(handle, cmd).await {
            Response::Result {
                ok: true,
                data,
                error: _,
            } => Ok(data),
            Response::Result {
                ok: false,
                data: _,
                error,
            } => Err(error.unwrap_or_else(|| "handler failed".into())),
            other => Err(format!("expected Result, got {other:?}")),
        }
    }

    /// Write `Command::Run { handler, args }` to `handle`'s pipe
    /// without waiting for a response. The command is routed through
    /// `route` + `wrap_forwards` to reach descendants via their
    /// parent's pipe.
    ///
    /// Pair with `run_read` to receive the response stream. Use this
    /// when you need to interleave writes across multiple agents
    /// (e.g. for a Class 1 rendezvous where two agents arrive at the
    /// same checkpoint before either resumes).
    ///
    /// # Errors
    /// - Returns Err if another `Run` is already in flight on the
    ///   same direct top-level pipe. Two concurrent Runs sharing a
    ///   pipe would deadlock (the agent's stdin/stdout can carry only
    ///   one active conversation at a time, and Forward arms can't
    ///   multiplex).
    /// - Returns Err on a routing or pipe-write failure.
    pub async fn run_write(
        &mut self,
        handle: &AgentHandle,
        handler: &str,
        args: serde_json::Value,
    ) -> Result<(), String> {
        let wire = handle.name().name();
        let (direct, _rest) = super::route(wire);
        if self.in_flight_directs.contains(direct) {
            return Err(format!(
                "another Run is already in flight on direct pipe '{direct}'; \
                 cannot start a second Run on {wire} until the in-flight one \
                 returns Result (or pick a target whose route() direct differs)"
            ));
        }
        let cmd = Command::Run {
            handler: handler.to_string(),
            args,
        };
        self.write_routed(handle, cmd).await?;
        self.in_flight_directs.insert(direct.to_string());
        Ok(())
    }

    /// Write `Command::Resume { tag }` to `handle`'s pipe without
    /// waiting for a response. Used after the coord observes a
    /// `Response::Checkpoint` and decides to release the handler.
    ///
    /// # Errors
    /// Returns Err on routing or pipe-write failure.
    pub async fn run_resume(&mut self, handle: &AgentHandle, tag: &str) -> Result<(), String> {
        let cmd = Command::Resume {
            tag: tag.to_string(),
        };
        self.write_routed(handle, cmd).await
    }

    /// Read one `Response` from `handle`'s pipe. Pair with
    /// `run_write` / `run_resume`. The response may be
    /// `Response::Checkpoint` (handler is paused) or
    /// `Response::Result` (handler is done) or an error.
    ///
    /// When `Response::Result` is returned (or an `Error` that
    /// indicates the conversation ended), the direct pipe is cleared
    /// from the in-flight set so a subsequent `run_write` to a
    /// target with the same direct pipe is allowed.
    pub async fn run_read(&mut self, handle: &AgentHandle) -> Response {
        use tokio::io::AsyncBufReadExt;
        let wire = handle.name().name();
        self.runner.contacted_agents.insert(wire.to_string());
        let (direct, _rest) = super::route(wire);
        let resp = {
            let Some(child) = self.runner.children.get_mut(direct) else {
                return Response::Error {
                    error: format!("no child {direct}"),
                };
            };
            let mut line = String::new();
            match tokio::time::timeout(
                std::time::Duration::from_secs(15),
                child.stdout.read_line(&mut line),
            )
            .await
            {
                Ok(Ok(0)) => Response::Error {
                    error: "EOF on agent stdout".into(),
                },
                Ok(Ok(_)) => match serde_json::from_str(line.trim()) {
                    Ok(r) => r,
                    Err(e) => Response::Error {
                        error: format!("response parse: {e}; line={}", line.trim()),
                    },
                },
                Ok(Err(e)) => Response::Error {
                    error: format!("read: {e}"),
                },
                Err(_) => Response::Error {
                    error: "timeout reading from agent".into(),
                },
            }
        };
        // Any non-Checkpoint response terminates the in-flight Run on
        // this direct pipe — Result is the happy path; Error means the
        // conversation is broken and we shouldn't keep blocking new
        // Runs that target the same direct pipe.
        if !matches!(&resp, Response::Checkpoint { .. }) {
            self.in_flight_directs.remove(direct);
        }
        resp
    }

    /// Common helper: route `cmd` to `handle` (Forward-wrapping for
    /// descendants), write to the appropriate direct-child pipe,
    /// flush, return without reading any response.
    async fn write_routed(&mut self, handle: &AgentHandle, cmd: Command) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        let wire = handle.name().name();
        self.runner.contacted_agents.insert(wire.to_string());
        let (direct, rest) = super::route(wire);
        let actual_cmd = super::wrap_forwards(rest, cmd);
        let Some(child) = self.runner.children.get_mut(direct) else {
            return Err(format!("no child {direct}"));
        };
        let json = serde_json::to_string(&actual_cmd).map_err(|e| e.to_string())?;
        child
            .stdin
            .write_all(format!("{json}\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        child.stdin.flush().await.map_err(|e| e.to_string())?;
        Ok(())
    }
}
