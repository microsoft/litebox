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
}

impl<'a> RunContext<'a> {
    pub(super) fn new(runner: &'a mut TestRunner) -> Self {
        Self { runner }
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
}
