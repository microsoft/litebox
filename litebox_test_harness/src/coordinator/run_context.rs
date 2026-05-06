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
use super::agents::AgentHandle;

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
        if handle.name().name() == "init" {
            return self.runner.exec_local(&cmd).await;
        }
        self.runner.send(handle.name().name(), cmd).await
    }

    /// Send a `Forward { target: handle, inner: cmd }` to the
    /// coordinator routing layer. Equivalent to constructing the
    /// `Forward` command by hand, but without exposing a public
    /// constructor that takes a string target.
    pub async fn forward(&mut self, handle: &AgentHandle, inner: Command) -> Response {
        self.runner
            .send(
                handle.name().name(),
                Command::Forward {
                    target: handle.name().name().to_string(),
                    inner: Box::new(inner),
                },
            )
            .await
    }

    /// Read a file from the coordinator's local filesystem (the
    /// `init` target).
    pub async fn fs_read(&self, path: &str) -> Response {
        self.runner
            .exec_local(&Command::FsRead {
                path: path.to_string(),
            })
            .await
    }

    /// Write a file to the coordinator's local filesystem (the
    /// `init` target).
    pub async fn fs_write(&self, path: &str, data: &str) -> Response {
        self.runner
            .exec_local(&Command::FsWrite {
                path: path.to_string(),
                data: data.to_string(),
            })
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
    /// tracked (e.g., already SIGKILLed by the runner's poisoning
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
        let mut child = match self.runner.children.remove(wire) {
            Some(c) => c,
            None => return Err(Duration::ZERO),
        };
        self.runner.spawned_agents.remove(wire);
        let _ = child.process.start_kill();
        let start = std::time::Instant::now();
        match tokio::time::timeout(budget, child.process.wait()).await {
            Ok(_) => Ok(start.elapsed()),
            Err(_) => Err(start.elapsed()),
        }
    }
}
