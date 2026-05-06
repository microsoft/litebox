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

use crate::protocol::{Command, Response};

use super::TestRunner;
use super::agents::{AgentHandle, EphemeralHandle};

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

    /// Spawn a fresh ephemeral child agent that is not part of the
    /// global matrix. Returns a handle distinct from `AgentHandle`
    /// (no global routing applies; the caller owns the lifecycle).
    /// Used by tests like `SK.subtree.*` that build their own
    /// subtree to exercise specific kill/teardown patterns.
    ///
    /// **Currently a placeholder**: ephemeral spawn requires deeper
    /// integration with the existing `spawn_child` plumbing, which
    /// the SK.subtree tests use directly today. Wired up in a
    /// follow-up; for now `RunContext` exposes the same shape but
    /// suite migrations that need ephemeral spawn keep using the
    /// existing internal helpers temporarily.
    pub async fn spawn_ephemeral_agent(&mut self, _label: &str) -> EphemeralHandle {
        unimplemented!(
            "ephemeral agent spawn through RunContext is reserved for the SK.subtree migration; \
             until then those tests use coordinator-internal helpers"
        );
    }
}
