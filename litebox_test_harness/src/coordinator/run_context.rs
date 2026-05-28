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
    /// returning its raw `Response`. **FRAMEWORK-ONLY**: test code in
    /// `coordinator/<family>.rs` should *not* call this. Use
    /// [`Self::send_named_typed`] (handler dispatch) or
    /// [`Self::rendezvous_pair`] (multi-agent rendezvous) instead.
    ///
    /// This entry point exists so the framework can issue the small
    /// set of process-lifecycle primitives (`Spawn`, `SpawnRemote`,
    /// `Fork`, `Forward`, `Run`, `Resume`, `Exec`, `ExecReady`,
    /// `Exit`) directly. See `litebox_test_harness/CLAUDE.md`
    /// "Handler Model" for the invariant.
    pub async fn send(&mut self, handle: &AgentHandle, cmd: Command) -> Response {
        let wire = handle.name().name();
        self.runner.contacted_agents.insert(wire.to_string());
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

    /// Token-typed variant of [`Self::send_named`]. The token's
    /// `A` / `O` types let the framework serialize `args` and
    /// deserialize the result, so the test author never sees
    /// `serde_json::Value` at the boundary.
    ///
    /// # Errors
    /// Returns Err on agent-side failure, serialization failure, or
    /// any non-`Result` response.
    pub async fn send_named_typed<A, O>(
        &mut self,
        handle: &AgentHandle,
        token: &crate::handlers::HandlerToken<A, O>,
        args: A,
    ) -> Result<O, String>
    where
        A: serde::Serialize,
        O: serde::de::DeserializeOwned,
    {
        let args_value = serde_json::to_value(&args).map_err(|e| format!("args serialize: {e}"))?;
        let data = self.send_named(handle, token.name(), args_value).await?;
        serde_json::from_value(data).map_err(|e| format!("typed deserialize: {e}"))
    }

    /// Assert that values computed by the same typed handler on two agents are equal.
    ///
    /// # Errors
    /// Returns a clear mismatch or handler-invocation error.
    pub async fn assert_eq_across_agents<A, T>(
        &mut self,
        agent_a: &AgentHandle,
        agent_b: &AgentHandle,
        label: &str,
        token: &crate::handlers::HandlerToken<A, T>,
        args_a: A,
        args_b: A,
    ) -> Result<(), String>
    where
        A: serde::Serialize,
        T: serde::Serialize + serde::de::DeserializeOwned + Eq + std::fmt::Debug,
    {
        let val_a = self.send_named_typed(agent_a, token, args_a).await?;
        let val_b = self.send_named_typed(agent_b, token, args_b).await?;
        if val_a == val_b {
            Ok(())
        } else {
            Err(format!(
                "assert_eq_across_agents({label}): {}={val_a:?} but {}={val_b:?}",
                agent_a.name(),
                agent_b.name()
            ))
        }
    }

    /// Send a typed handler request and convert any infrastructure
    /// error (timeout, malformed JSON, missing handler, ...) into a
    /// `Response::Error`. The handler's own `Result<Response, _>` is
    /// returned as-is on success.
    ///
    /// Equivalent to `send_named_typed(...).await.unwrap_or_else(|e| Response::Error { error: e })`,
    /// but avoids the boilerplate at every call site.
    pub async fn typed_or_error<A>(
        &mut self,
        handle: &AgentHandle,
        token: &'static crate::handlers::HandlerToken<A, Response>,
        args: A,
    ) -> Response
    where
        A: serde::Serialize + Send,
    {
        self.send_named_typed(handle, token, args)
            .await
            .unwrap_or_else(|e| Response::Error { error: e })
    }

    /// Spawn an ephemeral leaf and start a typed handler on it without
    /// waiting for the response. Pair with `run_leaf_read_checkpoint`,
    /// `run_leaf_resume`, and `run_leaf_read_result` for leaf handlers
    /// that need coordinator-driven rendezvous.
    pub async fn run_leaf_write<A, O>(
        &mut self,
        leaf: &EphemeralHandle,
        token: &crate::handlers::HandlerToken<A, O>,
        args: A,
    ) -> Result<(), String>
    where
        A: serde::Serialize,
    {
        let spawn_resp = self.spawn_ephemeral(leaf).await;
        if !matches!(&spawn_resp, Response::Ok { .. }) {
            return Err(format!("spawn_ephemeral: {spawn_resp:?}"));
        }
        let args_value = serde_json::to_value(&args).map_err(|e| format!("args serialize: {e}"))?;
        self.write_ephemeral(
            leaf,
            Command::Run {
                handler: token.name().to_string(),
                args: args_value,
            },
            true,
        )
        .await
    }

    /// Resume a checkpointed typed handler running on an ephemeral leaf.
    pub async fn run_leaf_resume(
        &mut self,
        leaf: &EphemeralHandle,
        tag: &str,
    ) -> Result<(), String> {
        self.write_ephemeral(
            leaf,
            Command::Resume {
                tag: tag.to_string(),
            },
            false,
        )
        .await
    }

    /// Send `Exit` to an ephemeral leaf.
    pub async fn run_leaf_exit(&mut self, leaf: &EphemeralHandle) -> Result<(), String> {
        self.write_ephemeral(leaf, Command::Exit, false).await
    }

    /// Read and validate a checkpoint from an ephemeral leaf handler.
    pub async fn run_leaf_read_checkpoint(
        &mut self,
        leaf: &EphemeralHandle,
        expected_tag: &str,
    ) -> Result<(), String> {
        match self.read_ephemeral(leaf).await {
            Response::Checkpoint { tag } if tag == expected_tag => Ok(()),
            Response::Checkpoint { tag } => Err(format!(
                "expected Checkpoint({expected_tag}), got Checkpoint({tag})"
            )),
            other => Err(format!("expected Checkpoint, got {other:?}")),
        }
    }

    /// Read and decode the terminal `Result` from an ephemeral leaf handler.
    pub async fn run_leaf_read_result<A, O>(
        &mut self,
        leaf: &EphemeralHandle,
        _token: &crate::handlers::HandlerToken<A, O>,
    ) -> Result<O, String>
    where
        O: serde::de::DeserializeOwned,
    {
        match self.read_ephemeral(leaf).await {
            Response::Result {
                ok: true,
                data,
                error: _,
            } => serde_json::from_value(data).map_err(|e| format!("typed deserialize: {e}")),
            Response::Result {
                ok: false,
                data: _,
                error,
            } => Err(error.unwrap_or_else(|| "handler failed".into())),
            other => Err(format!("expected Result, got {other:?}")),
        }
    }

    /// Spawn an ephemeral leaf agent (per `leaf.kind()`), invoke one
    /// typed handler on it via `Command::Run`, then send `Command::Exit`
    /// to terminate it. Returns the handler's typed `Out`.
    ///
    /// This is the **default way to run leaf programs** in the new
    /// model: instead of `EXEC_BIN { argv: [bt_binary, "name", …] }`
    /// (which fork+execs into a fresh argv-dispatched main()), the
    /// test does `cx.declare_ephemeral(parent, "Leaf…",
    /// SpawnKind::Fork{binary=bt, …})` and `run_leaf(&leaf, &TOKEN,
    /// args).await`. The fork+exec round-trip across binary types
    /// is preserved (`Command::Fork{binary}` is the same kernel
    /// mechanism), but the leaf body lives as a registered handler
    /// in the family's `coordinator/<family>.rs`, co-located with
    /// the tests that drive it.
    ///
    /// Use [`Self::spawn_ephemeral`] + [`Self::forward`] directly only
    /// when you need finer control (e.g., multiple handler calls on
    /// one leaf, or rendezvous between two leaves). For the common
    /// one-shot leaf-handler pattern, prefer this helper.
    ///
    /// On error (spawn failure, handler error, deserialization failure),
    /// still attempts a best-effort `Command::Exit` so a half-spawned
    /// leaf doesn't linger across the rest of the test run.
    ///
    /// # Errors
    /// Returns Err on spawn failure, handler-side failure, serialization
    /// failure, or any non-`Result` response from the leaf.
    #[allow(dead_code)] // called by family register_* fns as B-phases land
    pub async fn run_leaf<A, O>(
        &mut self,
        leaf: &EphemeralHandle,
        token: &crate::handlers::HandlerToken<A, O>,
        args: A,
    ) -> Result<O, String>
    where
        A: serde::Serialize,
        O: serde::de::DeserializeOwned,
    {
        // Step 1: fork+exec the leaf agent under its declared parent.
        let spawn_resp = self.spawn_ephemeral(leaf).await;
        if !matches!(&spawn_resp, Response::Ok { .. }) {
            return Err(format!("spawn_ephemeral: {spawn_resp:?}"));
        }

        // Step 2: invoke the handler via Forward routing through the
        // parent. (Direct send_named_typed would require an
        // AgentHandle, which EphemeralHandle isn't. Forward+Run is the
        // canonical leaf-dispatch path.)
        let args_value = serde_json::to_value(&args).map_err(|e| format!("args serialize: {e}"))?;
        let run_resp = self
            .forward(
                leaf,
                Command::Run {
                    handler: token.name().to_string(),
                    args: args_value,
                },
            )
            .await;

        // Step 3: parse the response, capture any error.
        let result: Result<O, String> = match run_resp {
            Response::Result {
                ok: true,
                data,
                error: _,
            } => serde_json::from_value(data).map_err(|e| format!("typed deserialize: {e}")),
            Response::Result {
                ok: false,
                data: _,
                error,
            } => Err(error.unwrap_or_else(|| "handler failed".into())),
            other => Err(format!("expected Result, got {other:?}")),
        };

        // Step 4: best-effort Exit, regardless of handler outcome.
        let _ = self.forward(leaf, Command::Exit).await;

        result
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

    /// Token-typed variant of [`Self::run_write`]. Same routing and
    /// in-flight rules; framework serializes `args` from `A`.
    ///
    /// # Errors
    /// Same as [`Self::run_write`], plus serialization errors.
    pub async fn run_write_typed<A, O>(
        &mut self,
        handle: &AgentHandle,
        token: &crate::handlers::HandlerToken<A, O>,
        args: A,
    ) -> Result<(), String>
    where
        A: serde::Serialize,
    {
        let args_value = serde_json::to_value(&args).map_err(|e| format!("args serialize: {e}"))?;
        self.run_write(handle, token.name(), args_value).await
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

    /// Read one response from `handle`'s pipe and expect it to be
    /// `Response::Checkpoint` with `expected_tag`. Convenience for
    /// the rendezvous pattern.
    ///
    /// # Errors
    /// Returns Err if the response is not a Checkpoint or if the tag
    /// doesn't match.
    pub async fn run_read_checkpoint(
        &mut self,
        handle: &AgentHandle,
        expected_tag: &str,
    ) -> Result<(), String> {
        match self.run_read(handle).await {
            Response::Checkpoint { tag } if tag == expected_tag => Ok(()),
            Response::Checkpoint { tag } => Err(format!(
                "expected Checkpoint({expected_tag}), got Checkpoint({tag})"
            )),
            other => Err(format!("expected Checkpoint, got {other:?}")),
        }
    }

    /// Read one response from `handle`'s pipe and decode the
    /// terminal `Response::Result` as `O`. Convenience after
    /// `run_resume` when the handler is expected to finish.
    ///
    /// # Errors
    /// Returns Err on any non-Result response, on `ok: false`, or on
    /// deserialization failure.
    pub async fn run_read_result<A, O>(
        &mut self,
        handle: &AgentHandle,
        _token: &crate::handlers::HandlerToken<A, O>,
    ) -> Result<O, String>
    where
        O: serde::de::DeserializeOwned,
    {
        match self.run_read(handle).await {
            Response::Result {
                ok: true,
                data,
                error: _,
            } => serde_json::from_value(data).map_err(|e| format!("typed deserialize: {e}")),
            Response::Result {
                ok: false,
                data: _,
                error,
            } => Err(error.unwrap_or_else(|| "handler failed".into())),
            other => Err(format!("expected Result, got {other:?}")),
        }
    }

    async fn write_ephemeral(
        &mut self,
        leaf: &EphemeralHandle,
        inner: Command,
        track_in_flight: bool,
    ) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        let parent = leaf.parent().name();
        self.runner.contacted_agents.insert(parent.to_string());
        let (direct, rest) = super::route(parent);
        if track_in_flight {
            if self.in_flight_directs.contains(direct) {
                return Err(format!(
                    "another Run is already in flight on direct pipe '{direct}'; \
                     cannot start a second Run on ephemeral leaf {} until the in-flight one \
                     returns Result",
                    leaf.label()
                ));
            }
            self.in_flight_directs.insert(direct.to_string());
        }
        let Some(child) = self.runner.children.get_mut(direct) else {
            if track_in_flight {
                self.in_flight_directs.remove(direct);
            }
            return Err(format!("no child {direct}"));
        };
        let actual_cmd = super::wrap_forwards(
            rest,
            Command::Forward {
                target: leaf.label().to_string(),
                inner: Box::new(inner),
            },
        );
        let json = serde_json::to_string(&actual_cmd).map_err(|e| e.to_string())?;
        child
            .stdin
            .write_all(format!("{json}\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        child.stdin.flush().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn read_ephemeral(&mut self, leaf: &EphemeralHandle) -> Response {
        use tokio::io::AsyncBufReadExt;
        let parent = leaf.parent().name();
        self.runner.contacted_agents.insert(parent.to_string());
        let (direct, _rest) = super::route(parent);
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

    /// Common pattern for Class A multi-agent rendezvous tests: a
    /// watcher and an actor each run a handler, both arrive at `tag`,
    /// the coord releases both, and the watcher's typed `Out` is
    /// returned. The actor's handler must return `()`.
    ///
    /// Replaces the per-family `run_watch_actor`-style boilerplate
    /// in test files like `coordinator/inotify.rs`.
    ///
    /// # Errors
    /// Returns Err on any wire failure, checkpoint mismatch, handler
    /// failure, or deserialization failure.
    #[allow(clippy::too_many_arguments)] // 3 typed (watcher,token,args) + 3 typed (actor,token,args) + tag = inherent to the pattern
    pub async fn rendezvous_pair<WA, WO, AA>(
        &mut self,
        watcher: &AgentHandle,
        watcher_token: &crate::handlers::HandlerToken<WA, WO>,
        watcher_args: WA,
        actor: &AgentHandle,
        actor_token: &crate::handlers::HandlerToken<AA, ()>,
        actor_args: AA,
        tag: &str,
    ) -> Result<WO, String>
    where
        WA: serde::Serialize,
        WO: serde::de::DeserializeOwned,
        AA: serde::Serialize,
    {
        self.run_write_typed(watcher, watcher_token, watcher_args)
            .await?;
        self.run_read_checkpoint(watcher, tag).await?;
        self.run_write_typed(actor, actor_token, actor_args).await?;
        self.run_read_checkpoint(actor, tag).await?;
        self.run_resume(watcher, tag).await?;
        self.run_resume(actor, tag).await?;
        // Read watcher first: its result tends to involve a drain
        // timeout, which lets the actor's quick work complete in
        // parallel. The actor's Result is read second.
        let out = self.run_read_result(watcher, watcher_token).await?;
        let () = self.run_read_result(actor, actor_token).await?;
        Ok(out)
    }
}
