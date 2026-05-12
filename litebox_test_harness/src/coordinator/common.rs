// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared bash + arbitrary-binary exec handlers.
//!
//! These two handlers replace the legacy `super::exec()` /
//! `super::exec_timeout()` helpers used across test families. They run
//! inside the agent (via `Command::Run`) and execute the requested
//! child process via `tokio::process::Command`, so the wire-level
//! `Command::Exec` + `Command::ExecReady` arms in `agent.rs` no longer
//! need to be involved in any test-logic dispatch.
//!
//! Reach for these in any new test that needs to spawn a child process
//! on an agent. Prefer over `super::exec*`.
//!
//! The `BASH` token runs a single bash one-liner (`bash -c <cmd>`).
//! The `EXEC_BIN` token runs an arbitrary `argv[0]` with `argv[1..]`.
//! Neither returns until the child has exited (or `timeout_ms`
//! expires). For background semantics, write a per-family handler
//! that records the child PID and returns immediately.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::registry::Registry;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

#[derive(Serialize, Deserialize)]
pub(crate) struct BashArgs {
    pub(crate) cmd: String,
    /// Optional timeout; default is 30 s.
    #[serde(default)]
    pub(crate) timeout_ms: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct BashOut {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) exit_code: i32,
    pub(crate) timed_out: bool,
}

pub(crate) const BASH: HandlerToken<BashArgs, BashOut> = HandlerToken::new("common.bash");

async fn handle_bash(args: BashArgs, _ctx: &mut HandlerCtx<'_>) -> Result<BashOut, HandlerError> {
    let timeout = Duration::from_millis(args.timeout_ms.unwrap_or(30_000));
    let mut cmd = tokio::process::Command::new("bash");
    cmd.arg("-c").arg(&args.cmd);
    run_to_completion(cmd, timeout).await
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ExecBinArgs {
    pub(crate) argv: Vec<String>,
    /// Optional timeout; default is 30 s.
    #[serde(default)]
    pub(crate) timeout_ms: Option<u64>,
    /// Optional payload piped to the child's stdin.
    #[serde(default)]
    pub(crate) stdin: Option<String>,
    /// Extra `(key, value)` env entries to set on the child.
    #[serde(default)]
    pub(crate) env: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ExecBinOut {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) exit_code: i32,
    pub(crate) timed_out: bool,
}

pub(crate) const EXEC_BIN: HandlerToken<ExecBinArgs, ExecBinOut> =
    HandlerToken::new("common.exec_bin");

async fn handle_exec_bin(
    args: ExecBinArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ExecBinOut, HandlerError> {
    if args.argv.is_empty() {
        return Err(HandlerError::from("exec_bin: empty argv"));
    }
    let timeout = Duration::from_millis(args.timeout_ms.unwrap_or(30_000));
    let mut cmd = tokio::process::Command::new(&args.argv[0]);
    cmd.args(&args.argv[1..]);
    for (k, v) in &args.env {
        cmd.env(k, v);
    }
    let stdin_payload = args.stdin.clone();
    if stdin_payload.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| HandlerError::from(format!("spawn: {e}")))?;
    if let Some(payload) = stdin_payload {
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(payload.as_bytes()).await;
            drop(stdin);
        }
    }
    let result = tokio::time::timeout(timeout, child.wait_with_output()).await;
    match result {
        Ok(Ok(out)) => Ok(ExecBinOut {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            exit_code: out.status.code().unwrap_or(-1),
            timed_out: false,
        }),
        Ok(Err(e)) => Err(HandlerError::from(format!("wait_with_output: {e}"))),
        Err(_) => Ok(ExecBinOut {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: -1,
            timed_out: true,
        }),
    }
}

async fn run_to_completion(
    mut cmd: tokio::process::Command,
    timeout: Duration,
) -> Result<BashOut, HandlerError> {
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let child = cmd
        .spawn()
        .map_err(|e| HandlerError::from(format!("spawn: {e}")))?;
    let result = tokio::time::timeout(timeout, child.wait_with_output()).await;
    match result {
        Ok(Ok(out)) => Ok(BashOut {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            exit_code: out.status.code().unwrap_or(-1),
            timed_out: false,
        }),
        Ok(Err(e)) => Err(HandlerError::from(format!("wait_with_output: {e}"))),
        Err(_) => Ok(BashOut {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: -1,
            timed_out: true,
        }),
    }
}

/// Register the shared `BASH` and `EXEC_BIN` handlers. Call once at
/// startup before any family registers tests that use these tokens.
pub(crate) fn register_common_handlers(_reg: &mut Registry<'_>) {
    register_handler!(BASH, handle_bash);
    register_handler!(EXEC_BIN, handle_exec_bin);
}
