// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Command/response protocol for parent-child coordination via pipes.

use serde::{Deserialize, Serialize};

fn default_fork_binary() -> String {
    "self".to_string()
}

fn default_marker_stream() -> String {
    "either".to_string()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SockOpt {
    ReuseAddr,
    ReusePort,
    KeepAlive,
    RecvBuf,
    SendBuf,
    NoDelay,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SockOptValue {
    Bool(bool),
    U32(u32),
}

/// Command sent from parent to child via stdin.
///
/// **This enum is closed to test-specific additions.** It carries only
/// generic wire primitives (process lifecycle, fs / net / unix / eventfd
/// I/O) plus the `Run { handler, args }` dispatch envelope. New test
/// behavior must be expressed as a registered handler in
/// `coordinator/<family>.rs` — see `litebox_test_harness/CLAUDE.md`
/// "Handler Model" for the pattern. If you find yourself wanting a new
/// `Command::Foo` for a single test family, write a handler instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum Command {
    /// Spawn child processes. Child creates the named agents as its
    /// own children with piped stdin/stdout.
    #[serde(rename = "spawn")]
    Spawn { children: Vec<String> },

    /// Spawn child agents using a non-PIE binary, forcing them to remote
    /// workers. Used to test cross-worker filesystem and socket coherence.
    #[serde(rename = "spawn_remote")]
    SpawnRemote { children: Vec<String> },

    /// Fork a child agent with explicit control over exec binary and fd
    /// inheritance. Subsumes Spawn/SpawnRemote with finer control.
    ///
    /// `binary`:
    ///   - `"self"` → fork+exec the PIE test harness (= Spawn)
    ///   - `"nonpie"` → fork+exec the non-PIE binary (= `SpawnRemote`)
    ///
    /// `inherit_listen_ports`: TCP listen ports whose listen socket fds
    /// should be inherited by the child. The parent duplicates each requested
    /// listener into deterministic child fd slots 80..99, clearing CLOEXEC only
    /// on those short-lived duplicates. This range is intentionally below the
    /// Litebox host bridge/infrastructure bands (100..199, 200..499, 500+) and
    /// above stdio. The child receives a `port=fd` mapping in
    /// `LITEBOX_TEST_HARNESS_INHERITED_LISTEN_FDS`; handler-dispatched probes
    /// accept on the inherited listener after the parent unlistens.
    #[serde(rename = "fork")]
    Fork {
        name: String,
        #[serde(default = "default_fork_binary")]
        binary: String,
        #[serde(default)]
        inherit_listen_ports: Vec<u16>,
    },

    /// Forward a command to a named child and return its response.
    #[serde(rename = "forward")]
    Forward { target: String, inner: Box<Command> },

    /// Invoke a registered handler on the agent. The agent looks up
    /// `handler` in its global registry (populated at startup via
    /// `collect_all_tests`), invokes it with `args`, and returns a
    /// `Response::Result` on completion. While running, a handler
    /// may emit `Response::Checkpoint { tag }` and block reading
    /// stdin for `Command::Resume { tag }`. This is the generic
    /// dispatch path; new test behavior should be expressed as a
    /// registered handler rather than as a new `Command::*` variant.
    #[serde(rename = "run")]
    Run {
        handler: String,
        args: serde_json::Value,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },

    /// Sent to an agent that is currently blocked at a handler's
    /// `ctx.checkpoint(tag)` call to release it. Must match the tag
    /// the handler is waiting on.
    #[serde(rename = "resume")]
    Resume { tag: String },

    /// Fork+exec with args. Captures stdout/stderr and waits, or runs
    /// in background and returns PID. Optionally pipes content to stdin.
    #[serde(rename = "exec")]
    Exec {
        args: Vec<String>,
        /// Timeout in seconds (default: 10). Ignored if background=true.
        #[serde(default)]
        timeout_secs: Option<u64>,
        /// Content to pipe to the child's stdin. None = /dev/null.
        #[serde(default)]
        stdin: Option<String>,
        /// If true, return Background { pid } immediately instead of waiting.
        #[serde(default)]
        background: bool,
        /// Extra environment variables to set on the child, on top of
        /// whatever the agent inherits. List of `(key, value)` pairs.
        /// Empty means "inherit unchanged".
        #[serde(default)]
        env: Vec<(String, String)>,
    },

    /// Fork+exec in the background, but return only after stdout/stderr
    /// contains the requested readiness marker. Output remains captured for
    /// `WaitBackground`, and is drained after readiness so helpers cannot block.
    #[serde(rename = "exec_ready")]
    ExecReady {
        args: Vec<String>,
        /// Stdout/stderr substring that, once observed, signals readiness.
        ready_marker: String,
        /// Hard cap on wait. None = 30 seconds.
        #[serde(default)]
        timeout_secs: Option<u64>,
        #[serde(default)]
        stdin: Option<String>,
        /// Where to look for the marker: "stdout" | "stderr" | "either".
        #[serde(default = "default_marker_stream")]
        stream: String,
    },

    /// Shut down gracefully.
    #[serde(rename = "exit")]
    Exit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "id", rename_all = "snake_case")]
pub enum FdRef {
    Eventfd(u64),
    TcpConn(u64),
    UnixPair(u64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WaitPredicate {
    PortListening { port: u16, host: String },
    FileExists { path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpollEvent {
    pub kind: String,
    pub id: u64,
    pub observed_events: String,
}

/// Response sent from child to parent via stdout.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum Response {
    /// Successful operation with optional data.
    #[serde(rename = "ok")]
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<String>,
    },

    /// File not found.
    #[serde(rename = "not_found")]
    NotFound,

    /// Terminal event for a `Command::Run`. The handler's typed
    /// `Out` is encoded as a `serde_json` `Value` in `data`. On
    /// failure, `ok` is false and `error` carries the message.
    #[serde(rename = "result")]
    Result {
        ok: bool,
        #[serde(default)]
        data: serde_json::Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },

    /// Mid-handler rendezvous arrival event. Emitted by an agent
    /// running a handler when it hits a `ctx.checkpoint(tag)` call;
    /// the agent then blocks reading stdin until the coord sends
    /// `Command::Resume` with the matching tag.
    #[serde(rename = "checkpoint")]
    Checkpoint { tag: String },

    /// TCP listener is ready.
    #[serde(rename = "listening")]
    Listening { port: u16 },

    /// Unix socket listener is ready.
    #[serde(rename = "unix_listening")]
    UnixListening { path: String },

    /// TCP connection + echo result.
    #[serde(rename = "connected")]
    Connected { echo: String },

    /// TCP connection failed.
    #[serde(rename = "connect_failed")]
    ConnectFailed { error: String },

    /// Exec result.
    #[serde(rename = "exec_result")]
    ExecResult {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },

    /// Exec timed out (likely deadlocked).
    #[serde(rename = "exec_timeout")]
    ExecTimeout { stderr: String },

    /// Background process started.
    #[serde(rename = "background")]
    Background { pid: u32 },

    /// Background process reached its readiness marker.
    #[serde(rename = "background_ready")]
    BackgroundReady { pid: u32 },

    /// Error.
    #[serde(rename = "error")]
    Error { error: String },
}
