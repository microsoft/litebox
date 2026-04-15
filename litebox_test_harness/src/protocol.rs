// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Command/response protocol for parent-child coordination via pipes.

use serde::{Deserialize, Serialize};

/// Command sent from parent to child via stdin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum Command {
    /// Spawn child processes. Child creates the named agents as its
    /// own children with piped stdin/stdout.
    #[serde(rename = "spawn")]
    Spawn { children: Vec<String> },

    /// Read a file and report contents (or not_found).
    #[serde(rename = "fs_read")]
    FsRead { path: String },

    /// Write data to a file.
    #[serde(rename = "fs_write")]
    FsWrite { path: String, data: String },

    /// Delete a file.
    #[serde(rename = "fs_delete")]
    FsDelete { path: String },

    /// Bind a TCP listener on the given port. Starts an echo handler.
    #[serde(rename = "net_listen")]
    NetListen { port: u16 },

    /// Stop listening on a port.
    #[serde(rename = "net_unlisten")]
    NetUnlisten { port: u16 },

    /// Connect to addr, send data, read echo response.
    #[serde(rename = "net_connect")]
    NetConnect { addr: String, data: String },

    /// Forward a command to a named child and return its response.
    #[serde(rename = "forward")]
    Forward { target: String, inner: Box<Command> },

    /// Fork+exec self with args and report exit code + stdout.
    #[serde(rename = "exec")]
    Exec {
        args: Vec<String>,
        /// Optional timeout in seconds (default: 10).
        #[serde(default)]
        timeout_secs: Option<u64>,
    },

    /// Report an environment variable value.
    #[serde(rename = "env_get")]
    EnvGet { var: String },

    /// Report current working directory.
    #[serde(rename = "cwd_get")]
    CwdGet,

    /// Test Unix domain socket lifecycle (create, bind, listen, connect, send, receive).
    #[serde(rename = "unix_socket_test")]
    UnixSocketTest { path: String },

    /// Test cross-process Unix socket relay: start a server, fork a child
    /// that connects, verify bidirectional data flow.
    #[serde(rename = "unix_socket_relay")]
    UnixSocketRelay { path: String, self_exe: String },

    /// Test reverse Unix socket relay: fork a child that creates the server,
    /// parent connects. Mimics VS Code's pattern (code-server creates socket,
    /// CLI connects).
    #[serde(rename = "unix_socket_reverse_relay")]
    UnixSocketReverseRelay { path: String, self_exe: String },

    /// Proceed (used after coordination points).
    #[serde(rename = "go")]
    Go,

    /// Shut down gracefully.
    #[serde(rename = "exit")]
    Exit,
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

    /// TCP listener is ready.
    #[serde(rename = "listening")]
    Listening { port: u16 },

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

    /// Error.
    #[serde(rename = "error")]
    Error { error: String },

    /// Test result (for structured reporting).
    #[serde(rename = "test_result")]
    TestResult {
        test: String,
        agent: String,
        result: String,
        detail: String,
    },
}
