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

    /// Spawn child agents using a non-PIE binary, forcing them to remote
    /// workers. Used to test cross-worker filesystem and socket coherence.
    #[serde(rename = "spawn_remote")]
    SpawnRemote { children: Vec<String> },

    /// Read a file and report contents (or not_found).
    #[serde(rename = "fs_read")]
    FsRead { path: String },

    /// Write data to a file.
    #[serde(rename = "fs_write")]
    FsWrite { path: String, data: String },

    /// Delete a file.
    #[serde(rename = "fs_delete")]
    FsDelete { path: String },

    /// Create a symbolic link.
    #[serde(rename = "fs_symlink")]
    FsSymlink { target: String, link: String },

    /// Read the target of a symbolic link.
    #[serde(rename = "fs_readlink")]
    FsReadlink { path: String },

    /// Stat a path — returns type (file/dir/symlink/notfound).
    #[serde(rename = "fs_stat")]
    FsStat { path: String },

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
    },

    /// Report an environment variable value.
    #[serde(rename = "env_get")]
    EnvGet { var: String },

    /// Report current working directory.
    #[serde(rename = "cwd_get")]
    CwdGet,

    /// Bind a Unix domain socket listener. Starts an echo handler task.
    #[serde(rename = "unix_listen")]
    UnixListen { path: String },

    /// Stop listening on a Unix socket path.
    #[serde(rename = "unix_unlisten")]
    UnixUnlisten { path: String },

    /// Connect to a Unix domain socket, send data, read echo response.
    #[serde(rename = "unix_connect")]
    UnixConnect { path: String, data: String },

    /// Kill a background process by PID.
    #[serde(rename = "kill")]
    Kill { pid: u32 },

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
