// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Command/response protocol for parent-child coordination via pipes.

use serde::{Deserialize, Serialize};

fn default_fork_binary() -> String {
    "self".to_string()
}

fn default_accept_timeout() -> u64 {
    10
}

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

    /// Fork a child agent with explicit control over exec binary and fd
    /// inheritance. Subsumes Spawn/SpawnRemote with finer control.
    ///
    /// `binary`:
    ///   - `"self"` → fork+exec the PIE test harness (= Spawn)
    ///   - `"nonpie"` → fork+exec the non-PIE binary (= `SpawnRemote`)
    ///
    /// `inherit_listen_ports`: TCP listen ports whose listen socket fds
    /// should be inherited by the child (CLOEXEC cleared before exec).
    /// **Not yet implemented** — see design notes below.
    ///
    /// # fd inheritance pattern (future work)
    ///
    /// The VS Code CLI does this:
    ///   1. Parent calls `bind()+listen()` on a port
    ///   2. Parent fork()+exec()s the server process
    ///   3. Parent closes its listen fd
    ///   4. Child calls `accept()` on the **inherited** listen fd
    ///
    /// To support this in the protocol:
    ///   1. Fork handler looks up the listen socket fd for each port in
    ///      `inherit_listen_ports` (the agent tracks port→fd mapping from
    ///      `NetListen`).
    ///   2. Clears CLOEXEC on those fds: `fcntl(fd, F_SETFD, 0)`.
    ///   3. fork()+exec()s the child, passing the fd numbers via a CLI
    ///      arg or env var (e.g., `--inherited-fds 3,5`).
    ///   4. Child agent reconstructs `TcpListeners` from the raw fds via
    ///      `TcpListener::from_raw_fd(fd)` and registers them in its
    ///      listener map.
    ///   5. The child's `NetAccept` or echo handler then works on the
    ///      inherited listener — no re-bind needed.
    ///
    /// Pair with `NetCloseListener` on the parent to reproduce the full
    /// VS Code pattern: `NetListen` → Fork(inherit) → `NetCloseListener` →
    /// child `NetAccept`.
    ///
    /// Currently this pattern is tested via the `tcp-fork-listen-accept`
    /// subcommand (see main.rs), which implements steps 1-4 as a single
    /// standalone program outside the agent protocol.
    #[serde(rename = "fork")]
    Fork {
        name: String,
        #[serde(default = "default_fork_binary")]
        binary: String,
        #[serde(default)]
        inherit_listen_ports: Vec<u16>,
    },

    /// Accept one connection on an already-listening TCP port.
    /// Decouples listen from accept so tests can fork/close between them.
    #[serde(rename = "net_accept")]
    NetAccept {
        port: u16,
        #[serde(default = "default_accept_timeout")]
        timeout_secs: u64,
    },

    /// Close the TCP listen socket on a port (without removing the echo
    /// handler task). Reproduces the parent-close-after-fork pattern.
    #[serde(rename = "net_close_listener")]
    NetCloseListener { port: u16 },

    /// Report the agent's process ID.
    #[serde(rename = "get_pid")]
    GetPid,

    /// Read a file and report contents (or `not_found`).
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

    /// Connect to addr, write data, shutdown one half of the TCP connection,
    /// then read echoed data until EOF. `half` must be `"wr"`, `"rd"`, or
    /// `"rdwr"`; TCP half-close EOF tests use `"wr"`.
    #[serde(rename = "net_halfclose_echo")]
    NetHalfCloseEcho {
        addr: String,
        write_data: String,
        half: String,
    },

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

    /// Open `count` concurrent TCP connections to `addr`, send `data` on each,
    /// read echoed response, report success count. Tests for data corruption
    /// and connection races under concurrency.
    #[serde(rename = "net_connect_many")]
    NetConnectMany {
        addr: String,
        data: String,
        count: u32,
        delay_ms: u32,
    },

    /// Send `size` bytes of a known repeating pattern to `addr`, read `size`
    /// bytes back, verify byte-by-byte integrity. Tests backpressure and
    /// large-transfer correctness.
    #[serde(rename = "net_send_recv")]
    NetSendRecv { addr: String, size: u32 },

    /// Open `count` sequential TCP connections to `addr`, send `data` on each,
    /// read echo, close. Tests `TIME_WAIT` handling and rapid port reuse.
    #[serde(rename = "net_reconnect_stress")]
    NetReconnectStress {
        addr: String,
        count: u32,
        data: String,
    },

    /// Connect to `addr`, send `size` bytes, read file at `path`, then read
    /// echoed TCP data. Reports both file content and TCP integrity. Tests for
    /// 9P deadlock when file I/O happens while TCP sockets are active.
    #[serde(rename = "net_send_file_recv")]
    NetSendFileRecv {
        addr: String,
        size: u32,
        path: String,
    },

    /// Create a pipe, write data, poll read-end for POLLIN readiness.
    /// Tests that file descriptors correctly report IN events in poll/epoll.
    #[serde(rename = "poll_ready")]
    PollReady { timeout_ms: u32 },

    /// Bind a TCP socket to ANY:0, call getsockname, report the assigned port.
    /// Tests that getsockname returns a nonzero port for bound sockets.
    #[serde(rename = "bind_getsockname")]
    BindGetsockname { family: String },

    /// Create+drop `count` pipe pairs, then create `count` more and check
    /// that no `pair_id` from the second batch collides with the first.
    /// Tests monotonic `pair_id` generation (vs. Arc pointer reuse).
    #[serde(rename = "pipe_pair_id_unique")]
    PipePairIdUnique { count: u32 },

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

    /// TCP half-close echo result.
    #[serde(rename = "halfclosed")]
    HalfClosed { echo: String },

    /// TCP half-close operation failed.
    #[serde(rename = "halfclose_failed")]
    HalfCloseFailed { error: String },

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
