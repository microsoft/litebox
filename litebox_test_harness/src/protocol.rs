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

fn default_marker_stream() -> String {
    "either".to_string()
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
    /// should be inherited by the child. The parent duplicates each requested
    /// listener into deterministic child fd slots 80..99, clearing CLOEXEC only
    /// on those short-lived duplicates. This range is intentionally below the
    /// Litebox host bridge/infrastructure bands (100..199, 200..499, 500+) and
    /// above stdio. The child receives a `port=fd` mapping in
    /// `LITEBOX_TEST_HARNESS_INHERITED_LISTEN_FDS`, imports each fd into its
    /// listener registry, and then normal `NetAccept` / `NetConnect` probing
    /// works without re-binding.
    ///
    /// Pair with `NetCloseListener` on the parent to reproduce the full
    /// VS Code pattern: `NetListen` → Fork(inherit) → `NetCloseListener` →
    /// child accepts on the inherited listener.
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

    /// Exercise curated `clone3(2)` flag combinations.
    #[serde(rename = "clone3")]
    Clone3 { kind: Clone3Kind },

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

    /// Connect to addr and register the TCP stream for stateful operations.
    #[serde(rename = "net_open")]
    NetOpen { addr: String },

    /// Send bytes on a registered TCP connection.
    #[serde(rename = "net_send")]
    NetSend { conn: u64, data: String },

    /// Receive bytes from a registered TCP connection. None means read to EOF.
    #[serde(rename = "net_recv")]
    NetRecv { conn: u64, n_bytes: Option<u32> },

    /// Shutdown one half of a registered TCP connection: "wr", "rd", or "rdwr".
    #[serde(rename = "net_shutdown")]
    NetShutdown { conn: u64, half: String },

    /// Close and unregister a TCP connection.
    #[serde(rename = "net_close")]
    NetClose { conn: u64 },

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

    /// Wait until this agent or a named child agent has accepted protocol
    /// commands. A child agent can only answer after its init phase entered
    /// the command loop, making this a process-ready beacon.
    #[serde(rename = "wait_ready")]
    WaitReady {
        agent: String,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },

    /// Wait for a previously backgrounded process to exit and return its
    /// captured output. For plain Exec background commands stdout/stderr are
    /// empty; `ExecReady` backgrounds retain captured output.
    #[serde(rename = "wait_background")]
    WaitBackground {
        pid: u32,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },

    /// Wait for an observed state predicate on this agent. This is a bounded
    /// protocol-level replacement for coordinator sleeps.
    #[serde(rename = "wait_for")]
    WaitFor {
        predicate: WaitPredicate,
        #[serde(default)]
        timeout_secs: Option<u64>,
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

    /// Open a pseudo-terminal pair and register the master fd.
    #[serde(rename = "pty_open")]
    PtyOpen {},

    /// Fork+exec `args` with stdio attached to a registered pty slave.
    #[serde(rename = "pty_exec")]
    PtyExec {
        master: u64,
        args: Vec<String>,
        ctrl_tty: bool,
    },

    /// Write bytes to a registered pty master.
    #[serde(rename = "pty_write")]
    PtyWrite { master: u64, data: String },

    /// Read bytes from a registered pty master. None means read until EOF.
    #[serde(rename = "pty_read")]
    PtyRead { master: u64, n_bytes: Option<u32> },

    /// Resize the terminal window for a registered pty master.
    #[serde(rename = "pty_resize")]
    PtyResize { master: u64, rows: u16, cols: u16 },

    /// Close and unregister a pty master.
    #[serde(rename = "pty_close")]
    PtyClose { master: u64 },

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

    /// Call io_uring_setup(2) once and report the kernel-visible outcome.
    #[serde(rename = "io_uring_setup")]
    IoUringSetup { entries: u32 },

    /// Call epoll_create1(2) once and report whether a descriptor was returned.
    #[serde(rename = "epoll_open")]
    EpollOpen,

    /// Open an eventfd and register it in this agent's local registry.
    /// Flags are parsed from strings like "semaphore|nonblock|cloexec".
    #[serde(rename = "eventfd_open")]
    EventfdOpen { initval: u64, flags: String },

    /// Read one u64 from a registered eventfd. Nonblocking empty reads return
    /// [`Response::Error`] with EAGAIN.
    #[serde(rename = "eventfd_read")]
    EventfdRead { id: u64 },

    /// Read one u64 on behalf of a reader authorized via EventfdShare. This
    /// models the layer-1 forward-via-creator path without passing fds.
    #[serde(rename = "eventfd_read_shared")]
    EventfdReadShared { id: u64, reader: String },

    /// Write one u64 to a registered eventfd.
    #[serde(rename = "eventfd_write")]
    EventfdWrite { id: u64, value: u64 },

    /// Close and unregister a registered eventfd.
    #[serde(rename = "eventfd_close")]
    EventfdClose { id: u64 },

    /// Mark a named agent as an authorized reader of this creator-local
    /// eventfd. Layer 1 deliberately models sharing as forwarding a command
    /// through the creator's registry, not as SCM_RIGHTS fd passing.
    #[serde(rename = "eventfd_share")]
    EventfdShare { id: u64, target: String },

    /// Minimal eventfd + epoll edge-triggered probe used until W2's structured
    /// epoll commands are available. The eventfd must already be ready.
    #[serde(rename = "eventfd_epollet")]
    EventfdEpollEt { id: u64 },

    /// Shut down gracefully.
    #[serde(rename = "exit")]
    Exit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Clone3Kind {
    Thread,
    Process,
    WithPidfd,
    WithSetTid { tid: u64 },
    WithCgroup { cgroup_fd: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloneResult {
    pub pid: u64,
    pub pidfd: Option<i32>,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WaitPredicate {
    PortListening { port: u16, host: String },
    FileExists { path: String },
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

    /// Stateful TCP connection opened.
    #[serde(rename = "opened")]
    Opened { conn: u64 },

    /// PTY master handle and slave path.
    #[serde(rename = "pty_handle")]
    PtyHandle { master: u64, slave_path: String },

    /// Stateful TCP bytes sent.
    #[serde(rename = "sent")]
    Sent,

    /// Stateful TCP bytes received.
    #[serde(rename = "received")]
    Received { data: String },

    /// Stateful TCP shutdown completed.
    #[serde(rename = "shutdown_ok")]
    ShutdownOk,

    /// Stateful TCP connection closed.
    #[serde(rename = "closed")]
    Closed,

    /// Eventfd registry handle.
    #[serde(rename = "eventfd_handle")]
    EventfdHandle { id: u64 },

    /// Eventfd read value.
    #[serde(rename = "eventfd_value")]
    EventfdValue { value: u64 },

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

    /// Result of a curated `clone3(2)` exercise.
    #[serde(rename = "clone_result")]
    CloneResult {
        pid: u64,
        pidfd: Option<i32>,
        ok: bool,
        error: Option<String>,
    },

    /// Readiness or wait predicate satisfied.
    #[serde(rename = "ready")]
    Ready,

    /// io_uring_setup(2) result. `errno` is a positive errno on failure.
    #[serde(rename = "io_uring_result")]
    IoUringResult { ring_fd: i32, errno: Option<i32> },

    /// epoll_create1(2) result. `errno` is a positive errno on failure.
    #[serde(rename = "epoll_open_result")]
    EpollOpenResult { epoll_fd: i32, errno: Option<i32> },

    /// Error.
    #[serde(rename = "error")]
    Error { error: String },
}
