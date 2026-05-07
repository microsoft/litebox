# Protocol surface gap audit

Scope: `audit-protocol-surface` from Phase 4 of the test-framework audit. This review starts from `docs/audit/protocol-coverage.md`, `litebox_test_harness/src/protocol.rs`, and the mandatory `litebox_test_harness/CLAUDE.md` fd-inheritance guidance.

## Ranked summary

| rank | gap | score | effort | why it ranks here |
|---:|---|---|---:|---|
| 1 | `Fork.inherit_listen_ports` + real inherited `NetAccept` | **VS-Code blocker** | M | `CLAUDE.md:272-288` says the VS Code CLI hands a listen socket to a fork+exec child, and the protocol field was designed for this but is not implemented. |
| 2 | PTY allocation + controlling-tty handover | **VS-Code blocker** | L | VS Code remote uses ptyHost/terminal flows; the harness can test pipe/socketpair IPC today, but not `openpty`/`setsid`/`TIOCSCTTY`/`TIOCSPGRP`. |
| 3 | SCM_RIGHTS fd-passing over Unix sockets | **VS-Code blocker** | M/L | The repo has socketpair and netlink `sendmsg` tests, but no protocol surface for `SCM_RIGHTS`, another common Node/ptyHost IPC primitive. |
| 4 | `Exec.env` | **regression-risk** | S | `Command::Exec` has args/stdin/background/timeout only (`protocol.rs:146-160`); `EnvGet` only reads the agent environment (`protocol.rs:162-164`). |
| 5 | Signals beyond `Kill` | **regression-risk** | M | `Kill { pid }` maps to SIGKILL cleanup (`protocol.rs:182-184`, `agent.rs:791-806`); no handler installation, arbitrary signal send, or ordered delivery assertion. |
| 6 | Stateful TCP connection registry | **regression-risk** | M | `NetHalfCloseEcho` is one one-shot command (`protocol.rs:132-140`) with one test and one fragile response (`protocol-coverage.md:26`, `:54`). |
| 7 | Background readiness / state waits | **regression-risk** | M | Not the main surface requested here, but `Exec background` discards stdout (`agent.rs:478-480`), forcing timer-based server readiness in multiple tests. |
| 8 | Dead/half-finished protocol variants | **cleanup** | S/M | `NetAccept`, `NetCloseListener`, `Go`, `HalfCloseFailed`, and `TestResult` are dead or unasserted per `protocol-coverage.md:14-15`, `:42`, `:55`, `:61`. |

Top-3 recommended additions: **(1) complete `Fork.inherit_listen_ports` with real inherited-listener accept, (2) add PTY open/exec/read/write/handover commands, (3) add SCM_RIGHTS fd-passing commands.**

## 1. `Fork.inherit_listen_ports` and real inherited-listener accept

### current state

`CLAUDE.md:272-288` documents the VS Code fd inheritance pattern:

```text
parent: bind()+listen() → clear CLOEXEC → fork()+exec(child) → close(fd)
child:  accept() on inherited fd → echo data
```

It explicitly says this is currently tested by the standalone `tcp-fork-listen-accept` subcommand and cannot be expressed via the agent protocol because the child must accept on a raw inherited fd. The `Fork` protocol already has `inherit_listen_ports` at `protocol.rs:37-75` and design notes at `protocol.rs:41-68`:

1. look up `port -> fd` from the agent listener map,
2. clear `CLOEXEC` with `fcntl(fd, F_SETFD, 0)`,
3. fork+exec the child and pass fd numbers via CLI arg or env var,
4. reconstruct `TcpListener::from_raw_fd(fd)` in the child agent,
5. use child `NetAccept` or an echo handler without re-binding.

But the agent handler only binds the value and discards it: `agent.rs:150-162` has `Command::Fork { ..., inherit_listen_ports }` followed by `let _ = &inherit_listen_ports;`. The standalone substitute lives at `main.rs:720-790`: `tcp-fork-listen-accept` clears `CLOEXEC`, spawns `tcp-accept-inherited`, drops the parent listener, and the child accepts on `TcpListener::from_raw_fd(fd)`.

`Command::NetAccept` and `Command::NetCloseListener` are also dead by coordinator callsite count (`protocol-coverage.md:14-15`). Worse, the current `NetAccept` implementation is not a true accept on an existing listener: `agent.rs:181-230` connects locally to the port and probes the already-running echo task. That does not exercise inherited raw-fd accept.

### what's missing

The test framework cannot express the real VS Code shape as protocol operations. It can only run a monolithic helper through `Exec`, which weakens axis coverage, forces readiness sleeps (`synchronization-primitives.md:51`), and bypasses the agent's listener registry. The missing implementation surface is:

- agent-side listener registry that stores the actual `TcpListener` object or a duplicateable raw fd per `NetListen` port;
- `Fork` fd plumbing that clears `FD_CLOEXEC` only for requested listen sockets, preserves or restores flags carefully, and passes inherited fd metadata to the child agent;
- child-agent startup path that imports inherited listener fds into its listener map before serving protocol commands;
- real `NetAccept` semantics that accept one connection on the registered listener instead of creating a client connection to the echo task;
- `NetCloseListener` parent-close semantics that close only the parent's listener without killing the child's inherited listener.

### proposed `Command` / `Response` shape

Keep the existing public shape but complete it, and add one explicit response for accepted connections:

```rust
pub enum Command {
    Fork {
        name: String,
        #[serde(default = "default_fork_binary")]
        binary: String,
        #[serde(default)]
        inherit_listen_ports: Vec<u16>,
    },
    NetAccept {
        port: u16,
        #[serde(default = "default_accept_timeout")]
        timeout_secs: u64,
    },
    NetCloseListener { port: u16 },
}

pub enum Response {
    Forked {
        name: String,
        inherited_ports: Vec<u16>,
    },
    Accepted {
        port: u16,
        peer: String,
        echo: Option<String>,
    },
    Error { error: String },
}
```

A backwards-compatible first pass can keep `Response::Ok` for `Fork` and use existing `Response::Connected { echo }` for `NetAccept`, but structured `Forked`/`Accepted` would make payload assertions stronger.

### example test sketch

```rust
let port = free_port();
assert!(matches!(send(A, Command::NetListen { port }).await, Response::Listening { port: p } if p == port));
assert_ok(send(A, Command::Fork {
    name: "A_inherit".into(),
    binary: "self".into(),
    inherit_listen_ports: vec![port],
}).await);
assert_ok(send(A, Command::NetCloseListener { port }).await);

let accept = send(A_inherit, Command::NetAccept { port, timeout_secs: 5 }).await;
let connect = send(B, Command::NetConnect { addr: format!("127.0.0.1:{port}"), data: "vscode".into() }).await;
assert_eq!(connect, Response::Connected { echo: "vscode".into() });
assert!(matches!(accept, Response::Accepted { port: p, .. } if p == port));
```

Cover parent->child, child->parent, sibling, and depth-2 axes once the base primitive works.

### scoring

- impact: **VS-Code blocker**
- effort: **M**
- dead-variant cross-reference: complete `Command::NetAccept` and `Command::NetCloseListener`; do not remove them. Their current dead status is a half-finished handler gap, not dead product value.

## 2. PTY allocation and controlling-tty handover

### current state

`protocol.rs` has no PTY commands. Grepping the harness shows VS-Code-adjacent ptyHost pipe/socketpair tests (`main.rs:4213-4215`, `main.rs:4612-4617`, `main.rs:4752-4759`), but these exercise fd bridging and epoll readiness around pipes/socketpairs, not a real pseudoterminal. The mandatory failure-investigation guidance names `pty` + `TIOCSPGRP` and controlling-tty handover as a suspect capability (`CLAUDE.md:16-18`).

### what's missing

The coordinator cannot ask an agent to allocate a PTY, exec a child attached to its slave side, move the child into a new session/process group, make the slave its controlling terminal, drive reads/writes through the master, or assert foreground process group behavior. That leaves VS Code terminal regressions invisible unless they are reproduced by broad integration tests.

### proposed `Command` / `Response` shape

```rust
pub type PtyHandle = u64;

pub enum Command {
    PtyOpen {
        #[serde(default)]
        rows: Option<u16>,
        #[serde(default)]
        cols: Option<u16>,
        #[serde(default)]
        term: Option<String>,
    },
    PtyExec {
        handle: PtyHandle,
        args: Vec<String>,
        #[serde(default)]
        env: Vec<(String, String)>,
        #[serde(default)]
        setsid: bool,
        #[serde(default)]
        controlling_tty: bool,
        #[serde(default)]
        foreground_pgrp: bool,
    },
    PtyWrite { handle: PtyHandle, data: Vec<u8> },
    PtyRead {
        handle: PtyHandle,
        #[serde(default)]
        max_bytes: Option<usize>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    PtyResize { handle: PtyHandle, rows: u16, cols: u16 },
    PtyClose { handle: PtyHandle },
}

pub enum Response {
    PtyOpened { handle: PtyHandle, master_fd: i32, slave_name: String },
    PtySpawned { handle: PtyHandle, pid: u32, pgrp: u32 },
    PtyRead { handle: PtyHandle, data: Vec<u8>, eof: bool },
    Ok { data: Option<String> },
    Error { error: String },
}
```

Implementation should use `openpty`/`posix_openpt` + `grantpt` + `unlockpt`, fork/exec with the slave as stdio, and in the child perform `setsid()` then `ioctl(slave, TIOCSCTTY)` when requested. A foreground-pgrp option should exercise `tcsetpgrp`/`TIOCSPGRP`.

### example test sketch

```rust
let h = expect_pty_open(send(A, Command::PtyOpen { rows: Some(24), cols: Some(80), term: Some("xterm-256color".into()) }).await);
let spawned = send(A, Command::PtyExec {
    handle: h,
    args: vec![self_exe, "pty-test".into(), "ctty-pgrp".into()],
    env: vec![],
    setsid: true,
    controlling_tty: true,
    foreground_pgrp: true,
}).await;
assert_spawned(spawned);
send(A, Command::PtyWrite { handle: h, data: b"echo ok\n".to_vec() }).await;
let out = expect_pty_read(send(A, Command::PtyRead { handle: h, max_bytes: Some(4096), timeout_ms: Some(5000) }).await);
assert!(out.contains(b"PTY_CTTY_OK"));
```

### scoring

- impact: **VS-Code blocker**
- effort: **L**
- dead-variant cross-reference: no existing dead PTY variant; this is a true missing surface.

## 3. SCM_RIGHTS fd-passing over Unix domain sockets

### current state

`protocol.rs` supports `UnixListen`, `UnixConnect`, and `UnixUnlisten` as string-echo helpers (`protocol.rs:170-180`), but no file descriptor transfer. The harness has socketpair inheritance tests and netlink `sendmsg`/`recvmsg` coverage (`main.rs:2494`, `main.rs:2642-2699`, `main.rs:3572-3840`, `main.rs:4421-4545`), but a grep found no `SCM_RIGHTS` protocol or helper path. `UnixListening.path` payload assertions are also weak (`protocol-coverage.md:31-33`, `:52`).

### what's missing

The coordinator cannot construct a Unix-domain connection, send a real fd in ancillary data, receive it in another process/agent, and perform I/O/stat assertions on the received fd. This is distinct from inheriting fds across fork+exec: it tests dynamic fd transfer over a live UDS connection, a common IPC pattern in Node and terminal host components.

### proposed `Command` / `Response` shape

A minimal high-signal protocol can avoid generic fd handles at first by passing predeclared fd kinds:

```rust
pub type FdHandle = u64;

pub enum FdSource {
    TempFile { contents: Vec<u8> },
    PipeReadWithWriter { contents: Vec<u8> },
    PipeWriteExpectRead,
    TcpListener { port: u16 },
}

pub enum Command {
    FdCreate { source: FdSource },
    UnixSocketPair,
    ScmSendFd { socket: FdHandle, fd: FdHandle, tag: String },
    ScmRecvFd { socket: FdHandle, timeout_ms: u64 },
    FdRead { fd: FdHandle, max_bytes: usize },
    FdWrite { fd: FdHandle, data: Vec<u8> },
    FdClose { fd: FdHandle },
}

pub enum Response {
    FdCreated { fd: FdHandle },
    SocketPair { left: FdHandle, right: FdHandle },
    FdReceived { fd: FdHandle, tag: String, rights_count: usize },
    FdData { data: Vec<u8>, eof: bool },
    Ok { data: Option<String> },
    Error { error: String },
}
```

A narrower first pass could be a single `UnixScmRightsRoundTrip { payload } -> Ok { data }` command, but that would repeat the `NetHalfCloseEcho` one-shot problem. Handles are preferable because they allow multi-step send/recv/use/close sequencing.

### example test sketch

```rust
let pair = expect_socket_pair(send(A, Command::UnixSocketPair).await);
let fd = expect_fd(send(A, Command::FdCreate { source: FdSource::TempFile { contents: b"rights".to_vec() } }).await);
assert_ok(send(A, Command::ScmSendFd { socket: pair.left, fd, tag: "file".into() }).await);
let got = expect_fd_received(send(B, Command::ScmRecvFd { socket: pair.right, timeout_ms: 5000 }).await);
let data = expect_fd_data(send(B, Command::FdRead { fd: got.fd, max_bytes: 64 }).await);
assert_eq!(data.data, b"rights");
```

Cross-agent execution may require `UnixSocketPair` endpoints to be inherited or routed; if that is too much for the first cut, start same-agent and child-inherited, then extend across agents.

### scoring

- impact: **VS-Code blocker**
- effort: **M/L**
- dead-variant cross-reference: overlaps with weak `UnixListening.path` assertions only indirectly; no current dead fd-passing variant exists.

## 4. `Exec.env`

### current state

`Command::Exec` exists with `args`, `timeout_secs`, `stdin`, and `background` fields (`protocol.rs:146-160`). It does **not** have an `env` field. The implementation correspondingly builds `tokio::process::Command`, sets args and stdio, but never calls `env`, `envs`, or `env_clear` (`agent.rs:455-515`). `EnvGet` exists (`protocol.rs:162-164`, `agent.rs:575-578`) but only reads the agent's own environment.

### what's missing

Tests cannot express "exec this process with these environment changes and assert the child sees them" without writing shell wrappers or helper-specific command-line encodings. Env propagation to Node/VS Code child processes is a practical regression surface: `PATH`, `HOME`, `SHELL`, `TERM`, locale, and VS Code server variables can affect startup behavior.

### proposed `Command` / `Response` shape

```rust
pub enum EnvMode {
    Inherit,
    Clear,
}

pub enum Command {
    Exec {
        args: Vec<String>,
        #[serde(default)]
        timeout_secs: Option<u64>,
        #[serde(default)]
        stdin: Option<String>,
        #[serde(default)]
        background: bool,
        #[serde(default)]
        env: Vec<(String, String)>,
        #[serde(default)]
        env_remove: Vec<String>,
        #[serde(default)]
        env_mode: Option<EnvMode>,
    },
}
```

`Response::ExecResult` is sufficient if tests assert stdout/stderr/exit code. Backwards compatibility is straightforward through serde defaults.

### example test sketch

```rust
let resp = send(A, Command::Exec {
    args: vec![self_exe, "env-dump".into(), "LITEBOX_ENV_PROBE".into()],
    timeout_secs: Some(5),
    stdin: None,
    background: false,
    env: vec![("LITEBOX_ENV_PROBE".into(), "child-only".into())],
    env_remove: vec!["SHOULD_NOT_EXIST".into()],
    env_mode: Some(EnvMode::Inherit),
}).await;
assert!(matches!(resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() == "child-only"));
```

### scoring

- impact: **regression-risk**
- effort: **S**
- dead-variant cross-reference: no dead variant; this complements healthy but indirect `EnvGet` coverage (`protocol-coverage.md:29`).

## 5. Signals beyond `Kill`

### current state

The protocol has only `Kill { pid: u32 }` (`protocol.rs:182-184`). The agent uses `start_kill()` for tracked background children and falls back to `libc::kill(pid, SIGKILL)` for untracked pids (`agent.rs:791-806`). Existing coordinator uses are mostly cleanup, and responses are often ignored (`protocol-coverage.md:34`).

### what's missing

There is no way to:

- start a helper that installs a signal handler and reports readiness;
- send arbitrary signals (`SIGUSR1`, `SIGTERM`, `SIGCHLD`, `SIGHUP`, signal 0 probes);
- assert signal delivery count/order;
- assert child reaping/`SIGCHLD` behavior without embedding custom logic in `Exec` helpers;
- test process-group signal delivery, which matters for PTY foreground groups and terminal job control.

### proposed `Command` / `Response` shape

```rust
pub type SignalHandle = u64;

pub enum SignalTarget {
    Pid(u32),
    ProcessGroup(i32),
    Agent,
}

pub enum Command {
    SignalTrapStart {
        signals: Vec<i32>,
        #[serde(default)]
        process_group: bool,
    },
    SignalSend { target: SignalTarget, signal: i32 },
    SignalWait {
        handle: SignalHandle,
        count: usize,
        timeout_ms: u64,
    },
    SignalClose { handle: SignalHandle },
}

pub enum Response {
    SignalTrapReady { handle: SignalHandle, pid: u32, pgrp: i32 },
    SignalDelivered { signal: i32, ordinal: usize },
    SignalEvents { signals: Vec<i32> },
    Ok { data: Option<String> },
    Error { error: String },
}
```

The trap should be a helper subprocess, not the long-lived agent process, to avoid destabilizing protocol I/O with process-wide signal handlers. Linux implementations could use `sigaction` or `signalfd`; the surface should assert observable delivery, not implementation details.

### example test sketch

```rust
let trap = expect_trap(send(A, Command::SignalTrapStart { signals: vec![libc::SIGUSR1, libc::SIGTERM], process_group: false }).await);
assert_ok(send(B, Command::SignalSend { target: SignalTarget::Pid(trap.pid), signal: libc::SIGUSR1 }).await);
assert_ok(send(B, Command::SignalSend { target: SignalTarget::Pid(trap.pid), signal: libc::SIGTERM }).await);
let events = expect_events(send(A, Command::SignalWait { handle: trap.handle, count: 2, timeout_ms: 5000 }).await);
assert_eq!(events.signals, vec![libc::SIGUSR1, libc::SIGTERM]);
```

### scoring

- impact: **regression-risk**
- effort: **M**
- dead-variant cross-reference: current `Kill` is healthy by count but weak as a behavior assertion. This addition should not reuse `Kill`; keep `Kill` as cleanup and add explicit signal-test semantics.

## 6. Stateful TCP connection registry vs one-shot `NetHalfCloseEcho`

### current state

`NetHalfCloseEcho` is a one-shot command: connect, write data, call `shutdown` on `wr`/`rd`/`rdwr`, then read echoed data until EOF (`protocol.rs:132-140`, `agent.rs:413-440`). It has one coordinator callsite and `Response::HalfClosed` has one assertion (`protocol-coverage.md:26`, `:54`). `Response::HalfCloseFailed` is dead in coordinator assertions (`protocol-coverage.md:55`) even though the agent returns it on errors/timeouts (`agent.rs:427-439`).

### what's missing

The atomic shape is useful for one EOF regression, but it cannot express:

- multi-recv reads where EOF timing matters;
- send-recv-send sequences;
- shutdown read half before write half;
- checking EPIPE/ECONNRESET after peer close;
- interleaving file I/O or process events between TCP operations;
- multiple concurrent open connections whose state is inspected step by step.

Keep `NetHalfCloseEcho` only as a compatibility/helper shortcut, but add a connection registry for new tests.

### proposed `Command` / `Response` shape

```rust
pub type ConnId = u64;

pub enum ShutdownHalf {
    Read,
    Write,
    Both,
}

pub enum Command {
    NetOpen { addr: String },
    NetSend { conn: ConnId, data: Vec<u8> },
    NetRecv {
        conn: ConnId,
        #[serde(default)]
        n_bytes: Option<usize>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    NetShutdown { conn: ConnId, half: ShutdownHalf },
    NetClose { conn: ConnId },
}

pub enum Response {
    NetOpened { conn: ConnId, local_addr: String, peer_addr: String },
    Sent { conn: ConnId, bytes: usize },
    Received { conn: ConnId, data: Vec<u8>, eof: bool },
    Ok { data: Option<String> },
    ConnectFailed { error: String },
    Error { error: String },
}
```

Do **not** put an optional echo into `NetSend`: echo is server behavior and should be observed with `NetRecv`. Keeping send and receive separate is what fixes the current expressiveness gap.

### example test sketch

```rust
assert_listening(send(A, Command::NetListen { port }).await);
let conn = expect_open(send(B, Command::NetOpen { addr: format!("127.0.0.1:{port}") }).await);
assert_sent(send(B, Command::NetSend { conn, data: b"one".to_vec() }).await, 3);
assert_eq!(expect_recv(send(B, Command::NetRecv { conn, n_bytes: Some(3), timeout_ms: Some(5000) }).await).data, b"one");
assert_sent(send(B, Command::NetSend { conn, data: b"two".to_vec() }).await, 3);
assert_eq!(expect_recv(send(B, Command::NetRecv { conn, n_bytes: Some(3), timeout_ms: Some(5000) }).await).data, b"two");
assert_ok(send(B, Command::NetShutdown { conn, half: ShutdownHalf::Write }).await);
let eof = expect_recv(send(B, Command::NetRecv { conn, n_bytes: None, timeout_ms: Some(5000) }).await);
assert!(eof.eof);
assert_ok(send(B, Command::NetClose { conn }).await);
```

### scoring

- impact: **regression-risk**
- effort: **M**
- dead-variant cross-reference: complete/assert `HalfCloseFailed` if keeping the one-shot command; otherwise remove it after equivalent negative cases are covered by `NetOpen`/`NetSend`/`NetRecv`/`NetShutdown`.

## 7. Background readiness / state-wait protocol surface

### current state

This is primarily covered by `audit-synchronization-primitives`, but it is also a protocol-surface gap visible while reading `Exec`. Foreground `Exec` waits for process exit; background `Exec` returns a PID immediately and redirects stdout/stderr to null (`agent.rs:478-493`). Several tests therefore start helper servers with sleeps before connecting. `synchronization-primitives.md:53-59` recommends `ExecReady`/`WaitReady` and `WaitFor` predicates.

### what's missing

The protocol cannot wait for a background helper's readiness line, file predicate, pid/cmdline predicate, TCP connectability, or Unix socket connectability. This makes some VS-Code-relevant helper tests timer-driven rather than signal-driven, violating `CLAUDE.md:106-107`.

### proposed `Command` / `Response` shape

```rust
pub enum ReadySource {
    StdoutLine(String),
    StderrLine(String),
}

pub enum WaitPredicate {
    FileExists { path: String },
    FileContains { path: String, needle: String },
    PidExists { pid: u32 },
    CmdlineContains { pid: u32, needle: String },
    TcpConnectable { addr: String },
    UnixSocketConnectable { path: String },
}

pub enum Command {
    ExecReady {
        args: Vec<String>,
        ready: ReadySource,
        timeout_secs: u64,
        #[serde(default)]
        env: Vec<(String, String)>,
    },
    WaitFor { predicate: WaitPredicate, timeout_ms: u64 },
}

pub enum Response {
    Background { pid: u32 },
    Ok { data: Option<String> },
    Error { error: String },
}
```

### example test sketch

```rust
let bg = expect_background(send(A, Command::ExecReady {
    args: vec![self_exe, "tcp-echo".into(), port.to_string()],
    ready: ReadySource::StderrLine("listening".into()),
    timeout_secs: 5,
    env: vec![],
}).await);
assert_eq!(expect_connected(send(B, Command::NetConnect { addr, data: "ready".into() }).await).echo, "ready");
send(A, Command::Kill { pid: bg.pid }).await;
```

### scoring

- impact: **regression-risk**
- effort: **M**
- dead-variant cross-reference: `Go` is a dead immediate ack and should not be stretched into this; either remove `Go` or keep it only if a real barrier semantics is designed.

## 8. Dead/half-finished variants and weak payloads to reconcile

### current state

From `protocol-coverage.md`:

- dead commands: `NetAccept`, `NetCloseListener`, `Go` (`protocol-coverage.md:14-15`, `:42`, `:73`);
- dead responses: `HalfCloseFailed`, `TestResult` (`protocol-coverage.md:55`, `:61`);
- weak payload assertions: `Listening.port`, `UnixListening.path`, `ConnectFailed.error`, `ExecTimeout.stderr`, much `Ok.data`, and most `ExecResult.stderr` (`protocol-coverage.md:77`).

### what's missing

Some dead variants are valuable half-finished surfaces; others are stale abstractions:

- `NetAccept` / `NetCloseListener`: **complete**, because they are the natural protocol surface for inherited-listener tests.
- `HalfCloseFailed`: **assert or fold into `Error`**. If `NetHalfCloseEcho` remains, add at least one negative test that asserts the error payload. If the connection registry replaces it, the generic `Error`/`ConnectFailed` path may be enough.
- `Go`: **remove or redesign**. It currently only returns `Ok` (`agent.rs:586-588`) and is not a barrier.
- `TestResult`: **remove unless agent-side structured reporting is revived**. Coordinator has its own `TestResult` struct (`coordinator/mod.rs:163-170`), so the protocol response appears stale.
- Weak payloads: strengthen tests while adding surfaces. For example, assert `Listening { port }` equals the requested/assigned port and assert `UnixListening { path }` equals the requested path.

### proposed `Command` / `Response` shape

No single shape; this is cleanup tied to the additions above. Prefer explicit response variants (`Forked`, `Accepted`, `FdReceived`, `PtyRead`, `SignalEvents`) over broad `Ok { data: Option<String> }` when adding new protocol areas.

### example test sketch

```rust
let resp = send(A, Command::NetListen { port: 0 }).await;
let actual = match resp {
    Response::Listening { port } if port != 0 => port,
    other => panic!("expected assigned listening port, got {other:?}"),
};

let resp = send(A, Command::UnixListen { path: sock.clone() }).await;
assert!(matches!(resp, Response::UnixListening { path } if path == sock));
```

### scoring

- impact: **cleanup** for `Go`/`TestResult`; **VS-Code blocker** for completing `NetAccept`/`NetCloseListener` because of inherited-listener coverage
- effort: **S** for deletion/assertion cleanup, **M** for the inherited-listener completion
- dead-variant cross-reference: see above; do not blanket-delete dead variants before separating stale (`Go`, `TestResult`) from half-finished (`NetAccept`, `NetCloseListener`, maybe `HalfCloseFailed`).

## Final recommendation order

1. Complete `Fork.inherit_listen_ports`, convert `NetAccept` to true inherited-listener accept, and use `NetCloseListener` in an axis-covered replacement for `FKLC.cross_connect`.
2. Add PTY commands sufficient for `openpty` + `setsid` + `TIOCSCTTY` + `TIOCSPGRP`/foreground-pgrp tests.
3. Add SCM_RIGHTS handle-based fd-passing over Unix sockets.
4. Add `Exec.env` while touching `Exec` plumbing; it is small and improves child-process reproducibility.
5. Add explicit signal testing primitives for arbitrary signal delivery and process-group behavior.
6. Add stateful TCP connection handles; keep `NetHalfCloseEcho` as a compatibility shortcut only if its failure response is asserted.
7. Reconcile dead variants and weak payload assertions as each related surface is completed.
