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

use super::agents::AgentName;
use super::registry::Registry;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::protocol::Response;
use crate::register_handler;

// ─── Shared canary / smoke-test helpers ──────────────────────────────────────

/// Canary / smoke-test agent triple — the three structural agents
/// used by `minimal_canary`, `vscode_shape`, and a few platform-fix tests.
pub(crate) const CANARY_AGENTS: &[AgentName] =
    &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2];

/// Generic single-string detail response wrapper. Used by handlers
/// that return a human-readable status string and rely on the test
/// closure to pass/fail-classify by substring match.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DetailOut {
    pub(crate) detail: String,
}

/// Map a binary type to the spawn-tree label that selects it as a
/// fork target (`"self"`, `"nonpie"`, etc.).
pub(crate) fn fork_binary_label(bt: crate::BinaryType) -> &'static str {
    match bt {
        crate::BinaryType::PieGlibc => "self",
        crate::BinaryType::NonPieGlibc => "nonpie",
        crate::BinaryType::StaticPieGlibc => "static-pie-glibc",
        crate::BinaryType::StaticPieMusl => "static-pie-musl",
        crate::BinaryType::NonPieStaticMusl => "non-pie-static-musl",
    }
}

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
    if let (Some(payload), Some(mut stdin)) = (stdin_payload, child.stdin.take()) {
        use tokio::io::AsyncWriteExt;
        let _ = stdin.write_all(payload.as_bytes()).await;
        drop(stdin);
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

#[derive(Serialize, Deserialize)]
pub(crate) struct EchoTestArgs {}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct EchoTestOut {
    pub(crate) msg: String,
}

pub(crate) const ECHO_TEST: HandlerToken<EchoTestArgs, EchoTestOut> =
    HandlerToken::new("common.echo_test");

async fn handle_echo_test(
    _args: EchoTestArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EchoTestOut, HandlerError> {
    Ok(EchoTestOut {
        msg: "ECHO_TEST_OK".into(),
    })
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ExitWithArgs {
    pub(crate) code: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ExitWithOut {
    pub(crate) effective_code: i32,
}

pub(crate) const EXIT_WITH: HandlerToken<ExitWithArgs, ExitWithOut> =
    HandlerToken::new("common.exit_with");

async fn handle_exit_with(
    args: ExitWithArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ExitWithOut, HandlerError> {
    std::process::exit(args.code);
}

#[derive(Serialize, Deserialize)]
pub(crate) struct WriteThenExitArgs {
    pub(crate) size: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WriteThenExitOut {
    pub(crate) data: Vec<u8>,
}

pub(crate) const WRITE_THEN_EXIT: HandlerToken<WriteThenExitArgs, WriteThenExitOut> =
    HandlerToken::new("common.write_then_exit");

async fn handle_write_then_exit(
    args: WriteThenExitArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<WriteThenExitOut, HandlerError> {
    let pattern = b"ABCDEFGHIJKLMNOP";
    let mut data = Vec::with_capacity(args.size);
    while data.len() < args.size {
        let chunk = (args.size - data.len()).min(pattern.len());
        data.extend_from_slice(&pattern[..chunk]);
    }
    Ok(WriteThenExitOut { data })
}

#[derive(Serialize, Deserialize)]
pub(crate) struct WriteKnownArgs {
    pub(crate) tag: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WriteKnownOut {
    pub(crate) line: String,
}

pub(crate) const WRITE_KNOWN: HandlerToken<WriteKnownArgs, WriteKnownOut> =
    HandlerToken::new("common.write_known");

async fn handle_write_known(
    args: WriteKnownArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<WriteKnownOut, HandlerError> {
    Ok(WriteKnownOut {
        line: format!("PIPEDATA:{}", args.tag),
    })
}

#[derive(Serialize, Deserialize)]
pub(crate) struct EchoExitArgs {}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct EchoExitOut {
    pub(crate) line: String,
}

pub(crate) const ECHO_EXIT: HandlerToken<EchoExitArgs, EchoExitOut> =
    HandlerToken::new("common.echo_exit");

async fn handle_echo_exit(
    _args: EchoExitArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EchoExitOut, HandlerError> {
    Ok(EchoExitOut {
        line: "PIPE_CHILD_DATA".into(),
    })
}

#[derive(Serialize, Deserialize)]
pub(crate) struct DoWriteArgs {
    pub(crate) path: String,
    pub(crate) data: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DoWriteOut {
    pub(crate) bytes_written: usize,
}

pub(crate) const DO_WRITE: HandlerToken<DoWriteArgs, DoWriteOut> =
    HandlerToken::new("common.do_write");

async fn handle_do_write(
    args: DoWriteArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DoWriteOut, HandlerError> {
    std::fs::write(&args.path, args.data.as_bytes())
        .map_err(|e| HandlerError::from(format!("do-write {}: {e}", args.path)))?;
    Ok(DoWriteOut {
        bytes_written: args.data.len(),
    })
}

#[derive(Serialize, Deserialize)]
pub(crate) struct DoWriteSleepArgs {
    pub(crate) path: String,
    pub(crate) data: String,
    pub(crate) sleep_secs: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DoWriteSleepOut {
    pub(crate) bytes_written: usize,
}

pub(crate) const DO_WRITE_SLEEP: HandlerToken<DoWriteSleepArgs, DoWriteSleepOut> =
    HandlerToken::new("common.do_write_sleep");

async fn handle_do_write_sleep(
    args: DoWriteSleepArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DoWriteSleepOut, HandlerError> {
    std::fs::write(&args.path, args.data.as_bytes())
        .map_err(|e| HandlerError::from(format!("do-write-sleep {}: {e}", args.path)))?;
    std::thread::sleep(Duration::from_secs(args.sleep_secs));
    Ok(DoWriteSleepOut {
        bytes_written: args.data.len(),
    })
}

#[derive(Serialize, Deserialize)]
pub(crate) struct WriteOnFdArgs {
    pub(crate) fds: Vec<i32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WriteOnFdOut {
    pub(crate) attempted: usize,
    pub(crate) failed: usize,
}

pub(crate) const WRITE_ON_FD: HandlerToken<WriteOnFdArgs, WriteOnFdOut> =
    HandlerToken::new("common.write_on_fd");

async fn handle_write_on_fd(
    args: WriteOnFdArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<WriteOnFdOut, HandlerError> {
    write_messages_on_fds(&args.fds, |fd| format!("PB_CHILD_WROTE:fd={fd}\n"))
}

#[derive(Serialize, Deserialize)]
pub(crate) struct DelayedWriteOnFdArgs {
    pub(crate) fds: Vec<i32>,
    pub(crate) delay_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DelayedWriteOnFdOut {
    pub(crate) attempted: usize,
    pub(crate) failed: usize,
}

pub(crate) const DELAYED_WRITE_ON_FD: HandlerToken<DelayedWriteOnFdArgs, DelayedWriteOnFdOut> =
    HandlerToken::new("common.delayed_write_on_fd");

async fn handle_delayed_write_on_fd(
    args: DelayedWriteOnFdArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DelayedWriteOnFdOut, HandlerError> {
    std::thread::sleep(Duration::from_millis(args.delay_ms));
    write_messages_on_fds(&args.fds, |fd| format!("PB_DELAYED_WRITE:fd={fd}\n")).map(|out| {
        DelayedWriteOnFdOut {
            attempted: out.attempted,
            failed: out.failed,
        }
    })
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ReadOnFdArgs {
    pub(crate) fd: i32,
    pub(crate) timeout_secs: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ReadOnFdOut {
    pub(crate) data: Vec<u8>,
    pub(crate) saw_expected: bool,
}

pub(crate) const READ_ON_FD: HandlerToken<ReadOnFdArgs, ReadOnFdOut> =
    HandlerToken::new("common.read_on_fd");

async fn handle_read_on_fd(
    args: ReadOnFdArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ReadOnFdOut, HandlerError> {
    let data = read_with_poll_timeout(args.fd, args.timeout_secs)?;
    // Safety: fd was provided by the test as an inherited fd and is no longer needed.
    unsafe { libc::close(args.fd) };
    let saw_expected = String::from_utf8_lossy(&data).contains("PB_PARENT_WROTE");
    Ok(ReadOnFdOut { data, saw_expected })
}

#[derive(Serialize, Deserialize)]
pub(crate) struct EchoOnFdArgs {
    pub(crate) fd: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct EchoOnFdOut {
    pub(crate) bytes_echoed: usize,
}

pub(crate) const ECHO_ON_FD: HandlerToken<EchoOnFdArgs, EchoOnFdOut> =
    HandlerToken::new("common.echo_on_fd");

async fn handle_echo_on_fd(
    args: EchoOnFdArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EchoOnFdOut, HandlerError> {
    let mut buf = [0u8; 4096];
    // Safety: fd was provided by the test as an inherited fd, and buf is valid for writes.
    let n = unsafe { libc::read(args.fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n <= 0 {
        // Safety: fd was provided by the test as an inherited fd and is no longer needed.
        unsafe { libc::close(args.fd) };
        return Err(HandlerError::from(format!(
            "echo-on-fd read: {}",
            std::io::Error::last_os_error()
        )));
    }
    let n = n.cast_unsigned();
    // Safety: fd was provided by the test as an inherited fd, and buf[..n] contains initialized data.
    let w = unsafe { libc::write(args.fd, buf.as_ptr().cast::<libc::c_void>(), n) };
    // Safety: fd was provided by the test as an inherited fd and is no longer needed.
    unsafe { libc::close(args.fd) };
    if w < 0 {
        Err(HandlerError::from(format!(
            "echo-on-fd write: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(EchoOnFdOut {
            bytes_echoed: w.cast_unsigned(),
        })
    }
}

fn write_messages_on_fds(
    fds: &[i32],
    mut message: impl FnMut(i32) -> String,
) -> Result<WriteOnFdOut, HandlerError> {
    if fds.is_empty() {
        return Err(HandlerError::from("no fds provided"));
    }
    let mut failed = 0;
    for &fd in fds {
        let msg = message(fd);
        // Safety: fd was provided by the test as an inherited fd, and msg is valid for reads.
        let n = unsafe { libc::write(fd, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        if n < 0 {
            failed += 1;
        }
        // Safety: fd was provided by the test as an inherited fd and is no longer needed.
        unsafe { libc::close(fd) };
    }
    Ok(WriteOnFdOut {
        attempted: fds.len(),
        failed,
    })
}

fn read_with_poll_timeout(fd: i32, timeout_secs: i32) -> Result<Vec<u8>, HandlerError> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout_ms = timeout_secs.saturating_mul(1000);
    // Safety: pfd points to one valid pollfd entry for the duration of the call.
    let pr = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
    if pr < 0 {
        return Err(HandlerError::from(format!(
            "poll: {}",
            std::io::Error::last_os_error()
        )));
    }
    if pr == 0 {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        // Safety: fd was provided by the test as an inherited fd, and buf is valid for writes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n > 0 {
            let n = n.cast_unsigned();
            out.extend_from_slice(&buf[..n]);
            if n < buf.len() {
                break;
            }
        } else {
            break;
        }
    }
    Ok(out)
}

mod leaf_subcmd {
    //! Argv-dispatched leaf programs that cannot be handlers because
    //! they verify fresh-process stdio inheritance — an agent's stdin
    //! and stdout are the protocol pipe, not the parent's inherited fds.

    pub(super) fn subcmd_large_stdout_test(args: &[String]) -> i32 {
        let n_bytes: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(65536);
        let chunk = b"X".repeat(64);
        let mut written = 0;
        while written < n_bytes {
            let want = (n_bytes - written).min(chunk.len());
            // Safety: fd 1 is stdout and chunk[..want] is valid for reads.
            let r = unsafe { libc::write(1, chunk.as_ptr().cast::<libc::c_void>(), want) };
            if r <= 0 {
                break;
            }
            written += r.cast_unsigned();
        }
        let trailer = format!("\nLARGE_STDOUT_OK n={written}\n");
        // Safety: fd 1 is stdout and trailer bytes are valid for reads.
        let _ = unsafe { libc::write(1, trailer.as_ptr().cast::<libc::c_void>(), trailer.len()) };
        0
    }

    pub(super) fn subcmd_stderr_only_test(_args: &[String]) -> i32 {
        eprintln!("STDERR_ONLY_OK");
        0
    }

    pub(super) fn subcmd_stdin_echo_test(_args: &[String]) -> i32 {
        let mut buf = [0u8; 4096];
        // Safety: fd 0 is stdin and buf is valid for writes.
        let n = unsafe { libc::read(0, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n > 0 {
            // Safety: fd 1 is stdout and buf[..n] contains initialized data.
            let _ =
                unsafe { libc::write(1, buf.as_ptr().cast::<libc::c_void>(), n.cast_unsigned()) };
        }
        0
    }

    /// Print "ECHO_TEST_OK" and exit. Argv-reachable counterpart of
    /// the [`super::ECHO_TEST`] handler — needed when a test invokes
    /// this leaf via `common::BASH` (bash inside the pipeline can only
    /// `exec` an argv subcommand, not call a handler).
    pub(super) fn subcmd_echo_test(_args: &[String]) -> i32 {
        println!("ECHO_TEST_OK");
        0
    }

    /// Argv counterpart of [`super::WRITE_KNOWN`]. See echo_test note.
    pub(super) fn subcmd_write_known(args: &[String]) -> i32 {
        let tag = args.get(2).map_or("default", String::as_str);
        println!("PIPEDATA:{tag}");
        0
    }

    /// Argv counterpart of [`super::EXIT_WITH`]. See echo_test note.
    /// Exits with the requested code via `std::process::exit` so the
    /// parent observes the exact exit code (the same semantic the
    /// handler form preserves by calling `std::process::exit` inside
    /// its handler body).
    pub(super) fn subcmd_exit_with(args: &[String]) -> i32 {
        let code: i32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        std::process::exit(code);
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
    register_handler!(ECHO_TEST, handle_echo_test);
    register_handler!(EXIT_WITH, handle_exit_with);
    register_handler!(WRITE_THEN_EXIT, handle_write_then_exit);
    register_handler!(WRITE_KNOWN, handle_write_known);
    register_handler!(ECHO_EXIT, handle_echo_exit);
    register_handler!(DO_WRITE, handle_do_write);
    register_handler!(DO_WRITE_SLEEP, handle_do_write_sleep);
    register_handler!(WRITE_ON_FD, handle_write_on_fd);
    register_handler!(DELAYED_WRITE_ON_FD, handle_delayed_write_on_fd);
    register_handler!(READ_ON_FD, handle_read_on_fd);
    register_handler!(ECHO_ON_FD, handle_echo_on_fd);

    crate::register_leaf_subcommand!("large-stdout-test", leaf_subcmd::subcmd_large_stdout_test);
    crate::register_leaf_subcommand!("stderr-only-test", leaf_subcmd::subcmd_stderr_only_test);
    crate::register_leaf_subcommand!("stdin-echo-test", leaf_subcmd::subcmd_stdin_echo_test);
    // Argv counterparts of the simple handlers above, needed for tests
    // that invoke these leaves via `common::BASH` pipelines (where bash
    // can only `exec` argv subcommands).
    crate::register_leaf_subcommand!("echo-test", leaf_subcmd::subcmd_echo_test);
    crate::register_leaf_subcommand!("write-known", leaf_subcmd::subcmd_write_known);
    crate::register_leaf_subcommand!("exit-with", leaf_subcmd::subcmd_exit_with);
}

// ═══════════════════════════════════════════════════════════════════
// M1-M4 / BS1-BS3: Minimal canary repros for SpawnRemote/non-PIE bug
// ═══════════════════════════════════════════════════════════════════
//
// These are the minimal repros for the wave-0 canary cascade. The
// canary itself runs `Exec [self_exe, "echo-test"]` on agent A. It
// times out under litebox not because echo-test is broken, but
// because spawn_tree's earlier SpawnRemote NP call killed agent A
// as a side effect.
//
// Each M test runs as `Exec [self_exe, "M{N}-..."]` from a launcher
// agent. The M subprocess then spawns a non-PIE child via the
// indicated mechanism and verifies the parent process is still
// alive after wait. If the parent dies before printing M{N}_OK,
// the launcher's Exec times out or returns a bad exit code, and
// the test FAILs.
//
// Matrix: 4 M variants × 5 launchers (A, AA, D3, D4, D5):
//   - A, AA, D3, D5 are PIE — they exec a PIE M-subprocess. The
//     canary mechanism (PIE process tokio runtime spawning non-PIE
//     child) is reproduced inside the M subprocess.
//   - D4 is non-PIE — it execs a non-PIE M-subprocess. This tests
//     the related non-PIE → non-PIE spawn path.
//
// Native must pass all 20 tests.

pub(crate) fn register_minimal_canary_tests(reg: &mut Registry<'_>) {
    use super::matrix::{EXEC, ExecArgs};

    // Register the M1-M4 + BS1-BS3 leaf subcommands. These stay as
    // argv subcommands (not handlers) because they test fresh-process
    // stdio inheritance across fork+exec; bodies live in
    // `mod canary_leaf_subcmd` below.
    crate::register_leaf_subcommand!(
        "M1-tokio-spawn-nonpie",
        canary_leaf_subcmd::subcmd_m1_tokio_spawn_nonpie
    );
    crate::register_leaf_subcommand!(
        "M2-libc-spawn-nonpie",
        canary_leaf_subcmd::subcmd_m2_libc_spawn_nonpie
    );
    crate::register_leaf_subcommand!(
        "M3-tokio-spawn-nonpie-then-work",
        canary_leaf_subcmd::subcmd_m3_tokio_spawn_nonpie_then_work
    );
    crate::register_leaf_subcommand!(
        "M4-tokio-spawn-nonpie-repeated",
        canary_leaf_subcmd::subcmd_m4_tokio_spawn_nonpie_repeated
    );
    crate::register_leaf_subcommand!(
        "BS1-tokio-spawn-nonpie-stderr",
        canary_leaf_subcmd::subcmd_bs1_tokio_spawn_nonpie_stderr
    );
    crate::register_leaf_subcommand!(
        "BS2-tokio-spawn-nonpie-stdin-echo",
        canary_leaf_subcmd::subcmd_bs2_tokio_spawn_nonpie_stdin_echo
    );
    crate::register_leaf_subcommand!(
        "BS3-tokio-spawn-nonpie-large-stdout",
        canary_leaf_subcmd::subcmd_bs3_tokio_spawn_nonpie_large_stdout
    );

    const M_LAUNCHERS: &[AgentName] = &[
        AgentName::Dpg1,
        AgentName::Dpg1Dpg1,
        AgentName::Dpg1Dpg1Dpg1,
        AgentName::Dpg1Dng,
        AgentName::Dpg1DngDpg,
    ];
    const M_VARIANTS: &[(&str, &str, &str, u64)] = &[
        // (id_prefix, subcommand, expected_stdout_marker, exec_timeout_secs)
        ("M1", "M1-tokio-spawn-nonpie", "M1_OK", 30),
        ("M2", "M2-libc-spawn-nonpie", "M2_OK", 30),
        ("M3", "M3-tokio-spawn-nonpie-then-work", "M3_OK", 30),
        ("M4", "M4-tokio-spawn-nonpie-repeated", "M4_OK", 60),
        // BS-variants: minimal stdio-direction repros for Bug B.
        // Same matrix shape as M1-M4. See main.rs comments for what
        // each subcommand exercises.
        ("BS1", "BS1-tokio-spawn-nonpie-stderr", "BS1_OK", 30),
        ("BS2", "BS2-tokio-spawn-nonpie-stdin-echo", "BS2_OK", 30),
        ("BS3", "BS3-tokio-spawn-nonpie-large-stdout", "BS3_OK", 30),
    ];

    for &launcher in M_LAUNCHERS {
        for &(id_prefix, subcommand, marker, timeout_secs) in M_VARIANTS {
            for &target_bt in crate::BinaryType::ALL {
                let launcher_s = launcher.to_string();
                let subcommand_s: String = subcommand.into();
                let marker_s: String = marker.into();
                let target_label = target_bt.label();
                let test_id = format!("{id_prefix}.{launcher_s}.{target_label}");
                reg.test("fork", "minimal_canary", test_id)
                    .timeout(timeout_secs + 10)
                    .build(move |cx| {
                        let handle = cx.require(launcher);
                        Box::new(move |run| {
                            let l = launcher_s.clone();
                            let sc = subcommand_s.clone();
                            let m = marker_s.clone();
                            let self_exe = run.self_exe().to_string();
                            Box::pin(async move {
                                let target = crate::binary_path(target_bt, &self_exe);
                                let resp = run
                                    .typed_or_error(
                                        &handle,
                                        &EXEC,
                                        ExecArgs {
                                            args: vec![self_exe, sc],
                                            timeout_secs: Some(timeout_secs),
                                            stdin: None,
                                            background: false,
                                            env: vec![("LITEBOX_M_TARGET_BINARY".into(), target)],
                                        },
                                    )
                                    .await;
                                let pass = matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if stdout.contains(m.as_str())
                                );
                                super::TestOutcome::new(&l, pass, format!("{resp:?}"))
                            })
                        })
                    });
            }
        }
    }
}

#[allow(
    clippy::items_after_statements,
    clippy::ptr_as_ptr,
    clippy::cast_sign_loss
)]
mod canary_leaf_subcmd {
    fn m_target_binary() -> String {
        if let Ok(p) = std::env::var("LITEBOX_M_TARGET_BINARY")
            && !p.is_empty()
        {
            return p;
        }
        crate::nonpie_binary()
    }

    pub(super) fn subcmd_m1_tokio_spawn_nonpie(_args: &[String]) -> i32 {
        let nonpie = m_target_binary();
        let parent_pid = std::process::id();
        eprintln!("[M1] pid={parent_pid} spawning nonpie={nonpie}");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let result: Result<(), String> = rt.block_on(async {
            let out = tokio::process::Command::new(&nonpie)
                .arg("echo-test")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await
                .map_err(|e| format!("spawn: {e}"))?;
            if !out.status.success() {
                return Err(format!("child exit: {:?}", out.status));
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            if !stdout.contains("ECHO_TEST_OK") {
                return Err(format!("child stdout missing ECHO_TEST_OK: {stdout:?}"));
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                eprintln!("[M1] pid={parent_pid} child OK, parent surviving");
                println!("M1_OK pid={parent_pid}");
            }
            Err(e) => {
                eprintln!("[M1] pid={parent_pid} FAIL: {e}");
                println!("M1_FAIL:{e}");
                std::process::exit(1);
            }
        }
        0
    }

    pub(super) fn subcmd_m2_libc_spawn_nonpie(_args: &[String]) -> i32 {
        let nonpie = m_target_binary();
        let parent_pid = std::process::id();
        eprintln!("[M2] pid={parent_pid} libc fork+execve nonpie={nonpie}");

        let mut pipefd = [-1i32; 2];
        if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
            println!("M2_FAIL:pipe");
            std::process::exit(1);
        }
        let pipe_r = pipefd[0];
        let pipe_w = pipefd[1];

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("M2_FAIL:fork");
            std::process::exit(1);
        }
        if pid == 0 {
            unsafe {
                libc::dup2(pipe_w, 1);
                libc::close(pipe_r);
                libc::close(pipe_w);
            }
            use std::ffi::CString;
            let bin = CString::new(nonpie.as_str()).unwrap();
            let arg_sub = CString::new("echo-test").unwrap();
            let argv = [bin.as_ptr(), arg_sub.as_ptr(), core::ptr::null()];
            unsafe { libc::execv(bin.as_ptr(), argv.as_ptr()) };
            std::process::exit(127);
        }
        unsafe { libc::close(pipe_w) };
        let mut buf = [0u8; 4096];
        let n = unsafe { libc::read(pipe_r, buf.as_mut_ptr() as *mut _, buf.len()) };
        unsafe { libc::close(pipe_r) };
        let mut status = 0i32;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            let ret = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
            if ret > 0 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                unsafe { libc::kill(pid, libc::SIGKILL) };
                unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
                println!("M2_FAIL:wait_timeout");
                std::process::exit(1);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            println!("M2_FAIL:child_status={status}");
            std::process::exit(1);
        }
        if n <= 0 {
            println!("M2_FAIL:no_child_stdout");
            std::process::exit(1);
        }
        let out = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
        if !out.contains("ECHO_TEST_OK") {
            println!("M2_FAIL:bad_stdout:{out:?}");
            std::process::exit(1);
        }
        eprintln!("[M2] pid={parent_pid} child OK, parent surviving");
        println!("M2_OK pid={parent_pid}");
        0
    }

    pub(super) fn subcmd_m3_tokio_spawn_nonpie_then_work(_args: &[String]) -> i32 {
        let nonpie = m_target_binary();
        let parent_pid = std::process::id();
        eprintln!("[M3] pid={parent_pid} step 1: spawn nonpie");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let m1_result: Result<(), String> = rt.block_on(async {
            let out = tokio::process::Command::new(&nonpie)
                .arg("echo-test")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await
                .map_err(|e| format!("spawn: {e}"))?;
            if !out.status.success() {
                return Err(format!("child exit: {:?}", out.status));
            }
            Ok(())
        });
        if let Err(e) = m1_result {
            println!("M3_FAIL:step1:{e}");
            std::process::exit(1);
        }
        eprintln!("[M3] pid={parent_pid} step 2: post-spawn work");
        drop(rt);
        let stat = std::fs::read_to_string("/proc/self/stat")
            .map_err(|e| format!("read /proc/self/stat: {e}"));
        let scratch = format!("/tmp/m3-{parent_pid}.txt");
        let write_res = std::fs::write(&scratch, b"M3_PARENT_ALIVE\n")
            .map_err(|e| format!("write {scratch}: {e}"));
        let read_back =
            std::fs::read_to_string(&scratch).map_err(|e| format!("read {scratch}: {e}"));
        let _ = std::fs::remove_file(&scratch);
        match (stat, write_res, read_back) {
            (Ok(_), Ok(()), Ok(s)) if s.contains("M3_PARENT_ALIVE") => {
                eprintln!("[M3] pid={parent_pid} step 2 OK");
                println!("M3_OK pid={parent_pid}");
            }
            (s, w, r) => {
                println!("M3_FAIL:step2:stat={s:?},write={w:?},read={r:?}");
                std::process::exit(1);
            }
        }
        0
    }

    pub(super) fn subcmd_m4_tokio_spawn_nonpie_repeated(args: &[String]) -> i32 {
        let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
        let nonpie = m_target_binary();
        let parent_pid = std::process::id();
        eprintln!("[M4] pid={parent_pid} N={n} spawning nonpie={nonpie}");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let result: Result<usize, String> = rt.block_on(async {
            for i in 0..n {
                let out = tokio::process::Command::new(&nonpie)
                    .arg("echo-test")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .output()
                    .await
                    .map_err(|e| format!("spawn iter={i}: {e}"))?;
                if !out.status.success() {
                    return Err(format!("iter={i} child exit: {:?}", out.status));
                }
                let stdout = String::from_utf8_lossy(&out.stdout);
                if !stdout.contains("ECHO_TEST_OK") {
                    return Err(format!("iter={i} bad stdout: {stdout:?}"));
                }
                eprintln!("[M4] pid={parent_pid} iter={i} OK");
            }
            Ok(n)
        });
        match result {
            Ok(k) => {
                eprintln!("[M4] pid={parent_pid} all {k} iterations OK");
                println!("M4_OK pid={parent_pid} iterations={k}");
            }
            Err(e) => {
                println!("M4_FAIL:{e}");
                std::process::exit(1);
            }
        }
        0
    }

    pub(super) fn subcmd_bs1_tokio_spawn_nonpie_stderr(_args: &[String]) -> i32 {
        let nonpie = m_target_binary();
        let parent_pid = std::process::id();
        eprintln!("[BS1] pid={parent_pid} spawning nonpie={nonpie} stderr-only-test");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let result: Result<(), String> = rt.block_on(async {
            let out = tokio::process::Command::new(&nonpie)
                .arg("stderr-only-test")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await
                .map_err(|e| format!("spawn: {e}"))?;
            if !out.status.success() {
                return Err(format!("child exit: {:?}", out.status));
            }
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.contains("STDERR_ONLY_OK") {
                return Err(format!("child stderr missing STDERR_ONLY_OK: {stderr:?}"));
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                eprintln!("[BS1] pid={parent_pid} OK");
                println!("BS1_OK pid={parent_pid}");
            }
            Err(e) => {
                println!("BS1_FAIL:{e}");
                std::process::exit(1);
            }
        }
        0
    }

    pub(super) fn subcmd_bs2_tokio_spawn_nonpie_stdin_echo(_args: &[String]) -> i32 {
        let nonpie = m_target_binary();
        let parent_pid = std::process::id();
        eprintln!("[BS2] pid={parent_pid} spawning nonpie={nonpie} stdin-echo-test");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let result: Result<(), String> = rt.block_on(async {
            use tokio::io::AsyncWriteExt;
            let mut child = tokio::process::Command::new(&nonpie)
                .arg("stdin-echo-test")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| format!("spawn: {e}"))?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(b"BS2_PING\n")
                    .await
                    .map_err(|e| format!("write stdin: {e}"))?;
                drop(stdin);
            }
            let out = child
                .wait_with_output()
                .await
                .map_err(|e| format!("wait: {e}"))?;
            if !out.status.success() {
                return Err(format!("child exit: {:?}", out.status));
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            if !stdout.contains("BS2_PING") {
                return Err(format!("child stdout missing BS2_PING: {stdout:?}"));
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                eprintln!("[BS2] pid={parent_pid} OK");
                println!("BS2_OK pid={parent_pid}");
            }
            Err(e) => {
                println!("BS2_FAIL:{e}");
                std::process::exit(1);
            }
        }
        0
    }

    pub(super) fn subcmd_bs3_tokio_spawn_nonpie_large_stdout(_args: &[String]) -> i32 {
        let nonpie = m_target_binary();
        let parent_pid = std::process::id();
        eprintln!("[BS3] pid={parent_pid} spawning nonpie={nonpie} large-stdout-test");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let result: Result<(), String> = rt.block_on(async {
            let out = tokio::process::Command::new(&nonpie)
                .arg("large-stdout-test")
                .arg("65536")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await
                .map_err(|e| format!("spawn: {e}"))?;
            if !out.status.success() {
                return Err(format!("child exit: {:?}", out.status));
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            if !stdout.contains("LARGE_STDOUT_OK") {
                return Err(format!(
                    "child stdout missing LARGE_STDOUT_OK (got {} bytes)",
                    stdout.len()
                ));
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                eprintln!("[BS3] pid={parent_pid} OK");
                println!("BS3_OK pid={parent_pid}");
            }
            Err(e) => {
                println!("BS3_FAIL:{e}");
                std::process::exit(1);
            }
        }
        0
    }
}
