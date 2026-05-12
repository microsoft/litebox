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
}
