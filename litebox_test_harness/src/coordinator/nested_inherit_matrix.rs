// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Three-deep fd-inheritance matrix.
//!
//! Parallel to `inherit_matrix` (2-deep: handler → spawned child) but
//! exercises **three** generations of processes so that the middle
//! process exits while the grandchild is still running. This is the
//! shape that broke under nested-fork CoW skip (commit `5241b07c`):
//! the grandchild's glibc post-fork user-space writes clobbered the
//! parent's stack canary because the page hadn't been COWed.
//!
//! Test layout:
//!
//! 1. Grandparent (the handler, in some `Dpg1*` agent) opens an fd
//!    plus a private "status" pipe and clears CLOEXEC on the
//!    inheritable ends.
//! 2. Grandparent spawns `middle_binary` with `LITEBOX_INHERIT_FD`
//!    and `LITEBOX_STATUS_FD` env vars. `middle_binary` is the harness
//!    binary running subcommand `nested-inherit-matrix middle …`.
//! 3. Middle process `fork()`s.
//!    - Parent-of-fork: `_exit(0)` immediately (the buggy shape).
//!    - Child-of-fork: `execve` the grandchild binary with subcommand
//!      `nested-inherit-matrix grandchild …`, preserving env.
//! 4. Grandchild uses the inherited test fd, then writes `"ok\n"` (or
//!    `"err:…\n"`) to the status fd and exits.
//! 5. Grandparent waits for the middle process (must exit code 0,
//!    *not* SIGSEGV-139), then reads the status fd for the grandchild's
//!    ack with a timeout. Any `"stack smashing detected"` text in the
//!    captured stderr is also a failure.
//!
//! Sparse cross-product: grandparent ∈ 5 binary types, middle and
//! grandchild ∈ {`StaticPieGlibc`, `PieGlibc`, `NonPieGlibc`} (covers
//! PIE-vs-non-PIE and static-vs-dynamic without the full 5×5×5).

#![allow(clippy::wildcard_enum_match_arm)]
// `libc::read`/`write`/`poll` return isize; harness control flow already
// guards `n > 0` before any `as usize` conversion, and the casts cannot
// truncate within those guards.
#![allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::eventfd::EventFd;
use crate::{BinaryType, register_handler, register_leaf_subcommand};

use serde::{Deserialize, Serialize};

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;

const NESTED_PIPE: HandlerToken<NestedPipeArgs, NestedOutcome> =
    HandlerToken::new("nested_inherit_matrix.pipe");
const NESTED_EVENTFD: HandlerToken<NestedEventfdArgs, NestedOutcome> =
    HandlerToken::new("nested_inherit_matrix.eventfd");
const NESTED_BROKERFILE: HandlerToken<NestedBrokerfileArgs, NestedOutcome> =
    HandlerToken::new("nested_inherit_matrix.brokerfile");

const STATUS_OK: &[u8] = b"ok\n";

const BROKERFILE_READ_PAYLOAD: &[u8] = b"nested-read-payload";
const BROKERFILE_WRITE_PAYLOAD: &[u8] = b"nested-write-payload";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NestedSubsystem {
    Pipe,
    Eventfd,
    BrokerFile,
}

impl NestedSubsystem {
    const ALL: &'static [Self] = &[Self::Pipe, Self::Eventfd, Self::BrokerFile];

    const fn id(self) -> &'static str {
        match self {
            Self::Pipe => "pipe",
            Self::Eventfd => "eventfd",
            Self::BrokerFile => "brokerfile",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NestedOp {
    // pipe
    ParentWritesChildReads,
    ChildWritesParentReads,
    ChildCloseParentReadsEof,
    // eventfd
    EventfdRead,
    EventfdWrite,
    // brokerfile
    BrokerfileReadAtOffset0,
    BrokerfileWriteThenParentReadsBack,
}

impl NestedOp {
    const fn id(self) -> &'static str {
        match self {
            Self::ParentWritesChildReads => "parent_writes_child_reads",
            Self::ChildWritesParentReads => "child_writes_parent_reads",
            Self::ChildCloseParentReadsEof => "child_close_parent_reads_eof",
            Self::EventfdRead => "eventfd_read",
            Self::EventfdWrite => "eventfd_write",
            Self::BrokerfileReadAtOffset0 => "brokerfile_read_at_offset_0",
            Self::BrokerfileWriteThenParentReadsBack => "brokerfile_write_then_parent_reads_back",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "parent_writes_child_reads" => Self::ParentWritesChildReads,
            "child_writes_parent_reads" => Self::ChildWritesParentReads,
            "child_close_parent_reads_eof" => Self::ChildCloseParentReadsEof,
            "eventfd_read" => Self::EventfdRead,
            "eventfd_write" => Self::EventfdWrite,
            "brokerfile_read_at_offset_0" => Self::BrokerfileReadAtOffset0,
            "brokerfile_write_then_parent_reads_back" => Self::BrokerfileWriteThenParentReadsBack,
            _ => return None,
        })
    }
}

const PIPE_OPS: &[NestedOp] = &[
    NestedOp::ParentWritesChildReads,
    NestedOp::ChildWritesParentReads,
    NestedOp::ChildCloseParentReadsEof,
];
const EVENTFD_OPS: &[NestedOp] = &[NestedOp::EventfdRead, NestedOp::EventfdWrite];
const BROKERFILE_OPS: &[NestedOp] = &[
    NestedOp::BrokerfileReadAtOffset0,
    NestedOp::BrokerfileWriteThenParentReadsBack,
];

const fn ops_for(s: NestedSubsystem) -> &'static [NestedOp] {
    match s {
        NestedSubsystem::Pipe => PIPE_OPS,
        NestedSubsystem::Eventfd => EVENTFD_OPS,
        NestedSubsystem::BrokerFile => BROKERFILE_OPS,
    }
}

/// Sparse middle/child binary axis: PIE-glibc + non-PIE-glibc +
/// static-PIE-glibc covers PIE-vs-non-PIE and static-vs-dynamic.
const PARENT_CHILD_AXIS: &[BinaryType] = &[
    BinaryType::PieGlibc,
    BinaryType::NonPieGlibc,
    BinaryType::StaticPieGlibc,
];

#[derive(Debug, Clone, Copy)]
struct NestedTrial {
    subsystem: NestedSubsystem,
    op: NestedOp,
    grandparent_bt: BinaryType,
    parent_bt: BinaryType,
    child_bt: BinaryType,
}

impl NestedTrial {
    fn id(self) -> String {
        format!(
            "NESTED_INHERIT.{}.{}.{}.{}.{}",
            self.subsystem.id(),
            self.op.id(),
            self.grandparent_bt.short_label(),
            self.parent_bt.short_label(),
            self.child_bt.short_label(),
        )
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct NestedPipeArgs {
    middle_binary: String,
    grandchild_binary: String,
    op: NestedOp,
    timeout_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct NestedEventfdArgs {
    middle_binary: String,
    grandchild_binary: String,
    op: NestedOp,
    timeout_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct NestedBrokerfileArgs {
    middle_binary: String,
    grandchild_binary: String,
    op: NestedOp,
    timeout_ms: u64,
    test_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct NestedOutcome {
    exit_code: i32,
    middle_exit: i32,
    status: String,
    stderr: String,
}

pub(crate) fn register_nested_inherit_matrix_tests(reg: &mut Registry<'_>) {
    register_handler!(NESTED_PIPE, handle_nested_pipe);
    register_handler!(NESTED_EVENTFD, handle_nested_eventfd);
    register_handler!(NESTED_BROKERFILE, handle_nested_brokerfile);
    register_leaf_subcommand!("nested-inherit-matrix", leaf_subcmd::dispatch);

    for &subsystem in NestedSubsystem::ALL {
        for &op in ops_for(subsystem) {
            for &grandparent_bt in BinaryType::ALL {
                for &parent_bt in PARENT_CHILD_AXIS {
                    for &child_bt in PARENT_CHILD_AXIS {
                        register_nested_trial(
                            reg,
                            NestedTrial {
                                subsystem,
                                op,
                                grandparent_bt,
                                parent_bt,
                                child_bt,
                            },
                        );
                    }
                }
            }
        }
    }
}

const fn grandparent_agent(bt: BinaryType) -> AgentName {
    match bt {
        BinaryType::PieGlibc => AgentName::Dpg1,
        BinaryType::NonPieGlibc => AgentName::Dpg1Dng,
        BinaryType::StaticPieGlibc => AgentName::Dpg1Spg,
        BinaryType::StaticPieMusl => AgentName::Dpg1Spm,
        BinaryType::NonPieStaticMusl => AgentName::Dpg1Snm,
    }
}

#[allow(clippy::too_many_lines)]
fn register_nested_trial(reg: &mut Registry<'_>, trial: NestedTrial) {
    let id = trial.id();
    let agent = grandparent_agent(trial.grandparent_bt);
    let test = reg.test("vscode", "nested_inherit_matrix", id).timeout(30);
    test.build(move |cx| {
        let agent_handle = cx.require(agent);
        Box::new(move |run| {
            Box::pin(async move {
                let self_exe = run.self_exe().to_string();
                let middle_binary = crate::binary_path(trial.parent_bt, &self_exe);
                let grandchild_binary = crate::binary_path(trial.child_bt, &self_exe);
                let timeout_ms = 3000;
                let trial_id = trial.id();
                let result = match trial.subsystem {
                    NestedSubsystem::Pipe => {
                        run.send_named_typed(
                            &agent_handle,
                            &NESTED_PIPE,
                            NestedPipeArgs {
                                middle_binary,
                                grandchild_binary,
                                op: trial.op,
                                timeout_ms,
                            },
                        )
                        .await
                    }
                    NestedSubsystem::Eventfd => {
                        run.send_named_typed(
                            &agent_handle,
                            &NESTED_EVENTFD,
                            NestedEventfdArgs {
                                middle_binary,
                                grandchild_binary,
                                op: trial.op,
                                timeout_ms,
                            },
                        )
                        .await
                    }
                    NestedSubsystem::BrokerFile => {
                        run.send_named_typed(
                            &agent_handle,
                            &NESTED_BROKERFILE,
                            NestedBrokerfileArgs {
                                middle_binary,
                                grandchild_binary,
                                op: trial.op,
                                timeout_ms,
                                test_id: trial_id.clone(),
                            },
                        )
                        .await
                    }
                };
                match result {
                    Ok(out) if out.exit_code == 0 => TestOutcome::new(
                        agent.name(),
                        true,
                        format!("middle_exit={} status={:?}", out.middle_exit, out.status),
                    ),
                    Ok(out) => TestOutcome::new(
                        agent.name(),
                        false,
                        format!(
                            "exit_code={} middle_exit={} status={:?} stderr={:?}",
                            out.exit_code, out.middle_exit, out.status, out.stderr
                        ),
                    ),
                    Err(e) => TestOutcome::new(agent.name(), false, format!("handler: {e}")),
                }
            })
        })
    });
}

// ---------- handlers ----------

async fn handle_nested_pipe(
    args: NestedPipeArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<NestedOutcome, HandlerError> {
    let (test_read, test_write) = pipe_owned(libc::O_CLOEXEC)?;
    let (status_read, status_write) = pipe_owned(libc::O_CLOEXEC)?;

    // Choose which test-pipe end the grandchild inherits.
    let (grandchild_test_end, parent_role): (RawFd, ParentRole) = match args.op {
        NestedOp::ParentWritesChildReads => (test_read.as_raw_fd(), ParentRole::Writer),
        NestedOp::ChildWritesParentReads | NestedOp::ChildCloseParentReadsEof => {
            (test_write.as_raw_fd(), ParentRole::Reader)
        }
        _ => {
            return Err(HandlerError(format!(
                "unsupported pipe op {}",
                args.op.id()
            )));
        }
    };

    clear_cloexec(grandchild_test_end)?;
    clear_cloexec(status_write.as_raw_fd())?;

    if args.op == NestedOp::ParentWritesChildReads {
        write_all_fd(test_write.as_raw_fd(), b"ping").map_err(HandlerError)?;
    }

    let mut middle = spawn_middle(
        &args.middle_binary,
        &args.grandchild_binary,
        "pipe",
        args.op,
        grandchild_test_end,
        status_write.as_raw_fd(),
    )?;

    // Drop our copies of fds the middle / grandchild now own.
    drop(status_write);

    // The middle process is the one we waitpid()-on. It _exits(0)
    // immediately. The grandchild is reparented to init and we observe
    // it via the status pipe.
    let mut middle_error: Option<String> = None;
    match parent_role {
        ParentRole::Writer => {
            drop(test_write); // close after write; grandchild has its end
            drop(test_read);
        }
        ParentRole::Reader => match args.op {
            NestedOp::ChildWritesParentReads => {
                drop(test_write);
                if let Err(e) =
                    read_payload_with_timeout(test_read.as_raw_fd(), b"pong", args.timeout_ms)
                {
                    middle_error = Some(e.0);
                }
            }
            NestedOp::ChildCloseParentReadsEof => {
                drop(test_write);
                if let Err(e) = read_eof_with_timeout(test_read.as_raw_fd(), args.timeout_ms) {
                    middle_error = Some(e.0);
                }
            }
            _ => unreachable!(),
        },
    }

    finalize_outcome(&mut middle, status_read, args.timeout_ms, middle_error)
}

async fn handle_nested_eventfd(
    args: NestedEventfdArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<NestedOutcome, HandlerError> {
    let ev = EventFd::open(0, "nonblock|semaphore|cloexec")
        .map_err(|e| HandlerError(format!("eventfd open: {e}")))?;
    let fd = ev.as_raw_fd();
    clear_cloexec(fd)?;

    let (status_read, status_write) = pipe_owned(libc::O_CLOEXEC)?;
    clear_cloexec(status_write.as_raw_fd())?;

    if args.op == NestedOp::EventfdRead {
        ev.write(7)
            .map_err(|e| HandlerError(format!("eventfd pre-write: {e}")))?;
    }

    let mut middle = spawn_middle(
        &args.middle_binary,
        &args.grandchild_binary,
        "eventfd",
        args.op,
        fd,
        status_write.as_raw_fd(),
    )?;
    drop(status_write);

    let mut middle_error: Option<String> = None;
    if args.op == NestedOp::EventfdWrite {
        // Grandchild writes; parent reads back.
        if let Err(e) = read_eventfd_with_timeout(&ev, args.timeout_ms) {
            middle_error = Some(e.0);
        }
    }

    finalize_outcome(&mut middle, status_read, args.timeout_ms, middle_error)
}

async fn handle_nested_brokerfile(
    args: NestedBrokerfileArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<NestedOutcome, HandlerError> {
    let path = brokerfile_path(&args.test_id);
    let _ = std::fs::remove_file(&path);
    let result = run_nested_brokerfile(&args, &path);
    let _ = std::fs::remove_file(&path);
    result
}

fn run_nested_brokerfile(
    args: &NestedBrokerfileArgs,
    path: &str,
) -> Result<NestedOutcome, HandlerError> {
    let mut file = match args.op {
        NestedOp::BrokerfileReadAtOffset0 => {
            std::fs::write(path, BROKERFILE_READ_PAYLOAD)
                .map_err(|e| HandlerError(format!("seed read payload {path}: {e}")))?;
            OpenOptions::new()
                .read(true)
                .open(path)
                .map_err(|e| HandlerError(format!("open read {path}: {e}")))?
        }
        NestedOp::BrokerfileWriteThenParentReadsBack => OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| HandlerError(format!("open rw {path}: {e}")))?,
        _ => {
            return Err(HandlerError(format!(
                "unsupported brokerfile op {}",
                args.op.id()
            )));
        }
    };
    let fd = file.as_raw_fd();
    clear_cloexec(fd)?;

    let (status_read, status_write) = pipe_owned(libc::O_CLOEXEC)?;
    clear_cloexec(status_write.as_raw_fd())?;

    let mut middle = spawn_middle(
        &args.middle_binary,
        &args.grandchild_binary,
        "brokerfile",
        args.op,
        fd,
        status_write.as_raw_fd(),
    )?;
    drop(status_write);

    let mut middle_error: Option<String> = None;

    let mut outcome = finalize_outcome(
        &mut middle,
        status_read,
        args.timeout_ms,
        middle_error.take(),
    )?;

    if outcome.exit_code == 0 && args.op == NestedOp::BrokerfileWriteThenParentReadsBack {
        match read_file_from_start(&mut file, BROKERFILE_WRITE_PAYLOAD.len()) {
            Ok(buf) if buf == BROKERFILE_WRITE_PAYLOAD => {}
            Ok(buf) => {
                outcome.exit_code = 1;
                outcome.stderr = format!(
                    "brokerfile parent read mismatch: got {:?} expected {:?}; {}",
                    String::from_utf8_lossy(&buf),
                    String::from_utf8_lossy(BROKERFILE_WRITE_PAYLOAD),
                    outcome.stderr,
                );
            }
            Err(e) => {
                outcome.exit_code = 1;
                outcome.stderr = format!("brokerfile parent read err: {}; {}", e.0, outcome.stderr);
            }
        }
    }
    Ok(outcome)
}

// ---------- shared finalize ----------

#[derive(Clone, Copy)]
enum ParentRole {
    Writer,
    Reader,
}

fn finalize_outcome(
    middle: &mut std::process::Child,
    status_read: OwnedFd,
    timeout_ms: u64,
    parent_test_error: Option<String>,
) -> Result<NestedOutcome, HandlerError> {
    let stdout = middle.stdout.take();
    let stderr = middle.stderr.take();
    if let Some(s) = stdout.as_ref() {
        set_nonblock(s.as_raw_fd())?;
    }
    if let Some(s) = stderr.as_ref() {
        set_nonblock(s.as_raw_fd())?;
    }
    let mut stdout = stdout;
    let mut stderr = stderr;
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();

    let deadline = Instant::now() + Duration::from_millis(timeout_ms + 1000);
    let middle_status = loop {
        let _ = drain_available(&mut stdout, &mut stdout_buf);
        let _ = drain_available(&mut stderr, &mut stderr_buf);
        if let Some(status) = middle
            .try_wait()
            .map_err(|e| HandlerError(format!("middle try_wait: {e}")))?
        {
            // Drain any remaining bytes before reporting.
            for _ in 0..10 {
                let _ = drain_available(&mut stdout, &mut stdout_buf);
                let _ = drain_available(&mut stderr, &mut stderr_buf);
                std::thread::sleep(Duration::from_millis(5));
            }
            break status;
        }
        if Instant::now() >= deadline {
            let _ = middle.kill();
            return Err(HandlerError("middle did not exit in time".into()));
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    let middle_exit = middle_status.code().unwrap_or(-1);
    let middle_signal = std::os::unix::process::ExitStatusExt::signal(&middle_status);

    // Read status pipe until "ok\n", "err:..\n", or EOF.
    let status_text = read_status(status_read, timeout_ms)?;

    let mut stderr_text = String::from_utf8_lossy(&stderr_buf).into_owned();
    if !stdout_buf.is_empty() {
        stderr_text.push_str("; stdout=");
        stderr_text.push_str(&String::from_utf8_lossy(&stdout_buf));
    }
    let stack_smashing = stderr_text.contains("stack smashing detected")
        || stderr_text.contains("*** stack smashing detected ***");

    let mut exit_code = 0;
    if let Some(sig) = middle_signal {
        exit_code = 128 + sig;
        stderr_text = format!("middle killed by signal {sig}; {stderr_text}");
    } else if middle_exit != 0 {
        exit_code = if middle_exit == 0 { 1 } else { middle_exit };
        stderr_text = format!("middle exit_code={middle_exit}; {stderr_text}");
    }
    if stack_smashing {
        exit_code = if exit_code == 0 { 1 } else { exit_code };
        stderr_text = format!("STACK SMASHING DETECTED; {stderr_text}");
    }
    if let Some(perr) = parent_test_error {
        exit_code = if exit_code == 0 { 1 } else { exit_code };
        stderr_text = format!("{perr}; {stderr_text}");
    }
    if status_text != "ok" && exit_code == 0 {
        exit_code = 1;
        stderr_text = format!("status={status_text:?}; {stderr_text}");
    }

    Ok(NestedOutcome {
        exit_code,
        middle_exit,
        status: status_text,
        stderr: stderr_text,
    })
}

fn read_status(status_read: OwnedFd, timeout_ms: u64) -> Result<String, HandlerError> {
    let fd = status_read.as_raw_fd();
    set_nonblock(fd)?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms + 1000);
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 256];
    while Instant::now() < deadline {
        // SAFETY: chunk is valid writable memory; fd is a live owned pipe end.
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr().cast::<libc::c_void>(), chunk.len()) };
        if n > 0 {
            buf.extend_from_slice(&chunk[..n as usize]);
            if buf.contains(&b'\n') {
                break;
            }
            continue;
        }
        if n == 0 {
            // EOF — all writers closed.
            break;
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EAGAIN) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Some(libc::EINTR) => {}
            _ => return Err(HandlerError(format!("status pipe read: {err}"))),
        }
    }
    let s = String::from_utf8_lossy(&buf).into_owned();
    Ok(s.trim().to_string())
}

// ---------- spawn middle ----------

fn spawn_middle(
    middle_binary: &str,
    grandchild_binary: &str,
    subsys: &str,
    op: NestedOp,
    inherit_fd: RawFd,
    status_fd: RawFd,
) -> Result<std::process::Child, HandlerError> {
    let mut cmd = Command::new(middle_binary);
    cmd.args([
        "nested-inherit-matrix",
        "middle",
        subsys,
        op.id(),
        grandchild_binary,
    ])
    .env("LITEBOX_INHERIT_FD", inherit_fd.to_string())
    .env("LITEBOX_STATUS_FD", status_fd.to_string())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    cmd.spawn()
        .map_err(|e| HandlerError(format!("spawn middle {middle_binary}: {e}")))
}

// ---------- fd helpers (mirrors of inherit_matrix; kept private so the
// 3-deep matrix is self-contained) ----------

fn pipe_owned(flags: i32) -> Result<(OwnedFd, OwnedFd), HandlerError> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 initializes both fd slots on success.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), flags) } != 0 {
        return Err(HandlerError(format!(
            "pipe2: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: pipe2 returned two fresh descriptors owned by this function.
    let r = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: pipe2 returned two fresh descriptors owned by this function.
    let w = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((r, w))
}

fn clear_cloexec(fd: RawFd) -> Result<(), HandlerError> {
    // SAFETY: fcntl on a live fd; errors checked.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
        return Err(HandlerError(format!(
            "fcntl(F_SETFD,0) fd={fd}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn set_nonblock(fd: RawFd) -> Result<(), HandlerError> {
    // SAFETY: fcntl on a live fd; errors checked.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(HandlerError(format!(
            "fcntl(F_GETFL) fd={fd}: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fcntl on a live fd; errors checked.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(HandlerError(format!(
            "fcntl(F_SETFL,O_NONBLOCK) fd={fd}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> Result<(), String> {
    while !buf.is_empty() {
        // SAFETY: buf valid for read; fd live.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
        if n > 0 {
            buf = &buf[n as usize..];
            continue;
        }
        if n == 0 {
            return Err(format!("write fd={fd}: wrote 0 bytes"));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(format!("write fd={fd}: {err}"));
        }
    }
    Ok(())
}

fn read_payload_with_timeout(
    fd: RawFd,
    expected: &[u8],
    timeout_ms: u64,
) -> Result<(), HandlerError> {
    poll_in(fd, timeout_ms)?;
    let mut buf = vec![0_u8; expected.len()];
    let mut filled = 0;
    while filled < buf.len() {
        // SAFETY: buf valid; fd live.
        let n = unsafe {
            libc::read(
                fd,
                buf.as_mut_ptr().add(filled).cast::<libc::c_void>(),
                buf.len() - filled,
            )
        };
        match n.cmp(&0) {
            std::cmp::Ordering::Greater => filled += n as usize,
            std::cmp::Ordering::Equal => {
                return Err(HandlerError(format!(
                    "unexpected EOF after {filled}/{} bytes",
                    buf.len()
                )));
            }
            std::cmp::Ordering::Less => {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(HandlerError(format!("read fd={fd}: {err}")));
            }
        }
    }
    if buf == expected {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "payload mismatch: got {:?} expected {:?}",
            String::from_utf8_lossy(&buf),
            String::from_utf8_lossy(expected)
        )))
    }
}

fn read_eof_with_timeout(fd: RawFd, timeout_ms: u64) -> Result<(), HandlerError> {
    poll_in_or_hup(fd, timeout_ms)?;
    let mut byte = [0_u8; 1];
    // SAFETY: byte valid writable; fd live.
    let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast::<libc::c_void>(), byte.len()) };
    match n.cmp(&0) {
        std::cmp::Ordering::Equal => Ok(()),
        std::cmp::Ordering::Greater => Err(HandlerError(format!("expected EOF, got {n} bytes"))),
        std::cmp::Ordering::Less => Err(HandlerError(format!(
            "EOF read: {}",
            std::io::Error::last_os_error()
        ))),
    }
}

fn read_eventfd_with_timeout(ev: &EventFd, timeout_ms: u64) -> Result<(), HandlerError> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while Instant::now() < deadline {
        match ev.read() {
            Ok(v) if v >= 1 => return Ok(()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(HandlerError(format!("eventfd read: {e}"))),
        }
    }
    Err(HandlerError("eventfd read: timeout".into()))
}

fn poll_in(fd: RawFd, timeout_ms: u64) -> Result<(), HandlerError> {
    let revents = poll_fd(fd, libc::POLLIN, timeout_ms)?;
    if revents & libc::POLLIN != 0 {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "poll fd={fd}: revents=0x{revents:x}, no POLLIN"
        )))
    }
}

fn poll_in_or_hup(fd: RawFd, timeout_ms: u64) -> Result<(), HandlerError> {
    let revents = poll_fd(fd, libc::POLLIN | libc::POLLHUP, timeout_ms)?;
    if revents & (libc::POLLIN | libc::POLLHUP) != 0 {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "poll fd={fd}: revents=0x{revents:x}, no POLLIN/POLLHUP"
        )))
    }
}

fn poll_fd(fd: RawFd, events: i16, timeout_ms: u64) -> Result<libc::c_short, HandlerError> {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32;
        // SAFETY: pfd is valid for the duration of this call.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, remaining) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(HandlerError(format!("poll fd={fd}: {err}")));
        }
        if rc == 0 {
            return Err(HandlerError(format!("poll fd={fd}: timeout")));
        }
        return Ok(pfd.revents);
    }
}

fn drain_available<R: Read>(r: &mut Option<R>, buf: &mut Vec<u8>) -> bool {
    let Some(stream) = r.as_mut() else {
        return false;
    };
    let mut chunk = [0_u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => {
                *r = None;
                return false;
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return true,
            Err(_) => {
                *r = None;
                return false;
            }
        }
    }
}

fn read_file_from_start(file: &mut File, len: usize) -> Result<Vec<u8>, HandlerError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| HandlerError(format!("seek: {e}")))?;
    let mut buf = vec![0_u8; len];
    file.read_exact(&mut buf)
        .map_err(|e| HandlerError(format!("read: {e}")))?;
    Ok(buf)
}

fn brokerfile_path(test_id: &str) -> String {
    let sanitized: String = test_id
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '-' => c,
            _ => '_',
        })
        .collect();
    format!("/tmp/nested-canary-{sanitized}-{}.txt", std::process::id())
}

// ---------- leaf subcommand: middle + grandchild ----------

mod leaf_subcmd {
    use super::{BROKERFILE_READ_PAYLOAD, BROKERFILE_WRITE_PAYLOAD, NestedOp, STATUS_OK};
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::{FromRawFd, RawFd};

    pub(super) fn dispatch(args: &[String]) -> i32 {
        match args.get(2).map(String::as_str) {
            Some("middle") => middle(args),
            Some("grandchild") => grandchild(args),
            Some(other) => {
                eprintln!("nested-inherit-matrix: unknown subcommand: {other}");
                2
            }
            None => {
                eprintln!("nested-inherit-matrix: missing subcommand");
                2
            }
        }
    }

    /// args: [exe, "nested-inherit-matrix", "middle", subsys, op, grandchild_binary]
    ///
    /// Forks. Parent of fork `_exit(0)` immediately — this is the
    /// load-bearing shape of commit 5241b07c. Child of fork execve's
    /// the grandchild binary preserving env (LITEBOX_INHERIT_FD,
    /// LITEBOX_STATUS_FD).
    fn middle(args: &[String]) -> i32 {
        let Some(subsys) = args.get(3) else {
            eprintln!("middle: missing subsys");
            return 2;
        };
        let Some(op) = args.get(4) else {
            eprintln!("middle: missing op");
            return 2;
        };
        let Some(grandchild_bin) = args.get(5) else {
            eprintln!("middle: missing grandchild binary");
            return 2;
        };

        // SAFETY: single-threaded test harness binary; fork before any
        // multithreaded runtime is started.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            eprintln!("middle: fork: {}", std::io::Error::last_os_error());
            return 1;
        }
        if pid > 0 {
            // Parent of fork: exit immediately with 0. THIS is the
            // shape that exposed the nested-CoW-skip bug. Do NOT call
            // exit() — _exit() avoids running atexit handlers that
            // might touch shared state.
            // SAFETY: _exit is async-signal-safe.
            unsafe { libc::_exit(0) };
        }

        // Child of fork: exec the grandchild binary.
        let Ok(prog) = CString::new(grandchild_bin.as_str()) else {
            eprintln!("middle child: grandchild path has nul");
            // SAFETY: _exit is async-signal-safe.
            unsafe { libc::_exit(2) };
        };
        let argv_subcmd = CString::new("nested-inherit-matrix").unwrap();
        let argv_role = CString::new("grandchild").unwrap();
        let argv_subsys =
            CString::new(subsys.as_str()).unwrap_or_else(|_| CString::new("bad").unwrap());
        let argv_op = CString::new(op.as_str()).unwrap_or_else(|_| CString::new("bad").unwrap());
        let argv_ptrs: [*const libc::c_char; 6] = [
            prog.as_ptr(),
            argv_subcmd.as_ptr(),
            argv_role.as_ptr(),
            argv_subsys.as_ptr(),
            argv_op.as_ptr(),
            std::ptr::null(),
        ];
        // SAFETY: execvp consumes valid CString-backed pointers and
        // inherits the current environment, including LITEBOX_INHERIT_FD
        // and LITEBOX_STATUS_FD.
        unsafe {
            libc::execvp(prog.as_ptr(), argv_ptrs.as_ptr());
        }
        // execvp returned → failure.
        let err = std::io::Error::last_os_error();
        eprintln!("middle child execvp {grandchild_bin}: {err}");
        // SAFETY: _exit is async-signal-safe.
        unsafe { libc::_exit(127) };
    }

    /// args: [exe, "nested-inherit-matrix", "grandchild", subsys, op]
    fn grandchild(args: &[String]) -> i32 {
        let Some(subsys) = args.get(3).map(String::as_str) else {
            return 2;
        };
        let Some(op_s) = args.get(4).map(String::as_str) else {
            return 2;
        };
        let Some(op) = NestedOp::parse(op_s) else {
            eprintln!("grandchild: unknown op {op_s}");
            return 2;
        };

        let Some(test_fd) = std::env::var("LITEBOX_INHERIT_FD")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("grandchild: bad LITEBOX_INHERIT_FD");
            return 2;
        };
        let Some(status_fd) = std::env::var("LITEBOX_STATUS_FD")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("grandchild: bad LITEBOX_STATUS_FD");
            return 2;
        };

        let rc = match subsys {
            "pipe" => do_pipe(op, test_fd),
            "eventfd" => do_eventfd(op, test_fd),
            "brokerfile" => do_brokerfile(op, test_fd),
            other => {
                eprintln!("grandchild: unknown subsys {other}");
                return 2;
            }
        };

        if rc == 0 {
            let _ = write_status(status_fd, STATUS_OK);
        } else {
            let msg = format!("err:rc={rc}\n");
            let _ = write_status(status_fd, msg.as_bytes());
        }
        rc
    }

    fn write_status(fd: RawFd, buf: &[u8]) -> i32 {
        let mut rest = buf;
        while !rest.is_empty() {
            // SAFETY: rest valid for read; fd live for write.
            let n = unsafe { libc::write(fd, rest.as_ptr().cast::<libc::c_void>(), rest.len()) };
            match n.cmp(&0) {
                std::cmp::Ordering::Greater => rest = &rest[n as usize..],
                std::cmp::Ordering::Less => {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() != Some(libc::EINTR) {
                        return 1;
                    }
                }
                std::cmp::Ordering::Equal => return 1,
            }
        }
        0
    }

    fn do_pipe(op: NestedOp, fd: RawFd) -> i32 {
        match op {
            NestedOp::ParentWritesChildReads => {
                let mut buf = [0_u8; 4];
                if !read_exact(fd, &mut buf) {
                    return 1;
                }
                if &buf != b"ping" {
                    eprintln!("pipe grandchild: bad payload {:?}", &buf);
                    return 1;
                }
                0
            }
            NestedOp::ChildWritesParentReads => {
                let buf = b"pong";
                if !write_all(fd, buf) {
                    return 1;
                }
                0
            }
            NestedOp::ChildCloseParentReadsEof => {
                // SAFETY: best-effort close of inherited write end.
                if unsafe { libc::close(fd) } != 0 {
                    return 1;
                }
                0
            }
            _ => 2,
        }
    }

    fn do_eventfd(op: NestedOp, fd: RawFd) -> i32 {
        match op {
            NestedOp::EventfdRead => {
                let mut buf = [0_u8; 8];
                if !read_exact(fd, &mut buf) {
                    return 1;
                }
                let v = u64::from_ne_bytes(buf);
                if v < 1 {
                    eprintln!("eventfd grandchild: got {v}");
                    return 1;
                }
                0
            }
            NestedOp::EventfdWrite => {
                let v: u64 = 1;
                let bytes = v.to_ne_bytes();
                if !write_all(fd, &bytes) {
                    return 1;
                }
                0
            }
            _ => 2,
        }
    }

    fn do_brokerfile(op: NestedOp, fd: RawFd) -> i32 {
        // Construct an owned File around the inherited fd so std I/O
        // works; forget on success to keep the fd alive for parent.
        // SAFETY: fd was inherited and is uniquely owned by this process.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let rc = match op {
            NestedOp::BrokerfileReadAtOffset0 => {
                use std::io::Read;
                let mut buf = vec![0_u8; BROKERFILE_READ_PAYLOAD.len()];
                match file.read_exact(&mut buf) {
                    Ok(()) if buf == BROKERFILE_READ_PAYLOAD => 0,
                    Ok(()) => {
                        eprintln!(
                            "brokerfile grandchild: payload mismatch got={:?} expected={:?}",
                            String::from_utf8_lossy(&buf),
                            String::from_utf8_lossy(BROKERFILE_READ_PAYLOAD)
                        );
                        1
                    }
                    Err(e) => {
                        eprintln!("brokerfile grandchild read: {e}");
                        1
                    }
                }
            }
            NestedOp::BrokerfileWriteThenParentReadsBack => {
                match file.write_all(BROKERFILE_WRITE_PAYLOAD) {
                    Ok(()) => match file.flush() {
                        Ok(()) => 0,
                        Err(e) => {
                            eprintln!("brokerfile flush: {e}");
                            1
                        }
                    },
                    Err(e) => {
                        eprintln!("brokerfile write: {e}");
                        1
                    }
                }
            }
            _ => 2,
        };
        // Hand the fd back to the OS rather than closing — parent may
        // need to read on its end.
        std::mem::forget(file);
        rc
    }

    fn read_exact(fd: RawFd, buf: &mut [u8]) -> bool {
        let mut filled = 0;
        while filled < buf.len() {
            // SAFETY: buf valid; fd live.
            let n = unsafe {
                libc::read(
                    fd,
                    buf.as_mut_ptr().add(filled).cast::<libc::c_void>(),
                    buf.len() - filled,
                )
            };
            match n.cmp(&0) {
                std::cmp::Ordering::Greater => filled += n as usize,
                std::cmp::Ordering::Equal => return false,
                std::cmp::Ordering::Less => {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() != Some(libc::EINTR) {
                        return false;
                    }
                }
            }
        }
        true
    }

    fn write_all(fd: RawFd, mut buf: &[u8]) -> bool {
        while !buf.is_empty() {
            // SAFETY: buf valid; fd live.
            let n = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
            match n.cmp(&0) {
                std::cmp::Ordering::Greater => buf = &buf[n as usize..],
                std::cmp::Ordering::Equal => return false,
                std::cmp::Ordering::Less => {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() != Some(libc::EINTR) {
                        return false;
                    }
                }
            }
        }
        true
    }
}
