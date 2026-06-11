// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fork+exec fd-inheritance matrix scaffold.
//!
//! The pilot covers TCP listen sockets across the full parent/child
//! binary-type cross-product. Additional fd subsystems are represented in
//! the dispatch/data model so the next subsystem can be added by filling in
//! the corresponding runner.

// TODO(#15): convert legacy wildcard enum dispatch in this file to explicit arms.
#![allow(clippy::wildcard_enum_match_arm)]

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::eventfd::EventFd;
use crate::os::pidfd::Pidfd;
use crate::os::pty::Pty;
use crate::os::signalfd::Signalfd;
use crate::{BinaryType, register_handler, register_leaf_subcommand};

use serde::{Deserialize, Serialize};

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::TestOutcome;
use super::agents::{AgentHandle, AgentName};
use super::registry::Registry;
use super::run_context::RunContext;

const TCP_LISTEN_MATRIX: HandlerToken<TcpListenTrialArgs, ChildOutput> =
    HandlerToken::new("inherit_matrix.tcp_listen");
const PIPE_MATRIX: HandlerToken<PipeTrialArgs, ChildOutput> =
    HandlerToken::new("inherit_matrix.pipe");
const EVENTFD_MATRIX: HandlerToken<EventfdTrialArgs, ChildOutput> =
    HandlerToken::new("inherit_matrix.eventfd");
const PTY_MATRIX: HandlerToken<PtyTrialArgs, ChildOutput> = HandlerToken::new("inherit_matrix.pty");
const SIGNALFD_MATRIX: HandlerToken<SignalfdTrialArgs, ChildOutput> =
    HandlerToken::new("inherit_matrix.signalfd");
const BROKER_FILE_MATRIX: HandlerToken<BrokerFileTrialArgs, ChildOutput> =
    HandlerToken::new("inherit_matrix.brokerfile");
const TIMERFD_MATRIX: HandlerToken<TimerfdTrialArgs, ChildOutput> =
    HandlerToken::new("inherit_matrix.timerfd");
const SOCKETPAIR_MATRIX: HandlerToken<SocketpairTrialArgs, ChildOutput> =
    HandlerToken::new("inherit_matrix.socketpair");
const TCP_CONN_MATRIX: HandlerToken<TcpConnTrialArgs, ChildOutput> =
    HandlerToken::new("inherit_matrix.tcp_conn");
const TCP_CONN_PEER: HandlerToken<TcpConnPeerArgs, TcpConnPeerOutput> =
    HandlerToken::new("inherit_matrix.tcp_conn_peer");
const FS_FID: HandlerToken<FsFidTrialArgs, ChildOutput> =
    HandlerToken::new("inherit_matrix.fs_fid");
const PIDFD_MATRIX: HandlerToken<PidfdTrialArgs, ChildOutput> =
    HandlerToken::new("inherit_matrix.pidfd");
const EPOLL_MATRIX: HandlerToken<EpollTrialArgs, ChildOutput> =
    HandlerToken::new("inherit_matrix.epoll");
const INOTIFY_MATRIX: HandlerToken<InotifyTrialArgs, ChildOutput> =
    HandlerToken::new("inherit_matrix.inotify");

const TCP_CONN_READY: &str = "tcp_conn_listening";

const TCP_LISTEN_OPS: &[InheritOp] = &[
    InheritOp::Accept,
    InheritOp::GetSockname,
    InheritOp::GetSockoptReuseport,
];

const PIPE_OPS: &[InheritOp] = &[
    InheritOp::ParentWritesChildReads,
    InheritOp::ChildWritesParentReads,
    InheritOp::ChildCloseParentReadsEof,
];
const SOCKETPAIR_OPS: &[InheritOp] = &[
    InheritOp::ReadAfterParentWrite,
    InheritOp::WriteThenParentReads,
    InheritOp::ChildShutdownThenParentEof,
];
const TCP_CONN_OPS: &[InheritOp] = &[
    InheritOp::ParentWritesChildReads,
    InheritOp::ChildWritesParentReads,
    InheritOp::ChildShutdownThenParentEof,
];
#[allow(dead_code)]
const EVENTFD_OPS: &[InheritOp] = &[InheritOp::Read, InheritOp::Write, InheritOp::Poll];
const SIGNALFD_OPS: &[InheritOp] = &[
    InheritOp::RecvPending,
    InheritOp::RecvAfterFork,
    InheritOp::RecvCloseEof,
];
const TIMERFD_OPS: &[InheritOp] = &[
    InheritOp::ReadAfterExpire,
    InheritOp::ArmThenInheritThenRead,
    InheritOp::PollReadableAfterExpire,
];
#[allow(dead_code)]
const PTY_OPS: &[InheritOp] = &[
    InheritOp::SlaveWrite,
    InheritOp::SlaveRead,
    InheritOp::SlaveClose,
];
const BROKER_FILE_OPS: &[InheritOp] = &[
    InheritOp::ReadAtOffset0,
    InheritOp::WriteThenParentReadsBack,
    InheritOp::LseekThenRead,
];
const PIDFD_OPS: &[InheritOp] = &[InheritOp::Poll, InheritOp::RecvAfterFork];
const EPOLL_OPS: &[InheritOp] = &[InheritOp::Poll, InheritOp::Read, InheritOp::EpollCtlAdd];
const INOTIFY_OPS: &[InheritOp] = &[InheritOp::InotifyReadEvent, InheritOp::Poll];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum InheritSubsystem {
    TcpListen,
    Pipe,
    SocketPair,
    TcpConn,
    Eventfd,
    Signalfd,
    Timerfd,
    Pty,
    BrokerFile,
    Pidfd,
    Epoll,
    Inotify,
}

impl InheritSubsystem {
    const ALL: &'static [Self] = &[
        Self::TcpListen,
        Self::Pipe,
        Self::SocketPair,
        Self::TcpConn,
        Self::Eventfd,
        Self::Signalfd,
        Self::Timerfd,
        Self::Pty,
        Self::BrokerFile,
        Self::Pidfd,
        Self::Epoll,
        Self::Inotify,
    ];

    /// Compile-time-exhaustive variant index. Adding a new
    /// `InheritSubsystem` variant must extend this match (rustc E0004)
    /// AND `Self::ALL` AND bump `EXPECTED_VARIANT_COUNT` below. The
    /// `every_variant_in_all_array` unit test wires those together so
    /// the structural-coverage gap caught by the wave-cleanup-2
    /// epoll/inotify regression cannot be re-introduced silently in
    /// the test-discovery layer.
    #[cfg(test)]
    const fn discriminant_index(self) -> usize {
        match self {
            Self::TcpListen => 0,
            Self::Pipe => 1,
            Self::SocketPair => 2,
            Self::TcpConn => 3,
            Self::Eventfd => 4,
            Self::Signalfd => 5,
            Self::Timerfd => 6,
            Self::Pty => 7,
            Self::BrokerFile => 8,
            Self::Pidfd => 9,
            Self::Epoll => 10,
            Self::Inotify => 11,
        }
    }

    /// Must equal the number of arms in `discriminant_index`. Verified
    /// by the unit test below.
    #[cfg(test)]
    const EXPECTED_VARIANT_COUNT: usize = 12;

    const fn id(self) -> &'static str {
        match self {
            Self::TcpListen => "tcp_listen",
            Self::Pipe => "pipe",
            Self::SocketPair => "socketpair",
            Self::TcpConn => "tcp_conn",
            Self::Eventfd => "eventfd",
            Self::Signalfd => "signalfd",
            Self::Timerfd => "timerfd",
            Self::Pty => "pty",
            Self::BrokerFile => "brokerfile",
            Self::Pidfd => "pidfd",
            Self::Epoll => "epoll",
            Self::Inotify => "inotify",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InheritOp {
    Accept,
    Read,
    Write,
    Poll,
    Close,
    Dup,
    Shutdown,
    GetSockname,
    GetSockoptReuseport,
    SlaveWrite,
    SlaveRead,
    SlaveClose,
    RecvPending,
    RecvAfterFork,
    RecvCloseEof,
    ParentWritesChildReads,
    ChildWritesParentReads,
    ChildCloseParentReadsEof,
    ReadAfterParentWrite,
    WriteThenParentReads,
    ChildShutdownThenParentEof,
    ReadAtOffset0,
    WriteThenParentReadsBack,
    LseekThenRead,
    ReadAfterExpire,
    ArmThenInheritThenRead,
    PollReadableAfterExpire,
    EpollCtlAdd,
    InotifyReadEvent,
}

impl InheritOp {
    const fn id(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Read => "read",
            Self::Write => "write",
            Self::Poll => "poll",
            Self::Close => "close",
            Self::Dup => "dup",
            Self::Shutdown => "shutdown",
            Self::GetSockname => "getsockname",
            Self::GetSockoptReuseport => "getsockopt_reuseport",
            Self::SlaveWrite => "slave_write",
            Self::SlaveRead => "slave_read",
            Self::SlaveClose => "slave_close",
            Self::RecvPending => "recv_pending",
            Self::RecvAfterFork => "recv_after_fork",
            Self::RecvCloseEof => "recv_close_eof",
            Self::ParentWritesChildReads => "parent_writes_child_reads",
            Self::ChildWritesParentReads => "child_writes_parent_reads",
            Self::ChildCloseParentReadsEof => "child_close_parent_reads_eof",
            Self::ReadAfterParentWrite => "read_after_parent_write",
            Self::WriteThenParentReads => "write_then_parent_reads",
            Self::ChildShutdownThenParentEof => "child_shutdown_then_parent_eof",
            Self::ReadAtOffset0 => "read_at_offset_0",
            Self::WriteThenParentReadsBack => "write_then_parent_reads_back",
            Self::LseekThenRead => "lseek_then_read",
            Self::ReadAfterExpire => "read_after_expire",
            Self::ArmThenInheritThenRead => "arm_then_inherit_then_read",
            Self::PollReadableAfterExpire => "poll_readable_after_expire",
            Self::EpollCtlAdd => "epoll_ctl_add",
            Self::InotifyReadEvent => "inotify_read_event",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct InheritTrial {
    parent_bt: BinaryType,
    child_bt: BinaryType,
    subsystem: InheritSubsystem,
    op: InheritOp,
}

impl InheritTrial {
    fn id(self) -> String {
        format!(
            "INHERIT.{}.{}.{}.{}",
            self.subsystem.id(),
            self.op.id(),
            self.parent_bt.short_label(),
            self.child_bt.short_label()
        )
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct TcpListenTrialArgs {
    child_binary: String,
    op: InheritOp,
    timeout_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct PipeTrialArgs {
    child_binary: String,
    op: InheritOp,
    timeout_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct SocketpairTrialArgs {
    child_binary: String,
    op: InheritOp,
    timeout_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct EventfdTrialArgs {
    child_binary: String,
    op: InheritOp,
    timeout_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct PtyTrialArgs {
    child_binary: String,
    op: InheritOp,
    timeout_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct SignalfdTrialArgs {
    child_binary: String,
    op: InheritOp,
    timeout_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct BrokerFileTrialArgs {
    child_binary: String,
    op: InheritOp,
    timeout_ms: u64,
    test_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct TimerfdTrialArgs {
    child_binary: String,
    op: InheritOp,
    timeout_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct PidfdTrialArgs {
    child_binary: String,
    op: InheritOp,
    timeout_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct EpollTrialArgs {
    child_binary: String,
    op: InheritOp,
    timeout_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct InotifyTrialArgs {
    child_binary: String,
    op: InheritOp,
    timeout_ms: u64,
    test_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct TcpConnTrialArgs {
    child_binary: String,
    op: InheritOp,
    timeout_ms: u64,
    port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct TcpConnPeerArgs {
    op: InheritOp,
    timeout_ms: u64,
    port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
struct TcpConnPeerOutput {
    passed: bool,
    detail: String,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
enum FsFidScenario {
    SharedPosition,
    UnlinkedAfterInherit,
    ParentCloseFirst,
}

impl FsFidScenario {
    const fn id(self) -> &'static str {
        match self {
            Self::SharedPosition => "shared_position",
            Self::UnlinkedAfterInherit => "unlinked_after_inherit",
            Self::ParentCloseFirst => "parent_close_first",
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct FsFidTrialArgs {
    child_binary: String,
    scenario: FsFidScenario,
    test_id: String,
    timeout_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct ChildOutput {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

pub(crate) fn register_inherit_matrix_tests(reg: &mut Registry<'_>) {
    register_handler!(TCP_LISTEN_MATRIX, handle_tcp_listen_trial);
    register_handler!(PIPE_MATRIX, handle_pipe_trial);
    register_handler!(EVENTFD_MATRIX, handle_eventfd_trial);
    register_handler!(PTY_MATRIX, handle_pty_trial);
    register_handler!(SIGNALFD_MATRIX, handle_signalfd_trial);
    register_handler!(BROKER_FILE_MATRIX, handle_brokerfile_trial);
    register_handler!(TIMERFD_MATRIX, handle_timerfd_trial);
    register_handler!(SOCKETPAIR_MATRIX, handle_socketpair_trial);
    register_handler!(TCP_CONN_MATRIX, handle_tcp_conn_trial);
    register_handler!(TCP_CONN_PEER, handle_tcp_conn_peer);
    register_handler!(FS_FID, handle_fs_fid_trial);
    register_handler!(PIDFD_MATRIX, handle_pidfd_trial);
    register_handler!(EPOLL_MATRIX, handle_epoll_trial);
    register_handler!(INOTIFY_MATRIX, handle_inotify_trial);
    register_leaf_subcommand!("inherit-matrix", leaf_subcmd::subcmd_inherit_matrix);

    for scenario in [
        FsFidScenario::SharedPosition,
        FsFidScenario::UnlinkedAfterInherit,
        FsFidScenario::ParentCloseFirst,
    ] {
        let id = format!("inherit_matrix.fs_fid.{}", scenario.id());
        reg.test("vscode", "inherit_matrix", id.clone())
            .timeout(30)
            .build(move |cx| {
                let parent = cx.require(AgentName::Dpg1);
                let id = id.clone();
                Box::new(move |run| {
                    Box::pin(async move {
                        let child_binary = run.self_exe().to_string();
                        let result = run
                            .send_named_typed(
                                &parent,
                                &FS_FID,
                                FsFidTrialArgs {
                                    child_binary,
                                    scenario,
                                    test_id: id,
                                    timeout_ms: 2000,
                                },
                            )
                            .await;
                        match result {
                            Ok(out) if out.exit_code == 0 => {
                                TestOutcome::new("Dpg1", true, out.stdout)
                            }
                            Ok(out) => TestOutcome::new(
                                "Dpg1",
                                false,
                                format!(
                                    "exit_code={} stdout={:?} stderr={:?}",
                                    out.exit_code, out.stdout, out.stderr
                                ),
                            ),
                            Err(error) => TestOutcome::new("Dpg1", false, error),
                        }
                    })
                })
            });
    }

    // Drive trial registration from `InheritSubsystem::ALL` so adding a
    // new variant only requires updating one place. The
    // `every_variant_in_all_array` test below asserts ALL stays
    // exhaustive vs the exhaustive-match in `discriminant_index`, so a
    // new variant cannot silently miss the cross-product registration
    // (the test-discovery-time gate Option 3 of the wave-cleanup-2
    // migration-gate work stream).
    for &subsystem in InheritSubsystem::ALL {
        for &parent_bt in BinaryType::ALL {
            for &child_bt in BinaryType::ALL {
                for &op in valid_ops(subsystem) {
                    let trial = InheritTrial {
                        parent_bt,
                        child_bt,
                        subsystem,
                        op,
                    };
                    register_trial(reg, trial);
                }
            }
        }
    }
}

const fn valid_ops(subsystem: InheritSubsystem) -> &'static [InheritOp] {
    match subsystem {
        InheritSubsystem::TcpListen => TCP_LISTEN_OPS,
        InheritSubsystem::Pipe => PIPE_OPS,
        InheritSubsystem::SocketPair => SOCKETPAIR_OPS,
        InheritSubsystem::TcpConn => TCP_CONN_OPS,
        InheritSubsystem::Eventfd => EVENTFD_OPS,
        InheritSubsystem::Signalfd => SIGNALFD_OPS,
        InheritSubsystem::Timerfd => TIMERFD_OPS,
        InheritSubsystem::Pty => PTY_OPS,
        InheritSubsystem::BrokerFile => BROKER_FILE_OPS,
        InheritSubsystem::Pidfd => PIDFD_OPS,
        InheritSubsystem::Epoll => EPOLL_OPS,
        InheritSubsystem::Inotify => INOTIFY_OPS,
    }
}

#[allow(clippy::too_many_lines)]
fn register_trial(reg: &mut Registry<'_>, trial: InheritTrial) {
    let id = trial.id();
    let parent = parent_agent(trial.parent_bt);
    let test = reg.test("vscode", "inherit_matrix", id).timeout(30);

    test.build(move |cx| {
        let parent_handle = cx.require(parent);
        let tcp_peer = cx.require(AgentName::Dpg2);
        Box::new(move |run| {
            Box::pin(async move {
                let self_exe = run.self_exe().to_string();
                let child_binary = crate::binary_path(trial.child_bt, &self_exe);
                let trial_id = trial.id();
                let result = match trial.subsystem {
                    InheritSubsystem::TcpListen => {
                        run.send_named_typed(
                            &parent_handle,
                            &TCP_LISTEN_MATRIX,
                            TcpListenTrialArgs {
                                child_binary,
                                op: trial.op,
                                timeout_ms: 5000,
                            },
                        )
                        .await
                    }
                    InheritSubsystem::Pipe => {
                        run.send_named_typed(
                            &parent_handle,
                            &PIPE_MATRIX,
                            PipeTrialArgs {
                                child_binary,
                                op: trial.op,
                                timeout_ms: 2000,
                            },
                        )
                        .await
                    }
                    InheritSubsystem::SocketPair => {
                        run.send_named_typed(
                            &parent_handle,
                            &SOCKETPAIR_MATRIX,
                            SocketpairTrialArgs {
                                child_binary,
                                op: trial.op,
                                timeout_ms: 5000,
                            },
                        )
                        .await
                    }
                    InheritSubsystem::Eventfd => {
                        run.send_named_typed(
                            &parent_handle,
                            &EVENTFD_MATRIX,
                            EventfdTrialArgs {
                                child_binary,
                                op: trial.op,
                                timeout_ms: 2000,
                            },
                        )
                        .await
                    }
                    InheritSubsystem::Pty => {
                        run.send_named_typed(
                            &parent_handle,
                            &PTY_MATRIX,
                            PtyTrialArgs {
                                child_binary,
                                op: trial.op,
                                timeout_ms: 2000,
                            },
                        )
                        .await
                    }
                    InheritSubsystem::Signalfd => {
                        run.send_named_typed(
                            &parent_handle,
                            &SIGNALFD_MATRIX,
                            SignalfdTrialArgs {
                                child_binary,
                                op: trial.op,
                                timeout_ms: 2000,
                            },
                        )
                        .await
                    }
                    InheritSubsystem::BrokerFile => {
                        run.send_named_typed(
                            &parent_handle,
                            &BROKER_FILE_MATRIX,
                            BrokerFileTrialArgs {
                                child_binary,
                                op: trial.op,
                                timeout_ms: 2000,
                                test_id: trial_id.clone(),
                            },
                        )
                        .await
                    }
                    InheritSubsystem::Timerfd => {
                        run.send_named_typed(
                            &parent_handle,
                            &TIMERFD_MATRIX,
                            TimerfdTrialArgs {
                                child_binary,
                                op: trial.op,
                                timeout_ms: 1000,
                            },
                        )
                        .await
                    }
                    InheritSubsystem::TcpConn => {
                        run_tcp_conn_trial(run, &parent_handle, &tcp_peer, trial, child_binary)
                            .await
                    }
                    InheritSubsystem::Pidfd => {
                        run.send_named_typed(
                            &parent_handle,
                            &PIDFD_MATRIX,
                            PidfdTrialArgs {
                                child_binary,
                                op: trial.op,
                                timeout_ms: 3000,
                            },
                        )
                        .await
                    }
                    InheritSubsystem::Epoll => {
                        run.send_named_typed(
                            &parent_handle,
                            &EPOLL_MATRIX,
                            EpollTrialArgs {
                                child_binary,
                                op: trial.op,
                                timeout_ms: 5000,
                            },
                        )
                        .await
                    }
                    InheritSubsystem::Inotify => {
                        run.send_named_typed(
                            &parent_handle,
                            &INOTIFY_MATRIX,
                            InotifyTrialArgs {
                                child_binary,
                                op: trial.op,
                                timeout_ms: 5000,
                                test_id: trial_id.clone(),
                            },
                        )
                        .await
                    }
                };
                match result {
                    Ok(out) if out.exit_code == 0 => TestOutcome::new(
                        parent.name(),
                        true,
                        format!(
                            "child {} inherited {} fd",
                            trial.op.id(),
                            trial.subsystem.id()
                        ),
                    ),
                    Ok(out) => TestOutcome::new(
                        parent.name(),
                        false,
                        format!(
                            "exit_code={} stdout={:?} stderr={:?}",
                            out.exit_code, out.stdout, out.stderr
                        ),
                    ),
                    Err(e) => TestOutcome::new(parent.name(), false, format!("handler: {e}")),
                }
            })
        })
    });
}

async fn run_tcp_conn_trial(
    run: &mut RunContext<'_>,
    parent: &AgentHandle,
    peer: &AgentHandle,
    trial: InheritTrial,
    child_binary: String,
) -> Result<ChildOutput, String> {
    let port = tcp_conn_port(trial.parent_bt, trial.child_bt, trial.op);
    let args = TcpConnTrialArgs {
        child_binary,
        op: trial.op,
        timeout_ms: 2000,
        port,
    };
    let peer_args = TcpConnPeerArgs {
        op: trial.op,
        timeout_ms: 2000,
        port,
    };

    run.run_write_typed(parent, &TCP_CONN_MATRIX, args).await?;
    run.run_read_checkpoint(parent, TCP_CONN_READY).await?;
    run.run_resume(parent, TCP_CONN_READY).await?;

    let peer_out = run.send_named_typed(peer, &TCP_CONN_PEER, peer_args).await;
    let parent_out = run.run_read_result(parent, &TCP_CONN_MATRIX).await;

    match (parent_out, peer_out) {
        (Ok(mut out), Ok(peer_out)) => {
            if !peer_out.passed {
                out.exit_code = 1;
                out.stderr = format!("tcp peer failed: {}; {}", peer_out.detail, out.stderr);
            }
            Ok(out)
        }
        (Ok(mut out), Err(peer_err)) => {
            out.exit_code = 1;
            out.stderr = format!("tcp peer handler: {peer_err}; {}", out.stderr);
            Ok(out)
        }
        (Err(parent_err), Ok(peer_out)) => Err(format!(
            "parent result: {parent_err}; peer: passed={} detail={}",
            peer_out.passed, peer_out.detail
        )),
        (Err(parent_err), Err(peer_err)) => Err(format!(
            "parent result: {parent_err}; peer handler: {peer_err}"
        )),
    }
}

const fn parent_agent(bt: BinaryType) -> AgentName {
    match bt {
        BinaryType::PieGlibc => AgentName::Dpg1,
        BinaryType::NonPieGlibc => AgentName::Dpg1Dng,
        BinaryType::StaticPieGlibc => AgentName::Dpg1Spg,
        BinaryType::StaticPieMusl => AgentName::Dpg1Spm,
        BinaryType::NonPieStaticMusl => AgentName::Dpg1Snm,
    }
}

fn tcp_conn_port(parent_bt: BinaryType, child_bt: BinaryType, op: InheritOp) -> u16 {
    36_000
        + binary_type_index(parent_bt) * 15
        + binary_type_index(child_bt) * 3
        + tcp_conn_op_index(op)
}

const fn binary_type_index(bt: BinaryType) -> u16 {
    match bt {
        BinaryType::PieGlibc => 0,
        BinaryType::NonPieGlibc => 1,
        BinaryType::StaticPieGlibc => 2,
        BinaryType::StaticPieMusl => 3,
        BinaryType::NonPieStaticMusl => 4,
    }
}

fn tcp_conn_op_index(op: InheritOp) -> u16 {
    match op {
        InheritOp::ParentWritesChildReads => 0,
        InheritOp::ChildWritesParentReads => 1,
        InheritOp::ChildShutdownThenParentEof => 2,
        _ => unreachable!("invalid tcp_conn op {}", op.id()),
    }
}

#[allow(dead_code)]
fn run_scaffolded_trial(subsystem: InheritSubsystem, _op: InheritOp) -> String {
    match subsystem {
        InheritSubsystem::TcpListen => {
            "tcp_listen is implemented by handle_tcp_listen_trial".into()
        }
        InheritSubsystem::Pipe => "pipe is implemented by handle_pipe_trial".into(),
        InheritSubsystem::SocketPair => run_socketpair_trial(),
        InheritSubsystem::TcpConn => run_tcp_conn_trial_scaffold(),
        InheritSubsystem::Eventfd => run_eventfd_trial(),
        InheritSubsystem::Signalfd => run_signalfd_trial(),
        InheritSubsystem::Timerfd => run_timerfd_trial(),
        InheritSubsystem::Pty => run_pty_trial(),
        InheritSubsystem::BrokerFile => run_broker_file_trial(),
        InheritSubsystem::Pidfd => "pidfd is implemented by handle_pidfd_trial".into(),
        InheritSubsystem::Epoll => "epoll is implemented by handle_epoll_trial".into(),
        InheritSubsystem::Inotify => "inotify is implemented by handle_inotify_trial".into(),
    }
}

#[allow(dead_code)]
fn run_pipe_trial_scaffold() -> String {
    "pipe is implemented by handle_pipe_trial".into()
}

#[allow(dead_code)]
fn run_socketpair_trial() -> String {
    "socketpair is implemented by handle_socketpair_trial".into()
}

#[allow(dead_code)]
fn run_tcp_conn_trial_scaffold() -> String {
    "tcp_conn is implemented by handle_tcp_conn_trial".into()
}

#[allow(dead_code)]
fn run_eventfd_trial() -> String {
    "eventfd is implemented by handle_eventfd_trial".into()
}

#[allow(dead_code)]
fn run_signalfd_trial() -> String {
    "signalfd is implemented by handle_signalfd_trial".into()
}

#[allow(dead_code)]
fn run_timerfd_trial() -> String {
    "timerfd is implemented by handle_timerfd_trial".into()
}

#[allow(dead_code)]
fn run_pty_trial() -> String {
    "pty is implemented by handle_pty_trial".into()
}

#[allow(dead_code)]
fn run_broker_file_trial() -> String {
    "brokerfile is implemented by handle_brokerfile_trial".into()
}

async fn handle_tcp_conn_trial(
    args: TcpConnTrialArgs,
    ctx: &mut HandlerCtx<'_>,
) -> Result<ChildOutput, HandlerError> {
    let (listener, _) = create_tcp_listener_on_port(args.port)?;
    ctx.checkpoint(TCP_CONN_READY).await?;
    wait_for_listener_connection(&listener, args.timeout_ms)?;
    let (conn, _) = listener
        .accept()
        .map_err(|e| HandlerError(format!("tcp_conn accept: {e}")))?;
    drop(listener);
    let fd = conn.as_raw_fd();
    clear_cloexec(fd)?;

    let mut child = Command::new(&args.child_binary);
    child
        .args([
            "inherit-matrix",
            "tcp-conn-child",
            args.op.id(),
            &args.timeout_ms.to_string(),
        ])
        .env("LITEBOX_INHERIT_FD", fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = child
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;

    let output = wait_with_timeout(child, Duration::from_millis(args.timeout_ms + 1000))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut exit_code = output.status.code().unwrap_or(-1);

    if exit_code == 0 {
        let expected = match args.op {
            InheritOp::ParentWritesChildReads => "ping",
            InheritOp::ChildWritesParentReads => "pong",
            InheritOp::ChildShutdownThenParentEof => "shutdown",
            _ => {
                return Err(HandlerError(format!(
                    "unsupported tcp_conn op {}",
                    args.op.id()
                )));
            }
        };
        if stdout != expected {
            exit_code = 1;
            return Ok(ChildOutput {
                exit_code,
                stdout,
                stderr: format!("tcp_conn child stdout mismatch: expected {expected}; {stderr}"),
            });
        }
    }

    Ok(ChildOutput {
        exit_code,
        stdout,
        stderr,
    })
}

async fn handle_tcp_conn_peer(
    args: TcpConnPeerArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<TcpConnPeerOutput, HandlerError> {
    Ok(tcp_conn_peer_out(run_tcp_conn_peer(args)))
}

fn run_tcp_conn_peer(args: TcpConnPeerArgs) -> Result<String, String> {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, args.port));
    let mut stream = connect_loopback_with_timeout(addr, args.timeout_ms)
        .map_err(|e| format!("tcp_conn peer connect port {}: {e}", args.port))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(args.timeout_ms)))
        .map_err(|e| format!("tcp_conn peer set_read_timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_millis(args.timeout_ms)))
        .map_err(|e| format!("tcp_conn peer set_write_timeout: {e}"))?;

    match args.op {
        InheritOp::ParentWritesChildReads => {
            stream
                .write_all(b"ping")
                .map_err(|e| format!("tcp_conn peer write ping: {e}"))?;
            Ok("wrote ping".to_string())
        }
        InheritOp::ChildWritesParentReads => {
            let mut buf = [0_u8; 4];
            stream
                .read_exact(&mut buf)
                .map_err(|e| format!("tcp_conn peer read pong: {e}"))?;
            if buf != *b"pong" {
                return Err(format!(
                    "tcp_conn peer payload mismatch: got {:?}, expected pong",
                    String::from_utf8_lossy(&buf)
                ));
            }
            Ok("read pong".to_string())
        }
        InheritOp::ChildShutdownThenParentEof => {
            let mut buf = [0_u8; 1];
            match stream.read(&mut buf) {
                Ok(0) => Ok("read EOF".to_string()),
                Ok(n) => Err(format!("tcp_conn peer EOF read got {n} bytes")),
                Err(e) => Err(format!("tcp_conn peer EOF read: {e}")),
            }
        }
        _ => Err(format!("unsupported tcp_conn peer op {}", args.op.id())),
    }
}

fn tcp_conn_peer_out(result: Result<String, String>) -> TcpConnPeerOutput {
    match result {
        Ok(detail) => TcpConnPeerOutput {
            passed: true,
            detail,
        },
        Err(detail) => TcpConnPeerOutput {
            passed: false,
            detail,
        },
    }
}

async fn handle_pipe_trial(
    args: PipeTrialArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ChildOutput, HandlerError> {
    run_pipe_trial(&args)
}

fn run_pipe_trial(args: &PipeTrialArgs) -> Result<ChildOutput, HandlerError> {
    let (read_end, write_end) = pipe_owned(libc::O_CLOEXEC)?;
    let read_fd = read_end.as_raw_fd();
    let write_fd = write_end.as_raw_fd();
    let child_fd = match args.op {
        InheritOp::ParentWritesChildReads => read_fd,
        InheritOp::ChildWritesParentReads | InheritOp::ChildCloseParentReadsEof => write_fd,
        _ => {
            return Err(HandlerError(format!(
                "unsupported pipe op {}",
                args.op.id()
            )));
        }
    };
    // `LITEBOX_INHERIT_FD` documents the single pipe end intentionally
    // inherited by the exec'd child: read end for p2c, write end for c2p/EOF.
    clear_cloexec(child_fd)?;

    if args.op == InheritOp::ParentWritesChildReads {
        write_all_fd(write_fd, b"ping", "pipe parent write ping").map_err(HandlerError)?;
    }

    let mut child = Command::new(&args.child_binary);
    child
        .args(["inherit-matrix", "pipe-child", args.op.id()])
        .env("LITEBOX_INHERIT_FD", child_fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = child
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;

    let mut parent_error = None;
    match args.op {
        InheritOp::ParentWritesChildReads => {
            drop(write_end);
        }
        InheritOp::ChildWritesParentReads => {
            drop(write_end);
            if let Err(e) = read_pipe_payload(read_fd, b"pong", args.timeout_ms) {
                parent_error = Some(e);
            }
        }
        InheritOp::ChildCloseParentReadsEof => {
            drop(write_end);
            if let Err(e) = read_pipe_eof(read_fd, args.timeout_ms) {
                parent_error = Some(e);
            }
        }
        _ => unreachable!(),
    }

    if parent_error.is_some() {
        let _ = child.kill();
    }

    let output = wait_with_timeout(child, Duration::from_millis(args.timeout_ms + 1000))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut exit_code = output.status.code().unwrap_or(-1);

    if let Some(e) = parent_error {
        exit_code = 1;
        return Ok(ChildOutput {
            exit_code,
            stdout,
            stderr: format!("{}; {stderr}", e.0),
        });
    }

    if exit_code == 0 {
        let expected = match args.op {
            InheritOp::ParentWritesChildReads => "ping",
            InheritOp::ChildWritesParentReads => "pong",
            InheritOp::ChildCloseParentReadsEof => "closed",
            _ => unreachable!(),
        };
        if stdout != expected {
            exit_code = 1;
            return Ok(ChildOutput {
                exit_code,
                stdout,
                stderr: format!("pipe stdout mismatch: expected {expected}; {stderr}"),
            });
        }
    }

    Ok(ChildOutput {
        exit_code,
        stdout,
        stderr,
    })
}

async fn handle_socketpair_trial(
    args: SocketpairTrialArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ChildOutput, HandlerError> {
    let (parent_end, child_end) = socketpair_owned()?;
    let parent_fd = parent_end.as_raw_fd();
    let child_fd = child_end.as_raw_fd();
    clear_cloexec(child_fd)?;

    if args.op == InheritOp::ReadAfterParentWrite {
        write_all_fd(parent_fd, b"ping", "socketpair parent pre-write").map_err(HandlerError)?;
    }

    let mut child = Command::new(&args.child_binary);
    child
        .args([
            "inherit-matrix",
            "socketpair-child",
            args.op.id(),
            &args.timeout_ms.to_string(),
        ])
        .env("LITEBOX_INHERIT_FD", child_fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = child
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;
    drop(child_end);

    let mut parent_error = None;
    match args.op {
        InheritOp::ReadAfterParentWrite => {}
        InheritOp::WriteThenParentReads => {
            if let Err(e) = read_socketpair_payload(parent_fd, b"pong", args.timeout_ms) {
                parent_error = Some(e);
            }
        }
        InheritOp::ChildShutdownThenParentEof => {
            if let Err(e) = read_socketpair_eof(parent_fd, args.timeout_ms) {
                parent_error = Some(e);
            }
        }
        _ => {
            return Err(HandlerError(format!(
                "unsupported socketpair op {}",
                args.op.id()
            )));
        }
    }

    if parent_error.is_some() {
        let _ = child.kill();
    }

    let output = wait_with_timeout(child, Duration::from_millis(args.timeout_ms + 1000))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut exit_code = output.status.code().unwrap_or(-1);

    if let Some(e) = parent_error {
        exit_code = 1;
        return Ok(ChildOutput {
            exit_code,
            stdout,
            stderr: format!("{}; {stderr}", e.0),
        });
    }

    if exit_code == 0 {
        let expected = match args.op {
            InheritOp::ReadAfterParentWrite => "ping",
            InheritOp::WriteThenParentReads => "pong",
            InheritOp::ChildShutdownThenParentEof => "shutdown",
            _ => unreachable!(),
        };
        if stdout != expected {
            exit_code = 1;
            return Ok(ChildOutput {
                exit_code,
                stdout,
                stderr: format!("socketpair stdout mismatch: expected {expected}; {stderr}"),
            });
        }
    }

    Ok(ChildOutput {
        exit_code,
        stdout,
        stderr,
    })
}

fn socketpair_owned() -> Result<(OwnedFd, OwnedFd), HandlerError> {
    let mut fds = [0; 2];
    // SAFETY: socketpair initializes both fd slots on success.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(HandlerError(format!(
            "socketpair(AF_UNIX, SOCK_STREAM): {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: socketpair returned two fresh descriptors owned by this function.
    let left = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: socketpair returned two fresh descriptors owned by this function.
    let right = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((left, right))
}

fn read_socketpair_payload(
    fd: RawFd,
    expected: &[u8],
    timeout_ms: u64,
) -> Result<(), HandlerError> {
    let revents = poll_fd(
        fd,
        libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        timeout_ms,
        "socketpair parent payload",
    )?;
    if revents & libc::POLLIN == 0 {
        return Err(HandlerError(format!(
            "socketpair parent payload poll got {}, expected POLLIN",
            describe_events(revents)
        )));
    }
    let mut buf = vec![0_u8; expected.len()];
    read_exact_fd(fd, &mut buf, "socketpair parent read")?;
    if buf == expected {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "socketpair parent payload mismatch: got {:?}, expected {:?}",
            String::from_utf8_lossy(&buf),
            String::from_utf8_lossy(expected)
        )))
    }
}

fn read_socketpair_eof(fd: RawFd, timeout_ms: u64) -> Result<(), HandlerError> {
    let revents = poll_fd(
        fd,
        libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        timeout_ms,
        "socketpair parent EOF",
    )?;
    if revents & (libc::POLLIN | libc::POLLHUP) == 0 {
        return Err(HandlerError(format!(
            "socketpair parent EOF poll got {}, expected POLLIN/POLLHUP",
            describe_events(revents)
        )));
    }
    let mut byte = [0_u8; 1];
    // SAFETY: `byte` is valid writable memory and fd is a live socketpair endpoint.
    let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast::<libc::c_void>(), byte.len()) };
    match n.cmp(&0) {
        std::cmp::Ordering::Equal => Ok(()),
        std::cmp::Ordering::Greater => Err(HandlerError(format!(
            "socketpair parent EOF read expected 0, got {n} bytes"
        ))),
        std::cmp::Ordering::Less => Err(HandlerError(format!(
            "socketpair parent EOF read: {}",
            std::io::Error::last_os_error()
        ))),
    }
}

fn read_pipe_payload(fd: RawFd, expected: &[u8], timeout_ms: u64) -> Result<(), HandlerError> {
    let revents = poll_fd(
        fd,
        libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        timeout_ms,
        "pipe parent payload",
    )?;
    if revents & libc::POLLIN == 0 {
        return Err(HandlerError(format!(
            "pipe parent payload poll got {}, expected POLLIN",
            describe_events(revents)
        )));
    }
    let mut buf = vec![0_u8; expected.len()];
    read_exact_fd(fd, &mut buf, "pipe parent read")?;
    if buf == expected {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "pipe parent payload mismatch: got {:?}, expected {:?}",
            String::from_utf8_lossy(&buf),
            String::from_utf8_lossy(expected)
        )))
    }
}

fn read_pipe_eof(fd: RawFd, timeout_ms: u64) -> Result<(), HandlerError> {
    let revents = poll_fd(
        fd,
        libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        timeout_ms,
        "pipe parent EOF",
    )?;
    if revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
        return Err(HandlerError(format!(
            "pipe parent EOF poll got {}, expected EOF readiness",
            describe_events(revents)
        )));
    }
    let mut byte = [0_u8; 1];
    // SAFETY: `byte` is valid writable memory and fd is a live pipe read end.
    let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast::<libc::c_void>(), byte.len()) };
    match n.cmp(&0) {
        std::cmp::Ordering::Equal => Ok(()),
        std::cmp::Ordering::Greater => Err(HandlerError(format!(
            "pipe parent EOF read expected 0, got {n} bytes"
        ))),
        std::cmp::Ordering::Less => Err(HandlerError(format!(
            "pipe parent EOF read: {}",
            std::io::Error::last_os_error()
        ))),
    }
}

#[allow(clippy::too_many_lines)]
async fn handle_signalfd_trial(
    args: SignalfdTrialArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ChildOutput, HandlerError> {
    Signalfd::block_signals(&[libc::SIGUSR1])
        .map_err(|e| HandlerError(format!("signalfd block SIGUSR1: {e}")))?;
    let sfd = Signalfd::open(&[libc::SIGUSR1], "nonblock|cloexec")
        .map_err(|e| HandlerError(format!("signalfd open: {e}")))?;
    let fd = sfd.as_raw_fd();
    clear_cloexec(fd)?;

    let ready_pipe = if matches!(args.op, InheritOp::RecvAfterFork | InheritOp::RecvCloseEof) {
        Some(pipe_owned(libc::O_CLOEXEC)?)
    } else {
        None
    };
    let go_pipe = if args.op == InheritOp::RecvCloseEof {
        Some(pipe_owned(libc::O_CLOEXEC)?)
    } else {
        None
    };

    if let Some((_, ready_write)) = &ready_pipe {
        clear_cloexec(ready_write.as_raw_fd())?;
    }
    if let Some((go_read, _)) = &go_pipe {
        clear_cloexec(go_read.as_raw_fd())?;
    }

    let mut child = Command::new(&args.child_binary);
    child
        .args([
            "inherit-matrix",
            "signalfd-child",
            args.op.id(),
            &args.timeout_ms.to_string(),
        ])
        .env("LITEBOX_INHERIT_FD", fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some((_, ready_write)) = &ready_pipe {
        child.env("LITEBOX_READY_FD", ready_write.as_raw_fd().to_string());
    }
    if let Some((go_read, _)) = &go_pipe {
        child.env("LITEBOX_GO_FD", go_read.as_raw_fd().to_string());
    }

    let mut child = child
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;
    let child_pid = child.id();
    let ready_read = ready_pipe.map(|(read, write)| {
        drop(write);
        read
    });
    let go_write = go_pipe.map(|(read, write)| {
        drop(read);
        write
    });

    let mut parent_error = None;
    match args.op {
        InheritOp::RecvPending => {
            if let Err(e) = kill_pid(child_pid, libc::SIGUSR1, "signalfd recv_pending") {
                parent_error = Some(e);
            }
        }
        InheritOp::RecvAfterFork => {
            if let Some(ready_read) = ready_read.as_ref()
                && let Err(e) = read_ready_byte(ready_read.as_raw_fd(), args.timeout_ms)
            {
                parent_error = Some(e);
            }
            if parent_error.is_none()
                && let Err(e) = kill_pid(child_pid, libc::SIGUSR1, "signalfd recv_after_fork")
            {
                parent_error = Some(e);
            }
        }
        InheritOp::RecvCloseEof => {
            if let Some(ready_read) = ready_read.as_ref()
                && let Err(e) = read_ready_byte(ready_read.as_raw_fd(), args.timeout_ms)
            {
                parent_error = Some(e);
            }
            if parent_error.is_none() {
                drop(sfd);
                if let Some(go_write) = go_write.as_ref()
                    && let Err(e) = write_all_fd(go_write.as_raw_fd(), b"g", "signalfd close sync")
                {
                    parent_error = Some(HandlerError(e));
                }
            }
        }
        _ => {
            return Err(HandlerError(format!(
                "unsupported signalfd op {}",
                args.op.id()
            )));
        }
    }

    if parent_error.is_some() {
        let _ = child.kill();
    }

    let output = wait_with_timeout(child, Duration::from_millis(args.timeout_ms + 1000))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut exit_code = output.status.code().unwrap_or(-1);

    if let Some(e) = parent_error {
        exit_code = 1;
        return Ok(ChildOutput {
            exit_code,
            stdout,
            stderr: format!("{}; {stderr}", e.0),
        });
    }

    if exit_code == 0 {
        let expected = match args.op {
            InheritOp::RecvPending | InheritOp::RecvAfterFork => libc::SIGUSR1.to_string(),
            InheritOp::RecvCloseEof => "eagain".to_string(),
            _ => String::new(),
        };
        if stdout != expected {
            exit_code = 1;
            return Ok(ChildOutput {
                exit_code,
                stdout,
                stderr: format!("signalfd stdout mismatch: expected {expected}; {stderr}"),
            });
        }
    }

    Ok(ChildOutput {
        exit_code,
        stdout,
        stderr,
    })
}

fn kill_pid(pid: u32, signo: i32, context: &str) -> Result<(), HandlerError> {
    // SAFETY: kill is called with a child pid returned by spawn and a valid signal number.
    let rc = unsafe { libc::kill(pid.cast_signed(), signo) };
    if rc == 0 {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "{context}: kill({pid}, {signo}): {}",
            std::io::Error::last_os_error()
        )))
    }
}

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
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: pipe2 returned two fresh descriptors owned by this function.
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((read, write))
}

fn read_ready_byte(fd: RawFd, timeout_ms: u64) -> Result<(), HandlerError> {
    let revents = poll_fd(
        fd,
        libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        timeout_ms,
        "signalfd child ready",
    )?;
    if revents & libc::POLLIN == 0 {
        return Err(HandlerError(format!(
            "signalfd child ready poll got {}, expected POLLIN",
            describe_events(revents)
        )));
    }
    let mut byte = [0_u8; 1];
    read_exact_fd(fd, &mut byte, "signalfd child ready read")
}

async fn handle_timerfd_trial(
    args: TimerfdTrialArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ChildOutput, HandlerError> {
    let timerfd = open_timerfd()?;
    let fd = timerfd.as_raw_fd();
    clear_cloexec(fd)?;

    match args.op {
        InheritOp::ReadAfterExpire => {
            arm_timerfd(fd, Duration::from_millis(50))?;
            wait_for_timerfd_readable(fd, args.timeout_ms, "timerfd pre-fork expiry")?;
        }
        InheritOp::ArmThenInheritThenRead => {
            arm_timerfd(fd, Duration::from_millis(200))?;
        }
        InheritOp::PollReadableAfterExpire => {
            arm_timerfd(fd, Duration::from_millis(50))?;
        }
        _ => {
            return Err(HandlerError(format!(
                "unsupported timerfd op {}",
                args.op.id()
            )));
        }
    }

    let child = Command::new(&args.child_binary)
        .args([
            "inherit-matrix",
            "timerfd-child",
            args.op.id(),
            &args.timeout_ms.to_string(),
        ])
        .env("LITEBOX_INHERIT_FD", fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;

    let output = wait_with_timeout(child, Duration::from_millis(args.timeout_ms + 1000))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut exit_code = output.status.code().unwrap_or(-1);

    if exit_code == 0 {
        let count = match stdout.parse::<u64>() {
            Ok(count) => count,
            Err(e) => {
                return Ok(ChildOutput {
                    exit_code: 1,
                    stdout,
                    stderr: format!("timerfd stdout parse: {e}; {stderr}"),
                });
            }
        };
        match args.op {
            InheritOp::ReadAfterExpire | InheritOp::PollReadableAfterExpire if count == 0 => {
                exit_code = 1;
                return Ok(ChildOutput {
                    exit_code,
                    stdout,
                    stderr: format!("timerfd read count mismatch: expected >=1; {stderr}"),
                });
            }
            InheritOp::ArmThenInheritThenRead if count != 1 => {
                exit_code = 1;
                return Ok(ChildOutput {
                    exit_code,
                    stdout,
                    stderr: format!("timerfd read count mismatch: expected 1; {stderr}"),
                });
            }
            _ => {}
        }
    }

    Ok(ChildOutput {
        exit_code,
        stdout,
        stderr,
    })
}

fn open_timerfd() -> Result<OwnedFd, HandlerError> {
    // SAFETY: timerfd_create is called with constant clock/flag values; errors are checked below.
    let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    if fd < 0 {
        return Err(HandlerError(format!(
            "timerfd_create(CLOCK_MONOTONIC): {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: timerfd_create returned a fresh descriptor and ownership is transferred here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn arm_timerfd(fd: RawFd, duration: Duration) -> Result<(), HandlerError> {
    let spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: duration.subsec_nanos().into(),
        },
    };
    // SAFETY: `spec` is initialized and `fd` is expected to be a live timerfd.
    if unsafe { libc::timerfd_settime(fd, 0, std::ptr::from_ref(&spec), std::ptr::null_mut()) } != 0
    {
        return Err(HandlerError(format!(
            "timerfd_settime: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn wait_for_timerfd_readable(
    fd: RawFd,
    timeout_ms: u64,
    context: &str,
) -> Result<(), HandlerError> {
    let revents = poll_fd(fd, libc::POLLIN | libc::POLLERR, timeout_ms, context)?;
    if revents & libc::POLLIN == 0 {
        return Err(HandlerError(format!(
            "{context}: poll got {}, expected POLLIN",
            describe_events(revents)
        )));
    }
    Ok(())
}

async fn handle_pty_trial(
    args: PtyTrialArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ChildOutput, HandlerError> {
    let (master, slave) = open_raw_pty_pair()?;
    let slave_fd = slave.as_raw_fd();
    clear_cloexec(slave_fd)?;

    let mut child = Command::new(&args.child_binary);
    child
        .args([
            "inherit-matrix",
            "pty-child",
            args.op.id(),
            &args.timeout_ms.to_string(),
        ])
        .env("LITEBOX_INHERIT_FD", slave_fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = child
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;
    drop(slave);

    let mut parent_error = None;
    match args.op {
        InheritOp::SlaveWrite => {
            if let Err(e) = read_pty_payload(master.as_raw_fd(), b"hi\n", args.timeout_ms) {
                parent_error = Some(e);
            }
        }
        InheritOp::SlaveRead => {
            if let Err(e) = write_all_fd(master.as_raw_fd(), b"hi\n", "pty master write") {
                parent_error = Some(HandlerError(e));
            }
        }
        InheritOp::SlaveClose => {
            if let Err(e) = wait_pty_hup_or_eof(master.as_raw_fd(), args.timeout_ms) {
                parent_error = Some(e);
            }
        }
        _ => {
            return Err(HandlerError(format!("unsupported pty op {}", args.op.id())));
        }
    }

    let output = wait_with_timeout(child, Duration::from_millis(args.timeout_ms + 1000))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut exit_code = output.status.code().unwrap_or(-1);

    if let Some(e) = parent_error {
        exit_code = 1;
        return Ok(ChildOutput {
            exit_code,
            stdout,
            stderr: format!("{}; {stderr}", e.0),
        });
    }

    if exit_code == 0 {
        match args.op {
            InheritOp::SlaveWrite if stdout != "wrote" => {
                exit_code = 1;
                return Ok(ChildOutput {
                    exit_code,
                    stdout,
                    stderr: format!("pty slave_write stdout mismatch: expected wrote; {stderr}"),
                });
            }
            InheritOp::SlaveRead if stdout != "hi" => {
                exit_code = 1;
                return Ok(ChildOutput {
                    exit_code,
                    stdout,
                    stderr: format!("pty slave_read stdout mismatch: expected hi; {stderr}"),
                });
            }
            InheritOp::SlaveClose if stdout != "closed" => {
                exit_code = 1;
                return Ok(ChildOutput {
                    exit_code,
                    stdout,
                    stderr: format!("pty slave_close stdout mismatch: expected closed; {stderr}"),
                });
            }
            _ => {}
        }
    }

    Ok(ChildOutput {
        exit_code,
        stdout,
        stderr,
    })
}

const FS_FID_PAYLOAD: &[u8] = b"fs-fid-payload";

async fn handle_fs_fid_trial(
    args: FsFidTrialArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ChildOutput, HandlerError> {
    let path = fs_fid_path(&args.test_id);
    let result = run_fs_fid_trial(&args, &path);
    let cleanup = std::fs::remove_file(&path);
    match result {
        Ok(mut out) => {
            if out.exit_code == 0
                && let Err(e) = cleanup
                && e.kind() != std::io::ErrorKind::NotFound
            {
                out.exit_code = 1;
                out.stderr = format!("fs_fid cleanup {}: {e}; {}", path.display(), out.stderr);
            }
            Ok(out)
        }
        Err(e) => {
            let _ = cleanup;
            Err(e)
        }
    }
}

fn run_fs_fid_trial(
    args: &FsFidTrialArgs,
    path: &std::path::Path,
) -> Result<ChildOutput, HandlerError> {
    let _ = std::fs::remove_file(path);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| HandlerError(format!("fs_fid open {}: {e}", path.display())))?;
    file.write_all(FS_FID_PAYLOAD)
        .map_err(|e| HandlerError(format!("fs_fid seed write: {e}")))?;
    file.flush()
        .map_err(|e| HandlerError(format!("fs_fid seed flush: {e}")))?;

    match args.scenario {
        FsFidScenario::SharedPosition => {}
        FsFidScenario::UnlinkedAfterInherit | FsFidScenario::ParentCloseFirst => {
            file.seek(SeekFrom::Start(0))
                .map_err(|e| HandlerError(format!("fs_fid seek start: {e}")))?;
        }
    }
    std::fs::remove_file(path)
        .map_err(|e| HandlerError(format!("fs_fid unlink {}: {e}", path.display())))?;

    let fd = file.as_raw_fd();
    clear_cloexec(fd)?;

    let mut control = [-1i32; 2];
    if matches!(args.scenario, FsFidScenario::ParentCloseFirst) {
        // SAFETY: control points to two writable fd slots.
        if unsafe { libc::pipe(control.as_mut_ptr()) } != 0 {
            return Err(HandlerError(format!(
                "fs_fid control pipe: {}",
                std::io::Error::last_os_error()
            )));
        }
        clear_cloexec(control[0])?;
    }

    let mut child = Command::new(&args.child_binary);
    child
        .args(["inherit-matrix", "fs-fid-child", args.scenario.id()])
        .env("LITEBOX_INHERIT_FD", fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if matches!(args.scenario, FsFidScenario::ParentCloseFirst) {
        child.env("LITEBOX_FS_FID_CONTROL_FD", control[0].to_string());
    }
    let child = child
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;

    if matches!(args.scenario, FsFidScenario::ParentCloseFirst) {
        drop(file);
        // SAFETY: parent writes one byte to release the child, then closes both
        // control endpoints it owns.
        unsafe {
            libc::close(control[0]);
            let byte = [b'!'];
            let _ = libc::write(control[1], byte.as_ptr().cast::<libc::c_void>(), byte.len());
            libc::close(control[1]);
        }
    } else if control[0] >= 0 {
        // SAFETY: defensive cleanup for unused control fds.
        unsafe {
            libc::close(control[0]);
            libc::close(control[1]);
        }
    }

    let output = wait_with_timeout(child, Duration::from_millis(args.timeout_ms + 1000))?;
    Ok(ChildOutput {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

fn fs_fid_path(test_id: &str) -> std::path::PathBuf {
    let sanitized: String = test_id
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '-' => c,
            _ => '_',
        })
        .collect();
    std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(format!("canary-{sanitized}-{}.txt", std::process::id()))
}

const BROKERFILE_READ_PAYLOAD: &[u8] = b"brokerfile inherited read\n";
const BROKERFILE_WRITE_PAYLOAD: &[u8] = b"hello\n";
const BROKERFILE_LSEEK_PAYLOAD: &[u8] = b"ABCDEFGH";
const BROKERFILE_LSEEK_EXPECTED: &[u8] = b"DEF";

async fn handle_brokerfile_trial(
    args: BrokerFileTrialArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ChildOutput, HandlerError> {
    let path = brokerfile_path(&args.test_id);
    let result = run_brokerfile_trial(&args, &path);
    let cleanup = std::fs::remove_file(&path);

    match result {
        Ok(mut out) => {
            if out.exit_code == 0
                && let Err(e) = cleanup
                && e.kind() != std::io::ErrorKind::NotFound
            {
                out.exit_code = 1;
                out.stderr = format!("brokerfile cleanup {path}: {e}; {}", out.stderr);
            }
            Ok(out)
        }
        Err(e) => {
            let _ = cleanup;
            Err(e)
        }
    }
}

fn run_brokerfile_trial(
    args: &BrokerFileTrialArgs,
    path: &str,
) -> Result<ChildOutput, HandlerError> {
    let _ = std::fs::remove_file(path);
    let mut file = prepare_brokerfile_parent_fd(args.op, path)?;
    let fd = file.as_raw_fd();
    clear_cloexec(fd)?;

    let mut child = Command::new(&args.child_binary);
    child
        .args(["inherit-matrix", "brokerfile-child", args.op.id()])
        .env("LITEBOX_INHERIT_FD", fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = child
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;

    let output = wait_with_timeout(child, Duration::from_millis(args.timeout_ms + 1000))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut exit_code = output.status.code().unwrap_or(-1);

    if exit_code == 0 {
        match args.op {
            InheritOp::ReadAtOffset0 => {
                exit_code = check_child_stdout(
                    &stdout,
                    BROKERFILE_READ_PAYLOAD,
                    "brokerfile read_at_offset_0",
                );
            }
            InheritOp::WriteThenParentReadsBack => {
                if stdout != "hello" {
                    exit_code = 1;
                    return Ok(ChildOutput {
                        exit_code,
                        stdout,
                        stderr: format!(
                            "brokerfile write stdout mismatch: expected hello; {stderr}"
                        ),
                    });
                }
                let contents =
                    read_parent_file_from_start(&mut file, BROKERFILE_WRITE_PAYLOAD.len())?;
                if contents != BROKERFILE_WRITE_PAYLOAD {
                    exit_code = 1;
                    return Ok(ChildOutput {
                        exit_code,
                        stdout,
                        stderr: format!(
                            "brokerfile parent read mismatch: got {:?}, expected {:?}; {stderr}",
                            String::from_utf8_lossy(&contents),
                            String::from_utf8_lossy(BROKERFILE_WRITE_PAYLOAD)
                        ),
                    });
                }
            }
            InheritOp::LseekThenRead => {
                exit_code = check_child_stdout(
                    &stdout,
                    BROKERFILE_LSEEK_EXPECTED,
                    "brokerfile lseek_then_read",
                );
            }
            _ => {
                return Err(HandlerError(format!(
                    "unsupported brokerfile op {}",
                    args.op.id()
                )));
            }
        }
    }

    Ok(ChildOutput {
        exit_code,
        stdout,
        stderr,
    })
}

fn prepare_brokerfile_parent_fd(op: InheritOp, path: &str) -> Result<File, HandlerError> {
    match op {
        InheritOp::ReadAtOffset0 => {
            File::create(path)
                .map_err(|e| HandlerError(format!("brokerfile create {path}: {e}")))?;
            let file = OpenOptions::new()
                .read(true)
                .open(path)
                .map_err(|e| HandlerError(format!("brokerfile open read {path}: {e}")))?;
            std::fs::write(path, BROKERFILE_READ_PAYLOAD)
                .map_err(|e| HandlerError(format!("brokerfile seed write {path}: {e}")))?;
            Ok(file)
        }
        InheritOp::WriteThenParentReadsBack => OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| HandlerError(format!("brokerfile open read/write {path}: {e}"))),
        InheritOp::LseekThenRead => {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|e| HandlerError(format!("brokerfile open lseek {path}: {e}")))?;
            file.write_all(BROKERFILE_LSEEK_PAYLOAD)
                .map_err(|e| HandlerError(format!("brokerfile seed lseek payload: {e}")))?;
            file.flush()
                .map_err(|e| HandlerError(format!("brokerfile seed flush: {e}")))?;
            Ok(file)
        }
        _ => Err(HandlerError(format!(
            "unsupported brokerfile op {}",
            op.id()
        ))),
    }
}

fn read_parent_file_from_start(file: &mut File, len: usize) -> Result<Vec<u8>, HandlerError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| HandlerError(format!("brokerfile parent seek: {e}")))?;
    let mut buf = vec![0_u8; len];
    file.read_exact(&mut buf)
        .map_err(|e| HandlerError(format!("brokerfile parent read: {e}")))?;
    Ok(buf)
}

fn check_child_stdout(stdout: &str, expected: &[u8], _context: &str) -> i32 {
    let expected = String::from_utf8_lossy(expected);
    let expected = expected.trim_end_matches('\n');
    i32::from(stdout != expected)
}

fn brokerfile_path(test_id: &str) -> String {
    let sanitized: String = test_id
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '-' => c,
            _ => '_',
        })
        .collect();
    format!("/tmp/canary-{sanitized}-{}.txt", std::process::id())
}

async fn handle_pidfd_trial(
    args: PidfdTrialArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ChildOutput, HandlerError> {
    // Pick a target sleep that fits the op's timing model:
    // - Poll: target is alive when child is spawned; exits ~400ms later
    //   so the child's poll(POLLIN, timeout_ms) observes the transition.
    // - RecvAfterFork: target exits quickly; parent waits for the exit
    //   before spawning the child, so the inherited pidfd is already
    //   POLLIN-ready when the child observes it (sticky).
    let target_sleep_ms = match args.op {
        InheritOp::Poll => 400_u32,
        InheritOp::RecvAfterFork => 50_u32,
        _ => {
            return Err(HandlerError(format!(
                "unsupported pidfd op {}",
                args.op.id()
            )));
        }
    };

    // SAFETY: fork is followed in the child by only async-signal-safe
    // libc calls (usleep, _exit). The parent continues normal Rust.
    let target_pid = unsafe { libc::fork() };
    if target_pid < 0 {
        return Err(HandlerError(format!(
            "pidfd target fork: {}",
            std::io::Error::last_os_error()
        )));
    }
    if target_pid == 0 {
        // SAFETY: child path - async-signal-safe primitives only.
        unsafe {
            libc::usleep(target_sleep_ms * 1000);
            libc::_exit(0);
        }
    }

    let target_pid_u32 =
        u32::try_from(target_pid).map_err(|e| HandlerError(format!("pidfd target pid: {e}")))?;
    let pidfd = match Pidfd::open(target_pid_u32) {
        Ok(p) => p,
        Err(e) => {
            // Best-effort reap; we can't proceed without the pidfd.
            // SAFETY: target_pid is a child of this process.
            unsafe {
                let mut status = 0;
                libc::waitpid(target_pid, &raw mut status, 0);
            }
            return Err(HandlerError(format!("pidfd_open({target_pid_u32}): {e}")));
        }
    };
    let fd = pidfd.as_raw_fd();
    clear_cloexec(fd)?;

    if args.op == InheritOp::RecvAfterFork {
        match pidfd.poll_exit_in(i32::try_from(args.timeout_ms).unwrap_or(i32::MAX)) {
            Ok(true) => {}
            Ok(false) => {
                // SAFETY: best-effort reap on the error path.
                unsafe {
                    let mut status = 0;
                    libc::waitpid(target_pid, &raw mut status, 0);
                }
                return Err(HandlerError(
                    "pidfd parent poll_exit_in: target did not exit before child spawn".into(),
                ));
            }
            Err(e) => {
                // SAFETY: best-effort reap on the error path.
                unsafe {
                    let mut status = 0;
                    libc::waitpid(target_pid, &raw mut status, 0);
                }
                return Err(HandlerError(format!("pidfd parent pre-spawn poll: {e}")));
            }
        }
    }

    let mut child = Command::new(&args.child_binary);
    child
        .args([
            "inherit-matrix",
            "pidfd-child",
            args.op.id(),
            &args.timeout_ms.to_string(),
        ])
        .env("LITEBOX_INHERIT_FD", fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = child
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;

    let output = wait_with_timeout(child, Duration::from_millis(args.timeout_ms + 2000))?;

    // Reap target now that the child has observed (or failed to observe) it.
    // SAFETY: target_pid is a child of this process; status is writable.
    unsafe {
        let mut status = 0;
        let _ = libc::waitpid(target_pid, &raw mut status, libc::WNOHANG);
        // If it hasn't exited yet (Poll op may finish first), block briefly.
        let _ = libc::waitpid(target_pid, &raw mut status, 0);
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut exit_code = output.status.code().unwrap_or(-1);

    if exit_code == 0 && stdout != "ready" {
        exit_code = 1;
        return Ok(ChildOutput {
            exit_code,
            stdout,
            stderr: format!("pidfd stdout mismatch: expected ready; {stderr}"),
        });
    }

    Ok(ChildOutput {
        exit_code,
        stdout,
        stderr,
    })
}

async fn handle_eventfd_trial(
    args: EventfdTrialArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ChildOutput, HandlerError> {
    let ev = EventFd::open(0, "nonblock|semaphore|cloexec")
        .map_err(|e| HandlerError(format!("eventfd open: {e}")))?;
    let fd = ev.as_raw_fd();
    clear_cloexec(fd)?;

    let (child_value, parent_value) = match args.op {
        InheritOp::Read | InheritOp::Poll => (42_u64, 0_u64),
        InheritOp::Write => (100_u64, 100_u64),
        _ => {
            return Err(HandlerError(format!(
                "unsupported eventfd op {}",
                args.op.id()
            )));
        }
    };

    if args.op == InheritOp::Read {
        ev.write(child_value)
            .map_err(|e| HandlerError(format!("eventfd pre-write {child_value}: {e}")))?;
    }

    let mut child = Command::new(&args.child_binary);
    child
        .args([
            "inherit-matrix",
            "eventfd-child",
            args.op.id(),
            &child_value.to_string(),
            &args.timeout_ms.to_string(),
        ])
        .env("LITEBOX_INHERIT_FD", fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = child
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;

    if args.op == InheritOp::Poll {
        ev.write(child_value)
            .map_err(|e| HandlerError(format!("eventfd poll-write {child_value}: {e}")))?;
    } else if args.op == InheritOp::Write {
        read_eventfd_total(&ev, parent_value, Duration::from_millis(args.timeout_ms))?;
    }

    let output = wait_with_timeout(child, Duration::from_millis(args.timeout_ms + 1000))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut exit_code = output.status.code().unwrap_or(-1);

    if exit_code == 0 {
        match args.op {
            InheritOp::Read | InheritOp::Poll if stdout != "1" => {
                exit_code = 1;
                return Ok(ChildOutput {
                    exit_code,
                    stdout,
                    stderr: format!("eventfd semaphore read mismatch: expected 1; {stderr}"),
                });
            }
            InheritOp::Write if stdout != parent_value.to_string() => {
                exit_code = 1;
                return Ok(ChildOutput {
                    exit_code,
                    stdout,
                    stderr: format!(
                        "eventfd write stdout mismatch: expected {parent_value}; {stderr}"
                    ),
                });
            }
            _ => {}
        }
    }

    Ok(ChildOutput {
        exit_code,
        stdout,
        stderr,
    })
}

async fn handle_epoll_trial(
    args: EpollTrialArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ChildOutput, HandlerError> {
    let ev = EventFd::open(0, "nonblock|cloexec")
        .map_err(|e| HandlerError(format!("epoll trial eventfd: {e}")))?;
    let event_fd = ev.as_raw_fd();
    // SAFETY: epoll_create1 returns a fresh fd on success.
    let raw_ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if raw_ep < 0 {
        return Err(HandlerError(format!(
            "epoll_create1: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: raw_ep is a newly returned descriptor owned here.
    let epoll_owned = unsafe { OwnedFd::from_raw_fd(raw_ep) };
    let epoll_fd = epoll_owned.as_raw_fd();

    let mut event = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: event_fd.cast_unsigned().into(),
    };
    // SAFETY: epoll_fd and event_fd are live; event points to initialized storage.
    let rc = unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, event_fd, &raw mut event) };
    if rc != 0 {
        return Err(HandlerError(format!(
            "epoll_ctl ADD eventfd: {}",
            std::io::Error::last_os_error()
        )));
    }

    clear_cloexec(epoll_fd)?;
    clear_cloexec(event_fd)?;

    // For Poll/Read ops, pre-write so the eventfd is readable immediately
    // when the child runs. For EpollCtlAdd the child creates its own fd.
    match args.op {
        InheritOp::Poll | InheritOp::Read => {
            ev.write(1)
                .map_err(|e| HandlerError(format!("epoll trial pre-write: {e}")))?;
        }
        InheritOp::EpollCtlAdd => {}
        _ => {
            return Err(HandlerError(format!(
                "unsupported epoll op {}",
                args.op.id()
            )));
        }
    }

    let child = Command::new(&args.child_binary)
        .args([
            "inherit-matrix",
            "epoll-child",
            args.op.id(),
            &args.timeout_ms.to_string(),
        ])
        .env("LITEBOX_INHERIT_FD", epoll_fd.to_string())
        .env("LITEBOX_INHERIT_FD2", event_fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;

    let output = wait_with_timeout(child, Duration::from_millis(args.timeout_ms + 1000))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut exit_code = output.status.code().unwrap_or(-1);

    if exit_code == 0 {
        let expected = match args.op {
            InheritOp::Poll => "ready=1",
            InheritOp::Read => "value=1",
            InheritOp::EpollCtlAdd => "ctl_add=ok",
            _ => "",
        };
        if stdout != expected {
            exit_code = 1;
            return Ok(ChildOutput {
                exit_code,
                stdout,
                stderr: format!("epoll stdout mismatch: expected {expected}; {stderr}"),
            });
        }
    }

    drop(ev);
    drop(epoll_owned);
    Ok(ChildOutput {
        exit_code,
        stdout,
        stderr,
    })
}

async fn handle_inotify_trial(
    args: InotifyTrialArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ChildOutput, HandlerError> {
    let dir = inotify_dir_path(&args.test_id);
    let result = run_inotify_trial(&args, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn run_inotify_trial(
    args: &InotifyTrialArgs,
    dir: &std::path::Path,
) -> Result<ChildOutput, HandlerError> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir)
        .map_err(|e| HandlerError(format!("inotify mkdir {}: {e}", dir.display())))?;

    // SAFETY: inotify_init1 returns a fresh fd on success.
    let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if raw < 0 {
        return Err(HandlerError(format!(
            "inotify_init1: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: raw is a newly returned descriptor owned here.
    let ino_owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let ino_fd = ino_owned.as_raw_fd();

    let path_c = CString::new(dir.to_string_lossy().as_ref())
        .map_err(|e| HandlerError(format!("inotify path nul: {e}")))?;
    // SAFETY: path_c is a valid C string; ino_fd is live.
    let wd = unsafe {
        libc::inotify_add_watch(ino_fd, path_c.as_ptr(), libc::IN_CREATE | libc::IN_DELETE)
    };
    if wd < 0 {
        return Err(HandlerError(format!(
            "inotify_add_watch {}: {}",
            dir.display(),
            std::io::Error::last_os_error()
        )));
    }

    // Pre-trigger the event so it sits in the inotify kernel queue at
    // inheritance time — avoids any post-exec synchronization race.
    let trigger_path = dir.join("trigger.txt");
    std::fs::write(&trigger_path, b"x")
        .map_err(|e| HandlerError(format!("inotify trigger {}: {e}", trigger_path.display())))?;

    clear_cloexec(ino_fd)?;

    let child = Command::new(&args.child_binary)
        .args([
            "inherit-matrix",
            "inotify-child",
            args.op.id(),
            &args.timeout_ms.to_string(),
        ])
        .env("LITEBOX_INHERIT_FD", ino_fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;

    let output = wait_with_timeout(child, Duration::from_millis(args.timeout_ms + 1000))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let mut exit_code = output.status.code().unwrap_or(-1);

    if exit_code == 0 {
        let expected = match args.op {
            InheritOp::InotifyReadEvent => "name=trigger.txt",
            InheritOp::Poll => "poll=in",
            _ => "",
        };
        if stdout != expected {
            exit_code = 1;
            return Ok(ChildOutput {
                exit_code,
                stdout,
                stderr: format!("inotify stdout mismatch: expected {expected}; {stderr}"),
            });
        }
    }

    drop(ino_owned);
    Ok(ChildOutput {
        exit_code,
        stdout,
        stderr,
    })
}

fn inotify_dir_path(test_id: &str) -> std::path::PathBuf {
    let sanitized: String = test_id
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '-' => c,
            _ => '_',
        })
        .collect();
    std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(format!("inotify-{sanitized}-{}", std::process::id()))
}

fn open_raw_pty_pair() -> Result<(Pty, OwnedFd), HandlerError> {
    let master = Pty::open().map_err(|e| HandlerError(format!("pty open: {e}")))?;
    let slave_path = CString::new(master.slave_path())
        .map_err(|e| HandlerError(format!("pty slave path contains nul: {e}")))?;
    // SAFETY: `slave_path` is a valid nul-terminated path returned by ptsname_r.
    let slave_fd = unsafe {
        libc::open(
            slave_path.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if slave_fd < 0 {
        return Err(HandlerError(format!(
            "open pty slave {}: {}",
            master.slave_path(),
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: `open` returned a fresh fd and ownership is transferred to OwnedFd.
    let slave = unsafe { OwnedFd::from_raw_fd(slave_fd) };
    make_raw(slave.as_raw_fd())?;
    Ok((master, slave))
}

fn make_raw(fd: RawFd) -> Result<(), HandlerError> {
    // SAFETY: zeroed termios is immediately initialized by tcgetattr on success.
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: tcgetattr writes termios state for a live PTY slave fd.
    if unsafe { libc::tcgetattr(fd, &raw mut termios) } != 0 {
        return Err(HandlerError(format!(
            "tcgetattr fd {fd}: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: cfmakeraw mutates an initialized termios value in place.
    unsafe { libc::cfmakeraw(&raw mut termios) };
    // SAFETY: tcsetattr reads the initialized termios for a live PTY slave fd.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw const termios) } != 0 {
        return Err(HandlerError(format!(
            "tcsetattr raw fd {fd}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn read_pty_payload(fd: RawFd, expected: &[u8], timeout_ms: u64) -> Result<(), HandlerError> {
    let revents = poll_fd(
        fd,
        libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        timeout_ms,
        "pty master payload",
    )?;
    if revents & libc::POLLIN == 0 {
        return Err(HandlerError(format!(
            "pty master payload poll got {}, expected POLLIN",
            describe_events(revents)
        )));
    }
    let mut buf = vec![0_u8; expected.len()];
    read_exact_fd(fd, &mut buf, "pty master read")?;
    if buf == expected {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "pty master payload mismatch: got {:?}, expected {:?}",
            String::from_utf8_lossy(&buf),
            String::from_utf8_lossy(expected)
        )))
    }
}

fn wait_pty_hup_or_eof(fd: RawFd, timeout_ms: u64) -> Result<(), HandlerError> {
    let revents = poll_fd(
        fd,
        libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        timeout_ms,
        "pty master close",
    )?;
    if revents & libc::POLLHUP != 0 {
        return Ok(());
    }
    if revents & (libc::POLLIN | libc::POLLERR) == 0 {
        return Err(HandlerError(format!(
            "pty slave close poll got {}, expected EOF/POLLHUP",
            describe_events(revents)
        )));
    }
    let mut buf = [0_u8; 1];
    // SAFETY: `buf` is valid writable memory and fd is a live PTY master fd.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n == 0 {
        return Ok(());
    }
    if n > 0 {
        return Err(HandlerError(format!(
            "pty slave close read expected EOF/EIO, got {n} bytes"
        )));
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EIO) {
        Ok(())
    } else {
        Err(HandlerError(format!("pty slave close read: {err}")))
    }
}

fn poll_fd(
    fd: RawFd,
    events: libc::c_short,
    timeout_ms: u64,
    context: &str,
) -> Result<libc::c_short, HandlerError> {
    let timeout_ms = i32::try_from(timeout_ms).unwrap_or(i32::MAX);
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    loop {
        // SAFETY: `pfd` points to one initialized pollfd; the fd remains live for the call.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
        if rc > 0 {
            return Ok(pfd.revents);
        }
        if rc == 0 {
            return Err(HandlerError(format!(
                "{context}: poll timeout after {timeout_ms}ms waiting for {}",
                describe_events(events)
            )));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(HandlerError(format!("{context}: poll: {err}")));
        }
    }
}

fn read_exact_fd(fd: RawFd, mut buf: &mut [u8], context: &str) -> Result<(), HandlerError> {
    while !buf.is_empty() {
        // SAFETY: `buf` is valid writable memory and fd is live for this read.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n > 0 {
            let n = usize::try_from(n)
                .map_err(|e| HandlerError(format!("{context}: read length conversion: {e}")))?;
            let (_, rest) = buf.split_at_mut(n);
            buf = rest;
            continue;
        }
        if n == 0 {
            return Err(HandlerError(format!("{context}: unexpected EOF")));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(HandlerError(format!("{context}: read: {err}")));
        }
    }
    Ok(())
}

fn write_all_fd(fd: RawFd, mut buf: &[u8], context: &str) -> Result<(), String> {
    while !buf.is_empty() {
        // SAFETY: `buf` is readable memory and fd is live for this write.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
        if n > 0 {
            let n = usize::try_from(n).map_err(|e| format!("{context}: length: {e}"))?;
            buf = &buf[n..];
            continue;
        }
        if n == 0 {
            return Err(format!("{context}: wrote 0 bytes"));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(format!("{context}: {err}"));
        }
    }
    Ok(())
}

fn describe_events(events: libc::c_short) -> String {
    let mut names = Vec::new();
    if events & libc::POLLIN != 0 {
        names.push("POLLIN");
    }
    if events & libc::POLLHUP != 0 {
        names.push("POLLHUP");
    }
    if events & libc::POLLERR != 0 {
        names.push("POLLERR");
    }
    if events & libc::POLLNVAL != 0 {
        names.push("POLLNVAL");
    }
    if names.is_empty() {
        format!("0x{events:x}")
    } else {
        format!("{}(0x{events:x})", names.join("|"))
    }
}

fn read_eventfd_total(
    ev: &EventFd,
    expected_total: u64,
    timeout: Duration,
) -> Result<(), HandlerError> {
    let deadline = Instant::now() + timeout;
    let mut total = 0_u64;
    while total < expected_total && Instant::now() < deadline {
        match ev.read() {
            Ok(value) => total = total.saturating_add(value),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(HandlerError(format!("eventfd read parent total: {e}"))),
        }
    }
    if total == expected_total {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "eventfd parent read timed out: total={total} expected={expected_total}"
        )))
    }
}

async fn handle_tcp_listen_trial(
    args: TcpListenTrialArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ChildOutput, HandlerError> {
    let (listener, addr) = create_tcp_listener()?;
    let fd = listener.as_raw_fd();
    clear_cloexec(fd)?;

    let mut child = Command::new(&args.child_binary);
    child
        .args([
            "inherit-matrix",
            "tcp-listen-child",
            args.op.id(),
            &fd.to_string(),
            &addr.port().to_string(),
            &args.timeout_ms.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = child
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;

    if args.op == InheritOp::Accept
        && let Err(e) = connect_and_expect_ok(addr, args.timeout_ms)
    {
        let _ = child.kill();
        let _ = wait_with_timeout(child, Duration::from_secs(1));
        return Err(e);
    }

    let output = wait_with_timeout(child, Duration::from_millis(args.timeout_ms + 1000))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    if exit_code == 0 {
        match args.op {
            InheritOp::GetSockname if stdout != addr.to_string() => {
                return Ok(ChildOutput {
                    exit_code: 1,
                    stdout,
                    stderr: format!("getsockname mismatch: expected {addr}"),
                });
            }
            InheritOp::GetSockoptReuseport if stdout != "1" => {
                return Ok(ChildOutput {
                    exit_code: 1,
                    stdout,
                    stderr: "SO_REUSEPORT mismatch: expected 1".into(),
                });
            }
            _ => {}
        }
    }

    drop(listener);
    Ok(ChildOutput {
        exit_code,
        stdout,
        stderr,
    })
}

#[allow(clippy::cast_possible_truncation)]
fn create_tcp_listener() -> Result<(TcpListener, SocketAddr), HandlerError> {
    create_tcp_listener_on_port(0)
}

#[allow(clippy::cast_possible_truncation)]
fn create_tcp_listener_on_port(port: u16) -> Result<(TcpListener, SocketAddr), HandlerError> {
    // SAFETY: socket parameters are constants; errors are checked below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(HandlerError(format!(
            "socket: {}",
            std::io::Error::last_os_error()
        )));
    }

    let one: libc::c_int = 1;
    for (opt, name) in [
        (libc::SO_REUSEADDR, "SO_REUSEADDR"),
        (libc::SO_REUSEPORT, "SO_REUSEPORT"),
    ] {
        if let Err(e) = set_socket_bool_opt(fd, opt, name, &one) {
            // SAFETY: fd is owned in this function on the error path.
            unsafe { libc::close(fd) };
            return Err(e);
        }
    }

    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: libc::htonl(libc::INADDR_LOOPBACK),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: fd is live; `addr` points to an initialized sockaddr_in.
    let rc = unsafe {
        libc::bind(
            fd,
            std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
            std::mem::size_of_val(&addr) as libc::socklen_t,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: fd is owned in this function on the error path.
        unsafe { libc::close(fd) };
        return Err(HandlerError(format!("bind(127.0.0.1:{port}): {err}")));
    }
    // SAFETY: fd is live; errors are checked below.
    let rc = unsafe { libc::listen(fd, 16) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: fd is owned in this function on the error path.
        unsafe { libc::close(fd) };
        return Err(HandlerError(format!("listen: {err}")));
    }

    // SAFETY: fd is a freshly-created listening socket and ownership
    // transfers to TcpListener exactly once.
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    let port = listener
        .local_addr()
        .map_err(|e| HandlerError(format!("local_addr: {e}")))?
        .port();
    Ok((
        listener,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
    ))
}

fn set_socket_bool_opt(
    fd: RawFd,
    opt: libc::c_int,
    name: &str,
    value: &libc::c_int,
) -> Result<(), HandlerError> {
    let opt_len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
        .expect("c_int size fits socklen_t");
    // SAFETY: fd is live; `value` points to an initialized c_int.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            std::ptr::from_ref(value).cast::<libc::c_void>(),
            opt_len,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "setsockopt({name}): {}",
            std::io::Error::last_os_error()
        )))
    }
}

fn clear_cloexec(fd: RawFd) -> Result<(), HandlerError> {
    // SAFETY: fcntl operates on a live fd; errors are checked.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    if rc != 0 {
        return Err(HandlerError(format!(
            "fcntl(F_SETFD, 0): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn wait_for_listener_connection(
    listener: &TcpListener,
    timeout_ms: u64,
) -> Result<(), HandlerError> {
    let revents = poll_fd(
        listener.as_raw_fd(),
        libc::POLLIN | libc::POLLERR,
        timeout_ms,
        "tcp_conn listener accept",
    )?;
    if revents & libc::POLLIN == 0 {
        return Err(HandlerError(format!(
            "tcp_conn listener poll got {}, expected POLLIN",
            describe_events(revents)
        )));
    }
    Ok(())
}

fn connect_loopback_with_timeout(addr: SocketAddr, timeout_ms: u64) -> std::io::Result<TcpStream> {
    let timeout = Duration::from_millis(timeout_ms);
    let deadline = Instant::now() + timeout;
    let mut last_err = None;
    while Instant::now() < deadline {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
    Err(last_err
        .unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout")))
}

fn connect_and_expect_ok(addr: SocketAddr, timeout_ms: u64) -> Result<(), HandlerError> {
    let timeout = Duration::from_millis(timeout_ms);
    let deadline = Instant::now() + timeout;
    let mut last_err = None;
    while Instant::now() < deadline {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|e| HandlerError(format!("set_read_timeout: {e}")))?;
                let mut buf = [0_u8; 2];
                stream
                    .read_exact(&mut buf)
                    .map_err(|e| HandlerError(format!("read child accept sentinel: {e}")))?;
                if &buf == b"ok" {
                    return Ok(());
                }
                return Err(HandlerError(format!("accept sentinel mismatch: {buf:?}")));
            }
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
    Err(HandlerError(format!(
        "connect to inherited listener timed out; last_err={last_err:?}"
    )))
}

fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, HandlerError> {
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    if let Some(stdout) = stdout.as_ref() {
        set_nonblock(stdout.as_raw_fd(), "child stdout")?;
    }
    if let Some(stderr) = stderr.as_ref() {
        set_nonblock(stderr.as_raw_fd(), "child stderr")?;
    }

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let _ = drain_available(&mut stdout, &mut stdout_buf, "child stdout")?;
        let _ = drain_available(&mut stderr, &mut stderr_buf, "child stderr")?;
        if let Some(status) = child
            .try_wait()
            .map_err(|e| HandlerError(format!("try_wait: {e}")))?
        {
            drain_after_exit(&mut stdout, &mut stdout_buf, &mut stderr, &mut stderr_buf)?;
            return Ok(std::process::Output {
                status,
                stdout: stdout_buf,
                stderr: stderr_buf,
            });
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    let _ = child.kill();
    drop(stdout);
    drop(stderr);
    if !stderr_buf.is_empty() {
        stderr_buf.push(b'\n');
    }
    stderr_buf.extend_from_slice(b"timeout waiting for child");
    let kill_deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| HandlerError(format!("try_wait after timeout: {e}")))?
        {
            break status;
        }
        if Instant::now() >= kill_deadline {
            stderr_buf.extend_from_slice(b"; child did not exit after kill");
            break std::os::unix::process::ExitStatusExt::from_raw(137 << 8);
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    Ok(std::process::Output {
        status,
        stdout: stdout_buf,
        stderr: stderr_buf,
    })
}

fn drain_after_exit(
    stdout: &mut Option<std::process::ChildStdout>,
    stdout_buf: &mut Vec<u8>,
    stderr: &mut Option<std::process::ChildStderr>,
    stderr_buf: &mut Vec<u8>,
) -> Result<(), HandlerError> {
    let deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < deadline {
        let stdout_open = drain_available(stdout, stdout_buf, "child stdout")?;
        let stderr_open = drain_available(stderr, stderr_buf, "child stderr")?;
        if !stdout_open && !stderr_open {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

fn drain_available<R: Read>(
    reader: &mut Option<R>,
    buf: &mut Vec<u8>,
    context: &str,
) -> Result<bool, HandlerError> {
    let Some(stream) = reader.as_mut() else {
        return Ok(false);
    };
    let mut chunk = [0_u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => {
                *reader = None;
                return Ok(false);
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(true),
            Err(e) => return Err(HandlerError(format!("read {context}: {e}"))),
        }
    }
}

fn set_nonblock(fd: RawFd, context: &str) -> Result<(), HandlerError> {
    // SAFETY: fcntl(F_GETFL) only reads descriptor flags for this live child pipe fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(HandlerError(format!(
            "fcntl(F_GETFL) {context}: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fcntl(F_SETFL) updates descriptor flags for this live child pipe fd.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(HandlerError(format!(
            "fcntl(F_SETFL O_NONBLOCK) {context}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

mod leaf_subcmd {
    use std::io::Write;
    use std::net::TcpStream;
    use std::os::fd::{FromRawFd, RawFd};

    pub(super) fn subcmd_inherit_matrix(args: &[String]) -> i32 {
        match args.get(2).map(String::as_str) {
            Some("tcp-listen-child") => tcp_listen_child(args),
            Some("pipe-child") => pipe_child(args),
            Some("socketpair-child") => socketpair_child(args),
            Some("tcp-conn-child") => tcp_conn_child(args),
            Some("eventfd-child") => eventfd_child(args),
            Some("pty-child") => pty_child(args),
            Some("signalfd-child") => signalfd_child(args),
            Some("brokerfile-child") => brokerfile_child(args),
            Some("fs-fid-child") => fs_fid_child(args),
            Some("timerfd-child") => timerfd_child(args),
            Some("pidfd-child") => pidfd_child(args),
            Some("epoll-child") => epoll_child(args),
            Some("inotify-child") => inotify_child(args),
            Some(other) => {
                eprintln!("inherit-matrix: unknown subcommand: {other}");
                2
            }
            None => {
                eprintln!("inherit-matrix: missing subcommand");
                2
            }
        }
    }

    fn pipe_child(args: &[String]) -> i32 {
        let Some(op) = args.get(3).map(String::as_str) else {
            eprintln!("inherit-matrix pipe-child: missing op");
            return 2;
        };
        let Some(fd) = std::env::var("LITEBOX_INHERIT_FD")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix pipe-child: bad LITEBOX_INHERIT_FD");
            return 2;
        };

        match op {
            "parent_writes_child_reads" => read_pipe_child(fd, b"ping"),
            "child_writes_parent_reads" => write_pipe_child(fd, b"pong"),
            "child_close_parent_reads_eof" => close_pipe_child(fd),
            other => {
                eprintln!("inherit-matrix pipe-child: unknown op {other}");
                2
            }
        }
    }

    fn read_pipe_child(fd: RawFd, expected: &[u8]) -> i32 {
        let mut buf = vec![0_u8; expected.len()];
        if read_exact_raw_fd(fd, &mut buf, "pipe child read") != 0 {
            return 1;
        }
        if buf != expected {
            eprintln!(
                "inherit-matrix pipe child read: got {:?} expected {:?}",
                String::from_utf8_lossy(&buf),
                String::from_utf8_lossy(expected)
            );
            return 1;
        }
        println!("{}", String::from_utf8_lossy(&buf));
        0
    }

    fn write_pipe_child(fd: RawFd, payload: &[u8]) -> i32 {
        if write_all_raw_fd(fd, payload, "pipe child write") != 0 {
            return 1;
        }
        println!("{}", String::from_utf8_lossy(payload));
        0
    }

    fn close_pipe_child(fd: RawFd) -> i32 {
        // SAFETY: best-effort close of the inherited pipe write end.
        if unsafe { libc::close(fd) } != 0 {
            eprintln!(
                "inherit-matrix pipe child close: {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        println!("closed");
        0
    }

    fn socketpair_child(args: &[String]) -> i32 {
        let Some(op) = args.get(3).map(String::as_str) else {
            eprintln!("inherit-matrix socketpair-child: missing op");
            return 2;
        };
        let Some(timeout_ms) = args.get(4).and_then(|s| s.parse::<i32>().ok()) else {
            eprintln!("inherit-matrix socketpair-child: bad timeout");
            return 2;
        };
        let Some(fd) = std::env::var("LITEBOX_INHERIT_FD")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix socketpair-child: bad LITEBOX_INHERIT_FD");
            return 2;
        };

        match op {
            "read_after_parent_write" => read_socketpair_child(fd, timeout_ms, b"ping"),
            "write_then_parent_reads" => write_socketpair_child(fd, b"pong"),
            "child_shutdown_then_parent_eof" => shutdown_socketpair_child(fd),
            other => {
                eprintln!("inherit-matrix socketpair-child: unknown op {other}");
                2
            }
        }
    }

    fn read_socketpair_child(fd: RawFd, timeout_ms: i32, expected: &[u8]) -> i32 {
        if poll_readable_child(fd, timeout_ms, "socketpair read") != 0 {
            return 1;
        }
        let mut buf = vec![0_u8; expected.len()];
        if read_exact_raw_fd(fd, &mut buf, "socketpair read") != 0 {
            return 1;
        }
        if buf != expected {
            eprintln!(
                "inherit-matrix socketpair read: got {:?} expected {:?}",
                String::from_utf8_lossy(&buf),
                String::from_utf8_lossy(expected)
            );
            return 1;
        }
        println!("{}", String::from_utf8_lossy(expected));
        0
    }

    fn write_socketpair_child(fd: RawFd, payload: &[u8]) -> i32 {
        if write_all_raw_fd(fd, payload, "socketpair write") != 0 {
            return 1;
        }
        println!("{}", String::from_utf8_lossy(payload));
        0
    }

    fn shutdown_socketpair_child(fd: RawFd) -> i32 {
        // SAFETY: fd is the inherited socket endpoint; errors are checked.
        if unsafe { libc::shutdown(fd, libc::SHUT_WR) } != 0 {
            eprintln!(
                "inherit-matrix socketpair shutdown(SHUT_WR): {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        println!("shutdown");
        0
    }

    fn poll_readable_child(fd: RawFd, timeout_ms: i32, context: &str) -> i32 {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is initialized and the count matches the buffer length.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        if rc <= 0 || pfd.revents & libc::POLLIN == 0 {
            eprintln!(
                "inherit-matrix {context} poll: rc={} revents={} err={}",
                rc,
                pfd.revents,
                std::io::Error::last_os_error()
            );
            return 1;
        }
        0
    }

    fn tcp_conn_child(args: &[String]) -> i32 {
        let Some(op) = args.get(3).map(String::as_str) else {
            eprintln!("inherit-matrix tcp-conn-child: missing op");
            return 2;
        };
        let Some(timeout_ms) = args.get(4).and_then(|s| s.parse::<i32>().ok()) else {
            eprintln!("inherit-matrix tcp-conn-child: bad timeout");
            return 2;
        };
        let Some(fd) = std::env::var("LITEBOX_INHERIT_FD")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix tcp-conn-child: bad LITEBOX_INHERIT_FD");
            return 2;
        };

        match op {
            "parent_writes_child_reads" => read_tcp_conn_child(fd, timeout_ms, b"ping"),
            "child_writes_parent_reads" => write_tcp_conn_child(fd, b"pong"),
            "child_shutdown_then_parent_eof" => shutdown_tcp_conn_child(fd),
            other => {
                eprintln!("inherit-matrix tcp-conn-child: unknown op {other}");
                2
            }
        }
    }

    fn read_tcp_conn_child(fd: RawFd, timeout_ms: i32, expected: &[u8]) -> i32 {
        if poll_inherited_fd(fd, timeout_ms, "tcp_conn child read") != 0 {
            return 1;
        }
        let mut buf = vec![0_u8; expected.len()];
        if read_exact_raw_fd(fd, &mut buf, "tcp_conn child read") != 0 {
            return 1;
        }
        if buf != expected {
            eprintln!(
                "inherit-matrix tcp_conn child read: got {:?} expected {:?}",
                String::from_utf8_lossy(&buf),
                String::from_utf8_lossy(expected)
            );
            return 1;
        }
        println!("{}", String::from_utf8_lossy(&buf));
        0
    }

    fn write_tcp_conn_child(fd: RawFd, payload: &[u8]) -> i32 {
        if write_all_raw_fd(fd, payload, "tcp_conn child write") != 0 {
            return 1;
        }
        println!("{}", String::from_utf8_lossy(payload));
        0
    }

    fn shutdown_tcp_conn_child(fd: RawFd) -> i32 {
        // SAFETY: fd is expected to be an inherited connected TCP socket.
        if unsafe { libc::shutdown(fd, libc::SHUT_WR) } != 0 {
            eprintln!(
                "inherit-matrix tcp_conn shutdown(SHUT_WR): {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        println!("shutdown");
        0
    }

    fn poll_inherited_fd(fd: RawFd, timeout_ms: i32, context: &str) -> i32 {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is initialized and the count matches the buffer length.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        if rc <= 0 || pfd.revents & libc::POLLIN == 0 {
            eprintln!(
                "inherit-matrix {context}: poll rc={} revents={} err={}",
                rc,
                pfd.revents,
                std::io::Error::last_os_error()
            );
            return 1;
        }
        0
    }

    fn fs_fid_child(args: &[String]) -> i32 {
        let Some(scenario) = args.get(3).map(String::as_str) else {
            eprintln!("inherit-matrix fs-fid-child: missing scenario");
            return 2;
        };
        let Some(fd) = std::env::var("LITEBOX_INHERIT_FD")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix fs-fid-child: bad LITEBOX_INHERIT_FD");
            return 2;
        };

        match scenario {
            "shared_position" => fs_fid_expect_eof(fd),
            "unlinked_after_inherit" => read_brokerfile(fd, b"fs-fid-payload"),
            "parent_close_first" => fs_fid_parent_close_first(fd),
            other => {
                eprintln!("inherit-matrix fs-fid-child: unknown scenario {other}");
                2
            }
        }
    }

    fn fs_fid_expect_eof(fd: RawFd) -> i32 {
        let mut byte = [0u8; 1];
        // SAFETY: fd is inherited from the parent and byte is writable.
        let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast::<libc::c_void>(), 1) };
        if n == 0 {
            println!("shared-position-eof");
            0
        } else {
            eprintln!(
                "inherit-matrix fs-fid shared_position: read n={n} byte={} err={}",
                byte[0],
                std::io::Error::last_os_error()
            );
            1
        }
    }

    fn fs_fid_parent_close_first(fd: RawFd) -> i32 {
        let Some(control_fd) = std::env::var("LITEBOX_FS_FID_CONTROL_FD")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix fs-fid-child: bad LITEBOX_FS_FID_CONTROL_FD");
            return 2;
        };
        let mut byte = [0u8; 1];
        if read_exact_raw_fd(control_fd, &mut byte, "fs_fid control") != 0 {
            return 1;
        }
        read_brokerfile(fd, b"fs-fid-payload")
    }

    fn brokerfile_child(args: &[String]) -> i32 {
        let Some(op) = args.get(3).map(String::as_str) else {
            eprintln!("inherit-matrix brokerfile-child: missing op");
            return 2;
        };
        let Some(fd) = std::env::var("LITEBOX_INHERIT_FD")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix brokerfile-child: bad LITEBOX_INHERIT_FD");
            return 2;
        };

        match op {
            "read_at_offset_0" => read_brokerfile(fd, b"brokerfile inherited read\n"),
            "write_then_parent_reads_back" => write_brokerfile(fd, b"hello\n"),
            "lseek_then_read" => lseek_read_brokerfile(fd, 3, b"DEF"),
            other => {
                eprintln!("inherit-matrix brokerfile-child: unknown op {other}");
                2
            }
        }
    }

    fn read_brokerfile(fd: RawFd, expected: &[u8]) -> i32 {
        let mut buf = vec![0_u8; expected.len()];
        if read_exact_raw_fd(fd, &mut buf, "brokerfile read") != 0 {
            return 1;
        }
        if buf != expected {
            eprintln!(
                "inherit-matrix brokerfile read: got {:?} expected {:?}",
                String::from_utf8_lossy(&buf),
                String::from_utf8_lossy(expected)
            );
            return 1;
        }
        println!("{}", String::from_utf8_lossy(&buf).trim_end_matches('\n'));
        0
    }

    fn write_brokerfile(fd: RawFd, payload: &[u8]) -> i32 {
        if write_all_raw_fd(fd, payload, "brokerfile write") != 0 {
            return 1;
        }
        println!(
            "{}",
            String::from_utf8_lossy(payload).trim_end_matches('\n')
        );
        0
    }

    fn lseek_read_brokerfile(fd: RawFd, offset: libc::off_t, expected: &[u8]) -> i32 {
        // SAFETY: fd is inherited from the parent and the result is checked.
        let pos = unsafe { libc::lseek(fd, offset, libc::SEEK_SET) };
        if pos != offset {
            eprintln!(
                "inherit-matrix brokerfile lseek: pos={pos} expected={offset} err={}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        read_brokerfile(fd, expected)
    }

    fn read_exact_raw_fd(fd: RawFd, mut buf: &mut [u8], context: &str) -> i32 {
        while !buf.is_empty() {
            // SAFETY: buf is valid writable memory and fd is inherited from the parent.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            if n > 0 {
                let n = n.cast_unsigned();
                let (_, rest) = buf.split_at_mut(n);
                buf = rest;
                continue;
            }
            if n == 0 {
                eprintln!("inherit-matrix {context}: unexpected EOF");
                return 1;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                eprintln!("inherit-matrix {context}: n={n} err={err}");
                return 1;
            }
        }
        0
    }

    fn write_all_raw_fd(fd: RawFd, mut buf: &[u8], context: &str) -> i32 {
        while !buf.is_empty() {
            // SAFETY: buf is valid readable memory and fd is inherited from the parent.
            let n = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
            if n > 0 {
                buf = &buf[n.cast_unsigned()..];
                continue;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                eprintln!("inherit-matrix {context}: n={n} err={err}");
                return 1;
            }
        }
        0
    }

    fn timerfd_child(args: &[String]) -> i32 {
        let Some(op) = args.get(3).map(String::as_str) else {
            eprintln!("inherit-matrix timerfd-child: missing op");
            return 2;
        };
        let Some(timeout_ms) = args.get(4).and_then(|s| s.parse::<i32>().ok()) else {
            eprintln!("inherit-matrix timerfd-child: bad timeout");
            return 2;
        };
        let Some(fd) = std::env::var("LITEBOX_INHERIT_FD")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix timerfd-child: bad LITEBOX_INHERIT_FD");
            return 2;
        };

        match op {
            "read_after_expire" => read_timerfd(fd),
            "arm_then_inherit_then_read" | "poll_readable_after_expire" => {
                poll_read_timerfd(fd, timeout_ms)
            }
            other => {
                eprintln!("inherit-matrix timerfd-child: unknown op {other}");
                2
            }
        }
    }

    fn poll_read_timerfd(fd: RawFd, timeout_ms: i32) -> i32 {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is initialized and the count matches the buffer length.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        if rc <= 0 || pfd.revents & libc::POLLIN == 0 {
            eprintln!(
                "inherit-matrix timerfd poll: rc={} revents={} err={}",
                rc,
                pfd.revents,
                std::io::Error::last_os_error()
            );
            return 1;
        }
        read_timerfd(fd)
    }

    fn read_timerfd(fd: RawFd) -> i32 {
        let mut value = 0_u64;
        loop {
            // SAFETY: value is valid writable storage for one timerfd expiration count.
            let n =
                unsafe { libc::read(fd, std::ptr::from_mut(&mut value).cast::<libc::c_void>(), 8) };
            if n == 8 {
                println!("{value}");
                return 0;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                eprintln!("inherit-matrix timerfd read: n={n} err={err}");
                return 1;
            }
        }
    }

    fn pidfd_child(args: &[String]) -> i32 {
        let Some(op) = args.get(3).map(String::as_str) else {
            eprintln!("inherit-matrix pidfd-child: missing op");
            return 2;
        };
        let Some(timeout_ms) = args.get(4).and_then(|s| s.parse::<i32>().ok()) else {
            eprintln!("inherit-matrix pidfd-child: bad timeout");
            return 2;
        };
        let Some(fd) = std::env::var("LITEBOX_INHERIT_FD")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix pidfd-child: bad LITEBOX_INHERIT_FD");
            return 2;
        };

        match op {
            // Both ops use the same child-side primitive: poll(POLLIN)
            // on the inherited pidfd. They differ in the parent's
            // sequencing (alive-then-exits vs. already-exited).
            "poll" | "recv_after_fork" => poll_pidfd_child(fd, timeout_ms),
            other => {
                eprintln!("inherit-matrix pidfd-child: unknown op {other}");
                2
            }
        }
    }

    fn poll_pidfd_child(fd: RawFd, timeout_ms: i32) -> i32 {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is initialized and the count matches the buffer length.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        if rc <= 0 || pfd.revents & libc::POLLIN == 0 {
            eprintln!(
                "inherit-matrix pidfd poll: rc={} revents={} err={}",
                rc,
                pfd.revents,
                std::io::Error::last_os_error()
            );
            return 1;
        }
        println!("ready");
        0
    }

    fn signalfd_child(args: &[String]) -> i32 {
        let Some(op) = args.get(3).map(String::as_str) else {
            eprintln!("inherit-matrix signalfd-child: missing op");
            return 2;
        };
        let Some(timeout_ms) = args.get(4).and_then(|s| s.parse::<i32>().ok()) else {
            eprintln!("inherit-matrix signalfd-child: bad timeout");
            return 2;
        };
        let Some(fd) = std::env::var("LITEBOX_INHERIT_FD")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix signalfd-child: bad LITEBOX_INHERIT_FD");
            return 2;
        };

        match op {
            "recv_pending" => poll_read_signalfd(fd, timeout_ms, libc::SIGUSR1),
            "recv_after_fork" => recv_signalfd_after_fork(fd, timeout_ms),
            "recv_close_eof" => recv_signalfd_close_eof(fd),
            other => {
                eprintln!("inherit-matrix signalfd-child: unknown op {other}");
                2
            }
        }
    }

    fn recv_signalfd_after_fork(fd: RawFd, timeout_ms: i32) -> i32 {
        if check_signalfd_eagain(fd, "recv_after_fork initial") != 0 {
            return 1;
        }
        if write_env_fd_byte("LITEBOX_READY_FD", b'r') != 0 {
            return 1;
        }
        poll_read_signalfd(fd, timeout_ms, libc::SIGUSR1)
    }

    fn recv_signalfd_close_eof(fd: RawFd) -> i32 {
        if write_env_fd_byte("LITEBOX_READY_FD", b'r') != 0 {
            return 1;
        }
        if read_env_fd_byte("LITEBOX_GO_FD") != 0 {
            return 1;
        }
        if check_signalfd_eagain(fd, "recv_close_eof") != 0 {
            return 1;
        }
        println!("eagain");
        0
    }

    fn poll_read_signalfd(fd: RawFd, timeout_ms: i32, expected_signo: i32) -> i32 {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is initialized and the count matches the buffer length.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        if rc <= 0 || pfd.revents & libc::POLLIN == 0 {
            eprintln!(
                "inherit-matrix signalfd poll: rc={} revents={} err={}",
                rc,
                pfd.revents,
                std::io::Error::last_os_error()
            );
            return 1;
        }
        match read_signalfd_signo(fd) {
            Ok(Some(signo)) if signo == expected_signo.cast_unsigned() => {
                println!("{signo}");
                0
            }
            Ok(Some(signo)) => {
                eprintln!("inherit-matrix signalfd read: signo={signo} expected={expected_signo}");
                1
            }
            Ok(None) => {
                eprintln!("inherit-matrix signalfd read: unexpected EAGAIN after poll");
                1
            }
            Err(e) => {
                eprintln!("inherit-matrix signalfd read: {e}");
                1
            }
        }
    }

    fn check_signalfd_eagain(fd: RawFd, context: &str) -> i32 {
        match read_signalfd_signo(fd) {
            Ok(None) => 0,
            Ok(Some(signo)) => {
                eprintln!("inherit-matrix signalfd {context}: unexpected signo {signo}");
                1
            }
            Err(e) => {
                eprintln!("inherit-matrix signalfd {context}: {e}");
                1
            }
        }
    }

    fn read_signalfd_signo(fd: RawFd) -> Result<Option<u32>, String> {
        let mut buf = [0_u8; 128];
        loop {
            // SAFETY: buf is valid writable storage for one signalfd_siginfo.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            if n == 128 {
                return Ok(Some(u32::from_ne_bytes(buf[0..4].try_into().unwrap())));
            }
            if n >= 0 {
                return Err(format!("short read: {n}"));
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => {}
                Some(libc::EAGAIN) => return Ok(None),
                _ => return Err(err.to_string()),
            }
        }
    }

    fn write_env_fd_byte(var: &str, byte: u8) -> i32 {
        let Some(fd) = std::env::var(var)
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix signalfd-child: bad {var}");
            return 2;
        };
        loop {
            // SAFETY: byte points to valid readable storage; fd is inherited from the parent.
            let n = unsafe { libc::write(fd, std::ptr::from_ref(&byte).cast::<libc::c_void>(), 1) };
            if n == 1 {
                return 0;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                eprintln!("inherit-matrix signalfd write {var}: n={n} err={err}");
                return 1;
            }
        }
    }

    fn read_env_fd_byte(var: &str) -> i32 {
        let Some(fd) = std::env::var(var)
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix signalfd-child: bad {var}");
            return 2;
        };
        let mut byte = [0_u8; 1];
        loop {
            // SAFETY: byte points to valid writable storage; fd is inherited from the parent.
            let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast::<libc::c_void>(), 1) };
            if n == 1 {
                return 0;
            }
            if n == 0 {
                eprintln!("inherit-matrix signalfd read {var}: unexpected EOF");
                return 1;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                eprintln!("inherit-matrix signalfd read {var}: n={n} err={err}");
                return 1;
            }
        }
    }

    fn pty_child(args: &[String]) -> i32 {
        let Some(op) = args.get(3).map(String::as_str) else {
            eprintln!("inherit-matrix pty-child: missing op");
            return 2;
        };
        let Some(timeout_ms) = args.get(4).and_then(|s| s.parse::<i32>().ok()) else {
            eprintln!("inherit-matrix pty-child: bad timeout");
            return 2;
        };
        let Some(fd) = std::env::var("LITEBOX_INHERIT_FD")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix pty-child: bad LITEBOX_INHERIT_FD");
            return 2;
        };

        match op {
            "slave_write" => write_pty_slave(fd, b"hi\n"),
            "slave_read" => read_pty_slave(fd, timeout_ms, b"hi\n"),
            "slave_close" => close_pty_slave(fd),
            other => {
                eprintln!("inherit-matrix pty-child: unknown op {other}");
                2
            }
        }
    }

    fn write_pty_slave(fd: RawFd, mut buf: &[u8]) -> i32 {
        while !buf.is_empty() {
            // SAFETY: `buf` is readable memory and fd is the inherited PTY slave.
            let n = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
            if n > 0 {
                buf = &buf[n.cast_unsigned()..];
                continue;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                eprintln!("inherit-matrix pty write: n={n} err={err}");
                return 1;
            }
        }
        println!("wrote");
        0
    }

    fn read_pty_slave(fd: RawFd, timeout_ms: i32, expected: &[u8]) -> i32 {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is initialized and the count matches the buffer length.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        if rc <= 0 || pfd.revents & libc::POLLIN == 0 {
            eprintln!(
                "inherit-matrix pty read poll: rc={} revents={} err={}",
                rc,
                pfd.revents,
                std::io::Error::last_os_error()
            );
            return 1;
        }

        let mut buf = vec![0_u8; expected.len()];
        let mut filled = 0;
        while filled < buf.len() {
            // SAFETY: the remaining `buf` slice is valid writable memory.
            let n = unsafe {
                libc::read(
                    fd,
                    buf[filled..].as_mut_ptr().cast::<libc::c_void>(),
                    buf.len() - filled,
                )
            };
            if n > 0 {
                filled += n.cast_unsigned();
                continue;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                eprintln!("inherit-matrix pty read: n={n} err={err}");
                return 1;
            }
        }
        if buf != expected {
            eprintln!(
                "inherit-matrix pty read: got {:?} expected {:?}",
                String::from_utf8_lossy(&buf),
                String::from_utf8_lossy(expected)
            );
            return 1;
        }
        println!("{}", String::from_utf8_lossy(expected).trim_end());
        0
    }

    fn close_pty_slave(fd: RawFd) -> i32 {
        // SAFETY: best-effort close of the inherited PTY slave fd.
        if unsafe { libc::close(fd) } != 0 {
            eprintln!(
                "inherit-matrix pty close: {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        println!("closed");
        0
    }

    fn eventfd_child(args: &[String]) -> i32 {
        let Some(op) = args.get(3).map(String::as_str) else {
            eprintln!("inherit-matrix eventfd-child: missing op");
            return 2;
        };
        let Some(value) = args.get(4).and_then(|s| s.parse::<u64>().ok()) else {
            eprintln!("inherit-matrix eventfd-child: bad value");
            return 2;
        };
        let Some(timeout_ms) = args.get(5).and_then(|s| s.parse::<i32>().ok()) else {
            eprintln!("inherit-matrix eventfd-child: bad timeout");
            return 2;
        };
        let Some(fd) = std::env::var("LITEBOX_INHERIT_FD")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix eventfd-child: bad LITEBOX_INHERIT_FD");
            return 2;
        };

        match op {
            "read" => read_eventfd(fd, 1),
            "write" => write_eventfd(fd, value),
            "poll" => poll_read_eventfd(fd, timeout_ms, 1),
            other => {
                eprintln!("inherit-matrix eventfd-child: unknown op {other}");
                2
            }
        }
    }

    fn read_eventfd(fd: RawFd, expected: u64) -> i32 {
        let mut value = 0_u64;
        loop {
            // SAFETY: value is valid writable storage for one eventfd word.
            let n =
                unsafe { libc::read(fd, std::ptr::from_mut(&mut value).cast::<libc::c_void>(), 8) };
            if n == 8 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                eprintln!("inherit-matrix eventfd read: n={n} err={err}");
                return 1;
            }
        }
        if value != expected {
            eprintln!("inherit-matrix eventfd read: value={value} expected={expected}");
            return 1;
        }
        println!("{value}");
        0
    }

    fn write_eventfd(fd: RawFd, value: u64) -> i32 {
        loop {
            // SAFETY: value is valid readable storage for one eventfd word.
            let n =
                unsafe { libc::write(fd, std::ptr::from_ref(&value).cast::<libc::c_void>(), 8) };
            if n == 8 {
                println!("{value}");
                return 0;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                eprintln!("inherit-matrix eventfd write: n={n} err={err}");
                return 1;
            }
        }
    }

    fn poll_read_eventfd(fd: RawFd, timeout_ms: i32, expected: u64) -> i32 {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is initialized and the count matches the buffer length.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        if rc <= 0 || pfd.revents & libc::POLLIN == 0 {
            eprintln!(
                "inherit-matrix eventfd poll: rc={} revents={} err={}",
                rc,
                pfd.revents,
                std::io::Error::last_os_error()
            );
            return 1;
        }
        read_eventfd(fd, expected)
    }

    fn epoll_child(args: &[String]) -> i32 {
        let Some(op) = args.get(3).map(String::as_str) else {
            eprintln!("inherit-matrix epoll-child: missing op");
            return 2;
        };
        let Some(timeout_ms) = args.get(4).and_then(|s| s.parse::<i32>().ok()) else {
            eprintln!("inherit-matrix epoll-child: bad timeout");
            return 2;
        };
        let Some(epoll_fd) = std::env::var("LITEBOX_INHERIT_FD")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix epoll-child: bad LITEBOX_INHERIT_FD");
            return 2;
        };
        let Some(event_fd) = std::env::var("LITEBOX_INHERIT_FD2")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix epoll-child: bad LITEBOX_INHERIT_FD2");
            return 2;
        };

        match op {
            "poll" => epoll_poll_child(epoll_fd, timeout_ms),
            "read" => epoll_read_child(event_fd),
            "epoll_ctl_add" => epoll_ctl_add_child(epoll_fd, timeout_ms),
            other => {
                eprintln!("inherit-matrix epoll-child: unknown op {other}");
                2
            }
        }
    }

    fn epoll_poll_child(epoll_fd: RawFd, timeout_ms: i32) -> i32 {
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
        // SAFETY: events is valid writable storage for 4 entries.
        let n = unsafe { libc::epoll_wait(epoll_fd, events.as_mut_ptr(), 4, timeout_ms) };
        if n < 0 {
            eprintln!(
                "inherit-matrix epoll_wait: {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        println!("ready={n}");
        i32::from(n != 1)
    }

    fn epoll_read_child(event_fd: RawFd) -> i32 {
        let mut value = 0_u64;
        // SAFETY: value is valid writable storage for one eventfd word.
        let n = unsafe {
            libc::read(
                event_fd,
                std::ptr::from_mut(&mut value).cast::<libc::c_void>(),
                8,
            )
        };
        if n != 8 {
            eprintln!(
                "inherit-matrix epoll read eventfd: n={n} err={}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        println!("value={value}");
        i32::from(value != 1)
    }

    fn epoll_ctl_add_child(epoll_fd: RawFd, timeout_ms: i32) -> i32 {
        // SAFETY: eventfd creates a new fd that we immediately own.
        let new_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if new_fd < 0 {
            eprintln!(
                "inherit-matrix epoll_ctl_add child eventfd: {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: new_fd.cast_unsigned().into(),
        };
        // SAFETY: epoll_fd and new_fd are live; ev is initialized.
        let rc = unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, new_fd, &raw mut ev) };
        if rc != 0 {
            eprintln!(
                "inherit-matrix epoll_ctl ADD inherited epoll_fd: {}",
                std::io::Error::last_os_error()
            );
            // SAFETY: best-effort close of fd we just created.
            unsafe { libc::close(new_fd) };
            return 1;
        }
        // Trigger readiness on the newly added fd, then verify epoll_wait sees it.
        let one: u64 = 1;
        // SAFETY: `one` is valid readable storage for 8 bytes.
        let wn = unsafe { libc::write(new_fd, std::ptr::from_ref(&one).cast::<libc::c_void>(), 8) };
        if wn != 8 {
            eprintln!(
                "inherit-matrix epoll_ctl_add child write: wn={wn} err={}",
                std::io::Error::last_os_error()
            );
            // SAFETY: best-effort close.
            unsafe { libc::close(new_fd) };
            return 1;
        }
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
        // SAFETY: events is valid writable storage for 4 entries.
        let n = unsafe { libc::epoll_wait(epoll_fd, events.as_mut_ptr(), 4, timeout_ms) };
        // SAFETY: best-effort close before returning.
        unsafe { libc::close(new_fd) };
        if n < 1 {
            eprintln!(
                "inherit-matrix epoll_ctl_add wait: n={n} err={}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        println!("ctl_add=ok");
        0
    }

    fn inotify_child(args: &[String]) -> i32 {
        let Some(op) = args.get(3).map(String::as_str) else {
            eprintln!("inherit-matrix inotify-child: missing op");
            return 2;
        };
        let Some(timeout_ms) = args.get(4).and_then(|s| s.parse::<i32>().ok()) else {
            eprintln!("inherit-matrix inotify-child: bad timeout");
            return 2;
        };
        let Some(fd) = std::env::var("LITEBOX_INHERIT_FD")
            .ok()
            .and_then(|s| s.parse::<RawFd>().ok())
        else {
            eprintln!("inherit-matrix inotify-child: bad LITEBOX_INHERIT_FD");
            return 2;
        };

        match op {
            "inotify_read_event" => inotify_read_event_child(fd, timeout_ms),
            "poll" => inotify_poll_child(fd, timeout_ms),
            other => {
                eprintln!("inherit-matrix inotify-child: unknown op {other}");
                2
            }
        }
    }

    fn inotify_poll_child(fd: RawFd, timeout_ms: i32) -> i32 {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is initialized and the count matches the buffer length.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        if rc <= 0 || pfd.revents & libc::POLLIN == 0 {
            eprintln!(
                "inherit-matrix inotify poll: rc={} revents={} err={}",
                rc,
                pfd.revents,
                std::io::Error::last_os_error()
            );
            return 1;
        }
        println!("poll=in");
        0
    }

    fn inotify_read_event_child(fd: RawFd, timeout_ms: i32) -> i32 {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is initialized.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        if rc <= 0 || pfd.revents & libc::POLLIN == 0 {
            eprintln!(
                "inherit-matrix inotify read poll: rc={} revents={} err={}",
                rc,
                pfd.revents,
                std::io::Error::last_os_error()
            );
            return 1;
        }
        let mut buf = [0_u8; 4096];
        // SAFETY: buf is valid writable storage; fd inherited from parent.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n <= 0 {
            eprintln!(
                "inherit-matrix inotify read: n={n} err={}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        let n = n.cast_unsigned();
        let event_size = std::mem::size_of::<libc::inotify_event>();
        if n < event_size {
            eprintln!("inherit-matrix inotify read: short n={n}");
            return 1;
        }
        // SAFETY: bounds-checked; read_unaligned tolerates any alignment.
        let raw_evt =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<libc::inotify_event>()) };
        let name_len = raw_evt.len as usize;
        if event_size + name_len > n {
            eprintln!("inherit-matrix inotify read: name overrun");
            return 1;
        }
        let name = if name_len == 0 {
            String::new()
        } else {
            let raw_name = &buf[event_size..event_size + name_len];
            let nul = raw_name
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(raw_name.len());
            String::from_utf8_lossy(&raw_name[..nul]).into_owned()
        };
        if raw_evt.mask & libc::IN_CREATE == 0 {
            eprintln!(
                "inherit-matrix inotify read: mask=0x{:x}, expected IN_CREATE",
                raw_evt.mask
            );
            return 1;
        }
        println!("name={name}");
        0
    }

    fn tcp_listen_child(args: &[String]) -> i32 {
        let Some(op) = args.get(3).map(String::as_str) else {
            eprintln!("inherit-matrix tcp-listen-child: missing op");
            return 2;
        };
        let Some(fd) = args.get(4).and_then(|s| s.parse::<RawFd>().ok()) else {
            eprintln!("inherit-matrix tcp-listen-child: bad fd");
            return 2;
        };
        let Some(expected_port) = args.get(5).and_then(|s| s.parse::<u16>().ok()) else {
            eprintln!("inherit-matrix tcp-listen-child: bad expected port");
            return 2;
        };
        let Some(timeout_ms) = args.get(6).and_then(|s| s.parse::<i32>().ok()) else {
            eprintln!("inherit-matrix tcp-listen-child: bad timeout");
            return 2;
        };

        match op {
            "accept" => accept_inherited(fd, timeout_ms),
            "getsockname" => getsockname_inherited(fd, expected_port),
            "getsockopt_reuseport" => getsockopt_reuseport_inherited(fd),
            other => {
                eprintln!("inherit-matrix tcp-listen-child: unknown op {other}");
                2
            }
        }
    }

    fn accept_inherited(fd: RawFd, timeout_ms: i32) -> i32 {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is initialized and the count matches the buffer length.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        if rc <= 0 || pfd.revents & libc::POLLIN == 0 {
            eprintln!(
                "inherit-matrix accept: poll rc={} revents={} err={}",
                rc,
                pfd.revents,
                std::io::Error::last_os_error()
            );
            return 1;
        }
        // SAFETY: fd is expected to be an inherited listening socket; errors
        // are checked before the accepted fd is used.
        let stream_fd = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if stream_fd < 0 {
            eprintln!(
                "inherit-matrix accept: accept failed: {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        // SAFETY: accept returned a new connected stream fd and ownership
        // transfers to TcpStream exactly once.
        let mut stream = unsafe { TcpStream::from_raw_fd(stream_fd) };
        if let Err(e) = stream.write_all(b"ok") {
            eprintln!("inherit-matrix accept: write sentinel: {e}");
            return 1;
        }
        0
    }

    #[allow(clippy::cast_possible_truncation)]
    fn getsockname_inherited(fd: RawFd, expected_port: u16) -> i32 {
        let mut addr = libc::sockaddr_in {
            sin_family: 0,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
        // SAFETY: addr and len point to initialized writable storage.
        let rc = unsafe {
            libc::getsockname(
                fd,
                std::ptr::from_mut(&mut addr).cast::<libc::sockaddr>(),
                std::ptr::from_mut(&mut len),
            )
        };
        if rc != 0 {
            eprintln!(
                "inherit-matrix getsockname: {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        if i32::from(addr.sin_family) != libc::AF_INET {
            eprintln!("inherit-matrix getsockname: family={}", addr.sin_family);
            return 1;
        }
        let port = u16::from_be(addr.sin_port);
        if port != expected_port {
            eprintln!("inherit-matrix getsockname: port={port} expected={expected_port}");
            return 1;
        }
        println!("127.0.0.1:{port}");
        0
    }

    #[allow(clippy::cast_possible_truncation)]
    fn getsockopt_reuseport_inherited(fd: RawFd) -> i32 {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: value and len point to initialized writable storage.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                std::ptr::from_mut(&mut value).cast::<libc::c_void>(),
                std::ptr::from_mut(&mut len),
            )
        };
        if rc != 0 {
            eprintln!(
                "inherit-matrix getsockopt(SO_REUSEPORT): {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        println!("{value}");
        i32::from(value != 1)
    }
}

#[cfg(test)]
mod coverage_gate {
    //! Test-discovery-time gate: assert that every `InheritSubsystem`
    //! variant is reachable from `InheritSubsystem::ALL` (and therefore
    //! that the cartesian-product trial registration above covers it).
    //!
    //! This is Option 3 of the wave-cleanup-2 migration-gate work
    //! stream: the gap that produced the epoll/inotify worker-exec
    //! regression (commit 5387acc3, 68/99 hard FAILs) was missed at
    //! the shim side AND at the test-discovery side — adding a new
    //! subsystem without registering its inherit-matrix family is a
    //! silent gap that this gate makes loud. Pairs with the
    //! shim-side compile-time gate in
    //! `litebox_shim_linux/src/syscalls/migration_policy.rs`.

    use super::InheritSubsystem;

    #[test]
    fn discriminant_indices_are_unique_and_consecutive() {
        // discriminant_index is exhaustively matched on InheritSubsystem
        // (rustc E0004 if a variant is missed). Verify ALL covers every
        // index 0..EXPECTED_VARIANT_COUNT exactly once.
        assert_eq!(
            InheritSubsystem::ALL.len(),
            InheritSubsystem::EXPECTED_VARIANT_COUNT,
            "InheritSubsystem::ALL length must equal EXPECTED_VARIANT_COUNT; \
             update ALL (and EXPECTED_VARIANT_COUNT) when adding a new variant"
        );
        let mut indices: Vec<usize> = InheritSubsystem::ALL
            .iter()
            .copied()
            .map(InheritSubsystem::discriminant_index)
            .collect();
        indices.sort_unstable();
        let expected: Vec<usize> = (0..InheritSubsystem::EXPECTED_VARIANT_COUNT).collect();
        assert_eq!(
            indices, expected,
            "InheritSubsystem::ALL must contain each variant exactly once; \
             gaps or duplicates indicate a missing or duplicated entry. \
             A common cause is adding a new InheritSubsystem variant and \
             discriminant_index arm but forgetting to append it to ALL."
        );
    }

    #[test]
    fn ids_are_unique() {
        // Inherit-matrix test IDs reach the dashboard as
        // `INHERIT.<id>.*.{dng,snm}` families; collisions would silently
        // alias families. The exhaustive match in `id()` already prevents
        // a new variant from being unnamed; this check prevents typos
        // that produce duplicate ids.
        let mut ids: Vec<&'static str> = InheritSubsystem::ALL
            .iter()
            .copied()
            .map(InheritSubsystem::id)
            .collect();
        ids.sort_unstable();
        let unique_count = {
            let mut copy = ids.clone();
            copy.dedup();
            copy.len()
        };
        assert_eq!(
            ids.len(),
            unique_count,
            "InheritSubsystem::id() must be unique across variants; \
             duplicates: {ids:?}",
        );
    }
}
