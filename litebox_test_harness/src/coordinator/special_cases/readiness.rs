// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Peer-readiness invariant tests.
//!
//! This scaffold exercises the invariant that an operation on one endpoint
//! which changes peer readiness must wake a peer waiting in `poll`, and that
//! the subsequent `read` observes the corresponding data or EOF.

use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{AgentName, HandlerCtx, HandlerError, HandlerToken, Registry};
use crate::coordinator::TestOutcome;
use crate::register_handler;

const READINESS: HandlerToken<ReadinessTrial, ReadinessOut> = HandlerToken::new("readiness.run");
const POLL_TIMEOUT_MS: i32 = 2_000;
const READ_TIMEOUT: Duration = Duration::from_secs(2);
const WRITE_THEN_CLOSE_PAYLOAD: &[u8] = b"READY_TCP_PAYLOAD";

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
struct ReadinessTrial {
    bt: crate::BinaryType,
    subsystem: ReadinessSubsystem,
    op: PeerOp,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
enum ReadinessSubsystem {
    TcpConn,
    Pipe,
    SocketPair,
    Eventfd,
    Signalfd,
    Pty,
    BrokerPipe,
}

impl ReadinessSubsystem {
    const ALL: &'static [Self] = &[
        Self::TcpConn,
        Self::Pipe,
        Self::SocketPair,
        Self::Eventfd,
        Self::Signalfd,
        Self::Pty,
        Self::BrokerPipe,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::TcpConn => "tcp_conn",
            Self::Pipe => "pipe",
            Self::SocketPair => "socketpair",
            Self::Eventfd => "eventfd",
            Self::Signalfd => "signalfd",
            Self::Pty => "pty",
            Self::BrokerPipe => "broker_pipe",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
enum PeerOp {
    ShutdownWr,
    Close,
    WriteThenClose,
}

impl PeerOp {
    fn label(self) -> &'static str {
        match self {
            Self::ShutdownWr => "peer_shutdown_wr",
            Self::Close => "peer_close",
            Self::WriteThenClose => "peer_write_then_close",
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ReadinessOut {
    passed: bool,
    detail: String,
}

async fn handle_readiness(
    trial: ReadinessTrial,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ReadinessOut, HandlerError> {
    let result = match trial.subsystem {
        ReadinessSubsystem::TcpConn => run_tcp_conn_trial(trial.op),
        ReadinessSubsystem::Pipe => skip_pending(ReadinessSubsystem::Pipe),
        ReadinessSubsystem::SocketPair => skip_pending(ReadinessSubsystem::SocketPair),
        ReadinessSubsystem::Eventfd => skip_pending(ReadinessSubsystem::Eventfd),
        ReadinessSubsystem::Signalfd => skip_pending(ReadinessSubsystem::Signalfd),
        ReadinessSubsystem::Pty => skip_pending(ReadinessSubsystem::Pty),
        ReadinessSubsystem::BrokerPipe => skip_pending(ReadinessSubsystem::BrokerPipe),
    };
    Ok(match result {
        TrialResult::Passed(detail) => ReadinessOut {
            passed: true,
            detail,
        },
        TrialResult::Failed(detail) | TrialResult::Skipped(detail) => ReadinessOut {
            passed: false,
            detail,
        },
    })
}

enum TrialResult {
    Passed(String),
    Failed(String),
    Skipped(String),
}

fn skip_pending(subsystem: ReadinessSubsystem) -> TrialResult {
    TrialResult::Skipped(format!(
        "READY.{} scaffold pending; no pilot trials registered",
        subsystem.label()
    ))
}

fn valid_ops(subsystem: ReadinessSubsystem) -> &'static [PeerOp] {
    match subsystem {
        ReadinessSubsystem::TcpConn => &[PeerOp::ShutdownWr, PeerOp::Close, PeerOp::WriteThenClose],
        ReadinessSubsystem::Pipe
        | ReadinessSubsystem::SocketPair
        | ReadinessSubsystem::Eventfd
        | ReadinessSubsystem::Signalfd
        | ReadinessSubsystem::Pty
        | ReadinessSubsystem::BrokerPipe => &[],
    }
}

fn run_tcp_conn_trial(op: PeerOp) -> TrialResult {
    match run_tcp_conn_trial_inner(op) {
        Ok(detail) => TrialResult::Passed(detail),
        Err(detail) => TrialResult::Failed(detail),
    }
}

fn run_tcp_conn_trial_inner(op: PeerOp) -> Result<String, String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| format!("bind: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    let peer = TcpStream::connect(addr).map_err(|e| format!("connect peer: {e}"))?;
    peer.set_nonblocking(true)
        .map_err(|e| format!("set peer nonblocking: {e}"))?;
    let (ours, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
    ours.set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|e| format!("set read timeout: {e}"))?;
    ours.set_nonblocking(true)
        .map_err(|e| format!("set nonblocking: {e}"))?;
    drop(listener);

    match op {
        PeerOp::ShutdownWr => {
            peer.shutdown(Shutdown::Write)
                .map_err(|e| format!("peer shutdown(SHUT_WR): {e}"))?;
            let revents = poll_fd(ours.as_raw_fd(), readiness_mask(), POLL_TIMEOUT_MS)?;
            require_any(
                revents,
                libc::POLLIN | libc::POLLRDHUP,
                "peer_shutdown_wr initial poll",
            )?;
            let n = read_once(ours.as_raw_fd(), &mut [0_u8; 1])?;
            if n != 0 {
                return Err(format!("peer_shutdown_wr read expected EOF, got {n} bytes"));
            }
            Ok(format!("poll={} read=EOF", describe_events(revents)))
        }
        PeerOp::Close => {
            drop(peer);
            let revents = poll_fd(ours.as_raw_fd(), readiness_mask(), POLL_TIMEOUT_MS)?;
            require_any(
                revents,
                libc::POLLHUP | libc::POLLRDHUP,
                "peer_close initial poll",
            )?;
            let n = read_once(ours.as_raw_fd(), &mut [0_u8; 1])?;
            if n != 0 {
                return Err(format!("peer_close read expected EOF, got {n} bytes"));
            }
            Ok(format!("poll={} read=EOF", describe_events(revents)))
        }
        PeerOp::WriteThenClose => {
            let n = send_once(peer.as_raw_fd(), WRITE_THEN_CLOSE_PAYLOAD)?;
            if n != WRITE_THEN_CLOSE_PAYLOAD.len() {
                return Err(format!(
                    "peer write length mismatch: got {n}, expected {}",
                    WRITE_THEN_CLOSE_PAYLOAD.len()
                ));
            }
            drop(peer);

            let revents1 = poll_fd(ours.as_raw_fd(), readiness_mask(), POLL_TIMEOUT_MS)?;
            require_any(revents1, libc::POLLIN, "peer_write_then_close data poll")?;
            let mut buf = [0_u8; WRITE_THEN_CLOSE_PAYLOAD.len()];
            let n = read_once(ours.as_raw_fd(), &mut buf)?;
            if n != WRITE_THEN_CLOSE_PAYLOAD.len() {
                return Err(format!(
                    "payload read length mismatch: got {n}, expected {}",
                    WRITE_THEN_CLOSE_PAYLOAD.len()
                ));
            }
            if buf != WRITE_THEN_CLOSE_PAYLOAD {
                return Err(format!(
                    "payload mismatch: got {:?}, expected {:?}",
                    String::from_utf8_lossy(&buf),
                    String::from_utf8_lossy(WRITE_THEN_CLOSE_PAYLOAD)
                ));
            }

            let revents2 = poll_fd(ours.as_raw_fd(), readiness_mask(), POLL_TIMEOUT_MS)?;
            require_any(
                revents2,
                libc::POLLIN | libc::POLLHUP | libc::POLLRDHUP,
                "peer_write_then_close eof poll",
            )?;
            let n = read_once(ours.as_raw_fd(), &mut [0_u8; 1])?;
            if n != 0 {
                return Err(format!(
                    "peer_write_then_close second read expected EOF, got {n} bytes"
                ));
            }
            Ok(format!(
                "data_poll={} eof_poll={} read={} bytes then EOF",
                describe_events(revents1),
                describe_events(revents2),
                n.max(WRITE_THEN_CLOSE_PAYLOAD.len())
            ))
        }
    }
}

fn readiness_mask() -> libc::c_short {
    libc::POLLIN | libc::POLLHUP | libc::POLLRDHUP
}

fn poll_fd(fd: i32, events: libc::c_short, timeout_ms: i32) -> Result<libc::c_short, String> {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    loop {
        // SAFETY: `pfd` points to one initialized pollfd, the count is 1,
        // and `fd` is owned by a live TcpStream for the duration of the call.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
        if rc > 0 {
            return Ok(pfd.revents);
        }
        if rc == 0 {
            return Err(format!(
                "poll timeout after {timeout_ms}ms waiting for {}",
                describe_events(events)
            ));
        }
        let errno = errno();
        if errno == libc::EINTR {
            continue;
        }
        return Err(format!("poll failed errno={errno}"));
    }
}

fn send_once(fd: i32, buf: &[u8]) -> Result<usize, String> {
    // SAFETY: `buf` is a valid readable byte slice and `fd` is owned by a
    // live TcpStream. `MSG_DONTWAIT` keeps the peer operation bounded.
    let n = unsafe {
        libc::send(
            fd,
            buf.as_ptr().cast::<libc::c_void>(),
            buf.len(),
            libc::MSG_DONTWAIT,
        )
    };
    syscall_len(n, "send")
}

fn read_once(fd: i32, buf: &mut [u8]) -> Result<usize, String> {
    // SAFETY: `buf` is a valid writable byte slice and `fd` is owned by a
    // live TcpStream. `MSG_DONTWAIT` makes the syscall bounded even if the
    // readiness path falsely reports readability.
    let n = unsafe {
        libc::recv(
            fd,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
            libc::MSG_DONTWAIT,
        )
    };
    syscall_len(n, "read")
}

fn syscall_len(n: isize, op: &str) -> Result<usize, String> {
    if n < 0 {
        let errno = errno();
        if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
            Err(format!(
                "{op} would block after poll timeout={}ms",
                POLL_TIMEOUT_MS
            ))
        } else {
            Err(format!("{op} failed errno={errno}"))
        }
    } else {
        usize::try_from(n).map_err(|e| format!("{op} result conversion failed: {e}"))
    }
}

fn require_any(
    revents: libc::c_short,
    expected: libc::c_short,
    context: &str,
) -> Result<(), String> {
    if revents & expected == 0 {
        Err(format!(
            "{context}: wrong event: got {}, expected any of {}",
            describe_events(revents),
            describe_events(expected)
        ))
    } else {
        Ok(())
    }
}

fn describe_events(events: libc::c_short) -> String {
    let mut names = Vec::new();
    if events & libc::POLLIN != 0 {
        names.push("POLLIN");
    }
    if events & libc::POLLHUP != 0 {
        names.push("POLLHUP");
    }
    if events & libc::POLLRDHUP != 0 {
        names.push("POLLRDHUP");
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

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn agent_for_bt(bt: crate::BinaryType) -> AgentName {
    match bt {
        crate::BinaryType::PieGlibc => AgentName::Dpg1,
        crate::BinaryType::NonPieGlibc => AgentName::Dpg1Dng,
        crate::BinaryType::StaticPieGlibc => AgentName::Dpg1Spg,
        crate::BinaryType::StaticPieMusl => AgentName::Dpg1Spm,
        crate::BinaryType::NonPieStaticMusl => AgentName::Dpg1Snm,
    }
}

pub(super) fn register_readiness_tests(reg: &mut Registry<'_>) {
    register_handler!(READINESS, handle_readiness);

    for &subsystem in ReadinessSubsystem::ALL {
        for &op in valid_ops(subsystem) {
            for &bt in crate::BinaryType::ALL {
                let trial = ReadinessTrial { bt, subsystem, op };
                let agent = agent_for_bt(bt);
                let agent_label = agent.to_string();
                let id = format!(
                    "READY.{}.{}.{}",
                    subsystem.label(),
                    op.label(),
                    bt.short_label()
                );
                reg.test("matrix", "readiness", id)
                    .timeout(30)
                    .build(move |cx| {
                        let handle = cx.require(agent);
                        let agent_label = agent_label.clone();
                        Box::new(move |run| {
                            Box::pin(async move {
                                let result = run.send_named_typed(&handle, &READINESS, trial).await;
                                match result {
                                    Ok(out) => {
                                        TestOutcome::new(&agent_label, out.passed, out.detail)
                                    }
                                    Err(e) => TestOutcome::new(
                                        &agent_label,
                                        false,
                                        format!("handler error: {e}"),
                                    ),
                                }
                            })
                        })
                    });
            }
        }
    }
}
