// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Peer-readiness invariant tests.
//!
//! This scaffold exercises the invariant that an operation on one endpoint
//! which changes peer readiness must wake a peer waiting in `poll`, and that
//! the subsequent `read` observes the corresponding data or EOF.

// TODO(#15): convert legacy wildcard enum dispatch in this file to explicit arms.
#![allow(clippy::wildcard_enum_match_arm)]

use std::ffi::CString;
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{AgentHandle, AgentName, HandlerCtx, HandlerError, HandlerToken, Registry, RunContext};
use crate::coordinator::TestOutcome;
use crate::os::pty::Pty;
use crate::os::socket::TcpSocket;
use crate::register_handler;

const READINESS: HandlerToken<ReadinessTrial, ReadinessOut> = HandlerToken::new("readiness.run");
const TCP_ACCEPT_PROXY_SERVER: HandlerToken<TcpAcceptProxyArgs, ReadinessOut> =
    HandlerToken::new("readiness.tcp_accept_proxy.server");
const TCP_ACCEPT_PROXY_CLIENT: HandlerToken<TcpAcceptProxyArgs, ReadinessOut> =
    HandlerToken::new("readiness.tcp_accept_proxy.client");
const TCP_ACCEPT_PROXY_READY: &str = "tcp_accept_proxy_listening";
const POLL_TIMEOUT_MS: i32 = 2_000;
const READ_TIMEOUT: Duration = Duration::from_secs(2);
const WRITE_THEN_CLOSE_PAYLOAD: &[u8] = b"READY_TCP_PAYLOAD";
const TCP_ACCEPT_PROXY_PAYLOAD: &[u8] = b"hi";
const TCP_ACCEPT_PROXY_ACK: &[u8] = b"ack";
const PTY_SLAVE_PAYLOAD: &[u8] = b"READY_PTY_SLAVE";
const PTY_MASTER_PAYLOAD: &[u8] = b"READY_PTY_MASTER";

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
struct ReadinessTrial {
    bt: crate::BinaryType,
    subsystem: ReadinessSubsystem,
    op: PeerOp,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
struct TcpAcceptProxyArgs {
    port: u16,
    op: PeerOp,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
enum ReadinessSubsystem {
    TcpConn,
    TcpAcceptProxy,
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
        Self::TcpAcceptProxy,
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
            Self::TcpAcceptProxy => "tcp_accept_proxy",
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
    ClientShutdownWrServerReadsEof,
    ClientCloseServerReadsEof,
    ClientWritesThenShutdownServerPollHup,
    ServerShutdownWrClientReadsEof,
    SlaveClose,
    SlaveWriteThenClose,
    SlaveWrite,
    MasterWrite,
}

impl PeerOp {
    fn label(self) -> &'static str {
        match self {
            Self::ShutdownWr => "peer_shutdown_wr",
            Self::Close => "peer_close",
            Self::WriteThenClose => "peer_write_then_close",
            Self::ClientShutdownWrServerReadsEof => "client_shutdown_wr_server_reads_eof",
            Self::ClientCloseServerReadsEof => "client_close_server_reads_eof",
            Self::ClientWritesThenShutdownServerPollHup => {
                "client_writes_then_shutdown_server_poll_hup"
            }
            Self::ServerShutdownWrClientReadsEof => "server_shutdown_wr_client_reads_eof",
            Self::SlaveClose => "slave_close",
            Self::SlaveWriteThenClose => "slave_write_then_close",
            Self::SlaveWrite => "slave_write",
            Self::MasterWrite => "master_write",
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
        ReadinessSubsystem::TcpAcceptProxy => skip_pending(ReadinessSubsystem::TcpAcceptProxy),
        ReadinessSubsystem::Pipe => skip_pending(ReadinessSubsystem::Pipe),
        ReadinessSubsystem::SocketPair => skip_pending(ReadinessSubsystem::SocketPair),
        ReadinessSubsystem::Eventfd => skip_pending(ReadinessSubsystem::Eventfd),
        ReadinessSubsystem::Signalfd => skip_pending(ReadinessSubsystem::Signalfd),
        ReadinessSubsystem::Pty => run_pty_trial(trial.op),
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
        ReadinessSubsystem::TcpAcceptProxy => &[
            PeerOp::ClientShutdownWrServerReadsEof,
            PeerOp::ClientCloseServerReadsEof,
            PeerOp::ClientWritesThenShutdownServerPollHup,
            PeerOp::ServerShutdownWrClientReadsEof,
        ],
        ReadinessSubsystem::Pty => &[
            PeerOp::SlaveClose,
            PeerOp::SlaveWriteThenClose,
            PeerOp::MasterWrite,
            PeerOp::SlaveWrite,
        ],
        ReadinessSubsystem::Pipe
        | ReadinessSubsystem::SocketPair
        | ReadinessSubsystem::Eventfd
        | ReadinessSubsystem::Signalfd
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
        PeerOp::ClientShutdownWrServerReadsEof
        | PeerOp::ClientCloseServerReadsEof
        | PeerOp::ClientWritesThenShutdownServerPollHup
        | PeerOp::ServerShutdownWrClientReadsEof
        | PeerOp::SlaveClose
        | PeerOp::SlaveWriteThenClose
        | PeerOp::SlaveWrite
        | PeerOp::MasterWrite => Err(format!("unsupported tcp_conn op {}", op.label())),
    }
}

fn run_pty_trial(op: PeerOp) -> TrialResult {
    match run_pty_trial_inner(op) {
        Ok(detail) => TrialResult::Passed(detail),
        Err(detail) => TrialResult::Failed(detail),
    }
}

fn run_pty_trial_inner(op: PeerOp) -> Result<String, String> {
    let (master, slave) = open_raw_pty_pair()?;

    match op {
        PeerOp::SlaveClose => {
            drop(slave);
            let revents = poll_fd(master.as_raw_fd(), pty_readiness_mask(), POLL_TIMEOUT_MS)?;
            require_any(revents, libc::POLLHUP, "slave_close master poll")?;
            let read_detail = read_zero_or_eio(master.as_raw_fd(), "slave_close master read")?;
            Ok(format!(
                "master_poll={} master_read={read_detail}",
                describe_events(revents)
            ))
        }
        PeerOp::SlaveWriteThenClose => {
            write_all_fd(slave.as_raw_fd(), PTY_SLAVE_PAYLOAD, "slave write")?;
            drop(slave);

            let revents1 = poll_fd(master.as_raw_fd(), pty_readiness_mask(), POLL_TIMEOUT_MS)?;
            require_any(revents1, libc::POLLIN, "slave_write_then_close data poll")?;
            read_exact_payload(
                master.as_raw_fd(),
                PTY_SLAVE_PAYLOAD,
                "slave_write_then_close data read",
            )?;

            let revents2 = poll_fd(master.as_raw_fd(), pty_readiness_mask(), POLL_TIMEOUT_MS)?;
            require_any(revents2, libc::POLLHUP, "slave_write_then_close hup poll")?;
            let read_detail = read_zero_or_eio(
                master.as_raw_fd(),
                "slave_write_then_close post-payload read",
            )?;
            Ok(format!(
                "data_poll={} hup_poll={} read={} bytes then {read_detail}",
                describe_events(revents1),
                describe_events(revents2),
                PTY_SLAVE_PAYLOAD.len()
            ))
        }
        PeerOp::SlaveWrite => {
            write_all_fd(slave.as_raw_fd(), PTY_SLAVE_PAYLOAD, "slave write")?;
            let revents = poll_fd(master.as_raw_fd(), pty_readiness_mask(), POLL_TIMEOUT_MS)?;
            require_any(revents, libc::POLLIN, "slave_write master poll")?;
            read_exact_payload(
                master.as_raw_fd(),
                PTY_SLAVE_PAYLOAD,
                "slave_write master read",
            )?;
            Ok(format!(
                "master_poll={} read={} bytes",
                describe_events(revents),
                PTY_SLAVE_PAYLOAD.len()
            ))
        }
        PeerOp::MasterWrite => {
            write_all_fd(master.as_raw_fd(), PTY_MASTER_PAYLOAD, "master write")?;
            let revents = poll_fd(
                slave.as_raw_fd(),
                libc::POLLIN | libc::POLLHUP,
                POLL_TIMEOUT_MS,
            )?;
            require_any(revents, libc::POLLIN, "master_write slave poll")?;
            read_exact_payload(
                slave.as_raw_fd(),
                PTY_MASTER_PAYLOAD,
                "master_write slave read",
            )?;
            Ok(format!(
                "slave_poll={} read={} bytes",
                describe_events(revents),
                PTY_MASTER_PAYLOAD.len()
            ))
        }
        PeerOp::ShutdownWr
        | PeerOp::Close
        | PeerOp::WriteThenClose
        | PeerOp::ClientShutdownWrServerReadsEof
        | PeerOp::ClientCloseServerReadsEof
        | PeerOp::ClientWritesThenShutdownServerPollHup
        | PeerOp::ServerShutdownWrClientReadsEof => {
            Err(format!("unsupported pty op {}", op.label()))
        }
    }
}

async fn handle_tcp_accept_proxy_server(
    args: TcpAcceptProxyArgs,
    ctx: &mut HandlerCtx<'_>,
) -> Result<ReadinessOut, HandlerError> {
    let result = run_tcp_accept_proxy_server(args, ctx).await;
    Ok(readiness_out(result))
}

async fn handle_tcp_accept_proxy_client(
    args: TcpAcceptProxyArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ReadinessOut, HandlerError> {
    Ok(readiness_out(run_tcp_accept_proxy_client(args)))
}

async fn run_tcp_accept_proxy_server(
    args: TcpAcceptProxyArgs,
    ctx: &mut HandlerCtx<'_>,
) -> Result<String, String> {
    let listener = TcpSocket::new_tcp_listen(args.port)
        .map_err(|e| format!("server bind/listen port {}: {e}", args.port))?;
    ctx.checkpoint(TCP_ACCEPT_PROXY_READY)
        .await
        .map_err(|e| e.0)?;
    let revents = poll_fd(listener.as_raw_fd(), libc::POLLIN, POLL_TIMEOUT_MS)?;
    require_any(revents, libc::POLLIN, "server listener accept poll")?;
    let conn = listener
        .accept()
        .map_err(|e| format!("server accept: {e}"))?;
    drop(listener);

    match args.op {
        PeerOp::ClientShutdownWrServerReadsEof => {
            read_exact_after_poll(
                conn.as_raw_fd(),
                TCP_ACCEPT_PROXY_PAYLOAD,
                "server data after client shutdown",
            )?;
            let eof_poll =
                read_eof_after_poll(conn.as_raw_fd(), "server EOF after client shutdown")?;
            Ok(format!(
                "accept_poll={} read={} bytes eof_poll={}",
                describe_events(revents),
                TCP_ACCEPT_PROXY_PAYLOAD.len(),
                describe_events(eof_poll)
            ))
        }
        PeerOp::ClientCloseServerReadsEof => {
            read_exact_after_poll(
                conn.as_raw_fd(),
                TCP_ACCEPT_PROXY_PAYLOAD,
                "server data after client close",
            )?;
            let eof_poll = read_eof_after_poll(conn.as_raw_fd(), "server EOF after client close")?;
            Ok(format!(
                "accept_poll={} read={} bytes eof_poll={}",
                describe_events(revents),
                TCP_ACCEPT_PROXY_PAYLOAD.len(),
                describe_events(eof_poll)
            ))
        }
        PeerOp::ClientWritesThenShutdownServerPollHup => {
            let eof_poll = poll_fd(conn.as_raw_fd(), readiness_mask(), POLL_TIMEOUT_MS)?;
            require_any(
                eof_poll,
                libc::POLLRDHUP | libc::POLLHUP,
                "server poll before reading client shutdown",
            )?;
            read_exact_nonblocking(
                conn.as_raw_fd(),
                TCP_ACCEPT_PROXY_PAYLOAD,
                "server data after EOF poll",
            )?;
            let n = read_once(conn.as_raw_fd(), &mut [0_u8; 1])?;
            if n != 0 {
                return Err(format!(
                    "server post-payload read expected EOF, got {n} bytes"
                ));
            }
            Ok(format!(
                "accept_poll={} eof_poll={} read={} bytes then EOF",
                describe_events(revents),
                describe_events(eof_poll),
                TCP_ACCEPT_PROXY_PAYLOAD.len()
            ))
        }
        PeerOp::ServerShutdownWrClientReadsEof => {
            send_all_fd(conn.as_raw_fd(), TCP_ACCEPT_PROXY_ACK, "server ack send")?;
            conn.shutdown_write()
                .map_err(|e| format!("server shutdown(SHUT_WR): {e}"))?;
            Ok(format!(
                "accept_poll={} sent={} bytes shutdown_wr",
                describe_events(revents),
                TCP_ACCEPT_PROXY_ACK.len()
            ))
        }
        _ => Err(format!(
            "unsupported tcp_accept_proxy server op {}",
            args.op.label()
        )),
    }
}

fn run_tcp_accept_proxy_client(args: TcpAcceptProxyArgs) -> Result<String, String> {
    let conn = TcpSocket::connect_loopback(args.port)
        .map_err(|e| format!("client connect port {}: {e}", args.port))?;
    match args.op {
        PeerOp::ClientShutdownWrServerReadsEof | PeerOp::ClientWritesThenShutdownServerPollHup => {
            send_all_fd(
                conn.as_raw_fd(),
                TCP_ACCEPT_PROXY_PAYLOAD,
                "client payload send",
            )?;
            conn.shutdown_write()
                .map_err(|e| format!("client shutdown(SHUT_WR): {e}"))?;
            Ok(format!(
                "sent={} bytes shutdown_wr",
                TCP_ACCEPT_PROXY_PAYLOAD.len()
            ))
        }
        PeerOp::ClientCloseServerReadsEof => {
            send_all_fd(
                conn.as_raw_fd(),
                TCP_ACCEPT_PROXY_PAYLOAD,
                "client payload send",
            )?;
            drop(conn);
            Ok(format!(
                "sent={} bytes close",
                TCP_ACCEPT_PROXY_PAYLOAD.len()
            ))
        }
        PeerOp::ServerShutdownWrClientReadsEof => {
            read_exact_after_poll(
                conn.as_raw_fd(),
                TCP_ACCEPT_PROXY_ACK,
                "client ack after server shutdown",
            )?;
            let eof_poll =
                read_eof_after_poll(conn.as_raw_fd(), "client EOF after server shutdown")?;
            Ok(format!(
                "read={} bytes eof_poll={}",
                TCP_ACCEPT_PROXY_ACK.len(),
                describe_events(eof_poll)
            ))
        }
        _ => Err(format!(
            "unsupported tcp_accept_proxy client op {}",
            args.op.label()
        )),
    }
}

async fn run_tcp_accept_proxy_trial(
    run: &mut RunContext<'_>,
    server: &AgentHandle,
    client: &AgentHandle,
    bt: crate::BinaryType,
    op: PeerOp,
) -> Result<String, String> {
    let port = tcp_accept_proxy_port(bt, op);
    let args = TcpAcceptProxyArgs { port, op };
    run.run_write_typed(server, &TCP_ACCEPT_PROXY_SERVER, args)
        .await
        .map_err(|e| format!("server start: {e}"))?;
    run.run_read_checkpoint(server, TCP_ACCEPT_PROXY_READY)
        .await
        .map_err(|e| format!("server checkpoint: {e}"))?;
    run.run_resume(server, TCP_ACCEPT_PROXY_READY)
        .await
        .map_err(|e| format!("server resume: {e}"))?;

    let client_out = run
        .send_named_typed(client, &TCP_ACCEPT_PROXY_CLIENT, args)
        .await
        .map_err(|e| format!("client handler: {e}"))?;
    let server_out = run
        .run_read_result(server, &TCP_ACCEPT_PROXY_SERVER)
        .await
        .map_err(|e| format!("server result: {e}"))?;

    if !client_out.passed {
        return Err(format!("client failed: {}", client_out.detail));
    }
    if !server_out.passed {
        return Err(format!("server failed: {}", server_out.detail));
    }
    Ok(format!(
        "port={port}; client: {}; server: {}",
        client_out.detail, server_out.detail
    ))
}

fn readiness_out(result: Result<String, String>) -> ReadinessOut {
    match result {
        Ok(detail) => ReadinessOut {
            passed: true,
            detail,
        },
        Err(detail) => ReadinessOut {
            passed: false,
            detail,
        },
    }
}

fn tcp_accept_proxy_port(bt: crate::BinaryType, op: PeerOp) -> u16 {
    34_000 + binary_type_index(bt) * 16 + tcp_accept_proxy_op_index(op)
}

fn binary_type_index(bt: crate::BinaryType) -> u16 {
    match bt {
        crate::BinaryType::PieGlibc => 0,
        crate::BinaryType::NonPieGlibc => 1,
        crate::BinaryType::StaticPieGlibc => 2,
        crate::BinaryType::StaticPieMusl => 3,
        crate::BinaryType::NonPieStaticMusl => 4,
    }
}

fn tcp_accept_proxy_op_index(op: PeerOp) -> u16 {
    match op {
        PeerOp::ClientShutdownWrServerReadsEof => 0,
        PeerOp::ClientCloseServerReadsEof => 1,
        PeerOp::ClientWritesThenShutdownServerPollHup => 2,
        PeerOp::ServerShutdownWrClientReadsEof => 3,
        _ => 15,
    }
}

fn readiness_mask() -> libc::c_short {
    libc::POLLIN | libc::POLLHUP | libc::POLLRDHUP
}

fn pty_readiness_mask() -> libc::c_short {
    libc::POLLIN | libc::POLLHUP | libc::POLLERR
}

fn open_raw_pty_pair() -> Result<(Pty, OwnedFd), String> {
    let master = Pty::open()?;
    let slave_path = CString::new(master.slave_path())
        .map_err(|e| format!("pty slave path contains nul: {e}"))?;
    // SAFETY: `slave_path` is a valid nul-terminated path returned by ptsname_r.
    let slave_fd = unsafe {
        libc::open(
            slave_path.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if slave_fd < 0 {
        return Err(format!(
            "open pty slave {}: {}",
            master.slave_path(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `open` returned a fresh fd and ownership is transferred to OwnedFd.
    let slave = unsafe { OwnedFd::from_raw_fd(slave_fd) };
    make_raw(slave.as_raw_fd())?;
    Ok((master, slave))
}

fn make_raw(fd: i32) -> Result<(), String> {
    // SAFETY: zeroed termios is immediately initialized by tcgetattr on success.
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: tcgetattr writes termios state for a live PTY slave fd.
    if unsafe { libc::tcgetattr(fd, &raw mut termios) } != 0 {
        return Err(format!(
            "tcgetattr fd {fd}: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: cfmakeraw mutates an initialized termios value in place.
    unsafe { libc::cfmakeraw(&raw mut termios) };
    // SAFETY: tcsetattr reads the initialized termios for a live PTY slave fd.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw const termios) } != 0 {
        return Err(format!(
            "tcsetattr raw fd {fd}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn poll_fd(fd: i32, events: libc::c_short, timeout_ms: i32) -> Result<libc::c_short, String> {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    loop {
        // SAFETY: `pfd` points to one initialized pollfd, the count is 1,
        // and `fd` is owned by a live endpoint for the duration of the call.
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

fn send_all_fd(fd: i32, mut buf: &[u8], op: &str) -> Result<(), String> {
    while !buf.is_empty() {
        let n = send_once(fd, buf).map_err(|e| format!("{op}: {e}"))?;
        if n == 0 {
            return Err(format!("{op} sent 0 bytes"));
        }
        buf = &buf[n..];
    }
    Ok(())
}

fn read_exact_after_poll(fd: i32, expected: &[u8], context: &str) -> Result<(), String> {
    let revents = poll_fd(fd, readiness_mask(), POLL_TIMEOUT_MS)?;
    require_any(revents, libc::POLLIN, context)?;
    read_exact_nonblocking(fd, expected, context)
}

fn read_exact_nonblocking(fd: i32, expected: &[u8], context: &str) -> Result<(), String> {
    let mut buf = vec![0_u8; expected.len()];
    let mut filled = 0;
    while filled < expected.len() {
        let n = read_once(fd, &mut buf[filled..]).map_err(|e| format!("{context}: {e}"))?;
        if n == 0 {
            return Err(format!(
                "{context}: early EOF after {filled} of {} bytes",
                expected.len()
            ));
        }
        filled += n;
        if filled < expected.len() {
            let revents = poll_fd(fd, readiness_mask(), POLL_TIMEOUT_MS)?;
            require_any(revents, libc::POLLIN, context)?;
        }
    }
    if buf != expected {
        return Err(format!(
            "{context}: payload mismatch: got {:?}, expected {:?}",
            String::from_utf8_lossy(&buf),
            String::from_utf8_lossy(expected)
        ));
    }
    Ok(())
}

fn read_eof_after_poll(fd: i32, context: &str) -> Result<libc::c_short, String> {
    let revents = poll_fd(fd, readiness_mask(), POLL_TIMEOUT_MS)?;
    require_any(
        revents,
        libc::POLLIN | libc::POLLHUP | libc::POLLRDHUP,
        context,
    )?;
    let n = read_once(fd, &mut [0_u8; 1]).map_err(|e| format!("{context}: {e}"))?;
    if n == 0 {
        Ok(revents)
    } else {
        Err(format!("{context}: expected EOF, got {n} bytes"))
    }
}

fn write_all_fd(fd: i32, mut buf: &[u8], op: &str) -> Result<(), String> {
    while !buf.is_empty() {
        // SAFETY: `buf` is readable memory and `fd` is a live PTY endpoint fd.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
        let n = syscall_len(n, op)?;
        if n == 0 {
            return Err(format!("{op} wrote 0 bytes"));
        }
        buf = &buf[n..];
    }
    Ok(())
}

fn read_exact_payload(fd: i32, expected: &[u8], context: &str) -> Result<(), String> {
    let mut buf = vec![0_u8; expected.len()];
    let n = read_fd_once(fd, &mut buf, context)?;
    if n != expected.len() {
        return Err(format!(
            "{context}: read length mismatch: got {n}, expected {}",
            expected.len()
        ));
    }
    if buf != expected {
        return Err(format!(
            "{context}: payload mismatch: got {:?}, expected {:?}",
            String::from_utf8_lossy(&buf),
            String::from_utf8_lossy(expected)
        ));
    }
    Ok(())
}

fn read_zero_or_eio(fd: i32, context: &str) -> Result<&'static str, String> {
    let mut buf = [0_u8; 1];
    // SAFETY: `buf` is valid writable memory and `fd` is a live PTY endpoint fd.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n == 0 {
        return Ok("EOF");
    }
    if n > 0 {
        return Err(format!("{context}: expected EOF/EIO, got {n} bytes"));
    }
    let errno = errno();
    if errno == libc::EIO {
        Ok("EIO")
    } else if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
        Err(format!("{context}: read would block after readiness"))
    } else {
        Err(format!("{context}: read failed errno={errno}"))
    }
}

fn read_fd_once(fd: i32, buf: &mut [u8], op: &str) -> Result<usize, String> {
    // SAFETY: `buf` is valid writable memory and `fd` is a live PTY endpoint fd.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    syscall_len(n, op)
}

fn syscall_len(n: isize, op: &str) -> Result<usize, String> {
    if n < 0 {
        let errno = errno();
        if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
            Err(format!(
                "{op} would block after poll timeout={POLL_TIMEOUT_MS}ms"
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
    register_handler!(TCP_ACCEPT_PROXY_SERVER, handle_tcp_accept_proxy_server);
    register_handler!(TCP_ACCEPT_PROXY_CLIENT, handle_tcp_accept_proxy_client);

    for &subsystem in ReadinessSubsystem::ALL {
        for &op in valid_ops(subsystem) {
            for &bt in crate::BinaryType::ALL {
                if subsystem == ReadinessSubsystem::TcpAcceptProxy {
                    register_tcp_accept_proxy_trial(reg, bt, op);
                } else {
                    register_single_agent_readiness_trial(reg, subsystem, bt, op);
                }
            }
        }
    }
}

fn register_single_agent_readiness_trial(
    reg: &mut Registry<'_>,
    subsystem: ReadinessSubsystem,
    bt: crate::BinaryType,
    op: PeerOp,
) {
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
                        Ok(out) => TestOutcome::new(&agent_label, out.passed, out.detail),
                        Err(e) => {
                            TestOutcome::new(&agent_label, false, format!("handler error: {e}"))
                        }
                    }
                })
            })
        });
}

fn register_tcp_accept_proxy_trial(reg: &mut Registry<'_>, bt: crate::BinaryType, op: PeerOp) {
    let server_agent = agent_for_bt(bt);
    let client_agent = AgentName::Dpg2;
    let agent_label = format!("{server_agent}<-{client_agent}");
    let id = format!(
        "READY.{}.{}.{}",
        ReadinessSubsystem::TcpAcceptProxy.label(),
        op.label(),
        bt.short_label()
    );
    reg.test("matrix", "readiness", id)
        .timeout(30)
        .build(move |cx| {
            let server = cx.require(server_agent);
            let client = cx.require(client_agent);
            let agent_label = agent_label.clone();
            Box::new(move |run| {
                Box::pin(async move {
                    match run_tcp_accept_proxy_trial(run, &server, &client, bt, op).await {
                        Ok(detail) => TestOutcome::new(&agent_label, true, detail),
                        Err(detail) => TestOutcome::new(&agent_label, false, detail),
                    }
                })
            })
        });
}
