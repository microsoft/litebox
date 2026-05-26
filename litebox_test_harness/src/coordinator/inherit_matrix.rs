// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fork+exec fd-inheritance matrix scaffold.
//!
//! The pilot covers TCP listen sockets across the full parent/child
//! binary-type cross-product. Additional fd subsystems are represented in
//! the dispatch/data model so the next subsystem can be added by filling in
//! the corresponding runner.

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::{BinaryType, register_handler, register_leaf_subcommand};

use serde::{Deserialize, Serialize};

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;

const TCP_LISTEN_MATRIX: HandlerToken<TcpListenTrialArgs, ChildOutput> =
    HandlerToken::new("inherit_matrix.tcp_listen");

const TCP_LISTEN_OPS: &[InheritOp] = &[
    InheritOp::Accept,
    InheritOp::GetSockname,
    InheritOp::GetSockoptReuseport,
];

#[allow(dead_code)]
const PIPE_OPS: &[InheritOp] = &[InheritOp::Read, InheritOp::Write, InheritOp::Poll];
#[allow(dead_code)]
const SOCKETPAIR_OPS: &[InheritOp] = &[
    InheritOp::Read,
    InheritOp::Write,
    InheritOp::Poll,
    InheritOp::Shutdown,
];
#[allow(dead_code)]
const TCP_CONN_OPS: &[InheritOp] = &[
    InheritOp::Read,
    InheritOp::Write,
    InheritOp::Poll,
    InheritOp::Shutdown,
    InheritOp::GetSockname,
];
#[allow(dead_code)]
const EVENTFD_OPS: &[InheritOp] = &[InheritOp::Read, InheritOp::Write, InheritOp::Poll];
#[allow(dead_code)]
const SIGNALFD_OPS: &[InheritOp] = &[InheritOp::Read, InheritOp::Poll];
#[allow(dead_code)]
const TIMERFD_OPS: &[InheritOp] = &[InheritOp::Read, InheritOp::Poll];
#[allow(dead_code)]
const PTY_OPS: &[InheritOp] = &[InheritOp::Read, InheritOp::Write, InheritOp::Poll];
#[allow(dead_code)]
const BROKER_FILE_OPS: &[InheritOp] = &[InheritOp::Read, InheritOp::Write, InheritOp::Dup];

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
}

impl InheritSubsystem {
    #[allow(dead_code)]
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
    ];

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
            Self::BrokerFile => "broker_file",
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
struct ChildOutput {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

pub(crate) fn register_inherit_matrix_tests(reg: &mut Registry<'_>) {
    register_handler!(TCP_LISTEN_MATRIX, handle_tcp_listen_trial);
    register_leaf_subcommand!("inherit-matrix", leaf_subcmd::subcmd_inherit_matrix);

    for &parent_bt in BinaryType::ALL {
        for &child_bt in BinaryType::ALL {
            for &op in valid_ops(InheritSubsystem::TcpListen) {
                let trial = InheritTrial {
                    parent_bt,
                    child_bt,
                    subsystem: InheritSubsystem::TcpListen,
                    op,
                };
                register_trial(reg, trial);
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
    }
}

const NON_PIE_CHILD_ACCEPT_XFAIL_REASON: &str =
    "non-PIE child cross-worker listen-queue ownership pending (follow-up to non-PIE inherit fix)";

fn expected_fail_reason(trial: InheritTrial) -> Option<&'static str> {
    if matches!(trial.subsystem, InheritSubsystem::TcpListen)
        && matches!(trial.op, InheritOp::Accept)
        && matches!(
            trial.parent_bt,
            BinaryType::PieGlibc
                | BinaryType::NonPieGlibc
                | BinaryType::StaticPieGlibc
                | BinaryType::StaticPieMusl
                | BinaryType::NonPieStaticMusl
        )
        && matches!(
            trial.child_bt,
            BinaryType::NonPieGlibc | BinaryType::NonPieStaticMusl
        )
    {
        Some(NON_PIE_CHILD_ACCEPT_XFAIL_REASON)
    } else {
        None
    }
}

fn register_trial(reg: &mut Registry<'_>, trial: InheritTrial) {
    let id = trial.id();
    let parent = parent_agent(trial.parent_bt);
    let mut test = reg.test("vscode", "inherit_matrix", id).timeout(30);
    if let Some(reason) = expected_fail_reason(trial) {
        test = test.expected_fail_on_litebox(reason);
    }

    test.build(move |cx| {
        let parent_handle = cx.require(parent);
        Box::new(move |run| {
            Box::pin(async move {
                let self_exe = run.self_exe().to_string();
                let child_binary = crate::binary_path(trial.child_bt, &self_exe);
                let result = run
                    .send_named_typed(
                        &parent_handle,
                        &TCP_LISTEN_MATRIX,
                        TcpListenTrialArgs {
                            child_binary,
                            op: trial.op,
                            timeout_ms: 5000,
                        },
                    )
                    .await;
                match result {
                    Ok(out) if out.exit_code == 0 => TestOutcome::new(
                        parent.name(),
                        true,
                        format!("child {} inherited tcp_listen fd", trial.op.id()),
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

const fn parent_agent(bt: BinaryType) -> AgentName {
    match bt {
        BinaryType::PieGlibc => AgentName::Dpg1,
        BinaryType::NonPieGlibc => AgentName::Dpg1Dng,
        BinaryType::StaticPieGlibc => AgentName::Dpg1Spg,
        BinaryType::StaticPieMusl => AgentName::Dpg1Spm,
        BinaryType::NonPieStaticMusl => AgentName::Dpg1Snm,
    }
}

#[allow(dead_code)]
fn run_scaffolded_trial(subsystem: InheritSubsystem, _op: InheritOp) -> String {
    match subsystem {
        InheritSubsystem::TcpListen => {
            "tcp_listen is implemented by handle_tcp_listen_trial".into()
        }
        InheritSubsystem::Pipe => run_pipe_trial(),
        InheritSubsystem::SocketPair => run_socketpair_trial(),
        InheritSubsystem::TcpConn => run_tcp_conn_trial(),
        InheritSubsystem::Eventfd => run_eventfd_trial(),
        InheritSubsystem::Signalfd => run_signalfd_trial(),
        InheritSubsystem::Timerfd => run_timerfd_trial(),
        InheritSubsystem::Pty => run_pty_trial(),
        InheritSubsystem::BrokerFile => run_broker_file_trial(),
    }
}

#[allow(dead_code)]
fn run_pipe_trial() -> String {
    "INHERIT.pipe: scaffold pending".into()
}

#[allow(dead_code)]
fn run_socketpair_trial() -> String {
    "INHERIT.socketpair: scaffold pending".into()
}

#[allow(dead_code)]
fn run_tcp_conn_trial() -> String {
    "INHERIT.tcp_conn: scaffold pending".into()
}

#[allow(dead_code)]
fn run_eventfd_trial() -> String {
    "INHERIT.eventfd: scaffold pending".into()
}

#[allow(dead_code)]
fn run_signalfd_trial() -> String {
    "INHERIT.signalfd: scaffold pending".into()
}

#[allow(dead_code)]
fn run_timerfd_trial() -> String {
    "INHERIT.timerfd: scaffold pending".into()
}

#[allow(dead_code)]
fn run_pty_trial() -> String {
    "INHERIT.pty: scaffold pending".into()
}

#[allow(dead_code)]
fn run_broker_file_trial() -> String {
    "INHERIT.broker_file: scaffold pending".into()
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
    // SAFETY: socket parameters are constants; errors are checked below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(HandlerError(format!(
            "socket: {}",
            std::io::Error::last_os_error()
        )));
    }

    let one: libc::c_int = 1;
    // SAFETY: fd is live; `one` points to an initialized c_int.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            std::ptr::from_ref(&one).cast::<libc::c_void>(),
            std::mem::size_of_val(&one) as libc::socklen_t,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: fd is owned in this function on the error path.
        unsafe { libc::close(fd) };
        return Err(HandlerError(format!("setsockopt(SO_REUSEPORT): {err}")));
    }

    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0u16.to_be(),
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
        return Err(HandlerError(format!("bind(127.0.0.1:0): {err}")));
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
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child
            .try_wait()
            .map_err(|e| HandlerError(format!("try_wait: {e}")))?
        {
            Some(_) => {
                let output = child
                    .wait_with_output()
                    .map_err(|e| HandlerError(format!("wait_with_output: {e}")))?;
                return Ok(output);
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
    let _ = child.kill();
    let output = child
        .wait_with_output()
        .map_err(|e| HandlerError(format!("wait after timeout: {e}")))?;
    Ok(std::process::Output {
        status: output.status,
        stdout: output.stdout,
        stderr: [output.stderr, b"timeout waiting for child".to_vec()].concat(),
    })
}

mod leaf_subcmd {
    use std::io::Write;
    use std::net::TcpStream;
    use std::os::fd::{FromRawFd, RawFd};

    pub(super) fn subcmd_inherit_matrix(args: &[String]) -> i32 {
        match args.get(2).map(String::as_str) {
            Some("tcp-listen-child") => tcp_listen_child(args),
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
