// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! SCM_RIGHTS fd-passing tests over Unix domain sockets.

use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::eventfd::EventFd;
use crate::os::unix_socket::{UnixListener, UnixStream};
use crate::register_handler;

use super::TestOutcome;
use super::agents::{AgentHandle, AgentName};
use super::registry::Registry;
use super::run_context::RunContext;

#[derive(Clone, Copy)]
struct ScmPair {
    sender: AgentName,
    receiver: AgentName,
}

const SCM_PAIRS: &[ScmPair] = &[
    ScmPair {
        // PIE-glibc → PIE-glibc, sibling subtree (baseline).
        sender: AgentName::Dpg1,
        receiver: AgentName::Dpg2,
    },
    ScmPair {
        // PIE-glibc → PIE-glibc, depth-2 (fd routes through one
        // hop on each side — exercises the bridge-fd inheritance).
        sender: AgentName::Dpg1Dpg1,
        receiver: AgentName::Dpg2Dpg,
    },
    // Cross-binary-type pairs. The shim's fd-bridge / replacement
    // table is driven by the parent's binary type; passing fds
    // across processes with different binary types exercises code
    // paths that same-type pairs do not.
    ScmPair {
        // PIE-glibc → non-PIE-glibc: the sshd→bash class fd passing
        // (every common Unix tool inherits an fd from its launcher).
        sender: AgentName::Dpg1,
        receiver: AgentName::Dpg1Dng,
    },
    ScmPair {
        // non-PIE-glibc → PIE-glibc: the reverse direction. Useful
        // because the receiver-side bridge install path differs
        // from the sender-side.
        sender: AgentName::Dpg1Dng,
        receiver: AgentName::Dpg1,
    },
    ScmPair {
        // non-PIE → non-PIE (the bash→bash recursion in VS Code).
        sender: AgentName::Dpg1Dng,
        receiver: AgentName::Dpg1DngDng,
    },
    ScmPair {
        // non-PIE → static-PIE-musl (the bash→cli VS Code entry
        // transition). Tests fd-passing across the cli boundary.
        sender: AgentName::Dpg1Dng,
        receiver: AgentName::Dpg1DngSpm,
    },
    ScmPair {
        // static-PIE-musl → non-PIE-glibc (the cli→node VS Code
        // signature transition). The most consequential pair for
        // VS Code Server: every fd Node.js needs (sockets, pipes,
        // pty endpoints) flows through this exact transition.
        sender: AgentName::Dpg1Spm,
        receiver: AgentName::Dpg1SpmDng,
    },
    // Static-PIE-glibc and non-PIE-static-musl coverage. Added so
    // every binary type appears as both sender and receiver at
    // least once. Without these pairs the shim's fd-table install
    // path for static-PIE-glibc and non-PIE-static-musl receivers
    // is never exercised by SCM tests.
    ScmPair {
        // static-PIE-glibc as sender (cross-tree): exercises the
        // sender-side passed_fds path on a static-PIE-glibc binary.
        sender: AgentName::Dpg1Spg,
        receiver: AgentName::Dpg2,
    },
    ScmPair {
        // non-PIE-static-musl as sender (cross-tree): exercises the
        // sender-side passed_fds path on a fully static musl binary.
        sender: AgentName::Dpg1Snm,
        receiver: AgentName::Dpg2,
    },
    ScmPair {
        // PIE-glibc → static-PIE-glibc within-tree: the receiver-side
        // fd-table install path on static-PIE-glibc (which still loads
        // ld.so for nss/dlopen but has fixed-load semantics).
        sender: AgentName::Dpg1,
        receiver: AgentName::Dpg1Spg,
    },
];

#[derive(Clone, Copy)]
struct ScmScenario {
    name: &'static str,
    kind: ScmKind,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScmKind {
    PassEventfd,
    PassEventfdPollWake,
    PassTcpSocket,
    PassThenCloseSender,
    PassTwoFdsOneMsg,
}

const SCM_SCENARIOS: &[ScmScenario] = &[
    ScmScenario {
        name: "pass_eventfd",
        kind: ScmKind::PassEventfd,
    },
    ScmScenario {
        name: "pass_eventfd_poll_wake",
        kind: ScmKind::PassEventfdPollWake,
    },
    ScmScenario {
        name: "pass_tcp_socket",
        kind: ScmKind::PassTcpSocket,
    },
    ScmScenario {
        name: "pass_then_close_sender",
        kind: ScmKind::PassThenCloseSender,
    },
    ScmScenario {
        name: "pass_two_fds_one_msg",
        kind: ScmKind::PassTwoFdsOneMsg,
    },
];

#[derive(Serialize, Deserialize)]
struct ScmArgs {
    kind: ScmKind,
    socket_path: String,
}

#[derive(Serialize, Deserialize)]
struct ReceiverStartArgs {
    kind: ScmKind,
    socket_path: String,
    result_path: String,
}

#[derive(Serialize, Deserialize)]
struct ReceiverFinishArgs {
    result_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScmOut {
    detail: String,
}

const SCM_RECEIVER: HandlerToken<ScmArgs, ScmOut> = HandlerToken::new("scm_rights.receiver");
const SCM_SENDER: HandlerToken<ScmArgs, ()> = HandlerToken::new("scm_rights.sender");
const SCM_RECEIVER_START: HandlerToken<ReceiverStartArgs, ()> =
    HandlerToken::new("scm_rights.receiver_start");
const SCM_RECEIVER_FINISH: HandlerToken<ReceiverFinishArgs, ScmOut> =
    HandlerToken::new("scm_rights.receiver_finish");
const SCM_SENDER_STAGED: HandlerToken<ScmArgs, ()> = HandlerToken::new("scm_rights.sender_staged");

async fn handle_receiver(args: ScmArgs, ctx: &mut HandlerCtx<'_>) -> Result<ScmOut, HandlerError> {
    let listener = UnixListener::bind(&args.socket_path)?;
    ctx.checkpoint("scm_ready").await?;
    accept_and_validate(args.kind, listener).map_err(HandlerError)
}

async fn handle_sender(args: ScmArgs, ctx: &mut HandlerCtx<'_>) -> Result<(), HandlerError> {
    ctx.checkpoint("scm_ready").await?;
    send_for_scenario(args.kind, &args.socket_path).map_err(HandlerError)
}

async fn handle_receiver_start(
    args: ReceiverStartArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<(), HandlerError> {
    let listener = UnixListener::bind(&args.socket_path)?;
    std::thread::spawn(move || {
        let result = accept_and_validate(args.kind, listener);
        let encoded = serde_json::to_string(&result)
            .unwrap_or_else(|e| format!("{{\"Err\":\"result serialize: {e}\"}}"));
        let _ = std::fs::write(args.result_path, encoded);
    });
    Ok(())
}

async fn handle_sender_staged(
    args: ScmArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<(), HandlerError> {
    send_for_scenario(args.kind, &args.socket_path).map_err(HandlerError)
}

async fn handle_receiver_finish(
    args: ReceiverFinishArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ScmOut, HandlerError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::read_to_string(&args.result_path) {
            Ok(contents) => {
                let _ = std::fs::remove_file(&args.result_path);
                let decoded: Result<ScmOut, String> = serde_json::from_str(&contents)
                    .map_err(|e| HandlerError(format!("result deserialize: {e}: {contents}")))?;
                return decoded.map_err(HandlerError);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(HandlerError(format!("read receiver result: {e}"))),
        }
    }
}

pub(crate) fn register_scm_rights_tests(reg: &mut Registry<'_>) {
    register_handler!(SCM_RECEIVER, handle_receiver);
    register_handler!(SCM_SENDER, handle_sender);
    register_handler!(SCM_RECEIVER_START, handle_receiver_start);
    register_handler!(SCM_RECEIVER_FINISH, handle_receiver_finish);
    register_handler!(SCM_SENDER_STAGED, handle_sender_staged);

    for &pair in SCM_PAIRS {
        for scenario in SCM_SCENARIOS {
            let id = format!("SCM.{}.{}_to_{}", scenario.name, pair.sender, pair.receiver);
            let label = format!("{}->{}", pair.sender, pair.receiver);
            let kind = scenario.kind;
            let scenario_name = scenario.name;
            reg.test("vscode", "scm_rights", id)
                .timeout(60)
                .build(move |cx| {
                    let sender = cx.require(pair.sender);
                    let receiver = cx.require(pair.receiver);
                    Box::new(move |run| {
                        let label = label.clone();
                        Box::pin(async move {
                            let result =
                                run_scenario(run, &sender, &receiver, pair, scenario_name, kind)
                                    .await;
                            match result {
                                Ok(detail) => TestOutcome::new(&label, true, detail),
                                Err(detail) => TestOutcome::new(&label, false, detail),
                            }
                        })
                    })
                });
        }
    }
}

async fn run_scenario(
    run: &mut RunContext<'_>,
    sender: &AgentHandle,
    receiver: &AgentHandle,
    pair: ScmPair,
    scenario: &str,
    kind: ScmKind,
) -> Result<String, String> {
    let socket_path = unique_path(scenario, "sock");
    if same_direct_pipe(pair.sender, pair.receiver) {
        run_staged(run, sender, receiver, kind, socket_path).await
    } else {
        let out = run
            .rendezvous_pair(
                receiver,
                &SCM_RECEIVER,
                ScmArgs {
                    kind,
                    socket_path: socket_path.clone(),
                },
                sender,
                &SCM_SENDER,
                ScmArgs { kind, socket_path },
                "scm_ready",
            )
            .await?;
        Ok(out.detail)
    }
}

async fn run_staged(
    run: &mut RunContext<'_>,
    sender: &AgentHandle,
    receiver: &AgentHandle,
    kind: ScmKind,
    socket_path: String,
) -> Result<String, String> {
    let result_path = unique_path("result", "json");
    run.send_named_typed(
        receiver,
        &SCM_RECEIVER_START,
        ReceiverStartArgs {
            kind,
            socket_path: socket_path.clone(),
            result_path: result_path.clone(),
        },
    )
    .await
    .map_err(|e| format!("receiver_start: {e}"))?;
    run.send_named_typed(sender, &SCM_SENDER_STAGED, ScmArgs { kind, socket_path })
        .await
        .map_err(|e| format!("sender_staged: {e}"))?;
    let out = run
        .send_named_typed(
            receiver,
            &SCM_RECEIVER_FINISH,
            ReceiverFinishArgs { result_path },
        )
        .await
        .map_err(|e| format!("receiver_finish: {e}"))?;
    Ok(out.detail)
}

fn same_direct_pipe(left: AgentName, right: AgentName) -> bool {
    direct_pipe(left) == direct_pipe(right)
}

fn direct_pipe(agent: AgentName) -> AgentName {
    agent.ancestors().first().copied().unwrap_or(agent)
}

fn unique_path(scenario: &str, ext: &str) -> String {
    format!(
        "/run/litebox-scm-{}-{scenario}-{}.{}",
        std::process::id(),
        monotonic_suffix(),
        ext
    )
}

fn monotonic_suffix() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn accept_and_validate(kind: ScmKind, listener: UnixListener) -> Result<ScmOut, String> {
    let stream = listener.accept()?;
    match kind {
        ScmKind::PassEventfd => receive_eventfd(stream, 7, false, "eventfd"),
        ScmKind::PassEventfdPollWake => receive_eventfd_poll_wake(stream),
        ScmKind::PassTcpSocket => receive_tcp(stream),
        ScmKind::PassThenCloseSender => receive_eventfd(stream, 5, true, "close_sender"),
        ScmKind::PassTwoFdsOneMsg => receive_two_eventfds(stream),
    }
}

fn send_for_scenario(kind: ScmKind, socket_path: &str) -> Result<(), String> {
    match kind {
        ScmKind::PassEventfd => {
            let ev = EventFd::open(0, "nonblock|cloexec").map_err(|e| e.to_string())?;
            let stream = UnixStream::connect(socket_path)?;
            stream.send_fd(ev.as_fd(), b"eventfd")?;
            ev.write(7).map_err(|e| e.to_string())?;
            Ok(())
        }
        ScmKind::PassEventfdPollWake => {
            let ev = EventFd::open(0, "nonblock|cloexec").map_err(|e| e.to_string())?;
            let stream = UnixStream::connect(socket_path)?;
            stream.send_fd(ev.as_fd(), b"eventfd_poll_wake")?;
            // Wait for receiver to confirm fast epoll_wait(0) returned no
            // events (READY sentinel = single 'R' byte).
            let mut sentinel = [0u8; 1];
            stream.read_exact(&mut sentinel)?;
            if sentinel[0] != b'R' {
                return Err(format!(
                    "poll_wake: bad READY sentinel {:?}",
                    sentinel[0] as char
                ));
            }
            // Now write to the eventfd; the receiver's epoll_wait(2000ms)
            // should observe IN promptly.
            ev.write(7).map_err(|e| e.to_string())?;
            Ok(())
        }
        ScmKind::PassTcpSocket => send_tcp(socket_path),
        ScmKind::PassThenCloseSender => {
            let ev = EventFd::open(0, "nonblock|cloexec").map_err(|e| e.to_string())?;
            let source_fd = ev.as_raw_fd();
            let stream = UnixStream::connect(socket_path)?;
            stream.send_fd(ev.as_fd(), b"close_sender")?;
            drop(ev);
            if fd_is_open(source_fd) {
                return Err(format!("source eventfd {source_fd} still open after drop"));
            }
            Ok(())
        }
        ScmKind::PassTwoFdsOneMsg => {
            let first = EventFd::open(0, "nonblock|cloexec").map_err(|e| e.to_string())?;
            let second = EventFd::open(0, "nonblock|cloexec").map_err(|e| e.to_string())?;
            let stream = UnixStream::connect(socket_path)?;
            stream.send_fds(&[first.as_fd(), second.as_fd()], b"two_eventfds")?;
            first.write(11).map_err(|e| e.to_string())?;
            second.write(13).map_err(|e| e.to_string())?;
            Ok(())
        }
    }
}

fn receive_eventfd(
    stream: UnixStream,
    expected: u64,
    write_received: bool,
    expected_payload: &str,
) -> Result<ScmOut, String> {
    let (fd, payload) = stream.recv_fd(64)?;
    expect_payload(&payload, expected_payload)?;
    let ev = eventfd_from_received(fd);
    if write_received {
        ev.write(expected).map_err(|e| e.to_string())?;
    }
    let value = ev.read().map_err(|e| e.to_string())?;
    if value != expected {
        return Err(format!("expected eventfd value {expected}, got {value}"));
    }
    Ok(ScmOut {
        detail: format!("received_eventfd_fd={} value={value}", ev.as_raw_fd()),
    })
}

fn receive_eventfd_poll_wake(stream: UnixStream) -> Result<ScmOut, String> {
    let (fd, payload) = stream.recv_fd(64)?;
    expect_payload(&payload, "eventfd_poll_wake")?;
    let ev = eventfd_from_received(fd);
    let mut epoll = crate::os::epoll::Epoll::new().map_err(|e| format!("epoll_create1: {e}"))?;
    epoll
        .add_fd(
            ev.as_raw_fd(),
            "in",
            crate::os::epoll::EpollTarget {
                kind: "eventfd",
                id: ev.as_raw_fd() as u64,
            },
        )
        .map_err(|e| format!("epoll_ctl add eventfd: {e}"))?;
    // Step 4: fast poll (timeout=0) should report no events.
    let pre = epoll
        .wait(0, 4)
        .map_err(|e| format!("pre epoll_wait: {e}"))?;
    if !pre.is_empty() {
        return Err(format!("pre epoll_wait(0) expected no events, got {pre:?}"));
    }
    // Tell sender to write.
    stream.write_all(b"R")?;
    // Step 6: wait up to 2s for the sender's write to wake us.
    let started = std::time::Instant::now();
    let post = epoll
        .wait(2000, 4)
        .map_err(|e| format!("post epoll_wait: {e}"))?;
    let elapsed_ms = started.elapsed().as_millis();
    if post.is_empty() {
        return Err(format!(
            "post epoll_wait(2000) timed out without IN ({elapsed_ms}ms elapsed)"
        ));
    }
    // Drain the eventfd so the post-test state is clean.
    let value = ev.read().map_err(|e| e.to_string())?;
    Ok(ScmOut {
        detail: format!("poll_wake_received={value} events={post:?} wake_ms={elapsed_ms}"),
    })
}

fn receive_two_eventfds(stream: UnixStream) -> Result<ScmOut, String> {
    let (fds, payload) = stream.recv_fds(64, 2)?;
    expect_payload(&payload, "two_eventfds")?;
    if fds.len() != 2 {
        return Err(format!("expected 2 eventfds, got {}", fds.len()));
    }
    let mut iter = fds.into_iter();
    let first = eventfd_from_received(iter.next().expect("len checked"));
    let second = eventfd_from_received(iter.next().expect("len checked"));
    let first_value = first.read().map_err(|e| e.to_string())?;
    let second_value = second.read().map_err(|e| e.to_string())?;
    if first_value != 11 || second_value != 13 {
        return Err(format!(
            "expected eventfd values 11,13 got {first_value},{second_value}"
        ));
    }
    Ok(ScmOut {
        detail: format!(
            "received_eventfds=[{},{}] values=11,13",
            first.as_raw_fd(),
            second.as_raw_fd()
        ),
    })
}

fn send_tcp(socket_path: &str) -> Result<(), String> {
    let listener = tcp_listener()?;
    let port = listener_port(listener.as_raw_fd())?;
    std::thread::spawn(move || {
        let _ = tcp_echo_once(listener);
    });
    let conn = tcp_connect(port)?;
    let stream = UnixStream::connect(socket_path)?;
    stream.send_fd(conn.as_fd(), b"tcp")?;
    Ok(())
}

fn receive_tcp(stream: UnixStream) -> Result<ScmOut, String> {
    let (fd, payload) = stream.recv_fd(64)?;
    expect_payload(&payload, "tcp")?;
    let raw = fd.as_raw_fd();
    let payload = b"SCM_TCP_PAYLOAD";
    write_all(raw, payload)?;
    let echoed = read_exact(raw, payload.len())?;
    if echoed != payload {
        return Err(format!(
            "tcp echo mismatch: {:?}",
            String::from_utf8_lossy(&echoed)
        ));
    }
    Ok(ScmOut {
        detail: format!("received_tcp_fd={raw} echo=ok"),
    })
}

fn tcp_listener() -> Result<OwnedFd, String> {
    // SAFETY: socket creates a fresh fd on success.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(format!("tcp socket: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: raw was just returned by socket and is uniquely owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let one: libc::c_int = 1;
    // SAFETY: setsockopt reads `one` and does not take ownership of fd.
    let _ = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            std::ptr::addr_of!(one).cast(),
            std::mem::size_of_val(&one) as libc::socklen_t,
        )
    };
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: libc::INADDR_LOOPBACK.to_be(),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: addr points to a valid IPv4 sockaddr and fd is a live TCP socket.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!("tcp bind: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: fd is a live bound TCP socket.
    if unsafe { libc::listen(fd.as_raw_fd(), 1) } != 0 {
        return Err(format!("tcp listen: {}", std::io::Error::last_os_error()));
    }
    Ok(fd)
}

fn listener_port(fd: i32) -> Result<u16, String> {
    // SAFETY: zeroed sockaddr_in is an output buffer for getsockname.
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: addr/len are writable and fd is a live socket.
    if unsafe {
        libc::getsockname(
            fd,
            std::ptr::addr_of_mut!(addr).cast::<libc::sockaddr>(),
            &mut len,
        )
    } != 0
    {
        return Err(format!("getsockname: {}", std::io::Error::last_os_error()));
    }
    Ok(u16::from_be(addr.sin_port))
}

fn tcp_connect(port: u16) -> Result<OwnedFd, String> {
    // SAFETY: socket creates a fresh fd on success.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(format!("tcp socket: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: raw was just returned by socket and is uniquely owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: libc::INADDR_LOOPBACK.to_be(),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: addr points to a valid IPv4 sockaddr and fd is a live TCP socket.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!("tcp connect: {}", std::io::Error::last_os_error()));
    }
    Ok(fd)
}

fn tcp_echo_once(listener: OwnedFd) -> Result<(), String> {
    let accepted = loop {
        // SAFETY: accept4 operates on the live listener fd and returns a fresh fd on success.
        let raw = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if raw >= 0 {
            // SAFETY: raw was just returned by accept4 and is uniquely owned here.
            break unsafe { OwnedFd::from_raw_fd(raw) };
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(format!("tcp accept: {err}"));
        }
    };
    let mut buf = [0u8; 4096];
    loop {
        let n = read_some(accepted.as_raw_fd(), &mut buf)?;
        if n == 0 {
            return Ok(());
        }
        write_all(accepted.as_raw_fd(), &buf[..n])?;
    }
}

fn read_some(fd: i32, buf: &mut [u8]) -> Result<usize, String> {
    loop {
        // SAFETY: buf is writable and fd is a live descriptor.
        let rc = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if rc >= 0 {
            return Ok(rc as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(format!("read fd {fd}: {err}"));
        }
    }
}

fn read_exact(fd: i32, len: usize) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; len];
    let mut offset = 0;
    while offset < len {
        let n = read_some(fd, &mut out[offset..])?;
        if n == 0 {
            return Err(format!("read fd {fd}: EOF after {offset}/{len} bytes"));
        }
        offset += n;
    }
    Ok(out)
}

fn write_all(fd: i32, mut data: &[u8]) -> Result<(), String> {
    while !data.is_empty() {
        // SAFETY: data is readable and fd is a live descriptor.
        let rc = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if rc > 0 {
            data = &data[rc as usize..];
            continue;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(format!("write fd {fd}: {err}"));
        }
    }
    Ok(())
}

fn fd_is_open(fd: i32) -> bool {
    // SAFETY: F_GETFD inspects descriptor state and does not take ownership.
    (unsafe { libc::fcntl(fd, libc::F_GETFD) }) >= 0
}

fn expect_payload(actual: &[u8], expected: &str) -> Result<(), String> {
    if actual == expected.as_bytes() {
        Ok(())
    } else {
        Err(format!(
            "payload mismatch: expected {expected:?}, got {:?}",
            String::from_utf8_lossy(actual)
        ))
    }
}

fn eventfd_from_received(fd: OwnedFd) -> EventFd {
    EventFd::from_owned_fd(fd, 0)
}
