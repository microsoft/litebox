// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Epoll + pidfd/eventfd/socket readiness tests for VS Code server blockers.
//!
//! Hosts three test families:
//! - `EPI.*` — epoll + pidfd/eventfd/socket scenarios (multi-agent, typed-handler protocol)
//! - `EP.*`  — raw epoll + TCP socket wakeup (direct and tokio variants, forked leaf agents)
//! - `POLL.*` — epoll/ppoll IN-event readiness over a pipe

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::epoll::{Epoll, EpollTarget};
use crate::os::eventfd::EventFd;
use crate::os::socket::TcpSocket;
use crate::protocol::EpollEvent;
use crate::register_handler;

use super::TestOutcome;
use super::agents::{AgentName, SpawnKind};
use super::registry::Registry;
use super::run_context::RunContext;

pub(crate) const EPI_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,
    AgentName::Dpg1Dpg1,
    AgentName::Dpg2,
    AgentName::Dpg2Dpg,
];

#[derive(Copy, Clone)]
enum ScenarioKind {
    PidfdExit,
    MultiSocket,
    EventfdWakeup,
    TimeoutZero,
    EdgeTrigger,
}

struct ScenarioDef {
    name: &'static str,
    kind: ScenarioKind,
    in_process_only: bool,
}

const EPI_SCENARIOS: &[ScenarioDef] = &[
    ScenarioDef {
        name: "pidfd_exit",
        kind: ScenarioKind::PidfdExit,
        in_process_only: false,
    },
    ScenarioDef {
        name: "multi_socket",
        kind: ScenarioKind::MultiSocket,
        in_process_only: false,
    },
    ScenarioDef {
        name: "eventfd_wakeup",
        kind: ScenarioKind::EventfdWakeup,
        in_process_only: false,
    },
    // These two scenarios intentionally exercise only one epoll set in one
    // process. Additional agent axes would duplicate the same kernel state.
    ScenarioDef {
        name: "timeout_zero",
        kind: ScenarioKind::TimeoutZero,
        in_process_only: true,
    },
    ScenarioDef {
        name: "edge_trigger",
        kind: ScenarioKind::EdgeTrigger,
        in_process_only: true,
    },
];

#[derive(Serialize, Deserialize)]
struct PidfdExitArgs {
    target: String,
    peer_addr: String,
}

#[derive(Serialize, Deserialize)]
struct PeerAddrArgs {
    peer_addr: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct DetailOut {
    detail: String,
}

#[derive(Serialize, Deserialize)]
struct SetupTcpListenArgs {
    port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
struct SetupTcpListenOut {
    port: u16,
}

const PIDFD_EXIT: HandlerToken<PidfdExitArgs, DetailOut> =
    HandlerToken::new("epoll_pidfd.pidfd_exit");
const MULTI_SOCKET: HandlerToken<PeerAddrArgs, DetailOut> =
    HandlerToken::new("epoll_pidfd.multi_socket");
const EVENTFD_WAKEUP: HandlerToken<(), DetailOut> = HandlerToken::new("epoll_pidfd.eventfd_wakeup");
const TIMEOUT_ZERO: HandlerToken<(), DetailOut> = HandlerToken::new("epoll_pidfd.timeout_zero");
const EDGE_TRIGGER: HandlerToken<PeerAddrArgs, DetailOut> =
    HandlerToken::new("epoll_pidfd.edge_trigger");
const SETUP_TCP_LISTEN: HandlerToken<SetupTcpListenArgs, SetupTcpListenOut> =
    HandlerToken::new("epoll_pidfd.setup_tcp_listen");
const EPOLL_SPIN_EVENTFD_IDLE: HandlerToken<(), EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.epoll_spin_eventfd_idle");
const EPOLL_SPIN_TIMERFD: HandlerToken<(), EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.epoll_spin_timerfd");
const EPOLL_SPIN_TIMERFD_INHERITED_FORK: HandlerToken<(), EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.epoll_spin_timerfd_inherited_fork");
const EPOLL_SPIN_BROKER_UDP_WRITABLE: HandlerToken<(), EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.epoll_spin_broker_udp_writable");
const EPOLL_SPIN_BROKER_TCP_STICKY_OUT: HandlerToken<PeerAddrArgs, EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.epoll_spin_broker_tcp_sticky_out");
const EPOLL_SPIN_BROKER_TCP_STICKY_IN: HandlerToken<PeerAddrArgs, EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.epoll_spin_broker_tcp_sticky_in");
const EPOLL_SPIN_BROKER_TCP_HALF_CLOSED: HandlerToken<PeerAddrArgs, EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.epoll_spin_broker_tcp_half_closed");
const EPOLL_REFIRE_BROKER_TCP_DRAIN_IN_ET: HandlerToken<PeerAddrArgs, EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.epoll_refire_broker_tcp_drain_in_et");
// EP.span.* — full-span EPOLLET / level-triggered / EPOLLONESHOT readiness
// matrix across always-ready broker fd kinds (eventfd, pipe, socketpair) for
// both IN and OUT readiness, plus the correctness guards (ET re-fires after a
// real transition; LT keeps reporting; ONESHOT fires once).
const EPOLL_SPAN_EVENTFD_OUT_ET: HandlerToken<(), EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.span_eventfd_out_et");
const EPOLL_SPAN_EVENTFD_IN_ET: HandlerToken<(), EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.span_eventfd_in_et");
const EPOLL_SPAN_PIPE_OUT_ET: HandlerToken<(), EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.span_pipe_out_et");
const EPOLL_SPAN_PIPE_IN_ET: HandlerToken<(), EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.span_pipe_in_et");
const EPOLL_SPAN_SOCKETPAIR_OUT_ET: HandlerToken<(), EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.span_socketpair_out_et");
const EPOLL_SPAN_SOCKETPAIR_IN_ET: HandlerToken<(), EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.span_socketpair_in_et");
const EPOLL_SPAN_EVENTFD_IN_REFIRE: HandlerToken<(), EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.span_eventfd_in_refire");
const EPOLL_SPAN_EVENTFD_OUT_LT: HandlerToken<(), EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.span_eventfd_out_lt");
const EPOLL_SPAN_EVENTFD_IN_ONESHOT: HandlerToken<(), EpollSpinOut> =
    HandlerToken::new("epoll_pidfd.span_eventfd_in_oneshot");

#[derive(Serialize, Deserialize, Debug)]
struct EpollSpinOut {
    detail: String,
    first_elapsed_ms: u64,
    first_events: i32,
    iterations: u64,
    loop_elapsed_ms: u64,
    timer_ready: u64,
    zero_event_returns: u64,
}

async fn handle_pidfd_exit(
    args: PidfdExitArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let mut epoll = Epoll::new()?;
    let mut child = std::process::Command::new(&args.target)
        .arg("wait-forever")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = child.id();
    epoll.add_pidfd(pid, "in")?;

    let mut stream = connect_peer(&args.peer_addr)?;
    epoll.add_fd(
        stream.as_raw_fd(),
        "in|oneshot",
        EpollTarget {
            kind: "socket",
            id: 1,
        },
    )?;
    stream.write_all(b"pidfd-socket-wakeup")?;
    wait_readable(&stream, Duration::from_secs(2))?;
    child.kill()?;

    let mut events = epoll.wait(5000, 4)?;
    let mut saw_pid = events
        .iter()
        .any(|event| event.kind == "pidfd" && event.id == u64::from(pid) && has_in(event));
    let mut saw_socket = events
        .iter()
        .any(|event| event.kind == "socket" && event.id == 1 && has_in(event));
    for _ in 0..5 {
        if saw_pid && saw_socket {
            break;
        }
        let more = epoll.wait(2000, 4)?;
        if more.is_empty() {
            break;
        }
        saw_pid |= more
            .iter()
            .any(|event| event.kind == "pidfd" && event.id == u64::from(pid) && has_in(event));
        saw_socket |= more
            .iter()
            .any(|event| event.kind == "socket" && event.id == 1 && has_in(event));
        events.extend(more);
    }
    let _ = child.wait();
    if saw_pid && saw_socket {
        Ok(DetailOut {
            detail: format!("pidfd pid={pid} and socket conn=1 events={events:?}"),
        })
    } else {
        Err(HandlerError(format!(
            "missing pidfd/socket readiness pid={pid} conn=1 events={events:?}"
        )))
    }
}

async fn handle_multi_socket(
    args: PeerAddrArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let mut epoll = Epoll::new()?;
    let mut streams = Vec::new();
    let mut conns = Vec::new();
    for i in 0..4_u64 {
        let mut stream = connect_peer(&args.peer_addr)?;
        let conn = i + 1;
        epoll.add_fd(
            stream.as_raw_fd(),
            "in",
            EpollTarget {
                kind: "socket",
                id: conn,
            },
        )?;
        stream.write_all(format!("multi-socket-{i}").as_bytes())?;
        wait_readable(&stream, Duration::from_secs(2))?;
        streams.push(stream);
        conns.push(conn);
    }
    let mut events = epoll.wait(5000, 8)?;
    let expected = conns;
    let mut ready = ready_socket_ids(&events);
    for _ in 0..5 {
        if ready == expected {
            break;
        }
        let more = epoll.wait(2000, 8)?;
        if more.is_empty() {
            break;
        }
        events.extend(more);
        ready = ready_socket_ids(&events);
    }
    drop(streams);
    if ready == expected {
        Ok(DetailOut {
            detail: format!("all sockets ready conns={expected:?} events={events:?}"),
        })
    } else {
        Err(HandlerError(format!(
            "socket readiness mismatch expected={expected:?} ready={ready:?} events={events:?}"
        )))
    }
}

async fn handle_eventfd_wakeup(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let mut epoll = Epoll::new()?;
    let eventfd = EventFd::open(0, "nonblock")?;
    epoll.add_fd(
        eventfd.as_raw_fd(),
        "in",
        EpollTarget {
            kind: "eventfd",
            id: 1,
        },
    )?;
    eventfd.write(1)?;
    let events = epoll.wait(5000, 4)?;
    if events
        .iter()
        .any(|event| event.kind == "eventfd" && event.id == 1 && has_in(event))
    {
        Ok(DetailOut {
            detail: format!("eventfd ready id=1 events={events:?}"),
        })
    } else {
        Err(HandlerError(format!(
            "missing eventfd readiness id=1 events={events:?}"
        )))
    }
}

async fn handle_timeout_zero(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let epoll = Epoll::new()?;
    let events = epoll.wait(0, 4)?;
    if events.is_empty() {
        Ok(DetailOut {
            detail: "idle epoll returned no events".to_string(),
        })
    } else {
        Err(HandlerError(format!(
            "idle epoll returned unexpected events {events:?}"
        )))
    }
}

async fn handle_edge_trigger(
    args: PeerAddrArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let mut epoll = Epoll::new()?;
    let mut stream = connect_peer(&args.peer_addr)?;
    epoll.add_fd(
        stream.as_raw_fd(),
        "in|et",
        EpollTarget {
            kind: "socket",
            id: 1,
        },
    )?;
    for payload in ["edge-one", "edge-two"] {
        stream.write_all(payload.as_bytes())?;
    }
    let first = epoll.wait(5000, 8)?;
    let first_count = first
        .iter()
        .filter(|event| event.kind == "socket" && event.id == 1 && has_in(event))
        .count();
    let second = epoll.wait(0, 8)?;
    let second_count = second
        .iter()
        .filter(|event| event.kind == "socket" && event.id == 1 && has_in(event))
        .count();
    if first_count == 1 && second_count == 0 {
        Ok(DetailOut {
            detail: format!("edge-trigger coalesced first={first:?} second={second:?}"),
        })
    } else {
        Err(HandlerError(format!(
            "edge-trigger mismatch first_count={first_count} second_count={second_count} first={first:?} second={second:?}"
        )))
    }
}

async fn handle_setup_tcp_listen(
    args: SetupTcpListenArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<SetupTcpListenOut, HandlerError> {
    let listener = TcpSocket::new_tcp_listen(args.port)?;
    let port = listener.local_port()?;
    let std_listener = listener.into_std_listener();
    std_listener.set_nonblocking(true)?;
    let task = spawn_tcp_echo_task(std_listener)?;

    // Process-scope state: these setup listeners intentionally outlive the
    // handler so the peer address remains connectable for the following test.
    setup_listeners().lock().unwrap().push(task);
    Ok(SetupTcpListenOut { port })
}

async fn handle_epoll_spin_eventfd_idle(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    let epfd = epoll_create()?;
    let eventfd = EventFd::open(0, "cloexec")?;
    epoll_add(
        epfd.as_raw_fd(),
        eventfd.as_raw_fd(),
        libc::EPOLLIN as u32,
        1,
    )?;

    let first = timed_epoll_pwait(epfd.as_raw_fd(), 1000, 4)?;
    let loop_start = Instant::now();
    let loop_deadline = loop_start + Duration::from_secs(5);
    let mut iterations = 0_u64;
    let mut zero_event_returns = u64::from(first.events == 0);
    while Instant::now() < loop_deadline {
        let sample = timed_epoll_pwait(epfd.as_raw_fd(), 1000, 4)?;
        iterations += 1;
        zero_event_returns += u64::from(sample.events == 0);
    }
    let loop_elapsed_ms = elapsed_ms(loop_start.elapsed());
    Ok(EpollSpinOut {
        detail: format!(
            "step=1 eventfd_idle first_events={} first_elapsed_ms={} iterations={} loop_elapsed_ms={} zero_event_returns={}",
            first.events,
            elapsed_ms(first.elapsed),
            iterations,
            loop_elapsed_ms,
            zero_event_returns
        ),
        first_elapsed_ms: elapsed_ms(first.elapsed),
        first_events: first.events,
        iterations,
        loop_elapsed_ms,
        timer_ready: 0,
        zero_event_returns,
    })
}

async fn handle_epoll_spin_broker_udp_writable(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    // A broker-held InetDgram (UDP) socket is *always* writable: under
    // litebox its broker readiness (`current_events`) always includes
    // NOTIFY_EVENT_OUT. Register it EPOLLOUT|EPOLLET — the writable edge
    // must fire exactly once, then `epoll_pwait` must BLOCK (no new edge),
    // which is what the native kernel does. If litebox's worker-local
    // epoll does not honor EPOLLET for a broker fd's persistent
    // writability, EPOLLOUT re-fires on every wait and the loop spins —
    // the VS Code agent-host signature (epoll_pwait + clock_gettime hot
    // loop). This is the axis the eventfd/timerfd spin probes do not
    // cover: a broker *socket* whose readiness lives in the broker.
    let sock = std::net::UdpSocket::bind(("127.0.0.1", 0))
        .map_err(|e| HandlerError(format!("udp bind: {e}")))?;
    sock.set_nonblocking(true)
        .map_err(|e| HandlerError(format!("set_nonblocking: {e}")))?;
    let epfd = epoll_create()?;
    epoll_add(
        epfd.as_raw_fd(),
        sock.as_raw_fd(),
        (libc::EPOLLOUT | libc::EPOLLET) as u32,
        3,
    )?;

    // First wait consumes the initial writable edge.
    let first = timed_epoll_pwait(epfd.as_raw_fd(), 1000, 4)?;
    let loop_start = Instant::now();
    let loop_deadline = loop_start + Duration::from_secs(5);
    let mut iterations = 0_u64;
    let mut zero_event_returns = u64::from(first.events == 0);
    // Never write to the socket: no new writable edge should occur, so an
    // EPOLLET registration must block until each timeout.
    while Instant::now() < loop_deadline {
        let sample = timed_epoll_pwait(epfd.as_raw_fd(), 1000, 4)?;
        iterations += 1;
        zero_event_returns += u64::from(sample.events == 0);
    }
    let loop_elapsed_ms = elapsed_ms(loop_start.elapsed());
    Ok(EpollSpinOut {
        detail: format!(
            "step=broker_udp_writable_et first_events={} first_elapsed_ms={} iterations={} loop_elapsed_ms={} zero_event_returns={}",
            first.events,
            elapsed_ms(first.elapsed),
            iterations,
            loop_elapsed_ms,
            zero_event_returns
        ),
        first_elapsed_ms: elapsed_ms(first.elapsed),
        first_events: first.events,
        iterations,
        loop_elapsed_ms,
        timer_ready: 0,
        zero_event_returns,
    })
}

async fn handle_epoll_spin_broker_tcp_sticky_out(
    args: PeerAddrArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    let mut stream = connect_peer(&args.peer_addr)
        .map_err(|e| HandlerError(format!("tcp connect {}: {e}", args.peer_addr)))?;
    stream
        .set_nonblocking(true)
        .map_err(|e| HandlerError(format!("tcp set_nonblocking: {e}")))?;

    let epfd = epoll_create()?;
    epoll_add(
        epfd.as_raw_fd(),
        stream.as_raw_fd(),
        (libc::EPOLLOUT | libc::EPOLLET) as u32,
        4,
    )?;

    let first = timed_epoll_pwait(epfd.as_raw_fd(), 1000, 4)?;
    let loop_start = Instant::now();
    let loop_deadline = loop_start + Duration::from_secs(3);
    let mut iterations = 0_u64;
    let mut zero_event_returns = u64::from(first.events == 0);
    let mut write_seq = 0_u64;
    while Instant::now() < loop_deadline {
        write_seq += 1;
        let payload = [(write_seq & 0xff) as u8];
        match stream.write(&payload) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(HandlerError(format!("tcp write: {e}"))),
        }
        let sample = timed_epoll_pwait(epfd.as_raw_fd(), 100, 4)?;
        iterations += 1;
        zero_event_returns += u64::from(sample.events == 0);
    }
    let loop_elapsed_ms = elapsed_ms(loop_start.elapsed());
    Ok(EpollSpinOut {
        detail: format!(
            "step=broker_tcp_sticky_out_et first_events={} first_elapsed_ms={} iterations={} loop_elapsed_ms={} zero_event_returns={}",
            first.events,
            elapsed_ms(first.elapsed),
            iterations,
            loop_elapsed_ms,
            zero_event_returns
        ),
        first_elapsed_ms: elapsed_ms(first.elapsed),
        first_events: first.events,
        iterations,
        loop_elapsed_ms,
        timer_ready: 0,
        zero_event_returns,
    })
}

async fn handle_epoll_spin_timerfd(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    let epfd = epoll_create()?;
    let timerfd = timerfd_create()?;
    epoll_add(
        epfd.as_raw_fd(),
        timerfd.as_raw_fd(),
        libc::EPOLLIN as u32,
        2,
    )?;
    run_epoll_spin_timerfd_probe(epfd.as_raw_fd(), timerfd.as_raw_fd(), "step=2 timerfd")
}

async fn handle_epoll_spin_timerfd_inherited_fork(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    let epfd = epoll_create()?;
    let timerfd = timerfd_create()?;
    epoll_add(
        epfd.as_raw_fd(),
        timerfd.as_raw_fd(),
        libc::EPOLLIN as u32,
        2,
    )?;
    run_timerfd_probe_in_forked_child(epfd.as_raw_fd(), timerfd.as_raw_fd())
}

fn run_epoll_spin_timerfd_probe(
    epfd: i32,
    timerfd: i32,
    detail_prefix: &str,
) -> Result<EpollSpinOut, HandlerError> {
    arm_timerfd(timerfd, Duration::from_secs(1))?;
    let first = timed_epoll_pwait(epfd, 2000, 4)?;
    let mut timer_ready = u64::from(first.timer_ready);
    if first.timer_ready {
        drain_timerfd(timerfd)?;
    }

    let loop_start = Instant::now();
    let loop_deadline = loop_start + Duration::from_secs(5);
    let mut iterations = 0_u64;
    let mut zero_event_returns = u64::from(first.events == 0);
    while Instant::now() < loop_deadline {
        arm_timerfd(timerfd, Duration::from_secs(1))?;
        let sample = timed_epoll_pwait(epfd, 2000, 4)?;
        iterations += 1;
        zero_event_returns += u64::from(sample.events == 0);
        if sample.timer_ready {
            timer_ready += 1;
            drain_timerfd(timerfd)?;
        }
    }
    let loop_elapsed_ms = elapsed_ms(loop_start.elapsed());
    Ok(EpollSpinOut {
        detail: format!(
            "{detail_prefix} first_events={} first_elapsed_ms={} iterations={} loop_elapsed_ms={} timer_ready={} zero_event_returns={}",
            first.events,
            elapsed_ms(first.elapsed),
            iterations,
            loop_elapsed_ms,
            timer_ready,
            zero_event_returns
        ),
        first_elapsed_ms: elapsed_ms(first.elapsed),
        first_events: first.events,
        iterations,
        loop_elapsed_ms,
        timer_ready,
        zero_event_returns,
    })
}

static SETUP_LISTENERS: OnceLock<Mutex<Vec<tokio::task::JoinHandle<()>>>> = OnceLock::new();

fn setup_listeners() -> &'static Mutex<Vec<tokio::task::JoinHandle<()>>> {
    SETUP_LISTENERS.get_or_init(|| Mutex::new(Vec::new()))
}

fn spawn_tcp_echo_task(
    std_listener: std::net::TcpListener,
) -> Result<tokio::task::JoinHandle<()>, HandlerError> {
    let listener = tokio::net::TcpListener::from_std(std_listener)
        .map_err(|e| HandlerError(format!("from_std: {e}")))?;
    Ok(tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0_u8; 4096];
                loop {
                    match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tokio::io::AsyncWriteExt::write_all(&mut stream, &buf[..n])
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
            });
        }
    }))
}

// ---------------------------------------------------------------------------
// EP.span.* — full-span epoll readiness semantics matrix.
//
// The EPOLLET-persistent probes are spin guards: a persistently-ready fd must
// fire its edge once then block, not re-fire on every wait. The refire / LT /
// oneshot probes are correctness guards so a general edge-dedup fix can't pass
// by simply over-suppressing.
// ---------------------------------------------------------------------------

fn write_eventfd_counter(fd: i32, val: u64) -> Result<(), HandlerError> {
    let buf = val.to_ne_bytes();
    // SAFETY: fd is a live eventfd; buf is 8 valid bytes.
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n == buf.len() as isize {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "eventfd write: {}",
            std::io::Error::last_os_error()
        )))
    }
}

fn drain_eventfd_counter(fd: i32) -> Result<(), HandlerError> {
    let mut buf = [0u8; 8];
    // SAFETY: fd is a live eventfd; buf is 8 valid writable bytes.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n == buf.len() as isize {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "eventfd read: {}",
            std::io::Error::last_os_error()
        )))
    }
}

fn make_pipe_cloexec() -> Result<(OwnedFd, OwnedFd), HandlerError> {
    let mut fds = [0i32; 2];
    // SAFETY: pipe2 writes two fresh fds into `fds` on success.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(HandlerError(format!(
            "pipe2: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: both are freshly returned owned descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn make_stream_socketpair() -> Result<(OwnedFd, OwnedFd), HandlerError> {
    let mut sv = [0i32; 2];
    // SAFETY: socketpair writes two fresh fds into `sv` on success.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(HandlerError(format!(
            "socketpair: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: both are freshly returned owned descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) })
}

/// One 1000ms wait to consume the initial edge, then a 5s loop of 1000ms waits
/// with no further state change. A correct EPOLLET (or disabled ONESHOT) epoll
/// does <=~5 iterations (each blocks to timeout); a spin does thousands.
fn persistent_et_spin_out(label: &str, epfd: i32) -> Result<EpollSpinOut, HandlerError> {
    let first = timed_epoll_pwait(epfd, 1000, 4)?;
    let loop_start = Instant::now();
    let loop_deadline = loop_start + Duration::from_secs(5);
    let mut iterations = 0_u64;
    let mut zero_event_returns = u64::from(first.events == 0);
    while Instant::now() < loop_deadline {
        let sample = timed_epoll_pwait(epfd, 1000, 4)?;
        iterations += 1;
        zero_event_returns += u64::from(sample.events == 0);
    }
    let loop_elapsed_ms = elapsed_ms(loop_start.elapsed());
    Ok(EpollSpinOut {
        detail: format!(
            "step={label} first_events={} first_elapsed_ms={} iterations={} loop_elapsed_ms={} zero_event_returns={}",
            first.events,
            elapsed_ms(first.elapsed),
            iterations,
            loop_elapsed_ms,
            zero_event_returns
        ),
        first_elapsed_ms: elapsed_ms(first.elapsed),
        first_events: first.events,
        iterations,
        loop_elapsed_ms,
        timer_ready: 0,
        zero_event_returns,
    })
}

async fn handle_epoll_spin_broker_tcp_sticky_in(
    args: PeerAddrArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    let mut stream = connect_peer(&args.peer_addr)
        .map_err(|e| HandlerError(format!("tcp connect {}: {e}", args.peer_addr)))?;
    // Write a few bytes; the echo peer sends them back so our conn becomes
    // persistently readable (sticky IN) without us ever draining it.
    stream
        .write_all(b"spin-probe")
        .map_err(|e| HandlerError(format!("tcp write: {e}")))?;
    wait_readable(&stream, Duration::from_secs(2))
        .map_err(|e| HandlerError(format!("await echo: {e}")))?;
    stream
        .set_nonblocking(true)
        .map_err(|e| HandlerError(format!("set_nonblocking: {e}")))?;
    let epfd = epoll_create()?;
    epoll_add(
        epfd.as_raw_fd(),
        stream.as_raw_fd(),
        (libc::EPOLLIN | libc::EPOLLET).cast_unsigned(),
        7,
    )?;
    // Never read the echoed data: the sticky IN must fire once then block. A
    // litebox that re-delivers IN on every broker notification spins — the VS
    // Code agent-host's unread-HTTPS-response (update.code.visualstudio.com)
    // signature that the OUT-only dedup missed.
    persistent_et_spin_out("broker_tcp_sticky_in_et", epfd.as_raw_fd())
}

async fn handle_epoll_spin_broker_tcp_half_closed(
    args: PeerAddrArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    let mut stream = connect_peer(&args.peer_addr)
        .map_err(|e| HandlerError(format!("tcp connect {}: {e}", args.peer_addr)))?;
    stream
        .write_all(b"spin-probe")
        .map_err(|e| HandlerError(format!("tcp write: {e}")))?;
    wait_readable(&stream, Duration::from_secs(2))
        .map_err(|e| HandlerError(format!("await echo: {e}")))?;
    // Half-close our write side: the echo peer reads EOF and closes, so our
    // conn gains a sticky RDHUP on top of the sticky IN — the exact half-closed
    // agent-host connection signature (IN|RDHUP under EPOLLET).
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| HandlerError(format!("shutdown write: {e}")))?;
    std::thread::sleep(Duration::from_millis(150));
    stream
        .set_nonblocking(true)
        .map_err(|e| HandlerError(format!("set_nonblocking: {e}")))?;
    let epfd = epoll_create()?;
    epoll_add(
        epfd.as_raw_fd(),
        stream.as_raw_fd(),
        (libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLET) as u32,
        7,
    )?;
    persistent_et_spin_out("broker_tcp_half_closed_et", epfd.as_raw_fd())
}

async fn handle_epoll_refire_broker_tcp_drain_in_et(
    args: PeerAddrArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    const CYCLES: usize = 4;

    let mut stream = connect_peer(&args.peer_addr)
        .map_err(|e| HandlerError(format!("tcp connect {}: {e}", args.peer_addr)))?;
    stream
        .set_nonblocking(true)
        .map_err(|e| HandlerError(format!("set_nonblocking: {e}")))?;
    let epfd = epoll_create()?;
    epoll_add(
        epfd.as_raw_fd(),
        stream.as_raw_fd(),
        (libc::EPOLLIN | libc::EPOLLET).cast_unsigned(),
        7,
    )?;

    let mut first_events = 0;
    let mut first_elapsed_ms = 0;
    let mut refires = 0_u64;
    let mut drained_bytes = 0_usize;
    let mut samples = Vec::with_capacity(CYCLES);

    for cycle in 0..CYCLES {
        let payload = format!("broker-tcp-drain-refire-cycle-{cycle}");
        write_all_nonblocking(&mut stream, payload.as_bytes(), Duration::from_secs(5))
            .map_err(|e| HandlerError(format!("cycle {cycle} tcp write: {e}")))?;
        // Generous per-cycle deadline: a correct re-fire returns immediately, so
        // a real under-fire still hangs the full timeout; the slack only absorbs
        // deep non-PIE-chain (dng) scheduling latency under heavy load so the
        // guard doesn't flake on the dashboard.
        let sample = timed_epoll_pwait(epfd.as_raw_fd(), 5000, 4)?;
        if cycle == 0 {
            first_events = sample.events;
            first_elapsed_ms = elapsed_ms(sample.elapsed);
        }
        samples.push(sample.events);
        if sample.events <= 0 {
            return Ok(EpollSpinOut {
                detail: format!(
                    "step=broker_tcp_drain_in_refire_et cycle={cycle} timed out samples={samples:?} drained_bytes={drained_bytes}"
                ),
                first_elapsed_ms,
                first_events,
                iterations: cycle as u64,
                loop_elapsed_ms: 0,
                timer_ready: refires,
                zero_event_returns: 1,
            });
        }
        refires += 1;
        drained_bytes += drain_tcp_stream_to_eagain(&mut stream)
            .map_err(|e| HandlerError(format!("cycle {cycle} drain: {e}")))?;
    }

    Ok(EpollSpinOut {
        detail: format!(
            "step=broker_tcp_drain_in_refire_et cycles={CYCLES} samples={samples:?} drained_bytes={drained_bytes}"
        ),
        first_elapsed_ms,
        first_events,
        iterations: CYCLES as u64,
        loop_elapsed_ms: 0,
        timer_ready: refires,
        zero_event_returns: 0,
    })
}

fn write_all_nonblocking(
    stream: &mut std::net::TcpStream,
    mut buf: &[u8],
    timeout: Duration,
) -> Result<(), std::io::Error> {
    let deadline = Instant::now() + timeout;
    while !buf.is_empty() {
        match stream.write(buf) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "tcp write returned zero",
                ));
            }
            Ok(n) => buf = &buf[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "timed out writing to tcp stream",
                    ));
                }
                std::thread::yield_now();
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn drain_tcp_stream_to_eagain(stream: &mut std::net::TcpStream) -> Result<usize, std::io::Error> {
    let mut total = 0_usize;
    let mut buf = [0_u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "tcp stream closed while draining",
                ));
            }
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if total == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "epoll reported readable but drain saw no bytes",
                    ));
                }
                return Ok(total);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

async fn drive_broker_tcp_in_probe(
    run: &mut RunContext<'_>,
    observer: &super::agents::AgentHandle,
    peer: &super::agents::AgentHandle,
    token: &'static HandlerToken<PeerAddrArgs, EpollSpinOut>,
) -> Result<String, String> {
    let peer_addr = open_peer_addr(run, peer).await?;
    let out = run
        .send_named_typed(observer, token, PeerAddrArgs { peer_addr })
        .await
        .map_err(|e| format!("send_named: {e}"))?;
    check_span_et_no_spin(&out)
}

fn register_broker_tcp_in_test(
    reg: &mut Registry<'_>,
    agent: AgentName,
    name: &str,
    token: &'static HandlerToken<PeerAddrArgs, EpollSpinOut>,
) {
    let label = agent.to_string();
    reg.test("vscode", "epoll_pidfd", format!("EP.spin.{name}.{agent}"))
        .timeout(60)
        .build(move |cx| {
            let observer = cx.require(agent);
            let peer_agent = peer_for(agent);
            let peer = if peer_agent == agent {
                observer.clone()
            } else {
                cx.require(peer_agent)
            };
            let label = label.clone();
            Box::new(move |run| {
                Box::pin(async move {
                    let result = drive_broker_tcp_in_probe(run, &observer, &peer, token).await;
                    match result {
                        Ok(detail) => TestOutcome::new(&label, true, detail),
                        Err(detail) => TestOutcome::new(&label, false, detail),
                    }
                })
            })
        });
}

async fn handle_span_eventfd_out_et(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    let efd = EventFd::open(0, "cloexec")?;
    let epfd = epoll_create()?;
    epoll_add(
        epfd.as_raw_fd(),
        efd.as_raw_fd(),
        (libc::EPOLLOUT | libc::EPOLLET) as u32,
        1,
    )?;
    persistent_et_spin_out("eventfd_out_et", epfd.as_raw_fd())
}

async fn handle_span_eventfd_in_et(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    // counter=1 → readable now, never drained: the tokio wakeup-eventfd shape.
    let efd = EventFd::open(1, "cloexec")?;
    let epfd = epoll_create()?;
    epoll_add(
        epfd.as_raw_fd(),
        efd.as_raw_fd(),
        (libc::EPOLLIN | libc::EPOLLET) as u32,
        1,
    )?;
    persistent_et_spin_out("eventfd_in_et", epfd.as_raw_fd())
}

async fn handle_span_pipe_out_et(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    let (_read_end, write_end) = make_pipe_cloexec()?;
    let epfd = epoll_create()?;
    epoll_add(
        epfd.as_raw_fd(),
        write_end.as_raw_fd(),
        (libc::EPOLLOUT | libc::EPOLLET) as u32,
        1,
    )?;
    persistent_et_spin_out("pipe_out_et", epfd.as_raw_fd())
}

async fn handle_span_pipe_in_et(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    let (read_end, write_end) = make_pipe_cloexec()?;
    // Make the read end persistently readable without draining it.
    write_eventfd_counter(write_end.as_raw_fd(), 1)?;
    let epfd = epoll_create()?;
    epoll_add(
        epfd.as_raw_fd(),
        read_end.as_raw_fd(),
        (libc::EPOLLIN | libc::EPOLLET) as u32,
        1,
    )?;
    persistent_et_spin_out("pipe_in_et", epfd.as_raw_fd())
}

async fn handle_span_socketpair_out_et(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    let (a, _b) = make_stream_socketpair()?;
    let epfd = epoll_create()?;
    epoll_add(
        epfd.as_raw_fd(),
        a.as_raw_fd(),
        (libc::EPOLLOUT | libc::EPOLLET) as u32,
        1,
    )?;
    persistent_et_spin_out("socketpair_out_et", epfd.as_raw_fd())
}

async fn handle_span_socketpair_in_et(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    let (a, b) = make_stream_socketpair()?;
    // Make `a` persistently readable: write from `b`, never drain `a`.
    write_eventfd_counter(b.as_raw_fd(), 1)?;
    let epfd = epoll_create()?;
    epoll_add(
        epfd.as_raw_fd(),
        a.as_raw_fd(),
        (libc::EPOLLIN | libc::EPOLLET) as u32,
        1,
    )?;
    persistent_et_spin_out("socketpair_in_et", epfd.as_raw_fd())
}

async fn handle_span_eventfd_in_refire(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    // Correctness guard against over-suppression: ET must re-deliver after a
    // genuine not-ready -> ready transition. write -> edge; drain -> not ready
    // (next wait times out); write -> edge again.
    let efd = EventFd::open(0, "cloexec")?;
    let epfd = epoll_create()?;
    epoll_add(
        epfd.as_raw_fd(),
        efd.as_raw_fd(),
        (libc::EPOLLIN | libc::EPOLLET) as u32,
        1,
    )?;
    write_eventfd_counter(efd.as_raw_fd(), 1)?;
    let e1 = timed_epoll_pwait(epfd.as_raw_fd(), 1000, 4)?;
    drain_eventfd_counter(efd.as_raw_fd())?;
    let e2 = timed_epoll_pwait(epfd.as_raw_fd(), 300, 4)?;
    write_eventfd_counter(efd.as_raw_fd(), 1)?;
    let e3 = timed_epoll_pwait(epfd.as_raw_fd(), 1000, 4)?;
    Ok(EpollSpinOut {
        detail: format!(
            "step=eventfd_in_refire e1={} e2={} e3={} e1_ms={} e3_ms={}",
            e1.events,
            e2.events,
            e3.events,
            elapsed_ms(e1.elapsed),
            elapsed_ms(e3.elapsed)
        ),
        first_elapsed_ms: elapsed_ms(e1.elapsed),
        first_events: e1.events,
        // re-purposed: 1 iff the post-rewrite edge re-fired.
        timer_ready: u64::from(e3.events > 0),
        // re-purposed: 1 iff the drained wait correctly timed out.
        zero_event_returns: u64::from(e2.events == 0),
        iterations: 0,
        loop_elapsed_ms: 0,
    })
}

async fn handle_span_eventfd_out_lt(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    // Level-triggered guard: a persistently-writable fd registered WITHOUT
    // EPOLLET must report ready on EVERY wait. A high iteration count with zero
    // timeouts is the CORRECT outcome here.
    let efd = EventFd::open(0, "cloexec")?;
    let epfd = epoll_create()?;
    epoll_add(epfd.as_raw_fd(), efd.as_raw_fd(), libc::EPOLLOUT as u32, 1)?;
    let first = timed_epoll_pwait(epfd.as_raw_fd(), 1000, 4)?;
    let loop_start = Instant::now();
    let loop_deadline = loop_start + Duration::from_secs(2);
    let mut iterations = 0_u64;
    let mut zero_event_returns = u64::from(first.events == 0);
    while Instant::now() < loop_deadline {
        let sample = timed_epoll_pwait(epfd.as_raw_fd(), 1000, 4)?;
        iterations += 1;
        zero_event_returns += u64::from(sample.events == 0);
    }
    Ok(EpollSpinOut {
        detail: format!(
            "step=eventfd_out_lt first_events={} iterations={} zero_event_returns={}",
            first.events, iterations, zero_event_returns
        ),
        first_elapsed_ms: elapsed_ms(first.elapsed),
        first_events: first.events,
        iterations,
        loop_elapsed_ms: elapsed_ms(loop_start.elapsed()),
        timer_ready: 0,
        zero_event_returns,
    })
}

async fn handle_span_eventfd_in_oneshot(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSpinOut, HandlerError> {
    // EPOLLONESHOT: a ready fd fires once then is disabled until re-armed via
    // EPOLL_CTL_MOD. We never re-arm, so after the initial fire every wait
    // must block (time out).
    let efd = EventFd::open(1, "cloexec")?;
    let epfd = epoll_create()?;
    epoll_add(
        epfd.as_raw_fd(),
        efd.as_raw_fd(),
        (libc::EPOLLIN | libc::EPOLLONESHOT) as u32,
        1,
    )?;
    persistent_et_spin_out("eventfd_in_oneshot", epfd.as_raw_fd())
}

fn check_span_et_no_spin(out: &EpollSpinOut) -> Result<String, String> {
    // The initial edge fires once (first_events>0); a 5s loop of 1000ms waits
    // then does <=~5 iterations when the epoll correctly blocks. A spin returns
    // immediately thousands of times. `iterations` is the discriminator; a
    // stray spurious wakeup or two is tolerated (the spin signal is ~100x).
    if out.first_events > 0 && out.iterations <= 10 {
        Ok(out.detail.clone())
    } else {
        Err(out.detail.clone())
    }
}

fn check_span_refire(out: &EpollSpinOut) -> Result<String, String> {
    // e1 fired (first_events>0), drained wait timed out (zero_event_returns==1),
    // re-armed write re-fired (timer_ready==1).
    if out.first_events > 0 && out.zero_event_returns == 1 && out.timer_ready == 1 {
        Ok(out.detail.clone())
    } else {
        Err(out.detail.clone())
    }
}

fn check_span_lt_persistent(out: &EpollSpinOut) -> Result<String, String> {
    // Level-triggered writable: every wait returns ready, so iterations is high
    // and no wait times out. Guards that the general ET fix does not suppress
    // legitimate level-triggered readiness.
    if out.first_events > 0 && out.iterations > 100 && out.zero_event_returns == 0 {
        Ok(out.detail.clone())
    } else {
        Err(out.detail.clone())
    }
}

pub(crate) fn register_epoll_pidfd_tests(reg: &mut Registry<'_>) {
    crate::register_leaf_subcommand!("wait-forever", leaf_subcmd::subcmd_wait_forever);

    register_handler!(PIDFD_EXIT, handle_pidfd_exit);
    register_handler!(MULTI_SOCKET, handle_multi_socket);
    register_handler!(EVENTFD_WAKEUP, handle_eventfd_wakeup);
    register_handler!(TIMEOUT_ZERO, handle_timeout_zero);
    register_handler!(EDGE_TRIGGER, handle_edge_trigger);
    register_handler!(SETUP_TCP_LISTEN, handle_setup_tcp_listen);
    register_handler!(EPOLL_SPIN_EVENTFD_IDLE, handle_epoll_spin_eventfd_idle);
    register_handler!(EPOLL_SPIN_TIMERFD, handle_epoll_spin_timerfd);
    register_handler!(
        EPOLL_SPIN_TIMERFD_INHERITED_FORK,
        handle_epoll_spin_timerfd_inherited_fork
    );
    register_handler!(
        EPOLL_SPIN_BROKER_UDP_WRITABLE,
        handle_epoll_spin_broker_udp_writable
    );
    register_handler!(
        EPOLL_SPIN_BROKER_TCP_STICKY_OUT,
        handle_epoll_spin_broker_tcp_sticky_out
    );
    register_handler!(
        EPOLL_SPIN_BROKER_TCP_STICKY_IN,
        handle_epoll_spin_broker_tcp_sticky_in
    );
    register_handler!(
        EPOLL_SPIN_BROKER_TCP_HALF_CLOSED,
        handle_epoll_spin_broker_tcp_half_closed
    );
    register_handler!(
        EPOLL_REFIRE_BROKER_TCP_DRAIN_IN_ET,
        handle_epoll_refire_broker_tcp_drain_in_et
    );
    register_handler!(EPOLL_SPAN_EVENTFD_OUT_ET, handle_span_eventfd_out_et);
    register_handler!(EPOLL_SPAN_EVENTFD_IN_ET, handle_span_eventfd_in_et);
    register_handler!(EPOLL_SPAN_PIPE_OUT_ET, handle_span_pipe_out_et);
    register_handler!(EPOLL_SPAN_PIPE_IN_ET, handle_span_pipe_in_et);
    register_handler!(EPOLL_SPAN_SOCKETPAIR_OUT_ET, handle_span_socketpair_out_et);
    register_handler!(EPOLL_SPAN_SOCKETPAIR_IN_ET, handle_span_socketpair_in_et);
    register_handler!(EPOLL_SPAN_EVENTFD_IN_REFIRE, handle_span_eventfd_in_refire);
    register_handler!(EPOLL_SPAN_EVENTFD_OUT_LT, handle_span_eventfd_out_lt);
    register_handler!(
        EPOLL_SPAN_EVENTFD_IN_ONESHOT,
        handle_span_eventfd_in_oneshot
    );

    for &agent in EPI_AGENTS {
        for def in EPI_SCENARIOS {
            if def.in_process_only && agent != AgentName::Dpg1 {
                continue;
            }
            let bts: &[Option<crate::BinaryType>] = if matches!(def.kind, ScenarioKind::PidfdExit) {
                &[
                    Some(crate::BinaryType::PieGlibc),
                    Some(crate::BinaryType::NonPieGlibc),
                    Some(crate::BinaryType::StaticPieGlibc),
                    Some(crate::BinaryType::StaticPieMusl),
                    Some(crate::BinaryType::NonPieStaticMusl),
                ]
            } else {
                &[None]
            };
            for &bt_opt in bts {
                let test_id = match bt_opt {
                    Some(bt) => format!("EPI.{}.{}.{agent}", def.name, bt.label()),
                    None => format!("EPI.{}.{agent}", def.name),
                };
                match def.kind {
                    ScenarioKind::EventfdWakeup => reg.single_agent_handler_test(
                        "vscode",
                        "epoll_pidfd",
                        test_id,
                        agent,
                        &EVENTFD_WAKEUP,
                        detail_out,
                    ),
                    ScenarioKind::TimeoutZero => reg.single_agent_handler_test(
                        "vscode",
                        "epoll_pidfd",
                        test_id,
                        agent,
                        &TIMEOUT_ZERO,
                        detail_out,
                    ),
                    ScenarioKind::PidfdExit
                    | ScenarioKind::MultiSocket
                    | ScenarioKind::EdgeTrigger => {
                        register_peer_addr_test(reg, def.kind, test_id, agent, bt_opt);
                    }
                }
            }
        }
    }

    for &agent in &[
        AgentName::Dpg1,
        AgentName::Dpg1DngSpm,
        AgentName::VsCodeCli,
        AgentName::VsCodeNode,
    ] {
        reg.single_agent_handler_test(
            "vscode",
            "epoll_pidfd",
            format!("EP.spin.eventfd_idle.{agent}"),
            agent,
            &EPOLL_SPIN_EVENTFD_IDLE,
            check_epoll_spin_eventfd_idle,
        );
        reg.single_agent_handler_test(
            "vscode",
            "epoll_pidfd",
            format!("EP.spin.timerfd.{agent}"),
            agent,
            &EPOLL_SPIN_TIMERFD,
            check_epoll_spin_timerfd,
        );
        reg.single_agent_handler_test(
            "vscode",
            "epoll_pidfd",
            format!("EP.spin.timerfd_inherited_fork.{agent}"),
            agent,
            &EPOLL_SPIN_TIMERFD_INHERITED_FORK,
            check_epoll_spin_timerfd,
        );
        reg.single_agent_handler_test(
            "vscode",
            "epoll_pidfd",
            format!("EP.spin.broker_udp_writable_et.{agent}"),
            agent,
            &EPOLL_SPIN_BROKER_UDP_WRITABLE,
            check_epoll_spin_broker_writable_et,
        );
        register_broker_tcp_sticky_out_test(reg, agent);
        register_broker_tcp_in_test(
            reg,
            agent,
            "broker_tcp_sticky_in_et",
            &EPOLL_SPIN_BROKER_TCP_STICKY_IN,
        );
        register_broker_tcp_in_test(
            reg,
            agent,
            "broker_tcp_half_closed_et",
            &EPOLL_SPIN_BROKER_TCP_HALF_CLOSED,
        );
        register_broker_tcp_refire_test(reg, agent);
        for (name, token, check) in [
            (
                "eventfd_out_et",
                &EPOLL_SPAN_EVENTFD_OUT_ET,
                check_span_et_no_spin as fn(&EpollSpinOut) -> Result<String, String>,
            ),
            (
                "eventfd_in_et",
                &EPOLL_SPAN_EVENTFD_IN_ET,
                check_span_et_no_spin,
            ),
            (
                "pipe_out_et",
                &EPOLL_SPAN_PIPE_OUT_ET,
                check_span_et_no_spin,
            ),
            ("pipe_in_et", &EPOLL_SPAN_PIPE_IN_ET, check_span_et_no_spin),
            (
                "socketpair_out_et",
                &EPOLL_SPAN_SOCKETPAIR_OUT_ET,
                check_span_et_no_spin,
            ),
            (
                "socketpair_in_et",
                &EPOLL_SPAN_SOCKETPAIR_IN_ET,
                check_span_et_no_spin,
            ),
            (
                "eventfd_in_oneshot",
                &EPOLL_SPAN_EVENTFD_IN_ONESHOT,
                check_span_et_no_spin,
            ),
            (
                "eventfd_in_refire",
                &EPOLL_SPAN_EVENTFD_IN_REFIRE,
                check_span_refire,
            ),
            (
                "eventfd_out_lt",
                &EPOLL_SPAN_EVENTFD_OUT_LT,
                check_span_lt_persistent,
            ),
        ] {
            reg.single_agent_handler_test(
                "vscode",
                "epoll_pidfd",
                format!("EP.span.{name}.{agent}"),
                agent,
                token,
                check,
            );
        }
    }
}

fn register_broker_tcp_sticky_out_test(reg: &mut Registry<'_>, agent: AgentName) {
    let label = agent.to_string();
    reg.test(
        "vscode",
        "epoll_pidfd",
        format!("EP.spin.broker_tcp_sticky_out_et.{agent}"),
    )
    .timeout(60)
    .build(move |cx| {
        let observer = cx.require(agent);
        let peer_agent = peer_for(agent);
        let peer = if peer_agent == agent {
            observer.clone()
        } else {
            cx.require(peer_agent)
        };
        let label = label.clone();
        Box::new(move |run| {
            Box::pin(async move {
                let result = drive_broker_tcp_sticky_out_probe(run, &observer, &peer).await;
                match result {
                    Ok(detail) => TestOutcome::new(&label, true, detail),
                    Err(detail) => TestOutcome::new(&label, false, detail),
                }
            })
        })
    });
}

fn register_broker_tcp_refire_test(reg: &mut Registry<'_>, agent: AgentName) {
    let label = agent.to_string();
    reg.test(
        "vscode",
        "epoll_pidfd",
        format!("EP.refire.broker_tcp_drain_in_et.{agent}"),
    )
    .timeout(60)
    .build(move |cx| {
        let observer = cx.require(agent);
        let peer_agent = peer_for(agent);
        let peer = if peer_agent == agent {
            observer.clone()
        } else {
            cx.require(peer_agent)
        };
        let label = label.clone();
        Box::new(move |run| {
            Box::pin(async move {
                let result = drive_broker_tcp_refire_probe(run, &observer, &peer).await;
                match result {
                    Ok(detail) => TestOutcome::new(&label, true, detail),
                    Err(detail) => TestOutcome::new(&label, false, detail),
                }
            })
        })
    });
}

fn check_epoll_spin_eventfd_idle(out: &EpollSpinOut) -> Result<String, String> {
    if out.first_events == 0
        && out.first_elapsed_ms >= 500
        && out.iterations <= 10
        && out.zero_event_returns == out.iterations + 1
    {
        Ok(out.detail.clone())
    } else {
        Err(out.detail.clone())
    }
}

fn check_epoll_spin_timerfd(out: &EpollSpinOut) -> Result<String, String> {
    if out.first_events > 0
        && out.first_elapsed_ms >= 500
        && out.first_elapsed_ms <= 1800
        && out.iterations <= 10
        && out.timer_ready == out.iterations + 1
        && out.zero_event_returns == 0
    {
        Ok(out.detail.clone())
    } else {
        Err(out.detail.clone())
    }
}

fn check_epoll_spin_broker_writable_et(out: &EpollSpinOut) -> Result<String, String> {
    // 5s loop with 1000ms timeouts: a correctly-blocking EPOLLET epoll
    // does at most ~5 iterations (each wait blocks until the timeout
    // because the writable edge already fired once). A spin — the broker
    // fd's persistent writability re-firing on every wait — does
    // thousands. `iterations` is the discriminator.
    if out.iterations <= 10 {
        Ok(out.detail.clone())
    } else {
        Err(out.detail.clone())
    }
}

fn check_epoll_spin_broker_tcp_sticky_out(out: &EpollSpinOut) -> Result<String, String> {
    // 3s loop with 100ms timeouts: native completes about 30 blocking waits.
    // The sticky-broker-notification bug returns immediately thousands of times.
    if out.first_events > 0 && out.iterations <= 40 && out.zero_event_returns == out.iterations {
        Ok(out.detail.clone())
    } else {
        Err(out.detail.clone())
    }
}

fn check_broker_tcp_refire(out: &EpollSpinOut) -> Result<String, String> {
    if out.first_events > 0
        && out.iterations == 4
        && out.timer_ready == 4
        && out.zero_event_returns == 0
    {
        Ok(out.detail.clone())
    } else {
        Err(out.detail.clone())
    }
}

fn run_timerfd_probe_in_forked_child(
    epfd: i32,
    timerfd: i32,
) -> Result<EpollSpinOut, HandlerError> {
    let mut pipe_fds = [0_i32; 2];
    // SAFETY: pipe writes two fresh fds into pipe_fds on success.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err(HandlerError(format!(
            "pipe: {}",
            std::io::Error::last_os_error()
        )));
    }
    let read_fd = pipe_fds[0];
    let write_fd = pipe_fds[1];

    // SAFETY: fork creates a child process. The child writes one JSON result
    // to the dedicated pipe and exits without returning to the async runtime.
    let child = unsafe { libc::fork() };
    if child < 0 {
        // SAFETY: both fds were returned by pipe and are owned here.
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        return Err(HandlerError(format!(
            "fork: {}",
            std::io::Error::last_os_error()
        )));
    }
    if child == 0 {
        // SAFETY: the child owns its inherited copy of read_fd and does not use it.
        unsafe {
            libc::close(read_fd);
        }
        let exit_code =
            match run_epoll_spin_timerfd_probe(epfd, timerfd, "step=3 timerfd_inherited_fork") {
                Ok(out) => match serde_json::to_vec(&out) {
                    Ok(bytes) => write_all_fd(write_fd, &bytes).map_or(1, |()| 0),
                    Err(_) => 1,
                },
                Err(err) => {
                    let message = format!("ERR:{err:?}");
                    write_all_fd(write_fd, message.as_bytes()).map_or(1, |()| 2)
                }
            };
        // SAFETY: write_fd is no longer needed in the child; _exit avoids
        // running non-async-signal-safe destructors in the forked child.
        unsafe {
            libc::close(write_fd);
            libc::_exit(exit_code);
        }
    }

    // SAFETY: parent only reads from the pipe.
    unsafe {
        libc::close(write_fd);
    }
    let bytes = read_all_fd(read_fd);
    // SAFETY: read_fd is owned by the parent.
    unsafe {
        libc::close(read_fd);
    }
    let mut status = 0_i32;
    // SAFETY: child is the pid just returned by fork; status points to valid storage.
    let wait_rc = unsafe { libc::waitpid(child, &raw mut status, 0) };
    if wait_rc < 0 {
        return Err(HandlerError(format!(
            "waitpid({child}): {}",
            std::io::Error::last_os_error()
        )));
    }
    let output = String::from_utf8_lossy(&bytes).into_owned();
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(HandlerError(format!(
            "forked timerfd probe child status={status:#x} output={output}"
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| HandlerError(format!("forked timerfd probe JSON parse: {e}; {output}")))
}

fn write_all_fd(fd: i32, mut bytes: &[u8]) -> Result<(), ()> {
    while !bytes.is_empty() {
        // SAFETY: bytes points to readable memory for bytes.len() bytes.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(());
        }
        let n = usize::try_from(n).map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        bytes = &bytes[n..];
    }
    Ok(())
}

fn read_all_fd(fd: i32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        // SAFETY: buf is valid writable storage for buf.len() bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        let Ok(n) = usize::try_from(n) else {
            break;
        };
        out.extend_from_slice(&buf[..n]);
    }
    out
}

struct EpollWaitSample {
    elapsed: Duration,
    events: i32,
    timer_ready: bool,
}

fn epoll_create() -> Result<OwnedFd, HandlerError> {
    // SAFETY: epoll_create1 creates a fresh descriptor on success.
    let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if fd < 0 {
        return Err(HandlerError(format!(
            "epoll_create1: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fd is a newly returned descriptor owned by this handler.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn epoll_add(epfd: i32, fd: i32, events: u32, token: u64) -> Result<(), HandlerError> {
    let mut ev = libc::epoll_event { events, u64: token };
    // SAFETY: epfd and fd are live descriptors; ev is initialized.
    let rc = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &raw mut ev) };
    if rc == 0 {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "epoll_ctl ADD fd={fd}: {}",
            std::io::Error::last_os_error()
        )))
    }
}

fn timed_epoll_pwait(
    epfd: i32,
    timeout_ms: i32,
    max_events: usize,
) -> Result<EpollWaitSample, HandlerError> {
    let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; max_events];
    let start = Instant::now();
    // SAFETY: events is valid writable storage for max_events entries, epfd is
    // live, and a null sigmask requests the current signal mask.
    let n = unsafe {
        libc::epoll_pwait(
            epfd,
            events.as_mut_ptr(),
            i32::try_from(max_events).unwrap_or(i32::MAX),
            timeout_ms,
            std::ptr::null(),
        )
    };
    let elapsed = start.elapsed();
    if n < 0 {
        return Err(HandlerError(format!(
            "epoll_pwait: {}",
            std::io::Error::last_os_error()
        )));
    }
    let timer_ready = events
        .iter()
        .take(usize::try_from(n).unwrap_or(0))
        .any(|ev| ev.u64 == 2 && (ev.events & libc::EPOLLIN as u32) != 0);
    Ok(EpollWaitSample {
        elapsed,
        events: n,
        timer_ready,
    })
}

fn timerfd_create() -> Result<OwnedFd, HandlerError> {
    // SAFETY: timerfd_create is called with constant clock/flag values; errors are checked.
    let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC) };
    if fd < 0 {
        return Err(HandlerError(format!(
            "timerfd_create(CLOCK_MONOTONIC): {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fd is a newly returned descriptor owned by this handler.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn arm_timerfd(fd: i32, duration: Duration) -> Result<(), HandlerError> {
    let spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: duration_to_timespec(duration)?,
    };
    // SAFETY: spec is initialized and fd is expected to refer to a live timerfd.
    let rc =
        unsafe { libc::timerfd_settime(fd, 0, std::ptr::from_ref(&spec), std::ptr::null_mut()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "timerfd_settime fd={fd}: {}",
            std::io::Error::last_os_error()
        )))
    }
}

fn duration_to_timespec(duration: Duration) -> Result<libc::timespec, HandlerError> {
    Ok(libc::timespec {
        tv_sec: libc::time_t::try_from(duration.as_secs())
            .map_err(|_| HandlerError("duration seconds exceed time_t".to_string()))?,
        tv_nsec: libc::c_long::from(duration.subsec_nanos()),
    })
}

fn drain_timerfd(fd: i32) -> Result<(), HandlerError> {
    let mut count = 0_u64;
    // SAFETY: count is valid writable storage for one timerfd expiration count.
    let n = unsafe {
        libc::read(
            fd,
            std::ptr::from_mut(&mut count).cast::<libc::c_void>(),
            std::mem::size_of::<u64>(),
        )
    };
    if n == std::mem::size_of::<u64>() as isize {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "timerfd read n={n}: {}",
            std::io::Error::last_os_error()
        )))
    }
}

fn elapsed_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn register_peer_addr_test(
    reg: &mut Registry<'_>,
    scenario: ScenarioKind,
    test_id: String,
    agent: AgentName,
    bt_opt: Option<crate::BinaryType>,
) {
    let label = agent.to_string();
    reg.test("vscode", "epoll_pidfd", test_id)
        .timeout(60)
        .build(move |cx| {
            let observer = cx.require(agent);
            let peer_agent = peer_for(agent);
            let peer = if peer_agent == agent {
                observer.clone()
            } else {
                cx.require(peer_agent)
            };
            let label = label.clone();
            Box::new(move |run| {
                Box::pin(async move {
                    let result =
                        drive_peer_addr_scenario(run, &observer, &peer, scenario, bt_opt).await;
                    match result {
                        Ok(detail) => TestOutcome::new(&label, true, detail),
                        Err(detail) => TestOutcome::new(&label, false, detail),
                    }
                })
            })
        });
}

fn detail_out(out: &DetailOut) -> Result<String, String> {
    if out.detail.is_empty() {
        Err("handler returned empty detail".to_string())
    } else {
        Ok(out.detail.clone())
    }
}

fn peer_for(agent: AgentName) -> AgentName {
    if matches!(agent, AgentName::Dpg1 | AgentName::Dpg1Dpg1) {
        AgentName::Dpg2
    } else {
        AgentName::Dpg1
    }
}

async fn drive_peer_addr_scenario(
    run: &mut RunContext<'_>,
    observer: &super::agents::AgentHandle,
    peer: &super::agents::AgentHandle,
    scenario: ScenarioKind,
    bt_opt: Option<crate::BinaryType>,
) -> Result<String, String> {
    let peer_addr = open_peer_addr(run, peer).await?;
    let out = match scenario {
        ScenarioKind::PidfdExit => {
            let bt = bt_opt.expect("PidfdExit always iterates a BinaryType");
            let target = crate::binary_path(bt, run.self_exe());
            run.send_named_typed(observer, &PIDFD_EXIT, PidfdExitArgs { target, peer_addr })
                .await
        }
        ScenarioKind::MultiSocket => {
            run.send_named_typed(observer, &MULTI_SOCKET, PeerAddrArgs { peer_addr })
                .await
        }
        ScenarioKind::EdgeTrigger => {
            run.send_named_typed(observer, &EDGE_TRIGGER, PeerAddrArgs { peer_addr })
                .await
        }
        ScenarioKind::EventfdWakeup | ScenarioKind::TimeoutZero => {
            return Err("scenario does not use peer addr".to_string());
        }
    }
    .map_err(|e| format!("send_named: {e}"))?;
    Ok(out.detail)
}

async fn drive_broker_tcp_sticky_out_probe(
    run: &mut RunContext<'_>,
    observer: &super::agents::AgentHandle,
    peer: &super::agents::AgentHandle,
) -> Result<String, String> {
    let peer_addr = open_peer_addr(run, peer).await?;
    let out = run
        .send_named_typed(
            observer,
            &EPOLL_SPIN_BROKER_TCP_STICKY_OUT,
            PeerAddrArgs { peer_addr },
        )
        .await
        .map_err(|e| format!("send_named: {e}"))?;
    check_epoll_spin_broker_tcp_sticky_out(&out)
}

async fn drive_broker_tcp_refire_probe(
    run: &mut RunContext<'_>,
    observer: &super::agents::AgentHandle,
    peer: &super::agents::AgentHandle,
) -> Result<String, String> {
    let peer_addr = open_peer_addr(run, peer).await?;
    let out = run
        .send_named_typed(
            observer,
            &EPOLL_REFIRE_BROKER_TCP_DRAIN_IN_ET,
            PeerAddrArgs { peer_addr },
        )
        .await
        .map_err(|e| format!("send_named: {e}"))?;
    check_broker_tcp_refire(&out)
}

async fn open_peer_addr(
    run: &mut RunContext<'_>,
    peer: &super::agents::AgentHandle,
) -> Result<String, String> {
    let out = run
        .send_named_typed(peer, &SETUP_TCP_LISTEN, SetupTcpListenArgs { port: 0 })
        .await
        .map_err(|e| format!("setup_tcp_listen: {e}"))?;
    Ok(format!("127.0.0.1:{}", out.port))
}

fn connect_peer(addr: &str) -> Result<std::net::TcpStream, std::io::Error> {
    let stream = std::net::TcpStream::connect(addr)?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn wait_readable(stream: &std::net::TcpStream, timeout: Duration) -> Result<(), std::io::Error> {
    stream.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    let mut byte = [0u8; 1];
    loop {
        match stream.peek(&mut byte) {
            Ok(n) if n > 0 => {
                stream.set_nonblocking(false)?;
                return Ok(());
            }
            Ok(_) => {
                stream.set_nonblocking(false)?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "socket closed before readability",
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    stream.set_nonblocking(false)?;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "timed out waiting for socket readability",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                stream.set_nonblocking(false)?;
                return Err(e);
            }
        }
    }
}

fn ready_socket_ids(events: &[EpollEvent]) -> Vec<u64> {
    let mut ready: Vec<u64> = events
        .iter()
        .filter(|event| event.kind == "socket" && has_in(event))
        .map(|event| event.id)
        .collect();
    ready.sort_unstable();
    ready.dedup();
    ready
}

fn has_in(event: &EpollEvent) -> bool {
    event.observed_events.split('|').any(|part| part == "in")
}

/// Argv-dispatched leaf subcommands. `wait-forever` stays as a subcommand because it blocks indefinitely — converting it to an agent handler would jam the agent loop.
mod leaf_subcmd {
    pub(super) fn subcmd_wait_forever(_args: &[String]) -> i32 {
        loop {
            std::thread::park();
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// EP: Epoll + Socket wakeup
// ═══════════════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Debug)]
struct EpollSocketArgs {
    port: u16,
    variant: String,
}

const EPOLL_SOCKET: HandlerToken<EpollSocketArgs, EpollSocketDetailOut> =
    HandlerToken::new("platform_fixes.epoll_socket");

#[derive(Serialize, Deserialize, Debug)]
struct EpollSocketDetailOut {
    detail: String,
}

async fn handle_epoll_socket(
    args: EpollSocketArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<EpollSocketDetailOut, HandlerError> {
    let detail = epoll_socket_detail(args.port, &args.variant)?;
    Ok(EpollSocketDetailOut { detail })
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]
fn epoll_socket_detail(port: u16, variant: &str) -> Result<String, HandlerError> {
    let mut out = Vec::new();
    // SAFETY: all raw sockets/fds created here are checked for errors and closed before return.
    unsafe {
        let srv = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        if srv < 0 {
            return Err(HandlerError::from(format!(
                "socket: {}",
                std::io::Error::last_os_error()
            )));
        }
        let one: libc::c_int = 1;
        libc::setsockopt(
            srv,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&raw const one).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        if libc::bind(
            srv,
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(srv);
            return Err(HandlerError::from(format!("bind: {e}")));
        }
        libc::listen(srv, 5);
        let epfd = libc::epoll_create1(0);
        if epfd < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(srv);
            return Err(HandlerError::from(format!("epoll_create1: {e}")));
        }
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: srv as u64,
        };
        libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, srv, &raw mut ev);
        let client = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            let sock = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            let addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: port.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
                },
                sin_zero: [0; 8],
            };
            libc::connect(
                sock,
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            let msg = b"EPOLL_DATA";
            libc::send(sock, msg.as_ptr().cast(), msg.len(), 0);
            libc::close(sock);
        });
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
        if variant == "tokio" {
            let n = libc::epoll_wait(epfd, events.as_mut_ptr(), 4, 0);
            if n > 0 {
                out.push("EPOLL_ACCEPT=IMMEDIATE".into());
            } else {
                let n = libc::epoll_wait(epfd, events.as_mut_ptr(), 4, 5000);
                if n <= 0 {
                    out.push("EPOLL_ACCEPT=TIMEOUT".into());
                    let _ = client.join();
                    libc::close(srv);
                    libc::close(epfd);
                    return Ok(out.join("\n"));
                }
                out.push("EPOLL_ACCEPT=WOKE".into());
            }
        } else {
            let n = libc::epoll_wait(epfd, events.as_mut_ptr(), 4, 5000);
            if n <= 0 {
                out.push("EPOLL_ACCEPT=TIMEOUT".into());
                let _ = client.join();
                libc::close(srv);
                libc::close(epfd);
                return Ok(out.join("\n"));
            }
            out.push("EPOLL_ACCEPT=READY".into());
        }
        let conn = libc::accept4(
            srv,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_NONBLOCK,
        );
        if conn < 0 {
            out.push("EPOLL_ACCEPT=FAIL".into());
        } else {
            let mut ev2 = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: conn as u64,
            };
            libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, conn, &raw mut ev2);
            let n2 = libc::epoll_wait(epfd, events.as_mut_ptr(), 4, 5000);
            if n2 <= 0 {
                out.push("EPOLL_READ=TIMEOUT".into());
            } else {
                let mut buf = [0u8; 64];
                let nr = libc::recv(conn, buf.as_mut_ptr().cast(), buf.len(), 0);
                if nr > 0 {
                    let data = std::str::from_utf8(&buf[..nr.cast_unsigned()]).unwrap_or("?");
                    out.push(format!("EPOLL_READ=OK data={data}"));
                } else {
                    out.push(format!("EPOLL_READ=NO_DATA nr={nr}"));
                }
            }
            libc::close(conn);
        }
        let _ = client.join();
        libc::close(srv);
        libc::close(epfd);
    }
    Ok(out.join("\n"))
}

#[allow(clippy::too_many_lines)]
pub(crate) fn register_epoll_socket_tests(reg: &mut Registry<'_>) {
    register_handler!(EPOLL_SOCKET, handle_epoll_socket);
    for &variant in &["direct", "tokio"] {
        // Long-lived agents the epoll/socket test runs in. Each
        // entry is a forking parent of a different binary type; the
        // syscall-rewrite / vDSO / epoll-host code path differs per
        // parent binary, so we want a slot per leg.
        for &agent in &[
            AgentName::Dpg1,       // PIE-glibc
            AgentName::Dpg1Dpg1,   // PIE-glibc depth-2
            AgentName::Dpg2,       // PIE-glibc sibling
            AgentName::Dpg1Dng,    // non-PIE-glibc (node form)
            AgentName::Dpg1DngDpg, // PIE child of non-PIE — round-trip
            AgentName::Dpg1DngDng, // bash → bash (VS Code hot path)
            AgentName::Dpg1DngSpm, // bash → cli (VS Code hot path)
            AgentName::Dpg1Spg,    // static-PIE-glibc
            AgentName::Dpg1Spm,    // static-PIE-musl (cli form)
            AgentName::Dpg1SpmDng, // cli → node (VS Code signature)
            AgentName::Dpg1Snm,    // non-PIE-static-musl
        ] {
            let port: u16 = match (variant, agent) {
                ("direct", AgentName::Dpg1) => 19990,
                ("direct", AgentName::Dpg1Dpg1) => 19991,
                ("direct", AgentName::Dpg2) => 19992,
                ("direct", AgentName::Dpg1Dng) => 19993,
                ("direct", AgentName::Dpg1DngDpg) => 19994,
                ("direct", AgentName::Dpg1Spg) => 19980,
                ("direct", AgentName::Dpg1Spm) => 19981,
                ("direct", AgentName::Dpg1Snm) => 19982,
                ("direct", AgentName::Dpg1DngDng) => 19970,
                ("direct", AgentName::Dpg1DngSpm) => 19971,
                ("direct", AgentName::Dpg1SpmDng) => 19972,
                ("tokio", AgentName::Dpg1) => 19995,
                ("tokio", AgentName::Dpg1Dpg1) => 19996,
                ("tokio", AgentName::Dpg2) => 19997,
                ("tokio", AgentName::Dpg1Dng) => 19998,
                ("tokio", AgentName::Dpg1DngDpg) => 19999,
                ("tokio", AgentName::Dpg1Spg) => 19985,
                ("tokio", AgentName::Dpg1Spm) => 19986,
                ("tokio", AgentName::Dpg1Snm) => 19987,
                ("tokio", AgentName::Dpg1DngDng) => 19975,
                ("tokio", AgentName::Dpg1DngSpm) => 19976,
                ("tokio", AgentName::Dpg1SpmDng) => 19977,
                _ => 19960,
            };

            // EP.{variant}.accept.{agent}
            {
                let agent_s = agent.to_string();
                let variant_s: String = variant.into();
                reg.test("matrix", "epoll_socket", format!("EP.{variant}.accept.{agent}"))
                    .timeout(60)
                    .build(move |cx| {
                        let leaf = cx.declare_ephemeral(
                            agent,
                            format!("EpollSocketAccept_{variant}_{agent}"),
                            SpawnKind::Fork {
                                binary: "self",
                                inherit_listen_ports: vec![],
                            },
                        );
                        Box::new(move |run| {
                            let a = agent_s.clone();
                            let v = variant_s.clone();
                            Box::pin(async move {
                                let result = run
                                    .run_leaf(
                                        &leaf,
                                        &EPOLL_SOCKET,
                                        EpollSocketArgs { port, variant: v })
                                    .await;
                                let pass = matches!(&result, Ok(out) if out.detail.contains("EPOLL_ACCEPT=") && !out.detail.contains("TIMEOUT"));
                                super::TestOutcome::new(&a, pass, format!("{result:?}"))
                            })
                        })
                    });
            }

            // EP.{variant}.read.{agent}
            {
                let agent_s = agent.to_string();
                let variant_s: String = variant.into();
                reg.test(
                    "matrix",
                    "epoll_socket",
                    format!("EP.{variant}.read.{agent}"),
                )
                .timeout(60)
                .build(move |cx| {
                    let leaf = cx.declare_ephemeral(
                        agent,
                        format!("EpollSocketRead_{variant}_{agent}"),
                        SpawnKind::Fork {
                            binary: "self",
                            inherit_listen_ports: vec![],
                        },
                    );
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let v = variant_s.clone();
                        Box::pin(async move {
                            let result = run
                                .run_leaf(
                                    &leaf,
                                    &EPOLL_SOCKET,
                                    EpollSocketArgs { port, variant: v },
                                )
                                .await;
                            let pass =
                                matches!(&result, Ok(out) if out.detail.contains("EPOLL_READ=OK"));
                            super::TestOutcome::new(&a, pass, format!("{result:?}"))
                        })
                    })
                });
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// POLL: epoll/ppoll IN events (fix 0fb258e2)
// ═══════════════════════════════════════════════════════════════════

const POLL_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2];

#[derive(Serialize, Deserialize, Debug)]
struct PollReadyArgs {
    timeout_ms: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct PollReadyOut {
    detail: String,
}

const POLL_READY: HandlerToken<PollReadyArgs, PollReadyOut> =
    HandlerToken::new("platform_fixes.poll_ready");

async fn handle_poll_ready(
    args: PollReadyArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PollReadyOut, HandlerError> {
    let detail = (|| -> Result<String, String> {
        let mut pipe_fds = [0i32; 2];
        // SAFETY: pipe writes two fresh fds into pipe_fds on success.
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(format!("pipe: {}", std::io::Error::last_os_error()));
        }
        let (read_fd, write_fd) = (pipe_fds[0], pipe_fds[1]);
        let data = b"poll_test_data";
        // SAFETY: write_fd is a live pipe fd and data points to readable bytes.
        let _ = unsafe { libc::write(write_fd, data.as_ptr().cast(), data.len()) };
        let mut fds = [libc::pollfd {
            fd: read_fd,
            events: libc::POLLIN,
            revents: 0,
        }];
        // SAFETY: fds points to one valid pollfd.
        let n = unsafe {
            libc::poll(
                fds.as_mut_ptr(),
                1,
                i32::try_from(args.timeout_ms).unwrap_or(i32::MAX),
            )
        };
        // SAFETY: both fds are owned by this handler.
        unsafe {
            libc::close(write_fd);
            libc::close(read_fd);
        }
        if n > 0 && (fds[0].revents & libc::POLLIN) != 0 {
            Ok("POLLIN".to_string())
        } else {
            Ok("TIMEOUT".to_string())
        }
    })()?;
    Ok(PollReadyOut { detail })
}

pub(crate) fn register_poll_ready_tests(reg: &mut Registry<'_>) {
    register_handler!(POLL_READY, handle_poll_ready);
    for &agent in POLL_AGENTS {
        let agent_s = agent.to_string();
        reg.test("matrix", "poll_ready", format!("POLL.pipe.{agent}"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = agent_s.clone();
                    Box::pin(async move {
                        let result = run
                            .send_named_typed(
                                &handle,
                                &POLL_READY,
                                PollReadyArgs { timeout_ms: 2000 },
                            )
                            .await;
                        let pass = matches!(&result, Ok(out) if out.detail == "POLLIN");
                        super::TestOutcome::new(&a, pass, format!("{result:?}"))
                    })
                })
            });
    }
}
