// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Epoll + pidfd/eventfd/socket readiness tests for VS Code server blockers.
//!
//! Migrated to the typed-handler protocol. Each scenario owns its epoll fd,
//! registered fds, and wait loop inside one straight-line handler body.

use std::io::Write;
use std::os::fd::AsRawFd;
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
use super::agents::AgentName;
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

pub(crate) fn register_epoll_pidfd_tests(reg: &mut Registry<'_>) {
    register_handler!(PIDFD_EXIT, handle_pidfd_exit);
    register_handler!(MULTI_SOCKET, handle_multi_socket);
    register_handler!(EVENTFD_WAKEUP, handle_eventfd_wakeup);
    register_handler!(TIMEOUT_ZERO, handle_timeout_zero);
    register_handler!(EDGE_TRIGGER, handle_edge_trigger);
    register_handler!(SETUP_TCP_LISTEN, handle_setup_tcp_listen);

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
