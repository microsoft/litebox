// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Epoll + pidfd/eventfd/socket readiness tests for VS Code server blockers.

use crate::protocol::{Command, EpollEvent, Response};

use super::agents::AgentName;
use super::registry::Registry;
use super::run_context::RunContext;
use super::{TestOutcome, expect_listening_port, ok_without_data};

pub(crate) const EPI_AGENTS: &[AgentName] =
    &[AgentName::A, AgentName::AA, AgentName::B, AgentName::BB];

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

pub(crate) fn register_epoll_pidfd_tests(reg: &mut Registry<'_>) {
    for &agent in EPI_AGENTS {
        for def in EPI_SCENARIOS {
            if def.in_process_only && agent != AgentName::A {
                continue;
            }
            // Only the PidfdExit scenario exec's a binary (it spawns a
            // background child to monitor for exit-via-pidfd). Iterate
            // the BinaryType axis there so each leg's execve path is
            // covered. Other scenarios are pure agent-protocol and
            // run once.
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
                let agent_s = agent.to_string();
                let scenario = def.kind;
                let test_id = match bt_opt {
                    Some(bt) => format!("EPI.{}.{}.{agent}", def.name, bt.label()),
                    None => format!("EPI.{}.{agent}", def.name),
                };
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
                        Box::new(move |run| {
                            let a = agent_s.clone();
                            Box::pin(async move {
                                let result = match scenario {
                                    ScenarioKind::PidfdExit => {
                                        let bt =
                                            bt_opt.expect("PidfdExit always iterates a BinaryType");
                                        let target = crate::binary_path(bt, run.self_exe());
                                        run_pidfd_exit(run, &observer, &peer, target).await
                                    }
                                    ScenarioKind::MultiSocket => {
                                        run_multi_socket(run, &observer, &peer).await
                                    }
                                    ScenarioKind::EventfdWakeup => {
                                        run_eventfd_wakeup(run, &observer).await
                                    }
                                    ScenarioKind::TimeoutZero => {
                                        run_timeout_zero(run, &observer).await
                                    }
                                    ScenarioKind::EdgeTrigger => {
                                        run_edge_trigger(run, &observer, &peer).await
                                    }
                                };
                                match result {
                                    Ok(detail) => TestOutcome::new(&a, true, detail),
                                    Err(detail) => TestOutcome::new(&a, false, detail),
                                }
                            })
                        })
                    });
            }
        }
    }
}

fn peer_for(agent: AgentName) -> AgentName {
    if matches!(agent, AgentName::A | AgentName::AA) {
        AgentName::B
    } else {
        AgentName::A
    }
}

async fn run_pidfd_exit(
    run: &mut RunContext<'_>,
    observer: &super::agents::AgentHandle,
    peer: &super::agents::AgentHandle,
    target: String,
) -> Result<String, String> {
    let epoll = epoll_open(run, observer).await?;
    let bg = run
        .send(
            observer,
            Command::Exec {
                args: vec![target, "wait-forever".to_string()],
                timeout_secs: None,
                stdin: None,
                background: true,
                env: vec![],
            },
        )
        .await;
    let pid = match bg {
        Response::Background { pid } => pid,
        other => return Err(format!("expected Background, got {other:?}")),
    };
    expect_ok(
        run.send(
            observer,
            Command::EpollAddPidfd {
                epoll,
                pid,
                events: "in".to_string(),
            },
        )
        .await,
        "epoll_add_pidfd",
    )?;

    let conn = open_registered_socket(run, observer, peer).await?;
    expect_ok(
        run.send(
            observer,
            Command::EpollAddSocket {
                epoll,
                conn,
                events: "in".to_string(),
            },
        )
        .await,
        "epoll_add_socket",
    )?;
    expect_sent(
        run.send(
            observer,
            Command::NetSend {
                conn,
                data: "pidfd-socket-wakeup".to_string(),
            },
        )
        .await,
    )?;
    expect_ok(run.send(observer, Command::Kill { pid }).await, "kill")?;

    let mut events = epoll_wait(run, observer, epoll, 5000, 4).await?;
    let mut saw_pid = events
        .iter()
        .any(|event| event.kind == "pidfd" && event.id == u64::from(pid) && has_in(event));
    let mut saw_socket = events
        .iter()
        .any(|event| event.kind == "socket" && event.id == conn && has_in(event));
    // The kernel may deliver the pidfd EPOLLIN slightly after Kill returns
    // (depending on scheduler timing), so loop epoll_wait a few more times
    // until both events are observed or we hit the cumulative timeout.
    for _ in 0..5 {
        if saw_pid && saw_socket {
            break;
        }
        let more = epoll_wait(run, observer, epoll, 2000, 4).await?;
        if more.is_empty() {
            break;
        }
        saw_pid |= more
            .iter()
            .any(|event| event.kind == "pidfd" && event.id == u64::from(pid) && has_in(event));
        saw_socket |= more
            .iter()
            .any(|event| event.kind == "socket" && event.id == conn && has_in(event));
        events.extend(more);
    }
    if saw_pid && saw_socket {
        Ok(format!(
            "pidfd pid={pid} and socket conn={conn} events={events:?}"
        ))
    } else {
        Err(format!(
            "missing pidfd/socket readiness pid={pid} conn={conn} events={events:?}"
        ))
    }
}

async fn run_multi_socket(
    run: &mut RunContext<'_>,
    observer: &super::agents::AgentHandle,
    peer: &super::agents::AgentHandle,
) -> Result<String, String> {
    let epoll = epoll_open(run, observer).await?;
    let mut conns = Vec::new();
    for i in 0..4 {
        let conn = open_registered_socket(run, observer, peer).await?;
        expect_ok(
            run.send(
                observer,
                Command::EpollAddSocket {
                    epoll,
                    conn,
                    events: "in".to_string(),
                },
            )
            .await,
            "epoll_add_socket",
        )?;
        conns.push(conn);
        expect_sent(
            run.send(
                observer,
                Command::NetSend {
                    conn,
                    data: format!("multi-socket-{i}"),
                },
            )
            .await,
        )?;
    }
    let mut events = epoll_wait(run, observer, epoll, 5000, 8).await?;
    let mut expected = conns.clone();
    expected.sort_unstable();
    let mut ready = ready_socket_ids(&events);
    for _ in 0..5 {
        if ready == expected {
            break;
        }
        let more = epoll_wait(run, observer, epoll, 2000, 8).await?;
        if more.is_empty() {
            break;
        }
        events.extend(more);
        ready = ready_socket_ids(&events);
    }
    if ready == expected {
        Ok(format!(
            "all sockets ready conns={conns:?} events={events:?}"
        ))
    } else {
        Err(format!(
            "socket readiness mismatch expected={expected:?} ready={ready:?} events={events:?}"
        ))
    }
}

async fn run_eventfd_wakeup(
    run: &mut RunContext<'_>,
    observer: &super::agents::AgentHandle,
) -> Result<String, String> {
    let epoll = epoll_open(run, observer).await?;
    let eventfd_id = match run
        .send(
            observer,
            Command::EventfdOpen {
                initval: 0,
                flags: "nonblock".to_string(),
            },
        )
        .await
    {
        Response::EventfdHandle { id } => id,
        other => return Err(format!("expected EventfdHandle, got {other:?}")),
    };
    expect_ok(
        run.send(
            observer,
            Command::EpollAddEventfd {
                epoll,
                eventfd_id,
                events: "in".to_string(),
            },
        )
        .await,
        "epoll_add_eventfd",
    )?;
    // Layer-1 local eventfd stub: this branch has no cross-agent fd-passing
    // registry yet, so the writer uses the same agent-owned registry entry.
    expect_ok(
        run.send(
            observer,
            Command::EventfdWrite {
                id: eventfd_id,
                value: 1,
            },
        )
        .await,
        "eventfd_write",
    )?;
    let events = epoll_wait(run, observer, epoll, 5000, 4).await?;
    if events
        .iter()
        .any(|event| event.kind == "eventfd" && event.id == eventfd_id && has_in(event))
    {
        Ok(format!("eventfd ready id={eventfd_id} events={events:?}"))
    } else {
        Err(format!(
            "missing eventfd readiness id={eventfd_id} events={events:?}"
        ))
    }
}

async fn run_timeout_zero(
    run: &mut RunContext<'_>,
    observer: &super::agents::AgentHandle,
) -> Result<String, String> {
    let epoll = epoll_open(run, observer).await?;
    let events = epoll_wait(run, observer, epoll, 0, 4).await?;
    if events.is_empty() {
        Ok("idle epoll returned no events".to_string())
    } else {
        Err(format!("idle epoll returned unexpected events {events:?}"))
    }
}

async fn run_edge_trigger(
    run: &mut RunContext<'_>,
    observer: &super::agents::AgentHandle,
    peer: &super::agents::AgentHandle,
) -> Result<String, String> {
    let epoll = epoll_open(run, observer).await?;
    let conn = open_registered_socket(run, observer, peer).await?;
    expect_ok(
        run.send(
            observer,
            Command::EpollAddSocket {
                epoll,
                conn,
                events: "in|et".to_string(),
            },
        )
        .await,
        "epoll_add_socket_et",
    )?;
    for payload in ["edge-one", "edge-two"] {
        expect_sent(
            run.send(
                observer,
                Command::NetSend {
                    conn,
                    data: payload.to_string(),
                },
            )
            .await,
        )?;
    }
    let first = epoll_wait(run, observer, epoll, 5000, 8).await?;
    let first_count = first
        .iter()
        .filter(|event| event.kind == "socket" && event.id == conn && has_in(event))
        .count();
    let second = epoll_wait(run, observer, epoll, 0, 8).await?;
    let second_count = second
        .iter()
        .filter(|event| event.kind == "socket" && event.id == conn && has_in(event))
        .count();
    if first_count == 1 && second_count == 0 {
        Ok(format!(
            "edge-trigger coalesced first={first:?} second={second:?}"
        ))
    } else {
        Err(format!(
            "edge-trigger mismatch first_count={first_count} second_count={second_count} first={first:?} second={second:?}"
        ))
    }
}

async fn open_registered_socket(
    run: &mut RunContext<'_>,
    observer: &super::agents::AgentHandle,
    peer: &super::agents::AgentHandle,
) -> Result<u64, String> {
    let listen = run
        .send(
            peer,
            Command::NetListen {
                port: 0,
                pre_bind_options: vec![],
            },
        )
        .await;
    let port = expect_listening_port(&listen, 0)?;
    match run
        .send(
            observer,
            Command::NetOpen {
                addr: format!("127.0.0.1:{port}"),
            },
        )
        .await
    {
        Response::Opened { conn } => Ok(conn),
        other => Err(format!("expected Opened for port {port}, got {other:?}")),
    }
}

async fn epoll_open(
    run: &mut RunContext<'_>,
    observer: &super::agents::AgentHandle,
) -> Result<u64, String> {
    match run.send(observer, Command::EpollCreate).await {
        Response::EpollHandle { id } => Ok(id),
        other => Err(format!("expected EpollHandle, got {other:?}")),
    }
}

async fn epoll_wait(
    run: &mut RunContext<'_>,
    observer: &super::agents::AgentHandle,
    epoll: u64,
    timeout_ms: i32,
    max_events: u32,
) -> Result<Vec<EpollEvent>, String> {
    match run
        .send(
            observer,
            Command::EpollWait {
                epoll,
                timeout_ms,
                max_events,
            },
        )
        .await
    {
        Response::EpollEvents { events } => Ok(events),
        other => Err(format!("expected EpollEvents, got {other:?}")),
    }
}

#[allow(clippy::needless_pass_by_value)] // keep call sites linear around awaited responses
fn expect_ok(resp: Response, op: &str) -> Result<(), String> {
    if ok_without_data(&resp) || matches!(resp, Response::Sent) {
        Ok(())
    } else {
        Err(format!("{op}: expected Ok without data, got {resp:?}"))
    }
}

fn expect_sent(resp: Response) -> Result<(), String> {
    match resp {
        Response::Sent => Ok(()),
        other => Err(format!("expected Sent, got {other:?}")),
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
