// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PR (Port Router) tests — verify that TCP port registrations survive
//! fork/exec of child processes.
//!
//! These tests exercise the pattern from the VS Code bootstrap:
//! a process listens on a TCP port, then forks child processes (which
//! inherit the listen socket fd), and the children exit. Connections
//! to the port must still succeed after the children die.
//!
//! The port router ownership fix (`worker_id` tracking) prevents a
//! re-registering child from deregistering the parent's route on exit.

// TODO(#15): convert legacy wildcard enum dispatch in this file to explicit arms.
#![allow(clippy::wildcard_enum_match_arm)]

use serde::{Deserialize, Serialize};

use super::agents::{AgentHandle, AgentName, EphemeralHandle, SpawnKind};
use super::registry::Registry;
use super::run_context::RunContext;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::socket::TcpSocket;
use crate::protocol::{Command, Response};
use crate::register_handler;

const FORK_SEQUENCE: HandlerToken<ForkSequenceArgs, DetailOut> =
    HandlerToken::new("port_router.fork_sequence");
const START_LISTENER: HandlerToken<StartListenerArgs, ListenerOut> =
    HandlerToken::new("port_router.start_listener");
const CONNECT_ECHO: HandlerToken<ConnectArgs, DetailOut> =
    HandlerToken::new("port_router.connect_echo");
const CHILD_LISTEN_ONCE: HandlerToken<ChildListenArgs, DetailOut> =
    HandlerToken::new("port_router.child_listen_once");

const TRUE_ARGV: &[&str] = &["true"];

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ForkSequenceArgs {
    port: u16,
    exec_count: u32,
    pre_connect: Option<String>,
    post_connect: Option<String>,
    background_sleep: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct StartListenerArgs {
    port: u16,
    expected_connections: u32,
    exec_count: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ConnectArgs {
    port: u16,
    data: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ChildListenArgs {
    port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
struct ListenerOut {
    port: u16,
    detail: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct DetailOut {
    detail: String,
}

pub(crate) fn register_port_router(reg: &mut Registry<'_>) {
    register_handler!(FORK_SEQUENCE, handle_fork_sequence);
    register_handler!(START_LISTENER, handle_start_listener);
    register_handler!(CONNECT_ECHO, handle_connect_echo);
    register_handler!(CHILD_LISTEN_ONCE, handle_child_listen_once);

    register_fork_port_tests(reg);
    register_fork_multi_tests(reg);
    register_fork_cross_tests(reg);
    register_fork_interleave_tests(reg);
    register_fork_background_tests(reg);
    register_fork_listen_inherit_tests(reg);
    register_child_listen_cross_connect_tests(reg);
    register_depth_axis_tests(reg);
}

fn register_fork_port_tests(reg: &mut Registry<'_>) {
    for &agent in &[AgentName::Dpg1, AgentName::Dpg2] {
        let port = if agent == AgentName::Dpg1 {
            18200
        } else {
            18201
        };

        register_sequence_test(
            reg,
            format!("PR.fork_exec.{agent}"),
            agent,
            ForkSequenceArgs {
                port,
                exec_count: 1,
                pre_connect: None,
                post_connect: None,
                background_sleep: false,
            },
        );

        register_sequence_test(
            reg,
            format!("PR.fork_single.{agent}"),
            agent,
            ForkSequenceArgs {
                port,
                exec_count: 1,
                pre_connect: None,
                post_connect: Some("after_fork".into()),
                background_sleep: false,
            },
        );
    }
}

fn register_fork_multi_tests(reg: &mut Registry<'_>) {
    register_sequence_test(
        reg,
        "PR.fork_multi_x5",
        AgentName::Dpg1,
        ForkSequenceArgs {
            port: 18210,
            exec_count: 5,
            pre_connect: None,
            post_connect: Some("after_5_forks".into()),
            background_sleep: false,
        },
    );
}

fn register_fork_cross_tests(reg: &mut Registry<'_>) {
    register_cross_connect_test(
        reg,
        "PR.fork_cross",
        AgentName::Dpg1,
        AgentName::Dpg2,
        18220,
        3,
        "cross_after_fork",
        "B",
    );
}

fn register_fork_interleave_tests(reg: &mut Registry<'_>) {
    register_sequence_test(
        reg,
        "PR.fork_interleave",
        AgentName::Dpg1,
        ForkSequenceArgs {
            port: 18230,
            exec_count: 1,
            pre_connect: Some("pre_fork".into()),
            post_connect: Some("post_fork".into()),
            background_sleep: false,
        },
    );
}

fn register_fork_background_tests(reg: &mut Registry<'_>) {
    register_sequence_test(
        reg,
        "PR.fork_bg",
        AgentName::Dpg1,
        ForkSequenceArgs {
            port: 18240,
            exec_count: 3,
            pre_connect: None,
            post_connect: Some("after_bg_fork".into()),
            background_sleep: true,
        },
    );
}

fn register_sequence_test(
    reg: &mut Registry<'_>,
    id: impl Into<String>,
    agent: AgentName,
    args: ForkSequenceArgs,
) {
    let agent_label = agent.to_string();
    reg.test("stress", "port_router", id)
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(agent);
            let args = args.clone();
            let agent_label = agent_label.clone();
            Box::new(move |run| {
                Box::pin(async move {
                    match run.send_named_typed(&handle, &FORK_SEQUENCE, args).await {
                        Ok(out) => super::TestOutcome::new(&agent_label, true, out.detail),
                        Err(e) => super::TestOutcome::new(&agent_label, false, e),
                    }
                })
            })
        });
}

#[allow(clippy::too_many_arguments)]
fn register_cross_connect_test(
    reg: &mut Registry<'_>,
    id: impl Into<String>,
    listener_agent: AgentName,
    connector_agent: AgentName,
    port: u16,
    exec_count: u32,
    data: &'static str,
    outcome_agent: &'static str,
) {
    reg.test("stress", "port_router", id)
        .timeout(180)
        .build(move |cx| {
            let listener = cx.require(listener_agent);
            let connector = cx.require(connector_agent);
            Box::new(move |run| {
                Box::pin(async move {
                    let started = run
                        .send_named_typed(
                            &listener,
                            &START_LISTENER,
                            StartListenerArgs {
                                port,
                                expected_connections: 1,
                                exec_count,
                            },
                        )
                        .await;
                    let listener_out = match started {
                        Ok(out) => out,
                        Err(e) => return super::TestOutcome::new(outcome_agent, false, e),
                    };
                    match run
                        .send_named_typed(
                            &connector,
                            &CONNECT_ECHO,
                            ConnectArgs {
                                port: listener_out.port,
                                data: data.into(),
                            },
                        )
                        .await
                    {
                        Ok(out) => super::TestOutcome::new(outcome_agent, true, out.detail),
                        Err(e) => super::TestOutcome::new(outcome_agent, false, e),
                    }
                })
            })
        });
}

#[allow(clippy::too_many_lines)]
fn register_fork_listen_inherit_tests(reg: &mut Registry<'_>) {
    reg.test("stress", "port_router", "PR.listen_inherit_self")
        .timeout(180)
        .build(|cx| {
            let handle_a = cx.require(AgentName::Dpg1);
            let li_c = cx.declare_ephemeral(
                AgentName::Dpg1,
                "LI_C",
                SpawnKind::Fork {
                    binary: "self",
                    inherit_listen_ports: vec![],
                },
            );
            Box::new(move |run| {
                let li_c = li_c.clone();
                Box::pin(async move {
                    let port = 18300;
                    let child_port = port + 100;
                    let started = run
                        .send_named_typed(
                            &handle_a,
                            &START_LISTENER,
                            StartListenerArgs {
                                port,
                                expected_connections: 1,
                                exec_count: 0,
                            },
                        )
                        .await;
                    if let Err(e) = started {
                        return super::TestOutcome::new("A", false, e);
                    }
                    if let Err(e) = spawn_and_probe_child(run, &li_c, child_port).await {
                        return super::TestOutcome::new("A", false, e);
                    }
                    connect_outcome(run, &handle_a, port, "inherit_self", "A").await
                })
            })
        });

    reg.test("stress", "port_router", "PR.listen_inherit_cross")
        .timeout(180)
        .build(|cx| {
            let handle_a = cx.require(AgentName::Dpg1);
            let handle_b = cx.require(AgentName::Dpg2);
            let li_c2 = cx.declare_ephemeral(
                AgentName::Dpg1,
                "LI_C2",
                SpawnKind::Fork {
                    binary: "self",
                    inherit_listen_ports: vec![],
                },
            );
            Box::new(move |run| {
                let li_c2 = li_c2.clone();
                Box::pin(async move {
                    let port = 18301;
                    let child_port = port + 100;
                    let started = run
                        .send_named_typed(
                            &handle_a,
                            &START_LISTENER,
                            StartListenerArgs {
                                port,
                                expected_connections: 1,
                                exec_count: 0,
                            },
                        )
                        .await;
                    if let Err(e) = started {
                        return super::TestOutcome::new("B", false, e);
                    }
                    if let Err(e) = spawn_and_probe_child(run, &li_c2, child_port).await {
                        return super::TestOutcome::new("B", false, e);
                    }
                    connect_outcome(run, &handle_b, port, "inherit_cross", "B").await
                })
            })
        });
}

fn register_child_listen_cross_connect_tests(reg: &mut Registry<'_>) {
    reg.test("stress", "port_router", "PR.child_listen_cross")
        .timeout(180)
        .build(|cx| {
            let handle_b = cx.require(AgentName::Dpg2);
            let cl_c_nonpie = cx.declare_ephemeral(
                AgentName::Dpg1,
                "CL_C",
                SpawnKind::Fork {
                    binary: "nonpie",
                    inherit_listen_ports: vec![],
                },
            );
            let cl_c_pie = cx.declare_ephemeral(
                AgentName::Dpg1,
                "CL_C",
                SpawnKind::Fork {
                    binary: "self",
                    inherit_listen_ports: vec![],
                },
            );
            Box::new(move |run| {
                let cl_c_nonpie = cl_c_nonpie.clone();
                let cl_c_pie = cl_c_pie.clone();
                Box::pin(async move {
                    let port = 18500;
                    let cl_c = match spawn_child_with_fallback(run, cl_c_nonpie, cl_c_pie).await {
                        Ok(child) => child,
                        Err(e) => return super::TestOutcome::new("B", false, e),
                    };
                    if let Err(e) = forward_child_listen(run, &cl_c, port).await {
                        return super::TestOutcome::new("B", false, e);
                    }
                    connect_outcome(run, &handle_b, port, "child_listen_test", "B").await
                })
            })
        });
}

fn register_depth_axis_tests(reg: &mut Registry<'_>) {
    register_cross_connect_test(
        reg,
        "PR.fork_child_parent",
        AgentName::Dpg1,
        AgentName::Dpg1Dpg1,
        18510,
        1,
        "child_parent_after_fork",
        "AA->A",
    );

    reg.test("stress", "port_router", "PR.child_listen_depth2")
        .timeout(180)
        .build(|cx| {
            let connector = cx.require(AgentName::Dpg1DngDpg);
            let child = cx.declare_ephemeral(
                AgentName::Dpg1Dng,
                "CL_dpg1_dng",
                SpawnKind::Fork {
                    binary: "self",
                    inherit_listen_ports: vec![],
                },
            );
            Box::new(move |run| {
                let child = child.clone();
                Box::pin(async move {
                    let port = 18521;
                    let spawn_resp = run.spawn_ephemeral(&child).await;
                    if !matches!(&spawn_resp, Response::Ok { .. }) {
                        return super::TestOutcome::new(
                            "dpg1_dng_dpg->CL_dpg1_dng",
                            false,
                            format!("fork failed: {spawn_resp:?}"),
                        );
                    }
                    if let Err(e) = forward_child_listen(run, &child, port).await {
                        return super::TestOutcome::new("dpg1_dng_dpg->CL_dpg1_dng", false, e);
                    }
                    connect_outcome(
                        run,
                        &connector,
                        port,
                        "child_listen_depth2",
                        "dpg1_dng_dpg->CL_dpg1_dng",
                    )
                    .await
                })
            })
        });
}

async fn connect_outcome(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    port: u16,
    data: &'static str,
    agent: &'static str,
) -> super::TestOutcome {
    match run
        .send_named_typed(
            handle,
            &CONNECT_ECHO,
            ConnectArgs {
                port,
                data: data.into(),
            },
        )
        .await
    {
        Ok(out) => super::TestOutcome::new(agent, true, out.detail),
        Err(e) => super::TestOutcome::new(agent, false, e),
    }
}

async fn spawn_and_probe_child(
    run: &mut RunContext<'_>,
    child: &EphemeralHandle,
    child_port: u16,
) -> Result<(), String> {
    let resp = run.spawn_ephemeral(child).await;
    if !super::ok_spawned_response(&resp) {
        return Err(format!("fork failed: {resp:?}"));
    }
    forward_child_listen(run, child, child_port).await
}

async fn spawn_child_with_fallback(
    run: &mut RunContext<'_>,
    nonpie: EphemeralHandle,
    pie: EphemeralHandle,
) -> Result<EphemeralHandle, String> {
    let resp = run.spawn_ephemeral(&nonpie).await;
    if super::ok_spawned_response(&resp) {
        return Ok(nonpie);
    }
    let resp = run.spawn_ephemeral(&pie).await;
    if super::ok_spawned_response(&resp) {
        Ok(pie)
    } else {
        Err(format!("fork failed: {resp:?}"))
    }
}

async fn forward_child_listen(
    run: &mut RunContext<'_>,
    child: &EphemeralHandle,
    port: u16,
) -> Result<(), String> {
    let args = serde_json::to_value(ChildListenArgs { port }).map_err(|e| e.to_string())?;
    match run
        .forward(
            child,
            Command::Run {
                handler: CHILD_LISTEN_ONCE.name().to_string(),
                args,
            },
        )
        .await
    {
        Response::Result { ok: true, .. } => Ok(()),
        Response::Result {
            ok: false, error, ..
        } => Err(error.unwrap_or_else(|| "child listen handler failed".to_string())),
        other => Err(format!("child listen expected Result, got {other:?}")),
    }
}

async fn handle_fork_sequence(
    args: ForkSequenceArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let expected_connections =
        u32::from(args.pre_connect.is_some()) + u32::from(args.post_connect.is_some());
    let port = start_detached_echo_server(args.port, expected_connections)?;

    let mut details = Vec::new();
    if let Some(data) = args.pre_connect {
        connect_expect(port, &data)?;
        details.push(format!("pre={data}"));
    }

    let mut background = if args.background_sleep {
        Some(std::process::Command::new("sleep").arg("30").spawn()?)
    } else {
        None
    };

    for i in 0..args.exec_count {
        run_child(TRUE_ARGV).map_err(|e| HandlerError(format!("child {i} failed: {}", e.0)))?;
    }

    if let Some(data) = args.post_connect {
        connect_expect(port, &data)?;
        details.push(format!("post={data}"));
    }

    if let Some(child) = background.as_mut() {
        let pid = child.id();
        // SAFETY: pid was returned by the child process we just spawned.
        unsafe { libc::kill(pid.cast_signed() as libc::pid_t, libc::SIGKILL) };
        let _ = child.wait();
        details.push(format!("bg_pid={pid}"));
    }

    Ok(DetailOut {
        detail: format!(
            "port={port} exec_count={} {}",
            args.exec_count,
            details.join(" ")
        ),
    })
}

async fn handle_start_listener(
    args: StartListenerArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ListenerOut, HandlerError> {
    let port = start_detached_echo_server(args.port, args.expected_connections)?;
    for i in 0..args.exec_count {
        run_child(TRUE_ARGV).map_err(|e| HandlerError(format!("child {i} failed: {}", e.0)))?;
    }
    Ok(ListenerOut {
        port,
        detail: format!(
            "port={port} expected_connections={} exec_count={}",
            args.expected_connections, args.exec_count
        ),
    })
}

async fn handle_connect_echo(
    args: ConnectArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    connect_expect(args.port, &args.data)?;
    Ok(DetailOut {
        detail: format!("connected port={} data={:?}", args.port, args.data),
    })
}

async fn handle_child_listen_once(
    args: ChildListenArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let port = start_detached_echo_server(args.port, 1)?;
    Ok(DetailOut {
        detail: format!("child listening port={port}"),
    })
}

fn start_detached_echo_server(port: u16, expected_connections: u32) -> Result<u16, HandlerError> {
    let listener = TcpSocket::new_tcp_listen(port)?;
    let actual_port = listener.local_port()?;
    if expected_connections == 0 {
        return Ok(actual_port);
    }
    std::thread::spawn(move || {
        for _ in 0..expected_connections {
            let Ok(conn) = listener.accept() else {
                return;
            };
            let _ = conn.echo_to_eof();
        }
    });
    Ok(actual_port)
}

fn connect_expect(port: u16, data: &str) -> Result<(), HandlerError> {
    let conn = TcpSocket::connect_loopback(port)?;
    conn.send_all(data.as_bytes())?;
    let echo = conn.recv_exact_string(data.len())?;
    if echo == data {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "expected echo {data:?} from port {port}, got {echo:?}"
        )))
    }
}

fn run_child(argv: &[&str]) -> Result<(), HandlerError> {
    let (program, child_args) = argv
        .split_first()
        .ok_or_else(|| HandlerError("empty argv".to_string()))?;
    let status = std::process::Command::new(program)
        .args(child_args)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(HandlerError(format!("{argv:?} exited with {status}")))
    }
}
