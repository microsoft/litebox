// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Stateful TCP protocol tests.
//!
//! TCS exercises multi-step connection state through handler-dispatched
//! raw socket operations instead of the legacy `Net*` wire commands.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::socket::TcpSocket;
use crate::register_handler;

use super::TestOutcome;
use super::agents::{AgentHandle, AgentName};
use super::registry::Registry;
use super::run_context::RunContext;

#[derive(Clone, Copy)]
struct AxisCase {
    name: &'static str,
    server: AgentName,
    client: AgentName,
}

const AXES: &[AxisCase] = &[
    AxisCase {
        name: "in_process",
        server: AgentName::Dpg1,
        client: AgentName::Dpg1,
    },
    AxisCase {
        name: "parent_child",
        server: AgentName::Dpg1Dpg1,
        client: AgentName::Dpg1,
    },
    AxisCase {
        name: "child_parent",
        server: AgentName::Dpg1,
        client: AgentName::Dpg1Dpg1,
    },
    AxisCase {
        name: "sibling",
        server: AgentName::Dpg1Dpg2,
        client: AgentName::Dpg1Dpg1,
    },
    AxisCase {
        name: "depth2",
        server: AgentName::Dpg1Dpg1Dpg1,
        client: AgentName::Dpg1Dpg1Dpg2,
    },
];

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ServerArgs {
    connections: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct InProcessArgs {
    client: ClientScenario,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ClientArgs {
    port: u16,
    scenario: ClientScenario,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
enum ClientScenario {
    WriteShutdownReadEof { payload: String },
    SendRecvSend { first: String, second: String },
    PartialRecv { payload: String, first_len: usize },
    HalfcloseThenReconnect { first: String, second: String },
}

impl ClientScenario {
    fn connections(&self) -> u32 {
        match self {
            Self::HalfcloseThenReconnect { .. } => 2,
            Self::WriteShutdownReadEof { .. }
            | Self::SendRecvSend { .. }
            | Self::PartialRecv { .. } => 1,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct DetailOut {
    detail: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ServerOut {
    port: u16,
    detail: String,
}

const SERVER: HandlerToken<ServerArgs, ServerOut> = HandlerToken::new("tcp_state.server");
const CLIENT: HandlerToken<ClientArgs, DetailOut> = HandlerToken::new("tcp_state.client");
const IN_PROCESS: HandlerToken<InProcessArgs, DetailOut> =
    HandlerToken::new("tcp_state.in_process");
const CONN_ID_UNIQUE: HandlerToken<(), DetailOut> = HandlerToken::new("tcp_state.conn_id_unique");

pub(crate) fn register_tcp_state_tests(reg: &mut Registry<'_>) {
    register_handler!(SERVER, handle_server);
    register_handler!(CLIENT, handle_client);
    register_handler!(IN_PROCESS, handle_in_process);
    register_handler!(CONN_ID_UNIQUE, handle_conn_id_unique);

    register_write_shutdown_read_eof(reg);
    register_send_recv_send(reg);
    register_partial_recv(reg);
    register_halfclose_then_reconnect(reg);
    register_conn_id_unique(reg);
}

fn register_write_shutdown_read_eof(reg: &mut Registry<'_>) {
    for axis in AXES {
        let scenario = ClientScenario::WriteShutdownReadEof {
            payload: format!("TCS_EOF_{}", axis.name),
        };
        register_axis_case(reg, axis, "TCS.write_shutdown_read_eof", scenario);
    }
}

fn register_send_recv_send(reg: &mut Registry<'_>) {
    for axis in AXES {
        let scenario = ClientScenario::SendRecvSend {
            first: format!("TCS_X_{}", axis.name),
            second: format!("TCS_Y_{}", axis.name),
        };
        register_axis_case(reg, axis, "TCS.send_recv_send", scenario);
    }
}

fn register_partial_recv(reg: &mut Registry<'_>) {
    for axis in AXES {
        let scenario = ClientScenario::PartialRecv {
            payload: format!("TCS_PARTIAL_{}_ABCDEFGHIJK", axis.name),
            first_len: 11,
        };
        register_axis_case(reg, axis, "TCS.partial_recv", scenario);
    }
}

fn register_halfclose_then_reconnect(reg: &mut Registry<'_>) {
    for axis in AXES {
        let scenario = ClientScenario::HalfcloseThenReconnect {
            first: format!("TCS_FIRST_{}", axis.name),
            second: format!("TCS_SECOND_{}", axis.name),
        };
        register_axis_case(reg, axis, "TCS.halfclose_then_reconnect", scenario);
    }
}

fn register_axis_case(
    reg: &mut Registry<'_>,
    axis: &AxisCase,
    id_prefix: &'static str,
    scenario: ClientScenario,
) {
    let id = format!("{id_prefix}.{}", axis.name);
    let server_label = axis.server.to_string();
    let client_label = axis.client.to_string();
    let agent_label = format!("{server_label}<-{client_label}");
    if axis.server == axis.client {
        reg.test("matrix", "tcp_state", id)
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(axis.server);
                let scenario = scenario.clone();
                let agent_label = agent_label.clone();
                Box::new(move |run| {
                    Box::pin(async move {
                        match run
                            .send_named_typed(
                                &handle,
                                &IN_PROCESS,
                                InProcessArgs { client: scenario },
                            )
                            .await
                        {
                            Ok(out) => TestOutcome::new(&agent_label, true, out.detail),
                            Err(e) => TestOutcome::new(&agent_label, false, e),
                        }
                    })
                })
            });
    } else {
        reg.test("matrix", "tcp_state", id)
            .timeout(60)
            .build(move |cx| {
                let server = cx.require(axis.server);
                let client = cx.require(axis.client);
                let scenario = scenario.clone();
                let agent_label = agent_label.clone();
                Box::new(move |run| {
                    Box::pin(async move {
                        match run_cross_agent_case(run, &server, &client, scenario).await {
                            Ok(detail) => TestOutcome::new(&agent_label, true, detail),
                            Err(e) => TestOutcome::new(&agent_label, false, e),
                        }
                    })
                })
            });
    }
}

fn register_conn_id_unique(reg: &mut Registry<'_>) {
    reg.single_agent_handler_test(
        "matrix",
        "tcp_state",
        "TCS.conn_id_unique.rapid_open_close",
        AgentName::Dpg1,
        &CONN_ID_UNIQUE,
        detail_out,
    );
}

pub(crate) async fn run_write_shutdown_read_eof_case(
    run: &mut RunContext<'_>,
    server: &AgentHandle,
    client: &AgentHandle,
    server_label: &str,
    client_label: &str,
    payload: &str,
) -> TestOutcome {
    let agent = format!("{server_label}<-{client_label}");
    let scenario = ClientScenario::WriteShutdownReadEof {
        payload: payload.to_string(),
    };
    match run_cross_agent_case(run, server, client, scenario).await {
        Ok(detail) => TestOutcome::new(&agent, true, detail),
        Err(e) => TestOutcome::new(&agent, false, e),
    }
}

async fn handle_server(
    args: ServerArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ServerOut, HandlerError> {
    let listener = TcpSocket::new_tcp_listen(0)?;
    let port = listener.local_port()?;
    std::thread::spawn(move || {
        for _ in 0..args.connections {
            let Ok(conn) = listener.accept() else {
                return;
            };
            if conn.echo_to_eof().is_err() {
                return;
            }
        }
    });
    Ok(ServerOut {
        port,
        detail: format!("port={port} expected_connections={}", args.connections),
    })
}

async fn handle_client(
    args: ClientArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let first = TcpSocket::connect_loopback(args.port)?;
    run_client_scenario(args.scenario, first, args.port)
}

async fn handle_in_process(
    args: InProcessArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    run_in_process(args.client)
}

async fn handle_conn_id_unique(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let iterations = 25;
    let listener = TcpSocket::new_tcp_listen(0)?;
    let port = listener.local_port()?;
    let server = std::thread::spawn(move || -> Result<u32, std::io::Error> {
        let mut accepted = 0;
        for _ in 0..iterations {
            let conn = listener.accept()?;
            accepted += 1;
            let _ = conn.recv_to_end_string()?;
        }
        Ok(accepted)
    });

    let mut seen = HashSet::new();
    for conn in 1..=iterations {
        let sock = TcpSocket::connect_loopback(port)?;
        if !seen.insert(conn) {
            return Err(HandlerError(format!(
                "conn id {conn} reused at iteration {}",
                conn - 1
            )));
        }
        drop(sock);
    }
    let accepted = join_server(server)?;
    Ok(DetailOut {
        detail: format!("{} unique ids; accepted={accepted}", seen.len()),
    })
}

async fn run_cross_agent_case(
    run: &mut RunContext<'_>,
    server: &AgentHandle,
    client: &AgentHandle,
    scenario: ClientScenario,
) -> Result<String, String> {
    let connections = scenario.connections();
    let server_out: ServerOut = run
        .send_named_typed(server, &SERVER, ServerArgs { connections })
        .await?;
    let client_out: DetailOut = run
        .send_named_typed(
            client,
            &CLIENT,
            ClientArgs {
                port: server_out.port,
                scenario,
            },
        )
        .await?;
    Ok(format!("{}; {}", client_out.detail, server_out.detail))
}

fn run_in_process(scenario: ClientScenario) -> Result<DetailOut, HandlerError> {
    let connections = scenario.connections();
    let listener = TcpSocket::new_tcp_listen(0)?;
    let port = listener.local_port()?;
    let server = std::thread::spawn(move || -> Result<u32, std::io::Error> {
        let mut accepted = 0;
        for _ in 0..connections {
            let conn = listener.accept()?;
            accepted += 1;
            conn.echo_to_eof()?;
        }
        Ok(accepted)
    });
    let first = TcpSocket::connect_loopback(port)?;
    let out = run_client_scenario(scenario, first, port)?;
    let accepted = join_server(server)?;
    Ok(DetailOut {
        detail: format!("{}; accepted={accepted}", out.detail),
    })
}

fn run_client_scenario(
    scenario: ClientScenario,
    first: TcpSocket,
    port: u16,
) -> Result<DetailOut, HandlerError> {
    let detail = match scenario {
        ClientScenario::WriteShutdownReadEof { payload } => {
            round_trip_to_eof(&first, &payload)?;
            format!("conn=1 payload={payload:?}")
        }
        ClientScenario::SendRecvSend { first: a, second } => {
            first.send_all(a.as_bytes())?;
            let first_echo = first.recv_exact_string(a.len())?;
            if first_echo != a {
                return Err(HandlerError(format!(
                    "first echo mismatch: expected {a:?}, got {first_echo:?}"
                )));
            }
            first.send_all(second.as_bytes())?;
            let second_echo = first.recv_exact_string(second.len())?;
            if second_echo != second {
                return Err(HandlerError(format!(
                    "second echo mismatch: expected {second:?}, got {second_echo:?}"
                )));
            }
            "conn=1 echoes exact".to_string()
        }
        ClientScenario::PartialRecv { payload, first_len } => {
            first.send_all(payload.as_bytes())?;
            let head = first.recv_exact_string(first_len)?;
            let rest = first.recv_exact_string(payload.len() - first_len)?;
            let combined = format!("{head}{rest}");
            if combined != payload {
                return Err(HandlerError(format!(
                    "partial continuity mismatch: expected {payload:?}, got {combined:?}"
                )));
            }
            format!("conn=1 split={first_len}+{}", rest.len())
        }
        ClientScenario::HalfcloseThenReconnect { first: a, second } => {
            round_trip_to_eof(&first, &a)?;
            drop(first);
            let second_conn = TcpSocket::connect_loopback(port)?;
            round_trip_to_eof(&second_conn, &second)?;
            "first_conn=1 second_conn=2".to_string()
        }
    };
    Ok(DetailOut { detail })
}

fn round_trip_to_eof(conn: &TcpSocket, payload: &str) -> Result<(), HandlerError> {
    conn.send_all(payload.as_bytes())?;
    conn.shutdown_write()?;
    let echo = conn.recv_to_end_string()?;
    if echo == payload {
        Ok(())
    } else {
        Err(HandlerError(format!(
            "expected exact echo {payload:?}, got {echo:?}"
        )))
    }
}

fn join_server(
    server: std::thread::JoinHandle<Result<u32, std::io::Error>>,
) -> Result<u32, HandlerError> {
    server
        .join()
        .map_err(|_| HandlerError("server thread panicked".to_string()))?
        .map_err(HandlerError::from)
}

fn detail_out(out: &DetailOut) -> Result<String, String> {
    if out.detail.is_empty() {
        Err("handler returned empty detail".to_string())
    } else {
        Ok(out.detail.clone())
    }
}
