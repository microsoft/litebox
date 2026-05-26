// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Stateful TCP protocol tests.
//!
//! Test families hosted here:
//! - `TCS.*` — multi-step connection state via handler-dispatched raw socket operations
//! - `THC.*` — TCP half-close / shutdown → EOF propagation
//! - `TLB.*` — TCP listener remains usable after a delayed accept window
//! - `XCONN.*` — cross-worker and same-worker first-connect correctness
//! - `FKLC.*` — fork-listen-close (VS Code CLI fd-inheritance pattern)

// TODO(#15): convert legacy wildcard enum dispatch in this file to explicit arms.
#![allow(clippy::wildcard_enum_match_arm)]

use std::collections::HashSet;
use std::os::fd::FromRawFd;
use std::time::Duration as StdDuration;

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::socket::TcpSocket;
use crate::protocol::{Command as InfraCommand, Response};
use crate::register_handler;

use super::TestOutcome;
use super::agents::{AgentHandle, AgentName, EphemeralHandle, SpawnKind};
use super::matrix::{
    EXEC, ExecArgs, NET_CONNECT, NET_LISTEN, NET_UNLISTEN, NetConnectArgs, NetListenArgs,
};
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

// ═══════════════════════════════════════════════════════════════════
// THC: TCP half-close EOF
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_tcp_halfclose_tests(reg: &mut Registry<'_>) {
    #[derive(Clone, Copy)]
    struct Case {
        id: &'static str,
        server: AgentName,
        client: AgentName,
        payload: &'static str,
    }

    let cases = [
        Case {
            id: "THC.halfclose.eof.same_agent",
            server: AgentName::Dpg1,
            client: AgentName::Dpg1,
            payload: "THC_SAME_AGENT_PAYLOAD",
        },
        Case {
            id: "THC.halfclose.eof.cross_agent",
            server: AgentName::Dpg1,
            client: AgentName::Dpg2,
            payload: "THC_CROSS_AGENT_PAYLOAD",
        },
        Case {
            id: "THC.halfclose.eof.sibling",
            server: AgentName::Dpg1Dpg1,
            client: AgentName::Dpg1Dpg2,
            payload: "THC_SIBLING_PAYLOAD",
        },
        Case {
            id: "THC.halfclose.eof.depth2",
            server: AgentName::Dpg1Dpg1Dpg1,
            client: AgentName::Dpg1Dpg1Dpg2,
            payload: "THC_DEPTH2_PAYLOAD",
        },
    ];

    for case in cases {
        let server_label = case.server.to_string();
        let client_label = case.client.to_string();
        reg.test("matrix", "tcp_halfclose", case.id)
            .timeout(60)
            .build(move |cx| {
                let server = cx.require(case.server);
                let client = cx.require(case.client);
                Box::new(move |run| {
                    let server_label = server_label.clone();
                    let client_label = client_label.clone();
                    let payload = case.payload.to_string();
                    Box::pin(async move {
                        run_write_shutdown_read_eof_case(
                            run,
                            &server,
                            &client,
                            &server_label,
                            &client_label,
                            &payload,
                        )
                        .await
                    })
                })
            });
    }
}

// ═══════════════════════════════════════════════════════════════════
// TLB: TCP listen remains usable after delayed accept window
// ═══════════════════════════════════════════════════════════════════

const TLB_DELAY_SECS: u64 = 1;

struct TlbListenBusyDef {
    name: &'static str,
    listener: AgentName,
    connector: AgentName,
}

async fn run_tlb_listen_busy_case(
    run: &mut RunContext<'_>,
    listener: &AgentHandle,
    connector: &AgentHandle,
    listener_name: &str,
    connector_name: &str,
    data: &str,
    delay_secs: u64,
) -> super::TestOutcome {
    let listen_resp = run
        .typed_or_error(listener, &NET_LISTEN, NetListenArgs { port: 0 })
        .await;
    let port = match super::expect_listening_port(&listen_resp, 0) {
        Ok(port) => port,
        Err(e) => {
            return super::TestOutcome::new(
                connector_name,
                false,
                format!("{listener_name} listen failed: {e}; resp={listen_resp:?}"),
            );
        }
    };

    let sleep_resp = run
        .typed_or_error(
            listener,
            &EXEC,
            ExecArgs {
                args: vec!["sleep".into(), delay_secs.to_string()],
                timeout_secs: Some(delay_secs + 5),
                stdin: None,
                background: false,
                env: vec![],
            },
        )
        .await;
    if !matches!(&sleep_resp, Response::ExecResult { exit_code: 0, .. }) {
        let _ = run
            .typed_or_error(listener, &NET_UNLISTEN, NetListenArgs { port })
            .await;
        return super::TestOutcome::new(
            connector_name,
            false,
            format!("{listener_name} delay failed: {sleep_resp:?}"),
        );
    }

    let conn_resp = run
        .typed_or_error(
            connector,
            &NET_CONNECT,
            NetConnectArgs {
                addr: format!("127.0.0.1:{port}"),
                data: data.to_string(),
            },
        )
        .await;
    let _ = run
        .typed_or_error(listener, &NET_UNLISTEN, NetListenArgs { port })
        .await;
    let pass = matches!(&conn_resp, Response::Connected { echo } if echo == data);
    super::TestOutcome::new(
        connector_name,
        pass,
        format!(
            "listener={listener_name} connector={connector_name} delay={delay_secs}s {conn_resp:?}"
        ),
    )
}

pub(crate) fn register_tcp_listen_busy_tests(reg: &mut Registry<'_>) {
    let defs = [
        TlbListenBusyDef {
            name: "same_agent",
            listener: AgentName::Dpg1,
            connector: AgentName::Dpg1,
        },
        TlbListenBusyDef {
            name: "parent_child",
            listener: AgentName::Dpg1,
            connector: AgentName::Dpg1Dpg1,
        },
        TlbListenBusyDef {
            name: "child_parent",
            listener: AgentName::Dpg1Dpg1,
            connector: AgentName::Dpg1,
        },
        TlbListenBusyDef {
            name: "sibling",
            listener: AgentName::Dpg1Dpg1,
            connector: AgentName::Dpg1Dpg2,
        },
        TlbListenBusyDef {
            name: "depth2",
            listener: AgentName::Dpg1Dpg1Dpg1,
            connector: AgentName::Dpg1Dpg1Dpg2,
        },
    ];

    for def in defs {
        let listener_name = def.listener.to_string();
        let connector_name = def.connector.to_string();
        let data = format!("TLB_{}", def.name);
        reg.test(
            "xworker",
            "tcp_listen_busy",
            format!("TLB.listen_busy.{}", def.name),
        )
        .timeout(60)
        .build(move |cx| {
            let listener = cx.require(def.listener);
            let connector = cx.require(def.connector);
            Box::new(move |run| {
                let listener_name = listener_name.clone();
                let connector_name = connector_name.clone();
                let data = data.clone();
                Box::pin(async move {
                    run_tlb_listen_busy_case(
                        run,
                        &listener,
                        &connector,
                        &listener_name,
                        &connector_name,
                        &data,
                        TLB_DELAY_SECS,
                    )
                    .await
                })
            })
        });
    }
}

// ═══════════════════════════════════════════════════════════════════
// XCONN: cross-worker TCP — first connection must succeed
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_cross_worker_first_connect_tests(reg: &mut Registry<'_>) {
    // XCONN.cross_first: A listens, B connects — first attempt must succeed.
    reg.test(
        "xworker",
        "cross_worker_first_connect",
        "XCONN.cross_first".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let handle_a = cx.require(AgentName::Dpg1);
        let handle_b = cx.require(AgentName::Dpg2);
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19900u16;
                let listen_resp = run
                    .typed_or_error(&handle_a, &NET_LISTEN, NetListenArgs { port })
                    .await;
                if super::expect_listening_port(&listen_resp, port).is_err() {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let conn_resp = run
                    .typed_or_error(
                        &handle_b,
                        &NET_CONNECT,
                        NetConnectArgs {
                            addr: format!("127.0.0.1:{port}"),
                            data: "first_connect".into(),
                        },
                    )
                    .await;
                let ok =
                    matches!(&conn_resp, Response::Connected { echo } if echo == "first_connect");
                let _ = run
                    .typed_or_error(&handle_a, &NET_UNLISTEN, NetListenArgs { port })
                    .await;
                super::TestOutcome::new("B", ok, format!("{conn_resp:?}"))
            })
        })
    });
    // XCONN.deep_cross: B listens, AA (deeper worker) connects.
    reg.test(
        "xworker",
        "cross_worker_first_connect",
        "XCONN.deep_cross".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let handle_aa = cx.require(AgentName::Dpg1Dpg1);
        let handle_b = cx.require(AgentName::Dpg2);
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19901u16;
                let listen_resp = run
                    .typed_or_error(&handle_b, &NET_LISTEN, NetListenArgs { port })
                    .await;
                if super::expect_listening_port(&listen_resp, port).is_err() {
                    return super::TestOutcome::new(
                        "AA",
                        false,
                        format!("listen on B failed: {listen_resp:?}"),
                    );
                }
                let conn_resp = run
                    .typed_or_error(
                        &handle_aa,
                        &NET_CONNECT,
                        NetConnectArgs {
                            addr: format!("127.0.0.1:{port}"),
                            data: "deep_cross".into(),
                        },
                    )
                    .await;
                let ok = matches!(&conn_resp, Response::Connected { echo } if echo == "deep_cross");
                let _ = run
                    .typed_or_error(&handle_b, &NET_UNLISTEN, NetListenArgs { port })
                    .await;
                super::TestOutcome::new("AA", ok, format!("{conn_resp:?}"))
            })
        })
    });
    // XCONN.cross_seq_x3: 3 rapid sequential connections from B to A's listener.
    reg.test("xworker", "cross_worker_first_connect", "XCONN.cross_seq_x3".to_string())
    .timeout(60)
    .build(move |cx| {
        let handle_a = cx.require(AgentName::Dpg1);
        let handle_b = cx.require(AgentName::Dpg2);
        Box::new(move |run| {
                Box::pin(async move {
                    let port = 19902u16;
                    let listen_resp = run.typed_or_error(&handle_a, &NET_LISTEN, NetListenArgs { port }).await;
                    if super::expect_listening_port(&listen_resp, port).is_err() {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let mut all_ok = true;
                    let mut fail_detail = String::new();
                    for i in 0..3 {
                        let conn_resp = run.typed_or_error(&handle_b, &NET_CONNECT, NetConnectArgs { addr: format!("127.0.0.1:{port}"), data: format!("seq_{i}") }).await;
                        if !matches!(&conn_resp, Response::Connected { echo } if echo == &format!("seq_{i}"))
                        {
                            all_ok = false;
                            fail_detail = format!("connection {i} failed: {conn_resp:?}");
                            break;
                        }
                    }
                    let _ = run.typed_or_error(&handle_a, &NET_UNLISTEN, NetListenArgs { port }).await;
                    let detail = if all_ok {
                        "3/3 sequential OK".into()
                    } else {
                        fail_detail
                    };
                    super::TestOutcome::new("B", all_ok, detail)
                })
        })
    });
}

// ═══════════════════════════════════════════════════════════════════
// XCONN.self: same-worker loopback (VS Code pattern)
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_cross_worker_self_connect_tests(reg: &mut Registry<'_>) {
    // XCONN.self_A: A listens, A connects to itself.
    reg.test(
        "xworker",
        "cross_worker_self_connect",
        "XCONN.self_A".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let handle_a = cx.require(AgentName::Dpg1);
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19910u16;
                let listen_resp = run
                    .typed_or_error(&handle_a, &NET_LISTEN, NetListenArgs { port })
                    .await;
                if super::expect_listening_port(&listen_resp, port).is_err() {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let conn_resp = run
                    .typed_or_error(
                        &handle_a,
                        &NET_CONNECT,
                        NetConnectArgs {
                            addr: format!("127.0.0.1:{port}"),
                            data: "self_loopback".into(),
                        },
                    )
                    .await;
                let ok =
                    matches!(&conn_resp, Response::Connected { echo } if echo == "self_loopback");
                let _ = run
                    .typed_or_error(&handle_a, &NET_UNLISTEN, NetListenArgs { port })
                    .await;
                super::TestOutcome::new("A", ok, format!("{conn_resp:?}"))
            })
        })
    });
    // XCONN.parent_child: A listens, AA connects.
    reg.test(
        "xworker",
        "cross_worker_self_connect",
        "XCONN.parent_child".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let handle_a = cx.require(AgentName::Dpg1);
        let handle_aa = cx.require(AgentName::Dpg1Dpg1);
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19911u16;
                let listen_resp = run
                    .typed_or_error(&handle_a, &NET_LISTEN, NetListenArgs { port })
                    .await;
                if super::expect_listening_port(&listen_resp, port).is_err() {
                    return super::TestOutcome::new(
                        "AA",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let conn_resp = run
                    .typed_or_error(
                        &handle_aa,
                        &NET_CONNECT,
                        NetConnectArgs {
                            addr: format!("127.0.0.1:{port}"),
                            data: "parent_child".into(),
                        },
                    )
                    .await;
                let ok =
                    matches!(&conn_resp, Response::Connected { echo } if echo == "parent_child");
                let _ = run
                    .typed_or_error(&handle_a, &NET_UNLISTEN, NetListenArgs { port })
                    .await;
                super::TestOutcome::new("AA", ok, format!("{conn_resp:?}"))
            })
        })
    });
    // XCONN.child_parent: AA listens, A connects.
    reg.test(
        "xworker",
        "cross_worker_self_connect",
        "XCONN.child_parent".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let handle_a = cx.require(AgentName::Dpg1);
        let handle_aa = cx.require(AgentName::Dpg1Dpg1);
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19912u16;
                let listen_resp = run
                    .typed_or_error(&handle_aa, &NET_LISTEN, NetListenArgs { port })
                    .await;
                if super::expect_listening_port(&listen_resp, port).is_err() {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let conn_resp = run
                    .typed_or_error(
                        &handle_a,
                        &NET_CONNECT,
                        NetConnectArgs {
                            addr: format!("127.0.0.1:{port}"),
                            data: "child_parent".into(),
                        },
                    )
                    .await;
                let ok =
                    matches!(&conn_resp, Response::Connected { echo } if echo == "child_parent");
                let _ = run
                    .typed_or_error(&handle_aa, &NET_UNLISTEN, NetListenArgs { port })
                    .await;
                super::TestOutcome::new("A", ok, format!("{conn_resp:?}"))
            })
        })
    });
    // XCONN.sibling_AB: A listens, AB connects.
    reg.test(
        "xworker",
        "cross_worker_self_connect",
        "XCONN.sibling_AB".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let handle_a = cx.require(AgentName::Dpg1);
        let handle_ab = cx.require(AgentName::Dpg1Dpg2);
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19913u16;
                let listen_resp = run
                    .typed_or_error(&handle_a, &NET_LISTEN, NetListenArgs { port })
                    .await;
                if super::expect_listening_port(&listen_resp, port).is_err() {
                    return super::TestOutcome::new(
                        "AB",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let conn_resp = run
                    .typed_or_error(
                        &handle_ab,
                        &NET_CONNECT,
                        NetConnectArgs {
                            addr: format!("127.0.0.1:{port}"),
                            data: "sibling_connect".into(),
                        },
                    )
                    .await;
                let ok =
                    matches!(&conn_resp, Response::Connected { echo } if echo == "sibling_connect");
                let _ = run
                    .typed_or_error(&handle_a, &NET_UNLISTEN, NetListenArgs { port })
                    .await;
                super::TestOutcome::new("AB", ok, format!("{conn_resp:?}"))
            })
        })
    });
}

// ═══════════════════════════════════════════════════════════════════
// FKLC: fork-listen-close — VS Code CLI pattern
// ═══════════════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Debug)]
struct AcceptInheritedArgs {
    port: u16,
    timeout_secs: u64,
}

const ACCEPT_INHERITED: HandlerToken<AcceptInheritedArgs, DetailOut> =
    HandlerToken::new("platform_fixes.accept_inherited");

async fn handle_accept_inherited(
    args: AcceptInheritedArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let spec = std::env::var("LITEBOX_TEST_HARNESS_INHERITED_LISTEN_FDS")
        .map_err(|e| HandlerError(format!("missing inherited listener env: {e}")))?;
    let fd = spec
        .split(',')
        .find_map(|item| {
            let (port_s, fd_s) = item.split_once('=')?;
            if port_s.parse::<u16>().ok()? == args.port {
                fd_s.parse::<i32>().ok()
            } else {
                None
            }
        })
        .ok_or_else(|| {
            HandlerError(format!(
                "no inherited fd for port {} in {spec:?}",
                args.port
            ))
        })?;
    let timeout = StdDuration::from_secs(args.timeout_secs);
    std::thread::spawn(move || {
        // SAFETY: agent import publishes a handler-owned duplicate fd in the
        // inheritance env mapping. This thread takes ownership of that fd.
        let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        let _ = listener.set_nonblocking(false);
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            let mut buf = [0u8; 4096];
            loop {
                match std::io::Read::read(&mut stream, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if std::io::Write::write_all(&mut stream, &buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });
    Ok(DetailOut {
        detail: format!("accepting on port {}", args.port),
    })
}

#[derive(Deserialize, Serialize)]
struct ClosePortArgs {
    port: u16,
}

const CLOSE_INHERITED: HandlerToken<ClosePortArgs, DetailOut> =
    HandlerToken::new("platform_fixes.close_inherited");

async fn handle_close_inherited(
    args: ClosePortArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<DetailOut, HandlerError> {
    let spec = std::env::var("LITEBOX_TEST_HARNESS_INHERITED_LISTEN_FDS")
        .map_err(|e| HandlerError(format!("missing inherited listener env: {e}")))?;
    let fd = spec
        .split(',')
        .find_map(|item| {
            let (port_s, fd_s) = item.split_once('=')?;
            if port_s.parse::<u16>().ok()? == args.port {
                fd_s.parse::<i32>().ok()
            } else {
                None
            }
        })
        .ok_or_else(|| {
            HandlerError(format!(
                "no inherited fd for port {} in {spec:?}",
                args.port
            ))
        })?;
    // SAFETY: closing an inherited listener fd published by the agent;
    // takes ownership via OwnedFd so the drop closes it exactly once.
    let _owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    Ok(DetailOut {
        detail: format!("closed inherited listener fd for port {}", args.port),
    })
}

async fn fklc_connect_from_agent(
    run: &mut RunContext<'_>,
    connector: &AgentHandle,
    port: u16,
    payload: &str,
) -> Result<Response, String> {
    let resp = run
        .typed_or_error(
            connector,
            &NET_CONNECT,
            NetConnectArgs {
                addr: format!("127.0.0.1:{port}"),
                data: payload.to_string(),
            },
        )
        .await;
    match &resp {
        Response::Connected { echo } if echo == payload => Ok(resp),
        _ => Err(format!("connect via agent failed: {resp:?}")),
    }
}

async fn fklc_child_accept_ready(
    run: &mut RunContext<'_>,
    child: &EphemeralHandle,
    port: u16,
) -> Result<Response, String> {
    let args = serde_json::to_value(AcceptInheritedArgs {
        port,
        timeout_secs: 5,
    })
    .map_err(|e| format!("accept args serialize: {e}"))?;
    let resp = run
        .forward(
            child,
            InfraCommand::Run {
                handler: ACCEPT_INHERITED.name().to_string(),
                args,
            },
        )
        .await;
    match &resp {
        Response::Result { ok: true, .. } => Ok(resp),
        _ => Err(format!("child accept start failed: {resp:?}")),
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn register_fork_listen_close_tests(reg: &mut Registry<'_>) {
    register_handler!(ACCEPT_INHERITED, handle_accept_inherited);
    register_handler!(CLOSE_INHERITED, handle_close_inherited);
    // FKLC.listen_unlisten: A listens then immediately unlistens,
    // B connects — should get RST.
    reg.test(
        "xworker",
        "fork_listen_close",
        "FKLC.listen_unlisten".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let handle_a = cx.require(AgentName::Dpg1);
        let handle_b = cx.require(AgentName::Dpg2);
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19920u16;
                let listen_resp = run
                    .typed_or_error(&handle_a, &NET_LISTEN, NetListenArgs { port })
                    .await;
                if let Err(e) = super::expect_listening_port(&listen_resp, port) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("listen failed: {e}; resp={listen_resp:?}"),
                    );
                }
                let _ = run
                    .typed_or_error(&handle_a, &NET_UNLISTEN, NetListenArgs { port })
                    .await;
                let conn_resp = run
                    .typed_or_error(
                        &handle_b,
                        &NET_CONNECT,
                        NetConnectArgs {
                            addr: format!("127.0.0.1:{port}"),
                            data: "listen_unlisten".into(),
                        },
                    )
                    .await;
                let got_rst = matches!(
                    &conn_resp,
                    Response::ConnectFailed { error }
                        if !error.is_empty()
                            && (error.contains("refused")
                                || error.contains("reset")
                                || error.contains("timeout"))
                );
                super::TestOutcome::new("B", got_rst, format!("expected RST: {conn_resp:?}"))
            })
        })
    });
    // FKLC.inherit.cross_connect.{pair}: protocol-only fd inheritance
    // across fork+exec, exercising the full cross-worker fd transport
    // surface across binary-type transitions.
    //
    // Three actors:
    //   - parent: AgentName that listens on the port, then forks an
    //     ephemeral child via SpawnKind::Fork{binary:"self",...}.
    //     Binary type of child == binary type of parent.
    //   - inheriting child: forked from parent, inherits the listen fd,
    //     accepts incoming connections.
    //   - connector: separate top-level agent that connects to the
    //     listened port from a sibling worker tree.
    //
    // Matrix axes:
    //   - parent binary type (5 values) → exercises Path A
    //     (external-fd-bridge fork-restore migration of the listen fd
    //     to the child worker host process). When parent and child
    //     are different binary types, the child runs in a separate
    //     worker process via delayed-fork migration.
    //   - connector binary type (chosen for cross-worker coverage)
    //     → exercises Path B (broker TCP via smoltcp for the connect
    //     side) when connector and listener are in different trees.
    //
    // Pre-architectural-fix (wave-5 baseline): listen-fd inheritance
    // is unimplemented at the product level; child accept(inherited_fd)
    // returns ENOTSOCK. Expected to fail on litebox for ALL pairs;
    // expected to pass on native for ALL pairs.
    //
    // Post-fix: all pairs pass on litebox.
    {
        struct FklcInheritPair {
            name: &'static str,
            parent: AgentName,
            connector: AgentName,
            base_port: u16,
        }
        // 5 parent binary types × Dpg2 connector. Each pair gets a
        // unique base port to avoid bind collisions when tests run in
        // parallel within the same docker container.
        const FKLC_INHERIT_PAIRS: &[FklcInheritPair] = &[
            // PIE-glibc → PIE-glibc, sibling-tree connector.
            // Baseline: parent and child same binary type, no
            // binary-type-transition fork-restore migration.
            FklcInheritPair {
                name: "dpg1",
                parent: AgentName::Dpg1,
                connector: AgentName::Dpg2,
                base_port: 19930,
            },
            // Non-PIE-glibc (within-tree depth-2 from Dpg1).
            // Parent is non-PIE-glibc; child fork+exec self also non-PIE-glibc.
            // Tests Path A across non-PIE-glibc.
            FklcInheritPair {
                name: "dpg1_dng",
                parent: AgentName::Dpg1Dng,
                connector: AgentName::Dpg2,
                base_port: 19931,
            },
            // Static-PIE-glibc parent.
            FklcInheritPair {
                name: "dpg1_spg",
                parent: AgentName::Dpg1Spg,
                connector: AgentName::Dpg2,
                base_port: 19932,
            },
            // Static-PIE-musl parent — VS Code CLI pattern's binary type.
            FklcInheritPair {
                name: "dpg1_spm",
                parent: AgentName::Dpg1Spm,
                connector: AgentName::Dpg2,
                base_port: 19933,
            },
            // Non-PIE-static-musl parent.
            FklcInheritPair {
                name: "dpg1_snm",
                parent: AgentName::Dpg1Snm,
                connector: AgentName::Dpg2,
                base_port: 19934,
            },
        ];

        for pair in FKLC_INHERIT_PAIRS {
            let id = format!("FKLC.inherit.cross_connect.{}", pair.name);
            let parent = pair.parent;
            let connector = pair.connector;
            let port = pair.base_port;
            let ephemeral_label = match pair.name {
                "dpg1" => "FKLCInheritCrossDpg1",
                "dpg1_dng" => "FKLCInheritCrossDpg1Dng",
                "dpg1_spg" => "FKLCInheritCrossDpg1Spg",
                "dpg1_spm" => "FKLCInheritCrossDpg1Spm",
                "dpg1_snm" => "FKLCInheritCrossDpg1Snm",
                _ => unreachable!(),
            };
            reg.test("xworker", "fork_listen_close", id)
                .timeout(60)
                .build(move |cx| {
                    let parent_handle = cx.require(parent);
                    let connector_handle = cx.require(connector);
                    let child = cx.declare_ephemeral(
                        parent,
                        ephemeral_label,
                        SpawnKind::Fork {
                            binary: "self",
                            inherit_listen_ports: vec![port],
                        },
                    );
                    Box::new(move |run| {
                        Box::pin(async move {
                            let listen_resp = run.typed_or_error(&parent_handle, &NET_LISTEN, NetListenArgs { port }).await;
                            if !matches!(&listen_resp, Response::Listening { port: p } if *p == port) {
                                return super::TestOutcome::new(
                                    "B",
                                    false,
                                    format!("listen failed: {listen_resp:?}"),
                                );
                            }
                            let fork_resp = run.spawn_ephemeral(&child).await;
                            if !matches!(&fork_resp, Response::Ok { .. }) {
                                return super::TestOutcome::new(
                                    "B",
                                    false,
                                    format!("fork failed: {fork_resp:?}"),
                                );
                            }
                            let _ = run.typed_or_error(&parent_handle, &NET_UNLISTEN, NetListenArgs { port }).await;
                            if let Err(e) = fklc_child_accept_ready(run, &child, port).await {
                                let _ = run.forward(&child, InfraCommand::Exit).await;
                                return super::TestOutcome::new("B", false, e);
                            }
                            match fklc_connect_from_agent(
                                run,
                                &connector_handle,
                                port,
                                "fork_listen_close",
                            )
                            .await
                            {
                                Ok(conn_resp) => {
                                    let _ = run.forward(&child, InfraCommand::Exit).await;
                                    super::TestOutcome::new("B", true, format!("{conn_resp:?}"))
                                }
                                Err(e) => {
                                    let _ = run.forward(&child, InfraCommand::Exit).await;
                                    super::TestOutcome::new("B", false, e)
                                }
                            }
                        })
                    })
                });
        }
    }

    // FKLC.inherit.multi_port: one fork imports two listen sockets at once.
    reg.test(
        "xworker",
        "fork_listen_close",
        "FKLC.inherit.multi_port".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let parent = cx.require(AgentName::Dpg1);
        let connector = cx.require(AgentName::Dpg2);
        let child = cx.declare_ephemeral(
            AgentName::Dpg1,
            "FKLCInheritMulti",
            SpawnKind::Fork {
                binary: "self",
                inherit_listen_ports: vec![19922, 19923],
            },
        );
        Box::new(move |run| {
            Box::pin(async move {
                for port in [19922u16, 19923] {
                    let listen_resp = run
                        .typed_or_error(&parent, &NET_LISTEN, NetListenArgs { port })
                        .await;
                    if !matches!(&listen_resp, Response::Listening { port: p } if *p == port) {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            format!("listen {port} failed: {listen_resp:?}"),
                        );
                    }
                }
                let fork_resp = run.spawn_ephemeral(&child).await;
                if !matches!(&fork_resp, Response::Ok { .. }) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("fork failed: {fork_resp:?}"),
                    );
                }
                for port in [19922u16, 19923] {
                    let _ = run
                        .typed_or_error(&parent, &NET_UNLISTEN, NetListenArgs { port })
                        .await;
                }
                let ready_first = fklc_child_accept_ready(run, &child, 19922).await;
                let ready_second = fklc_child_accept_ready(run, &child, 19923).await;
                let first = fklc_connect_from_agent(run, &connector, 19922, "multi_one").await;
                let second = fklc_connect_from_agent(run, &connector, 19923, "multi_two").await;
                let _ = run.forward(&child, InfraCommand::Exit).await;
                match (ready_first, ready_second, first, second) {
                    (Ok(a), Ok(b), Ok(c), Ok(d)) => {
                        super::TestOutcome::new("B", true, format!("{a:?}; {b:?}; {c:?}; {d:?}"))
                    }
                    results => super::TestOutcome::new("B", false, format!("{results:?}")),
                }
            })
        })
    });

    // FKLC.inherit.close_parent: the child keeps accepting after the parent closes.
    reg.test(
        "xworker",
        "fork_listen_close",
        "FKLC.inherit.close_parent".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let parent = cx.require(AgentName::Dpg1);
        let connector = cx.require(AgentName::Dpg2);
        let child = cx.declare_ephemeral(
            AgentName::Dpg1,
            "FKLCInheritCloseParent",
            SpawnKind::Fork {
                binary: "self",
                inherit_listen_ports: vec![19924],
            },
        );
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19924u16;
                let listen_resp = run
                    .typed_or_error(&parent, &NET_LISTEN, NetListenArgs { port })
                    .await;
                if !matches!(&listen_resp, Response::Listening { port: p } if *p == port) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let fork_resp = run.spawn_ephemeral(&child).await;
                let close_resp = run
                    .typed_or_error(&parent, &NET_UNLISTEN, NetListenArgs { port })
                    .await;
                if !matches!(
                    (&fork_resp, &close_resp),
                    (Response::Ok { .. }, Response::Ok { .. })
                ) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("fork/close failed: {fork_resp:?}; {close_resp:?}"),
                    );
                }
                let ready = fklc_child_accept_ready(run, &child, port).await;
                let result = if let Err(e) = ready {
                    Err(e)
                } else {
                    fklc_connect_from_agent(run, &connector, port, "close_parent").await
                };
                let _ = run.forward(&child, InfraCommand::Exit).await;
                match result {
                    Ok(resp) => super::TestOutcome::new("B", true, format!("{resp:?}")),
                    Err(e) => super::TestOutcome::new("B", false, e),
                }
            })
        })
    });

    // FKLC.inherit.depth2: an inheriting child can fork the listener onward.
    reg.test(
        "xworker",
        "fork_listen_close",
        "FKLC.inherit.depth2".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let parent = cx.require(AgentName::Dpg1);
        let connector = cx.require(AgentName::Dpg2);
        let child = cx.declare_ephemeral(
            AgentName::Dpg1,
            "FKLCInheritDepth1",
            SpawnKind::Fork {
                binary: "self",
                inherit_listen_ports: vec![19925],
            },
        );
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19925u16;
                let listen_resp = run
                    .typed_or_error(&parent, &NET_LISTEN, NetListenArgs { port })
                    .await;
                if !matches!(&listen_resp, Response::Listening { port: p } if *p == port) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let fork1_resp = run.spawn_ephemeral(&child).await;
                let _ = run
                    .typed_or_error(&parent, &NET_UNLISTEN, NetListenArgs { port })
                    .await;
                if !matches!(&fork1_resp, Response::Ok { .. }) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("fork depth1 failed: {fork1_resp:?}"),
                    );
                }
                let fork2_resp = run
                    .forward(
                        &child,
                        InfraCommand::Fork {
                            name: "FKLCInheritDepth2".into(),
                            binary: "self".into(),
                            inherit_listen_ports: vec![port],
                        },
                    )
                    .await;
                let close1_resp = run
                    .forward(
                        &child,
                        InfraCommand::Run {
                            handler: CLOSE_INHERITED.name().to_string(),
                            args: serde_json::to_value(ClosePortArgs { port })
                                .expect("close args serialize"),
                        },
                    )
                    .await;
                if !matches!(
                    (&fork2_resp, &close1_resp),
                    (Response::Ok { .. }, Response::Result { ok: true, .. })
                ) {
                    let _ = run.forward(&child, InfraCommand::Exit).await;
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("fork depth2/close depth1 failed: {fork2_resp:?}; {close1_resp:?}"),
                    );
                }
                let ready_args = serde_json::to_value(AcceptInheritedArgs {
                    port,
                    timeout_secs: 5,
                })
                .expect("accept args serialize");
                let ready = run
                    .forward(
                        &child,
                        InfraCommand::Forward {
                            target: "FKLCInheritDepth2".into(),
                            inner: Box::new(InfraCommand::Run {
                                handler: ACCEPT_INHERITED.name().to_string(),
                                args: ready_args,
                            }),
                        },
                    )
                    .await;
                let conn = fklc_connect_from_agent(run, &connector, port, "depth2").await;
                let _ = run
                    .forward(
                        &child,
                        InfraCommand::Forward {
                            target: "FKLCInheritDepth2".into(),
                            inner: Box::new(InfraCommand::Exit),
                        },
                    )
                    .await;
                let _ = run.forward(&child, InfraCommand::Exit).await;
                match (&ready, conn) {
                    (Response::Result { ok: true, .. }, Ok(conn_resp)) => {
                        super::TestOutcome::new("B", true, format!("{ready:?}; {conn_resp:?}"))
                    }
                    (_, conn_result) => super::TestOutcome::new(
                        "B",
                        false,
                        format!("ready={ready:?}; connect={conn_result:?}"),
                    ),
                }
            })
        })
    });

    // FKLC.inherit.sibling_connect: a sibling child, not the parent, connects.
    reg.test(
        "xworker",
        "fork_listen_close",
        "FKLC.inherit.sibling_connect".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let parent = cx.require(AgentName::Dpg1);
        let connector = cx.require(AgentName::Dpg2);
        let server = cx.declare_ephemeral(
            AgentName::Dpg1,
            "FKLCInheritSiblingServer",
            SpawnKind::Fork {
                binary: "self",
                inherit_listen_ports: vec![19926],
            },
        );
        Box::new(move |run| {
            Box::pin(async move {
                let port = 19926u16;
                let listen_resp = run
                    .typed_or_error(&parent, &NET_LISTEN, NetListenArgs { port })
                    .await;
                if !matches!(&listen_resp, Response::Listening { port: p } if *p == port) {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let server_resp = run.spawn_ephemeral(&server).await;
                let _ = run
                    .typed_or_error(&parent, &NET_UNLISTEN, NetListenArgs { port })
                    .await;
                if !matches!(&server_resp, Response::Ok { .. }) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("spawn failed: {server_resp:?}"),
                    );
                }
                let ready = fklc_child_accept_ready(run, &server, port).await;
                let result = if let Err(e) = ready {
                    Err(e)
                } else {
                    fklc_connect_from_agent(run, &connector, port, "sibling_connect").await
                };
                let _ = run.forward(&server, InfraCommand::Exit).await;
                match result {
                    Ok(resp) => super::TestOutcome::new("B", true, format!("{resp:?}")),
                    Err(e) => super::TestOutcome::new("B", false, e),
                }
            })
        })
    });
}
