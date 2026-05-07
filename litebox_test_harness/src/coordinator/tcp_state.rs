// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Stateful TCP protocol tests.
//!
//! TCS exercises multi-step connection state through the agent's TCP
//! connection registry, replacing one-shot helper subcommands.

use std::collections::HashSet;

use crate::protocol::{Command, Response};

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

pub(crate) fn register_tcp_state_tests(reg: &mut Registry<'_>) {
    register_write_shutdown_read_eof(reg);
    register_send_recv_send(reg);
    register_partial_recv(reg);
    register_halfclose_then_reconnect(reg);
    register_conn_id_unique(reg);
}

fn register_write_shutdown_read_eof(reg: &mut Registry<'_>) {
    for axis in AXES {
        let id = format!("TCS.write_shutdown_read_eof.{}", axis.name);
        let server_label = axis.server.to_string();
        let client_label = axis.client.to_string();
        reg.test("matrix", "tcp_state", id)
            .timeout(60)
            .build(move |cx| {
                let server = cx.require(axis.server);
                let client = cx.require(axis.client);
                Box::new(move |run| {
                    let server_label = server_label.clone();
                    let client_label = client_label.clone();
                    Box::pin(async move {
                        run_write_shutdown_read_eof_case(
                            run,
                            &server,
                            &client,
                            &server_label,
                            &client_label,
                            &format!("TCS_EOF_{}", axis.name),
                        )
                        .await
                    })
                })
            });
    }
}

fn register_send_recv_send(reg: &mut Registry<'_>) {
    for axis in AXES {
        let id = format!("TCS.send_recv_send.{}", axis.name);
        let server_label = axis.server.to_string();
        let client_label = axis.client.to_string();
        reg.test("matrix", "tcp_state", id)
            .timeout(60)
            .build(move |cx| {
                let server = cx.require(axis.server);
                let client = cx.require(axis.client);
                Box::new(move |run| {
                    let server_label = server_label.clone();
                    let client_label = client_label.clone();
                    Box::pin(async move {
                        run_send_recv_send_case(
                            run,
                            &server,
                            &client,
                            &server_label,
                            &client_label,
                            &format!("TCS_X_{}", axis.name),
                            &format!("TCS_Y_{}", axis.name),
                        )
                        .await
                    })
                })
            });
    }
}

fn register_partial_recv(reg: &mut Registry<'_>) {
    for axis in AXES {
        let id = format!("TCS.partial_recv.{}", axis.name);
        let server_label = axis.server.to_string();
        let client_label = axis.client.to_string();
        reg.test("matrix", "tcp_state", id)
            .timeout(60)
            .build(move |cx| {
                let server = cx.require(axis.server);
                let client = cx.require(axis.client);
                Box::new(move |run| {
                    let server_label = server_label.clone();
                    let client_label = client_label.clone();
                    Box::pin(async move {
                        let payload = format!("TCS_PARTIAL_{}_ABCDEFGHIJK", axis.name);
                        run_partial_recv_case(
                            run,
                            &server,
                            &client,
                            &server_label,
                            &client_label,
                            &payload,
                            11,
                        )
                        .await
                    })
                })
            });
    }
}

fn register_halfclose_then_reconnect(reg: &mut Registry<'_>) {
    for axis in AXES {
        let id = format!("TCS.halfclose_then_reconnect.{}", axis.name);
        let server_label = axis.server.to_string();
        let client_label = axis.client.to_string();
        reg.test("matrix", "tcp_state", id)
            .timeout(60)
            .build(move |cx| {
                let server = cx.require(axis.server);
                let client = cx.require(axis.client);
                Box::new(move |run| {
                    let server_label = server_label.clone();
                    let client_label = client_label.clone();
                    Box::pin(async move {
                        run_halfclose_then_reconnect_case(
                            run,
                            &server,
                            &client,
                            &server_label,
                            &client_label,
                            &format!("TCS_FIRST_{}", axis.name),
                            &format!("TCS_SECOND_{}", axis.name),
                        )
                        .await
                    })
                })
            });
    }
}

fn register_conn_id_unique(reg: &mut Registry<'_>) {
    reg.test(
        "matrix",
        "tcp_state",
        "TCS.conn_id_unique.rapid_open_close".to_string(),
    )
    .timeout(60)
    .build(move |cx| {
        let handle = cx.require(AgentName::Dpg1);
        Box::new(move |run| Box::pin(async move { run_conn_id_unique_case(run, &handle).await }))
    });
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
    let (port, conn) = match listen_open(run, server, client).await {
        Ok(pair) => pair,
        Err(e) => return TestOutcome::new(&agent, false, format!("setup failed: {e}")),
    };

    let outcome = async {
        expect_sent(
            run.send(
                client,
                Command::NetSend {
                    conn,
                    data: payload.into(),
                },
            )
            .await,
        )?;
        expect_shutdown(
            run.send(
                client,
                Command::NetShutdown {
                    conn,
                    half: "wr".into(),
                },
            )
            .await,
        )?;
        let data = expect_received(
            run.send(
                client,
                Command::NetRecv {
                    conn,
                    n_bytes: None,
                },
            )
            .await,
        )?;
        if data != payload {
            return Err(format!("expected exact EOF echo {payload:?}, got {data:?}"));
        }
        Ok::<_, String>(format!("conn={conn} payload={payload:?}"))
    }
    .await;

    let _ = run.send(client, Command::NetClose { conn }).await;
    let _ = run.send(server, Command::NetUnlisten { port }).await;
    match outcome {
        Ok(detail) => TestOutcome::new(&agent, true, detail),
        Err(detail) => TestOutcome::new(&agent, false, detail),
    }
}

async fn run_send_recv_send_case(
    run: &mut RunContext<'_>,
    server: &AgentHandle,
    client: &AgentHandle,
    server_label: &str,
    client_label: &str,
    first: &str,
    second: &str,
) -> TestOutcome {
    let agent = format!("{server_label}<-{client_label}");
    let (port, conn) = match listen_open(run, server, client).await {
        Ok(pair) => pair,
        Err(e) => return TestOutcome::new(&agent, false, format!("setup failed: {e}")),
    };

    let outcome = async {
        expect_sent(
            run.send(
                client,
                Command::NetSend {
                    conn,
                    data: first.into(),
                },
            )
            .await,
        )?;
        let first_echo = expect_received(
            run.send(
                client,
                Command::NetRecv {
                    conn,
                    n_bytes: Some(first.len() as u32),
                },
            )
            .await,
        )?;
        if first_echo != first {
            return Err(format!(
                "first echo mismatch: expected {first:?}, got {first_echo:?}"
            ));
        }

        expect_sent(
            run.send(
                client,
                Command::NetSend {
                    conn,
                    data: second.into(),
                },
            )
            .await,
        )?;
        let second_echo = expect_received(
            run.send(
                client,
                Command::NetRecv {
                    conn,
                    n_bytes: Some(second.len() as u32),
                },
            )
            .await,
        )?;
        if second_echo != second {
            return Err(format!(
                "second echo mismatch: expected {second:?}, got {second_echo:?}"
            ));
        }
        Ok::<_, String>(format!("conn={conn} echoes exact"))
    }
    .await;

    let _ = run.send(client, Command::NetClose { conn }).await;
    let _ = run.send(server, Command::NetUnlisten { port }).await;
    match outcome {
        Ok(detail) => TestOutcome::new(&agent, true, detail),
        Err(detail) => TestOutcome::new(&agent, false, detail),
    }
}

async fn run_partial_recv_case(
    run: &mut RunContext<'_>,
    server: &AgentHandle,
    client: &AgentHandle,
    server_label: &str,
    client_label: &str,
    payload: &str,
    first_len: usize,
) -> TestOutcome {
    let agent = format!("{server_label}<-{client_label}");
    let (port, conn) = match listen_open(run, server, client).await {
        Ok(pair) => pair,
        Err(e) => return TestOutcome::new(&agent, false, format!("setup failed: {e}")),
    };

    let outcome = async {
        expect_sent(
            run.send(
                client,
                Command::NetSend {
                    conn,
                    data: payload.into(),
                },
            )
            .await,
        )?;
        let first = expect_received(
            run.send(
                client,
                Command::NetRecv {
                    conn,
                    n_bytes: Some(first_len as u32),
                },
            )
            .await,
        )?;
        let rest = expect_received(
            run.send(
                client,
                Command::NetRecv {
                    conn,
                    n_bytes: Some((payload.len() - first_len) as u32),
                },
            )
            .await,
        )?;
        let combined = format!("{first}{rest}");
        if combined != payload {
            return Err(format!(
                "partial continuity mismatch: expected {payload:?}, got {combined:?}"
            ));
        }
        Ok::<_, String>(format!("conn={conn} split={first_len}+{}", rest.len()))
    }
    .await;

    let _ = run.send(client, Command::NetClose { conn }).await;
    let _ = run.send(server, Command::NetUnlisten { port }).await;
    match outcome {
        Ok(detail) => TestOutcome::new(&agent, true, detail),
        Err(detail) => TestOutcome::new(&agent, false, detail),
    }
}

async fn run_halfclose_then_reconnect_case(
    run: &mut RunContext<'_>,
    server: &AgentHandle,
    client: &AgentHandle,
    server_label: &str,
    client_label: &str,
    first: &str,
    second: &str,
) -> TestOutcome {
    let agent = format!("{server_label}<-{client_label}");
    let listen_resp = run.send(server, Command::NetListen { port: 0 }).await;
    let port = match super::expect_listening_port(&listen_resp, 0) {
        Ok(port) => port,
        Err(e) => {
            return TestOutcome::new(
                &agent,
                false,
                format!("listen failed: {e}; resp={listen_resp:?}"),
            );
        }
    };

    let outcome = async {
        let first_conn = expect_opened(
            run.send(
                client,
                Command::NetOpen {
                    addr: format!("127.0.0.1:{port}"),
                },
            )
            .await,
        )?;
        round_trip_to_eof(run, client, first_conn, first).await?;
        expect_closed(
            run.send(client, Command::NetClose { conn: first_conn })
                .await,
        )?;

        let second_conn = expect_opened(
            run.send(
                client,
                Command::NetOpen {
                    addr: format!("127.0.0.1:{port}"),
                },
            )
            .await,
        )?;
        if second_conn == first_conn {
            return Err(format!("connection id reused: {second_conn}"));
        }
        round_trip_to_eof(run, client, second_conn, second).await?;
        expect_closed(
            run.send(client, Command::NetClose { conn: second_conn })
                .await,
        )?;
        Ok::<_, String>(format!("first_conn={first_conn} second_conn={second_conn}"))
    }
    .await;

    let _ = run.send(server, Command::NetUnlisten { port }).await;
    match outcome {
        Ok(detail) => TestOutcome::new(&agent, true, detail),
        Err(detail) => TestOutcome::new(&agent, false, detail),
    }
}

async fn run_conn_id_unique_case(run: &mut RunContext<'_>, handle: &AgentHandle) -> TestOutcome {
    let listen_resp = run.send(handle, Command::NetListen { port: 0 }).await;
    let port = match super::expect_listening_port(&listen_resp, 0) {
        Ok(port) => port,
        Err(e) => {
            return TestOutcome::new(
                "A",
                false,
                format!("listen failed: {e}; resp={listen_resp:?}"),
            );
        }
    };

    let mut seen = HashSet::new();
    let mut detail = String::new();
    let mut pass = true;
    for i in 0..25 {
        let conn = match expect_opened(
            run.send(
                handle,
                Command::NetOpen {
                    addr: format!("127.0.0.1:{port}"),
                },
            )
            .await,
        ) {
            Ok(conn) => conn,
            Err(e) => {
                pass = false;
                detail = format!("open {i} failed: {e}");
                break;
            }
        };
        if !seen.insert(conn) {
            pass = false;
            detail = format!("conn id {conn} reused at iteration {i}");
            let _ = run.send(handle, Command::NetClose { conn }).await;
            break;
        }
        match expect_closed(run.send(handle, Command::NetClose { conn }).await) {
            Ok(()) => {}
            Err(e) => {
                pass = false;
                detail = format!("close {conn} failed: {e}");
                break;
            }
        }
    }
    let _ = run.send(handle, Command::NetUnlisten { port }).await;
    if pass {
        detail = format!("{} unique ids", seen.len());
    }
    TestOutcome::new("A", pass, detail)
}

async fn listen_open(
    run: &mut RunContext<'_>,
    server: &AgentHandle,
    client: &AgentHandle,
) -> Result<(u16, u64), String> {
    let listen_resp = run.send(server, Command::NetListen { port: 0 }).await;
    let port = match super::expect_listening_port(&listen_resp, 0) {
        Ok(port) => port,
        Err(e) => return Err(format!("listen failed: {e}; resp={listen_resp:?}")),
    };
    let open_resp = run
        .send(
            client,
            Command::NetOpen {
                addr: format!("127.0.0.1:{port}"),
            },
        )
        .await;
    let conn = match expect_opened(open_resp) {
        Ok(conn) => conn,
        Err(e) => {
            let _ = run.send(server, Command::NetUnlisten { port }).await;
            return Err(e);
        }
    };
    Ok((port, conn))
}

async fn round_trip_to_eof(
    run: &mut RunContext<'_>,
    client: &AgentHandle,
    conn: u64,
    payload: &str,
) -> Result<(), String> {
    expect_sent(
        run.send(
            client,
            Command::NetSend {
                conn,
                data: payload.into(),
            },
        )
        .await,
    )?;
    expect_shutdown(
        run.send(
            client,
            Command::NetShutdown {
                conn,
                half: "wr".into(),
            },
        )
        .await,
    )?;
    let echo = expect_received(
        run.send(
            client,
            Command::NetRecv {
                conn,
                n_bytes: None,
            },
        )
        .await,
    )?;
    if echo == payload {
        Ok(())
    } else {
        Err(format!("expected exact echo {payload:?}, got {echo:?}"))
    }
}

fn expect_opened(resp: Response) -> Result<u64, String> {
    match resp {
        Response::Opened { conn } => Ok(conn),
        other => Err(format!("expected Opened, got {other:?}")),
    }
}

fn expect_sent(resp: Response) -> Result<(), String> {
    match resp {
        Response::Sent => Ok(()),
        other => Err(format!("expected Sent, got {other:?}")),
    }
}

fn expect_received(resp: Response) -> Result<String, String> {
    match resp {
        Response::Received { data } => Ok(data),
        other => Err(format!("expected Received, got {other:?}")),
    }
}

fn expect_shutdown(resp: Response) -> Result<(), String> {
    match resp {
        Response::ShutdownOk => Ok(()),
        other => Err(format!("expected ShutdownOk, got {other:?}")),
    }
}

fn expect_closed(resp: Response) -> Result<(), String> {
    match resp {
        Response::Closed => Ok(()),
        other => Err(format!("expected Closed, got {other:?}")),
    }
}
