// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! TCP stress tests — exhaustive matrix tests for TCP connection reliability,
//! concurrency, large data transfer, and cross-worker races.
//!
//! Categories:
//! - TC: concurrent connections
//! - TD: large data transfer integrity
//! - TRR: rapid reconnect stress
//! - TF: full-duplex simultaneous read+write
//! - TW: cross-worker concurrent TCP

use super::agents::{AgentName, SpawnKind};
use super::registry::Registry;

// ═══════════════════════════════════════════════════════════════════
// TC: TCP Concurrency — multiple parallel connections
// ═══════════════════════════════════════════════════════════════════

struct TcCase {
    name: &'static str,
    listener: AgentName,
    connector: AgentName,
    count: u32,
    delay_ms: u32,
}

const TC_CASES: &[TcCase] = &[
    TcCase {
        name: "in_process",
        listener: AgentName::A,
        connector: AgentName::A,
        count: 2,
        delay_ms: 0,
    },
    TcCase {
        name: "in_process",
        listener: AgentName::A,
        connector: AgentName::A,
        count: 5,
        delay_ms: 0,
    },
    TcCase {
        name: "in_process",
        listener: AgentName::A,
        connector: AgentName::A,
        count: 10,
        delay_ms: 0,
    },
    TcCase {
        name: "sibling",
        listener: AgentName::B,
        connector: AgentName::A,
        count: 2,
        delay_ms: 0,
    },
    TcCase {
        name: "sibling",
        listener: AgentName::B,
        connector: AgentName::A,
        count: 5,
        delay_ms: 0,
    },
    TcCase {
        name: "sibling",
        listener: AgentName::B,
        connector: AgentName::A,
        count: 10,
        delay_ms: 0,
    },
    TcCase {
        name: "depth2",
        listener: AgentName::AB,
        connector: AgentName::AA,
        count: 2,
        delay_ms: 0,
    },
    TcCase {
        name: "depth2",
        listener: AgentName::AB,
        connector: AgentName::AA,
        count: 5,
        delay_ms: 0,
    },
    TcCase {
        name: "sibling_delayed",
        listener: AgentName::B,
        connector: AgentName::A,
        count: 5,
        delay_ms: 10,
    },
    TcCase {
        name: "depth2_delayed",
        listener: AgentName::AB,
        connector: AgentName::AA,
        count: 5,
        delay_ms: 10,
    },
];

// ═══════════════════════════════════════════════════════════════════
// TD: TCP Data Size — large transfer integrity
// ═══════════════════════════════════════════════════════════════════

struct TdCase {
    name: &'static str,
    listener: AgentName,
    connector: AgentName,
    size: u32,
}

const TD_CASES: &[TdCase] = &[
    TdCase {
        name: "in_process",
        listener: AgentName::A,
        connector: AgentName::A,
        size: 1024,
    },
    TdCase {
        name: "sibling",
        listener: AgentName::B,
        connector: AgentName::A,
        size: 1024,
    },
    TdCase {
        name: "cross_subtree",
        listener: AgentName::AAA,
        connector: AgentName::B,
        size: 1024,
    },
    TdCase {
        name: "in_process",
        listener: AgentName::A,
        connector: AgentName::A,
        size: 65_536,
    },
    TdCase {
        name: "sibling",
        listener: AgentName::B,
        connector: AgentName::A,
        size: 65_536,
    },
    TdCase {
        name: "cross_subtree",
        listener: AgentName::AAA,
        connector: AgentName::B,
        size: 65_536,
    },
    TdCase {
        name: "in_process",
        listener: AgentName::A,
        connector: AgentName::A,
        size: 262_144,
    },
    TdCase {
        name: "sibling",
        listener: AgentName::B,
        connector: AgentName::A,
        size: 262_144,
    },
];

// ═══════════════════════════════════════════════════════════════════
// TRR: TCP Reconnect Stress — rapid sequential connections
// ═══════════════════════════════════════════════════════════════════

struct TrrCase {
    name: &'static str,
    listener: AgentName,
    connector: AgentName,
    count: u32,
}

const TRR_CASES: &[TrrCase] = &[
    TrrCase {
        name: "in_process",
        listener: AgentName::A,
        connector: AgentName::A,
        count: 5,
    },
    TrrCase {
        name: "in_process",
        listener: AgentName::A,
        connector: AgentName::A,
        count: 20,
    },
    TrrCase {
        name: "sibling",
        listener: AgentName::B,
        connector: AgentName::A,
        count: 5,
    },
    TrrCase {
        name: "sibling",
        listener: AgentName::B,
        connector: AgentName::A,
        count: 20,
    },
];

// ═══════════════════════════════════════════════════════════════════
// TF: TCP Full-Duplex — simultaneous bidirectional transfer
// ═══════════════════════════════════════════════════════════════════

const TF_AGENTS: &[AgentName] = &[AgentName::A, AgentName::AA, AgentName::B];
const TF_SIZE: usize = 65_536;

// ═══════════════════════════════════════════════════════════════════
// TW: TCP Cross-Worker Concurrency (extends XW5/XW6)
// ═══════════════════════════════════════════════════════════════════

const TW_COUNTS: &[u32] = &[1, 3, 5];

pub(crate) fn register_tcp_stress(reg: &mut Registry<'_>) {
    register_tcp_concurrency_tests(reg);
    register_tcp_data_size_tests(reg);
    register_tcp_reconnect_stress_tests(reg);
    register_tcp_fullduplex_tests(reg);
    register_tcp_cross_worker_concurrent_tests(reg);
}

fn register_tcp_concurrency_tests(reg: &mut Registry<'_>) {
    let mut port = 20_001u16;
    for tc in TC_CASES {
        let test_id = format!("TC.{}.x{}.d{}", tc.name, tc.count, tc.delay_ms);
        let listener = tc.listener;
        let connector = tc.connector;
        let count = tc.count;
        let delay_ms = tc.delay_ms;
        let name = tc.name.to_string();
        let p = port;
        port += 1;

        reg.test("stress", "tcp_stress", test_id)
            .timeout(180)
            .build(move |cx| {
                let listener_handle = cx.require(listener);
                let connector_handle = cx.require(connector);
                let connector_label = connector.to_string();
                Box::new(move |run| {
                    Box::pin(async move {
                        let resp = run
                            .send(
                                &listener_handle,
                                crate::protocol::Command::NetListen { port: p },
                            )
                            .await;
                        if !matches!(resp, crate::protocol::Response::Listening { .. }) {
                            return super::TestOutcome::new(
                                &connector_label,
                                false,
                                format!("listen failed: {resp:?}"),
                            );
                        }
                        let resp = run
                            .send(
                                &connector_handle,
                                crate::protocol::Command::NetConnectMany {
                                    addr: format!("127.0.0.1:{p}"),
                                    data: format!("TC_{name}"),
                                    count,
                                    delay_ms,
                                },
                            )
                            .await;
                        let pass = match &resp {
                            crate::protocol::Response::Ok { data: Some(d) } => {
                                d == &format!("success={count}/{count}")
                            }
                            _ => false,
                        };
                        let _ = run
                            .send(
                                &listener_handle,
                                crate::protocol::Command::NetUnlisten { port: p },
                            )
                            .await;
                        super::TestOutcome::new(&connector_label, pass, format!("{resp:?}"))
                    })
                })
            });
    }
}

fn register_tcp_data_size_tests(reg: &mut Registry<'_>) {
    let mut port = 20_100u16;
    for tc in TD_CASES {
        let size_label = if tc.size >= 262_144 {
            "256K"
        } else if tc.size >= 65_536 {
            "64K"
        } else {
            "1K"
        };
        let test_id = format!("TD.{}.{}", size_label, tc.name);
        let listener = tc.listener;
        let connector = tc.connector;
        let size = tc.size;
        let p = port;
        port += 1;

        reg.test("stress", "tcp_stress", test_id)
            .timeout(180)
            .build(move |cx| {
                let listener_handle = cx.require(listener);
                let connector_handle = cx.require(connector);
                let connector_label = connector.to_string();
                Box::new(move |run| {
                    Box::pin(async move {
                        let resp = run
                            .send(&listener_handle, crate::protocol::Command::NetListen { port: p })
                            .await;
                        if !matches!(resp, crate::protocol::Response::Listening { .. }) {
                            return super::TestOutcome::new(&connector_label, false, format!("listen failed: {resp:?}"));
                        }
                        let resp = run
                            .send(&connector_handle, crate::protocol::Command::NetSendRecv { addr: format!("127.0.0.1:{p}"), size })
                            .await;
                        let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) } if d.starts_with("verified="));
                        let _ = run
                            .send(&listener_handle, crate::protocol::Command::NetUnlisten { port: p })
                            .await;
                        super::TestOutcome::new(&connector_label, pass, format!("{resp:?}"))
                    })
                })
            });
    }
}

fn register_tcp_reconnect_stress_tests(reg: &mut Registry<'_>) {
    let mut port = 20_200u16;
    for tc in TRR_CASES {
        let test_id = format!("TRR.x{}.{}", tc.count, tc.name);
        let listener = tc.listener;
        let connector = tc.connector;
        let count = tc.count;
        let name = tc.name.to_string();
        let p = port;
        port += 1;

        reg.test("stress", "tcp_stress", test_id)
            .timeout(180)
            .build(move |cx| {
                let listener_handle = cx.require(listener);
                let connector_handle = cx.require(connector);
                let connector_label = connector.to_string();
                Box::new(move |run| {
                    Box::pin(async move {
                        let resp = run
                            .send(&listener_handle, crate::protocol::Command::NetListen { port: p })
                            .await;
                        if !matches!(resp, crate::protocol::Response::Listening { .. }) {
                            return super::TestOutcome::new(&connector_label, false, format!("listen failed: {resp:?}"));
                        }
                        let resp = run
                            .send(&connector_handle, crate::protocol::Command::NetReconnectStress { addr: format!("127.0.0.1:{p}"), count, data: format!("TRR_{name}") })
                            .await;
                        let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) } if d == &format!("success={count}/{count}"));
                        let _ = run
                            .send(&listener_handle, crate::protocol::Command::NetUnlisten { port: p })
                            .await;
                        super::TestOutcome::new(&connector_label, pass, format!("{resp:?}"))
                    })
                })
            });
    }
}

fn register_tcp_fullduplex_tests(reg: &mut Registry<'_>) {
    let mut port = 20_300u16;
    for &agent in TF_AGENTS {
        let test_id = format!("TF.{agent}");
        let p = port;
        port += 1;

        reg.test("stress", "tcp_stress", test_id)
            .timeout(180)
            .build(move |cx| {
                let handle = cx.require(agent);
                let agent_label = agent.to_string();
                Box::new(move |run| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let server_resp = run
                            .send(
                                &handle,
                                crate::protocol::Command::Exec {
                                    args: vec![
                                        self_exe.clone(),
                                        "tcp-fullduplex".into(),
                                        p.to_string(),
                                        TF_SIZE.to_string(),
                                    ],
                                    timeout_secs: Some(30),
                                    stdin: None,
                                    background: true,
                                },
                            )
                            .await;
                        let server_pid = match &server_resp {
                            crate::protocol::Response::Background { pid } => Some(*pid),
                            _ => {
                                return super::TestOutcome::new(
                                    &agent_label,
                                    false,
                                    format!("server spawn failed: {server_resp:?}"),
                                );
                            }
                        };
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        let client_resp = run
                            .send(
                                &handle,
                                super::exec_timeout(
                                    vec![
                                        self_exe,
                                        "tcp-fullduplex-client".into(),
                                        format!("127.0.0.1:{p}"),
                                        TF_SIZE.to_string(),
                                    ],
                                    15,
                                ),
                            )
                            .await;
                        if let Some(pid) = server_pid {
                            let _ = run
                                .send(&handle, crate::protocol::Command::Kill { pid })
                                .await;
                        }
                        let pass = match &client_resp {
                            crate::protocol::Response::ExecResult { stdout, .. } => {
                                stdout.contains(&format!("CLIENT:sent={TF_SIZE}"))
                                    && stdout.contains("recv=")
                            }
                            _ => false,
                        };
                        super::TestOutcome::new(&agent_label, pass, format!("{client_resp:?}"))
                    })
                })
            });
    }
}

fn register_tcp_cross_worker_concurrent_tests(reg: &mut Registry<'_>) {
    let mut port = 20_400u16;
    for &count in TW_COUNTS {
        {
            let test_id = format!("TW.remote_listen.x{count}");
            let p = port;
            port += 1;

            reg.test("stress", "tcp_stress", test_id)
                .timeout(180)
                .build(move |cx| {
                    let handle = cx.require(AgentName::A);
                    let aremote = cx.declare_ephemeral(AgentName::A, "ARemote", SpawnKind::NonPie);
                    Box::new(move |run| {
                        let aremote = aremote.clone();
                        Box::pin(async move {
                            let resp = run.spawn_ephemeral(&aremote).await;
                            if !matches!(&resp, crate::protocol::Response::Ok { .. }) {
                                return super::TestOutcome::new("A", false, "FAIL: SpawnRemote unavailable");
                            }
                            let resp = run
                                .forward(&aremote, crate::protocol::Command::NetListen { port: p })
                                .await;
                            if !matches!(resp, crate::protocol::Response::Listening { .. }) {
                                return super::TestOutcome::new("A", false, format!("listen failed: {resp:?}"));
                            }
                            let resp = run
                                .send(&handle, crate::protocol::Command::NetConnectMany { addr: format!("127.0.0.1:{p}"), data: "TW_REMOTE".to_string(), count, delay_ms: 0 })
                                .await;
                            let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) } if d == &format!("success={count}/{count}"));
                            let _ = run
                                .forward(&aremote, crate::protocol::Command::NetUnlisten { port: p })
                                .await;
                            super::TestOutcome::new("A", pass, format!("{resp:?}"))
                        })
                    })
                });
        }

        {
            let test_id = format!("TW.local_listen.x{count}");
            let p = port;
            port += 1;

            reg.test("stress", "tcp_stress", test_id)
                .timeout(180)
                .build(move |cx| {
                    let handle = cx.require(AgentName::A);
                    let aremote = cx.declare_ephemeral(AgentName::A, "ARemote", SpawnKind::NonPie);
                    Box::new(move |run| {
                        let aremote = aremote.clone();
                        Box::pin(async move {
                            let resp = run.spawn_ephemeral(&aremote).await;
                            if !matches!(&resp, crate::protocol::Response::Ok { .. }) {
                                return super::TestOutcome::new("A", false, "FAIL: SpawnRemote unavailable");
                            }
                            let resp = run.send(&handle, crate::protocol::Command::NetListen { port: p }).await;
                            if !matches!(resp, crate::protocol::Response::Listening { .. }) {
                                return super::TestOutcome::new("A", false, format!("listen failed: {resp:?}"));
                            }
                            let resp = run
                                .forward(&aremote, crate::protocol::Command::NetConnectMany { addr: format!("127.0.0.1:{p}"), data: "TW_LOCAL".to_string(), count, delay_ms: 0 })
                                .await;
                            let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) } if d == &format!("success={count}/{count}"));
                            let _ = run.send(&handle, crate::protocol::Command::NetUnlisten { port: p }).await;
                            super::TestOutcome::new("A", pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}
