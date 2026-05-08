// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! TCP stress tests — exhaustive matrix tests for TCP connection reliability,
//! concurrency, large data transfer, and cross-worker races.
//!
//! Categories:
//! - TC: concurrent connections
//! - TD: large data transfer integrity
//! - TRR: rapid reconnect stress
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
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        count: 2,
        delay_ms: 0,
    },
    TcCase {
        name: "in_process",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        count: 5,
        delay_ms: 0,
    },
    TcCase {
        name: "in_process",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        count: 10,
        delay_ms: 0,
    },
    TcCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        count: 2,
        delay_ms: 0,
    },
    TcCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        count: 5,
        delay_ms: 0,
    },
    TcCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        count: 10,
        delay_ms: 0,
    },
    TcCase {
        name: "depth2",
        listener: AgentName::Dpg1Dpg2,
        connector: AgentName::Dpg1Dpg1,
        count: 2,
        delay_ms: 0,
    },
    TcCase {
        name: "depth2",
        listener: AgentName::Dpg1Dpg2,
        connector: AgentName::Dpg1Dpg1,
        count: 5,
        delay_ms: 0,
    },
    TcCase {
        name: "sibling_delayed",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        count: 5,
        delay_ms: 10,
    },
    TcCase {
        name: "depth2_delayed",
        listener: AgentName::Dpg1Dpg2,
        connector: AgentName::Dpg1Dpg1,
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
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        size: 1024,
    },
    TdCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        size: 1024,
    },
    TdCase {
        name: "cross_subtree",
        listener: AgentName::Dpg1Dpg1Dpg1,
        connector: AgentName::Dpg2,
        size: 1024,
    },
    TdCase {
        name: "in_process",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        size: 65_536,
    },
    TdCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        size: 65_536,
    },
    TdCase {
        name: "cross_subtree",
        listener: AgentName::Dpg1Dpg1Dpg1,
        connector: AgentName::Dpg2,
        size: 65_536,
    },
    TdCase {
        name: "in_process",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        size: 262_144,
    },
    TdCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
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
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        count: 5,
    },
    TrrCase {
        name: "in_process",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1,
        count: 20,
    },
    TrrCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        count: 5,
    },
    TrrCase {
        name: "sibling",
        listener: AgentName::Dpg2,
        connector: AgentName::Dpg1,
        count: 20,
    },
    TrrCase {
        name: "parent_child",
        listener: AgentName::Dpg1Dpg1,
        connector: AgentName::Dpg1,
        count: 5,
    },
    TrrCase {
        name: "child_parent",
        listener: AgentName::Dpg1,
        connector: AgentName::Dpg1Dpg1,
        count: 5,
    },
    TrrCase {
        name: "depth2",
        listener: AgentName::Dpg1Dpg1Dpg1,
        connector: AgentName::Dpg1Dpg1Dpg2,
        count: 5,
    },
];

// ═══════════════════════════════════════════════════════════════════
// TW: TCP Cross-Worker Concurrency (extends XW5/XW6)
// ═══════════════════════════════════════════════════════════════════

const TW_COUNTS: &[u32] = &[1, 3, 5];

pub(crate) fn register_tcp_stress(reg: &mut Registry<'_>) {
    register_tcp_concurrency_tests(reg);
    register_tcp_data_size_tests(reg);
    register_tcp_reconnect_stress_tests(reg);
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
                                crate::protocol::Command::NetListen {
                                    port: p,
                                    pre_bind_options: vec![],
                                },
                            )
                            .await;
                        if super::expect_listening_port(&resp, p).is_err() {
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
                            .send(&listener_handle, crate::protocol::Command::NetListen { port: p, pre_bind_options: vec![] })
                            .await;
                        if super::expect_listening_port(&resp, p).is_err() {
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
                            .send(&listener_handle, crate::protocol::Command::NetListen { port: p, pre_bind_options: vec![] })
                            .await;
                        if super::expect_listening_port(&resp, p).is_err() {
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

fn register_tcp_cross_worker_concurrent_tests(reg: &mut Registry<'_>) {
    #[derive(Clone, Copy)]
    struct StableCase {
        name: &'static str,
        listener: AgentName,
        connector: AgentName,
    }

    const STABLE_CASES: &[StableCase] = &[
        StableCase {
            name: "sibling",
            listener: AgentName::Dpg2,
            connector: AgentName::Dpg1,
        },
        StableCase {
            name: "depth2",
            listener: AgentName::Dpg1Dng,
            connector: AgentName::Dpg1DngDpg,
        },
    ];

    let mut port = 20_400u16;
    for &count in TW_COUNTS {
        {
            let test_id = format!("TW.remote_listen.x{count}");
            let p = port;
            port += 1;

            reg.test("stress", "tcp_stress", test_id)
                .timeout(180)
                .build(move |cx| {
                    let handle = cx.require(AgentName::Dpg1);
                    let aremote = cx.declare_ephemeral(AgentName::Dpg1, "ARemote", SpawnKind::NonPie);
                    Box::new(move |run| {
                        let aremote = aremote.clone();
                        Box::pin(async move {
                            let resp = run.spawn_ephemeral(&aremote).await;
                            if !super::ok_spawned_response(&resp) {
                                return super::TestOutcome::new("A", false, "FAIL: SpawnRemote unavailable");
                            }
                            let resp = run
                                .forward(&aremote, crate::protocol::Command::NetListen { port: p, pre_bind_options: vec![] })
                                .await;
                            if super::expect_listening_port(&resp, p).is_err() {
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
                    let handle = cx.require(AgentName::Dpg1);
                    let aremote = cx.declare_ephemeral(AgentName::Dpg1, "ARemote", SpawnKind::NonPie);
                    Box::new(move |run| {
                        let aremote = aremote.clone();
                        Box::pin(async move {
                            let resp = run.spawn_ephemeral(&aremote).await;
                            if !super::ok_spawned_response(&resp) {
                                return super::TestOutcome::new("A", false, "FAIL: SpawnRemote unavailable");
                            }
                            let resp = run.send(&handle, crate::protocol::Command::NetListen { port: p, pre_bind_options: vec![] }).await;
                            if super::expect_listening_port(&resp, p).is_err() {
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

        if count == 1 {
            for case in STABLE_CASES {
                let test_id = format!("TW.{}.x{count}", case.name);
                let p = port;
                port += 1;
                let listener = case.listener;
                let connector = case.connector;
                let label = format!("{}->{}", connector, listener);

                reg.test("stress", "tcp_stress", test_id)
                    .timeout(180)
                    .build(move |cx| {
                        let listener_handle = cx.require(listener);
                        let connector_handle = cx.require(connector);
                        let label = label.clone();
                        Box::new(move |run| {
                            let label = label.clone();
                            Box::pin(async move {
                                let resp = run
                                    .send(
                                        &listener_handle,
                                        crate::protocol::Command::NetListen { port: p, pre_bind_options: vec![] },
                                    )
                                    .await;
                                if !matches!(resp, crate::protocol::Response::Listening { .. }) {
                                    return super::TestOutcome::new(
                                        &label,
                                        false,
                                        format!("listen failed: {resp:?}"),
                                    );
                                }
                                let resp = run
                                    .send(
                                        &connector_handle,
                                        crate::protocol::Command::NetConnectMany {
                                            addr: format!("127.0.0.1:{p}"),
                                            data: format!("TW_{}", case.name),
                                            count,
                                            delay_ms: 0,
                                        },
                                    )
                                    .await;
                                let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) } if d == &format!("success={count}/{count}"));
                                let _ = run
                                    .send(
                                        &listener_handle,
                                        crate::protocol::Command::NetUnlisten { port: p },
                                    )
                                    .await;
                                super::TestOutcome::new(&label, pass, format!("{resp:?}"))
                            })
                        })
                    });
            }
        }
    }
}
