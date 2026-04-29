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

use super::{TestRunner, exec_timeout};
use crate::protocol::{Command, Response};

// ═══════════════════════════════════════════════════════════════════
// TC: TCP Concurrency — multiple parallel connections
// ═══════════════════════════════════════════════════════════════════

struct TcCase {
    name: &'static str,
    listener: &'static str,
    connector: &'static str,
    count: u32,
    delay_ms: u32,
}

const TC_CASES: &[TcCase] = &[
    // In-process: listener and connector are the same agent
    TcCase {
        name: "in_process",
        listener: "A",
        connector: "A",
        count: 2,
        delay_ms: 0,
    },
    TcCase {
        name: "in_process",
        listener: "A",
        connector: "A",
        count: 5,
        delay_ms: 0,
    },
    TcCase {
        name: "in_process",
        listener: "A",
        connector: "A",
        count: 10,
        delay_ms: 0,
    },
    // Sibling: different agents at the same depth
    TcCase {
        name: "sibling",
        listener: "B",
        connector: "A",
        count: 2,
        delay_ms: 0,
    },
    TcCase {
        name: "sibling",
        listener: "B",
        connector: "A",
        count: 5,
        delay_ms: 0,
    },
    TcCase {
        name: "sibling",
        listener: "B",
        connector: "A",
        count: 10,
        delay_ms: 0,
    },
    // Depth 2 sibling
    TcCase {
        name: "depth2",
        listener: "AB",
        connector: "AA",
        count: 2,
        delay_ms: 0,
    },
    TcCase {
        name: "depth2",
        listener: "AB",
        connector: "AA",
        count: 5,
        delay_ms: 0,
    },
    // With delay — staggered connections
    TcCase {
        name: "sibling_delayed",
        listener: "B",
        connector: "A",
        count: 5,
        delay_ms: 10,
    },
    TcCase {
        name: "depth2_delayed",
        listener: "AB",
        connector: "AA",
        count: 5,
        delay_ms: 10,
    },
];

pub(crate) async fn tcp_concurrency_tests(r: &mut TestRunner) {
    eprintln!(
        "[tcp_stress] === TC: TCP Concurrency ({} cases) ===",
        TC_CASES.len()
    );

    let mut port = 20_001u16;
    for tc in TC_CASES {
        let test_id = format!("TC.{}.x{}.d{}", tc.name, tc.count, tc.delay_ms);

        // Start listener
        let resp = r.send(tc.listener, Command::NetListen { port }).await;
        if !matches!(resp, Response::Listening { .. }) {
            r.record(
                &test_id,
                tc.connector,
                false,
                &format!("listen failed: {resp:?}"),
            );
            port += 1;
            continue;
        }

        // Run concurrent connections
        let resp = r
            .send(
                tc.connector,
                Command::NetConnectMany {
                    addr: format!("127.0.0.1:{port}"),
                    data: format!("TC_{}", tc.name),
                    count: tc.count,
                    delay_ms: tc.delay_ms,
                },
            )
            .await;

        let pass = match &resp {
            Response::Ok { data: Some(d) } => d == &format!("success={}/{}", tc.count, tc.count),
            _ => false,
        };
        r.record(&test_id, tc.connector, pass, &format!("{resp:?}"));

        let _ = r.send(tc.listener, Command::NetUnlisten { port }).await;
        port += 1;
    }
}

// ═══════════════════════════════════════════════════════════════════
// TD: TCP Data Size — large transfer integrity
// ═══════════════════════════════════════════════════════════════════

struct TdCase {
    name: &'static str,
    listener: &'static str,
    connector: &'static str,
    size: u32,
}

const TD_CASES: &[TdCase] = &[
    // 1 KB
    TdCase {
        name: "in_process",
        listener: "A",
        connector: "A",
        size: 1024,
    },
    TdCase {
        name: "sibling",
        listener: "B",
        connector: "A",
        size: 1024,
    },
    TdCase {
        name: "cross_subtree",
        listener: "AAA",
        connector: "B",
        size: 1024,
    },
    // 64 KB
    TdCase {
        name: "in_process",
        listener: "A",
        connector: "A",
        size: 65536,
    },
    TdCase {
        name: "sibling",
        listener: "B",
        connector: "A",
        size: 65536,
    },
    TdCase {
        name: "cross_subtree",
        listener: "AAA",
        connector: "B",
        size: 65536,
    },
    // 256 KB
    TdCase {
        name: "in_process",
        listener: "A",
        connector: "A",
        size: 262144,
    },
    TdCase {
        name: "sibling",
        listener: "B",
        connector: "A",
        size: 262144,
    },
];

pub(crate) async fn tcp_data_size_tests(r: &mut TestRunner) {
    eprintln!(
        "[tcp_stress] === TD: TCP Data Size ({} cases) ===",
        TD_CASES.len()
    );

    let mut port = 20_100u16;
    for tc in TD_CASES {
        let size_label = if tc.size >= 262144 {
            "256K"
        } else if tc.size >= 65536 {
            "64K"
        } else {
            "1K"
        };
        let test_id = format!("TD.{}.{}", size_label, tc.name);

        let resp = r.send(tc.listener, Command::NetListen { port }).await;
        if !matches!(resp, Response::Listening { .. }) {
            r.record(
                &test_id,
                tc.connector,
                false,
                &format!("listen failed: {resp:?}"),
            );
            port += 1;
            continue;
        }

        let resp = r
            .send(
                tc.connector,
                Command::NetSendRecv {
                    addr: format!("127.0.0.1:{port}"),
                    size: tc.size,
                },
            )
            .await;

        let pass = matches!(&resp, Response::Ok { data: Some(d) }
            if d.starts_with("verified="));
        r.record(&test_id, tc.connector, pass, &format!("{resp:?}"));

        let _ = r.send(tc.listener, Command::NetUnlisten { port }).await;
        port += 1;
    }
}

// ═══════════════════════════════════════════════════════════════════
// TRR: TCP Reconnect Stress — rapid sequential connections
// ═══════════════════════════════════════════════════════════════════

struct TrrCase {
    name: &'static str,
    listener: &'static str,
    connector: &'static str,
    count: u32,
}

const TRR_CASES: &[TrrCase] = &[
    TrrCase {
        name: "in_process",
        listener: "A",
        connector: "A",
        count: 5,
    },
    TrrCase {
        name: "in_process",
        listener: "A",
        connector: "A",
        count: 20,
    },
    TrrCase {
        name: "sibling",
        listener: "B",
        connector: "A",
        count: 5,
    },
    TrrCase {
        name: "sibling",
        listener: "B",
        connector: "A",
        count: 20,
    },
];

pub(crate) async fn tcp_reconnect_stress_tests(r: &mut TestRunner) {
    eprintln!(
        "[tcp_stress] === TRR: TCP Reconnect Stress ({} cases) ===",
        TRR_CASES.len()
    );

    let mut port = 20_200u16;
    for tc in TRR_CASES {
        let test_id = format!("TRR.x{}.{}", tc.count, tc.name);

        let resp = r.send(tc.listener, Command::NetListen { port }).await;
        if !matches!(resp, Response::Listening { .. }) {
            r.record(
                &test_id,
                tc.connector,
                false,
                &format!("listen failed: {resp:?}"),
            );
            port += 1;
            continue;
        }

        let resp = r
            .send(
                tc.connector,
                Command::NetReconnectStress {
                    addr: format!("127.0.0.1:{port}"),
                    count: tc.count,
                    data: format!("TRR_{}", tc.name),
                },
            )
            .await;

        let pass = matches!(&resp, Response::Ok { data: Some(d) }
            if d == &format!("success={}/{}", tc.count, tc.count));
        r.record(&test_id, tc.connector, pass, &format!("{resp:?}"));

        let _ = r.send(tc.listener, Command::NetUnlisten { port }).await;
        port += 1;
    }
}

// ═══════════════════════════════════════════════════════════════════
// TF: TCP Full-Duplex — simultaneous bidirectional transfer
// ═══════════════════════════════════════════════════════════════════

const TF_AGENTS: &[&str] = &["A", "AA", "B"];
const TF_SIZE: usize = 65536;

pub(crate) async fn tcp_fullduplex_tests(r: &mut TestRunner) {
    eprintln!(
        "[tcp_stress] === TF: TCP Full-Duplex ({} agents) ===",
        TF_AGENTS.len()
    );

    let self_exe = r.self_exe.clone();
    let mut port = 20_300u16;

    for &agent in TF_AGENTS {
        let test_id = format!("TF.{agent}");

        // Start the fullduplex server via Exec (background).
        let server_resp = r
            .send(
                agent,
                Command::Exec {
                    args: vec![
                        self_exe.clone(),
                        "tcp-fullduplex".into(),
                        port.to_string(),
                        TF_SIZE.to_string(),
                    ],
                    timeout_secs: Some(30),
                    stdin: None,
                    background: true,
                },
            )
            .await;
        let server_pid = match &server_resp {
            Response::Background { pid } => Some(*pid),
            _ => {
                r.record(
                    &test_id,
                    agent,
                    false,
                    &format!("server spawn failed: {server_resp:?}"),
                );
                port += 1;
                continue;
            }
        };

        // Give server time to bind.
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Client: connect, send SIZE bytes of 'C', read SIZE bytes of 'S'.
        let client_resp = r
            .send(
                agent,
                exec_timeout(
                    vec![
                        self_exe.clone(),
                        "tcp-fullduplex-client".into(),
                        format!("127.0.0.1:{port}"),
                        TF_SIZE.to_string(),
                    ],
                    15,
                ),
            )
            .await;

        // Kill the server.
        if let Some(pid) = server_pid {
            let _ = r.send(agent, Command::Kill { pid }).await;
        }

        let pass = match &client_resp {
            Response::ExecResult { stdout, .. } => {
                stdout.contains(&format!("CLIENT:sent={TF_SIZE}")) && stdout.contains("recv=")
            }
            _ => false,
        };
        r.record(&test_id, agent, pass, &format!("{client_resp:?}"));
        port += 1;
    }
}

// ═══════════════════════════════════════════════════════════════════
// TW: TCP Cross-Worker Concurrency (extends XW5/XW6)
// ═══════════════════════════════════════════════════════════════════

const TW_COUNTS: &[u32] = &[1, 3, 5];

pub(crate) async fn tcp_cross_worker_concurrent_tests(r: &mut TestRunner) {
    eprintln!("[tcp_stress] === TW: Cross-Worker TCP Concurrency ===",);

    // Need SpawnRemote for cross-worker agents. Use "A" which has
    // remote children from earlier tests (if available).
    // First check if we can spawn a remote child.
    let resp = r
        .send(
            "A",
            Command::SpawnRemote {
                children: vec!["ARemote".to_string()],
            },
        )
        .await;
    let spawned = matches!(&resp, Response::Ok { .. });
    if !spawned {
        eprintln!("[tcp_stress] SpawnRemote failed, skipping TW tests");
        for &count in TW_COUNTS {
            r.record(
                &format!("TW.remote_listen.x{count}"),
                "A",
                false,
                "FAIL: SpawnRemote unavailable",
            );
            r.record(
                &format!("TW.local_listen.x{count}"),
                "A",
                false,
                "FAIL: SpawnRemote unavailable",
            );
        }
        return;
    }

    let mut port = 20_400u16;

    for &count in TW_COUNTS {
        // Remote listens, local sends N concurrent connections
        {
            let test_id = format!("TW.remote_listen.x{count}");
            let resp = r
                .send(
                    "A",
                    Command::Forward {
                        target: "ARemote".to_string(),
                        inner: Box::new(Command::NetListen { port }),
                    },
                )
                .await;
            if !matches!(resp, Response::Listening { .. }) {
                r.record(&test_id, "A", false, &format!("listen failed: {resp:?}"));
                port += 1;
            } else {
                let resp = r
                    .send(
                        "A",
                        Command::NetConnectMany {
                            addr: format!("127.0.0.1:{port}"),
                            data: "TW_REMOTE".to_string(),
                            count,
                            delay_ms: 0,
                        },
                    )
                    .await;
                let pass = matches!(&resp, Response::Ok { data: Some(d) }
                    if d == &format!("success={count}/{count}"));
                r.record(&test_id, "A", pass, &format!("{resp:?}"));
                let _ = r
                    .send(
                        "A",
                        Command::Forward {
                            target: "ARemote".to_string(),
                            inner: Box::new(Command::NetUnlisten { port }),
                        },
                    )
                    .await;
                port += 1;
            }
        }

        // Local listens, remote sends N concurrent connections
        {
            let test_id = format!("TW.local_listen.x{count}");
            let resp = r.send("A", Command::NetListen { port }).await;
            if !matches!(resp, Response::Listening { .. }) {
                r.record(&test_id, "A", false, &format!("listen failed: {resp:?}"));
                port += 1;
            } else {
                let resp = r
                    .send(
                        "A",
                        Command::Forward {
                            target: "ARemote".to_string(),
                            inner: Box::new(Command::NetConnectMany {
                                addr: format!("127.0.0.1:{port}"),
                                data: "TW_LOCAL".to_string(),
                                count,
                                delay_ms: 0,
                            }),
                        },
                    )
                    .await;
                let pass = matches!(&resp, Response::Ok { data: Some(d) }
                    if d == &format!("success={count}/{count}"));
                r.record(&test_id, "A", pass, &format!("{resp:?}"));
                let _ = r.send("A", Command::NetUnlisten { port }).await;
                port += 1;
            }
        }
    }
}

/// Run all TCP stress tests.
pub(crate) async fn run(r: &mut TestRunner) {
    tcp_concurrency_tests(r).await;
    tcp_data_size_tests(r).await;
    tcp_reconnect_stress_tests(r).await;
    tcp_fullduplex_tests(r).await;
    tcp_cross_worker_concurrent_tests(r).await;
}
