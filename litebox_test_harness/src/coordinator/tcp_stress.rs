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

// ═══════════════════════════════════════════════════════════════════
// TF: TCP Full-Duplex — simultaneous bidirectional transfer
// ═══════════════════════════════════════════════════════════════════

const TF_AGENTS: &[&str] = &["A", "AA", "B"];
const TF_SIZE: usize = 65536;

// ═══════════════════════════════════════════════════════════════════
// TW: TCP Cross-Worker Concurrency (extends XW5/XW6)
// ═══════════════════════════════════════════════════════════════════

const TW_COUNTS: &[u32] = &[1, 3, 5];

pub(crate) fn register_tcp_stress(tests: &mut Vec<super::Test>) {
    register_tcp_concurrency_tests(tests);
    register_tcp_data_size_tests(tests);
    register_tcp_reconnect_stress_tests(tests);
    register_tcp_fullduplex_tests(tests);
    register_tcp_cross_worker_concurrent_tests(tests);
}

fn register_tcp_concurrency_tests(tests: &mut Vec<super::Test>) {
    let mut port = 20_001u16;
    for tc in TC_CASES {
        let test_id = format!("TC.{}.x{}.d{}", tc.name, tc.count, tc.delay_ms);
        let listener = tc.listener.to_string();
        let connector = tc.connector.to_string();
        let count = tc.count;
        let delay_ms = tc.delay_ms;
        let name = tc.name.to_string();
        let p = port;
        port += 1;

        tests.push(super::Test {
            suite: "stress",
            group: "tcp_stress",
            id: test_id,
            xfail: None,
            timeout_secs: 180,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let resp = r
                        .send(&listener, crate::protocol::Command::NetListen { port: p })
                        .await;
                    if !matches!(resp, crate::protocol::Response::Listening { .. }) {
                        return super::TestOutcome::new(
                            &connector,
                            false,
                            format!("listen failed: {resp:?}"),
                        );
                    }
                    let resp = r
                        .send(
                            &connector,
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
                    let _ = r
                        .send(&listener, crate::protocol::Command::NetUnlisten { port: p })
                        .await;
                    super::TestOutcome::new(&connector, pass, format!("{resp:?}"))
                })
            }),
        });
    }
}

fn register_tcp_data_size_tests(tests: &mut Vec<super::Test>) {
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
        let listener = tc.listener.to_string();
        let connector = tc.connector.to_string();
        let size = tc.size;
        let p = port;
        port += 1;

        tests.push(super::Test {
            suite: "stress",
            group: "tcp_stress",
            id: test_id,
            xfail: None,
            timeout_secs: 180,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let resp = r
                        .send(&listener, crate::protocol::Command::NetListen { port: p })
                        .await;
                    if !matches!(resp, crate::protocol::Response::Listening { .. }) {
                        return super::TestOutcome::new(
                            &connector,
                            false,
                            format!("listen failed: {resp:?}"),
                        );
                    }
                    let resp = r
                        .send(
                            &connector,
                            crate::protocol::Command::NetSendRecv {
                                addr: format!("127.0.0.1:{p}"),
                                size,
                            },
                        )
                        .await;
                    let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) }
                        if d.starts_with("verified="));
                    let _ = r
                        .send(&listener, crate::protocol::Command::NetUnlisten { port: p })
                        .await;
                    super::TestOutcome::new(&connector, pass, format!("{resp:?}"))
                })
            }),
        });
    }
}

fn register_tcp_reconnect_stress_tests(tests: &mut Vec<super::Test>) {
    let mut port = 20_200u16;
    for tc in TRR_CASES {
        let test_id = format!("TRR.x{}.{}", tc.count, tc.name);
        let listener = tc.listener.to_string();
        let connector = tc.connector.to_string();
        let count = tc.count;
        let name = tc.name.to_string();
        let p = port;
        port += 1;

        tests.push(super::Test {
            suite: "stress",
            group: "tcp_stress",
            id: test_id,
            xfail: None,
            timeout_secs: 180,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let resp = r
                        .send(&listener, crate::protocol::Command::NetListen { port: p })
                        .await;
                    if !matches!(resp, crate::protocol::Response::Listening { .. }) {
                        return super::TestOutcome::new(
                            &connector,
                            false,
                            format!("listen failed: {resp:?}"),
                        );
                    }
                    let resp = r
                        .send(
                            &connector,
                            crate::protocol::Command::NetReconnectStress {
                                addr: format!("127.0.0.1:{p}"),
                                count,
                                data: format!("TRR_{name}"),
                            },
                        )
                        .await;
                    let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) }
                        if d == &format!("success={count}/{count}"));
                    let _ = r
                        .send(&listener, crate::protocol::Command::NetUnlisten { port: p })
                        .await;
                    super::TestOutcome::new(&connector, pass, format!("{resp:?}"))
                })
            }),
        });
    }
}

fn register_tcp_fullduplex_tests(tests: &mut Vec<super::Test>) {
    let mut port = 20_300u16;
    for &agent in TF_AGENTS {
        let test_id = format!("TF.{agent}");
        let agent_s = agent.to_string();
        let p = port;
        port += 1;

        tests.push(super::Test {
            suite: "stress",
            group: "tcp_stress",
            id: test_id,
            xfail: None,
            timeout_secs: 180,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let server_resp = r
                        .send(
                            &agent_s,
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
                                &agent_s,
                                false,
                                format!("server spawn failed: {server_resp:?}"),
                            );
                        }
                    };
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    let client_resp = r
                        .send(
                            &agent_s,
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
                        let _ = r
                            .send(&agent_s, crate::protocol::Command::Kill { pid })
                            .await;
                    }
                    let pass = match &client_resp {
                        crate::protocol::Response::ExecResult { stdout, .. } => {
                            stdout.contains(&format!("CLIENT:sent={TF_SIZE}"))
                                && stdout.contains("recv=")
                        }
                        _ => false,
                    };
                    super::TestOutcome::new(&agent_s, pass, format!("{client_resp:?}"))
                })
            }),
        });
    }
}

fn register_tcp_cross_worker_concurrent_tests(tests: &mut Vec<super::Test>) {
    let mut port = 20_400u16;
    for &count in TW_COUNTS {
        {
            let test_id = format!("TW.remote_listen.x{count}");
            let p = port;
            port += 1;

            tests.push(super::Test {
                suite: "stress",
                group: "tcp_stress",
                id: test_id,
                xfail: None,
                timeout_secs: 180,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let resp = r
                            .send(
                                "A",
                                crate::protocol::Command::SpawnRemote {
                                    children: vec!["ARemote".to_string()],
                                },
                            )
                            .await;
                        if !matches!(&resp, crate::protocol::Response::Ok { .. }) {
                            return super::TestOutcome::new(
                                "A",
                                false,
                                "FAIL: SpawnRemote unavailable",
                            );
                        }
                        let resp = r
                            .send(
                                "A",
                                crate::protocol::Command::Forward {
                                    target: "ARemote".to_string(),
                                    inner: Box::new(crate::protocol::Command::NetListen {
                                        port: p,
                                    }),
                                },
                            )
                            .await;
                        if !matches!(resp, crate::protocol::Response::Listening { .. }) {
                            return super::TestOutcome::new(
                                "A",
                                false,
                                format!("listen failed: {resp:?}"),
                            );
                        }
                        let resp = r
                            .send(
                                "A",
                                crate::protocol::Command::NetConnectMany {
                                    addr: format!("127.0.0.1:{p}"),
                                    data: "TW_REMOTE".to_string(),
                                    count,
                                    delay_ms: 0,
                                },
                            )
                            .await;
                        let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) }
                            if d == &format!("success={count}/{count}"));
                        let _ = r
                            .send(
                                "A",
                                crate::protocol::Command::Forward {
                                    target: "ARemote".to_string(),
                                    inner: Box::new(crate::protocol::Command::NetUnlisten {
                                        port: p,
                                    }),
                                },
                            )
                            .await;
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        {
            let test_id = format!("TW.local_listen.x{count}");
            let p = port;
            port += 1;

            tests.push(super::Test {
                suite: "stress",
                group: "tcp_stress",
                id: test_id,
                xfail: None,
                timeout_secs: 180,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let resp = r
                            .send(
                                "A",
                                crate::protocol::Command::SpawnRemote {
                                    children: vec!["ARemote".to_string()],
                                },
                            )
                            .await;
                        if !matches!(&resp, crate::protocol::Response::Ok { .. }) {
                            return super::TestOutcome::new(
                                "A",
                                false,
                                "FAIL: SpawnRemote unavailable",
                            );
                        }
                        let resp = r
                            .send("A", crate::protocol::Command::NetListen { port: p })
                            .await;
                        if !matches!(resp, crate::protocol::Response::Listening { .. }) {
                            return super::TestOutcome::new(
                                "A",
                                false,
                                format!("listen failed: {resp:?}"),
                            );
                        }
                        let resp = r
                            .send(
                                "A",
                                crate::protocol::Command::Forward {
                                    target: "ARemote".to_string(),
                                    inner: Box::new(crate::protocol::Command::NetConnectMany {
                                        addr: format!("127.0.0.1:{p}"),
                                        data: "TW_LOCAL".to_string(),
                                        count,
                                        delay_ms: 0,
                                    }),
                                },
                            )
                            .await;
                        let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) }
                            if d == &format!("success={count}/{count}"));
                        let _ = r
                            .send("A", crate::protocol::Command::NetUnlisten { port: p })
                            .await;
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
}
