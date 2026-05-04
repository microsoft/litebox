// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Contamination sequence tests — inherently sequential tests that depend on
//! accumulated per-agent state from prior execs.
//!
//! These cannot be expressed as cross-product loops because each test depends
//! on the state left by the previous exec on the same agent (e.g., "run
//! non-PIE, then run PIE — does the PIE see clean output?").

use super::{TestRunner, exec};
use crate::protocol::{Command, Response};

/// Contamination isolation sequence tests (X49-X59).
pub(super) async fn contamination_sequence_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    let bash = |cmd: &str| -> Vec<String> { vec!["bash".into(), "-c".into(), cmd.into()] };

    eprintln!("[special] === Contamination Sequence Tests ===");

    let nonpie_bin = crate::find_nonpie_binary();
    let nonpie_args = |bin: &str| -> Vec<String> { vec![bin.into(), "echo-test".into()] };

    // X49: Two sequential PIE execs — baseline.
    let resp = r
        .send("A", exec(vec![self_exe.clone(), "echo-test".into()]))
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
    r.record("X49a.pie_sequential_1", "A", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "A",
            exec(vec![self_exe.clone(), "exit-with".into(), "0".into()]),
        )
        .await;
    let pass =
        matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.is_empty());
    r.record("X49b.pie_sequential_2", "A", pass, &format!("{resp:?}"));

    // X50: PIE after non-PIE on same agent.
    if let Some(ref nonpie) = nonpie_bin {
        let resp = r.send("A", exec(nonpie_args(nonpie))).await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
        r.record("X50a.nonpie_then_pie_1", "A", pass, &format!("{resp:?}"));

        let resp = r
            .send("A", exec(vec![self_exe.clone(), "echo-test".into()]))
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
        r.record("X50b.nonpie_then_pie_2", "A", pass, &format!("{resp:?}"));
    } else {
        r.record(
            "X50a.nonpie_then_pie_1",
            "A",
            false,
            "FAIL: nonpie binary not found — mount at /opt/nonpie",
        );
        r.record(
            "X50b.nonpie_then_pie_2",
            "A",
            false,
            "FAIL: nonpie binary not found — mount at /opt/nonpie",
        );
    }

    // X51-X52: Non-PIE on fresh agent B, then PIE sequence.
    if let Some(ref nonpie) = nonpie_bin {
        let resp = r.send("B", exec(nonpie_args(nonpie))).await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
        r.record("X51.nonpie_fresh_agent", "B", pass, &format!("{resp:?}"));

        let resp = r
            .send("B", exec(vec![self_exe.clone(), "echo-test".into()]))
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
        r.record("X52a.B_nonpie_then_pie", "B", pass, &format!("{resp:?}"));

        let resp = r
            .send(
                "B",
                exec(vec![self_exe.clone(), "exit-with".into(), "0".into()]),
            )
            .await;
        let pass =
            matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.is_empty());
        r.record("X52b.B_pie_after_nonpie", "B", pass, &format!("{resp:?}"));

        let resp = r
            .send("B", exec(vec![self_exe.clone(), "echo-test".into()]))
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
        r.record("X52c.B_third_exec", "B", pass, &format!("{resp:?}"));
    } else {
        r.record(
            "X51.nonpie_fresh_agent",
            "B",
            false,
            "FAIL: nonpie binary not found — mount at /opt/nonpie",
        );
        r.record(
            "X52a.B_nonpie_then_pie",
            "B",
            false,
            "FAIL: nonpie binary not found — mount at /opt/nonpie",
        );
        r.record(
            "X52b.B_pie_after_nonpie",
            "B",
            false,
            "FAIL: nonpie binary not found — mount at /opt/nonpie",
        );
        r.record(
            "X52c.B_third_exec",
            "B",
            false,
            "FAIL: nonpie binary not found — mount at /opt/nonpie",
        );
    }

    // X53: Stress — 30 sequential PIE execs on fresh agent AB.
    let mut x53_all_pass = true;
    for i in 0..30 {
        let resp = r
            .send("AB", exec(vec![self_exe.clone(), "echo-test".into()]))
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
        if !pass {
            r.record(
                "X53.stress_pie",
                "AB",
                false,
                &format!("failed at iteration {i}: {resp:?}"),
            );
            x53_all_pass = false;
            break;
        }
    }
    if x53_all_pass {
        r.record(
            "X53.stress_pie",
            "AB",
            true,
            "30 sequential PIE execs all passed",
        );
    }

    // X54: Non-PIE after 30 PIE execs on AB.
    if let Some(ref nonpie) = nonpie_bin {
        let resp = r.send("AB", exec(nonpie_args(nonpie))).await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
        r.record("X54.nonpie_after_stress", "AB", pass, &format!("{resp:?}"));
    } else {
        r.record(
            "X54.nonpie_after_stress",
            "AB",
            false,
            "FAIL: nonpie binary not found — mount at /opt/nonpie",
        );
    }

    // X55: Non-PIE as second exec on fresh agent AAB.
    let resp = r
        .send("AAB", exec(vec![self_exe.clone(), "echo-test".into()]))
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
    r.record("X55a.one_pie_first", "AAB", pass, &format!("{resp:?}"));

    if let Some(ref nonpie) = nonpie_bin {
        let resp = r.send("AAB", exec(nonpie_args(nonpie))).await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
        r.record("X55b.nonpie_second", "AAB", pass, &format!("{resp:?}"));
    } else {
        r.record(
            "X55b.nonpie_second",
            "AAB",
            false,
            "FAIL: nonpie binary not found — mount at /opt/nonpie",
        );
    }

    // X56-X59: Sequence tests on B.
    if let Some(ref nonpie) = nonpie_bin {
        let resp = r.send("B", exec(nonpie_args(nonpie))).await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
        r.record("X56.second_nonpie_on_B", "B", pass, &format!("{resp:?}"));

        // X57: Pipe churn then non-PIE.
        for _ in 0..20 {
            let _ = r.send("B", exec(bash("echo churn >/dev/null"))).await;
        }
        let resp = r.send("B", exec(nonpie_args(nonpie))).await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
        r.record(
            "X57.pipe_churn_then_nonpie",
            "B",
            pass,
            &format!("{resp:?}"),
        );

        // X58: Alternating PIE and non-PIE.
        let results: Vec<(String, bool)> = {
            let mut results = Vec::new();
            for _ in 0..2 {
                let resp = r
                    .send("B", exec(vec![self_exe.clone(), "echo-test".into()]))
                    .await;
                let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
                results.push((format!("{resp:?}"), pass));

                let resp = r.send("B", exec(nonpie_args(nonpie))).await;
                let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
                results.push((format!("{resp:?}"), pass));
            }
            results
        };
        let all_pass = results.iter().all(|(_, p)| *p);
        let detail = results
            .iter()
            .enumerate()
            .map(|(i, (d, p))| format!("[{i}]={p}: {d}"))
            .collect::<Vec<_>>()
            .join("; ");
        r.record("X58.alternating_pie_nonpie", "B", all_pass, &detail);

        // X59: Sequential non-PIE.
        let mut x59_all_pass = true;
        for i in 0..5 {
            let resp = r.send("B", exec(nonpie_args(nonpie))).await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
            if !pass {
                r.record(
                    "X59.sequential_nonpie",
                    "B",
                    false,
                    &format!("failed at iteration {i}: {resp:?}"),
                );
                x59_all_pass = false;
                break;
            }
        }
        if x59_all_pass {
            r.record(
                "X59.sequential_nonpie",
                "B",
                true,
                "5 sequential non-PIE execs all passed",
            );
        }
    }
}

/// Netlink / getifaddrs layered tests.
pub(super) async fn netlink_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    eprintln!("[special] === Netlink Tests ===");

    let resp = r
        .send(
            "A",
            exec(vec![
                self_exe.clone(),
                "getifaddrs-test".into(),
                "socket".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NETLINK_SOCKET_OK"));
    r.record("NL1.netlink_socket", "A", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "A",
            exec(vec![
                self_exe.clone(),
                "getifaddrs-test".into(),
                "bind".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NETLINK_BIND_OK"));
    r.record("NL2.netlink_bind", "A", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "A",
            exec(vec![
                self_exe.clone(),
                "getifaddrs-test".into(),
                "getlink".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NETLINK_GETLINK_OK"));
    r.record("NL3.netlink_getlink", "A", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "A",
            exec(vec![
                self_exe.clone(),
                "getifaddrs-test".into(),
                "getaddr".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NETLINK_GETADDR_OK"));
    r.record("NL4.netlink_getaddr", "A", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "A",
            exec(vec![
                self_exe.clone(),
                "getifaddrs-test".into(),
                "sendmsg".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NETLINK_SENDMSG_RECVMSG_OK"));
    r.record("NL3b.sendmsg_recvmsg", "A", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "A",
            super::exec_timeout(
                vec![self_exe.clone(), "getifaddrs-test".into(), "double".into()],
                30,
            ),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NETLINK_DOUBLE_OK"));
    r.record("NL3c.double_request", "A", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "A",
            super::exec_timeout(
                vec![
                    self_exe.clone(),
                    "getifaddrs-test".into(),
                    "peek-trunc".into(),
                ],
                30,
            ),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NETLINK_PEEK_TRUNC_OK"));
    r.record("NL3d.peek_trunc", "A", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "A",
            super::exec_timeout(
                vec![self_exe.clone(), "getifaddrs-test".into(), "full".into()],
                30,
            ),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("GETIFADDRS_OK"));
    r.record("NL5.getifaddrs_full", "A", pass, &format!("{resp:?}"));

    // X48 / NL6: Node.js os.networkInterfaces()
    let resp = r.send("A", super::exec_timeout(vec![
        "/usr/local/bin/node".into(), "-e".into(),
        "try { const r = require('os').networkInterfaces(); console.log('NETIF_OK:' + Object.keys(r).length); } catch(e) { console.log('NETIF_ERR:' + e.code); }".into(),
    ], 30)).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
        if stdout.contains("NETIF_OK:") || stdout.contains("NETIF_ERR:"));
    r.record(
        "X48.node_networkInterfaces",
        "A",
        pass,
        &format!("{resp:?}"),
    );

    // NL6: Check if getifaddrs returns AF_PACKET entries (MAC address)
    let resp = r
        .send(
            "A",
            super::exec_timeout(
                vec![self_exe.clone(), "unix-socket-test".into(), "mac".into()],
                30,
            ),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NL6_MAC_CHECK"));
    r.record("NL6.mac_address", "A", pass, &format!("{resp:?}"));
}

/// Unix socket cross-process tests.
pub(super) async fn unix_socket_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    eprintln!("[special] === Unix Socket Tests ===");

    // US1-US4, US5, VS1: Run via Exec subprocess so that timeouts kill
    // the subprocess cleanly without desynchronizing the agent's protocol.
    let tests = [
        (
            "US1.cross_process_unix",
            "cross-process",
            "US1_CROSS_PROCESS_OK",
        ),
        ("US2.cross_exec_unix", "cross-exec", "US2_CROSS_EXEC_OK"),
        ("US3.bidirectional_unix", "bidirectional", "US3_BIDI_OK"),
        ("US4.multi_conn_unix", "multi-conn", "US4_MULTI_OK"),
        ("US5.abstract_unix", "abstract", "US5_ABSTRACT_OK"),
        ("VS1.socket_race", "race", "VS1_RACE_OK"),
    ];

    for (name, sub, expected) in &tests {
        let resp = r
            .send(
                "A",
                super::exec_timeout(
                    vec![self_exe.clone(), "unix-socket-test".into(), (*sub).into()],
                    10,
                ),
            )
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains(expected));
        r.record(name, "A", pass, &format!("{resp:?}"));
    }

    // Run the same fork+bind+connect pattern on different agents to validate
    // across worker topologies (fork-restore, worker-exec, etc.).
    let fork_agents = ["A", "AA", "B"];
    for agent in &fork_agents {
        let test_name = format!("UF.fork_unix.{agent}");
        let resp = r
            .send(
                agent,
                super::exec_timeout(
                    vec![
                        self_exe.clone(),
                        "unix-socket-test".into(),
                        "cross-process".into(),
                    ],
                    15,
                ),
            )
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("US1_CROSS_PROCESS_OK"));
        r.record(&test_name, agent, pass, &format!("{resp:?}"));
    }

    // US6: socketpair(AF_UNIX) + fork — tests both directions.
    // US6a (write): child writes to inherited fd, parent reads after waitpid.
    // US6b (read): parent writes, child reads from inherited fd.
    // Runs across all agent topologies to catch SpawnRemote snapshot issues
    // where unix socket fds fail to transfer.
    let socketpair_agents = ["A", "AA", "B", "D3", "D4", "NP"];
    for agent in &socketpair_agents {
        // child→parent (write direction)
        let test_name = format!("US6.socketpair_write.{agent}");
        let resp = r
            .send(
                agent,
                super::exec_timeout(
                    vec![
                        self_exe.clone(),
                        "unix-socket-test".into(),
                        "socketpair-fork-write".into(),
                    ],
                    15,
                ),
            )
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("US6_SOCKETPAIR_FORK_OK"));
        r.record(&test_name, agent, pass, &format!("{resp:?}"));

        // parent→child (read direction)
        let test_name = format!("US6.socketpair_read.{agent}");
        let resp = r
            .send(
                agent,
                super::exec_timeout(
                    vec![
                        self_exe.clone(),
                        "unix-socket-test".into(),
                        "socketpair-fork-read".into(),
                    ],
                    15,
                ),
            )
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("US6R_SOCKETPAIR_FORK_READ_OK"));
        r.record(&test_name, agent, pass, &format!("{resp:?}"));
    }

    // US6c: socketpair(AF_UNIX) + fork+exec — bidirectional IPC.
    // Reproduces the exact VS Code extension host pattern:
    //   parent: socketpair() → fork+exec(child) → write → read reply
    //   child (exec'd): read from inherited fd → write reply → exit
    // This is the critical test — the exec triggers SpawnRemote migration,
    // and the inherited socketpair fd must survive the exec boundary.
    let exec_agents = ["A", "AA", "B", "D3", "D4", "NP"];
    for agent in &exec_agents {
        let test_name = format!("US6.socketpair_exec.{agent}");
        let resp = r
            .send(
                agent,
                super::exec_timeout(
                    vec![
                        self_exe.clone(),
                        "unix-socket-test".into(),
                        "socketpair-exec".into(),
                    ],
                    20,
                ),
            )
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("US6E_SOCKETPAIR_EXEC_OK"));
        r.record(&test_name, agent, pass, &format!("{resp:?}"));
    }

    // US6d: socketpair+fork+exec via nonpie binary — reproduces VS Code pattern.
    // The nonpie exec triggers exec-on-remote-host, creating a new worker.
    // Inside that worker, socketpair → fork → execv triggers a nested delayed
    // fork where the socketpair fd must be bridged across workers.
    // This is the exact VS Code extension host pattern:
    //   code CLI (PIE) → exec(code-server, non-PIE musl) → socketpair → fork → exec(node)
    if let Some(nonpie) = crate::find_nonpie_binary() {
        let nonpie_agents = ["A", "AA", "B"];
        for agent in &nonpie_agents {
            let test_name = format!("US6.socketpair_nonpie.{agent}");
            let resp = r
                .send(
                    agent,
                    super::exec_timeout(
                        vec![
                            nonpie.clone(),
                            "unix-socket-test".into(),
                            "socketpair-exec".into(),
                        ],
                        30,
                    ),
                )
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("US6E_SOCKETPAIR_EXEC_OK"));
            r.record(&test_name, agent, pass, &format!("{resp:?}"));
        }
    }
}

/// Pipe EOF lifecycle tests — verify relay pipes close properly after child exits.
pub(super) async fn pipe_eof_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    eprintln!("[special] === Pipe EOF Lifecycle Tests ===");

    // P1: pipe + fork — child writes + exits → parent gets data + EOF.
    let fork_agents = ["A", "AA", "B", "D3", "D4", "NP"];
    for agent in &fork_agents {
        let test_name = format!("P1.pipe_eof_fork.{agent}");
        let resp = r
            .send(
                agent,
                super::exec_timeout(
                    vec![self_exe.clone(), "pipe-test".into(), "eof-fork".into()],
                    20,
                ),
            )
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("P1_EOF_OK"));
        r.record(&test_name, agent, pass, &format!("{resp:?}"));
    }

    // P2-PIE: fork+exec(PIE) → parent reads child stdout → expects data + EOF.
    let exec_agents = ["A", "AA", "B"];
    for agent in &exec_agents {
        let test_name = format!("P2.pipe_eof_exec_pie.{agent}");
        let resp = r
            .send(
                agent,
                super::exec_timeout(
                    vec![
                        self_exe.clone(),
                        "pipe-test".into(),
                        "eof-exec".into(),
                        self_exe.clone(), // PIE binary
                    ],
                    20,
                ),
            )
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("P2_EOF_OK"));
        r.record(&test_name, agent, pass, &format!("{resp:?}"));
    }

    // P2-NONPIE: fork+exec(nonpie) → triggers exec-on-remote-host with mux relay.
    // This is the critical test — the mux relay pipe's write end must close
    // when the child worker exits so the parent gets EOF.
    if let Some(nonpie) = crate::find_nonpie_binary() {
        let nonpie_agents = ["A", "AA", "B"];
        for agent in &nonpie_agents {
            let test_name = format!("P2.pipe_eof_exec_nonpie.{agent}");
            let resp = r
                .send(
                    agent,
                    super::exec_timeout(
                        vec![
                            self_exe.clone(),
                            "pipe-test".into(),
                            "eof-exec".into(),
                            nonpie.clone(), // non-PIE → exec-on-remote-host
                        ],
                        20,
                    ),
                )
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("P2_EOF_OK"));
            r.record(&test_name, agent, pass, &format!("{resp:?}"));
        }
    }
}
pub(super) async fn node_exit_tests(r: &mut TestRunner) {
    eprintln!("[special] === Node.js Exit Tests ===");

    // EX6: node --version should print version and exit with code 0
    let resp = r
        .send(
            "A",
            super::exec_timeout(vec!["/usr/local/bin/node".into(), "--version".into()], 10),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.starts_with('v'));
    r.record("EX6.node_version_exit", "A", pass, &format!("{resp:?}"));

    // EX7: node -e 'process.exit(0)' should exit immediately with code 0
    let resp = r
        .send(
            "A",
            super::exec_timeout(
                vec![
                    "/usr/local/bin/node".into(),
                    "-e".into(),
                    "process.exit(0)".into(),
                ],
                10,
            ),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, .. });
    r.record("EX7.node_process_exit", "A", pass, &format!("{resp:?}"));

    // EX8: node -e 'process.exit(42)' should exit with code 42
    let resp = r
        .send(
            "A",
            super::exec_timeout(
                vec![
                    "/usr/local/bin/node".into(),
                    "-e".into(),
                    "process.exit(42)".into(),
                ],
                10,
            ),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 42, .. });
    r.record("EX8.node_exit_code", "A", pass, &format!("{resp:?}"));

    // EX9: node -e 'console.log("HELLO")' should print and exit
    let resp = r
        .send(
            "A",
            super::exec_timeout(
                vec![
                    "/usr/local/bin/node".into(),
                    "-e".into(),
                    "console.log(\"NODE_EXIT_OK\")".into(),
                ],
                10,
            ),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NODE_EXIT_OK"));
    r.record("EX9.node_console_exit", "A", pass, &format!("{resp:?}"));
}

/// Terminal ioctl matrix tests: op × fd.
/// Coordinator agents have pipes (not TTYs), so ioctls return ENOTTY.
/// We still run them to verify they don't hang — ENOTTY is a valid result.
pub(super) async fn terminal_ioctl_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    let ops = ["tcgets", "tcsets", "tcsetsw", "tcsetsf", "tiocgwinsz"];
    let fds = [0, 1, 2];

    eprintln!(
        "[special] === Terminal Ioctl Matrix ({} ops × {} fds) ===",
        ops.len(),
        fds.len()
    );

    for op in &ops {
        for fd in &fds {
            let test_name = format!("TERM.{op}_fd{fd}");
            let resp = r
                .send(
                    "A",
                    super::exec_timeout(
                        vec![
                            self_exe.clone(),
                            "exit-test".into(),
                            "term".into(),
                            (*op).into(),
                            fd.to_string(),
                        ],
                        8,
                    ),
                )
                .await;
            // Accept both TERM_OK (real TTY) and TERM_ERR with ENOTTY (pipes).
            // The key validation is that the ioctl doesn't hang.
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0 | 1, stdout, .. }
                if stdout.contains("TERM_OK") || stdout.contains("TERM_ERR"));
            r.record(&test_name, "A", pass, &format!("{resp:?}"));
        }
    }
}

/// Filesystem I/O matrix tests: op × path.
pub(super) async fn fs_io_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    let ops = [
        "write-read",
        "append-read",
        "write-bg-read",
        "redirect-bg-read",
        "fork-write-read",
        "bg-open-read",
        "parent-open-fork-read",
    ];
    let paths = ["/tmp/fs-test.txt", "/root/fs-test.txt"];

    eprintln!(
        "[special] === FS I/O Matrix ({} ops × {} paths) ===",
        ops.len(),
        paths.len()
    );

    for op in &ops {
        for path in &paths {
            let dir = if path.contains("/tmp/") {
                "tmp"
            } else {
                "root"
            };
            let test_name = format!("FS.{op}.{dir}");
            let resp = r
                .send(
                    "A",
                    super::exec_timeout(
                        vec![
                            self_exe.clone(),
                            "fs-test".into(),
                            "io".into(),
                            (*op).into(),
                            (*path).into(),
                        ],
                        15,
                    ),
                )
                .await;
            let pass =
                matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("FS_OK"));
            r.record(&test_name, "A", pass, &format!("{resp:?}"));
        }
    }

    // Exec-write matrix: binary_type × path
    // "child writes file, exits, then parent reads"
    let bin_types = ["pie", "nonpie"];
    let exec_paths = ["/tmp/fs-exec.txt"];

    eprintln!(
        "[special] === FS Exec-Write ({} bins × {} paths) ===",
        bin_types.len(),
        exec_paths.len()
    );

    for bin in &bin_types {
        for path in &exec_paths {
            let pname = path.rsplit('/').next().unwrap_or(path);
            let resp = r
                .send(
                    "A",
                    super::exec_timeout(
                        vec![
                            self_exe.clone(),
                            "fs-test".into(),
                            "exec-write".into(),
                            (*bin).into(),
                            (*path).into(),
                        ],
                        30,
                    ),
                )
                .await;
            let pass =
                matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("FS_OK"));
            r.record(
                &format!("FS.exec_{bin}_{pname}"),
                "A",
                pass,
                &format!("{resp:?}"),
            );
        }
    }

    // Exec-open-read matrix: binary_type × path
    // "child writes file and stays alive, parent reads WHILE child running"
    // This tests 9P coherence for files written by a remote worker.
    eprintln!(
        "[special] === FS Exec-Open-Read ({} bins × {} paths) ===",
        bin_types.len(),
        exec_paths.len()
    );

    for bin in &bin_types {
        for path in &exec_paths {
            let pname = path.rsplit('/').next().unwrap_or(path);
            let resp = r
                .send(
                    "A",
                    super::exec_timeout(
                        vec![
                            self_exe.clone(),
                            "fs-test".into(),
                            "exec-open-read".into(),
                            (*bin).into(),
                            (*path).into(),
                        ],
                        30,
                    ),
                )
                .await;
            let pass =
                matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("FS_OK"));
            r.record(
                &format!("FS.open_{bin}_{pname}"),
                "A",
                pass,
                &format!("{resp:?}"),
            );
        }
    }
}

/// IPv6 network tests.
pub(super) async fn net_ipv6_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    let tests = [
        ("NET1.ipv6_socket", "ipv6-socket"),
        ("NET2.ipv6_listen", "ipv6-listen"),
        ("NET4.ipv4_listen", "ipv4-listen"),
        ("NET5.ipv6_getaddrinfo", "ipv6-getaddrinfo"),
        ("NET6.ipv6_v6only", "ipv6-v6only"),
    ];

    eprintln!(
        "[special] === IPv6 Network Tests ({} cases) ===",
        tests.len()
    );

    for (name, sub) in &tests {
        let resp = r
            .send(
                "A",
                super::exec_timeout(vec![self_exe.clone(), "net-test".into(), (*sub).into()], 10),
            )
            .await;
        let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("_OK"));
        r.record(name, "A", pass, &format!("{resp:?}"));
    }
}

/// Stdin-piped script tests: pipe shell scripts to sh/bash via the Exec
/// protocol's stdin field. Reproduces the VS Code install script pattern
/// where the script is piped through `ssh host sh`.
///
/// Matrix: 8 scripts × 2 shells × 2 agent depths.
pub(super) async fn stdin_script_tests(r: &mut TestRunner) {
    const SCRIPTS: &[(&str, &str, &str)] = &[
        (
            "cmd_subst",
            "FOO=$(echo hello)\necho FOO=$FOO\necho DONE\n",
            "FOO=hello",
        ),
        (
            "pipe_in_subst",
            "A=$(echo one | cat)\necho A=$A\necho DONE\n",
            "A=one",
        ),
        (
            "multi_pipe_subst",
            "A=$(echo data | grep data | cat)\necho A=$A\necho DONE\n",
            "A=data",
        ),
        (
            "file_pipe_subst",
            "A=$(cat /etc/hostname | cat)\necho A=$A\necho DONE\n",
            "DONE",
        ),
        (
            "sequential_subst",
            "A=$(echo first)\nB=$(echo second)\necho A=$A B=$B\necho DONE\n",
            "A=first B=second",
        ),
        (
            "subst_then_cmds",
            "A=$(echo val | cat)\necho LINE1\necho LINE2\necho LINE3\n",
            "LINE3",
        ),
        (
            "vscode_osrelease",
            "ID=$(cat /etc/os-release | grep -E '^ID=' | sed 's/ID=//g' | sed 's/\"//g')\necho ID=$ID\necho DONE\n",
            "DONE",
        ),
        (
            "backtick_pipe",
            "A=`echo one | cat`\necho A=$A\necho DONE\n",
            "A=one",
        ),
    ];
    const SHELLS: &[&str] = &["sh", "bash"];
    const AGENTS: &[&str] = &["A", "AA"];

    eprintln!(
        "[special] === Stdin-Piped Script Tests ({} × {} × {}) ===",
        SCRIPTS.len(),
        SHELLS.len(),
        AGENTS.len()
    );

    for agent in AGENTS {
        for shell in SHELLS {
            for &(name, script, expected) in SCRIPTS {
                let test_id = format!("SS.{name}.{shell}.{agent}");
                let resp = r
                    .send(
                        agent,
                        Command::Exec {
                            args: vec![(*shell).into()],
                            timeout_secs: Some(10),
                            stdin: Some(script.into()),
                            background: false,
                        },
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    Response::ExecResult { stdout, .. } if stdout.contains(expected)
                );
                r.record(&test_id, agent, pass, &format!("{resp:?}"));
            }
        }
    }
}

/// Capture-pipe fork tests: minimal reproduction of the $() mechanism.
/// pipe() → fork() → child: dup2 + exec → parent: read capture pipe.
/// Tests the delayed-fork capture pipe bridging directly.
///
/// Matrix: 3 cmd types × 2 shells × 2 agent depths.
pub(super) async fn capture_pipe_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    const CMD_TYPES: &[&str] = &[
        "simple",
        "pipe",
        "multi",
        "noexec",
        "nested_fork",
        "subshell_pipe",
        "subshell_continue",
    ];
    const SHELLS: &[&str] = &["sh", "bash"];
    const AGENTS: &[&str] = &["A", "AA"];

    eprintln!(
        "[special] === Capture-Pipe Fork Tests ({} × {} × {}) ===",
        CMD_TYPES.len(),
        SHELLS.len(),
        AGENTS.len()
    );

    for agent in AGENTS {
        for shell in SHELLS {
            for cmd_type in CMD_TYPES {
                let test_id = format!("CP.{cmd_type}.{shell}.{agent}");
                let resp = r
                    .send(
                        agent,
                        super::exec_timeout(
                            vec![
                                self_exe.clone(),
                                "capture-pipe".into(),
                                (*cmd_type).into(),
                                (*shell).into(),
                            ],
                            10,
                        ),
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    Response::ExecResult { stdout, .. } if stdout.contains("CP_OK")
                );
                r.record(&test_id, agent, pass, &format!("{resp:?}"));
            }
        }
    }
}

pub(super) async fn cross_worker_tests(r: &mut TestRunner) {
    eprintln!("[special] === Cross-Worker Tests (SpawnRemote) ===");

    let resp = r
        .send(
            "A",
            Command::SpawnRemote {
                children: vec!["R".to_string()],
            },
        )
        .await;
    let spawned = matches!(&resp, Response::Ok { .. });
    r.record("XW.spawn_remote", "A", spawned, &format!("{resp:?}"));
    if !spawned {
        eprintln!("[special] SpawnRemote failed, skipping cross-worker tests");
        return;
    }

    // XW1: Remote writes, local reads
    let resp = r
        .send(
            "A",
            Command::Forward {
                target: "R".to_string(),
                inner: Box::new(Command::FsWrite {
                    path: "/tmp/xw1.txt".to_string(),
                    data: "REMOTE_DATA".to_string(),
                }),
            },
        )
        .await;
    r.record(
        "XW1.remote_write",
        "A",
        matches!(&resp, Response::Ok { .. }),
        &format!("{resp:?}"),
    );

    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/tmp/xw1.txt".to_string(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d), .. } if d == "REMOTE_DATA");
    r.record("XW1.local_read", "A", pass, &format!("{resp:?}"));

    // XW2: Local writes, remote reads
    let resp = r
        .send(
            "A",
            Command::FsWrite {
                path: "/tmp/xw2.txt".to_string(),
                data: "LOCAL_DATA".to_string(),
            },
        )
        .await;
    r.record(
        "XW2.local_write",
        "A",
        matches!(&resp, Response::Ok { .. }),
        &format!("{resp:?}"),
    );

    let resp = r
        .send(
            "A",
            Command::Forward {
                target: "R".to_string(),
                inner: Box::new(Command::FsRead {
                    path: "/tmp/xw2.txt".to_string(),
                }),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d), .. } if d == "LOCAL_DATA");
    r.record("XW2.remote_read", "A", pass, &format!("{resp:?}"));

    // XW3: Remote listens unix socket, local connects
    let resp = r
        .send(
            "A",
            Command::Forward {
                target: "R".to_string(),
                inner: Box::new(Command::UnixListen {
                    path: "/tmp/xw3.sock".to_string(),
                }),
            },
        )
        .await;
    let listen_ok = matches!(&resp, Response::UnixListening { .. });
    r.record("XW3.remote_listen", "A", listen_ok, &format!("{resp:?}"));

    if listen_ok {
        let resp = r
            .send(
                "A",
                Command::UnixConnect {
                    path: "/tmp/xw3.sock".to_string(),
                    data: "XW_HELLO".to_string(),
                },
            )
            .await;
        let pass = matches!(&resp, Response::Connected { echo } if echo.contains("XW_HELLO"));
        r.record("XW3.local_connect", "A", pass, &format!("{resp:?}"));
    }

    // XW4: Local listens, remote connects
    let resp = r
        .send(
            "A",
            Command::UnixListen {
                path: "/tmp/xw4.sock".to_string(),
            },
        )
        .await;
    let listen_ok = matches!(&resp, Response::UnixListening { .. });
    r.record("XW4.local_listen", "A", listen_ok, &format!("{resp:?}"));

    if listen_ok {
        let resp = r
            .send(
                "A",
                Command::Forward {
                    target: "R".to_string(),
                    inner: Box::new(Command::UnixConnect {
                        path: "/tmp/xw4.sock".to_string(),
                        data: "XW_HELLO2".to_string(),
                    }),
                },
            )
            .await;
        let pass = matches!(&resp, Response::Connected { echo } if echo.contains("XW_HELLO2"));
        r.record("XW4.remote_connect", "A", pass, &format!("{resp:?}"));
    }

    // XW5: Remote listens TCP, local connects (TCP should work cross-worker)
    let resp = r
        .send(
            "A",
            Command::Forward {
                target: "R".to_string(),
                inner: Box::new(Command::NetListen { port: 0 }),
            },
        )
        .await;
    let remote_port = match &resp {
        Response::Listening { port } => Some(*port),
        _ => None,
    };
    r.record(
        "XW5.remote_tcp_listen",
        "A",
        remote_port.is_some(),
        &format!("{resp:?}"),
    );

    if let Some(port) = remote_port {
        let resp = r
            .send(
                "A",
                Command::NetConnect {
                    addr: format!("127.0.0.1:{port}"),
                    data: "XW_TCP_HELLO".to_string(),
                },
            )
            .await;
        let pass = matches!(&resp, Response::Connected { echo } if echo.contains("XW_TCP_HELLO"));
        r.record("XW5.local_tcp_connect", "A", pass, &format!("{resp:?}"));

        let _ = r
            .send(
                "A",
                Command::Forward {
                    target: "R".to_string(),
                    inner: Box::new(Command::NetUnlisten { port }),
                },
            )
            .await;
    }

    // XW6: Local listens TCP, remote connects
    let resp = r.send("A", Command::NetListen { port: 0 }).await;
    let local_port = match &resp {
        Response::Listening { port } => Some(*port),
        _ => None,
    };
    r.record(
        "XW6.local_tcp_listen",
        "A",
        local_port.is_some(),
        &format!("{resp:?}"),
    );

    if let Some(port) = local_port {
        let resp = r
            .send(
                "A",
                Command::Forward {
                    target: "R".to_string(),
                    inner: Box::new(Command::NetConnect {
                        addr: format!("127.0.0.1:{port}"),
                        data: "XW_TCP_HELLO2".to_string(),
                    }),
                },
            )
            .await;
        let pass = matches!(&resp, Response::Connected { echo } if echo.contains("XW_TCP_HELLO2"));
        r.record("XW6.remote_tcp_connect", "A", pass, &format!("{resp:?}"));

        let _ = r.send("A", Command::NetUnlisten { port }).await;
    }

    // ─── Deep-topology Unix socket tests ───
    // These exercise the VS Code process tree pattern where the
    // server (worker-exec) and client (fork-restore) are in different
    // workers connected through a deep chain.
    //
    // D3 (PIE, fork-restore) ≈ VS Code CLI
    // D4 (non-PIE, worker-exec) ≈ node server
    // This matches the VS Code failure: CLI connects to socket
    // created by exec'd node server in a different worker.

    // XW7: D4 (worker-exec) listens, D3 (fork-restore) connects
    // This is the EXACT VS Code pattern.
    let resp = r
        .send(
            "D4",
            Command::UnixListen {
                path: "/tmp/xw7.sock".to_string(),
            },
        )
        .await;
    let listen_ok = matches!(&resp, Response::UnixListening { .. });
    r.record("XW7.d4_listen", "D4", listen_ok, &format!("{resp:?}"));

    if listen_ok {
        let resp = r
            .send(
                "D3",
                Command::UnixConnect {
                    path: "/tmp/xw7.sock".to_string(),
                    data: "XW7_D3_TO_D4".to_string(),
                },
            )
            .await;
        let pass = matches!(&resp, Response::Connected { echo } if echo.contains("XW7_D3_TO_D4"));
        r.record("XW7.d3_connect", "D3", pass, &format!("{resp:?}"));

        let _ = r
            .send(
                "D4",
                Command::UnixUnlisten {
                    path: "/tmp/xw7.sock".to_string(),
                },
            )
            .await;
    }

    // XW8: D3 (fork-restore) listens, D4 (worker-exec) connects
    let resp = r
        .send(
            "D3",
            Command::UnixListen {
                path: "/tmp/xw8.sock".to_string(),
            },
        )
        .await;
    let listen_ok = matches!(&resp, Response::UnixListening { .. });
    r.record("XW8.d3_listen", "D3", listen_ok, &format!("{resp:?}"));

    if listen_ok {
        let resp = r
            .send(
                "D4",
                Command::UnixConnect {
                    path: "/tmp/xw8.sock".to_string(),
                    data: "XW8_D4_TO_D3".to_string(),
                },
            )
            .await;
        let pass = matches!(&resp, Response::Connected { echo } if echo.contains("XW8_D4_TO_D3"));
        r.record("XW8.d4_connect", "D4", pass, &format!("{resp:?}"));

        let _ = r
            .send(
                "D3",
                Command::UnixUnlisten {
                    path: "/tmp/xw8.sock".to_string(),
                },
            )
            .await;
    }

    // XW9: D4 (worker-exec) listens, AA (grandparent, 2 hops away) connects
    let resp = r
        .send(
            "D4",
            Command::UnixListen {
                path: "/tmp/xw9.sock".to_string(),
            },
        )
        .await;
    let listen_ok = matches!(&resp, Response::UnixListening { .. });
    r.record("XW9.d4_listen", "D4", listen_ok, &format!("{resp:?}"));

    if listen_ok {
        let resp = r
            .send(
                "AA",
                Command::UnixConnect {
                    path: "/tmp/xw9.sock".to_string(),
                    data: "XW9_AA_TO_D4".to_string(),
                },
            )
            .await;
        let pass = matches!(&resp, Response::Connected { echo } if echo.contains("XW9_AA_TO_D4"));
        r.record("XW9.aa_connect", "AA", pass, &format!("{resp:?}"));

        let _ = r
            .send(
                "D4",
                Command::UnixUnlisten {
                    path: "/tmp/xw9.sock".to_string(),
                },
            )
            .await;
    }

    // ─── VS Code SOCKS pattern: cross-subtree TCP connect ───
    // VS Code opens a SECOND SSH session (new fork from INIT worker)
    // with a SOCKS proxy that connects to port 63084. The listener
    // is in a DIFFERENT fork-restore worker. This tests the exact
    // pattern: listener in one subtree, connector in a completely
    // independent subtree spawned later.
    //
    // XW10: D3 (subtree under AA) listens TCP, B (independent subtree) connects
    // This reproduces: fork-restore worker 1 listens, fork-restore worker 2 connects.
    let resp = r.send("D3", Command::NetListen { port: 0 }).await;
    let listen_port = match &resp {
        Response::Listening { port } => Some(*port),
        _ => None,
    };
    r.record(
        "XW10.d3_tcp_listen",
        "D3",
        listen_port.is_some(),
        &format!("{resp:?}"),
    );

    if let Some(port) = listen_port {
        // B connects — B is in a completely separate subtree from D3.
        // This SYN goes: B's smoltcp → broker → needs PortRouter to
        // route to D3's broker proxy.
        let resp = r
            .send(
                "B",
                Command::NetConnect {
                    addr: format!("127.0.0.1:{port}"),
                    data: "XW10_CROSS_SUBTREE".to_string(),
                },
            )
            .await;
        let pass =
            matches!(&resp, Response::Connected { echo } if echo.contains("XW10_CROSS_SUBTREE"));
        r.record("XW10.b_tcp_connect", "B", pass, &format!("{resp:?}"));

        let _ = r.send("D3", Command::NetUnlisten { port }).await;
    }

    // XW11: Same but with a freshly-spawned remote worker as connector.
    // This is even closer to VS Code: the connector doesn't exist when
    // the listener starts.
    let resp = r.send("D3", Command::NetListen { port: 0 }).await;
    let listen_port = match &resp {
        Response::Listening { port } => Some(*port),
        _ => None,
    };
    r.record(
        "XW11.d3_tcp_listen",
        "D3",
        listen_port.is_some(),
        &format!("{resp:?}"),
    );

    if let Some(port) = listen_port {
        // Spawn a fresh remote worker under B (different subtree).
        let resp = r
            .send(
                "B",
                Command::SpawnRemote {
                    children: vec!["R2".to_string()],
                },
            )
            .await;
        let spawned = matches!(&resp, Response::Ok { .. });
        r.record("XW11.spawn_r2", "B", spawned, &format!("{resp:?}"));

        if spawned {
            let resp = r
                .send(
                    "B",
                    Command::Forward {
                        target: "R2".to_string(),
                        inner: Box::new(Command::NetConnect {
                            addr: format!("127.0.0.1:{port}"),
                            data: "XW11_LATE_SPAWN".to_string(),
                        }),
                    },
                )
                .await;
            let pass =
                matches!(&resp, Response::Connected { echo } if echo.contains("XW11_LATE_SPAWN"));
            r.record("XW11.r2_tcp_connect", "R2", pass, &format!("{resp:?}"));
        }

        let _ = r.send("D3", Command::NetUnlisten { port }).await;
    }
}
/// Register netlink tests. Each test is self-contained: one exec + check.
pub(super) fn register_netlink(tests: &mut Vec<super::Test>) {
    // Helper: create a test that execs a subcommand and checks stdout.
    let nl =
        |id: &str, args: Vec<String>, timeout_secs: u64, check: fn(&str) -> bool| -> super::Test {
            let id = id.to_string();
            let id2 = id.clone();
            super::Test {
                suite: "matrix",
                group: "netlink",
                id,
                xfail: None,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let cmd = if timeout_secs > 0 {
                            super::exec_timeout(args, timeout_secs)
                        } else {
                            super::exec(args)
                        };
                        let resp = r.send("A", cmd).await;
                        let pass = matches!(
                            &resp,
                            crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                                if check(stdout)
                        );
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                }),
            }
        };

    let exe = || {
        std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .to_string()
    };
    // We can't call r.self_exe here (no runner yet), so tests will
    // use the self_exe from the runner. Let's capture it differently.
    // Actually, the closure captures the runner, so we can read self_exe there.
    // But our helper doesn't have the runner. Let's restructure:

    // Each test captures its args as a closure over the runner.
    let self_exe_test =
        |id: &str, subcmd: &str, arg: &str, timeout: u64, check: fn(&str) -> bool| {
            let id = id.to_string();
            let subcmd = subcmd.to_string();
            let arg = arg.to_string();
            super::Test {
                suite: "matrix",
                group: "netlink",
                id: id.clone(),
                xfail: None,
                run: Box::new(move |r| {
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let args = vec![self_exe, subcmd, arg];
                        let cmd = if timeout > 0 {
                            super::exec_timeout(args, timeout)
                        } else {
                            super::exec(args)
                        };
                        let resp = r.send("A", cmd).await;
                        let pass = matches!(
                            &resp,
                            crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                                if check(stdout)
                        );
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                }),
            }
        };

    tests.push(self_exe_test(
        "NL1.netlink_socket",
        "getifaddrs-test",
        "socket",
        0,
        |s| s.contains("NETLINK_SOCKET_OK"),
    ));
    tests.push(self_exe_test(
        "NL2.netlink_bind",
        "getifaddrs-test",
        "bind",
        0,
        |s| s.contains("NETLINK_BIND_OK"),
    ));
    tests.push(self_exe_test(
        "NL3.netlink_getlink",
        "getifaddrs-test",
        "getlink",
        0,
        |s| s.contains("NETLINK_GETLINK_OK"),
    ));
    tests.push(self_exe_test(
        "NL4.netlink_getaddr",
        "getifaddrs-test",
        "getaddr",
        0,
        |s| s.contains("NETLINK_GETADDR_OK"),
    ));
    tests.push(self_exe_test(
        "NL3b.sendmsg_recvmsg",
        "getifaddrs-test",
        "sendmsg",
        0,
        |s| s.contains("NETLINK_SENDMSG_RECVMSG_OK"),
    ));
    tests.push(self_exe_test(
        "NL3c.double_request",
        "getifaddrs-test",
        "double",
        30,
        |s| s.contains("NETLINK_DOUBLE_OK"),
    ));
    tests.push(self_exe_test(
        "NL3d.peek_trunc",
        "getifaddrs-test",
        "peek-trunc",
        30,
        |s| s.contains("NETLINK_PEEK_TRUNC_OK"),
    ));
    tests.push(self_exe_test(
        "NL5.getifaddrs_full",
        "getifaddrs-test",
        "full",
        30,
        |s| s.contains("GETIFADDRS_OK"),
    ));

    // X48: Node.js os.networkInterfaces()
    {
        let id = "X48.node_networkInterfaces".to_string();
        tests.push(super::Test {
            suite: "matrix",
            group: "netlink",
            id: id.clone(),
            xfail: None,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let resp = r
                        .send(
                            "A",
                            super::exec_timeout(
                                vec![
                                    "/usr/local/bin/node".into(),
                                    "-e".into(),
                                    "try { const r = require('os').networkInterfaces(); console.log('NETIF_OK:' + Object.keys(r).length); } catch(e) { console.log('NETIF_ERR:' + e.code); }".into(),
                                ],
                                30,
                            ),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("NETIF_OK:") || stdout.contains("NETIF_ERR:")
                    );
                    super::TestOutcome::new("A", pass, format!("{resp:?}"))
                })
            }),
        });
    }

    // NL6: MAC address via getifaddrs
    tests.push(self_exe_test(
        "NL6.mac_address",
        "unix-socket-test",
        "mac",
        30,
        |s| s.contains("NL6_MAC_CHECK"),
    ));
}
/// Register IPv6 network tests.
pub(super) fn register_net_ipv6(tests: &mut Vec<super::Test>) {
    let cases: &[(&str, &str)] = &[
        ("NET1.ipv6_socket", "ipv6-socket"),
        ("NET2.ipv6_listen", "ipv6-listen"),
        ("NET4.ipv4_listen", "ipv4-listen"),
        ("NET5.ipv6_getaddrinfo", "ipv6-getaddrinfo"),
        ("NET6.ipv6_v6only", "ipv6-v6only"),
    ];
    for &(name, sub) in cases {
        let id = name.to_string();
        let sub = sub.to_string();
        tests.push(super::Test {
            suite: "matrix",
            group: "net_ipv6",
            id,
            xfail: None,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let resp = r
                        .send("A", super::exec_timeout(vec![self_exe, "net-test".into(), sub], 10))
                        .await;
                    let pass = matches!(&resp, crate::protocol::Response::ExecResult { stdout, .. } if stdout.contains("_OK"));
                    super::TestOutcome::new("A", pass, format!("{resp:?}"))
                })
            }),
        });
    }
}

/// Register terminal ioctl tests.
pub(super) fn register_terminal_ioctl(tests: &mut Vec<super::Test>) {
    let ops = ["tcgets", "tcsets", "tcsetsw", "tcsetsf", "tiocgwinsz"];
    let fds = [0, 1, 2];
    for op in &ops {
        for fd in &fds {
            let id = format!("TERM.{op}_fd{fd}");
            let op = op.to_string();
            let fd_str = fd.to_string();
            tests.push(super::Test {
                suite: "matrix",
                group: "terminal_ioctl",
                id,
                xfail: None,
                run: Box::new(move |r| {
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let resp = r
                            .send(
                                "A",
                                super::exec_timeout(
                                    vec![self_exe, "exit-test".into(), "term".into(), op, fd_str],
                                    8,
                                ),
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            crate::protocol::Response::ExecResult { exit_code: 0 | 1, stdout, .. }
                                if stdout.contains("TERM_OK") || stdout.contains("TERM_ERR")
                        );
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
}

/// Register Node.js exit tests.
pub(super) fn register_node_exit(tests: &mut Vec<super::Test>) {
    let node_tests: &[(
        &str,
        Vec<&str>,
        Box<dyn Fn(&crate::protocol::Response) -> bool + Send + Sync>,
    )] = &[];
    // Simpler: just push each test individually.

    tests.push(super::Test {
        suite: "fork", group: "node_exit",
        id: "EX6.node_version_exit".into(), xfail: None,
        run: Box::new(|r| Box::pin(async move {
            let resp = r.send("A", super::exec_timeout(vec!["/usr/local/bin/node".into(), "--version".into()], 10)).await;
            let pass = matches!(&resp, crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. } if stdout.starts_with('v'));
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        })),
    });

    tests.push(super::Test {
        suite: "fork",
        group: "node_exit",
        id: "EX7.node_process_exit".into(),
        xfail: None,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r
                    .send(
                        "A",
                        super::exec_timeout(
                            vec![
                                "/usr/local/bin/node".into(),
                                "-e".into(),
                                "process.exit(0)".into(),
                            ],
                            10,
                        ),
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, .. }
                );
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    tests.push(super::Test {
        suite: "fork",
        group: "node_exit",
        id: "EX8.node_exit_code".into(),
        xfail: None,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r
                    .send(
                        "A",
                        super::exec_timeout(
                            vec![
                                "/usr/local/bin/node".into(),
                                "-e".into(),
                                "process.exit(42)".into(),
                            ],
                            10,
                        ),
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 42, .. }
                );
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    tests.push(super::Test {
        suite: "fork", group: "node_exit",
        id: "EX9.node_console_exit".into(), xfail: None,
        run: Box::new(|r| Box::pin(async move {
            let resp = r.send("A", super::exec_timeout(vec!["/usr/local/bin/node".into(), "-e".into(), "console.log(\"NODE_EXIT_OK\")".into()], 10)).await;
            let pass = matches!(&resp, crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NODE_EXIT_OK"));
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        })),
    });
}
/// Register FS I/O matrix tests.
pub(super) fn register_fs_io(tests: &mut Vec<super::Test>) {
    let ops: &[&str] = &[
        "write-read",
        "append-read",
        "write-bg-read",
        "redirect-bg-read",
        "fork-write-read",
        "bg-open-read",
        "parent-open-fork-read",
    ];
    let paths: &[(&str, &str)] = &[("/tmp/fs-test.txt", "tmp"), ("/root/fs-test.txt", "root")];

    for &op in ops {
        for &(path, dir) in paths {
            let id = format!("FS.{op}.{dir}");
            let op = op.to_string();
            let path = path.to_string();
            tests.push(super::Test {
                suite: "matrix", group: "fs_io", id, xfail: None,
                run: Box::new(move |r| {
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let resp = r.send("A", super::exec_timeout(
                            vec![self_exe, "fs-test".into(), "io".into(), op, path], 15,
                        )).await;
                        let pass = matches!(&resp, crate::protocol::Response::ExecResult { stdout, .. } if stdout.contains("FS_OK"));
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }

    // Exec-write and exec-open-read
    for &mode in &["exec-write", "exec-open-read"] {
        let prefix = if mode == "exec-write" { "exec" } else { "open" };
        for &bin in &["pie", "nonpie"] {
            let path = "/tmp/fs-exec.txt";
            let pname = "fs-exec.txt";
            let id = format!("FS.{prefix}_{bin}_{pname}");
            let mode = mode.to_string();
            let bin = bin.to_string();
            let path = path.to_string();
            tests.push(super::Test {
                suite: "matrix", group: "fs_io", id, xfail: None,
                run: Box::new(move |r| {
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let resp = r.send("A", super::exec_timeout(
                            vec![self_exe, "fs-test".into(), mode, bin, path], 30,
                        )).await;
                        let pass = matches!(&resp, crate::protocol::Response::ExecResult { stdout, .. } if stdout.contains("FS_OK"));
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
}

/// Register capture-pipe fork tests.
pub(super) fn register_capture_pipe(tests: &mut Vec<super::Test>) {
    const CMD_TYPES: &[&str] = &[
        "simple",
        "pipe",
        "multi",
        "noexec",
        "nested_fork",
        "subshell_pipe",
        "subshell_continue",
    ];
    const SHELLS: &[&str] = &["sh", "bash"];
    const CP_AGENTS: &[&str] = &["A", "AA"];

    for &agent in CP_AGENTS {
        for &shell in SHELLS {
            for &cmd_type in CMD_TYPES {
                let id = format!("CP.{cmd_type}.{shell}.{agent}");
                let agent = agent.to_string();
                let shell = shell.to_string();
                let cmd_type = cmd_type.to_string();
                tests.push(super::Test {
                    suite: "fork", group: "capture_pipe", id, xfail: None,
                    run: Box::new(move |r| {
                        let self_exe = r.self_exe.clone();
                        Box::pin(async move {
                            let resp = r.send(&agent, super::exec_timeout(
                                vec![self_exe, "capture-pipe".into(), cmd_type, shell], 10,
                            )).await;
                            let pass = matches!(&resp, crate::protocol::Response::ExecResult { stdout, .. } if stdout.contains("CP_OK"));
                            super::TestOutcome::new(&agent, pass, format!("{resp:?}"))
                        })
                    }),
                });
            }
        }
    }
}
/// Register stdin-piped script tests.
pub(super) fn register_stdin_script(tests: &mut Vec<super::Test>) {
    const SCRIPTS: &[(&str, &str, &str)] = &[
        (
            "cmd_subst",
            "FOO=$(echo hello)\necho FOO=$FOO\necho DONE\n",
            "FOO=hello",
        ),
        (
            "pipe_in_subst",
            "A=$(echo one | cat)\necho A=$A\necho DONE\n",
            "A=one",
        ),
        (
            "multi_pipe_subst",
            "A=$(echo data | grep data | cat)\necho A=$A\necho DONE\n",
            "A=data",
        ),
        (
            "file_pipe_subst",
            "A=$(cat /etc/hostname | cat)\necho A=$A\necho DONE\n",
            "DONE",
        ),
        (
            "sequential_subst",
            "A=$(echo first)\nB=$(echo second)\necho A=$A B=$B\necho DONE\n",
            "A=first B=second",
        ),
        (
            "subst_then_cmds",
            "A=$(echo val | cat)\necho LINE1\necho LINE2\necho LINE3\n",
            "LINE3",
        ),
        (
            "vscode_osrelease",
            "ID=$(cat /etc/os-release | grep -E '^ID=' | sed 's/ID=//g' | sed 's/\"//g')\necho ID=$ID\necho DONE\n",
            "DONE",
        ),
        (
            "backtick_pipe",
            "A=`echo one | cat`\necho A=$A\necho DONE\n",
            "A=one",
        ),
    ];
    const SHELLS: &[&str] = &["sh", "bash"];
    const SS_AGENTS: &[&str] = &["A", "AA"];

    for &agent in SS_AGENTS {
        for &shell in SHELLS {
            for &(name, script, expected) in SCRIPTS {
                let id = format!("SS.{name}.{shell}.{agent}");
                let agent = agent.to_string();
                let shell = shell.to_string();
                let script = script.to_string();
                let expected = expected.to_string();
                tests.push(super::Test {
                    suite: "shell", group: "stdin_script", id, xfail: None,
                    run: Box::new(move |r| {
                        Box::pin(async move {
                            let resp = r.send(&agent, crate::protocol::Command::Exec {
                                args: vec![shell],
                                timeout_secs: Some(10),
                                stdin: Some(script),
                                background: false,
                            }).await;
                            let pass = matches!(&resp, crate::protocol::Response::ExecResult { stdout, .. } if stdout.contains(&*expected));
                            super::TestOutcome::new(&agent, pass, format!("{resp:?}"))
                        })
                    }),
                });
            }
        }
    }
}
