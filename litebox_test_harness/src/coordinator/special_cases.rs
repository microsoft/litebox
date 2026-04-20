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
        r.record("X50a.nonpie_then_pie_1", "A", true, "skipped");
        r.record("X50b.nonpie_then_pie_2", "A", true, "skipped");
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
        r.record("X51.nonpie_fresh_agent", "B", true, "skipped");
        r.record("X52a.B_nonpie_then_pie", "B", true, "skipped");
        r.record("X52b.B_pie_after_nonpie", "B", true, "skipped");
        r.record("X52c.B_third_exec", "B", true, "skipped");
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
        r.record("X54.nonpie_after_stress", "AB", true, "skipped");
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
        r.record("X55b.nonpie_second", "AAB", true, "skipped");
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
        ("US1.cross_process_unix", "cross-process", "US1_CROSS_PROCESS_OK"),
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
                    vec![
                        self_exe.clone(),
                        "unix-socket-test".into(),
                        (*sub).into(),
                    ],
                    10,
                ),
            )
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains(expected));
        r.record(name, "A", pass, &format!("{resp:?}"));
    }
}

/// Node.js exit behavior tests.
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
            let test_name = format!("FS.{}_{}", op, path.rsplit('/').next().unwrap_or(path));
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

/// Stdin-piped script tests: pipe shell scripts to `sh` via stdin.
/// Reproduces the VS Code install script pattern where the script is
/// piped through `ssh host sh`. Tests pipe-in-subshell, command
/// substitution, and multi-stage pipes — all across agent depths.
pub(super) async fn stdin_script_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    eprintln!("[special] === Stdin-Piped Script Tests ===");

    // Run all stdin-script tests as a single Exec. The subcommand
    // runs each test internally and reports STDIN_OK/STDIN_FAIL.
    for agent in &["A", "AA"] {
        let resp = r
            .send(
                agent,
                super::exec_timeout(
                    vec![self_exe.clone(), "stdin-script".into(), "all".into()],
                    30,
                ),
            )
            .await;

        // Parse individual results from stdout
        if let Response::ExecResult {
            exit_code, stdout, ..
        } = &resp
        {
            for line in stdout.lines() {
                if let Some(name) = line.strip_prefix("STDIN_OK:name=") {
                    let name = name.split(',').next().unwrap_or(name);
                    r.record(
                        &format!("SS.{name}.{agent}"),
                        agent,
                        true,
                        line,
                    );
                } else if let Some(rest) = line.strip_prefix("STDIN_FAIL:name=") {
                    let name = rest.split(',').next().unwrap_or(rest);
                    r.record(
                        &format!("SS.{name}.{agent}"),
                        agent,
                        false,
                        line,
                    );
                }
            }
            if *exit_code != 0 && !stdout.contains("STDIN_") {
                r.record(
                    &format!("SS.all.{agent}"),
                    agent,
                    false,
                    &format!("{resp:?}"),
                );
            }
        } else {
            r.record(
                &format!("SS.all.{agent}"),
                agent,
                false,
                &format!("{resp:?}"),
            );
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
        let pass =
            matches!(&resp, Response::Connected { echo } if echo.contains("XW_TCP_HELLO"));
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
        let pass =
            matches!(&resp, Response::Connected { echo } if echo.contains("XW_TCP_HELLO2"));
        r.record("XW6.remote_tcp_connect", "A", pass, &format!("{resp:?}"));

        let _ = r
            .send("A", Command::NetUnlisten { port })
            .await;
    }
}
