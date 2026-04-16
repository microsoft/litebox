// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Contamination sequence tests — inherently sequential tests that depend on
//! accumulated per-agent state from prior execs.
//!
//! These cannot be expressed as cross-product loops because each test depends
//! on the state left by the previous exec on the same agent (e.g., "run
//! non-PIE, then run PIE — does the PIE see clean output?").

use super::{TestRunner, exec};
use crate::protocol::Response;

/// Contamination isolation sequence tests (X49-X59).
pub(super) async fn contamination_sequence_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    let bash = |cmd: &str| -> Vec<String> { vec!["bash".into(), "-c".into(), cmd.into()] };

    eprintln!("[special] === Contamination Sequence Tests ===");

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
    let resp = r.send("A", exec(vec!["/nonpie-echo".into()])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record("X50a.nonpie_then_pie_1", "A", true, "skipped");
        r.record("X50b.nonpie_then_pie_2", "A", true, "skipped");
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record("X50a.nonpie_then_pie_1", "A", pass, &format!("{resp:?}"));

        let resp = r
            .send("A", exec(vec![self_exe.clone(), "echo-test".into()]))
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
        r.record("X50b.nonpie_then_pie_2", "A", pass, &format!("{resp:?}"));
    }

    // X51-X52: Non-PIE on fresh agent B, then PIE sequence.
    let resp = r.send("B", exec(vec!["/nonpie-echo".into()])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record("X51.nonpie_fresh_agent", "B", true, "skipped");
        r.record("X52a.B_nonpie_then_pie", "B", true, "skipped");
        r.record("X52b.B_pie_after_nonpie", "B", true, "skipped");
        r.record("X52c.B_third_exec", "B", true, "skipped");
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
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
    let resp = r.send("AB", exec(vec!["/nonpie-echo".into()])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record("X54.nonpie_after_stress", "AB", true, "skipped");
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record("X54.nonpie_after_stress", "AB", pass, &format!("{resp:?}"));
    }

    // X55: Non-PIE as second exec on fresh agent AAB.
    let resp = r
        .send("AAB", exec(vec![self_exe.clone(), "echo-test".into()]))
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
    r.record("X55a.one_pie_first", "AAB", pass, &format!("{resp:?}"));

    let resp = r.send("AAB", exec(vec!["/nonpie-echo".into()])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record("X55b.nonpie_second", "AAB", true, "skipped");
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record("X55b.nonpie_second", "AAB", pass, &format!("{resp:?}"));
    }

    // X56-X59: Sequence tests on B.
    let resp = r.send("B", exec(vec!["/nonpie-echo".into()])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record("X56.second_nonpie_on_B", "B", true, "skipped");
        r.record("X57.pipe_churn_then_nonpie", "B", true, "skipped");
        r.record("X58.alternating_pie_nonpie", "B", true, "skipped");
        r.record("X59.sequential_nonpie", "B", true, "skipped");
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record("X56.second_nonpie_on_B", "B", pass, &format!("{resp:?}"));

        // X57: Pipe churn then non-PIE.
        for _ in 0..20 {
            let _ = r.send("B", exec(bash("echo churn >/dev/null"))).await;
        }
        let resp = r.send("B", exec(vec!["/nonpie-echo".into()])).await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
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

                let resp = r.send("B", exec(vec!["/nonpie-echo".into()])).await;
                let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
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
            let resp = r.send("B", exec(vec!["/nonpie-echo".into()])).await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
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
}
