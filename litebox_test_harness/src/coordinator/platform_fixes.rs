// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform fix validation tests — matrix-loop tests that prove specific bug
//! fixes are needed by exercising the exact behavior each fix corrected.
//!
//! Each test category targets a commit in the wportnoy/vscode-server-in-litebox
//! branch and must pass on both native WSL2 (gold standard) and litebox.

use super::{TestRunner, exec, exec_timeout};
use crate::protocol::{Command, Response};
use tokio::time::Duration;

const AGENTS: &[&str] = &["A", "AA", "B"];
const DEPTH_AGENTS: &[&str] = &["A", "AA"];

// ═══════════════════════════════════════════════════════════════════
// POLL: epoll/ppoll IN events (fix 0fb258e2)
// ═══════════════════════════════════════════════════════════════════

/// Verify that poll() returns POLLIN for a pipe with data available.
/// Without fix 0fb258e2, file descriptors only reported OUT events,
/// causing shells to hang when polling stdin for readability.
pub(crate) async fn poll_ready_tests(r: &mut TestRunner) {
    eprintln!("[platform] === Poll Ready ({} agents) ===", AGENTS.len());

    for &agent in AGENTS {
        let test_id = format!("POLL.pipe.{agent}");
        let resp = r.send(agent, Command::PollReady { timeout_ms: 2000 }).await;
        let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "POLLIN");
        r.record(&test_id, agent, pass, &format!("{resp:?}"));
    }
}

// ═══════════════════════════════════════════════════════════════════
// GSN: getsockname port after bind (fix 336dc79e)
// ═══════════════════════════════════════════════════════════════════

const FAMILIES: &[&str] = &["ipv4", "ipv6"];

/// Verify that getsockname returns a nonzero port after bind(ANY, 0).
/// Without fix 336dc79e, smoltcp returned None for the local endpoint
/// of bound-but-not-connected sockets, yielding port 0.
pub(crate) async fn bind_getsockname_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === Bind+Getsockname ({} families × {} agents) ===",
        FAMILIES.len(),
        DEPTH_AGENTS.len()
    );

    for &family in FAMILIES {
        for &agent in DEPTH_AGENTS {
            let test_id = format!("GSN.{family}.{agent}");
            let resp = r
                .send(
                    agent,
                    Command::BindGetsockname {
                        family: family.to_string(),
                    },
                )
                .await;
            let pass = match &resp {
                Response::Ok { data: Some(d) } => {
                    // Parse "port=NNNN" and verify > 0.
                    d.strip_prefix("port=")
                        .and_then(|s| s.parse::<u16>().ok())
                        .map_or(false, |p| p > 0)
                }
                _ => false,
            };
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// PID: monotonic pipe pair_id (fix c2d0abdc)
// ═══════════════════════════════════════════════════════════════════

/// Verify that pipe pair IDs are unique even after create+drop+recreate.
/// Without fix c2d0abdc, Arc::as_ptr() was used for pair_id, and the
/// allocator could reuse addresses after free, causing ID collisions
/// in mux_pipe_pair_ids.
pub(crate) async fn pipe_pair_id_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === Pipe Pair ID Unique ({} agents) ===",
        AGENTS.len()
    );

    for &agent in AGENTS {
        let test_id = format!("PID.{agent}");
        let resp = r
            .send(agent, Command::PipePairIdUnique { count: 100 })
            .await;
        let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "unique");
        r.record(&test_id, agent, pass, &format!("{resp:?}"));
    }
}

// ═══════════════════════════════════════════════════════════════════
// EXITD: bridge thread join before exit (fix 2def3ac6)
// ═══════════════════════════════════════════════════════════════════

const EXIT_SIZES: &[usize] = &[256, 4096, 65536];
const EXIT_BINARIES: &[&str] = &["pie", "nonpie"];

/// Verify that large writes complete fully before process exit.
/// Without fix 2def3ac6, bridge threads were not joined before
/// exit_group, causing data truncation on large stdout writes.
pub(crate) async fn exit_data_integrity_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === Exit Data Integrity ({} sizes × {} binaries × {} agents) ===",
        EXIT_SIZES.len(),
        EXIT_BINARIES.len(),
        DEPTH_AGENTS.len()
    );

    let self_exe = r.self_exe.clone();
    let nonpie = crate::find_nonpie_binary();

    for &size in EXIT_SIZES {
        for &binary in EXIT_BINARIES {
            let bin_path = match binary {
                "pie" => self_exe.clone(),
                "nonpie" => match &nonpie {
                    Some(p) => p.clone(),
                    None => {
                        for &agent in DEPTH_AGENTS {
                            let test_id = format!("EXITD.{size}.{binary}.{agent}");
                            r.record(
                                &test_id,
                                agent,
                                false,
                                "FAIL: nonpie binary not found — mount at /opt/nonpie",
                            );
                        }
                        continue;
                    }
                },
                _ => unreachable!(),
            };

            for &agent in DEPTH_AGENTS {
                let test_id = format!("EXITD.{size}.{binary}.{agent}");
                let resp = r
                    .send(
                        agent,
                        exec(vec![
                            bin_path.clone(),
                            "write-then-exit".into(),
                            size.to_string(),
                        ]),
                    )
                    .await;
                let pass = match &resp {
                    Response::ExecResult {
                        exit_code: 0,
                        stdout,
                        ..
                    } => stdout.len() == size,
                    _ => false,
                };
                let detail = match &resp {
                    Response::ExecResult { stdout, .. } => {
                        format!("got {} bytes, expected {size}", stdout.len())
                    }
                    _ => format!("{resp:?}"),
                };
                r.record(&test_id, agent, pass, &detail);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// NPIPE: non-PIE pipe chain integrity (fix febc3e41)
// ═══════════════════════════════════════════════════════════════════

const NPIPE_REPS: &[usize] = &[1, 5, 10];

/// Verify that repeated non-PIE execs produce clean pipe output.
/// Without the proper pipe chain handling, data from one exec could
/// leak into subsequent execs via stale mux_pipe_pair_ids entries.
///
/// Tests two patterns:
/// - Sequential non-PIE: N consecutive non-PIE execs on same agent
/// - Interleaved: alternating PIE and non-PIE execs on same agent
pub(crate) async fn nonpie_pipe_chain_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    let nonpie = match crate::find_nonpie_binary() {
        Some(p) => p,
        None => {
            eprintln!("[platform] === Non-PIE Pipe Chain (SKIPPED — no nonpie binary) ===");
            // Record skips for all planned test IDs.
            for &reps in NPIPE_REPS {
                for pattern in &["seq", "interleaved"] {
                    for &agent in DEPTH_AGENTS {
                        let test_id = format!("NPIPE.{pattern}.x{reps}.{agent}");
                        r.record(
                            &test_id,
                            agent,
                            false,
                            "FAIL: nonpie binary not found — mount at /opt/nonpie",
                        );
                    }
                }
            }
            return;
        }
    };

    eprintln!(
        "[platform] === Non-PIE Pipe Chain ({} reps × 2 patterns × {} agents) ===",
        NPIPE_REPS.len(),
        DEPTH_AGENTS.len()
    );

    for &reps in NPIPE_REPS {
        for &agent in DEPTH_AGENTS {
            // Sequential non-PIE pattern.
            {
                let test_id = format!("NPIPE.seq.x{reps}.{agent}");
                let mut all_clean = true;
                let mut detail = String::new();
                for i in 0..reps {
                    let tag = format!("seq_{agent}_{i}");
                    let resp = r
                        .send(
                            agent,
                            exec(vec![nonpie.clone(), "write-known".into(), tag.clone()]),
                        )
                        .await;
                    let expected = format!("PIPEDATA:{tag}");
                    let ok = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.trim() == expected);
                    if !ok {
                        all_clean = false;
                        detail = format!("iter {i}: expected '{expected}', got {resp:?}");
                        break;
                    }
                }
                if all_clean {
                    detail = format!("{reps} sequential non-PIE execs all clean");
                }
                r.record(&test_id, agent, all_clean, &detail);
            }

            // Interleaved PIE + non-PIE pattern.
            {
                let test_id = format!("NPIPE.interleaved.x{reps}.{agent}");
                let mut all_clean = true;
                let mut detail = String::new();
                for i in 0..reps {
                    // Non-PIE exec.
                    let np_tag = format!("np_{agent}_{i}");
                    let resp = r
                        .send(
                            agent,
                            exec(vec![nonpie.clone(), "write-known".into(), np_tag.clone()]),
                        )
                        .await;
                    let expected = format!("PIPEDATA:{np_tag}");
                    let ok = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.trim() == expected);
                    if !ok {
                        all_clean = false;
                        detail = format!("iter {i} nonpie: expected '{expected}', got {resp:?}");
                        break;
                    }

                    // PIE exec — must not see contamination from prior non-PIE.
                    let resp = r
                        .send(agent, exec(vec![self_exe.clone(), "echo-test".into()]))
                        .await;
                    let ok = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.trim() == "ECHO_TEST_OK");
                    if !ok {
                        all_clean = false;
                        detail = format!("iter {i} pie: expected 'ECHO_TEST_OK', got {resp:?}");
                        break;
                    }
                }
                if all_clean {
                    detail = format!("{reps} interleaved PIE+nonPIE execs all clean");
                }
                r.record(&test_id, agent, all_clean, &detail);
            }
        }
    }
}

/// Run all platform fix validation tests.

// ═══════════════════════════════════════════════════════════════════
// XCONN: cross-worker TCP — first connection must succeed
// ═══════════════════════════════════════════════════════════════════

/// Reproduces the VS Code exec server "Connection closed" failure.
///
/// Agent A starts a TCP echo server (NetListen). Agent B connects
/// to it. In litebox, this goes through the cross-worker TCP bridge.
/// The bug: the init proxy and the worker proxy BOTH try to bridge the
/// connection, creating duplicate smoltcp sockets with colliding source
/// ports. The first bridge fails (SynSent → Closed), VS Code sees
/// "Connection closed".
///
/// The test verifies that the FIRST connection attempt succeeds —
/// not just that "some" connection eventually works.
pub(crate) async fn cross_worker_first_connect_tests(r: &mut TestRunner) {
    eprintln!("[platform] === XCONN: cross-worker first connect ===");

    // Agent A listens.
    let port = 19900u16;
    let listen_resp = r.send("A", Command::NetListen { port }).await;
    if !matches!(&listen_resp, Response::Listening { .. }) {
        r.record(
            "XCONN.cross_first",
            "B",
            false,
            &format!("listen failed: {listen_resp:?}"),
        );
        return;
    }

    // Agent B connects — single connection, must succeed on first try.
    let conn_resp = r
        .send(
            "B",
            Command::NetConnect {
                addr: format!("127.0.0.1:{port}"),
                data: "first_connect".into(),
            },
        )
        .await;
    let ok = matches!(&conn_resp, Response::Connected { echo } if echo == "first_connect");
    r.record("XCONN.cross_first", "B", ok, &format!("{conn_resp:?}"));

    // Same test but agent AA (deeper worker) connects to agent B's listener.
    let port2 = 19901u16;
    let listen_resp = r.send("B", Command::NetListen { port: port2 }).await;
    if !matches!(&listen_resp, Response::Listening { .. }) {
        r.record(
            "XCONN.deep_cross",
            "AA",
            false,
            &format!("listen on B failed: {listen_resp:?}"),
        );
    } else {
        let conn_resp = r
            .send(
                "AA",
                Command::NetConnect {
                    addr: format!("127.0.0.1:{port2}"),
                    data: "deep_cross".into(),
                },
            )
            .await;
        let ok = matches!(&conn_resp, Response::Connected { echo } if echo == "deep_cross");
        r.record("XCONN.deep_cross", "AA", ok, &format!("{conn_resp:?}"));
        let _ = r.send("B", Command::NetUnlisten { port: port2 }).await;
    }

    // Rapid sequential: 3 connections from B to A's listener.
    // Each must succeed on first try.
    let mut all_ok = true;
    for i in 0..3 {
        let conn_resp = r
            .send(
                "B",
                Command::NetConnect {
                    addr: format!("127.0.0.1:{port}"),
                    data: format!("seq_{i}"),
                },
            )
            .await;
        if !matches!(&conn_resp, Response::Connected { echo } if echo == &format!("seq_{i}")) {
            all_ok = false;
            r.record(
                "XCONN.cross_seq_x3",
                "B",
                false,
                &format!("connection {i} failed: {conn_resp:?}"),
            );
            break;
        }
    }
    if all_ok {
        r.record("XCONN.cross_seq_x3", "B", true, "3/3 sequential OK");
    }

    let _ = r.send("A", Command::NetUnlisten { port }).await;
}

// ═══════════════════════════════════════════════════════════════════
// XCONN.self: same-worker loopback (VS Code pattern)
// ═══════════════════════════════════════════════════════════════════

/// VS Code topology: the CLI (listener) and dropbear (connector) are
/// in the SAME worker. The connector calls connect(127.0.0.1:PORT)
/// which goes through the same smoltcp instance as the listener.
///
/// This tests same-worker loopback via NetListen + NetConnect on the
/// SAME agent, and also the parent→child topology (A listens, AA connects)
/// which mirrors how the CLI runs in the init worker and dropbear
/// (also in init worker) connects via the SSH direct-tcpip channel.
pub(crate) async fn cross_worker_self_connect_tests(r: &mut TestRunner) {
    eprintln!("[platform] === XCONN.self: same-worker loopback ===");

    // Same agent: A listens, A connects to itself.
    let port = 19910u16;
    let listen_resp = r.send("A", Command::NetListen { port }).await;
    if !matches!(&listen_resp, Response::Listening { .. }) {
        r.record(
            "XCONN.self_A",
            "A",
            false,
            &format!("listen failed: {listen_resp:?}"),
        );
        return;
    }
    let conn_resp = r
        .send(
            "A",
            Command::NetConnect {
                addr: format!("127.0.0.1:{port}"),
                data: "self_loopback".into(),
            },
        )
        .await;
    let ok = matches!(&conn_resp, Response::Connected { echo } if echo == "self_loopback");
    r.record("XCONN.self_A", "A", ok, &format!("{conn_resp:?}"));
    let _ = r.send("A", Command::NetUnlisten { port }).await;

    // Parent→child: A listens, AA connects (AA is a child process of A,
    // so in litebox with PIE they share the same worker).
    let port2 = 19911u16;
    let listen_resp = r.send("A", Command::NetListen { port: port2 }).await;
    if !matches!(&listen_resp, Response::Listening { .. }) {
        r.record(
            "XCONN.parent_child",
            "AA",
            false,
            &format!("listen failed: {listen_resp:?}"),
        );
        return;
    }
    let conn_resp = r
        .send(
            "AA",
            Command::NetConnect {
                addr: format!("127.0.0.1:{port2}"),
                data: "parent_child".into(),
            },
        )
        .await;
    let ok = matches!(&conn_resp, Response::Connected { echo } if echo == "parent_child");
    r.record("XCONN.parent_child", "AA", ok, &format!("{conn_resp:?}"));
    let _ = r.send("A", Command::NetUnlisten { port: port2 }).await;

    // Child→parent: AA listens, A connects.
    let port3 = 19912u16;
    let listen_resp = r.send("AA", Command::NetListen { port: port3 }).await;
    if !matches!(&listen_resp, Response::Listening { .. }) {
        r.record(
            "XCONN.child_parent",
            "A",
            false,
            &format!("listen failed: {listen_resp:?}"),
        );
        return;
    }
    let conn_resp = r
        .send(
            "A",
            Command::NetConnect {
                addr: format!("127.0.0.1:{port3}"),
                data: "child_parent".into(),
            },
        )
        .await;
    let ok = matches!(&conn_resp, Response::Connected { echo } if echo == "child_parent");
    r.record("XCONN.child_parent", "A", ok, &format!("{conn_resp:?}"));
    let _ = r.send("AA", Command::NetUnlisten { port: port3 }).await;

    // Sibling: A listens, AB connects (AB is sibling of AA, both children of A).
    let port4 = 19913u16;
    let listen_resp = r.send("A", Command::NetListen { port: port4 }).await;
    if !matches!(&listen_resp, Response::Listening { .. }) {
        r.record(
            "XCONN.sibling_AB",
            "AB",
            false,
            &format!("listen failed: {listen_resp:?}"),
        );
        return;
    }
    let conn_resp = r
        .send(
            "AB",
            Command::NetConnect {
                addr: format!("127.0.0.1:{port4}"),
                data: "sibling_connect".into(),
            },
        )
        .await;
    let ok = matches!(&conn_resp, Response::Connected { echo } if echo == "sibling_connect");
    r.record("XCONN.sibling_AB", "AB", ok, &format!("{conn_resp:?}"));
    let _ = r.send("A", Command::NetUnlisten { port: port4 }).await;
}

// ═══════════════════════════════════════════════════════════════════
// BASH: bash fork+exec of child commands
// ═══════════════════════════════════════════════════════════════════

/// Reproduces the VS Code bootstrap failure: the VS Code Remote-SSH
/// extension pipes a script to `ssh host sh`. The shell (bash) runs
/// external commands via fork+exec. In litebox, the runner resolves
/// relative program names (e.g., `bash` → `/usr/bin/bash`) for the
/// initial load, but when the shell itself forks+exec's children,
/// the child worker receives the guest exec path which must be
/// resolvable via the 9P filesystem.
///
/// This test verifies that bash can fork+exec external commands
/// (ls, cat, uname) — the same commands the VS Code bootstrap runs
/// after spawning the CLI server.
pub(crate) async fn bash_fork_exec_tests(r: &mut TestRunner) {
    eprintln!("[platform] === BASH fork+exec tests ===");

    for &agent in &["A", "B"] {
        // Test 1: bash -c running an external command (ls)
        let resp = r
            .send(
                agent,
                exec(vec![
                    "bash".into(),
                    "-c".into(),
                    "ls / > /dev/null && echo LS_OK".into(),
                ]),
            )
            .await;
        let pass = matches!(
            &resp,
            Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("LS_OK")
        );
        r.record(
            &format!("BASH.fork_ls.{agent}"),
            agent,
            pass,
            &format!("{resp:?}"),
        );

        // Test 2: bash -c with command substitution (forks subshell)
        let resp = r
            .send(
                agent,
                exec(vec![
                    "bash".into(),
                    "-c".into(),
                    "echo HOST=$(cat /etc/hostname)".into(),
                ]),
            )
            .await;
        let pass = matches!(
            &resp,
            Response::ExecResult { exit_code: 0, stdout, .. } if stdout.starts_with("HOST=")
        );
        r.record(
            &format!("BASH.fork_subst.{agent}"),
            agent,
            pass,
            &format!("{resp:?}"),
        );

        // Test 3: bash -c with background + foreground (VS Code pattern)
        let resp = r
            .send(
                agent,
                exec(vec![
                    "bash".into(),
                    "-c".into(),
                    "sleep 0.1 & cat /etc/hostname > /dev/null; echo BG_FG_OK".into(),
                ]),
            )
            .await;
        let pass = matches!(
            &resp,
            Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("BG_FG_OK")
        );
        r.record(
            &format!("BASH.fork_bg_fg.{agent}"),
            agent,
            pass,
            &format!("{resp:?}"),
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// FORK-FROM-WORKER-EXEC: fork+exec from non-PIE worker-exec hosts
// (reproduces VS Code ptyHost/extensionHost spawn hang)
// ═══════════════════════════════════════════════════════════════════

/// Tests fork+exec from within a worker-exec host.
///
/// VS Code's code-server (running as a non-PIE node binary in a worker-exec)
/// spawns ptyHost/extensionHost by forking and exec'ing node.  This test
/// validates that path using the coordinator's agent tree:
///
/// - FWE.pie_from_init: fork+exec PIE from init worker (baseline)
/// - FWE.nonpie_from_init: fork+exec nonpie from init worker (baseline)
/// - FWE.pie_from_worker_exec: fork+exec PIE from NP (worker-exec host)
/// - FWE.nonpie_from_worker_exec: fork+exec nonpie from NP (worker-exec)
pub(crate) async fn fork_from_worker_exec_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    let nonpie = crate::find_nonpie_binary();

    eprintln!("[platform] === Fork from Worker-Exec Tests ===");

    let Some(ref nonpie_bin) = nonpie else {
        for name in [
            "pie_from_init",
            "nonpie_from_init",
            "pie_from_worker_exec",
            "nonpie_from_worker_exec",
        ] {
            r.record(
                &format!("FWE.{name}"),
                "A",
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
        }
        return;
    };

    // Baseline: fork+exec PIE from init worker (agent A, PIE)
    let resp = r
        .send(
            "A",
            exec_timeout(
                vec![
                    self_exe.clone(),
                    "fork-exec-nonpie".into(),
                    nonpie_bin.clone(),
                    "echo-test".into(),
                ],
                20,
            ),
        )
        .await;
    let pass = matches!(
        &resp,
        Response::ExecResult { exit_code: 0, stdout, .. }
            if stdout.contains("FORK_EXEC_NONPIE_OK")
    );
    r.record("FWE.nonpie_from_init", "A", pass, &format!("{resp:?}"));

    // Baseline: fork+exec PIE from init worker
    let resp = r
        .send(
            "A",
            exec_timeout(
                vec![
                    self_exe.clone(),
                    "fork-exec-pie".into(),
                    self_exe.clone(),
                    "echo-test".into(),
                ],
                20,
            ),
        )
        .await;
    let pass = matches!(
        &resp,
        Response::ExecResult { exit_code: 0, stdout, .. }
            if stdout.contains("FORK_EXEC_PIE_OK")
    );
    r.record("FWE.pie_from_init", "A", pass, &format!("{resp:?}"));

    // Key test: fork+exec PIE from NP (worker-exec host).
    // This is the VS Code pattern: worker-exec node forks bash/node.
    let resp = r
        .send(
            "NP",
            exec_timeout(
                vec![
                    nonpie_bin.clone(),
                    "fork-exec-pie".into(),
                    self_exe.clone(),
                    "echo-test".into(),
                ],
                30,
            ),
        )
        .await;
    let pass = matches!(
        &resp,
        Response::ExecResult { exit_code: 0, stdout, .. }
            if stdout.contains("FORK_EXEC_PIE_OK")
    );
    r.record("FWE.pie_from_worker_exec", "NP", pass, &format!("{resp:?}"));

    // Fork+exec nonpie from NP (nested worker-exec).
    let resp = r
        .send(
            "NP",
            exec_timeout(
                vec![
                    nonpie_bin.clone(),
                    "fork-exec-nonpie".into(),
                    nonpie_bin.clone(),
                    "echo-test".into(),
                ],
                30,
            ),
        )
        .await;
    let pass = matches!(
        &resp,
        Response::ExecResult { exit_code: 0, stdout, .. }
            if stdout.contains("FORK_EXEC_NONPIE_OK")
    );
    r.record(
        "FWE.nonpie_from_worker_exec",
        "NP",
        pass,
        &format!("{resp:?}"),
    );
}

/// When a shell script is piped via stdin (as VS Code Remote-SSH does),
/// $() command substitution with pipelines must return correct output.
///
/// The issue: vfork children share the kernel pipe file description
/// for stdin. Pipeline children (head, grep, sed) may consume stdin
/// data, causing the parent shell to lose its script position.
///
/// Tests cover:
///   SP.simple      — $(echo hello) via stdin pipe
///   SP.pipeline    — $(echo hello | cat) via stdin pipe
///   SP.file_read   — $(cat /etc/passwd) via stdin pipe
///   SP.file_pipe   — $(cat /etc/passwd | head -1) via stdin pipe [THE BUG]
///   SP.multi_subst — multiple $() in sequence via stdin pipe
///   SP.os_detect   — $(uname -m) + $(uname -s) via stdin pipe [VS Code pattern]
pub(crate) async fn stdin_pipe_subst_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === Stdin-Pipe Subst ({} agents) ===",
        AGENTS.len()
    );

    struct SubstTest {
        name: &'static str,
        /// Script to pipe via stdin to /bin/sh
        script: &'static str,
        /// Expected stdout (exact match after trim)
        expected: &'static str,
    }

    let tests = &[
        SubstTest {
            name: "simple",
            script: "X=$(echo hello)\necho R=$X\n",
            expected: "R=hello",
        },
        SubstTest {
            name: "pipeline",
            script: "X=$(echo hello | cat)\necho R=$X\n",
            expected: "R=hello",
        },
        SubstTest {
            name: "file_read",
            script: "X=$(head -1 /etc/passwd)\necho R=${X%%:*}\n",
            expected: "R=root",
        },
        // Known litebox bug: vfork children share kernel pipe file
        // description for stdin. Pipeline children (head) consume
        // stdin data, causing $() to return empty.
        // Passes on WSL2, fails on litebox (counted in EXPECTED_FAIL_COUNT).
        SubstTest {
            name: "file_pipe",
            script: "X=$(cat /etc/passwd | head -1)\necho R=${X%%:*}\n",
            expected: "R=root",
        },
        SubstTest {
            name: "multi_subst",
            script: "A=$(echo first)\nB=$(echo second)\necho R=$A.$B\n",
            expected: "R=first.second",
        },
        SubstTest {
            name: "os_detect",
            script: "ARCH=$(uname -m)\nPLATFORM=$(uname -s)\necho R=$ARCH.$PLATFORM\n",
            expected: "R=x86_64.Linux",
        },
    ];

    for &agent in AGENTS {
        for test in tests {
            let test_id = format!("SP.{}.{}", test.name, agent);
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["/bin/sh".into()],
                        timeout_secs: Some(15),
                        stdin: Some(test.script.into()),
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if stdout.trim() == test.expected
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// CWF: Cross-worker file coherence
// (9P broker concurrent read-while-write across worker sessions)
// ═══════════════════════════════════════════════════════════════════

/// When a fork+exec'd child writes to a file and the parent reads it,
/// the data must be visible — even if the child is still alive (the
/// VS Code CLI pattern).
///
/// The bug: after delayed-fork migration, the child writes to the file
/// through the worker's 9P session.  The parent opens the same path
/// through its own 9P session.  `stat` sees the correct size, but
/// `read` returns EIO when the child's session still has the file open.
///
/// Tests:
///   CWF.seq          — child writes, exits, parent reads (sequential)
///   CWF.concurrent   — child writes, stays alive, parent reads (concurrent)
///   CWF.redirect     — bash `cmd > file &` pattern (VS Code CLI pattern)
pub(crate) async fn cross_worker_file_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === Cross-Worker File ({} agents) ===",
        AGENTS.len()
    );

    let self_exe = r.self_exe.clone();

    for &agent in AGENTS {
        // CWF.seq: child writes, exits, then parent reads.
        {
            let test_id = format!("CWF.seq.{agent}");
            let path = format!("/shared/cwf-seq-{agent}.txt");
            // Write via fork+exec (child writes + exits).
            let resp = r
                .send(
                    agent,
                    exec(vec![
                        "bash".into(),
                        "-c".into(),
                        format!("{} cross-worker-file write-and-exit {}", self_exe, path),
                    ]),
                )
                .await;
            let wrote = matches!(&resp, Response::ExecResult { exit_code: 0, .. });
            if !wrote {
                r.record(&test_id, agent, false, &format!("write failed: {resp:?}"));
                continue;
            }
            // Read from same agent.
            let resp = r.send(agent, Command::FsRead { path: path.clone() }).await;
            let pass = matches!(
                &resp,
                Response::Ok { data: Some(d) } if d.starts_with("line0")
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }

        // CWF.concurrent: child writes, closes fd, stays alive, parent reads.
        // The child drops the file handle before sleeping — tests that the
        // parent can read after the child's 9P session releases the file.
        {
            let test_id = format!("CWF.concurrent.{agent}");
            let path = format!("/shared/cwf-conc-{agent}.txt");
            // Start child in background (it writes, closes fd, then sleeps).
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec![
                            self_exe.clone(),
                            "cross-worker-file".into(),
                            "write-and-sleep".into(),
                            path.clone(),
                        ],
                        timeout_secs: None,
                        stdin: None,
                        background: true,
                    },
                )
                .await;
            let bg_pid = match &resp {
                Response::Background { pid } => Some(*pid),
                _ => None,
            };
            if bg_pid.is_none() {
                r.record(
                    &test_id,
                    agent,
                    false,
                    &format!("bg spawn failed: {resp:?}"),
                );
                continue;
            }
            // Wait for child to write.
            tokio::time::sleep(Duration::from_secs(3)).await;
            // Read file while child is alive.
            let resp = r.send(agent, Command::FsRead { path: path.clone() }).await;
            let pass = matches!(
                &resp,
                Response::Ok { data: Some(d) } if d.starts_with("line0")
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
            // Clean up.
            if let Some(pid) = bg_pid {
                let _ = r.send(agent, Command::Kill { pid }).await;
            }
        }

        // CWF.hold: child writes, keeps fd OPEN, parent reads.
        // This is the VS Code CLI pattern — the CLI keeps its log file
        // open while the parent polls it for "Listening on <port>".
        {
            let test_id = format!("CWF.hold.{agent}");
            let path = format!("/shared/cwf-hold-{agent}.txt");
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec![
                            self_exe.clone(),
                            "cross-worker-file".into(),
                            "write-and-hold".into(),
                            path.clone(),
                        ],
                        timeout_secs: None,
                        stdin: None,
                        background: true,
                    },
                )
                .await;
            let bg_pid = match &resp {
                Response::Background { pid } => Some(*pid),
                _ => None,
            };
            if bg_pid.is_none() {
                r.record(
                    &test_id,
                    agent,
                    false,
                    &format!("bg spawn failed: {resp:?}"),
                );
                continue;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            let resp = r.send(agent, Command::FsRead { path: path.clone() }).await;
            let pass = matches!(
                &resp,
                Response::Ok { data: Some(d) } if d.starts_with("line0")
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
            if let Some(pid) = bg_pid {
                let _ = r.send(agent, Command::Kill { pid }).await;
            }
        }

        // CWF.self_open: child opens file itself (no inherited fd).
        // Control test — child writes to the path directly, no redirect.
        {
            let test_id = format!("CWF.self_open.{agent}");
            let path = format!("/shared/cwf-self-{agent}.txt");
            let script = format!(
                concat!(
                    "rm -f {path}; ",
                    "{exe} cross-worker-file write-and-hold {path} &\n",
                    "BGPID=$!\nsleep 3\ncat {path}\n",
                    "kill $BGPID 2>/dev/null\n",
                ),
                path = path,
                exe = self_exe,
            );
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(15),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if stdout.starts_with("line0")
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }

        // CWF.redirect_stdout: bash `cmd > file &` — child writes to stdout
        // which bash redirects to a file.  Parent reads the file.
        // This is the EXACT VS Code CLI pattern.
        {
            let test_id = format!("CWF.redirect_stdout.{agent}");
            let path = format!("/shared/cwf-rstdout-{agent}.txt");
            let script = format!(
                concat!(
                    "rm -f {path}; ",
                    "{exe} cross-worker-file write-stdout ",
                    "> {path} 2>&1 &\n",
                    "BGPID=$!\nsleep 3\ncat {path}\n",
                    "kill $BGPID 2>/dev/null\n",
                ),
                path = path,
                exe = self_exe,
            );
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(15),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if stdout.contains("line0")
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }

        // CWF.redirect_exit: same as redirect_stdout but child exits quickly.
        // Tests if data becomes visible after the worker child exits.
        {
            let test_id = format!("CWF.redirect_exit.{agent}");
            let path = format!("/shared/cwf-rexit-{agent}.txt");
            let script = format!(
                concat!(
                    "rm -f {path}; ",
                    "{exe} echo-test ",
                    "> {path} 2>&1\n",
                    "cat {path}\n",
                ),
                path = path,
                exe = self_exe,
            );
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(15),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if stdout.contains("ECHO_TEST_OK")
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }

        // CWF.builtin_redirect: shell builtin redirected to file.
        // No exec, no delayed fork — data should always be visible.
        {
            let test_id = format!("CWF.builtin_redirect.{agent}");
            let path = format!("/shared/cwf-builtin-{agent}.txt");
            let script = format!(
                concat!(
                    "rm -f {path}; ",
                    "echo builtin-data > {path}\n",
                    "cat {path}\n",
                ),
                path = path,
            );
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(10),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if stdout.contains("builtin-data")
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// SC: $() command substitution capture — various commands
// (readlink -f failure blocks VS Code Server startup)
// ═══════════════════════════════════════════════════════════════════

/// Tests that $() command substitution correctly captures output from
/// various commands.  The VS Code Server startup script uses:
///   ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
/// If readlink -f returns empty in $(), ROOT="" and the server can't
/// find its own node binary.
///
/// Tests cover progressively more complex capture patterns:
///   SC.echo       — $(echo hello)                   [baseline]
///   SC.cat        — $(cat /etc/hostname)             [file read]
///   SC.readlink   — $(readlink -f /usr/bin/bash)     [THE BUG]
///   SC.dirname    — $(dirname /usr/bin/bash)         [path manipulation]
///   SC.nested     — $(dirname $(readlink -f ...))    [nested subst]
///   SC.vscode     — full VS Code ROOT= pattern       [end-to-end]
///   SC.which      — $(which bash)                    [path search]
///   SC.uname      — $(uname -m)                     [system info]
pub(crate) async fn subst_capture_tests(r: &mut TestRunner) {
    eprintln!("[platform] === Subst Capture ({} agents) ===", AGENTS.len());

    struct Test {
        name: &'static str,
        script: &'static str,
        check: fn(&str) -> bool,
    }

    let tests: &[Test] = &[
        Test {
            name: "echo",
            script: "X=$(echo hello); echo $X",
            check: |s| s.trim() == "hello",
        },
        Test {
            name: "cat",
            script: "X=$(cat /etc/hostname); echo $X",
            check: |s| !s.trim().is_empty(),
        },
        Test {
            name: "readlink",
            script: "X=$(readlink -f /usr/bin/bash); echo $X",
            check: |s| s.trim().contains("bash"),
        },
        Test {
            name: "dirname",
            script: "X=$(dirname /usr/bin/bash); echo $X",
            check: |s| s.trim() == "/usr/bin",
        },
        Test {
            name: "nested",
            script: "X=$(dirname $(readlink -f /usr/bin/bash)); echo $X",
            check: |s| !s.trim().is_empty() && s.trim() != "/",
        },
        Test {
            name: "vscode_root",
            // Use the test harness binary itself — a deeply nested path
            // that exists in any rootfs with /opt/litebox mounted.
            script: concat!(
                "SCRIPT=$(which bash); ",
                "ROOT=$(dirname $(dirname $(readlink -f $SCRIPT))); ",
                "echo $ROOT",
            ),
            // /usr/bin/bash → readlink → /usr/bin/bash → dirname² → /usr
            check: |s| !s.trim().is_empty() && s.trim() != "/" && s.trim() != "",
        },
        Test {
            name: "which",
            script: "X=$(which bash); echo $X",
            check: |s| s.trim().contains("bash"),
        },
        Test {
            name: "uname",
            script: "X=$(uname -m); echo $X",
            check: |s| s.trim() == "x86_64",
        },
    ];

    for &agent in AGENTS {
        for test in tests {
            let test_id = format!("SC.{}.{}", test.name, agent);
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), test.script.into()],
                        timeout_secs: Some(10),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if (test.check)(stdout)
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// CC: Concurrent fork/exec/pipe tests
// (stress test delayed-fork, CoW, pipe bridging under concurrency)
// ═══════════════════════════════════════════════════════════════════

/// Tests that fork/exec/pipe operations work correctly when multiple
/// agents perform them simultaneously.  Each test starts the same
/// operation on ALL agents via background exec (each writing results
/// to a unique file), waits, then reads and verifies results.
///
/// This catches races in:
///   - delayed-fork worker spawning under concurrent forks
///   - CoW page snapshot/restore with simultaneous vfork children
///   - pipe ring buffer position tracking across multiple processes
///   - 9P file coherence with concurrent writers
///
/// Tests:
///   CC.echo         — concurrent $(echo hello) on all agents
///   CC.fork_exec    — concurrent fork+exec of test harness
///   CC.pipe_capture — concurrent $(echo | cat) pipeline capture
///   CC.file_write   — concurrent writes, then cross-read
pub(crate) async fn concurrent_fork_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === Concurrent Fork ({} agents) ===",
        AGENTS.len()
    );

    let self_exe = r.self_exe.clone();

    struct ConcTest {
        name: &'static str,
        /// Shell script template. {path} is replaced with the result file path.
        script_template: &'static str,
        /// Check function for the result file content.
        check: fn(&str) -> bool,
    }

    let tests: &[ConcTest] = &[
        ConcTest {
            name: "echo",
            script_template: "echo $(echo hello) > {path}",
            check: |s| s.trim() == "hello",
        },
        ConcTest {
            name: "fork_exec",
            script_template: "{exe} echo-test > {path} 2>&1",
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        ConcTest {
            name: "pipe_capture",
            script_template: "echo $(echo data | cat) > {path}",
            check: |s| s.trim() == "data",
        },
        ConcTest {
            name: "file_write",
            script_template: "echo agent-wrote-{agent} > {path}",
            check: |s| s.contains("agent-wrote-"),
        },
    ];

    for test in tests {
        let test_base = format!("CC.{}", test.name);

        // Phase 1: Start all agents concurrently via background exec.
        let mut bg_pids: Vec<(&str, Option<u32>, String)> = Vec::new();
        for &agent in AGENTS {
            let path = format!("/shared/cc-{}-{}.txt", test.name, agent);
            let script = test
                .script_template
                .replace("{path}", &path)
                .replace("{exe}", &self_exe)
                .replace("{agent}", agent);
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: None,
                        stdin: None,
                        background: true,
                    },
                )
                .await;
            let pid = match &resp {
                Response::Background { pid } => Some(*pid),
                Response::ExecResult { .. } => None,
                _ => None,
            };
            bg_pids.push((agent, pid, path));
        }

        // Phase 2: Wait for all to complete.
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Phase 3: Read result files and verify.
        for (agent, pid, path) in &bg_pids {
            let test_id = format!("{test_base}.{agent}");
            let resp = r.send(*agent, Command::FsRead { path: path.clone() }).await;
            let pass = matches!(
                &resp,
                Response::Ok { data: Some(d) } if (test.check)(d)
            );
            r.record(&test_id, *agent, pass, &format!("{resp:?}"));

            if let Some(pid) = pid {
                let _ = r.send(*agent, Command::Kill { pid: *pid }).await;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// TR: Touch + redirect file coherence
// (9P cache stale inode after touch + fork+exec redirect)
// ═══════════════════════════════════════════════════════════════════

/// When a file is pre-created with `touch`, then a fork+exec'd binary
/// writes to it via shell redirect (`cmd > file &`), the parent's
/// `cat` of the file must see the child's output.
///
/// The VS Code install script does:
///   touch "$LOG"; chmod 600 "$LOG"
///   CLI > "$LOG" 2>&1 < /dev/null &
///   cat "$LOG"   ← must see CLI output
///
/// Tests:
///   TR.no_touch      — no pre-creation, redirect creates file (control)
///   TR.touch          — touch before redirect
///   TR.touch_chmod    — touch + chmod before redirect (VS Code pattern)
///   TR.echo_touch     — echo > file before redirect (pre-create with data)
///   TR.builtin_touch  — touch + builtin redirect (no fork+exec)
pub(crate) async fn touch_redirect_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === Touch+Redirect ({} agents) ===",
        AGENTS.len()
    );

    let self_exe = r.self_exe.clone();

    struct TRTest {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }

    let tests: &[TRTest] = &[
        TRTest {
            name: "no_touch",
            script_template: concat!(
                "rm -f {path}; ",
                "{exe} echo-test > {path} 2>&1 &\n",
                "BGPID=$!\nsleep 2\ncat {path}\n",
                "kill $BGPID 2>/dev/null\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        TRTest {
            name: "touch",
            script_template: concat!(
                "rm -f {path}; touch {path}; ",
                "{exe} echo-test > {path} 2>&1 &\n",
                "BGPID=$!\nsleep 2\ncat {path}\n",
                "kill $BGPID 2>/dev/null\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        TRTest {
            name: "touch_chmod",
            script_template: concat!(
                "rm -f {path}; touch {path}; chmod 600 {path}; ",
                "{exe} echo-test > {path} 2>&1 &\n",
                "BGPID=$!\nsleep 2\ncat {path}\n",
                "kill $BGPID 2>/dev/null\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        TRTest {
            name: "echo_touch",
            script_template: concat!(
                "rm -f {path}; echo init > {path}; ",
                "{exe} echo-test > {path} 2>&1 &\n",
                "BGPID=$!\nsleep 2\ncat {path}\n",
                "kill $BGPID 2>/dev/null\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        TRTest {
            name: "builtin_touch",
            script_template: concat!(
                "rm -f {path}; touch {path}; chmod 600 {path}; ",
                "echo builtin-data > {path} &\n",
                "wait\ncat {path}\n",
            ),
            check: |s| s.contains("builtin-data"),
        },
    ];

    for &agent in AGENTS {
        for test in tests {
            let test_id = format!("TR.{}.{}", test.name, agent);
            let path = format!("/shared/tr-{}-{}.txt", test.name, agent);
            let script = test
                .script_template
                .replace("{path}", &path)
                .replace("{exe}", &self_exe);
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(10),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if (test.check)(stdout)
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// KP: PID and /proc visibility across delayed-fork migration
// ═══════════════════════════════════════════════════════════════════

/// After fork+exec, the child is migrated to a new worker via delayed fork.
/// These tests cover the full visibility matrix:
///
/// **Observation direction:**
///   parent → child:  kill -0, /proc/<child>/cmdline
///   child  → parent: kill -0, /proc/<ppid>, /proc/<ppid>/cmdline, getppid()
///   self:            /proc/self, /proc/self/cmdline, /proc/self/stat, /proc/<own_pid>
///
/// **Conditions:**
///   immediate vs delayed (1s), single fork vs many prior forks
///
/// Tests:
///   KP.kill0_bg           — parent kill -0 $! immediate
///   KP.kill0_many         — parent kill -0 after many prior forks
///   KP.proc_child         — parent /proc/<child_pid>/cmdline readable
///   KP.proc_self          — /proc/self + /proc/<own_pid> from migrated child
///   KP.ppid_proc          — child /proc/<ppid> visible
///   KP.ppid_kill0         — child kill -0 ppid
///   KP.ppid_cmdline       — child /proc/<ppid>/cmdline readable
///   KP.getppid_correct    — child getppid() returns parent's PID
///   KP.parent_monitor     — child stays alive while monitoring parent via /proc
pub(crate) async fn pid_visibility_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === PID Visibility ({} agents) ===",
        AGENTS.len()
    );

    let self_exe = r.self_exe.clone();

    struct KPTest {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }

    let tests: &[KPTest] = &[
        // --- Parent → child direction ---
        // Basic: parent kill -0 $! after background fork+exec
        KPTest {
            name: "kill0_bg",
            script_template: concat!(
                "{exe} slow-echo > /dev/null 2>&1 &\n",
                "PID=$!\n",
                "kill -0 $PID 2>/dev/null && echo KILL0_OK || echo KILL0_FAIL\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("KILL0_OK"),
        },
        // Parent kill -0 after many prior forks (higher PID, install-script-like)
        KPTest {
            name: "kill0_many",
            script_template: concat!(
                "A=$(cat /etc/os-release | head -1)\n",
                "B=$(uname -m)\n",
                "C=$(ls /tmp | head -1)\n",
                "D=$(echo x | cat)\n",
                "{exe} slow-echo > /dev/null 2>&1 &\n",
                "PID=$!\n",
                "kill -0 $PID 2>/dev/null && echo KILL0_OK || echo KILL0_FAIL\n",
                "sleep 1\n",
                "kill -0 $PID 2>/dev/null && echo KILL0_1s_OK || echo KILL0_1s_FAIL\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("KILL0_OK") && s.contains("KILL0_1s_OK"),
        },
        // Parent reads /proc/<child>/cmdline of a migrated child
        KPTest {
            name: "proc_child",
            script_template: concat!(
                "{exe} slow-echo > /dev/null 2>&1 &\n",
                "PID=$!\n",
                "sleep 1\n",
                "test -d /proc/$PID && echo PROC_DIR_OK || echo PROC_DIR_FAIL\n",
                "cat /proc/$PID/cmdline 2>/dev/null | tr '\\0' ' ' | ",
                "grep -q litebox_test_harness && echo CMDLINE_OK || echo CMDLINE_FAIL\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("PROC_DIR_OK") && s.contains("CMDLINE_OK"),
        },
        // --- Self visibility ---
        // /proc/self and /proc/<own_pid> from a migrated child
        KPTest {
            name: "proc_self",
            script_template: concat!(
                "{exe} proc-probe > /tmp/proc-self.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/proc-self.txt\n",
            ),
            check: |s| {
                s.contains("self=true")
                    && s.contains("self_cmdline=true")
                    && s.contains("own_proc=true")
                    && s.contains("own_cmdline=true")
            },
        },
        // --- Child → parent direction ---
        // Child sees parent in /proc/<ppid>
        KPTest {
            name: "ppid_proc",
            script_template: concat!(
                "{exe} proc-probe > /tmp/ppid-proc.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-proc.txt\n",
            ),
            check: |s| s.contains("ppid_proc=true"),
        },
        // Child can kill -0 parent
        KPTest {
            name: "ppid_kill0",
            script_template: concat!(
                "{exe} proc-probe > /tmp/ppid-k0.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-k0.txt\n",
            ),
            check: |s| s.contains("ppid_kill0=true"),
        },
        // Child can read /proc/<ppid>/cmdline (sysinfo reads this)
        KPTest {
            name: "ppid_cmdline",
            script_template: concat!(
                "{exe} proc-probe > /tmp/ppid-cl.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-cl.txt\n",
            ),
            check: |s| s.contains("ppid_cmdline=true"),
        },
        // Child getppid() returns the parent's actual PID
        KPTest {
            name: "getppid_correct",
            script_template: concat!(
                "echo $$\n",
                "{exe} check-ppid > /tmp/ppid-val.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-val.txt\n",
            ),
            check: |s| {
                // First line is parent's $$, check-ppid reports ppid=N
                let lines: Vec<&str> = s.lines().collect();
                if lines.len() < 2 {
                    return false;
                }
                let parent_pid = lines[0].trim();
                // The ppid line may be prefixed with [harness] line
                lines
                    .iter()
                    .any(|l| l.contains(&format!("ppid={parent_pid}")))
            },
        },
        // --- Combined: parent-monitor pattern ---
        // Child can see parent via both /proc and kill -0
        KPTest {
            name: "parent_monitor",
            script_template: concat!(
                "{exe} proc-probe > /tmp/pmon.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/pmon.txt\n",
            ),
            check: |s| s.contains("ppid_proc=true") && s.contains("ppid_kill0=true"),
        },
    ];

    for &agent in AGENTS {
        for test in tests {
            let test_id = format!("KP.{}.{}", test.name, agent);
            let script = test.script_template.replace("{exe}", &self_exe);
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(15),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if (test.check)(stdout)
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// FR: File-Redirect — stdout of background process → file via redirect
// (discovered during cross-worker TCP debugging: nc prints to stdout
// but the redirected file stays empty)
// ═══════════════════════════════════════════════════════════════════

/// When a background command's stdout is redirected to a file
/// (`cmd > file &`), the child process's fd 1 is connected through
/// the mux bridge to the parent, which holds the file fd.
/// Data written by the child must be visible when the parent (or a
/// sibling) reads the file.
///
/// Tests cover:
///   FR.bg_echo       — echo in background: `echo DATA > file &; wait; cat file`
///   FR.bg_printf      — printf (no trailing newline): `printf DATA > file &; wait; cat file`
///   FR.bg_exe         — exec'd process writes to stdout → file
///   FR.bg_cat_pipe    — piped: `echo DATA | cat > file &; wait; cat file`
///   FR.fg_redirect    — control: foreground redirect should always work
pub(crate) async fn file_redirect_tests(r: &mut TestRunner) {
    eprintln!("[platform] === File Redirect ({} agents) ===", AGENTS.len());

    let self_exe = r.self_exe.clone();

    struct FRTest {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }

    let tests: &[FRTest] = &[
        // Control: foreground redirect (no background, no mux bridge)
        FRTest {
            name: "fg_redirect",
            script_template: concat!("echo FR_FG > {path}\n", "cat {path}\n",),
            check: |s| s.contains("FR_FG"),
        },
        // Background builtin (echo) writes to redirected stdout
        FRTest {
            name: "bg_echo",
            script_template: concat!("echo FR_BGECHO > {path} &\n", "wait\n", "cat {path}\n",),
            check: |s| s.contains("FR_BGECHO"),
        },
        // Background exec'd process writes to redirected stdout.
        // The child goes through delayed fork → different worker.
        // Its stdout is connected through the mux bridge.
        FRTest {
            name: "bg_exe",
            script_template: concat!("{exe} echo-test > {path} &\n", "wait\n", "cat {path}\n",),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        // Background pipeline writes to redirected file
        FRTest {
            name: "bg_cat_pipe",
            script_template: concat!("echo FR_PIPE | cat > {path} &\n", "wait\n", "cat {path}\n",),
            check: |s| s.contains("FR_PIPE"),
        },
        // Background process with append redirect (>>)
        FRTest {
            name: "bg_append",
            script_template: concat!(
                "echo LINE1 > {path}\n",
                "echo LINE2 >> {path} &\n",
                "wait\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("LINE1") && s.contains("LINE2"),
        },
    ];

    for &agent in AGENTS {
        for test in tests {
            let test_id = format!("FR.{}.{}", test.name, agent);
            let path = format!("/shared/fr-{}-{}.txt", test.name, agent);
            let script = test
                .script_template
                .replace("{path}", &path)
                .replace("{exe}", &self_exe);
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(10),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if (test.check)(stdout)
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// PN: Pipe Non-blocking — fcntl F_SETFL O_NONBLOCK on pipes
// (dropbear sets pipes non-blocking for its event loop; if F_SETFL
// silently fails, read() returns 0/EOF instead of EAGAIN, causing
// a busy-loop that starves the network worker and blocks new SSH
// connections including the VS Code SOCKS tunnel)
// ═══════════════════════════════════════════════════════════════════

/// Tests that pipes support F_SETFL O_NONBLOCK correctly:
///   PN.setfl        — fcntl(F_SETFL, O_NONBLOCK) succeeds
///   PN.empty_eagain — read() on empty non-blocking pipe returns EAGAIN
///   PN.data         — read() returns data after write
///   PN.eof          — read() returns 0 only after write end is closed
///   PN.child_eagain — dropbear pattern: fork, set pipe non-blocking,
///                     read returns EAGAIN while child is alive
///   PN.child_data   — child writes data, parent reads it
///   PN.child_eof    — child exits, parent gets real EOF (0)
pub(crate) async fn pipe_nonblock_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === Pipe Non-blocking ({} agents) ===",
        AGENTS.len()
    );

    let self_exe = r.self_exe.clone();

    // Test 1: basic pipe non-blocking (within a single process)
    for &agent in AGENTS {
        let test_prefix = format!("PN.{agent}");
        let resp = r
            .send(
                agent,
                Command::Exec {
                    args: vec![self_exe.clone(), "pipe-nonblock".into()],
                    timeout_secs: Some(10),
                    stdin: None,
                    background: false,
                },
            )
            .await;
        match &resp {
            Response::ExecResult { stdout, .. } => {
                r.record(
                    &format!("{test_prefix}.setfl"),
                    agent,
                    stdout.contains("PIPE_NB_SETFL=OK"),
                    &format!("{resp:?}"),
                );
                r.record(
                    &format!("{test_prefix}.empty_eagain"),
                    agent,
                    stdout.contains("PIPE_NB_EMPTY=EAGAIN"),
                    &format!("{resp:?}"),
                );
                r.record(
                    &format!("{test_prefix}.data"),
                    agent,
                    stdout.contains("PIPE_NB_DATA=OK"),
                    &format!("{resp:?}"),
                );
                r.record(
                    &format!("{test_prefix}.eof"),
                    agent,
                    stdout.contains("PIPE_NB_EOF=OK"),
                    &format!("{resp:?}"),
                );
            }
            _ => {
                for suffix in ["setfl", "empty_eagain", "data", "eof"] {
                    r.record(
                        &format!("{test_prefix}.{suffix}"),
                        agent,
                        false,
                        &format!("{resp:?}"),
                    );
                }
            }
        }
    }

    // Test 2: cross-process pipe non-blocking (the dropbear pattern)
    for &agent in DEPTH_AGENTS {
        let test_prefix = format!("PN.child.{agent}");
        let resp = r
            .send(
                agent,
                Command::Exec {
                    args: vec![self_exe.clone(), "pipe-child-nonblock".into()],
                    timeout_secs: Some(10),
                    stdin: None,
                    background: false,
                },
            )
            .await;
        match &resp {
            Response::ExecResult { stdout, .. } => {
                r.record(
                    &format!("{test_prefix}.eagain"),
                    agent,
                    stdout.contains("PCHILD_INITIAL=EAGAIN"),
                    &format!("{resp:?}"),
                );
                r.record(
                    &format!("{test_prefix}.data"),
                    agent,
                    stdout.contains("PCHILD_DATA=OK"),
                    &format!("{resp:?}"),
                );
                r.record(
                    &format!("{test_prefix}.eof"),
                    agent,
                    stdout.contains("PCHILD_EOF=OK"),
                    &format!("{resp:?}"),
                );
            }
            _ => {
                for suffix in ["eagain", "data", "eof"] {
                    r.record(
                        &format!("{test_prefix}.{suffix}"),
                        agent,
                        false,
                        &format!("{resp:?}"),
                    );
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// EP: Epoll + Socket wakeup — epoll_wait must wake when TCP data arrives
// (the tokio pattern: epoll_wait → futex park → data arrives → must wake)
// ═══════════════════════════════════════════════════════════════════

/// Tests that epoll_wait correctly wakes when data arrives on a TCP socket.
///
/// This is the pattern every async runtime (tokio, async-std) uses:
/// register a socket with epoll, then call epoll_wait. When data arrives
/// via the network worker, epoll must wake the thread.
///
/// In litebox, the network worker delivers data via the proxy ring buffer
/// and calls notify_observers(IN). This must propagate through the epoll
/// subsystem to wake a thread sleeping in epoll_wait. If the thread is
/// parked on a futex (tokio's parking mechanism) between the epoll check
/// and the sleep, the notification must still reach it.
///
/// Tests:
///   EP.direct.accept — blocking epoll_wait wakes for accept
///   EP.direct.read  — blocking epoll_wait wakes for data
///   EP.tokio.accept — epoll_wait(0) → re-wait wakes for accept
///   EP.tokio.read   — epoll_wait(0) → re-wait wakes for data
pub(crate) async fn epoll_socket_tests(r: &mut TestRunner) {
    eprintln!("[platform] === Epoll Socket ({} agents) ===", AGENTS.len());

    let self_exe = r.self_exe.clone();

    for &variant in &["direct", "tokio"] {
        for &agent in AGENTS {
            let port = match (variant, agent) {
                ("direct", "A") => 19990,
                ("direct", "AA") => 19991,
                ("direct", _) => 19992,
                ("tokio", "A") => 19993,
                ("tokio", "AA") => 19994,
                _ => 19995,
            };
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec![
                            self_exe.clone(),
                            "epoll-socket".into(),
                            port.to_string(),
                            variant.to_string(),
                        ],
                        timeout_secs: Some(15),
                        stdin: None,
                        background: false,
                    },
                )
                .await;

            match &resp {
                Response::ExecResult { stdout, .. } => {
                    let accept_ok = stdout.contains("EPOLL_ACCEPT=") && !stdout.contains("TIMEOUT");
                    r.record(
                        &format!("EP.{variant}.accept.{agent}"),
                        agent,
                        accept_ok,
                        &format!("{resp:?}"),
                    );

                    let read_ok = stdout.contains("EPOLL_READ=OK");
                    r.record(
                        &format!("EP.{variant}.read.{agent}"),
                        agent,
                        read_ok,
                        &format!("{resp:?}"),
                    );
                }
                _ => {
                    r.record(
                        &format!("EP.{variant}.accept.{agent}"),
                        agent,
                        false,
                        &format!("{resp:?}"),
                    );
                    r.record(
                        &format!("EP.{variant}.read.{agent}"),
                        agent,
                        false,
                        &format!("{resp:?}"),
                    );
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// LB: Loopback TCP across delayed-fork workers
// (VS Code exec server uses SOCKS proxy → TCP loopback to CLI port)
// ═══════════════════════════════════════════════════════════════════

/// A background process (different worker after delayed fork) listens on
/// a TCP port. The parent (original worker) connects to it. This is the
/// exact pattern VS Code uses: the CLI listens on a port, and the SOCKS
/// proxy (through dropbear in the same sandbox) connects to it.
///
/// Tests cover the address matrix:
///   LB.localhost    — connect via 127.0.0.1
///   LB.guest_ip     — connect via 10.0.0.2 (guest's own IP)
///   LB.any          — listen 0.0.0.0, connect 127.0.0.1
///   LB.same_worker  — listen and connect in same worker (control)
pub(crate) async fn loopback_tcp_tests(r: &mut TestRunner) {
    eprintln!("[platform] === Loopback TCP (3 agents) ===");

    let self_exe = r.self_exe.clone();

    struct LBTest {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }

    let tests: &[LBTest] = &[
        // Control: same-worker TCP (no delayed fork, should always work)
        LBTest {
            name: "same_worker",
            script_template: concat!(
                "{exe} tcp-echo 19876 &\n",
                "sleep 1\n",
                "REPLY=$(echo LB_SAME | nc -q1 127.0.0.1 19876 2>/dev/null)\n",
                "echo REPLY=$REPLY\n",
                "wait\n",
            ),
            check: |s| s.contains("REPLY=LB_SAME"),
        },
        // Cross-worker: bg process (different worker) listens, parent connects via 127.0.0.1
        LBTest {
            name: "localhost",
            script_template: concat!(
                "{exe} tcp-echo 19877 > /dev/null 2>&1 &\n",
                "PID=$!\nsleep 2\n",
                "REPLY=$(echo LB_LOCAL | nc -q1 127.0.0.1 19877 2>/dev/null)\n",
                "echo REPLY=$REPLY\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("REPLY=LB_LOCAL"),
        },
        // Cross-worker: listen on 0.0.0.0, connect via 127.0.0.1
        // (exact VS Code pattern: CLI listens 0.0.0.0, SOCKS connects 127.0.0.1)
        LBTest {
            name: "any_to_local",
            script_template: concat!(
                "{exe} tcp-echo 19879 > /dev/null 2>&1 &\n",
                "PID=$!\nsleep 2\n",
                "REPLY=$(echo LB_ANY | nc -q1 127.0.0.1 19879 2>/dev/null)\n",
                "echo REPLY=$REPLY\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("REPLY=LB_ANY"),
        },
        // Cross-worker: server does CPU work after listen() before accept()
        // (Node.js pattern: listen succeeds, module loading delays accept)
        LBTest {
            name: "busy_after_listen",
            script_template: concat!(
                "{exe} tcp-listen-busy 19880 3 > /dev/null 2>&1 &\n",
                "PID=$!\nsleep 1\n",
                "REPLY=$(echo LB_BUSY | nc -q5 -w10 127.0.0.1 19880 2>/dev/null)\n",
                "echo REPLY=$REPLY\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("REPLY=LB_BUSY"),
        },
        // Cross-worker: fast-close client (data + immediate FIN).
        // Exercises CloseWait promotion — when data+FIN arrive in rapid
        // succession, the broker's smoltcp socket can skip Established and
        // land directly in CloseWait within one iface.poll() call.
        // promote_established must accept CloseWait sockets to relay the data.
        LBTest {
            name: "fast_close",
            script_template: concat!(
                "{exe} tcp-recv-all 19881 &\n",
                "PID=$!\nsleep 2\n",
                // -q0: close immediately after stdin EOF (fastest possible FIN)
                "echo LB_FAST | nc -q0 127.0.0.1 19881 2>/dev/null\n",
                "sleep 2\n",
                // tcp-recv-all prints RECV=... to stdout, captured via wait
                "wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("RECV=LB_FAST"),
        },
        // Cross-worker: verify half-close FIN propagation.
        // Server uses tcp-recv-all which calls read_to_end() — it only
        // exits when it sees EOF on the socket. EOF requires the client's
        // FIN to propagate through the TCP pair via shutdown(Write).
        // Without half-close propagation, tcp-recv-all hangs forever.
        LBTest {
            name: "halfclose_eof",
            script_template: concat!(
                "{exe} tcp-recv-all 19882 &\n",
                "PID=$!\nsleep 2\n",
                // -w2: wait 2s after stdin EOF before closing
                // (data and FIN arrive in separate iterations)
                "echo LB_HALF | nc -w2 127.0.0.1 19882 2>/dev/null\n",
                "sleep 3\n",
                "wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("RECV=LB_HALF"),
        },
    ];

    for &agent in AGENTS {
        for test in tests {
            let test_id = format!("LB.{}.{}", test.name, agent);
            let script = test.script_template.replace("{exe}", &self_exe);
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(15),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if (test.check)(stdout)
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// FKLC: fork-listen-close — VS Code CLI pattern
// ═══════════════════════════════════════════════════════════════════

/// Reproduces the VS Code CLI listen-fork-close pattern:
///   1. Agent A calls NetListenForkClose(port) — binds, listens, forks
///      a child echo server, then parent closes its listen fd.
///   2. Agent B connects to that port.
///
/// In litebox delayed-fork, the parent's close() destroys the shared
/// listen socket before the child migrates, so B's connection gets RST.
///
/// This is the root cause of the VS Code "Connection closed" failure:
/// the VS Code CLI process forks a child to handle connections, closes
/// its own listen fd, and the child's listen socket is destroyed.
pub(crate) async fn fork_listen_close_tests(r: &mut TestRunner) {
    eprintln!("[platform] === FKLC: fork-listen-close ===");

    // Test 1: Listen then immediately unlisten, then cross-worker connect.
    // This reproduces the VS Code CLI pattern where the listen socket
    // is created and then closed before the cross-worker SYN arrives.
    let port = 19920u16;

    // Agent A: listen then unlisten (simulating VS Code CLI close).
    let listen_resp = r.send("A", Command::NetListen { port }).await;
    if !matches!(&listen_resp, Response::Listening { .. }) {
        r.record(
            "FKLC.listen_unlisten",
            "B",
            false,
            &format!("listen failed: {listen_resp:?}"),
        );
        return;
    }
    // Immediately unlisten — the port is still registered in the broker
    // until the broker processes the unlisten message.
    let _ = r.send("A", Command::NetUnlisten { port }).await;

    // Agent B connects — the broker still has the port registered,
    // but the runner's smoltcp no longer has listen sockets.
    let conn_resp = r
        .send(
            "B",
            Command::NetConnect {
                addr: format!("127.0.0.1:{port}"),
                data: "listen_unlisten".into(),
            },
        )
        .await;
    // This SHOULD fail (RST) — the listen socket was closed.
    let got_rst = matches!(&conn_resp, Response::ConnectFailed { .. });
    r.record(
        "FKLC.listen_unlisten",
        "B",
        got_rst,
        &format!("expected RST: {conn_resp:?}"),
    );

    // Test 2: fd inheritance across fork+exec — the VS Code CLI pattern.
    // Uses tcp-fork-listen-accept subcommand which:
    //   1. bind+listen on port
    //   2. Clear CLOEXEC on listen fd
    //   3. fork+exec child ("tcp-accept-inherited") that accepts on inherited fd
    //   4. Parent closes its listen fd
    //   5. Child accepts and echoes
    //
    // This tests whether the child's inherited listen fd survives the
    // parent closing its copy. Cannot be expressed via protocol primitives
    // because the child needs to accept on a raw fd, not re-bind.
    let port2 = 19921u16;
    let bg_resp = r
        .send(
            "A",
            Command::Exec {
                args: vec![
                    r.self_exe.clone(),
                    "tcp-fork-listen-accept".into(),
                    port2.to_string(),
                ],
                timeout_secs: None,
                stdin: None,
                background: true,
            },
        )
        .await;
    let bg_pid = match &bg_resp {
        Response::Background { pid } => Some(*pid),
        _ => {
            r.record(
                "FKLC.cross_connect",
                "B",
                false,
                &format!("bg spawn failed: {bg_resp:?}"),
            );
            return;
        }
    };

    // Wait for bind+listen+fork+parent-close to complete.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Cross-worker connect from B — the child should accept and echo.
    let conn_resp = r
        .send(
            "B",
            Command::NetConnect {
                addr: format!("127.0.0.1:{port2}"),
                data: "fork_listen_close".into(),
            },
        )
        .await;
    let pass = matches!(&conn_resp, Response::Connected { echo } if echo == "fork_listen_close");
    r.record("FKLC.cross_connect", "B", pass, &format!("{conn_resp:?}"));

    if let Some(pid) = bg_pid {
        let _ = r.send("A", Command::Kill { pid }).await;
    }
}

// ═══════════════════════════════════════════════════════════════════
// PROC: /proc filesystem tests
// ═══════════════════════════════════════════════════════════════════

/// Tests that synthetic /proc files behave like real Linux:
/// - /proc/self/stat is readable and seekable (not ESPIPE)
/// - /proc/uptime is readable
/// - /proc/self/maps is readable
///
/// The lseek test is critical: the VS Code Server reads /proc/PID/stat
/// and calls lseek() to check seekability. If lseek returns ESPIPE
/// (pipe-backed), the server tears down its listener.
pub(crate) async fn proc_filesystem_tests(r: &mut TestRunner) {
    eprintln!("[platform] === PROC: /proc filesystem ===");

    for &agent in AGENTS {
        // Test 1: /proc/self/stat is readable and contains PID.
        let test_id = format!("PROC.self_stat.{agent}");
        let resp = r
            .send(
                agent,
                Command::FsRead {
                    path: "/proc/self/stat".into(),
                },
            )
            .await;
        let pass = matches!(&resp, Response::Ok { data: Some(d) } if d.contains(") "));
        r.record(&test_id, agent, pass, &format!("{resp:?}"));

        // Test 2: /proc/self/stat is seekable (lseek doesn't return ESPIPE).
        // We test this by using dd which does lseek internally.
        let test_id = format!("PROC.stat_seekable.{agent}");
        let resp = r
            .send(
                agent,
                exec(vec![
                    "sh".into(),
                    "-c".into(),
                    "dd if=/proc/self/stat bs=1 skip=0 count=10 2>/dev/null | wc -c".into(),
                ]),
            )
            .await;
        let pass = matches!(
            &resp,
            Response::ExecResult { exit_code: 0, stdout, .. }
                if stdout.trim().parse::<u32>().unwrap_or(0) > 0
        );
        r.record(&test_id, agent, pass, &format!("{resp:?}"));

        // Test 3: /proc/uptime is readable.
        let test_id = format!("PROC.uptime.{agent}");
        let resp = r
            .send(
                agent,
                Command::FsRead {
                    path: "/proc/uptime".into(),
                },
            )
            .await;
        let pass = matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty());
        r.record(&test_id, agent, pass, &format!("{resp:?}"));
    }
}

// Register functions that convert platform fix tests into `super::Test` structs.
// Each `register_*` function returns a `Vec<super::Test>`.

// ═══════════════════════════════════════════════════════════════════
// POLL: epoll/ppoll IN events (fix 0fb258e2)
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_poll_ready_tests() -> Vec<super::Test> {
    let mut tests = Vec::new();
    for &agent in AGENTS {
        let agent_s = agent.to_string();
        tests.push(super::Test {
            suite: "matrix",
            group: "poll_ready",
            id: format!("POLL.pipe.{agent}"),
            xfail: None,
            run: Box::new(move |r| {
                let a = agent_s.clone();
                Box::pin(async move {
                    let resp = r.send(&a, Command::PollReady { timeout_ms: 2000 }).await;
                    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "POLLIN");
                    super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                })
            }),
        });
    }
    tests
}

// ═══════════════════════════════════════════════════════════════════
// GSN: getsockname port after bind (fix 336dc79e)
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_bind_getsockname_tests() -> Vec<super::Test> {
    let mut tests = Vec::new();
    for &family in FAMILIES {
        for &agent in DEPTH_AGENTS {
            let agent_s = agent.to_string();
            let family_s = family.to_string();
            tests.push(super::Test {
                suite: "matrix",
                group: "bind_getsockname",
                id: format!("GSN.{family}.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = agent_s.clone();
                    let f = family_s.clone();
                    Box::pin(async move {
                        let resp = r.send(&a, Command::BindGetsockname { family: f }).await;
                        let pass = match &resp {
                            Response::Ok { data: Some(d) } => d
                                .strip_prefix("port=")
                                .and_then(|s| s.parse::<u16>().ok())
                                .map_or(false, |p| p > 0),
                            _ => false,
                        };
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
    tests
}

// ═══════════════════════════════════════════════════════════════════
// PID: monotonic pipe pair_id (fix c2d0abdc)
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_pipe_pair_id_tests() -> Vec<super::Test> {
    let mut tests = Vec::new();
    for &agent in AGENTS {
        let agent_s = agent.to_string();
        tests.push(super::Test {
            suite: "matrix",
            group: "pipe_pair_id",
            id: format!("PID.{agent}"),
            xfail: None,
            run: Box::new(move |r| {
                let a = agent_s.clone();
                Box::pin(async move {
                    let resp = r.send(&a, Command::PipePairIdUnique { count: 100 }).await;
                    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "unique");
                    super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                })
            }),
        });
    }
    tests
}

// ═══════════════════════════════════════════════════════════════════
// EXITD: bridge thread join before exit (fix 2def3ac6)
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_exit_data_integrity_tests() -> Vec<super::Test> {
    let mut tests = Vec::new();
    for &size in EXIT_SIZES {
        for &binary in EXIT_BINARIES {
            for &agent in DEPTH_AGENTS {
                let agent_s = agent.to_string();
                let binary_s = binary.to_string();
                tests.push(super::Test {
                    suite: "fork",
                    group: "exit_data_integrity",
                    id: format!("EXITD.{size}.{binary}.{agent}"),
                    xfail: None,
                    run: Box::new(move |r| {
                        let a = agent_s.clone();
                        let b = binary_s.clone();
                        let self_exe = r.self_exe.clone();
                        Box::pin(async move {
                            let bin_path = match b.as_str() {
                                "pie" => self_exe,
                                "nonpie" => match crate::find_nonpie_binary() {
                                    Some(p) => p,
                                    None => {
                                        return super::TestOutcome::new(
                                            &a,
                                            false,
                                            "FAIL: nonpie binary not found — mount at /opt/nonpie"
                                                .to_string(),
                                        );
                                    }
                                },
                                _ => unreachable!(),
                            };
                            let resp = r
                                .send(
                                    &a,
                                    super::exec(vec![
                                        bin_path,
                                        "write-then-exit".into(),
                                        size.to_string(),
                                    ]),
                                )
                                .await;
                            let pass = match &resp {
                                Response::ExecResult {
                                    exit_code: 0,
                                    stdout,
                                    ..
                                } => stdout.len() == size,
                                _ => false,
                            };
                            let detail = match &resp {
                                Response::ExecResult { stdout, .. } => {
                                    format!("got {} bytes, expected {size}", stdout.len())
                                }
                                _ => format!("{resp:?}"),
                            };
                            super::TestOutcome::new(&a, pass, detail)
                        })
                    }),
                });
            }
        }
    }
    tests
}

// ═══════════════════════════════════════════════════════════════════
// NPIPE: non-PIE pipe chain integrity (fix febc3e41)
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_nonpie_pipe_chain_tests() -> Vec<super::Test> {
    let mut tests = Vec::new();
    for &reps in NPIPE_REPS {
        for &agent in DEPTH_AGENTS {
            let agent_s = agent.to_string();
            // Sequential non-PIE pattern.
            tests.push(super::Test {
                suite: "fork",
                group: "nonpie_pipe_chain",
                id: format!("NPIPE.seq.x{reps}.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = agent_s.clone();
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let nonpie = match crate::find_nonpie_binary() {
                            Some(p) => p,
                            None => {
                                return super::TestOutcome::new(
                                    &a,
                                    false,
                                    "FAIL: nonpie binary not found — mount at /opt/nonpie"
                                        .to_string(),
                                );
                            }
                        };
                        let mut all_clean = true;
                        let mut detail = String::new();
                        for i in 0..reps {
                            let tag = format!("seq_{a}_{i}");
                            let resp = r
                                .send(
                                    &a,
                                    super::exec(vec![
                                        nonpie.clone(),
                                        "write-known".into(),
                                        tag.clone(),
                                    ]),
                                )
                                .await;
                            let expected = format!("PIPEDATA:{tag}");
                            let ok = matches!(
                                &resp,
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.trim() == expected
                            );
                            if !ok {
                                all_clean = false;
                                detail = format!("iter {i}: expected '{expected}', got {resp:?}");
                                break;
                            }
                        }
                        if all_clean {
                            detail = format!("{reps} sequential non-PIE execs all clean");
                        }
                        super::TestOutcome::new(&a, all_clean, detail)
                    })
                }),
            });

            // Interleaved PIE + non-PIE pattern.
            let agent_s2 = agent.to_string();
            tests.push(super::Test {
                suite: "fork",
                group: "nonpie_pipe_chain",
                id: format!("NPIPE.interleaved.x{reps}.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = agent_s2.clone();
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let nonpie = match crate::find_nonpie_binary() {
                            Some(p) => p,
                            None => {
                                return super::TestOutcome::new(
                                    &a,
                                    false,
                                    "FAIL: nonpie binary not found — mount at /opt/nonpie"
                                        .to_string(),
                                );
                            }
                        };
                        let mut all_clean = true;
                        let mut detail = String::new();
                        for i in 0..reps {
                            let np_tag = format!("np_{a}_{i}");
                            let resp = r
                                .send(
                                    &a,
                                    super::exec(vec![
                                        nonpie.clone(),
                                        "write-known".into(),
                                        np_tag.clone(),
                                    ]),
                                )
                                .await;
                            let expected = format!("PIPEDATA:{np_tag}");
                            let ok = matches!(
                                &resp,
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.trim() == expected
                            );
                            if !ok {
                                all_clean = false;
                                detail =
                                    format!("iter {i} nonpie: expected '{expected}', got {resp:?}");
                                break;
                            }
                            let resp = r
                                .send(&a, super::exec(vec![self_exe.clone(), "echo-test".into()]))
                                .await;
                            let ok = matches!(
                                &resp,
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.trim() == "ECHO_TEST_OK"
                            );
                            if !ok {
                                all_clean = false;
                                detail =
                                    format!("iter {i} pie: expected 'ECHO_TEST_OK', got {resp:?}");
                                break;
                            }
                        }
                        if all_clean {
                            detail = format!("{reps} interleaved PIE+nonPIE execs all clean");
                        }
                        super::TestOutcome::new(&a, all_clean, detail)
                    })
                }),
            });
        }
    }
    tests
}

// ═══════════════════════════════════════════════════════════════════
// XCONN: cross-worker TCP — first connection must succeed
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_cross_worker_first_connect_tests() -> Vec<super::Test> {
    vec![
        // XCONN.cross_first: A listens, B connects — first attempt must succeed.
        super::Test {
            suite: "xworker",
            group: "cross_worker_first_connect",
            id: "XCONN.cross_first".to_string(),
            xfail: None,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let port = 19900u16;
                    let listen_resp = r.send("A", Command::NetListen { port }).await;
                    if !matches!(&listen_resp, Response::Listening { .. }) {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let conn_resp = r
                        .send(
                            "B",
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "first_connect".into(),
                            },
                        )
                        .await;
                    let ok = matches!(&conn_resp, Response::Connected { echo } if echo == "first_connect");
                    let _ = r.send("A", Command::NetUnlisten { port }).await;
                    super::TestOutcome::new("B", ok, format!("{conn_resp:?}"))
                })
            }),
        },
        // XCONN.deep_cross: B listens, AA (deeper worker) connects.
        super::Test {
            suite: "xworker",
            group: "cross_worker_first_connect",
            id: "XCONN.deep_cross".to_string(),
            xfail: None,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let port = 19901u16;
                    let listen_resp = r.send("B", Command::NetListen { port }).await;
                    if !matches!(&listen_resp, Response::Listening { .. }) {
                        return super::TestOutcome::new(
                            "AA",
                            false,
                            format!("listen on B failed: {listen_resp:?}"),
                        );
                    }
                    let conn_resp = r
                        .send(
                            "AA",
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "deep_cross".into(),
                            },
                        )
                        .await;
                    let ok =
                        matches!(&conn_resp, Response::Connected { echo } if echo == "deep_cross");
                    let _ = r.send("B", Command::NetUnlisten { port }).await;
                    super::TestOutcome::new("AA", ok, format!("{conn_resp:?}"))
                })
            }),
        },
        // XCONN.cross_seq_x3: 3 rapid sequential connections from B to A's listener.
        super::Test {
            suite: "xworker",
            group: "cross_worker_first_connect",
            id: "XCONN.cross_seq_x3".to_string(),
            xfail: None,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let port = 19902u16;
                    let listen_resp = r.send("A", Command::NetListen { port }).await;
                    if !matches!(&listen_resp, Response::Listening { .. }) {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let mut all_ok = true;
                    let mut fail_detail = String::new();
                    for i in 0..3 {
                        let conn_resp = r
                            .send(
                                "B",
                                Command::NetConnect {
                                    addr: format!("127.0.0.1:{port}"),
                                    data: format!("seq_{i}"),
                                },
                            )
                            .await;
                        if !matches!(&conn_resp, Response::Connected { echo } if echo == &format!("seq_{i}"))
                        {
                            all_ok = false;
                            fail_detail = format!("connection {i} failed: {conn_resp:?}");
                            break;
                        }
                    }
                    let _ = r.send("A", Command::NetUnlisten { port }).await;
                    let detail = if all_ok {
                        "3/3 sequential OK".into()
                    } else {
                        fail_detail
                    };
                    super::TestOutcome::new("B", all_ok, detail)
                })
            }),
        },
    ]
}

// ═══════════════════════════════════════════════════════════════════
// XCONN.self: same-worker loopback (VS Code pattern)
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_cross_worker_self_connect_tests() -> Vec<super::Test> {
    vec![
        // XCONN.self_A: A listens, A connects to itself.
        super::Test {
            suite: "xworker",
            group: "cross_worker_self_connect",
            id: "XCONN.self_A".to_string(),
            xfail: None,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let port = 19910u16;
                    let listen_resp = r.send("A", Command::NetListen { port }).await;
                    if !matches!(&listen_resp, Response::Listening { .. }) {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let conn_resp = r
                        .send(
                            "A",
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "self_loopback".into(),
                            },
                        )
                        .await;
                    let ok = matches!(&conn_resp, Response::Connected { echo } if echo == "self_loopback");
                    let _ = r.send("A", Command::NetUnlisten { port }).await;
                    super::TestOutcome::new("A", ok, format!("{conn_resp:?}"))
                })
            }),
        },
        // XCONN.parent_child: A listens, AA connects.
        super::Test {
            suite: "xworker",
            group: "cross_worker_self_connect",
            id: "XCONN.parent_child".to_string(),
            xfail: None,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let port = 19911u16;
                    let listen_resp = r.send("A", Command::NetListen { port }).await;
                    if !matches!(&listen_resp, Response::Listening { .. }) {
                        return super::TestOutcome::new(
                            "AA",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let conn_resp = r
                        .send(
                            "AA",
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "parent_child".into(),
                            },
                        )
                        .await;
                    let ok = matches!(&conn_resp, Response::Connected { echo } if echo == "parent_child");
                    let _ = r.send("A", Command::NetUnlisten { port }).await;
                    super::TestOutcome::new("AA", ok, format!("{conn_resp:?}"))
                })
            }),
        },
        // XCONN.child_parent: AA listens, A connects.
        super::Test {
            suite: "xworker",
            group: "cross_worker_self_connect",
            id: "XCONN.child_parent".to_string(),
            xfail: None,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let port = 19912u16;
                    let listen_resp = r.send("AA", Command::NetListen { port }).await;
                    if !matches!(&listen_resp, Response::Listening { .. }) {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let conn_resp = r
                        .send(
                            "A",
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "child_parent".into(),
                            },
                        )
                        .await;
                    let ok = matches!(&conn_resp, Response::Connected { echo } if echo == "child_parent");
                    let _ = r.send("AA", Command::NetUnlisten { port }).await;
                    super::TestOutcome::new("A", ok, format!("{conn_resp:?}"))
                })
            }),
        },
        // XCONN.sibling_AB: A listens, AB connects.
        super::Test {
            suite: "xworker",
            group: "cross_worker_self_connect",
            id: "XCONN.sibling_AB".to_string(),
            xfail: None,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let port = 19913u16;
                    let listen_resp = r.send("A", Command::NetListen { port }).await;
                    if !matches!(&listen_resp, Response::Listening { .. }) {
                        return super::TestOutcome::new(
                            "AB",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let conn_resp = r
                        .send(
                            "AB",
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "sibling_connect".into(),
                            },
                        )
                        .await;
                    let ok = matches!(&conn_resp, Response::Connected { echo } if echo == "sibling_connect");
                    let _ = r.send("A", Command::NetUnlisten { port }).await;
                    super::TestOutcome::new("AB", ok, format!("{conn_resp:?}"))
                })
            }),
        },
    ]
}

// ═══════════════════════════════════════════════════════════════════
// BASH: bash fork+exec of child commands
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_bash_fork_exec_tests() -> Vec<super::Test> {
    let mut tests = Vec::new();
    for &agent in &["A", "B"] {
        let agent_s = agent.to_string();

        // BASH.fork_ls: bash -c running ls
        let a = agent_s.clone();
        tests.push(super::Test {
            suite: "fork",
            group: "bash_fork_exec",
            id: format!("BASH.fork_ls.{agent}"),
            xfail: None,
            run: Box::new(move |r| {
                let a = a.clone();
                Box::pin(async move {
                    let resp = r
                        .send(
                            &a,
                            super::exec(vec![
                                "bash".into(),
                                "-c".into(),
                                "ls / > /dev/null && echo LS_OK".into(),
                            ]),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("LS_OK")
                    );
                    super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                })
            }),
        });

        // BASH.fork_subst: bash -c with command substitution
        let a = agent_s.clone();
        tests.push(super::Test {
            suite: "fork",
            group: "bash_fork_exec",
            id: format!("BASH.fork_subst.{agent}"),
            xfail: None,
            run: Box::new(move |r| {
                let a = a.clone();
                Box::pin(async move {
                    let resp = r
                        .send(
                            &a,
                            super::exec(vec![
                                "bash".into(),
                                "-c".into(),
                                "echo HOST=$(cat /etc/hostname)".into(),
                            ]),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.starts_with("HOST=")
                    );
                    super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                })
            }),
        });

        // BASH.fork_bg_fg: bash -c with background + foreground
        let a = agent_s.clone();
        tests.push(super::Test {
            suite: "fork",
            group: "bash_fork_exec",
            id: format!("BASH.fork_bg_fg.{agent}"),
            xfail: None,
            run: Box::new(move |r| {
                let a = a.clone();
                Box::pin(async move {
                    let resp = r
                        .send(
                            &a,
                            super::exec(vec![
                                "bash".into(),
                                "-c".into(),
                                "sleep 0.1 & cat /etc/hostname > /dev/null; echo BG_FG_OK".into(),
                            ]),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("BG_FG_OK")
                    );
                    super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                })
            }),
        });
    }
    tests
}

// ═══════════════════════════════════════════════════════════════════
// FWE: fork+exec from non-PIE worker-exec hosts
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_fork_from_worker_exec_tests() -> Vec<super::Test> {
    vec![
        // FWE.nonpie_from_init: fork+exec nonpie from init worker (agent A)
        super::Test {
            suite: "fork",
            group: "fork_from_worker_exec",
            id: "FWE.nonpie_from_init".to_string(),
            xfail: None,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let nonpie = match crate::find_nonpie_binary() {
                        Some(p) => p,
                        None => {
                            return super::TestOutcome::new(
                                "A",
                                false,
                                "FAIL: nonpie binary not found — mount at /opt/nonpie".to_string(),
                            );
                        }
                    };
                    let resp = r
                        .send(
                            "A",
                            super::exec_timeout(
                                vec![
                                    self_exe,
                                    "fork-exec-nonpie".into(),
                                    nonpie,
                                    "echo-test".into(),
                                ],
                                20,
                            ),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("FORK_EXEC_NONPIE_OK")
                    );
                    super::TestOutcome::new("A", pass, format!("{resp:?}"))
                })
            }),
        },
        // FWE.pie_from_init: fork+exec PIE from init worker (agent A)
        super::Test {
            suite: "fork",
            group: "fork_from_worker_exec",
            id: "FWE.pie_from_init".to_string(),
            xfail: None,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let resp = r
                        .send(
                            "A",
                            super::exec_timeout(
                                vec![
                                    self_exe.clone(),
                                    "fork-exec-pie".into(),
                                    self_exe,
                                    "echo-test".into(),
                                ],
                                20,
                            ),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("FORK_EXEC_PIE_OK")
                    );
                    super::TestOutcome::new("A", pass, format!("{resp:?}"))
                })
            }),
        },
        // FWE.pie_from_worker_exec: fork+exec PIE from NP (worker-exec host)
        super::Test {
            suite: "fork",
            group: "fork_from_worker_exec",
            id: "FWE.pie_from_worker_exec".to_string(),
            xfail: None,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let nonpie = match crate::find_nonpie_binary() {
                        Some(p) => p,
                        None => {
                            return super::TestOutcome::new(
                                "NP",
                                false,
                                "FAIL: nonpie binary not found — mount at /opt/nonpie".to_string(),
                            );
                        }
                    };
                    let resp = r
                        .send(
                            "NP",
                            super::exec_timeout(
                                vec![nonpie, "fork-exec-pie".into(), self_exe, "echo-test".into()],
                                30,
                            ),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("FORK_EXEC_PIE_OK")
                    );
                    super::TestOutcome::new("NP", pass, format!("{resp:?}"))
                })
            }),
        },
        // FWE.nonpie_from_worker_exec: fork+exec nonpie from NP
        super::Test {
            suite: "fork",
            group: "fork_from_worker_exec",
            id: "FWE.nonpie_from_worker_exec".to_string(),
            xfail: None,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let nonpie = match crate::find_nonpie_binary() {
                        Some(p) => p,
                        None => {
                            return super::TestOutcome::new(
                                "NP",
                                false,
                                "FAIL: nonpie binary not found — mount at /opt/nonpie".to_string(),
                            );
                        }
                    };
                    let resp = r
                        .send(
                            "NP",
                            super::exec_timeout(
                                vec![
                                    nonpie.clone(),
                                    "fork-exec-nonpie".into(),
                                    nonpie,
                                    "echo-test".into(),
                                ],
                                30,
                            ),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("FORK_EXEC_NONPIE_OK")
                    );
                    super::TestOutcome::new("NP", pass, format!("{resp:?}"))
                })
            }),
        },
    ]
}

// ═══════════════════════════════════════════════════════════════════
// SP: stdin-pipe command substitution
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_stdin_pipe_subst_tests() -> Vec<super::Test> {
    struct Def {
        name: &'static str,
        script: &'static str,
        expected: &'static str,
    }
    let defs: &[Def] = &[
        Def {
            name: "simple",
            script: "X=$(echo hello)\necho R=$X\n",
            expected: "R=hello",
        },
        Def {
            name: "pipeline",
            script: "X=$(echo hello | cat)\necho R=$X\n",
            expected: "R=hello",
        },
        Def {
            name: "file_read",
            script: "X=$(head -1 /etc/passwd)\necho R=${X%%:*}\n",
            expected: "R=root",
        },
        Def {
            name: "file_pipe",
            script: "X=$(cat /etc/passwd | head -1)\necho R=${X%%:*}\n",
            expected: "R=root",
        },
        Def {
            name: "multi_subst",
            script: "A=$(echo first)\nB=$(echo second)\necho R=$A.$B\n",
            expected: "R=first.second",
        },
        Def {
            name: "os_detect",
            script: "ARCH=$(uname -m)\nPLATFORM=$(uname -s)\necho R=$ARCH.$PLATFORM\n",
            expected: "R=x86_64.Linux",
        },
    ];

    let mut tests = Vec::new();
    for &agent in AGENTS {
        for def in defs {
            let agent_s = agent.to_string();
            let script: String = def.script.into();
            let expected: String = def.expected.into();
            let name = def.name;
            tests.push(super::Test {
                suite: "shell",
                group: "stdin_pipe_subst",
                id: format!("SP.{name}.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = agent_s.clone();
                    let s = script.clone();
                    let exp = expected.clone();
                    Box::pin(async move {
                        let resp = r
                            .send(
                                &a,
                                Command::Exec {
                                    args: vec!["/bin/sh".into()],
                                    timeout_secs: Some(15),
                                    stdin: Some(s),
                                    background: false,
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if stdout.trim() == exp
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
    tests
}

// ═══════════════════════════════════════════════════════════════════
// CWF: Cross-worker file coherence
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_cross_worker_file_tests() -> Vec<super::Test> {
    let mut tests = Vec::new();
    for &agent in AGENTS {
        let agent_s = agent.to_string();

        // CWF.seq: child writes, exits, parent reads.
        {
            let a = agent_s.clone();
            tests.push(super::Test {
                suite: "xworker",
                group: "cross_worker_file",
                id: format!("CWF.seq.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = a.clone();
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let path = format!("/shared/cwf-seq-{a}.txt");
                        let resp = r
                            .send(
                                &a,
                                super::exec(vec![
                                    "bash".into(),
                                    "-c".into(),
                                    format!(
                                        "{} cross-worker-file write-and-exit {}",
                                        self_exe, path
                                    ),
                                ]),
                            )
                            .await;
                        if !matches!(&resp, Response::ExecResult { exit_code: 0, .. }) {
                            return super::TestOutcome::new(
                                &a,
                                false,
                                format!("write failed: {resp:?}"),
                            );
                        }
                        let resp = r.send(&a, Command::FsRead { path: path.clone() }).await;
                        let pass = matches!(
                            &resp,
                            Response::Ok { data: Some(d) } if d.starts_with("line0")
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // CWF.concurrent: child writes, closes fd, stays alive, parent reads.
        {
            let a = agent_s.clone();
            tests.push(super::Test {
                suite: "xworker",
                group: "cross_worker_file",
                id: format!("CWF.concurrent.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = a.clone();
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let path = format!("/shared/cwf-conc-{a}.txt");
                        let resp = r
                            .send(
                                &a,
                                Command::Exec {
                                    args: vec![
                                        self_exe,
                                        "cross-worker-file".into(),
                                        "write-and-sleep".into(),
                                        path.clone(),
                                    ],
                                    timeout_secs: None,
                                    stdin: None,
                                    background: true,
                                },
                            )
                            .await;
                        let bg_pid = match &resp {
                            Response::Background { pid } => Some(*pid),
                            _ => {
                                return super::TestOutcome::new(
                                    &a,
                                    false,
                                    format!("bg spawn failed: {resp:?}"),
                                );
                            }
                        };
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        let resp = r.send(&a, Command::FsRead { path: path.clone() }).await;
                        let pass = matches!(
                            &resp,
                            Response::Ok { data: Some(d) } if d.starts_with("line0")
                        );
                        if let Some(pid) = bg_pid {
                            let _ = r.send(&a, Command::Kill { pid }).await;
                        }
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // CWF.hold: child writes, keeps fd OPEN, parent reads.
        {
            let a = agent_s.clone();
            tests.push(super::Test {
                suite: "xworker",
                group: "cross_worker_file",
                id: format!("CWF.hold.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = a.clone();
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let path = format!("/shared/cwf-hold-{a}.txt");
                        let resp = r
                            .send(
                                &a,
                                Command::Exec {
                                    args: vec![
                                        self_exe,
                                        "cross-worker-file".into(),
                                        "write-and-hold".into(),
                                        path.clone(),
                                    ],
                                    timeout_secs: None,
                                    stdin: None,
                                    background: true,
                                },
                            )
                            .await;
                        let bg_pid = match &resp {
                            Response::Background { pid } => Some(*pid),
                            _ => {
                                return super::TestOutcome::new(
                                    &a,
                                    false,
                                    format!("bg spawn failed: {resp:?}"),
                                );
                            }
                        };
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        let resp = r.send(&a, Command::FsRead { path: path.clone() }).await;
                        let pass = matches!(
                            &resp,
                            Response::Ok { data: Some(d) } if d.starts_with("line0")
                        );
                        if let Some(pid) = bg_pid {
                            let _ = r.send(&a, Command::Kill { pid }).await;
                        }
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // CWF.self_open: child opens file itself (no inherited fd).
        {
            let a = agent_s.clone();
            tests.push(super::Test {
                suite: "xworker",
                group: "cross_worker_file",
                id: format!("CWF.self_open.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = a.clone();
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let path = format!("/shared/cwf-self-{a}.txt");
                        let script = format!(
                            concat!(
                                "rm -f {path}; ",
                                "{exe} cross-worker-file write-and-hold {path} &\n",
                                "BGPID=$!\nsleep 3\ncat {path}\n",
                                "kill $BGPID 2>/dev/null\n",
                            ),
                            path = path,
                            exe = self_exe,
                        );
                        let resp = r
                            .send(
                                &a,
                                Command::Exec {
                                    args: vec!["bash".into(), "-c".into(), script],
                                    timeout_secs: Some(15),
                                    stdin: None,
                                    background: false,
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if stdout.starts_with("line0")
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // CWF.redirect_stdout: bash `cmd > file &` pattern.
        {
            let a = agent_s.clone();
            tests.push(super::Test {
                suite: "xworker",
                group: "cross_worker_file",
                id: format!("CWF.redirect_stdout.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = a.clone();
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let path = format!("/shared/cwf-rstdout-{a}.txt");
                        let script = format!(
                            concat!(
                                "rm -f {path}; ",
                                "{exe} cross-worker-file write-stdout ",
                                "> {path} 2>&1 &\n",
                                "BGPID=$!\nsleep 3\ncat {path}\n",
                                "kill $BGPID 2>/dev/null\n",
                            ),
                            path = path,
                            exe = self_exe,
                        );
                        let resp = r
                            .send(
                                &a,
                                Command::Exec {
                                    args: vec!["bash".into(), "-c".into(), script],
                                    timeout_secs: Some(15),
                                    stdin: None,
                                    background: false,
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if stdout.contains("line0")
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // CWF.redirect_exit: child exits quickly, data becomes visible.
        {
            let a = agent_s.clone();
            tests.push(super::Test {
                suite: "xworker",
                group: "cross_worker_file",
                id: format!("CWF.redirect_exit.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = a.clone();
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let path = format!("/shared/cwf-rexit-{a}.txt");
                        let script = format!(
                            concat!(
                                "rm -f {path}; ",
                                "{exe} echo-test ",
                                "> {path} 2>&1\n",
                                "cat {path}\n",
                            ),
                            path = path,
                            exe = self_exe,
                        );
                        let resp = r
                            .send(
                                &a,
                                Command::Exec {
                                    args: vec!["bash".into(), "-c".into(), script],
                                    timeout_secs: Some(15),
                                    stdin: None,
                                    background: false,
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if stdout.contains("ECHO_TEST_OK")
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // CWF.builtin_redirect: shell builtin redirected to file.
        {
            let a = agent_s.clone();
            tests.push(super::Test {
                suite: "xworker",
                group: "cross_worker_file",
                id: format!("CWF.builtin_redirect.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = a.clone();
                    Box::pin(async move {
                        let path = format!("/shared/cwf-builtin-{a}.txt");
                        let script = format!(
                            concat!(
                                "rm -f {path}; ",
                                "echo builtin-data > {path}\n",
                                "cat {path}\n",
                            ),
                            path = path,
                        );
                        let resp = r
                            .send(
                                &a,
                                Command::Exec {
                                    args: vec!["bash".into(), "-c".into(), script],
                                    timeout_secs: Some(10),
                                    stdin: None,
                                    background: false,
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if stdout.contains("builtin-data")
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
    tests
}

// ═══════════════════════════════════════════════════════════════════
// SC: $() command substitution capture
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_subst_capture_tests() -> Vec<super::Test> {
    struct Def {
        name: &'static str,
        script: &'static str,
        check: fn(&str) -> bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "echo",
            script: "X=$(echo hello); echo $X",
            check: |s| s.trim() == "hello",
        },
        Def {
            name: "cat",
            script: "X=$(cat /etc/hostname); echo $X",
            check: |s| !s.trim().is_empty(),
        },
        Def {
            name: "readlink",
            script: "X=$(readlink -f /usr/bin/bash); echo $X",
            check: |s| s.trim().contains("bash"),
        },
        Def {
            name: "dirname",
            script: "X=$(dirname /usr/bin/bash); echo $X",
            check: |s| s.trim() == "/usr/bin",
        },
        Def {
            name: "nested",
            script: "X=$(dirname $(readlink -f /usr/bin/bash)); echo $X",
            check: |s| !s.trim().is_empty() && s.trim() != "/",
        },
        Def {
            name: "vscode_root",
            script: concat!(
                "SCRIPT=$(which bash); ",
                "ROOT=$(dirname $(dirname $(readlink -f $SCRIPT))); ",
                "echo $ROOT",
            ),
            check: |s| !s.trim().is_empty() && s.trim() != "/" && s.trim() != "",
        },
        Def {
            name: "which",
            script: "X=$(which bash); echo $X",
            check: |s| s.trim().contains("bash"),
        },
        Def {
            name: "uname",
            script: "X=$(uname -m); echo $X",
            check: |s| s.trim() == "x86_64",
        },
    ];

    let mut tests = Vec::new();
    for &agent in AGENTS {
        for def in defs {
            let agent_s = agent.to_string();
            let script: String = def.script.into();
            let check = def.check;
            let name = def.name;
            tests.push(super::Test {
                suite: "shell",
                group: "subst_capture",
                id: format!("SC.{name}.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = agent_s.clone();
                    let s = script.clone();
                    Box::pin(async move {
                        let resp = r
                            .send(
                                &a,
                                Command::Exec {
                                    args: vec!["bash".into(), "-c".into(), s],
                                    timeout_secs: Some(10),
                                    stdin: None,
                                    background: false,
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if check(stdout)
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
    tests
}

// ═══════════════════════════════════════════════════════════════════
// CC: Concurrent fork/exec/pipe tests
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_concurrent_fork_tests() -> Vec<super::Test> {
    struct Def {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "echo",
            script_template: "echo $(echo hello) > {path}",
            check: |s| s.trim() == "hello",
        },
        Def {
            name: "fork_exec",
            script_template: "{exe} echo-test > {path} 2>&1",
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "pipe_capture",
            script_template: "echo $(echo data | cat) > {path}",
            check: |s| s.trim() == "data",
        },
        Def {
            name: "file_write",
            script_template: "echo agent-wrote-{agent} > {path}",
            check: |s| s.contains("agent-wrote-"),
        },
    ];

    let mut tests = Vec::new();
    for def in defs {
        for &agent in AGENTS {
            let agent_s = agent.to_string();
            let template: String = def.script_template.into();
            let check = def.check;
            let name = def.name;
            tests.push(super::Test {
                suite: "fork",
                group: "concurrent_fork",
                id: format!("CC.{name}.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = agent_s.clone();
                    let t = template.clone();
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let path = format!("/shared/cc-{name}-{a}.txt");
                        let script = t
                            .replace("{path}", &path)
                            .replace("{exe}", &self_exe)
                            .replace("{agent}", &a);
                        let resp = r
                            .send(
                                &a,
                                Command::Exec {
                                    args: vec!["bash".into(), "-c".into(), script],
                                    timeout_secs: None,
                                    stdin: None,
                                    background: true,
                                },
                            )
                            .await;
                        let pid = match &resp {
                            Response::Background { pid } => Some(*pid),
                            _ => None,
                        };
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        let resp = r.send(&a, Command::FsRead { path: path.clone() }).await;
                        let pass = matches!(
                            &resp,
                            Response::Ok { data: Some(d) } if check(d)
                        );
                        if let Some(pid) = pid {
                            let _ = r.send(&a, Command::Kill { pid }).await;
                        }
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
    tests
}

// ═══════════════════════════════════════════════════════════════════
// TR: Touch + redirect file coherence
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_touch_redirect_tests() -> Vec<super::Test> {
    struct Def {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "no_touch",
            script_template: concat!(
                "rm -f {path}; ",
                "{exe} echo-test > {path} 2>&1 &\n",
                "BGPID=$!\nsleep 2\ncat {path}\n",
                "kill $BGPID 2>/dev/null\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "touch",
            script_template: concat!(
                "rm -f {path}; touch {path}; ",
                "{exe} echo-test > {path} 2>&1 &\n",
                "BGPID=$!\nsleep 2\ncat {path}\n",
                "kill $BGPID 2>/dev/null\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "touch_chmod",
            script_template: concat!(
                "rm -f {path}; touch {path}; chmod 600 {path}; ",
                "{exe} echo-test > {path} 2>&1 &\n",
                "BGPID=$!\nsleep 2\ncat {path}\n",
                "kill $BGPID 2>/dev/null\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "echo_touch",
            script_template: concat!(
                "rm -f {path}; echo init > {path}; ",
                "{exe} echo-test > {path} 2>&1 &\n",
                "BGPID=$!\nsleep 2\ncat {path}\n",
                "kill $BGPID 2>/dev/null\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "builtin_touch",
            script_template: concat!(
                "rm -f {path}; touch {path}; chmod 600 {path}; ",
                "echo builtin-data > {path} &\n",
                "wait\ncat {path}\n",
            ),
            check: |s| s.contains("builtin-data"),
        },
    ];

    let mut tests = Vec::new();
    for &agent in AGENTS {
        for def in defs {
            let agent_s = agent.to_string();
            let template: String = def.script_template.into();
            let check = def.check;
            let name = def.name;
            tests.push(super::Test {
                suite: "shell",
                group: "touch_redirect",
                id: format!("TR.{name}.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = agent_s.clone();
                    let t = template.clone();
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let path = format!("/shared/tr-{name}-{a}.txt");
                        let script = t.replace("{path}", &path).replace("{exe}", &self_exe);
                        let resp = r
                            .send(
                                &a,
                                Command::Exec {
                                    args: vec!["bash".into(), "-c".into(), script],
                                    timeout_secs: Some(10),
                                    stdin: None,
                                    background: false,
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if check(stdout)
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
    tests
}

// ═══════════════════════════════════════════════════════════════════
// KP: PID and /proc visibility across delayed-fork migration
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_pid_visibility_tests() -> Vec<super::Test> {
    struct Def {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "kill0_bg",
            script_template: concat!(
                "{exe} slow-echo > /dev/null 2>&1 &\n",
                "PID=$!\n",
                "kill -0 $PID 2>/dev/null && echo KILL0_OK || echo KILL0_FAIL\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("KILL0_OK"),
        },
        Def {
            name: "kill0_many",
            script_template: concat!(
                "A=$(cat /etc/os-release | head -1)\n",
                "B=$(uname -m)\n",
                "C=$(ls /tmp | head -1)\n",
                "D=$(echo x | cat)\n",
                "{exe} slow-echo > /dev/null 2>&1 &\n",
                "PID=$!\n",
                "kill -0 $PID 2>/dev/null && echo KILL0_OK || echo KILL0_FAIL\n",
                "sleep 1\n",
                "kill -0 $PID 2>/dev/null && echo KILL0_1s_OK || echo KILL0_1s_FAIL\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("KILL0_OK") && s.contains("KILL0_1s_OK"),
        },
        Def {
            name: "proc_child",
            script_template: concat!(
                "{exe} slow-echo > /dev/null 2>&1 &\n",
                "PID=$!\n",
                "sleep 1\n",
                "test -d /proc/$PID && echo PROC_DIR_OK || echo PROC_DIR_FAIL\n",
                "cat /proc/$PID/cmdline 2>/dev/null | tr '\\0' ' ' | ",
                "grep -q litebox_test_harness && echo CMDLINE_OK || echo CMDLINE_FAIL\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("PROC_DIR_OK") && s.contains("CMDLINE_OK"),
        },
        Def {
            name: "proc_self",
            script_template: concat!(
                "{exe} proc-probe > /tmp/proc-self.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/proc-self.txt\n",
            ),
            check: |s| {
                s.contains("self=true")
                    && s.contains("self_cmdline=true")
                    && s.contains("own_proc=true")
                    && s.contains("own_cmdline=true")
            },
        },
        Def {
            name: "ppid_proc",
            script_template: concat!(
                "{exe} proc-probe > /tmp/ppid-proc.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-proc.txt\n",
            ),
            check: |s| s.contains("ppid_proc=true"),
        },
        Def {
            name: "ppid_kill0",
            script_template: concat!(
                "{exe} proc-probe > /tmp/ppid-k0.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-k0.txt\n",
            ),
            check: |s| s.contains("ppid_kill0=true"),
        },
        Def {
            name: "ppid_cmdline",
            script_template: concat!(
                "{exe} proc-probe > /tmp/ppid-cl.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-cl.txt\n",
            ),
            check: |s| s.contains("ppid_cmdline=true"),
        },
        Def {
            name: "getppid_correct",
            script_template: concat!(
                "echo $$\n",
                "{exe} check-ppid > /tmp/ppid-val.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-val.txt\n",
            ),
            check: |s| {
                let lines: Vec<&str> = s.lines().collect();
                if lines.len() < 2 {
                    return false;
                }
                let parent_pid = lines[0].trim();
                lines
                    .iter()
                    .any(|l| l.contains(&format!("ppid={parent_pid}")))
            },
        },
        Def {
            name: "parent_monitor",
            script_template: concat!(
                "{exe} proc-probe > /tmp/pmon.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/pmon.txt\n",
            ),
            check: |s| s.contains("ppid_proc=true") && s.contains("ppid_kill0=true"),
        },
    ];

    let mut tests = Vec::new();
    for &agent in AGENTS {
        for def in defs {
            let agent_s = agent.to_string();
            let template: String = def.script_template.into();
            let check = def.check;
            let name = def.name;
            tests.push(super::Test {
                suite: "fork",
                group: "pid_visibility",
                id: format!("KP.{name}.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = agent_s.clone();
                    let t = template.clone();
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let script = t.replace("{exe}", &self_exe);
                        let resp = r
                            .send(
                                &a,
                                Command::Exec {
                                    args: vec!["bash".into(), "-c".into(), script],
                                    timeout_secs: Some(15),
                                    stdin: None,
                                    background: false,
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if check(stdout)
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
    tests
}

// ═══════════════════════════════════════════════════════════════════
// FR: File-Redirect — stdout of background process → file
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_file_redirect_tests() -> Vec<super::Test> {
    struct Def {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "fg_redirect",
            script_template: concat!("echo FR_FG > {path}\n", "cat {path}\n"),
            check: |s| s.contains("FR_FG"),
        },
        Def {
            name: "bg_echo",
            script_template: concat!("echo FR_BGECHO > {path} &\n", "wait\n", "cat {path}\n"),
            check: |s| s.contains("FR_BGECHO"),
        },
        Def {
            name: "bg_exe",
            script_template: concat!("{exe} echo-test > {path} &\n", "wait\n", "cat {path}\n"),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "bg_cat_pipe",
            script_template: concat!("echo FR_PIPE | cat > {path} &\n", "wait\n", "cat {path}\n",),
            check: |s| s.contains("FR_PIPE"),
        },
        Def {
            name: "bg_append",
            script_template: concat!(
                "echo LINE1 > {path}\n",
                "echo LINE2 >> {path} &\n",
                "wait\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("LINE1") && s.contains("LINE2"),
        },
    ];

    let mut tests = Vec::new();
    for &agent in AGENTS {
        for def in defs {
            let agent_s = agent.to_string();
            let template: String = def.script_template.into();
            let check = def.check;
            let name = def.name;
            tests.push(super::Test {
                suite: "shell",
                group: "file_redirect",
                id: format!("FR.{name}.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = agent_s.clone();
                    let t = template.clone();
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let path = format!("/shared/fr-{name}-{a}.txt");
                        let script = t.replace("{path}", &path).replace("{exe}", &self_exe);
                        let resp = r
                            .send(
                                &a,
                                Command::Exec {
                                    args: vec!["bash".into(), "-c".into(), script],
                                    timeout_secs: Some(10),
                                    stdin: None,
                                    background: false,
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if check(stdout)
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
    tests
}

// ═══════════════════════════════════════════════════════════════════
// PN: Pipe Non-blocking
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_pipe_nonblock_tests() -> Vec<super::Test> {
    let mut tests = Vec::new();

    // Part 1: basic pipe non-blocking (single process)
    for &agent in AGENTS {
        for &(suffix, marker) in &[
            ("setfl", "PIPE_NB_SETFL=OK"),
            ("empty_eagain", "PIPE_NB_EMPTY=EAGAIN"),
            ("data", "PIPE_NB_DATA=OK"),
            ("eof", "PIPE_NB_EOF=OK"),
        ] {
            let agent_s = agent.to_string();
            let marker_s: String = marker.into();
            tests.push(super::Test {
                suite: "matrix",
                group: "pipe_nonblock",
                id: format!("PN.{agent}.{suffix}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = agent_s.clone();
                    let m = marker_s.clone();
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let resp = r
                            .send(
                                &a,
                                Command::Exec {
                                    args: vec![self_exe, "pipe-nonblock".into()],
                                    timeout_secs: Some(10),
                                    stdin: None,
                                    background: false,
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if stdout.contains(&*m)
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }

    // Part 2: cross-process pipe non-blocking (dropbear pattern)
    for &agent in DEPTH_AGENTS {
        for &(suffix, marker) in &[
            ("eagain", "PCHILD_INITIAL=EAGAIN"),
            ("data", "PCHILD_DATA=OK"),
            ("eof", "PCHILD_EOF=OK"),
        ] {
            let agent_s = agent.to_string();
            let marker_s: String = marker.into();
            tests.push(super::Test {
                suite: "matrix",
                group: "pipe_nonblock",
                id: format!("PN.child.{agent}.{suffix}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = agent_s.clone();
                    let m = marker_s.clone();
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let resp = r
                            .send(
                                &a,
                                Command::Exec {
                                    args: vec![self_exe, "pipe-child-nonblock".into()],
                                    timeout_secs: Some(10),
                                    stdin: None,
                                    background: false,
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if stdout.contains(&*m)
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }

    tests
}

// ═══════════════════════════════════════════════════════════════════
// EP: Epoll + Socket wakeup
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_epoll_socket_tests() -> Vec<super::Test> {
    let mut tests = Vec::new();
    for &variant in &["direct", "tokio"] {
        for &agent in AGENTS {
            let port: u16 = match (variant, agent) {
                ("direct", "A") => 19990,
                ("direct", "AA") => 19991,
                ("direct", _) => 19992,
                ("tokio", "A") => 19993,
                ("tokio", "AA") => 19994,
                _ => 19995,
            };

            // EP.{variant}.accept.{agent}
            {
                let agent_s = agent.to_string();
                let variant_s: String = variant.into();
                tests.push(super::Test {
                    suite: "matrix",
                    group: "epoll_socket",
                    id: format!("EP.{variant}.accept.{agent}"),
                    xfail: None,
                    run: Box::new(move |r| {
                        let a = agent_s.clone();
                        let v = variant_s.clone();
                        let self_exe = r.self_exe.clone();
                        Box::pin(async move {
                            let resp = r
                                .send(
                                    &a,
                                    Command::Exec {
                                        args: vec![
                                            self_exe,
                                            "epoll-socket".into(),
                                            port.to_string(),
                                            v,
                                        ],
                                        timeout_secs: Some(15),
                                        stdin: None,
                                        background: false,
                                    },
                                )
                                .await;
                            let pass = matches!(
                                &resp,
                                Response::ExecResult { stdout, .. }
                                    if stdout.contains("EPOLL_ACCEPT=") && !stdout.contains("TIMEOUT")
                            );
                            super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    }),
                });
            }

            // EP.{variant}.read.{agent}
            {
                let agent_s = agent.to_string();
                let variant_s: String = variant.into();
                tests.push(super::Test {
                    suite: "matrix",
                    group: "epoll_socket",
                    id: format!("EP.{variant}.read.{agent}"),
                    xfail: None,
                    run: Box::new(move |r| {
                        let a = agent_s.clone();
                        let v = variant_s.clone();
                        let self_exe = r.self_exe.clone();
                        Box::pin(async move {
                            let resp = r
                                .send(
                                    &a,
                                    Command::Exec {
                                        args: vec![
                                            self_exe,
                                            "epoll-socket".into(),
                                            port.to_string(),
                                            v,
                                        ],
                                        timeout_secs: Some(15),
                                        stdin: None,
                                        background: false,
                                    },
                                )
                                .await;
                            let pass = matches!(
                                &resp,
                                Response::ExecResult { stdout, .. }
                                    if stdout.contains("EPOLL_READ=OK")
                            );
                            super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    }),
                });
            }
        }
    }
    tests
}

// ═══════════════════════════════════════════════════════════════════
// LB: Loopback TCP across delayed-fork workers
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_loopback_tcp_tests() -> Vec<super::Test> {
    struct Def {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "same_worker",
            script_template: concat!(
                "{exe} tcp-echo 19876 &\n",
                "sleep 1\n",
                "REPLY=$(echo LB_SAME | nc -q1 127.0.0.1 19876 2>/dev/null)\n",
                "echo REPLY=$REPLY\n",
                "wait\n",
            ),
            check: |s| s.contains("REPLY=LB_SAME"),
        },
        Def {
            name: "localhost",
            script_template: concat!(
                "{exe} tcp-echo 19877 > /dev/null 2>&1 &\n",
                "PID=$!\nsleep 2\n",
                "REPLY=$(echo LB_LOCAL | nc -q1 127.0.0.1 19877 2>/dev/null)\n",
                "echo REPLY=$REPLY\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("REPLY=LB_LOCAL"),
        },
        Def {
            name: "any_to_local",
            script_template: concat!(
                "{exe} tcp-echo 19879 > /dev/null 2>&1 &\n",
                "PID=$!\nsleep 2\n",
                "REPLY=$(echo LB_ANY | nc -q1 127.0.0.1 19879 2>/dev/null)\n",
                "echo REPLY=$REPLY\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("REPLY=LB_ANY"),
        },
        Def {
            name: "busy_after_listen",
            script_template: concat!(
                "{exe} tcp-listen-busy 19880 3 > /dev/null 2>&1 &\n",
                "PID=$!\nsleep 1\n",
                "REPLY=$(echo LB_BUSY | nc -q5 -w10 127.0.0.1 19880 2>/dev/null)\n",
                "echo REPLY=$REPLY\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("REPLY=LB_BUSY"),
        },
        Def {
            name: "fast_close",
            script_template: concat!(
                "{exe} tcp-recv-all 19881 &\n",
                "PID=$!\nsleep 2\n",
                "echo LB_FAST | nc -q0 127.0.0.1 19881 2>/dev/null\n",
                "sleep 2\n",
                "wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("RECV=LB_FAST"),
        },
        Def {
            name: "halfclose_eof",
            script_template: concat!(
                "{exe} tcp-recv-all 19882 &\n",
                "PID=$!\nsleep 2\n",
                "echo LB_HALF | nc -w2 127.0.0.1 19882 2>/dev/null\n",
                "sleep 3\n",
                "wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("RECV=LB_HALF"),
        },
    ];

    let mut tests = Vec::new();
    for &agent in AGENTS {
        for def in defs {
            let agent_s = agent.to_string();
            let template: String = def.script_template.into();
            let check = def.check;
            let name = def.name;
            tests.push(super::Test {
                suite: "matrix",
                group: "loopback_tcp",
                id: format!("LB.{name}.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = agent_s.clone();
                    let t = template.clone();
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let script = t.replace("{exe}", &self_exe);
                        let resp = r
                            .send(
                                &a,
                                Command::Exec {
                                    args: vec!["bash".into(), "-c".into(), script],
                                    timeout_secs: Some(15),
                                    stdin: None,
                                    background: false,
                                },
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { stdout, .. }
                                if check(stdout)
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
    tests
}

// ═══════════════════════════════════════════════════════════════════
// FKLC: fork-listen-close — VS Code CLI pattern
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_fork_listen_close_tests() -> Vec<super::Test> {
    vec![
        // FKLC.listen_unlisten: A listens then immediately unlistens,
        // B connects — should get RST.
        super::Test {
            suite: "xworker",
            group: "fork_listen_close",
            id: "FKLC.listen_unlisten".to_string(),
            xfail: None,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let port = 19920u16;
                    let listen_resp = r.send("A", Command::NetListen { port }).await;
                    if !matches!(&listen_resp, Response::Listening { .. }) {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let _ = r.send("A", Command::NetUnlisten { port }).await;
                    let conn_resp = r
                        .send(
                            "B",
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "listen_unlisten".into(),
                            },
                        )
                        .await;
                    let got_rst = matches!(&conn_resp, Response::ConnectFailed { .. });
                    super::TestOutcome::new("B", got_rst, format!("expected RST: {conn_resp:?}"))
                })
            }),
        },
        // FKLC.cross_connect: fd inheritance across fork+exec.
        // A spawns tcp-fork-listen-accept in bg, B connects.
        super::Test {
            suite: "xworker",
            group: "fork_listen_close",
            id: "FKLC.cross_connect".to_string(),
            xfail: None,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let port = 19921u16;
                    let bg_resp = r
                        .send(
                            "A",
                            Command::Exec {
                                args: vec![
                                    self_exe,
                                    "tcp-fork-listen-accept".into(),
                                    port.to_string(),
                                ],
                                timeout_secs: None,
                                stdin: None,
                                background: true,
                            },
                        )
                        .await;
                    let bg_pid = match &bg_resp {
                        Response::Background { pid } => Some(*pid),
                        _ => {
                            return super::TestOutcome::new(
                                "B",
                                false,
                                format!("bg spawn failed: {bg_resp:?}"),
                            );
                        }
                    };
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    let conn_resp = r
                        .send(
                            "B",
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "fork_listen_close".into(),
                            },
                        )
                        .await;
                    let pass = matches!(
                        &conn_resp,
                        Response::Connected { echo } if echo == "fork_listen_close"
                    );
                    if let Some(pid) = bg_pid {
                        let _ = r.send("A", Command::Kill { pid }).await;
                    }
                    super::TestOutcome::new("B", pass, format!("{conn_resp:?}"))
                })
            }),
        },
    ]
}

// ═══════════════════════════════════════════════════════════════════
// PROC: /proc filesystem tests
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_proc_filesystem_tests() -> Vec<super::Test> {
    let mut tests = Vec::new();
    for &agent in AGENTS {
        let agent_s = agent.to_string();

        // PROC.self_stat: /proc/self/stat is readable.
        {
            let a = agent_s.clone();
            tests.push(super::Test {
                suite: "matrix",
                group: "proc_filesystem",
                id: format!("PROC.self_stat.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = a.clone();
                    Box::pin(async move {
                        let resp = r
                            .send(
                                &a,
                                Command::FsRead {
                                    path: "/proc/self/stat".into(),
                                },
                            )
                            .await;
                        let pass =
                            matches!(&resp, Response::Ok { data: Some(d) } if d.contains(") "));
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // PROC.stat_seekable: /proc/self/stat is seekable (lseek).
        {
            let a = agent_s.clone();
            tests.push(super::Test {
                suite: "matrix",
                group: "proc_filesystem",
                id: format!("PROC.stat_seekable.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = a.clone();
                    Box::pin(async move {
                        let resp = r
                            .send(
                                &a,
                                super::exec(vec![
                                    "sh".into(),
                                    "-c".into(),
                                    "dd if=/proc/self/stat bs=1 skip=0 count=10 2>/dev/null | wc -c"
                                        .into(),
                                ]),
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.trim().parse::<u32>().unwrap_or(0) > 0
                        );
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }

        // PROC.uptime: /proc/uptime is readable.
        {
            let a = agent_s.clone();
            tests.push(super::Test {
                suite: "matrix",
                group: "proc_filesystem",
                id: format!("PROC.uptime.{agent}"),
                xfail: None,
                run: Box::new(move |r| {
                    let a = a.clone();
                    Box::pin(async move {
                        let resp = r
                            .send(
                                &a,
                                Command::FsRead {
                                    path: "/proc/uptime".into(),
                                },
                            )
                            .await;
                        let pass = matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty());
                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
    tests
}
