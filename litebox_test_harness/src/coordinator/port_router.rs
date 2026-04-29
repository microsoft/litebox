// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PR (Port Router) tests — verify that TCP port registrations survive
//! fork/exec of child processes.
//!
//! These tests exercise the pattern from the VS Code bootstrap:
//! a process listens on a TCP port, then forks child processes (which
//! inherit the listen socket fd), and the children exit. Connections
//! to the port must still succeed after the children die.
//!
//! The port router ownership fix (worker_id tracking) prevents a
//! re-registering child from deregistering the parent's route on exit.

use super::{TestRunner, exec};
use crate::protocol::{Command, Response};

// ═══════════════════════════════════════════════════════════════════
// PR.fork: port survives child fork+exit
// ═══════════════════════════════════════════════════════════════════

/// Start a TCP listener, exec a short-lived child (inherits the listen
/// socket), wait for the child to exit, then connect to the port.
/// Without the port router ownership fix, the child's death deregisters
/// the port and the connection fails.
pub(crate) async fn fork_port_tests(r: &mut TestRunner) {
    eprintln!("[pr] === PR.fork: port survives child fork+exit ===");

    for &agent in &["A", "B"] {
        let port = if agent == "A" { 18200 } else { 18201 };

        // Start echo server.
        let listen_resp = r.send(agent, Command::NetListen { port }).await;
        if !matches!(&listen_resp, Response::Listening { .. }) {
            r.record(
                &format!("PR.fork_single.{agent}"),
                agent,
                false,
                &format!("listen failed: {listen_resp:?}"),
            );
            continue;
        }

        // Exec a child that exits immediately. The child process inherits
        // the listening socket fd. In litebox, this creates a new worker
        // that registers the same port, then dies and deregisters it.
        let exec_resp = r
            .send(agent, exec(vec!["true".into()]))
            .await;
        let exec_ok = matches!(&exec_resp, Response::ExecResult { exit_code: 0, .. });
        r.record(
            &format!("PR.fork_exec.{agent}"),
            agent,
            exec_ok,
            &format!("{exec_resp:?}"),
        );

        // Connect AFTER the child has exited. This is the critical test:
        // the port route must still exist.
        let conn_resp = r
            .send(
                agent,
                Command::NetConnect {
                    addr: format!("127.0.0.1:{port}"),
                    data: "after_fork".into(),
                },
            )
            .await;
        let conn_ok = matches!(&conn_resp, Response::Connected { echo } if echo == "after_fork");
        r.record(
            &format!("PR.fork_single.{agent}"),
            agent,
            conn_ok,
            &format!("{conn_resp:?}"),
        );

        let _ = r.send(agent, Command::NetUnlisten { port }).await;
    }
}

/// Multiple sequential fork+exit cycles with a persistent listener.
/// Each child inherits the listen socket and dies. After all children
/// exit, the listener should still accept connections.
pub(crate) async fn fork_multi_tests(r: &mut TestRunner) {
    eprintln!("[pr] === PR.fork_multi: port survives N children ===");

    let agent = "A";
    let port = 18210;

    let listen_resp = r.send(agent, Command::NetListen { port }).await;
    if !matches!(&listen_resp, Response::Listening { .. }) {
        r.record(
            "PR.fork_multi_x5",
            agent,
            false,
            &format!("listen failed: {listen_resp:?}"),
        );
        return;
    }

    // Spawn 5 sequential children that each exit immediately.
    for i in 0..5 {
        let resp = r
            .send(agent, exec(vec!["true".into()]))
            .await;
        if !matches!(&resp, Response::ExecResult { exit_code: 0, .. }) {
            r.record(
                "PR.fork_multi_x5",
                agent,
                false,
                &format!("child {i} failed: {resp:?}"),
            );
            let _ = r.send(agent, Command::NetUnlisten { port }).await;
            return;
        }
    }

    // Connect after all 5 children have exited.
    let conn_resp = r
        .send(
            agent,
            Command::NetConnect {
                addr: format!("127.0.0.1:{port}"),
                data: "after_5_forks".into(),
            },
        )
        .await;
    let conn_ok =
        matches!(&conn_resp, Response::Connected { echo } if echo == "after_5_forks");
    r.record(
        "PR.fork_multi_x5",
        agent,
        conn_ok,
        &format!("{conn_resp:?}"),
    );

    let _ = r.send(agent, Command::NetUnlisten { port }).await;
}

/// Cross-agent: listener on A, fork children on A, connect from B.
/// The cross-worker TCP bridge routing must survive the child deaths.
pub(crate) async fn fork_cross_tests(r: &mut TestRunner) {
    eprintln!("[pr] === PR.fork_cross: cross-agent after fork ===");

    let listener = "A";
    let connector = "B";
    let port = 18220;

    let listen_resp = r.send(listener, Command::NetListen { port }).await;
    if !matches!(&listen_resp, Response::Listening { .. }) {
        r.record(
            "PR.fork_cross",
            connector,
            false,
            &format!("listen on {listener} failed: {listen_resp:?}"),
        );
        return;
    }

    // Exec children on the listener agent to trigger port re-registration.
    for _ in 0..3 {
        let _ = r.send(listener, exec(vec!["true".into()])).await;
    }

    // Connect from a different agent (cross-worker TCP pair).
    let conn_resp = r
        .send(
            connector,
            Command::NetConnect {
                addr: format!("127.0.0.1:{port}"),
                data: "cross_after_fork".into(),
            },
        )
        .await;
    let conn_ok =
        matches!(&conn_resp, Response::Connected { echo } if echo == "cross_after_fork");
    r.record(
        "PR.fork_cross",
        connector,
        conn_ok,
        &format!("{conn_resp:?}"),
    );

    let _ = r.send(listener, Command::NetUnlisten { port }).await;
}

/// Interleaved: connect before fork, fork child, connect after fork.
/// Both connections should succeed.
pub(crate) async fn fork_interleave_tests(r: &mut TestRunner) {
    eprintln!("[pr] === PR.fork_interleave: connect before and after fork ===");

    let agent = "A";
    let port = 18230;

    let listen_resp = r.send(agent, Command::NetListen { port }).await;
    if !matches!(&listen_resp, Response::Listening { .. }) {
        r.record(
            "PR.fork_interleave",
            agent,
            false,
            &format!("listen failed: {listen_resp:?}"),
        );
        return;
    }

    // Connect BEFORE fork.
    let pre = r
        .send(
            agent,
            Command::NetConnect {
                addr: format!("127.0.0.1:{port}"),
                data: "pre_fork".into(),
            },
        )
        .await;
    let pre_ok = matches!(&pre, Response::Connected { echo } if echo == "pre_fork");

    // Fork a child.
    let _ = r.send(agent, exec(vec!["true".into()])).await;

    // Connect AFTER fork.
    let post = r
        .send(
            agent,
            Command::NetConnect {
                addr: format!("127.0.0.1:{port}"),
                data: "post_fork".into(),
            },
        )
        .await;
    let post_ok = matches!(&post, Response::Connected { echo } if echo == "post_fork");

    r.record(
        "PR.fork_interleave",
        agent,
        pre_ok && post_ok,
        &format!("pre={pre_ok} post={post_ok} pre_detail={pre:?} post_detail={post:?}"),
    );

    let _ = r.send(agent, Command::NetUnlisten { port }).await;
}

/// Background process: start listener, spawn background child that runs
/// longer (like VS Code CLI), exec short-lived children, then connect.
/// Simulates the VS Code bootstrap pattern.
pub(crate) async fn fork_background_tests(r: &mut TestRunner) {
    eprintln!("[pr] === PR.fork_bg: background process + short children ===");

    let agent = "A";
    let port = 18240;

    let listen_resp = r.send(agent, Command::NetListen { port }).await;
    if !matches!(&listen_resp, Response::Listening { .. }) {
        r.record(
            "PR.fork_bg",
            agent,
            false,
            &format!("listen failed: {listen_resp:?}"),
        );
        return;
    }

    // Start a background process (simulates VS Code CLI).
    // "sleep 30" runs for 30s in background — long enough for the test.
    let bg_resp = r
        .send(
            agent,
            Command::Exec {
                args: vec!["sleep".into(), "30".into()],
                timeout_secs: None,
                stdin: None,
                background: true,
            },
        )
        .await;
    let bg_ok = matches!(&bg_resp, Response::Background { .. });
    let bg_pid = match &bg_resp {
        Response::Background { pid } => Some(*pid),
        _ => None,
    };

    // Exec short-lived children (simulates bootstrap script subcommands).
    for _ in 0..3 {
        let _ = r.send(agent, exec(vec!["true".into()])).await;
    }

    // Connect after children died — should still work.
    let conn_resp = r
        .send(
            agent,
            Command::NetConnect {
                addr: format!("127.0.0.1:{port}"),
                data: "after_bg_fork".into(),
            },
        )
        .await;
    let conn_ok =
        matches!(&conn_resp, Response::Connected { echo } if echo == "after_bg_fork");
    r.record(
        "PR.fork_bg",
        agent,
        bg_ok && conn_ok,
        &format!("bg={bg_ok} conn={conn_ok} conn_detail={conn_resp:?}"),
    );

    // Clean up background process.
    if let Some(pid) = bg_pid {
        let _ = r.send(agent, Command::Kill { pid }).await;
    }
    let _ = r.send(agent, Command::NetUnlisten { port }).await;
}

/// Run all PR tests.
pub(crate) async fn run(r: &mut TestRunner) {
    fork_port_tests(r).await;
    fork_multi_tests(r).await;
    fork_cross_tests(r).await;
    fork_interleave_tests(r).await;
    fork_background_tests(r).await;
    fork_listen_inherit_tests(r).await;
    child_listen_cross_connect_tests(r).await;
    vscode_cli_cross_connect_tests(r).await;
}

// ═══════════════════════════════════════════════════════════════════
// PR.listen_inherit: reproduces VS Code exec server failure
// ═══════════════════════════════════════════════════════════════════

/// Exact reproduction of the VS Code bootstrap failure:
/// 1. Parent process calls listen() on a port
/// 2. Parent forks a child that INHERITS the listen socket fd
/// 3. The child's litebox worker re-registers the port with the broker
/// 4. Child exits → child worker dies → port route deregistered
/// 5. Cross-worker connection to the port fails (SynSent → Closed)
///
/// Reproduces the VS Code bootstrap pattern using protocol primitives:
///   1. Agent A calls NetListen (bind+listen on port)
///   2. Agent A forks a child agent (Fork, binary=self or nonpie)
///   3. The child does network activity (NetListen on a different port)
///   4. The child exits
///   5. Agent A verifies the original listen port still works
///   6. Same-worker and cross-worker connections are tested
///
/// Previously this used the compound `tcp-listen-fork` subcommand via Exec.
/// Now uses Fork + NetListen + NetConnect primitives for transparency.
pub(crate) async fn fork_listen_inherit_tests(r: &mut TestRunner) {
    eprintln!("[pr] === PR.listen_inherit: VS Code fork reproduction (primitives) ===");

    let port = 18300u16;
    let child_port = port + 100; // child listens on a different port

    // Step 1: Agent A listens on the main port.
    let resp = r.send("A", Command::NetListen { port }).await;
    let listen_ok = matches!(&resp, Response::Listening { .. });
    if !listen_ok {
        r.record(
            "PR.listen_inherit_self",
            "A",
            false,
            &format!("listen failed: {resp:?}"),
        );
        return;
    }

    // Step 2: Fork a child agent from A. The child is a new agent process
    // that will do network activity then exit.
    let resp = r
        .send(
            "A",
            Command::Fork {
                name: "LI_C".to_string(),
                binary: "self".to_string(),
                inherit_listen_ports: vec![],
            },
        )
        .await;
    let fork_ok = matches!(&resp, Response::Ok { .. });
    if !fork_ok {
        r.record(
            "PR.listen_inherit_self",
            "A",
            false,
            &format!("fork failed: {resp:?}"),
        );
        let _ = r.send("A", Command::NetUnlisten { port }).await;
        return;
    }

    // Step 3: Child does network activity (listen on a different port),
    // then we shut it down. This exercises the port router's handling
    // of the child's network stack init.
    let resp = r
        .send(
            "A",
            Command::Forward {
                target: "LI_C".to_string(),
                inner: Box::new(Command::NetListen {
                    port: child_port,
                }),
            },
        )
        .await;
    // Whether child listen succeeds or not, continue.
    let _ = &resp;

    // Step 4: Shut down the child.
    let _ = r
        .send(
            "A",
            Command::Forward {
                target: "LI_C".to_string(),
                inner: Box::new(Command::NetUnlisten {
                    port: child_port,
                }),
            },
        )
        .await;
    let _ = r
        .send(
            "A",
            Command::Forward {
                target: "LI_C".to_string(),
                inner: Box::new(Command::Exit),
            },
        )
        .await;

    // Brief pause for cleanup.
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Step 5: Same-worker connection — verify the parent's listener survives.
    let conn_resp = r
        .send(
            "A",
            Command::NetConnect {
                addr: format!("127.0.0.1:{port}"),
                data: "inherit_self".into(),
            },
        )
        .await;
    let self_ok =
        matches!(&conn_resp, Response::Connected { echo } if echo == "inherit_self");
    r.record(
        "PR.listen_inherit_self",
        "A",
        self_ok,
        &format!("{conn_resp:?}"),
    );

    let _ = r.send("A", Command::NetUnlisten { port }).await;

    // Step 6: Cross-worker connection — same pattern but connect from B.
    let port2 = port + 1;
    let child_port2 = port2 + 100;

    let resp = r.send("A", Command::NetListen { port: port2 }).await;
    if !matches!(&resp, Response::Listening { .. }) {
        r.record(
            "PR.listen_inherit_cross",
            "B",
            false,
            &format!("listen2 failed: {resp:?}"),
        );
        return;
    }

    let resp = r
        .send(
            "A",
            Command::Fork {
                name: "LI_C2".to_string(),
                binary: "self".to_string(),
                inherit_listen_ports: vec![],
            },
        )
        .await;
    if !matches!(&resp, Response::Ok { .. }) {
        r.record(
            "PR.listen_inherit_cross",
            "B",
            false,
            &format!("fork2 failed: {resp:?}"),
        );
        let _ = r.send("A", Command::NetUnlisten { port: port2 }).await;
        return;
    }

    let _ = r
        .send(
            "A",
            Command::Forward {
                target: "LI_C2".to_string(),
                inner: Box::new(Command::NetListen {
                    port: child_port2,
                }),
            },
        )
        .await;
    let _ = r
        .send(
            "A",
            Command::Forward {
                target: "LI_C2".to_string(),
                inner: Box::new(Command::NetUnlisten {
                    port: child_port2,
                }),
            },
        )
        .await;
    let _ = r
        .send(
            "A",
            Command::Forward {
                target: "LI_C2".to_string(),
                inner: Box::new(Command::Exit),
            },
        )
        .await;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let conn_resp = r
        .send(
            "B",
            Command::NetConnect {
                addr: format!("127.0.0.1:{port2}"),
                data: "inherit_cross".into(),
            },
        )
        .await;
    let cross_ok =
        matches!(&conn_resp, Response::Connected { echo } if echo == "inherit_cross");
    r.record(
        "PR.listen_inherit_cross",
        "B",
        cross_ok,
        &format!("{conn_resp:?}"),
    );

    let _ = r.send("A", Command::NetUnlisten { port: port2 }).await;
}

// ═══════════════════════════════════════════════════════════════════
// PR.child_listen: child process calls listen(), cross-worker connect
// ═══════════════════════════════════════════════════════════════════

/// Reproduces the VS Code exec server failure using protocol primitives:
///   1. Agent A forks a child (non-PIE → separate worker in litebox)
///   2. Child calls NetListen immediately
///   3. Agent B connects to the child's port (cross-worker TCP bridge)
///
/// Previously used the `tcp-echo` subcommand via background Exec.
/// Now uses Fork + NetListen + NetConnect primitives.
pub(crate) async fn child_listen_cross_connect_tests(r: &mut TestRunner) {
    eprintln!("[pr] === PR.child_listen: child calls listen, cross-worker connect (primitives) ===");

    let port = 18500u16;

    // Fork a non-PIE child from A (forces separate worker in litebox).
    let resp = r
        .send(
            "A",
            Command::Fork {
                name: "CL_C".to_string(),
                binary: "nonpie".to_string(),
                inherit_listen_ports: vec![],
            },
        )
        .await;
    if !matches!(&resp, Response::Ok { .. }) {
        // Fall back to PIE if non-PIE not available.
        let resp = r
            .send(
                "A",
                Command::Fork {
                    name: "CL_C".to_string(),
                    binary: "self".to_string(),
                    inherit_listen_ports: vec![],
                },
            )
            .await;
        if !matches!(&resp, Response::Ok { .. }) {
            r.record(
                "PR.child_listen_cross",
                "B",
                false,
                &format!("fork failed: {resp:?}"),
            );
            return;
        }
    }

    // Child listens on the port immediately.
    let resp = r
        .send(
            "A",
            Command::Forward {
                target: "CL_C".to_string(),
                inner: Box::new(Command::NetListen { port }),
            },
        )
        .await;
    let listen_ok = matches!(&resp, Response::Listening { .. });
    if !listen_ok {
        r.record(
            "PR.child_listen_cross",
            "B",
            false,
            &format!("child listen failed: {resp:?}"),
        );
        return;
    }

    // Cross-worker connect from agent B.
    let conn_resp = r
        .send(
            "B",
            Command::NetConnect {
                addr: format!("127.0.0.1:{port}"),
                data: "child_listen_test".into(),
            },
        )
        .await;
    let cross_ok =
        matches!(&conn_resp, Response::Connected { echo } if echo == "child_listen_test");
    r.record(
        "PR.child_listen_cross",
        "B",
        cross_ok,
        &format!("{conn_resp:?}"),
    );

    // Clean up.
    let _ = r
        .send(
            "A",
            Command::Forward {
                target: "CL_C".to_string(),
                inner: Box::new(Command::NetUnlisten { port }),
            },
        )
        .await;
    let _ = r
        .send(
            "A",
            Command::Forward {
                target: "CL_C".to_string(),
                inner: Box::new(Command::Exit),
            },
        )
        .await;
}

// ═══════════════════════════════════════════════════════════════════
// PR.vscode_cli: actual VS Code CLI listen + cross-worker connect
// ═══════════════════════════════════════════════════════════════════

/// Reproduces the VS Code exec server connection failure using the
/// actual VS Code CLI binary (100MB, statically-linked musl).
///
/// The sequence mirrors the real VS Code Remote-SSH bootstrap:
///   1. Agent A background-exec's the CLI via bash
///   2. Coordinator waits for the CLI to start listening (~45s)
///   3. Agent A reads the port from the CLI's log
///   4. Agent B connects to the CLI's port (cross-worker TCP bridge)
///
/// Skipped if the VS Code CLI is not installed.
pub(crate) async fn vscode_cli_cross_connect_tests(r: &mut TestRunner) {
    eprintln!("[pr] === PR.vscode_cli: VS Code CLI listen + cross-worker connect ===");

    let resp = r
        .send(
            "A",
            super::exec_timeout(
                vec![
                    "bash".into(),
                    "-c".into(),
                    "if [ -x /root/.vscode-server/code ]; then \
                       /root/.vscode-server/code --version 2>/dev/null \
                       | grep -oP 'commit \\K[a-f0-9]{40}'; \
                     else echo MISSING; fi"
                        .into(),
                ],
                60,
            ),
        )
        .await;
    let commit = match &resp {
        Response::ExecResult {
            exit_code: 0,
            stdout,
            ..
        } if stdout.trim().len() == 40 => stdout.trim().to_string(),
        _ => {
            r.record(
                "PR.vscode_cli_cross",
                "B", false,                "FAIL: VS Code CLI not installed — use litebox-vscode image",
            );
            return;
        }
    };

    let start_cmd = format!(
        "LOG=/tmp/pr-cli.log; \
         /root/.vscode-server/code-{commit} command-shell \
           --cli-data-dir /root/.vscode-server/cli \
           --parent-process-id $$ \
           --on-host 0.0.0.0 > $LOG 2>&1 & \
         CLI_PID=$!; \
         for i in $(seq 1 60); do \
           PORT=$(grep -oP 'Listening on [^:]+:\\K[0-9]+' $LOG 2>/dev/null); \
           if [ -n \"$PORT\" ]; then echo PORT=$PORT; break; fi; \
           sleep 1; \
         done; \
         echo CLI_PID=$CLI_PID; \
         sleep 60"
    );
    let bg_resp = r
        .send(
            "A",
            Command::Exec {
                args: vec!["bash".into(), "-c".into(), start_cmd],
                timeout_secs: None,
                stdin: None,
                background: true,
            },
        )
        .await;
    let bg_pid = match &bg_resp {
        Response::Background { pid } => *pid,
        _ => {
            r.record(
                "PR.vscode_cli_cross",
                "B",
                false,
                &format!("bg spawn failed: {bg_resp:?}"),
            );
            return;
        }
    };

    tokio::time::sleep(tokio::time::Duration::from_secs(45)).await;

    let resp = r
        .send(
            "A",
            super::exec_timeout(
                vec![
                    "bash".into(),
                    "-c".into(),
                    "grep -oP 'Listening on [^:]+:\\K[0-9]+' /tmp/pr-cli.log 2>/dev/null \
                     || echo NONE"
                        .into(),
                ],
                5,
            ),
        )
        .await;
    let port: Option<u16> = match &resp {
        Response::ExecResult {
            exit_code: 0,
            stdout,
            ..
        } => stdout.trim().parse().ok(),
        _ => None,
    };
    let Some(port) = port else {
        r.record(
            "PR.vscode_cli_cross",
            "B",
            false,
            &format!("CLI didn't start: {resp:?}"),
        );
        let _ = r.send("A", Command::Kill { pid: bg_pid }).await;
        return;
    };

    let cmd = format!(
        "echo PROBE | nc -w5 127.0.0.1 {port} >/dev/null 2>&1; echo CONN=$?"
    );
    let conn_resp = r
        .send(
            "B",
            super::exec_timeout(vec!["bash".into(), "-c".into(), cmd], 10),
        )
        .await;
    let cross_ok = matches!(
        &conn_resp,
        Response::ExecResult { stdout, .. } if stdout.contains("CONN=0")
    );
    r.record(
        "PR.vscode_cli_cross",
        "B",
        cross_ok,
        &format!("{conn_resp:?}"),
    );

    let _ = r.send("A", Command::Kill { pid: bg_pid }).await;
}


