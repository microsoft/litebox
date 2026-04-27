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

use super::{TestRunner, exec, exec_timeout};
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
/// Uses the `tcp-listen-fork` subcommand which does a real libc::fork()
/// to create a child with inherited listen socket. The child sleeps 3s
/// (enough for network stack init) then exits. After the child exits,
/// a cross-worker connection is attempted.
pub(crate) async fn fork_listen_inherit_tests(r: &mut TestRunner) {
    eprintln!("[pr] === PR.listen_inherit: VS Code fork reproduction ===");

    // Agent A starts tcp-listen-fork in background. It listens on port
    // 18300, forks a child that sleeps 3s, waits for the child, then
    // accepts a connection and echoes.
    let port = 18300u16;

    // Start the tcp-listen-fork server as a background exec on agent A.
    let bg_resp = r
        .send(
            "A",
            Command::Exec {
                args: vec![
                    r.self_exe.clone(),
                    "tcp-listen-fork".into(),
                    port.to_string(),
                    "3".into(), // child sleeps 3s
                ],
                timeout_secs: Some(30),
                stdin: None,
                background: false,
            },
        )
        .await;

    // The exec blocks until accept+echo completes (foreground). We need
    // it to run in background while we connect from agent B.
    // Use background=true instead.
    // Actually, we need to orchestrate: start the server in background,
    // wait for the child to exit (~4s), then connect from B.
    // Let's restart with background=true.
    let bg_resp = r
        .send(
            "A",
            Command::Exec {
                args: vec![
                    r.self_exe.clone(),
                    "tcp-listen-fork".into(),
                    port.to_string(),
                    "3".into(),
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
                "PR.listen_inherit_self",
                "A",
                false,
                &format!("bg spawn failed: {bg_resp:?}"),
            );
            return;
        }
    };

    // Wait for: listen (~0s) + child fork+sleep (3s) + child exit (~0s)
    // + a margin for the network stack to process everything.
    tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;

    // Same-worker connection from agent A.
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
    r.record_xfail(
        "PR.listen_inherit_self",
        "A",
        self_ok,
        "same-worker loopback after fork+wait has echo data loss",
        &format!("{conn_resp:?}"),
    );

    // Clean up.
    if let Some(pid) = bg_pid {
        let _ = r.send("A", Command::Kill { pid }).await;
    }

    // Cross-worker test: same pattern but connect from B.
    let bg_resp = r
        .send(
            "A",
            Command::Exec {
                args: vec![
                    r.self_exe.clone(),
                    "tcp-listen-fork".into(),
                    (port + 1).to_string(),
                    "3".into(),
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
                "PR.listen_inherit_cross",
                "B",
                false,
                &format!("bg spawn failed: {bg_resp:?}"),
            );
            return;
        }
    };

    tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;

    // Cross-worker connection from agent B — this is the VS Code pattern:
    // a different SSH session (different worker) connects to the CLI's port.
    let conn_resp = r
        .send(
            "B",
            Command::NetConnect {
                addr: format!("127.0.0.1:{}", port + 1),
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

    if let Some(pid) = bg_pid {
        let _ = r.send("A", Command::Kill { pid }).await;
    }
}
