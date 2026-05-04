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
        let exec_resp = r.send(agent, exec(vec!["true".into()])).await;
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
        let resp = r.send(agent, exec(vec!["true".into()])).await;
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
    let conn_ok = matches!(&conn_resp, Response::Connected { echo } if echo == "after_5_forks");
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
    let conn_ok = matches!(&conn_resp, Response::Connected { echo } if echo == "cross_after_fork");
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
    let conn_ok = matches!(&conn_resp, Response::Connected { echo } if echo == "after_bg_fork");
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
                inner: Box::new(Command::NetListen { port: child_port }),
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
                inner: Box::new(Command::NetUnlisten { port: child_port }),
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
    let self_ok = matches!(&conn_resp, Response::Connected { echo } if echo == "inherit_self");
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
                inner: Box::new(Command::NetListen { port: child_port2 }),
            },
        )
        .await;
    let _ = r
        .send(
            "A",
            Command::Forward {
                target: "LI_C2".to_string(),
                inner: Box::new(Command::NetUnlisten { port: child_port2 }),
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
    let cross_ok = matches!(&conn_resp, Response::Connected { echo } if echo == "inherit_cross");
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
    eprintln!(
        "[pr] === PR.child_listen: child calls listen, cross-worker connect (primitives) ==="
    );

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

pub(crate) fn register_port_router(tests: &mut Vec<super::Test>) {
    register_fork_port_tests(tests);
    register_fork_multi_tests(tests);
    register_fork_cross_tests(tests);
    register_fork_interleave_tests(tests);
    register_fork_background_tests(tests);
    register_fork_listen_inherit_tests(tests);
    register_child_listen_cross_connect_tests(tests);
}

fn register_fork_port_tests(tests: &mut Vec<super::Test>) {
    for &agent in &["A", "B"] {
        let port = if agent == "A" { 18200u16 } else { 18201u16 };
        let agent_s = agent.to_string();

        // PR.fork_exec.{agent}
        {
            let id = format!("PR.fork_exec.{agent}");
            let ag = agent_s.clone();
            tests.push(super::Test {
                suite: "stress",
                group: "port_router",
                id,
                xfail: None,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let listen_resp = r
                            .send(&ag, crate::protocol::Command::NetListen { port })
                            .await;
                        if !matches!(&listen_resp, crate::protocol::Response::Listening { .. }) {
                            return super::TestOutcome::new(
                                &ag,
                                false,
                                format!("listen failed: {listen_resp:?}"),
                            );
                        }
                        let exec_resp = r.send(&ag, super::exec(vec!["true".into()])).await;
                        let exec_ok = matches!(
                            &exec_resp,
                            crate::protocol::Response::ExecResult { exit_code: 0, .. }
                        );
                        let _ = r
                            .send(&ag, crate::protocol::Command::NetUnlisten { port })
                            .await;
                        super::TestOutcome::new(&ag, exec_ok, format!("{exec_resp:?}"))
                    })
                }),
            });
        }

        // PR.fork_single.{agent}
        {
            let id = format!("PR.fork_single.{agent}");
            let ag = agent_s.clone();
            tests.push(super::Test {
                suite: "stress",
                group: "port_router",
                id,
                xfail: None,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let listen_resp = r
                            .send(&ag, crate::protocol::Command::NetListen { port })
                            .await;
                        if !matches!(&listen_resp, crate::protocol::Response::Listening { .. }) {
                            return super::TestOutcome::new(
                                &ag,
                                false,
                                format!("listen failed: {listen_resp:?}"),
                            );
                        }
                        let _ = r
                            .send(&ag, super::exec(vec!["true".into()]))
                            .await;
                        let conn_resp = r
                            .send(
                                &ag,
                                crate::protocol::Command::NetConnect {
                                    addr: format!("127.0.0.1:{port}"),
                                    data: "after_fork".into(),
                                },
                            )
                            .await;
                        let conn_ok = matches!(&conn_resp, crate::protocol::Response::Connected { echo } if echo == "after_fork");
                        let _ = r
                            .send(&ag, crate::protocol::Command::NetUnlisten { port })
                            .await;
                        super::TestOutcome::new(&ag, conn_ok, format!("{conn_resp:?}"))
                    })
                }),
            });
        }
    }
}

fn register_fork_multi_tests(tests: &mut Vec<super::Test>) {
    let port = 18210u16;

    tests.push(super::Test {
        suite: "stress",
        group: "port_router",
        id: "PR.fork_multi_x5".to_string(),
        xfail: None,
        run: Box::new(move |r| {
            Box::pin(async move {
                let agent = "A";
                let listen_resp = r
                    .send(agent, crate::protocol::Command::NetListen { port })
                    .await;
                if !matches!(&listen_resp, crate::protocol::Response::Listening { .. }) {
                    return super::TestOutcome::new(
                        agent,
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                for i in 0..5 {
                    let resp = r.send(agent, super::exec(vec!["true".into()])).await;
                    if !matches!(&resp, crate::protocol::Response::ExecResult { exit_code: 0, .. })
                    {
                        let _ = r
                            .send(agent, crate::protocol::Command::NetUnlisten { port })
                            .await;
                        return super::TestOutcome::new(
                            agent,
                            false,
                            format!("child {i} failed: {resp:?}"),
                        );
                    }
                }
                let conn_resp = r
                    .send(
                        agent,
                        crate::protocol::Command::NetConnect {
                            addr: format!("127.0.0.1:{port}"),
                            data: "after_5_forks".into(),
                        },
                    )
                    .await;
                let conn_ok = matches!(&conn_resp, crate::protocol::Response::Connected { echo } if echo == "after_5_forks");
                let _ = r
                    .send(agent, crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new(agent, conn_ok, format!("{conn_resp:?}"))
            })
        }),
    });
}

fn register_fork_cross_tests(tests: &mut Vec<super::Test>) {
    let port = 18220u16;

    tests.push(super::Test {
        suite: "stress",
        group: "port_router",
        id: "PR.fork_cross".to_string(),
        xfail: None,
        run: Box::new(move |r| {
            Box::pin(async move {
                let listener = "A";
                let connector = "B";
                let listen_resp = r
                    .send(listener, crate::protocol::Command::NetListen { port })
                    .await;
                if !matches!(&listen_resp, crate::protocol::Response::Listening { .. }) {
                    return super::TestOutcome::new(
                        connector,
                        false,
                        format!("listen on {listener} failed: {listen_resp:?}"),
                    );
                }
                for _ in 0..3 {
                    let _ = r.send(listener, super::exec(vec!["true".into()])).await;
                }
                let conn_resp = r
                    .send(
                        connector,
                        crate::protocol::Command::NetConnect {
                            addr: format!("127.0.0.1:{port}"),
                            data: "cross_after_fork".into(),
                        },
                    )
                    .await;
                let conn_ok = matches!(&conn_resp, crate::protocol::Response::Connected { echo } if echo == "cross_after_fork");
                let _ = r
                    .send(listener, crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new(connector, conn_ok, format!("{conn_resp:?}"))
            })
        }),
    });
}

fn register_fork_interleave_tests(tests: &mut Vec<super::Test>) {
    let port = 18230u16;

    tests.push(super::Test {
        suite: "stress",
        group: "port_router",
        id: "PR.fork_interleave".to_string(),
        xfail: None,
        run: Box::new(move |r| {
            Box::pin(async move {
                let agent = "A";
                let listen_resp = r
                    .send(agent, crate::protocol::Command::NetListen { port })
                    .await;
                if !matches!(&listen_resp, crate::protocol::Response::Listening { .. }) {
                    return super::TestOutcome::new(
                        agent,
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let pre = r
                    .send(
                        agent,
                        crate::protocol::Command::NetConnect {
                            addr: format!("127.0.0.1:{port}"),
                            data: "pre_fork".into(),
                        },
                    )
                    .await;
                let pre_ok = matches!(&pre, crate::protocol::Response::Connected { echo } if echo == "pre_fork");
                let _ = r.send(agent, super::exec(vec!["true".into()])).await;
                let post = r
                    .send(
                        agent,
                        crate::protocol::Command::NetConnect {
                            addr: format!("127.0.0.1:{port}"),
                            data: "post_fork".into(),
                        },
                    )
                    .await;
                let post_ok = matches!(&post, crate::protocol::Response::Connected { echo } if echo == "post_fork");
                let _ = r
                    .send(agent, crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new(
                    agent,
                    pre_ok && post_ok,
                    format!("pre={pre_ok} post={post_ok} pre_detail={pre:?} post_detail={post:?}"),
                )
            })
        }),
    });
}

fn register_fork_background_tests(tests: &mut Vec<super::Test>) {
    let port = 18240u16;

    tests.push(super::Test {
        suite: "stress",
        group: "port_router",
        id: "PR.fork_bg".to_string(),
        xfail: None,
        run: Box::new(move |r| {
            Box::pin(async move {
                let agent = "A";
                let listen_resp = r
                    .send(agent, crate::protocol::Command::NetListen { port })
                    .await;
                if !matches!(&listen_resp, crate::protocol::Response::Listening { .. }) {
                    return super::TestOutcome::new(
                        agent,
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let bg_resp = r
                    .send(
                        agent,
                        crate::protocol::Command::Exec {
                            args: vec!["sleep".into(), "30".into()],
                            timeout_secs: None,
                            stdin: None,
                            background: true,
                        },
                    )
                    .await;
                let bg_ok = matches!(&bg_resp, crate::protocol::Response::Background { .. });
                let bg_pid = match &bg_resp {
                    crate::protocol::Response::Background { pid } => Some(*pid),
                    _ => None,
                };
                for _ in 0..3 {
                    let _ = r.send(agent, super::exec(vec!["true".into()])).await;
                }
                let conn_resp = r
                    .send(
                        agent,
                        crate::protocol::Command::NetConnect {
                            addr: format!("127.0.0.1:{port}"),
                            data: "after_bg_fork".into(),
                        },
                    )
                    .await;
                let conn_ok = matches!(&conn_resp, crate::protocol::Response::Connected { echo } if echo == "after_bg_fork");
                if let Some(pid) = bg_pid {
                    let _ = r
                        .send(agent, crate::protocol::Command::Kill { pid })
                        .await;
                }
                let _ = r
                    .send(agent, crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new(
                    agent,
                    bg_ok && conn_ok,
                    format!("bg={bg_ok} conn={conn_ok} conn_detail={conn_resp:?}"),
                )
            })
        }),
    });
}

fn register_fork_listen_inherit_tests(tests: &mut Vec<super::Test>) {
    // PR.listen_inherit_self
    tests.push(super::Test {
        suite: "stress",
        group: "port_router",
        id: "PR.listen_inherit_self".to_string(),
        xfail: None,
        run: Box::new(|r| {
            Box::pin(async move {
                let port = 18300u16;
                let child_port = port + 100;
                let resp = r
                    .send("A", crate::protocol::Command::NetListen { port })
                    .await;
                if !matches!(&resp, crate::protocol::Response::Listening { .. }) {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen failed: {resp:?}"),
                    );
                }
                let resp = r
                    .send(
                        "A",
                        crate::protocol::Command::Fork {
                            name: "LI_C".to_string(),
                            binary: "self".to_string(),
                            inherit_listen_ports: vec![],
                        },
                    )
                    .await;
                if !matches!(&resp, crate::protocol::Response::Ok { .. }) {
                    let _ = r
                        .send("A", crate::protocol::Command::NetUnlisten { port })
                        .await;
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("fork failed: {resp:?}"),
                    );
                }
                let _ = r
                    .send(
                        "A",
                        crate::protocol::Command::Forward {
                            target: "LI_C".to_string(),
                            inner: Box::new(crate::protocol::Command::NetListen {
                                port: child_port,
                            }),
                        },
                    )
                    .await;
                let _ = r
                    .send(
                        "A",
                        crate::protocol::Command::Forward {
                            target: "LI_C".to_string(),
                            inner: Box::new(crate::protocol::Command::NetUnlisten {
                                port: child_port,
                            }),
                        },
                    )
                    .await;
                let _ = r
                    .send(
                        "A",
                        crate::protocol::Command::Forward {
                            target: "LI_C".to_string(),
                            inner: Box::new(crate::protocol::Command::Exit),
                        },
                    )
                    .await;
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                let conn_resp = r
                    .send(
                        "A",
                        crate::protocol::Command::NetConnect {
                            addr: format!("127.0.0.1:{port}"),
                            data: "inherit_self".into(),
                        },
                    )
                    .await;
                let self_ok = matches!(&conn_resp, crate::protocol::Response::Connected { echo } if echo == "inherit_self");
                let _ = r
                    .send("A", crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new("A", self_ok, format!("{conn_resp:?}"))
            })
        }),
    });

    // PR.listen_inherit_cross
    tests.push(super::Test {
        suite: "stress",
        group: "port_router",
        id: "PR.listen_inherit_cross".to_string(),
        xfail: None,
        run: Box::new(|r| {
            Box::pin(async move {
                let port2 = 18301u16;
                let child_port2 = port2 + 100;
                let resp = r
                    .send("A", crate::protocol::Command::NetListen { port: port2 })
                    .await;
                if !matches!(&resp, crate::protocol::Response::Listening { .. }) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("listen2 failed: {resp:?}"),
                    );
                }
                let resp = r
                    .send(
                        "A",
                        crate::protocol::Command::Fork {
                            name: "LI_C2".to_string(),
                            binary: "self".to_string(),
                            inherit_listen_ports: vec![],
                        },
                    )
                    .await;
                if !matches!(&resp, crate::protocol::Response::Ok { .. }) {
                    let _ = r
                        .send("A", crate::protocol::Command::NetUnlisten { port: port2 })
                        .await;
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("fork2 failed: {resp:?}"),
                    );
                }
                let _ = r
                    .send(
                        "A",
                        crate::protocol::Command::Forward {
                            target: "LI_C2".to_string(),
                            inner: Box::new(crate::protocol::Command::NetListen {
                                port: child_port2,
                            }),
                        },
                    )
                    .await;
                let _ = r
                    .send(
                        "A",
                        crate::protocol::Command::Forward {
                            target: "LI_C2".to_string(),
                            inner: Box::new(crate::protocol::Command::NetUnlisten {
                                port: child_port2,
                            }),
                        },
                    )
                    .await;
                let _ = r
                    .send(
                        "A",
                        crate::protocol::Command::Forward {
                            target: "LI_C2".to_string(),
                            inner: Box::new(crate::protocol::Command::Exit),
                        },
                    )
                    .await;
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                let conn_resp = r
                    .send(
                        "B",
                        crate::protocol::Command::NetConnect {
                            addr: format!("127.0.0.1:{port2}"),
                            data: "inherit_cross".into(),
                        },
                    )
                    .await;
                let cross_ok = matches!(&conn_resp, crate::protocol::Response::Connected { echo } if echo == "inherit_cross");
                let _ = r
                    .send("A", crate::protocol::Command::NetUnlisten { port: port2 })
                    .await;
                super::TestOutcome::new("B", cross_ok, format!("{conn_resp:?}"))
            })
        }),
    });
}

fn register_child_listen_cross_connect_tests(tests: &mut Vec<super::Test>) {
    let port = 18500u16;

    tests.push(super::Test {
        suite: "stress",
        group: "port_router",
        id: "PR.child_listen_cross".to_string(),
        xfail: None,
        run: Box::new(move |r| {
            Box::pin(async move {
                let resp = r
                    .send(
                        "A",
                        crate::protocol::Command::Fork {
                            name: "CL_C".to_string(),
                            binary: "nonpie".to_string(),
                            inherit_listen_ports: vec![],
                        },
                    )
                    .await;
                let fork_ok = matches!(&resp, crate::protocol::Response::Ok { .. });
                if !fork_ok {
                    let resp = r
                        .send(
                            "A",
                            crate::protocol::Command::Fork {
                                name: "CL_C".to_string(),
                                binary: "self".to_string(),
                                inherit_listen_ports: vec![],
                            },
                        )
                        .await;
                    if !matches!(&resp, crate::protocol::Response::Ok { .. }) {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            format!("fork failed: {resp:?}"),
                        );
                    }
                }
                let resp = r
                    .send(
                        "A",
                        crate::protocol::Command::Forward {
                            target: "CL_C".to_string(),
                            inner: Box::new(crate::protocol::Command::NetListen { port }),
                        },
                    )
                    .await;
                if !matches!(&resp, crate::protocol::Response::Listening { .. }) {
                    return super::TestOutcome::new(
                        "B",
                        false,
                        format!("child listen failed: {resp:?}"),
                    );
                }
                let conn_resp = r
                    .send(
                        "B",
                        crate::protocol::Command::NetConnect {
                            addr: format!("127.0.0.1:{port}"),
                            data: "child_listen_test".into(),
                        },
                    )
                    .await;
                let cross_ok = matches!(&conn_resp, crate::protocol::Response::Connected { echo } if echo == "child_listen_test");
                let _ = r
                    .send(
                        "A",
                        crate::protocol::Command::Forward {
                            target: "CL_C".to_string(),
                            inner: Box::new(crate::protocol::Command::NetUnlisten { port }),
                        },
                    )
                    .await;
                let _ = r
                    .send(
                        "A",
                        crate::protocol::Command::Forward {
                            target: "CL_C".to_string(),
                            inner: Box::new(crate::protocol::Command::Exit),
                        },
                    )
                    .await;
                super::TestOutcome::new("B", cross_ok, format!("{conn_resp:?}"))
            })
        }),
    });
}
