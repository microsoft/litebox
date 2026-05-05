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

// ═══════════════════════════════════════════════════════════════════
// PR.listen_inherit: reproduces VS Code exec server failure
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// PR.child_listen: child process calls listen(), cross-worker connect
// ═══════════════════════════════════════════════════════════════════

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
                timeout_secs: 180,
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
            timeout_secs: 180,
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
            timeout_secs: 180,
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
            timeout_secs: 180,
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
            timeout_secs: 180,
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
            timeout_secs: 180,
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
            timeout_secs: 180,
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
            timeout_secs: 180,
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
            timeout_secs: 180,
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
