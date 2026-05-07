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
//! The port router ownership fix (`worker_id` tracking) prevents a
//! re-registering child from deregistering the parent's route on exit.

use super::agents::{AgentName, SpawnKind};
use super::registry::Registry;
use crate::protocol::{Command, Response};

pub(crate) fn register_port_router(reg: &mut Registry<'_>) {
    register_fork_port_tests(reg);
    register_fork_multi_tests(reg);
    register_fork_cross_tests(reg);
    register_fork_interleave_tests(reg);
    register_fork_background_tests(reg);
    register_fork_listen_inherit_tests(reg);
    register_child_listen_cross_connect_tests(reg);
    register_depth_axis_tests(reg);
}

fn register_fork_port_tests(reg: &mut Registry<'_>) {
    for &agent in &[AgentName::A, AgentName::B] {
        let port = if agent == AgentName::A {
            18200u16
        } else {
            18201u16
        };

        // PR.fork_exec.{agent}
        {
            let id = format!("PR.fork_exec.{agent}");
            let agent_label = agent.to_string();
            reg.test("stress", "port_router", id)
                .timeout(180)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        Box::pin(async move {
                            let listen_resp = run.send(&handle, Command::NetListen { port }).await;
                            if !super::expect_listening_port(&listen_resp, port).is_ok() {
                                return super::TestOutcome::new(
                                    &agent_label,
                                    false,
                                    format!("listen failed: {listen_resp:?}"),
                                );
                            }
                            let exec_resp =
                                run.send(&handle, super::exec(vec!["true".into()])).await;
                            let exec_ok =
                                matches!(&exec_resp, Response::ExecResult { exit_code: 0, .. });
                            let _ = run.send(&handle, Command::NetUnlisten { port }).await;
                            super::TestOutcome::new(&agent_label, exec_ok, format!("{exec_resp:?}"))
                        })
                    })
                });
        }

        // PR.fork_single.{agent}
        {
            let id = format!("PR.fork_single.{agent}");
            let agent_label = agent.to_string();
            reg.test("stress", "port_router", id)
                .timeout(180)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        Box::pin(async move {
                            let listen_resp = run.send(&handle, Command::NetListen { port }).await;
                            if !super::expect_listening_port(&listen_resp, port).is_ok() {
                                return super::TestOutcome::new(
                                    &agent_label,
                                    false,
                                    format!("listen failed: {listen_resp:?}"),
                                );
                            }
                            let _ = run.send(&handle, super::exec(vec!["true".into()])).await;
                            let conn_resp = run
                                .send(
                                    &handle,
                                    Command::NetConnect {
                                        addr: format!("127.0.0.1:{port}"),
                                        data: "after_fork".into(),
                                    },
                                )
                                .await;
                            let conn_ok = matches!(&conn_resp, Response::Connected { echo } if echo == "after_fork");
                            let _ = run.send(&handle, Command::NetUnlisten { port }).await;
                            super::TestOutcome::new(&agent_label, conn_ok, format!("{conn_resp:?}"))
                        })
                    })
                });
        }
    }
}

fn register_fork_multi_tests(reg: &mut Registry<'_>) {
    let port = 18210u16;

    reg.test("stress", "port_router", "PR.fork_multi_x5")
        .timeout(180)
        .build(move |cx| {
            let handle_a = cx.require(AgentName::A);
            Box::new(move |run| {
                Box::pin(async move {
                    let agent = "A";
                    let listen_resp = run.send(&handle_a, Command::NetListen { port }).await;
                    if !super::expect_listening_port(&listen_resp, port).is_ok() {
                        return super::TestOutcome::new(
                            agent,
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    for i in 0..5 {
                        let resp = run
                            .send(&handle_a, super::exec(vec!["true".into()]))
                            .await;
                        if !matches!(&resp, Response::ExecResult { exit_code: 0, .. }) {
                            let _ = run.send(&handle_a, Command::NetUnlisten { port }).await;
                            return super::TestOutcome::new(
                                agent,
                                false,
                                format!("child {i} failed: {resp:?}"),
                            );
                        }
                    }
                    let conn_resp = run
                        .send(
                            &handle_a,
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "after_5_forks".into(),
                            },
                        )
                        .await;
                    let conn_ok = matches!(&conn_resp, Response::Connected { echo } if echo == "after_5_forks");
                    let _ = run.send(&handle_a, Command::NetUnlisten { port }).await;
                    super::TestOutcome::new(agent, conn_ok, format!("{conn_resp:?}"))
                })
            })
        });
}

fn register_fork_cross_tests(reg: &mut Registry<'_>) {
    let port = 18220u16;

    reg.test("stress", "port_router", "PR.fork_cross")
        .timeout(180)
        .build(move |cx| {
            let handle_a = cx.require(AgentName::A);
            let handle_b = cx.require(AgentName::B);
            Box::new(move |run| {
                Box::pin(async move {
                    let listener = "A";
                    let connector = "B";
                    let listen_resp = run.send(&handle_a, Command::NetListen { port }).await;
                    if !super::expect_listening_port(&listen_resp, port).is_ok() {
                        return super::TestOutcome::new(
                            connector,
                            false,
                            format!("listen on {listener} failed: {listen_resp:?}"),
                        );
                    }
                    for _ in 0..3 {
                        let _ = run
                            .send(&handle_a, super::exec(vec!["true".into()]))
                            .await;
                    }
                    let conn_resp = run
                        .send(
                            &handle_b,
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "cross_after_fork".into(),
                            },
                        )
                        .await;
                    let conn_ok = matches!(&conn_resp, Response::Connected { echo } if echo == "cross_after_fork");
                    let _ = run.send(&handle_a, Command::NetUnlisten { port }).await;
                    super::TestOutcome::new(connector, conn_ok, format!("{conn_resp:?}"))
                })
            })
        });
}

#[allow(clippy::similar_names)] // `post` vs `port`: distinct test fixture names.
fn register_fork_interleave_tests(reg: &mut Registry<'_>) {
    let port = 18230u16;

    reg.test("stress", "port_router", "PR.fork_interleave")
        .timeout(180)
        .build(move |cx| {
            let handle_a = cx.require(AgentName::A);
            Box::new(move |run| {
                Box::pin(async move {
                    let agent = "A";
                    let listen_resp = run.send(&handle_a, Command::NetListen { port }).await;
                    if !super::expect_listening_port(&listen_resp, port).is_ok() {
                        return super::TestOutcome::new(
                            agent,
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let pre = run
                        .send(
                            &handle_a,
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "pre_fork".into(),
                            },
                        )
                        .await;
                    let pre_ok = matches!(&pre, Response::Connected { echo } if echo == "pre_fork");
                    let _ = run.send(&handle_a, super::exec(vec!["true".into()])).await;
                    let post = run
                        .send(
                            &handle_a,
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "post_fork".into(),
                            },
                        )
                        .await;
                    let post_ok =
                        matches!(&post, Response::Connected { echo } if echo == "post_fork");
                    let _ = run.send(&handle_a, Command::NetUnlisten { port }).await;
                    super::TestOutcome::new(
                        agent,
                        pre_ok && post_ok,
                        format!(
                            "pre={pre_ok} post={post_ok} pre_detail={pre:?} post_detail={post:?}"
                        ),
                    )
                })
            })
        });
}

fn register_fork_background_tests(reg: &mut Registry<'_>) {
    let port = 18240u16;

    reg.test("stress", "port_router", "PR.fork_bg")
        .timeout(180)
        .build(move |cx| {
            let handle_a = cx.require(AgentName::A);
            Box::new(move |run| {
                Box::pin(async move {
                    let agent = "A";
                    let listen_resp = run.send(&handle_a, Command::NetListen { port }).await;
                    if !super::expect_listening_port(&listen_resp, port).is_ok() {
                        return super::TestOutcome::new(
                            agent,
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let bg_resp = run
                        .send(
                            &handle_a,
                            Command::Exec {
                                args: vec!["sleep".into(), "30".into()],
                                timeout_secs: None,
                                stdin: None,
                                background: true,
                                env: vec![],
                            },
                        )
                        .await;
                    let bg_ok = matches!(&bg_resp, Response::Background { .. });
                    let bg_pid = match &bg_resp {
                        Response::Background { pid } => Some(*pid),
                        _ => None,
                    };
                    for _ in 0..3 {
                        let _ = run
                            .send(&handle_a, super::exec(vec!["true".into()]))
                            .await;
                    }
                    let conn_resp = run
                        .send(
                            &handle_a,
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "after_bg_fork".into(),
                            },
                        )
                        .await;
                    let conn_ok = matches!(&conn_resp, Response::Connected { echo } if echo == "after_bg_fork");
                    if let Some(pid) = bg_pid {
                        let _ = run.send(&handle_a, Command::Kill { pid }).await;
                    }
                    let _ = run.send(&handle_a, Command::NetUnlisten { port }).await;
                    super::TestOutcome::new(
                        agent,
                        bg_ok && conn_ok,
                        format!("bg={bg_ok} conn={conn_ok} conn_detail={conn_resp:?}"),
                    )
                })
            })
        });
}

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
fn register_fork_listen_inherit_tests(reg: &mut Registry<'_>) {
    // PR.listen_inherit_self
    reg.test("stress", "port_router", "PR.listen_inherit_self")
        .timeout(180)
        .build(|cx| {
            let handle_a = cx.require(AgentName::A);
            let li_c = cx.declare_ephemeral(
                AgentName::A,
                "LI_C",
                SpawnKind::Fork {
                    binary: "self",
                    inherit_listen_ports: vec![],
                },
            );
            Box::new(move |run| {
                let li_c = li_c.clone();
                Box::pin(async move {
                    let port = 18300u16;
                    let child_port = port + 100;
                    let resp = run.send(&handle_a, Command::NetListen { port }).await;
                    if let Err(e) = super::expect_listening_port(&resp, port) {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            format!("listen failed: {e}; resp={resp:?}"),
                        );
                    }
                    let resp = run.spawn_ephemeral(&li_c).await;
                    if !super::ok_spawned_response(&resp) {
                        let _ = run.send(&handle_a, Command::NetUnlisten { port }).await;
                        return super::TestOutcome::new(
                            "A",
                            false,
                            format!("fork failed: {resp:?}"),
                        );
                    }
                    let _ = run
                        .forward(&li_c, Command::NetListen { port: child_port })
                        .await;
                    let _ = run
                        .forward(&li_c, Command::NetUnlisten { port: child_port })
                        .await;
                    let _ = run.forward(&li_c, Command::Exit).await;
                    let conn_resp = run
                        .send(
                            &handle_a,
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "inherit_self".into(),
                            },
                        )
                        .await;
                    let self_ok = matches!(&conn_resp, Response::Connected { echo } if echo == "inherit_self");
                    let _ = run.send(&handle_a, Command::NetUnlisten { port }).await;
                    super::TestOutcome::new("A", self_ok, format!("{conn_resp:?}"))
                })
            })
        });

    // PR.listen_inherit_cross
    reg.test("stress", "port_router", "PR.listen_inherit_cross")
        .timeout(180)
        .build(|cx| {
            let handle_a = cx.require(AgentName::A);
            let handle_b = cx.require(AgentName::B);
            let li_c2 = cx.declare_ephemeral(
                AgentName::A,
                "LI_C2",
                SpawnKind::Fork {
                    binary: "self",
                    inherit_listen_ports: vec![],
                },
            );
            Box::new(move |run| {
                let li_c2 = li_c2.clone();
                Box::pin(async move {
                    let port2 = 18301u16;
                    let child_port2 = port2 + 100;
                    let resp = run
                        .send(&handle_a, Command::NetListen { port: port2 })
                        .await;
                    if let Err(e) = super::expect_listening_port(&resp, port2) {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            format!("listen2 failed: {e}; resp={resp:?}"),
                        );
                    }
                    let resp = run.spawn_ephemeral(&li_c2).await;
                    if !super::ok_spawned_response(&resp) {
                        let _ = run
                            .send(&handle_a, Command::NetUnlisten { port: port2 })
                            .await;
                        return super::TestOutcome::new(
                            "B",
                            false,
                            format!("fork2 failed: {resp:?}"),
                        );
                    }
                    let _ = run
                        .forward(&li_c2, Command::NetListen { port: child_port2 })
                        .await;
                    let _ = run
                        .forward(&li_c2, Command::NetUnlisten { port: child_port2 })
                        .await;
                    let _ = run.forward(&li_c2, Command::Exit).await;
                    let conn_resp = run
                        .send(
                            &handle_b,
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port2}"),
                                data: "inherit_cross".into(),
                            },
                        )
                        .await;
                    let cross_ok = matches!(&conn_resp, Response::Connected { echo } if echo == "inherit_cross");
                    let _ = run
                        .send(&handle_a, Command::NetUnlisten { port: port2 })
                        .await;
                    super::TestOutcome::new("B", cross_ok, format!("{conn_resp:?}"))
                })
            })
        });
}

fn register_child_listen_cross_connect_tests(reg: &mut Registry<'_>) {
    let port = 18500u16;

    reg.test("stress", "port_router", "PR.child_listen_cross")
        .timeout(180)
        .build(move |cx| {
            let _handle_a = cx.require(AgentName::A);
            let handle_b = cx.require(AgentName::B);
            // Try CL_C as a non-PIE Fork first; fall back to PIE.
            // Both share the same wire label so forwarding works
            // regardless of which kind succeeded.
            let cl_c_nonpie = cx.declare_ephemeral(
                AgentName::A,
                "CL_C",
                SpawnKind::Fork {
                    binary: "nonpie",
                    inherit_listen_ports: vec![],
                },
            );
            let cl_c_pie = cx.declare_ephemeral(
                AgentName::A,
                "CL_C",
                SpawnKind::Fork {
                    binary: "self",
                    inherit_listen_ports: vec![],
                },
            );
            Box::new(move |run| {
                let cl_c_nonpie = cl_c_nonpie.clone();
                let cl_c_pie = cl_c_pie.clone();
                Box::pin(async move {
                    let resp = run.spawn_ephemeral(&cl_c_nonpie).await;
                    let cl_c = if super::ok_spawned_response(&resp) {
                        cl_c_nonpie
                    } else {
                        let resp = run.spawn_ephemeral(&cl_c_pie).await;
                        if !super::ok_spawned_response(&resp) {
                            return super::TestOutcome::new(
                                "B",
                                false,
                                format!("fork failed: {resp:?}"),
                            );
                        }
                        cl_c_pie
                    };
                    let resp = run
                        .forward(&cl_c, Command::NetListen { port })
                        .await;
                    if let Err(e) = super::expect_listening_port(&resp, port) {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            format!("child listen failed: {e}; resp={resp:?}"),
                        );
                    }
                    let conn_resp = run
                        .send(
                            &handle_b,
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "child_listen_test".into(),
                            },
                        )
                        .await;
                    let cross_ok = matches!(&conn_resp, Response::Connected { echo } if echo == "child_listen_test");
                    let _ = run
                        .forward(&cl_c, Command::NetUnlisten { port })
                        .await;
                    let _ = run.forward(&cl_c, Command::Exit).await;
                    super::TestOutcome::new("B", cross_ok, format!("{conn_resp:?}"))
                })
            })
        });
}

fn register_depth_axis_tests(reg: &mut Registry<'_>) {
    reg.test("stress", "port_router", "PR.fork_child_parent")
        .timeout(180)
        .build(|cx| {
            let parent = cx.require(AgentName::A);
            let child = cx.require(AgentName::AA);
            Box::new(move |run| {
                Box::pin(async move {
                    let port = 18510u16;
                    let listen_resp = run.send(&parent, Command::NetListen { port }).await;
                    if !matches!(&listen_resp, Response::Listening { port: p } if *p == port) {
                        return super::TestOutcome::new(
                            "AA->A",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let exec_resp = run.send(&parent, super::exec(vec!["true".into()])).await;
                    if !matches!(&exec_resp, Response::ExecResult { exit_code: 0, .. }) {
                        let _ = run.send(&parent, Command::NetUnlisten { port }).await;
                        return super::TestOutcome::new(
                            "AA->A",
                            false,
                            format!("fork failed: {exec_resp:?}"),
                        );
                    }
                    let conn_resp = run
                        .send(
                            &child,
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "child_parent_after_fork".into(),
                            },
                        )
                        .await;
                    let pass = matches!(&conn_resp, Response::Connected { echo } if echo == "child_parent_after_fork");
                    let _ = run.send(&parent, Command::NetUnlisten { port }).await;
                    super::TestOutcome::new("AA->A", pass, format!("{conn_resp:?}"))
                })
            })
        });

    reg.test("stress", "port_router", "PR.child_listen_depth2")
        .timeout(180)
        .build(|cx| {
            let connector = cx.require(AgentName::D5);
            let child = cx.declare_ephemeral(
                AgentName::D4,
                "CL_D4",
                SpawnKind::Fork {
                    binary: "self",
                    inherit_listen_ports: vec![],
                },
            );
            Box::new(move |run| {
                let child = child.clone();
                Box::pin(async move {
                    let port = 18521u16;
                    let spawn_resp = run.spawn_ephemeral(&child).await;
                    if !matches!(&spawn_resp, Response::Ok { .. }) {
                        return super::TestOutcome::new(
                            "D5->CL_D4",
                            false,
                            format!("fork failed: {spawn_resp:?}"),
                        );
                    }
                    let listen_resp = run.forward(&child, Command::NetListen { port }).await;
                    if !matches!(&listen_resp, Response::Listening { port: p } if *p == port) {
                        let _ = run.forward(&child, Command::Exit).await;
                        return super::TestOutcome::new(
                            "D5->CL_D4",
                            false,
                            format!("child listen failed: {listen_resp:?}"),
                        );
                    }
                    let conn_resp = run
                        .send(
                            &connector,
                            Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "child_listen_depth2".into(),
                            },
                        )
                        .await;
                    let pass = matches!(&conn_resp, Response::Connected { echo } if echo == "child_listen_depth2");
                    let _ = run.forward(&child, Command::NetUnlisten { port }).await;
                    let _ = run.forward(&child, Command::Exit).await;
                    super::TestOutcome::new("D5->CL_D4", pass, format!("{conn_resp:?}"))
                })
            })
        });
}
