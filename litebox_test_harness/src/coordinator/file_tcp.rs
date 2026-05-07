// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! FT (File+TCP) tests — combined file I/O and TCP operations.
//!
//! These tests reproduce the 9P deadlock found via GDB: when a tokio agent
//! has active TCP sockets and tries to open/read a file, the `sys_openat`
//! call goes through the 9P client which blocks in `wait_for_completion`,
//! hanging the entire single-threaded tokio runtime.
//!
//! Categories:
//! - FT.listen: file ops while a TCP listener is active
//! - FT.conn: file ops while a TCP connection is active
//! - FT.interleave: file I/O interleaved between TCP send and recv
//! - FT.multi: multiple file+TCP round-trips in sequence

use super::agents::{AgentHandle, AgentName};
use super::registry::Registry;
use super::run_context::RunContext;

const TEST_FILE: &str = "/tmp/ft_test.txt";
const TEST_DATA: &str = "file_tcp_test_data_1234567890";

pub(crate) fn register_file_tcp(reg: &mut Registry<'_>) {
    register_listen_file_tests(reg);
    register_conn_file_tests(reg);
    register_interleave_tests(reg);
    register_multi_cycle_tests(reg);
    register_exec_during_tcp_tests(reg);
    register_axis_file_tcp_tests(reg);
}

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
fn register_listen_file_tests(reg: &mut Registry<'_>) {
    for &agent in &[AgentName::A, AgentName::B] {
        let port = if agent == AgentName::A { 18100 } else { 18101 };

        // FT.listen_write.{agent}
        {
            let id = format!("FT.listen_write.{agent}");
            let agent_label = agent.to_string();
            reg.test("stress", "file_tcp", id)
                .timeout(180)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        Box::pin(async move {
                            let listen_resp = run
                                .send(
                                    &handle,
                                    crate::protocol::Command::NetListen {
                                        port,
                                        pre_bind_options: vec![],
                                    },
                                )
                                .await;
                            if !super::expect_listening_port(&listen_resp, port).is_ok() {
                                return super::TestOutcome::new(
                                    &agent_label,
                                    false,
                                    format!("listen failed: {listen_resp:?}"),
                                );
                            }
                            let write_resp = run
                                .send(
                                    &handle,
                                    crate::protocol::Command::FsWrite {
                                        path: TEST_FILE.into(),
                                        data: TEST_DATA.into(),
                                    },
                                )
                                .await;
                            let write_ok = super::ok_without_data(&write_resp);
                            let _ = run
                                .send(&handle, crate::protocol::Command::NetUnlisten { port })
                                .await;
                            super::TestOutcome::new(
                                &agent_label,
                                write_ok,
                                format!("{write_resp:?}"),
                            )
                        })
                    })
                });
        }

        // FT.listen_read.{agent}
        {
            let id = format!("FT.listen_read.{agent}");
            let agent_label = agent.to_string();
            reg.test("stress", "file_tcp", id)
                .timeout(180)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        Box::pin(async move {
                            let listen_resp = run
                                .send(&handle, crate::protocol::Command::NetListen { port, pre_bind_options: vec![] })
                                .await;
                            if !super::expect_listening_port(&listen_resp, port).is_ok() {
                                return super::TestOutcome::new(
                                    &agent_label,
                                    false,
                                    format!("listen failed: {listen_resp:?}"),
                                );
                            }
                            let _ = run
                                .send(
                                    &handle,
                                    crate::protocol::Command::FsWrite {
                                        path: TEST_FILE.into(),
                                        data: TEST_DATA.into(),
                                    },
                                )
                                .await;
                            let read_resp = run
                                .send(
                                    &handle,
                                    crate::protocol::Command::FsRead {
                                        path: TEST_FILE.into(),
                                    },
                                )
                                .await;
                            let read_ok = matches!(&read_resp, crate::protocol::Response::Ok { data: Some(d) } if d == TEST_DATA);
                            let _ = run
                                .send(&handle, crate::protocol::Command::NetUnlisten { port })
                                .await;
                            super::TestOutcome::new(&agent_label, read_ok, format!("{read_resp:?}"))
                        })
                    })
                });
        }

        // FT.listen_read_etc.{agent}
        {
            let id = format!("FT.listen_read_etc.{agent}");
            let agent_label = agent.to_string();
            reg.test("stress", "file_tcp", id)
                .timeout(180)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        Box::pin(async move {
                            let listen_resp = run
                                .send(&handle, crate::protocol::Command::NetListen { port, pre_bind_options: vec![] })
                                .await;
                            if !super::expect_listening_port(&listen_resp, port).is_ok() {
                                return super::TestOutcome::new(
                                    &agent_label,
                                    false,
                                    format!("listen failed: {listen_resp:?}"),
                                );
                            }
                            let host_resp = run
                                .send(
                                    &handle,
                                    crate::protocol::Command::FsRead {
                                        path: "/etc/hostname".into(),
                                    },
                                )
                                .await;
                            let host_ok = matches!(&host_resp, crate::protocol::Response::Ok { data: Some(d) } if !d.is_empty());
                            let _ = run
                                .send(&handle, crate::protocol::Command::NetUnlisten { port })
                                .await;
                            super::TestOutcome::new(&agent_label, host_ok, format!("{host_resp:?}"))
                        })
                    })
                });
        }
    }
}

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
fn register_conn_file_tests(reg: &mut Registry<'_>) {
    let port = 18110u16;

    // FT.conn_echo
    reg.test("stress", "file_tcp", "FT.conn_echo")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::A);
            Box::new(move |run| {
                Box::pin(async move {
                    let listen_resp = run
                        .send(&handle, crate::protocol::Command::NetListen { port, pre_bind_options: vec![] })
                        .await;
                    if !super::expect_listening_port(&listen_resp, port).is_ok() {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let conn_resp = run
                        .send(
                            &handle,
                            crate::protocol::Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "conn_test".into(),
                            },
                        )
                        .await;
                    let conn_ok = matches!(&conn_resp, crate::protocol::Response::Connected { echo } if echo == "conn_test");
                    let _ = run
                        .send(&handle, crate::protocol::Command::NetUnlisten { port })
                        .await;
                    super::TestOutcome::new("A", conn_ok, format!("{conn_resp:?}"))
                })
            })
        });

    // FT.conn_read_after
    reg.test("stress", "file_tcp", "FT.conn_read_after")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::A);
            Box::new(move |run| {
                Box::pin(async move {
                    let listen_resp = run
                        .send(&handle, crate::protocol::Command::NetListen { port, pre_bind_options: vec![] })
                        .await;
                    if !super::expect_listening_port(&listen_resp, port).is_ok() {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let _ = run
                        .send(
                            &handle,
                            crate::protocol::Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "conn_test".into(),
                            },
                        )
                        .await;
                    let read_resp = run
                        .send(
                            &handle,
                            crate::protocol::Command::FsRead {
                                path: "/etc/hostname".into(),
                            },
                        )
                        .await;
                    let read_ok = matches!(&read_resp, crate::protocol::Response::Ok { data: Some(d) } if !d.is_empty());
                    let _ = run
                        .send(&handle, crate::protocol::Command::NetUnlisten { port })
                        .await;
                    super::TestOutcome::new("A", read_ok, format!("{read_resp:?}"))
                })
            })
        });

    // FT.conn_write
    reg.test("stress", "file_tcp", "FT.conn_write")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::A);
            Box::new(move |run| {
                Box::pin(async move {
                    let listen_resp = run
                        .send(
                            &handle,
                            crate::protocol::Command::NetListen {
                                port,
                                pre_bind_options: vec![],
                            },
                        )
                        .await;
                    if !super::expect_listening_port(&listen_resp, port).is_ok() {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let _ = run
                        .send(
                            &handle,
                            crate::protocol::Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "conn_test".into(),
                            },
                        )
                        .await;
                    let write_resp = run
                        .send(
                            &handle,
                            crate::protocol::Command::FsWrite {
                                path: "/tmp/ft_conn.txt".into(),
                                data: "during_conn".into(),
                            },
                        )
                        .await;
                    let write_ok = super::ok_without_data(&write_resp);
                    let _ = run
                        .send(&handle, crate::protocol::Command::NetUnlisten { port })
                        .await;
                    super::TestOutcome::new("A", write_ok, format!("{write_resp:?}"))
                })
            })
        });

    // FT.conn_readback
    reg.test("stress", "file_tcp", "FT.conn_readback")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::A);
            Box::new(move |run| {
                Box::pin(async move {
                    let listen_resp = run
                        .send(&handle, crate::protocol::Command::NetListen { port, pre_bind_options: vec![] })
                        .await;
                    if !super::expect_listening_port(&listen_resp, port).is_ok() {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let _ = run
                        .send(
                            &handle,
                            crate::protocol::Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "conn_test".into(),
                            },
                        )
                        .await;
                    let _ = run
                        .send(
                            &handle,
                            crate::protocol::Command::FsWrite {
                                path: "/tmp/ft_conn.txt".into(),
                                data: "during_conn".into(),
                            },
                        )
                        .await;
                    let readback = run
                        .send(
                            &handle,
                            crate::protocol::Command::FsRead {
                                path: "/tmp/ft_conn.txt".into(),
                            },
                        )
                        .await;
                    let readback_ok = matches!(&readback, crate::protocol::Response::Ok { data: Some(d) } if d == "during_conn");
                    let _ = run
                        .send(&handle, crate::protocol::Command::NetUnlisten { port })
                        .await;
                    super::TestOutcome::new("A", readback_ok, format!("{readback:?}"))
                })
            })
        });
}

fn register_interleave_tests(reg: &mut Registry<'_>) {
    for &(id, size, path) in &[
        ("FT.interleave_self_small", 64u32, "/tmp/ft_interleave.txt"),
        ("FT.interleave_self_4k", 4096u32, "/etc/hostname"),
        ("FT.interleave_self_32k", 32768u32, "/tmp/ft_interleave.txt"),
    ] {
        reg.test("stress", "file_tcp", id)
            .timeout(180)
            .build(move |cx| {
                let handle = cx.require(AgentName::A);
                Box::new(move |run| {
                    Box::pin(async move {
                        let port = 18120u16;
                        let _ = run
                            .send(
                                &handle,
                                crate::protocol::Command::FsWrite {
                                    path: "/tmp/ft_interleave.txt".into(),
                                    data: "interleave_marker".into(),
                                },
                            )
                            .await;
                        let listen_resp = run
                            .send(&handle, crate::protocol::Command::NetListen { port, pre_bind_options: vec![] })
                            .await;
                        if !super::expect_listening_port(&listen_resp, port).is_ok() {
                            return super::TestOutcome::new(
                                "A",
                                false,
                                format!("listen failed: {listen_resp:?}"),
                            );
                        }
                        let resp = run
                            .send(
                                &handle,
                                crate::protocol::Command::NetSendFileRecv {
                                    addr: format!("127.0.0.1:{port}"),
                                    size,
                                    path: path.into(),
                                },
                            )
                            .await;
                        let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) } if d.contains(&format!("tcp_ok={size}")));
                        let _ = run
                            .send(&handle, crate::protocol::Command::NetUnlisten { port })
                            .await;
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                })
            });
    }

    for &(id, size, path) in &[
        ("FT.interleave_cross_small", 64u32, "/tmp/ft_interleave.txt"),
        ("FT.interleave_cross_4k", 4096u32, "/etc/hostname"),
    ] {
        reg.test("stress", "file_tcp", id)
            .timeout(180)
            .build(move |cx| {
                let handle_a = cx.require(AgentName::A);
                let handle_b = cx.require(AgentName::B);
                Box::new(move |run| {
                    Box::pin(async move {
                        let port = 18121u16;
                        let _ = run
                            .send(
                                &handle_a,
                                crate::protocol::Command::FsWrite {
                                    path: "/tmp/ft_interleave.txt".into(),
                                    data: "interleave_marker".into(),
                                },
                            )
                            .await;
                        let listen_resp = run
                            .send(&handle_b, crate::protocol::Command::NetListen { port, pre_bind_options: vec![] })
                            .await;
                        if !super::expect_listening_port(&listen_resp, port).is_ok() {
                            return super::TestOutcome::new(
                                "A",
                                false,
                                format!("listen on B failed: {listen_resp:?}"),
                            );
                        }
                        let resp = run
                            .send(
                                &handle_a,
                                crate::protocol::Command::NetSendFileRecv {
                                    addr: format!("127.0.0.1:{port}"),
                                    size,
                                    path: path.into(),
                                },
                            )
                            .await;
                        let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) } if d.contains(&format!("tcp_ok={size}")));
                        let _ = run
                            .send(&handle_b, crate::protocol::Command::NetUnlisten { port })
                            .await;
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                })
            });
    }
}

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
fn register_multi_cycle_tests(reg: &mut Registry<'_>) {
    let port = 18130u16;

    // FT.multi_x5
    reg.test("stress", "file_tcp", "FT.multi_x5")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::A);
            Box::new(move |run| {
                Box::pin(async move {
                    let listen_resp = run
                        .send(&handle, crate::protocol::Command::NetListen { port, pre_bind_options: vec![] })
                        .await;
                    if !super::expect_listening_port(&listen_resp, port).is_ok() {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let mut all_ok = true;
                    let count = 5;
                    for i in 0..count {
                        let conn_resp = run
                            .send(
                                &handle,
                                crate::protocol::Command::NetConnect {
                                    addr: format!("127.0.0.1:{port}"),
                                    data: format!("cycle_{i}"),
                                },
                            )
                            .await;
                        let conn_ok = matches!(&conn_resp, crate::protocol::Response::Connected { echo } if echo == &format!("cycle_{i}"));
                        if !conn_ok {
                            all_ok = false;
                            break;
                        }
                        let path = format!("/tmp/ft_multi_{i}.txt");
                        let data = format!("cycle_data_{i}");
                        let write_resp = run
                            .send(
                                &handle,
                                crate::protocol::Command::FsWrite {
                                    path: path.clone(),
                                    data: data.clone(),
                                },
                            )
                            .await;
                        if !super::ok_without_data(&write_resp) {
                            all_ok = false;
                            break;
                        }
                        let read_resp = run
                            .send(&handle, crate::protocol::Command::FsRead { path })
                            .await;
                        if !matches!(&read_resp, crate::protocol::Response::Ok { data: Some(d) } if *d == data) {
                            all_ok = false;
                            break;
                        }
                    }
                    let _ = run
                        .send(&handle, crate::protocol::Command::NetUnlisten { port })
                        .await;
                    super::TestOutcome::new("A", all_ok, format!("{count} file+TCP cycles"))
                })
            })
        });

    // FT.multi_interleave_x5
    reg.test("stress", "file_tcp", "FT.multi_interleave_x5")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::A);
            Box::new(move |run| {
                Box::pin(async move {
                    let listen_resp = run
                        .send(&handle, crate::protocol::Command::NetListen { port, pre_bind_options: vec![] })
                        .await;
                    if !super::expect_listening_port(&listen_resp, port).is_ok() {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let mut interleave_ok = true;
                    let count = 5;
                    for i in 0..count {
                        let path = format!("/tmp/ft_multi_{i}.txt");
                        let write_resp = run
                            .send(
                                &handle,
                                crate::protocol::Command::FsWrite {
                                    path: path.clone(),
                                    data: format!("cycle_data_{i}"),
                                },
                            )
                            .await;
                        if !super::ok_without_data(&write_resp) {
                            interleave_ok = false;
                            break;
                        }
                        let resp = run
                            .send(
                                &handle,
                                crate::protocol::Command::NetSendFileRecv {
                                    addr: format!("127.0.0.1:{port}"),
                                    size: 256,
                                    path,
                                },
                            )
                            .await;
                        if !matches!(&resp, crate::protocol::Response::Ok { data: Some(d) } if d.contains("tcp_ok=256")) {
                            interleave_ok = false;
                            break;
                        }
                    }
                    let _ = run
                        .send(&handle, crate::protocol::Command::NetUnlisten { port })
                        .await;
                    super::TestOutcome::new(
                        "A",
                        interleave_ok,
                        format!("{count} interleaved file+TCP cycles"),
                    )
                })
            })
        });
}

fn register_exec_during_tcp_tests(reg: &mut Registry<'_>) {
    let port = 18140u16;

    // FT.exec_cat_during_tcp
    reg.test("stress", "file_tcp", "FT.exec_cat_during_tcp")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::A);
            Box::new(move |run| {
                Box::pin(async move {
                    let listen_resp = run
                        .send(&handle, crate::protocol::Command::NetListen { port, pre_bind_options: vec![] })
                        .await;
                    if !super::expect_listening_port(&listen_resp, port).is_ok() {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let _ = run
                        .send(
                            &handle,
                            crate::protocol::Command::FsWrite {
                                path: "/tmp/ft_exec.txt".into(),
                                data: "exec_test_content".into(),
                            },
                        )
                        .await;
                    let exec_resp = run
                        .send(
                            &handle,
                            super::exec_timeout(vec!["cat".into(), "/tmp/ft_exec.txt".into()], 5),
                        )
                        .await;
                    let exec_ok = matches!(
                        &exec_resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() == "exec_test_content"
                    );
                    let _ = run
                        .send(&handle, crate::protocol::Command::NetUnlisten { port })
                        .await;
                    super::TestOutcome::new("A", exec_ok, format!("{exec_resp:?}"))
                })
            })
        });

    // FT.echo_after_exec
    reg.test("stress", "file_tcp", "FT.echo_after_exec")
        .timeout(180)
        .build(move |cx| {
            let handle = cx.require(AgentName::A);
            Box::new(move |run| {
                Box::pin(async move {
                    let listen_resp = run
                        .send(&handle, crate::protocol::Command::NetListen { port, pre_bind_options: vec![] })
                        .await;
                    if !super::expect_listening_port(&listen_resp, port).is_ok() {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            format!("listen failed: {listen_resp:?}"),
                        );
                    }
                    let _ = run
                        .send(
                            &handle,
                            crate::protocol::Command::FsWrite {
                                path: "/tmp/ft_exec.txt".into(),
                                data: "exec_test_content".into(),
                            },
                        )
                        .await;
                    let _ = run
                        .send(
                            &handle,
                            super::exec_timeout(vec!["cat".into(), "/tmp/ft_exec.txt".into()], 5),
                        )
                        .await;
                    let conn_resp = run
                        .send(
                            &handle,
                            crate::protocol::Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "post_exec".into(),
                            },
                        )
                        .await;
                    let conn_ok = matches!(&conn_resp, crate::protocol::Response::Connected { echo } if echo == "post_exec");
                    let _ = run
                        .send(&handle, crate::protocol::Command::NetUnlisten { port })
                        .await;
                    super::TestOutcome::new("A", conn_ok, format!("{conn_resp:?}"))
                })
            })
        });
}

#[derive(Clone, Copy)]
struct FtAxisCase {
    name: &'static str,
    server: AgentName,
    client: AgentName,
}

const FT_AXIS_CASES: &[FtAxisCase] = &[
    FtAxisCase {
        name: "parent_child",
        server: AgentName::AA,
        client: AgentName::A,
    },
    FtAxisCase {
        name: "child_parent",
        server: AgentName::A,
        client: AgentName::AA,
    },
    FtAxisCase {
        name: "depth2",
        server: AgentName::D4,
        client: AgentName::D5,
    },
];

fn register_axis_file_tcp_tests(reg: &mut Registry<'_>) {
    for case in FT_AXIS_CASES {
        let id = format!("FT.axis.{}", case.name);
        let server_label = case.server.to_string();
        let client_label = case.client.to_string();
        reg.test("stress", "file_tcp", id)
            .timeout(180)
            .build(move |cx| {
                let server = cx.require(case.server);
                let client = cx.require(case.client);
                Box::new(move |run| {
                    let server_label = server_label.clone();
                    let client_label = client_label.clone();
                    Box::pin(async move {
                        run_axis_file_tcp_case(
                            run,
                            &server,
                            &client,
                            &server_label,
                            &client_label,
                            case.name,
                        )
                        .await
                    })
                })
            });
    }
}

async fn run_axis_file_tcp_case(
    run: &mut RunContext<'_>,
    server: &AgentHandle,
    client: &AgentHandle,
    server_label: &str,
    client_label: &str,
    axis: &str,
) -> super::TestOutcome {
    let agent = format!("{server_label}<-{client_label}");
    let path = format!("/root/litebox_ft_axis_{axis}.txt");
    let data = format!("ft_axis_payload_{axis}");
    let write_resp = run
        .send(
            server,
            crate::protocol::Command::FsWrite {
                path: path.clone(),
                data: data.clone(),
            },
        )
        .await;
    if !matches!(&write_resp, crate::protocol::Response::Ok { .. }) {
        return super::TestOutcome::new(&agent, false, format!("write failed: {write_resp:?}"));
    }

    let listen_resp = run
        .send(
            server,
            crate::protocol::Command::NetListen {
                port: 0,
                pre_bind_options: vec![],
            },
        )
        .await;
    let port = match listen_resp {
        crate::protocol::Response::Listening { port } if port > 0 => port,
        other => {
            let _ = run
                .send(server, crate::protocol::Command::FsDelete { path })
                .await;
            return super::TestOutcome::new(&agent, false, format!("listen failed: {other:?}"));
        }
    };

    let resp = run
        .send(
            client,
            crate::protocol::Command::NetSendFileRecv {
                addr: format!("127.0.0.1:{port}"),
                size: 128,
                path: path.clone(),
            },
        )
        .await;
    let expected = format!("tcp_ok=128,file_len={}", data.len());
    let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) } if d == &expected);
    let _ = run
        .send(server, crate::protocol::Command::NetUnlisten { port })
        .await;
    let _ = run
        .send(server, crate::protocol::Command::FsDelete { path })
        .await;
    super::TestOutcome::new(&agent, pass, format!("expected={expected} resp={resp:?}"))
}
