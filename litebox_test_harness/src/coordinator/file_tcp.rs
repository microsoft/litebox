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

const TEST_FILE: &str = "/tmp/ft_test.txt";
const TEST_DATA: &str = "file_tcp_test_data_1234567890";

pub(crate) fn register_file_tcp(tests: &mut Vec<super::Test>) {
    register_listen_file_tests(tests);
    register_conn_file_tests(tests);
    register_interleave_tests(tests);
    register_multi_cycle_tests(tests);
    register_exec_during_tcp_tests(tests);
}

fn register_listen_file_tests(tests: &mut Vec<super::Test>) {
    for &agent in &["A", "B"] {
        let port = if agent == "A" { 18100 } else { 18101 };
        let agent_s = agent.to_string();

        // FT.listen_write.{agent}
        {
            let id = format!("FT.listen_write.{agent}");
            let ag = agent_s.clone();
            tests.push(super::Test {
                suite: "stress",
                group: "file_tcp",
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
                        let write_resp = r
                            .send(
                                &ag,
                                crate::protocol::Command::FsWrite {
                                    path: TEST_FILE.into(),
                                    data: TEST_DATA.into(),
                                },
                            )
                            .await;
                        let write_ok = matches!(&write_resp, crate::protocol::Response::Ok { .. });
                        let _ = r
                            .send(&ag, crate::protocol::Command::NetUnlisten { port })
                            .await;
                        super::TestOutcome::new(&ag, write_ok, format!("{write_resp:?}"))
                    })
                }),
            });
        }

        // FT.listen_read.{agent}
        {
            let id = format!("FT.listen_read.{agent}");
            let ag = agent_s.clone();
            tests.push(super::Test {
                suite: "stress",
                group: "file_tcp",
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
                            .send(
                                &ag,
                                crate::protocol::Command::FsWrite {
                                    path: TEST_FILE.into(),
                                    data: TEST_DATA.into(),
                                },
                            )
                            .await;
                        let read_resp = r
                            .send(
                                &ag,
                                crate::protocol::Command::FsRead {
                                    path: TEST_FILE.into(),
                                },
                            )
                            .await;
                        let read_ok = matches!(&read_resp, crate::protocol::Response::Ok { data: Some(d) } if d == TEST_DATA);
                        let _ = r
                            .send(&ag, crate::protocol::Command::NetUnlisten { port })
                            .await;
                        super::TestOutcome::new(&ag, read_ok, format!("{read_resp:?}"))
                    })
                }),
            });
        }

        // FT.listen_read_etc.{agent}
        {
            let id = format!("FT.listen_read_etc.{agent}");
            let ag = agent_s.clone();
            tests.push(super::Test {
                suite: "stress",
                group: "file_tcp",
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
                        let host_resp = r
                            .send(
                                &ag,
                                crate::protocol::Command::FsRead {
                                    path: "/etc/hostname".into(),
                                },
                            )
                            .await;
                        let host_ok = matches!(&host_resp, crate::protocol::Response::Ok { data: Some(d) } if !d.is_empty());
                        let _ = r
                            .send(&ag, crate::protocol::Command::NetUnlisten { port })
                            .await;
                        super::TestOutcome::new(&ag, host_ok, format!("{host_resp:?}"))
                    })
                }),
            });
        }
    }
}

fn register_conn_file_tests(tests: &mut Vec<super::Test>) {
    let port = 18110u16;

    // FT.conn_echo
    tests.push(super::Test {
        suite: "stress",
        group: "file_tcp",
        id: "FT.conn_echo".to_string(),
        xfail: None,
            timeout_secs: 180,
        run: Box::new(move |r| {
            Box::pin(async move {
                let listen_resp = r
                    .send("A", crate::protocol::Command::NetListen { port })
                    .await;
                if !matches!(&listen_resp, crate::protocol::Response::Listening { .. }) {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let conn_resp = r
                    .send(
                        "A",
                        crate::protocol::Command::NetConnect {
                            addr: format!("127.0.0.1:{port}"),
                            data: "conn_test".into(),
                        },
                    )
                    .await;
                let conn_ok = matches!(&conn_resp, crate::protocol::Response::Connected { echo } if echo == "conn_test");
                let _ = r
                    .send("A", crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new("A", conn_ok, format!("{conn_resp:?}"))
            })
        }),
    });

    // FT.conn_read_after
    tests.push(super::Test {
        suite: "stress",
        group: "file_tcp",
        id: "FT.conn_read_after".to_string(),
        xfail: None,
            timeout_secs: 180,
        run: Box::new(move |r| {
            Box::pin(async move {
                let listen_resp = r
                    .send("A", crate::protocol::Command::NetListen { port })
                    .await;
                if !matches!(&listen_resp, crate::protocol::Response::Listening { .. }) {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let _ = r
                    .send(
                        "A",
                        crate::protocol::Command::NetConnect {
                            addr: format!("127.0.0.1:{port}"),
                            data: "conn_test".into(),
                        },
                    )
                    .await;
                let read_resp = r
                    .send(
                        "A",
                        crate::protocol::Command::FsRead {
                            path: "/etc/hostname".into(),
                        },
                    )
                    .await;
                let read_ok = matches!(&read_resp, crate::protocol::Response::Ok { data: Some(d) } if !d.is_empty());
                let _ = r
                    .send("A", crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new("A", read_ok, format!("{read_resp:?}"))
            })
        }),
    });

    // FT.conn_write
    tests.push(super::Test {
        suite: "stress",
        group: "file_tcp",
        id: "FT.conn_write".to_string(),
        xfail: None,
        timeout_secs: 180,
        run: Box::new(move |r| {
            Box::pin(async move {
                let listen_resp = r
                    .send("A", crate::protocol::Command::NetListen { port })
                    .await;
                if !matches!(&listen_resp, crate::protocol::Response::Listening { .. }) {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let _ = r
                    .send(
                        "A",
                        crate::protocol::Command::NetConnect {
                            addr: format!("127.0.0.1:{port}"),
                            data: "conn_test".into(),
                        },
                    )
                    .await;
                let write_resp = r
                    .send(
                        "A",
                        crate::protocol::Command::FsWrite {
                            path: "/tmp/ft_conn.txt".into(),
                            data: "during_conn".into(),
                        },
                    )
                    .await;
                let write_ok = matches!(&write_resp, crate::protocol::Response::Ok { .. });
                let _ = r
                    .send("A", crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new("A", write_ok, format!("{write_resp:?}"))
            })
        }),
    });

    // FT.conn_readback
    tests.push(super::Test {
        suite: "stress",
        group: "file_tcp",
        id: "FT.conn_readback".to_string(),
        xfail: None,
            timeout_secs: 180,
        run: Box::new(move |r| {
            Box::pin(async move {
                let listen_resp = r
                    .send("A", crate::protocol::Command::NetListen { port })
                    .await;
                if !matches!(&listen_resp, crate::protocol::Response::Listening { .. }) {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen failed: {listen_resp:?}"),
                    );
                }
                let _ = r
                    .send(
                        "A",
                        crate::protocol::Command::NetConnect {
                            addr: format!("127.0.0.1:{port}"),
                            data: "conn_test".into(),
                        },
                    )
                    .await;
                let _ = r
                    .send(
                        "A",
                        crate::protocol::Command::FsWrite {
                            path: "/tmp/ft_conn.txt".into(),
                            data: "during_conn".into(),
                        },
                    )
                    .await;
                let readback = r
                    .send(
                        "A",
                        crate::protocol::Command::FsRead {
                            path: "/tmp/ft_conn.txt".into(),
                        },
                    )
                    .await;
                let readback_ok = matches!(&readback, crate::protocol::Response::Ok { data: Some(d) } if d == "during_conn");
                let _ = r
                    .send("A", crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new("A", readback_ok, format!("{readback:?}"))
            })
        }),
    });
}

fn register_interleave_tests(tests: &mut Vec<super::Test>) {
    // FT.interleave_self_small
    tests.push(super::Test {
        suite: "stress",
        group: "file_tcp",
        id: "FT.interleave_self_small".to_string(),
        xfail: None,
            timeout_secs: 180,
        run: Box::new(|r| {
            Box::pin(async move {
                let agent = "A";
                let port = 18120u16;
                let _ = r
                    .send(
                        agent,
                        crate::protocol::Command::FsWrite {
                            path: "/tmp/ft_interleave.txt".into(),
                            data: "interleave_marker".into(),
                        },
                    )
                    .await;
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
                let resp = r
                    .send(
                        agent,
                        crate::protocol::Command::NetSendFileRecv {
                            addr: format!("127.0.0.1:{port}"),
                            size: 64,
                            path: "/tmp/ft_interleave.txt".into(),
                        },
                    )
                    .await;
                let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) } if d.contains("tcp_ok=64"));
                let _ = r
                    .send(agent, crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new(agent, pass, format!("{resp:?}"))
            })
        }),
    });

    // FT.interleave_self_4k
    tests.push(super::Test {
        suite: "stress",
        group: "file_tcp",
        id: "FT.interleave_self_4k".to_string(),
        xfail: None,
            timeout_secs: 180,
        run: Box::new(|r| {
            Box::pin(async move {
                let agent = "A";
                let port = 18120u16;
                let _ = r
                    .send(
                        agent,
                        crate::protocol::Command::FsWrite {
                            path: "/tmp/ft_interleave.txt".into(),
                            data: "interleave_marker".into(),
                        },
                    )
                    .await;
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
                let resp = r
                    .send(
                        agent,
                        crate::protocol::Command::NetSendFileRecv {
                            addr: format!("127.0.0.1:{port}"),
                            size: 4096,
                            path: "/etc/hostname".into(),
                        },
                    )
                    .await;
                let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) } if d.contains("tcp_ok=4096"));
                let _ = r
                    .send(agent, crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new(agent, pass, format!("{resp:?}"))
            })
        }),
    });

    // FT.interleave_self_32k
    tests.push(super::Test {
        suite: "stress",
        group: "file_tcp",
        id: "FT.interleave_self_32k".to_string(),
        xfail: None,
            timeout_secs: 180,
        run: Box::new(|r| {
            Box::pin(async move {
                let agent = "A";
                let port = 18120u16;
                let _ = r
                    .send(
                        agent,
                        crate::protocol::Command::FsWrite {
                            path: "/tmp/ft_interleave.txt".into(),
                            data: "interleave_marker".into(),
                        },
                    )
                    .await;
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
                let resp = r
                    .send(
                        agent,
                        crate::protocol::Command::NetSendFileRecv {
                            addr: format!("127.0.0.1:{port}"),
                            size: 32768,
                            path: "/tmp/ft_interleave.txt".into(),
                        },
                    )
                    .await;
                let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) } if d.contains("tcp_ok=32768"));
                let _ = r
                    .send(agent, crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new(agent, pass, format!("{resp:?}"))
            })
        }),
    });

    // FT.interleave_cross_small
    tests.push(super::Test {
        suite: "stress",
        group: "file_tcp",
        id: "FT.interleave_cross_small".to_string(),
        xfail: None,
            timeout_secs: 180,
        run: Box::new(|r| {
            Box::pin(async move {
                let port = 18121u16;
                let _ = r
                    .send(
                        "A",
                        crate::protocol::Command::FsWrite {
                            path: "/tmp/ft_interleave.txt".into(),
                            data: "interleave_marker".into(),
                        },
                    )
                    .await;
                let listen_resp = r
                    .send("B", crate::protocol::Command::NetListen { port })
                    .await;
                if !matches!(&listen_resp, crate::protocol::Response::Listening { .. }) {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen on B failed: {listen_resp:?}"),
                    );
                }
                let resp = r
                    .send(
                        "A",
                        crate::protocol::Command::NetSendFileRecv {
                            addr: format!("127.0.0.1:{port}"),
                            size: 64,
                            path: "/tmp/ft_interleave.txt".into(),
                        },
                    )
                    .await;
                let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) } if d.contains("tcp_ok=64"));
                let _ = r
                    .send("B", crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // FT.interleave_cross_4k
    tests.push(super::Test {
        suite: "stress",
        group: "file_tcp",
        id: "FT.interleave_cross_4k".to_string(),
        xfail: None,
            timeout_secs: 180,
        run: Box::new(|r| {
            Box::pin(async move {
                let port = 18121u16;
                let _ = r
                    .send(
                        "A",
                        crate::protocol::Command::FsWrite {
                            path: "/tmp/ft_interleave.txt".into(),
                            data: "interleave_marker".into(),
                        },
                    )
                    .await;
                let listen_resp = r
                    .send("B", crate::protocol::Command::NetListen { port })
                    .await;
                if !matches!(&listen_resp, crate::protocol::Response::Listening { .. }) {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen on B failed: {listen_resp:?}"),
                    );
                }
                let resp = r
                    .send(
                        "A",
                        crate::protocol::Command::NetSendFileRecv {
                            addr: format!("127.0.0.1:{port}"),
                            size: 4096,
                            path: "/etc/hostname".into(),
                        },
                    )
                    .await;
                let pass = matches!(&resp, crate::protocol::Response::Ok { data: Some(d) } if d.contains("tcp_ok=4096"));
                let _ = r
                    .send("B", crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });
}

fn register_multi_cycle_tests(tests: &mut Vec<super::Test>) {
    let port = 18130u16;

    // FT.multi_x5
    tests.push(super::Test {
        suite: "stress",
        group: "file_tcp",
        id: "FT.multi_x5".to_string(),
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
                let mut all_ok = true;
                let count = 5;
                for i in 0..count {
                    let conn_resp = r
                        .send(
                            agent,
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
                    let write_resp = r
                        .send(
                            agent,
                            crate::protocol::Command::FsWrite {
                                path: path.clone(),
                                data: data.clone(),
                            },
                        )
                        .await;
                    if !matches!(&write_resp, crate::protocol::Response::Ok { .. }) {
                        all_ok = false;
                        break;
                    }
                    let read_resp = r
                        .send(agent, crate::protocol::Command::FsRead { path })
                        .await;
                    if !matches!(&read_resp, crate::protocol::Response::Ok { data: Some(d) } if *d == data) {
                        all_ok = false;
                        break;
                    }
                }
                let _ = r
                    .send(agent, crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new(agent, all_ok, format!("{count} file+TCP cycles"))
            })
        }),
    });

    // FT.multi_interleave_x5
    tests.push(super::Test {
        suite: "stress",
        group: "file_tcp",
        id: "FT.multi_interleave_x5".to_string(),
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
                let mut interleave_ok = true;
                let count = 5;
                for i in 0..count {
                    let path = format!("/tmp/ft_multi_{i}.txt");
                    let resp = r
                        .send(
                            agent,
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
                let _ = r
                    .send(agent, crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new(
                    agent,
                    interleave_ok,
                    format!("{count} interleaved file+TCP cycles"),
                )
            })
        }),
    });
}

fn register_exec_during_tcp_tests(tests: &mut Vec<super::Test>) {
    let port = 18140u16;

    // FT.exec_cat_during_tcp
    tests.push(super::Test {
        suite: "stress",
        group: "file_tcp",
        id: "FT.exec_cat_during_tcp".to_string(),
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
                let _ = r
                    .send(
                        agent,
                        crate::protocol::Command::FsWrite {
                            path: "/tmp/ft_exec.txt".into(),
                            data: "exec_test_content".into(),
                        },
                    )
                    .await;
                let exec_resp = r
                    .send(
                        agent,
                        super::exec_timeout(vec!["cat".into(), "/tmp/ft_exec.txt".into()], 5),
                    )
                    .await;
                let exec_ok = matches!(
                    &exec_resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() == "exec_test_content"
                );
                let _ = r
                    .send(agent, crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new(agent, exec_ok, format!("{exec_resp:?}"))
            })
        }),
    });

    // FT.echo_after_exec
    tests.push(super::Test {
        suite: "stress",
        group: "file_tcp",
        id: "FT.echo_after_exec".to_string(),
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
                let _ = r
                    .send(
                        agent,
                        crate::protocol::Command::FsWrite {
                            path: "/tmp/ft_exec.txt".into(),
                            data: "exec_test_content".into(),
                        },
                    )
                    .await;
                let _ = r
                    .send(
                        agent,
                        super::exec_timeout(vec!["cat".into(), "/tmp/ft_exec.txt".into()], 5),
                    )
                    .await;
                let conn_resp = r
                    .send(
                        agent,
                        crate::protocol::Command::NetConnect {
                            addr: format!("127.0.0.1:{port}"),
                            data: "post_exec".into(),
                        },
                    )
                    .await;
                let conn_ok = matches!(&conn_resp, crate::protocol::Response::Connected { echo } if echo == "post_exec");
                let _ = r
                    .send(agent, crate::protocol::Command::NetUnlisten { port })
                    .await;
                super::TestOutcome::new(agent, conn_ok, format!("{conn_resp:?}"))
            })
        }),
    });
}
