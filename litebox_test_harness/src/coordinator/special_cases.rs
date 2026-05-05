// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Contamination sequence tests — inherently sequential tests that depend on
//! accumulated per-agent state from prior execs.
//!
//! These cannot be expressed as cross-product loops because each test depends
//! on the state left by the previous exec on the same agent (e.g., "run
//! non-PIE, then run PIE — does the PIE see clean output?").

use crate::protocol::{Command, Response};
/// Register netlink tests. Each test is self-contained: one exec + check.
pub(super) fn register_netlink(tests: &mut Vec<super::Test>) {
    // Helper: create a test that execs a subcommand and checks stdout.
    let _nl =
        |id: &str, args: Vec<String>, timeout_secs: u64, check: fn(&str) -> bool| -> super::Test {
            let id = id.to_string();
            let _id2 = id.clone();
            super::Test {
                suite: "matrix",
                group: "netlink",
                id,
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let cmd = if timeout_secs > 0 {
                            super::exec_timeout(args, timeout_secs)
                        } else {
                            super::exec(args)
                        };
                        let resp = r.send("A", cmd).await;
                        let pass = matches!(
                            &resp,
                            crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                                if check(stdout)
                        );
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                }),
            }
        };

    let _exe = || {
        std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .to_string()
    };
    // We can't call r.self_exe here (no runner yet), so tests will
    // use the self_exe from the runner. Let's capture it differently.
    // Actually, the closure captures the runner, so we can read self_exe there.
    // But our helper doesn't have the runner. Let's restructure:

    // Each test captures its args as a closure over the runner.
    let self_exe_test =
        |id: &str, subcmd: &str, arg: &str, timeout: u64, check: fn(&str) -> bool| {
            let id = id.to_string();
            let subcmd = subcmd.to_string();
            let arg = arg.to_string();
            super::Test {
                suite: "matrix",
                group: "netlink",
                id: id.clone(),
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let args = vec![self_exe, subcmd, arg];
                        let cmd = if timeout > 0 {
                            super::exec_timeout(args, timeout)
                        } else {
                            super::exec(args)
                        };
                        let resp = r.send("A", cmd).await;
                        let pass = matches!(
                            &resp,
                            crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                                if check(stdout)
                        );
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                }),
            }
        };

    tests.push(self_exe_test(
        "NL1.netlink_socket",
        "getifaddrs-test",
        "socket",
        0,
        |s| s.contains("NETLINK_SOCKET_OK"),
    ));
    tests.push(self_exe_test(
        "NL2.netlink_bind",
        "getifaddrs-test",
        "bind",
        0,
        |s| s.contains("NETLINK_BIND_OK"),
    ));
    tests.push(self_exe_test(
        "NL3.netlink_getlink",
        "getifaddrs-test",
        "getlink",
        0,
        |s| s.contains("NETLINK_GETLINK_OK"),
    ));
    tests.push(self_exe_test(
        "NL4.netlink_getaddr",
        "getifaddrs-test",
        "getaddr",
        0,
        |s| s.contains("NETLINK_GETADDR_OK"),
    ));
    tests.push(self_exe_test(
        "NL3b.sendmsg_recvmsg",
        "getifaddrs-test",
        "sendmsg",
        0,
        |s| s.contains("NETLINK_SENDMSG_RECVMSG_OK"),
    ));
    tests.push(self_exe_test(
        "NL3c.double_request",
        "getifaddrs-test",
        "double",
        30,
        |s| s.contains("NETLINK_DOUBLE_OK"),
    ));
    tests.push(self_exe_test(
        "NL3d.peek_trunc",
        "getifaddrs-test",
        "peek-trunc",
        30,
        |s| s.contains("NETLINK_PEEK_TRUNC_OK"),
    ));
    tests.push(self_exe_test(
        "NL5.getifaddrs_full",
        "getifaddrs-test",
        "full",
        30,
        |s| s.contains("GETIFADDRS_OK"),
    ));

    // X48: Node.js os.networkInterfaces()
    {
        let id = "X48.node_networkInterfaces".to_string();
        tests.push(super::Test {
            suite: "matrix",
            group: "netlink",
            id: id.clone(),
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let resp = r
                        .send(
                            "A",
                            super::exec_timeout(
                                vec![
                                    "/usr/local/bin/node".into(),
                                    "-e".into(),
                                    "try { const r = require('os').networkInterfaces(); console.log('NETIF_OK:' + Object.keys(r).length); } catch(e) { console.log('NETIF_ERR:' + e.code); }".into(),
                                ],
                                30,
                            ),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("NETIF_OK:") || stdout.contains("NETIF_ERR:")
                    );
                    super::TestOutcome::new("A", pass, format!("{resp:?}"))
                })
            }),
        });
    }

    // NL6: MAC address via getifaddrs
    tests.push(self_exe_test(
        "NL6.mac_address",
        "unix-socket-test",
        "mac",
        30,
        |s| s.contains("NL6_MAC_CHECK"),
    ));
}
/// Register IPv6 network tests.
pub(super) fn register_net_ipv6(tests: &mut Vec<super::Test>) {
    let cases: &[(&str, &str)] = &[
        ("NET1.ipv6_socket", "ipv6-socket"),
        ("NET2.ipv6_listen", "ipv6-listen"),
        ("NET4.ipv4_listen", "ipv4-listen"),
        ("NET5.ipv6_getaddrinfo", "ipv6-getaddrinfo"),
        ("NET6.ipv6_v6only", "ipv6-v6only"),
    ];
    for &(name, sub) in cases {
        let id = name.to_string();
        let sub = sub.to_string();
        tests.push(super::Test {
            suite: "matrix",
            group: "net_ipv6",
            id,
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let resp = r
                        .send("A", super::exec_timeout(vec![self_exe, "net-test".into(), sub], 10))
                        .await;
                    let pass = matches!(&resp, crate::protocol::Response::ExecResult { stdout, .. } if stdout.contains("_OK"));
                    super::TestOutcome::new("A", pass, format!("{resp:?}"))
                })
            }),
        });
    }
}

/// Register terminal ioctl tests.
pub(super) fn register_terminal_ioctl(tests: &mut Vec<super::Test>) {
    let ops = ["tcgets", "tcsets", "tcsetsw", "tcsetsf", "tiocgwinsz"];
    let fds = [0, 1, 2];
    for op in &ops {
        for fd in &fds {
            let id = format!("TERM.{op}_fd{fd}");
            let op = op.to_string();
            let fd_str = fd.to_string();
            tests.push(super::Test {
                suite: "matrix",
                group: "terminal_ioctl",
                id,
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let resp = r
                            .send(
                                "A",
                                super::exec_timeout(
                                    vec![self_exe, "exit-test".into(), "term".into(), op, fd_str],
                                    8,
                                ),
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            crate::protocol::Response::ExecResult { exit_code: 0 | 1, stdout, .. }
                                if stdout.contains("TERM_OK") || stdout.contains("TERM_ERR")
                        );
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
}

/// Register Node.js exit tests.
pub(super) fn register_node_exit(tests: &mut Vec<super::Test>) {
    let _node_tests: &[(
        &str,
        Vec<&str>,
        Box<dyn Fn(&crate::protocol::Response) -> bool + Send + Sync>,
    )] = &[];
    // Simpler: just push each test individually.

    tests.push(super::Test {
        suite: "fork", group: "node_exit",
        id: "EX6.node_version_exit".into(), xfail: None,
            timeout_secs: 60,
        run: Box::new(|r| Box::pin(async move {
            let resp = r.send("A", super::exec_timeout(vec!["/usr/local/bin/node".into(), "--version".into()], 10)).await;
            let pass = matches!(&resp, crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. } if stdout.starts_with('v'));
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        })),
    });

    tests.push(super::Test {
        suite: "fork",
        group: "node_exit",
        id: "EX7.node_process_exit".into(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
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
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, .. }
                );
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    tests.push(super::Test {
        suite: "fork",
        group: "node_exit",
        id: "EX8.node_exit_code".into(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
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
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 42, .. }
                );
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    tests.push(super::Test {
        suite: "fork", group: "node_exit",
        id: "EX9.node_console_exit".into(), xfail: None,
            timeout_secs: 60,
        run: Box::new(|r| Box::pin(async move {
            let resp = r.send("A", super::exec_timeout(vec!["/usr/local/bin/node".into(), "-e".into(), "console.log(\"NODE_EXIT_OK\")".into()], 10)).await;
            let pass = matches!(&resp, crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NODE_EXIT_OK"));
            super::TestOutcome::new("A", pass, format!("{resp:?}"))
        })),
    });
}
/// Register FS I/O matrix tests.
pub(super) fn register_fs_io(tests: &mut Vec<super::Test>) {
    let ops: &[&str] = &[
        "write-read",
        "append-read",
        "write-bg-read",
        "redirect-bg-read",
        "fork-write-read",
        "bg-open-read",
        "parent-open-fork-read",
    ];
    let paths: &[(&str, &str)] = &[("/tmp/fs-test.txt", "tmp"), ("/root/fs-test.txt", "root")];

    for &op in ops {
        for &(path, dir) in paths {
            let id = format!("FS.{op}.{dir}");
            let op = op.to_string();
            let path = path.to_string();
            tests.push(super::Test {
                suite: "matrix", group: "fs_io", id, xfail: None,
            timeout_secs: 60,
                run: Box::new(move |r| {
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let resp = r.send("A", super::exec_timeout(
                            vec![self_exe, "fs-test".into(), "io".into(), op, path], 15,
                        )).await;
                        let pass = matches!(&resp, crate::protocol::Response::ExecResult { stdout, .. } if stdout.contains("FS_OK"));
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }

    // Exec-write and exec-open-read
    for &mode in &["exec-write", "exec-open-read"] {
        let prefix = if mode == "exec-write" { "exec" } else { "open" };
        for &bin in &["pie", "nonpie"] {
            let path = "/tmp/fs-exec.txt";
            let pname = "fs-exec.txt";
            let id = format!("FS.{prefix}_{bin}_{pname}");
            let mode = mode.to_string();
            let bin = bin.to_string();
            let path = path.to_string();
            tests.push(super::Test {
                suite: "matrix", group: "fs_io", id, xfail: None,
            timeout_secs: 60,
                run: Box::new(move |r| {
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let resp = r.send("A", super::exec_timeout(
                            vec![self_exe, "fs-test".into(), mode, bin, path], 30,
                        )).await;
                        let pass = matches!(&resp, crate::protocol::Response::ExecResult { stdout, .. } if stdout.contains("FS_OK"));
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
}

/// Register capture-pipe fork tests.
pub(super) fn register_capture_pipe(tests: &mut Vec<super::Test>) {
    const CMD_TYPES: &[&str] = &[
        "simple",
        "pipe",
        "multi",
        "noexec",
        "nested_fork",
        "subshell_pipe",
        "subshell_continue",
    ];
    const SHELLS: &[&str] = &["sh", "bash"];
    const CP_AGENTS: &[&str] = &["A", "AA"];

    for &agent in CP_AGENTS {
        for &shell in SHELLS {
            for &cmd_type in CMD_TYPES {
                let id = format!("CP.{cmd_type}.{shell}.{agent}");
                let agent = agent.to_string();
                let shell = shell.to_string();
                let cmd_type = cmd_type.to_string();
                tests.push(super::Test {
                    suite: "fork", group: "capture_pipe", id, xfail: None,
            timeout_secs: 60,
                    run: Box::new(move |r| {
                        let self_exe = r.self_exe.clone();
                        Box::pin(async move {
                            let resp = r.send(&agent, super::exec_timeout(
                                vec![self_exe, "capture-pipe".into(), cmd_type, shell], 10,
                            )).await;
                            let pass = matches!(&resp, crate::protocol::Response::ExecResult { stdout, .. } if stdout.contains("CP_OK"));
                            super::TestOutcome::new(&agent, pass, format!("{resp:?}"))
                        })
                    }),
                });
            }
        }
    }
}
/// Register stdin-piped script tests.
pub(super) fn register_stdin_script(tests: &mut Vec<super::Test>) {
    const SCRIPTS: &[(&str, &str, &str)] = &[
        (
            "cmd_subst",
            "FOO=$(echo hello)\necho FOO=$FOO\necho DONE\n",
            "FOO=hello",
        ),
        (
            "pipe_in_subst",
            "A=$(echo one | cat)\necho A=$A\necho DONE\n",
            "A=one",
        ),
        (
            "multi_pipe_subst",
            "A=$(echo data | grep data | cat)\necho A=$A\necho DONE\n",
            "A=data",
        ),
        (
            "file_pipe_subst",
            "A=$(cat /etc/hostname | cat)\necho A=$A\necho DONE\n",
            "DONE",
        ),
        (
            "sequential_subst",
            "A=$(echo first)\nB=$(echo second)\necho A=$A B=$B\necho DONE\n",
            "A=first B=second",
        ),
        (
            "subst_then_cmds",
            "A=$(echo val | cat)\necho LINE1\necho LINE2\necho LINE3\n",
            "LINE3",
        ),
        (
            "vscode_osrelease",
            "ID=$(cat /etc/os-release | grep -E '^ID=' | sed 's/ID=//g' | sed 's/\"//g')\necho ID=$ID\necho DONE\n",
            "DONE",
        ),
        (
            "backtick_pipe",
            "A=`echo one | cat`\necho A=$A\necho DONE\n",
            "A=one",
        ),
    ];
    const SHELLS: &[&str] = &["sh", "bash"];
    const SS_AGENTS: &[&str] = &["A", "AA"];

    for &agent in SS_AGENTS {
        for &shell in SHELLS {
            for &(name, script, expected) in SCRIPTS {
                let id = format!("SS.{name}.{shell}.{agent}");
                let agent = agent.to_string();
                let shell = shell.to_string();
                let script = script.to_string();
                let expected = expected.to_string();
                tests.push(super::Test {
                    suite: "shell", group: "stdin_script", id, xfail: None,
            timeout_secs: 60,
                    run: Box::new(move |r| {
                        Box::pin(async move {
                            let resp = r.send(&agent, crate::protocol::Command::Exec {
                                args: vec![shell],
                                timeout_secs: Some(10),
                                stdin: Some(script),
                                background: false,
                            }).await;
                            let pass = matches!(&resp, crate::protocol::Response::ExecResult { stdout, .. } if stdout.contains(&*expected));
                            super::TestOutcome::new(&agent, pass, format!("{resp:?}"))
                        })
                    }),
                });
            }
        }
    }
}

// Register unix socket tests.
pub(crate) fn register_unix_socket(tests: &mut Vec<super::Test>) {
    // Simple exec tests on agent A
    let simple_tests: &[(&str, &str, &str)] = &[
        (
            "US1.cross_process_unix",
            "cross-process",
            "US1_CROSS_PROCESS_OK",
        ),
        ("US2.cross_exec_unix", "cross-exec", "US2_CROSS_EXEC_OK"),
        ("US3.bidirectional_unix", "bidirectional", "US3_BIDI_OK"),
        ("US4.multi_conn_unix", "multi-conn", "US4_MULTI_OK"),
        ("US5.abstract_unix", "abstract", "US5_ABSTRACT_OK"),
        ("VS1.socket_race", "race", "VS1_RACE_OK"),
    ];
    for &(name, sub, expected) in simple_tests {
        let id = name.to_string();
        let sub = sub.to_string();
        let expected = expected.to_string();
        tests.push(super::Test {
            suite: "xworker",
            group: "unix_socket",
            id,
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let resp = r
                        .send(
                            "A",
                            super::exec_timeout(vec![self_exe, "unix-socket-test".into(), sub], 10),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains(&*expected)
                    );
                    super::TestOutcome::new("A", pass, format!("{resp:?}"))
                })
            }),
        });
    }

    // Fork agents: cross-process on different agents
    for &agent in &["A", "AA", "B"] {
        let id = format!("UF.fork_unix.{agent}");
        let agent_s = agent.to_string();
        tests.push(super::Test {
            suite: "xworker",
            group: "unix_socket",
            id,
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let resp = r
                        .send(
                            &agent_s,
                            super::exec_timeout(
                                vec![self_exe, "unix-socket-test".into(), "cross-process".into()],
                                15,
                            ),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("US1_CROSS_PROCESS_OK")
                    );
                    super::TestOutcome::new(&agent_s, pass, format!("{resp:?}"))
                })
            }),
        });
    }

    // Socketpair write/read across agents
    for &agent in &["A", "AA", "B", "D3", "D4", "NP"] {
        // write direction
        let id = format!("US6.socketpair_write.{agent}");
        let agent_s = agent.to_string();
        tests.push(super::Test {
            suite: "xworker",
            group: "unix_socket",
            id,
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let resp = r
                        .send(
                            &agent_s,
                            super::exec_timeout(
                                vec![
                                    self_exe,
                                    "unix-socket-test".into(),
                                    "socketpair-fork-write".into(),
                                ],
                                15,
                            ),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("US6_SOCKETPAIR_FORK_OK")
                    );
                    super::TestOutcome::new(&agent_s, pass, format!("{resp:?}"))
                })
            }),
        });

        // read direction
        let id = format!("US6.socketpair_read.{agent}");
        let agent_s = agent.to_string();
        tests.push(super::Test {
            suite: "xworker",
            group: "unix_socket",
            id,
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let resp = r
                        .send(
                            &agent_s,
                            super::exec_timeout(
                                vec![
                                    self_exe,
                                    "unix-socket-test".into(),
                                    "socketpair-fork-read".into(),
                                ],
                                15,
                            ),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("US6R_SOCKETPAIR_FORK_READ_OK")
                    );
                    super::TestOutcome::new(&agent_s, pass, format!("{resp:?}"))
                })
            }),
        });
    }

    // Socketpair exec across agents
    for &agent in &["A", "AA", "B", "D3", "D4", "NP"] {
        let id = format!("US6.socketpair_exec.{agent}");
        let agent_s = agent.to_string();
        tests.push(super::Test {
            suite: "xworker",
            group: "unix_socket",
            id,
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let resp = r
                        .send(
                            &agent_s,
                            super::exec_timeout(
                                vec![
                                    self_exe,
                                    "unix-socket-test".into(),
                                    "socketpair-exec".into(),
                                ],
                                20,
                            ),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("US6E_SOCKETPAIR_EXEC_OK")
                    );
                    super::TestOutcome::new(&agent_s, pass, format!("{resp:?}"))
                })
            }),
        });
    }

    // Socketpair nonpie
    for &agent in &["A", "AA", "B"] {
        let id = format!("US6.socketpair_nonpie.{agent}");
        let agent_s = agent.to_string();
        tests.push(super::Test {
            suite: "xworker",
            group: "unix_socket",
            id,
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let nonpie = match crate::find_nonpie_binary() {
                        Some(p) => p,
                        None => {
                            return super::TestOutcome::new(
                                &agent_s,
                                false,
                                "FAIL: nonpie binary not found",
                            );
                        }
                    };
                    let resp = r
                        .send(
                            &agent_s,
                            super::exec_timeout(
                                vec![nonpie, "unix-socket-test".into(), "socketpair-exec".into()],
                                30,
                            ),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("US6E_SOCKETPAIR_EXEC_OK")
                    );
                    super::TestOutcome::new(&agent_s, pass, format!("{resp:?}"))
                })
            }),
        });
    }
}

// Register cross-worker tests.
pub(crate) fn register_cross_worker(tests: &mut Vec<super::Test>) {
    // XW.spawn_remote
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW.spawn_remote".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r
                    .send(
                        "A",
                        Command::SpawnRemote {
                            children: vec!["R".to_string()],
                        },
                    )
                    .await;
                let pass = matches!(&resp, Response::Ok { .. });
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW1.remote_write
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW1.remote_write".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
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
                let pass = matches!(&resp, Response::Ok { .. });
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW1.local_read
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW1.local_read".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r
                    .send(
                        "A",
                        Command::FsRead {
                            path: "/tmp/xw1.txt".to_string(),
                        },
                    )
                    .await;
                let pass =
                    matches!(&resp, Response::Ok { data: Some(d), .. } if d == "REMOTE_DATA");
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW2.local_write
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW2.local_write".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r
                    .send(
                        "A",
                        Command::FsWrite {
                            path: "/tmp/xw2.txt".to_string(),
                            data: "LOCAL_DATA".to_string(),
                        },
                    )
                    .await;
                let pass = matches!(&resp, Response::Ok { .. });
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW2.remote_read
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW2.remote_read".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
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
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW3.remote_listen
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW3.remote_listen".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
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
                let pass = matches!(&resp, Response::UnixListening { .. });
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW3.local_connect — does own listen setup on unique path
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW3.local_connect".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                // Listen on a unique path (setup)
                let listen_resp = r
                    .send(
                        "A",
                        Command::Forward {
                            target: "R".to_string(),
                            inner: Box::new(Command::UnixListen {
                                path: "/tmp/xw3c.sock".to_string(),
                            }),
                        },
                    )
                    .await;
                if !matches!(&listen_resp, Response::UnixListening { .. }) {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen setup failed: {listen_resp:?}"),
                    );
                }
                let resp = r
                    .send(
                        "A",
                        Command::UnixConnect {
                            path: "/tmp/xw3c.sock".to_string(),
                            data: "XW_HELLO".to_string(),
                        },
                    )
                    .await;
                let pass =
                    matches!(&resp, Response::Connected { echo } if echo.contains("XW_HELLO"));
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW4.local_listen
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW4.local_listen".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r
                    .send(
                        "A",
                        Command::UnixListen {
                            path: "/tmp/xw4.sock".to_string(),
                        },
                    )
                    .await;
                let pass = matches!(&resp, Response::UnixListening { .. });
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW4.remote_connect — does own listen setup on unique path
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW4.remote_connect".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let listen_resp = r
                    .send(
                        "A",
                        Command::UnixListen {
                            path: "/tmp/xw4c.sock".to_string(),
                        },
                    )
                    .await;
                if !matches!(&listen_resp, Response::UnixListening { .. }) {
                    return super::TestOutcome::new(
                        "A",
                        false,
                        format!("listen setup failed: {listen_resp:?}"),
                    );
                }
                let resp = r
                    .send(
                        "A",
                        Command::Forward {
                            target: "R".to_string(),
                            inner: Box::new(Command::UnixConnect {
                                path: "/tmp/xw4c.sock".to_string(),
                                data: "XW_HELLO2".to_string(),
                            }),
                        },
                    )
                    .await;
                let pass =
                    matches!(&resp, Response::Connected { echo } if echo.contains("XW_HELLO2"));
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW5.remote_tcp_listen
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW5.remote_tcp_listen".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r
                    .send(
                        "A",
                        Command::Forward {
                            target: "R".to_string(),
                            inner: Box::new(Command::NetListen { port: 0 }),
                        },
                    )
                    .await;
                let pass = matches!(&resp, Response::Listening { .. });
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW5.local_tcp_connect — does own listen setup
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW5.local_tcp_connect".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let listen_resp = r
                    .send(
                        "A",
                        Command::Forward {
                            target: "R".to_string(),
                            inner: Box::new(Command::NetListen { port: 0 }),
                        },
                    )
                    .await;
                let port = match &listen_resp {
                    Response::Listening { port } => *port,
                    _ => {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            format!("listen setup failed: {listen_resp:?}"),
                        );
                    }
                };
                let resp = r
                    .send(
                        "A",
                        Command::NetConnect {
                            addr: format!("127.0.0.1:{port}"),
                            data: "XW_TCP_HELLO".to_string(),
                        },
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    Response::Connected { echo } if echo.contains("XW_TCP_HELLO")
                );
                let _ = r
                    .send(
                        "A",
                        Command::Forward {
                            target: "R".to_string(),
                            inner: Box::new(Command::NetUnlisten { port }),
                        },
                    )
                    .await;
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW6.local_tcp_listen
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW6.local_tcp_listen".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r.send("A", Command::NetListen { port: 0 }).await;
                let pass = matches!(&resp, Response::Listening { .. });
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW6.remote_tcp_connect — does own listen setup
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW6.remote_tcp_connect".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let listen_resp = r.send("A", Command::NetListen { port: 0 }).await;
                let port = match &listen_resp {
                    Response::Listening { port } => *port,
                    _ => {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            format!("listen setup failed: {listen_resp:?}"),
                        );
                    }
                };
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
                let pass = matches!(
                    &resp,
                    Response::Connected { echo } if echo.contains("XW_TCP_HELLO2")
                );
                let _ = r.send("A", Command::NetUnlisten { port }).await;
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW7.d4_listen
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW7.d4_listen".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r
                    .send(
                        "D4",
                        Command::UnixListen {
                            path: "/tmp/xw7.sock".to_string(),
                        },
                    )
                    .await;
                let pass = matches!(&resp, Response::UnixListening { .. });
                super::TestOutcome::new("D4", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW7.d3_connect — does own listen setup
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW7.d3_connect".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let listen_resp = r
                    .send(
                        "D4",
                        Command::UnixListen {
                            path: "/tmp/xw7c.sock".to_string(),
                        },
                    )
                    .await;
                if !matches!(&listen_resp, Response::UnixListening { .. }) {
                    return super::TestOutcome::new(
                        "D3",
                        false,
                        format!("listen setup failed: {listen_resp:?}"),
                    );
                }
                let resp = r
                    .send(
                        "D3",
                        Command::UnixConnect {
                            path: "/tmp/xw7c.sock".to_string(),
                            data: "XW7_D3_TO_D4".to_string(),
                        },
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    Response::Connected { echo } if echo.contains("XW7_D3_TO_D4")
                );
                super::TestOutcome::new("D3", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW8.d3_listen
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW8.d3_listen".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r
                    .send(
                        "D3",
                        Command::UnixListen {
                            path: "/tmp/xw8.sock".to_string(),
                        },
                    )
                    .await;
                let pass = matches!(&resp, Response::UnixListening { .. });
                super::TestOutcome::new("D3", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW8.d4_connect — does own listen setup
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW8.d4_connect".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let listen_resp = r
                    .send(
                        "D3",
                        Command::UnixListen {
                            path: "/tmp/xw8c.sock".to_string(),
                        },
                    )
                    .await;
                if !matches!(&listen_resp, Response::UnixListening { .. }) {
                    return super::TestOutcome::new(
                        "D4",
                        false,
                        format!("listen setup failed: {listen_resp:?}"),
                    );
                }
                let resp = r
                    .send(
                        "D4",
                        Command::UnixConnect {
                            path: "/tmp/xw8c.sock".to_string(),
                            data: "XW8_D4_TO_D3".to_string(),
                        },
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    Response::Connected { echo } if echo.contains("XW8_D4_TO_D3")
                );
                super::TestOutcome::new("D4", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW9.d4_listen
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW9.d4_listen".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r
                    .send(
                        "D4",
                        Command::UnixListen {
                            path: "/tmp/xw9.sock".to_string(),
                        },
                    )
                    .await;
                let pass = matches!(&resp, Response::UnixListening { .. });
                super::TestOutcome::new("D4", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW9.aa_connect — does own listen setup
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW9.aa_connect".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let listen_resp = r
                    .send(
                        "D4",
                        Command::UnixListen {
                            path: "/tmp/xw9c.sock".to_string(),
                        },
                    )
                    .await;
                if !matches!(&listen_resp, Response::UnixListening { .. }) {
                    return super::TestOutcome::new(
                        "AA",
                        false,
                        format!("listen setup failed: {listen_resp:?}"),
                    );
                }
                let resp = r
                    .send(
                        "AA",
                        Command::UnixConnect {
                            path: "/tmp/xw9c.sock".to_string(),
                            data: "XW9_AA_TO_D4".to_string(),
                        },
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    Response::Connected { echo } if echo.contains("XW9_AA_TO_D4")
                );
                super::TestOutcome::new("AA", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW10.d3_tcp_listen
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW10.d3_tcp_listen".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r.send("D3", Command::NetListen { port: 0 }).await;
                let pass = matches!(&resp, Response::Listening { .. });
                super::TestOutcome::new("D3", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW10.b_tcp_connect — does own listen setup
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW10.b_tcp_connect".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let listen_resp = r.send("D3", Command::NetListen { port: 0 }).await;
                let port = match &listen_resp {
                    Response::Listening { port } => *port,
                    _ => {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            format!("listen setup failed: {listen_resp:?}"),
                        );
                    }
                };
                let resp = r
                    .send(
                        "B",
                        Command::NetConnect {
                            addr: format!("127.0.0.1:{port}"),
                            data: "XW10_CROSS_SUBTREE".to_string(),
                        },
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    Response::Connected { echo } if echo.contains("XW10_CROSS_SUBTREE")
                );
                let _ = r.send("D3", Command::NetUnlisten { port }).await;
                super::TestOutcome::new("B", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW11.d3_tcp_listen
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW11.d3_tcp_listen".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r.send("D3", Command::NetListen { port: 0 }).await;
                let pass = matches!(&resp, Response::Listening { .. });
                super::TestOutcome::new("D3", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW11.spawn_r2
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW11.spawn_r2".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r
                    .send(
                        "B",
                        Command::SpawnRemote {
                            children: vec!["R2".to_string()],
                        },
                    )
                    .await;
                let pass = matches!(&resp, Response::Ok { .. });
                super::TestOutcome::new("B", pass, format!("{resp:?}"))
            })
        }),
    });

    // XW11.r2_tcp_connect — does own setup (listen + spawn)
    tests.push(super::Test {
        suite: "xworker",
        group: "cross_worker",
        id: "XW11.r2_tcp_connect".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                // Setup: listen on D3
                let listen_resp = r.send("D3", Command::NetListen { port: 0 }).await;
                let port = match &listen_resp {
                    Response::Listening { port } => *port,
                    _ => {
                        return super::TestOutcome::new(
                            "R2",
                            false,
                            format!("listen setup failed: {listen_resp:?}"),
                        );
                    }
                };
                // Setup: spawn R2 under B (may already exist)
                let _ = r
                    .send(
                        "B",
                        Command::SpawnRemote {
                            children: vec!["R2".to_string()],
                        },
                    )
                    .await;
                // Connect from R2
                let resp = r
                    .send(
                        "B",
                        Command::Forward {
                            target: "R2".to_string(),
                            inner: Box::new(Command::NetConnect {
                                addr: format!("127.0.0.1:{port}"),
                                data: "XW11_LATE_SPAWN".to_string(),
                            }),
                        },
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    Response::Connected { echo } if echo.contains("XW11_LATE_SPAWN")
                );
                let _ = r.send("D3", Command::NetUnlisten { port }).await;
                super::TestOutcome::new("R2", pass, format!("{resp:?}"))
            })
        }),
    });
}

// Register pipe EOF tests.
pub(crate) fn register_pipe_eof(tests: &mut Vec<super::Test>) {
    // P1: pipe + fork
    for &agent in &["A", "AA", "B", "D3", "D4", "NP"] {
        let id = format!("P1.pipe_eof_fork.{agent}");
        let agent_s = agent.to_string();
        tests.push(super::Test {
            suite: "xworker",
            group: "pipe_eof",
            id,
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let resp = r
                        .send(
                            &agent_s,
                            super::exec_timeout(
                                vec![self_exe, "pipe-test".into(), "eof-fork".into()],
                                20,
                            ),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("P1_EOF_OK")
                    );
                    super::TestOutcome::new(&agent_s, pass, format!("{resp:?}"))
                })
            }),
        });
    }

    // P2: fork+exec(PIE)
    for &agent in &["A", "AA", "B"] {
        let id = format!("P2.pipe_eof_exec_pie.{agent}");
        let agent_s = agent.to_string();
        tests.push(super::Test {
            suite: "xworker",
            group: "pipe_eof",
            id,
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let resp = r
                        .send(
                            &agent_s,
                            super::exec_timeout(
                                vec![
                                    self_exe.clone(),
                                    "pipe-test".into(),
                                    "eof-exec".into(),
                                    self_exe,
                                ],
                                20,
                            ),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("P2_EOF_OK")
                    );
                    super::TestOutcome::new(&agent_s, pass, format!("{resp:?}"))
                })
            }),
        });
    }

    // P2: fork+exec(nonpie)
    for &agent in &["A", "AA", "B"] {
        let id = format!("P2.pipe_eof_exec_nonpie.{agent}");
        let agent_s = agent.to_string();
        tests.push(super::Test {
            suite: "xworker",
            group: "pipe_eof",
            id,
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let nonpie = match crate::find_nonpie_binary() {
                        Some(p) => p,
                        None => {
                            return super::TestOutcome::new(
                                &agent_s,
                                false,
                                "FAIL: nonpie binary not found",
                            );
                        }
                    };
                    let resp = r
                        .send(
                            &agent_s,
                            super::exec_timeout(
                                vec![self_exe, "pipe-test".into(), "eof-exec".into(), nonpie],
                                20,
                            ),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("P2_EOF_OK")
                    );
                    super::TestOutcome::new(&agent_s, pass, format!("{resp:?}"))
                })
            }),
        });
    }
}

// Register contamination sequence tests (X49-X59).
pub(crate) fn register_contamination_sequence(tests: &mut Vec<super::Test>) {
    // X49a
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X49a.pie_sequential_1".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            let self_exe = r.self_exe.clone();
            Box::pin(async move {
                let resp = r
                    .send("A", super::exec(vec![self_exe, "echo-test".into()]))
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout == "ECHO_TEST_OK"
                );
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // X49b
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X49b.pie_sequential_2".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            let self_exe = r.self_exe.clone();
            Box::pin(async move {
                let resp = r
                    .send(
                        "A",
                        super::exec(vec![self_exe, "exit-with".into(), "0".into()]),
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.is_empty()
                );
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // X50a
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X50a.nonpie_then_pie_1".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let nonpie = match crate::find_nonpie_binary() {
                    Some(p) => p,
                    None => {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            "FAIL: nonpie binary not found",
                        );
                    }
                };
                let resp = r
                    .send("A", super::exec(vec![nonpie, "echo-test".into()]))
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.contains("ECHO_TEST_OK")
                );
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // X50b
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X50b.nonpie_then_pie_2".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            let self_exe = r.self_exe.clone();
            Box::pin(async move {
                let resp = r
                    .send("A", super::exec(vec![self_exe, "echo-test".into()]))
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout == "ECHO_TEST_OK"
                );
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // X51
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X51.nonpie_fresh_agent".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let nonpie = match crate::find_nonpie_binary() {
                    Some(p) => p,
                    None => {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            "FAIL: nonpie binary not found",
                        );
                    }
                };
                let resp = r
                    .send("B", super::exec(vec![nonpie, "echo-test".into()]))
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.contains("ECHO_TEST_OK")
                );
                super::TestOutcome::new("B", pass, format!("{resp:?}"))
            })
        }),
    });

    // X52a
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X52a.B_nonpie_then_pie".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            let self_exe = r.self_exe.clone();
            Box::pin(async move {
                let resp = r
                    .send("B", super::exec(vec![self_exe, "echo-test".into()]))
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout == "ECHO_TEST_OK"
                );
                super::TestOutcome::new("B", pass, format!("{resp:?}"))
            })
        }),
    });

    // X52b
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X52b.B_pie_after_nonpie".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            let self_exe = r.self_exe.clone();
            Box::pin(async move {
                let resp = r
                    .send(
                        "B",
                        super::exec(vec![self_exe, "exit-with".into(), "0".into()]),
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.is_empty()
                );
                super::TestOutcome::new("B", pass, format!("{resp:?}"))
            })
        }),
    });

    // X52c
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X52c.B_third_exec".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            let self_exe = r.self_exe.clone();
            Box::pin(async move {
                let resp = r
                    .send("B", super::exec(vec![self_exe, "echo-test".into()]))
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout == "ECHO_TEST_OK"
                );
                super::TestOutcome::new("B", pass, format!("{resp:?}"))
            })
        }),
    });

    // X53 — 30 sequential PIE execs on AB
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X53.stress_pie".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            let self_exe = r.self_exe.clone();
            Box::pin(async move {
                for i in 0..30 {
                    let resp = r
                        .send(
                            "AB",
                            super::exec(vec![self_exe.clone(), "echo-test".into()]),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout == "ECHO_TEST_OK"
                    );
                    if !pass {
                        return super::TestOutcome::new(
                            "AB",
                            false,
                            format!("failed at iteration {i}: {resp:?}"),
                        );
                    }
                }
                super::TestOutcome::new("AB", true, "30 sequential PIE execs all passed")
            })
        }),
    });

    // X54
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X54.nonpie_after_stress".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let nonpie = match crate::find_nonpie_binary() {
                    Some(p) => p,
                    None => {
                        return super::TestOutcome::new(
                            "AB",
                            false,
                            "FAIL: nonpie binary not found",
                        );
                    }
                };
                let resp = r
                    .send("AB", super::exec(vec![nonpie, "echo-test".into()]))
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.contains("ECHO_TEST_OK")
                );
                super::TestOutcome::new("AB", pass, format!("{resp:?}"))
            })
        }),
    });

    // X55a
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X55a.one_pie_first".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            let self_exe = r.self_exe.clone();
            Box::pin(async move {
                let resp = r
                    .send("AAB", super::exec(vec![self_exe, "echo-test".into()]))
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout == "ECHO_TEST_OK"
                );
                super::TestOutcome::new("AAB", pass, format!("{resp:?}"))
            })
        }),
    });

    // X55b
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X55b.nonpie_second".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let nonpie = match crate::find_nonpie_binary() {
                    Some(p) => p,
                    None => {
                        return super::TestOutcome::new(
                            "AAB",
                            false,
                            "FAIL: nonpie binary not found",
                        );
                    }
                };
                let resp = r
                    .send("AAB", super::exec(vec![nonpie, "echo-test".into()]))
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.contains("ECHO_TEST_OK")
                );
                super::TestOutcome::new("AAB", pass, format!("{resp:?}"))
            })
        }),
    });

    // X56
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X56.second_nonpie_on_B".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let nonpie = match crate::find_nonpie_binary() {
                    Some(p) => p,
                    None => {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            "FAIL: nonpie binary not found",
                        );
                    }
                };
                let resp = r
                    .send("B", super::exec(vec![nonpie, "echo-test".into()]))
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.contains("ECHO_TEST_OK")
                );
                super::TestOutcome::new("B", pass, format!("{resp:?}"))
            })
        }),
    });

    // X57 — 20 pipe churns then nonpie
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X57.pipe_churn_then_nonpie".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let nonpie = match crate::find_nonpie_binary() {
                    Some(p) => p,
                    None => {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            "FAIL: nonpie binary not found",
                        );
                    }
                };
                for _ in 0..20 {
                    let _ = r
                        .send(
                            "B",
                            super::exec(vec![
                                "bash".into(),
                                "-c".into(),
                                "echo churn >/dev/null".into(),
                            ]),
                        )
                        .await;
                }
                let resp = r
                    .send("B", super::exec(vec![nonpie, "echo-test".into()]))
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.contains("ECHO_TEST_OK")
                );
                super::TestOutcome::new("B", pass, format!("{resp:?}"))
            })
        }),
    });

    // X58 — alternating PIE and non-PIE
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X58.alternating_pie_nonpie".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            let self_exe = r.self_exe.clone();
            Box::pin(async move {
                let nonpie = match crate::find_nonpie_binary() {
                    Some(p) => p,
                    None => {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            "FAIL: nonpie binary not found",
                        );
                    }
                };
                let mut results: Vec<(String, bool)> = Vec::new();
                for _ in 0..2 {
                    let resp = r
                        .send("B", super::exec(vec![self_exe.clone(), "echo-test".into()]))
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout == "ECHO_TEST_OK"
                    );
                    results.push((format!("{resp:?}"), pass));

                    let resp = r
                        .send("B", super::exec(vec![nonpie.clone(), "echo-test".into()]))
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("ECHO_TEST_OK")
                    );
                    results.push((format!("{resp:?}"), pass));
                }
                let all_pass = results.iter().all(|(_, p)| *p);
                let detail = results
                    .iter()
                    .enumerate()
                    .map(|(i, (d, p))| format!("[{i}]={p}: {d}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                super::TestOutcome::new("B", all_pass, detail)
            })
        }),
    });

    // X59 — 5 sequential non-PIE
    tests.push(super::Test {
        suite: "contamination",
        group: "contamination_sequence",
        id: "X59.sequential_nonpie".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let nonpie = match crate::find_nonpie_binary() {
                    Some(p) => p,
                    None => {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            "FAIL: nonpie binary not found",
                        );
                    }
                };
                for i in 0..5 {
                    let resp = r
                        .send("B", super::exec(vec![nonpie.clone(), "echo-test".into()]))
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("ECHO_TEST_OK")
                    );
                    if !pass {
                        return super::TestOutcome::new(
                            "B",
                            false,
                            format!("failed at iteration {i}: {resp:?}"),
                        );
                    }
                }
                super::TestOutcome::new("B", true, "5 sequential non-PIE execs all passed")
            })
        }),
    });
}
