// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Non-matrix tests that cover edge cases or special behaviors not expressible
//! as capability × topology cross-products.
//!
//! These are preserved from the original hand-written test modules because they
//! test specific semantics (isolation, dangling symlinks, nested symlinks,
//! directory symlinks, relative targets, deeper unix socket patterns, etc.)
//! rather than systematic configuration coverage.

use super::{TestRunner, exec};
use crate::protocol::{Command, Response};

/// Filesystem edge-case tests not covered by the matrix.
pub(super) async fn fs_special_tests(r: &mut TestRunner) {
    eprintln!("[special] === Filesystem Edge Cases ===");

    // F5: /tmp isolation — A writes /tmp, AA reads (should be absent if isolated).
    r.send(
        "A",
        Command::FsWrite {
            path: "/tmp/f5.txt".into(),
            data: "temp".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "AA",
            Command::FsRead {
                path: "/tmp/f5.txt".into(),
            },
        )
        .await;
    let is_isolated = matches!(resp, Response::NotFound);
    r.record(
        "F5.parent_child_tmp",
        "AA",
        true,
        &format!("tmp_isolated={is_isolated}: {resp:?}"),
    );
    let resp = r
        .send(
            "B",
            Command::FsRead {
                path: "/tmp/f5.txt".into(),
            },
        )
        .await;
    let is_isolated = matches!(resp, Response::NotFound);
    r.record(
        "F5.sibling_tmp",
        "B",
        true,
        &format!("tmp_isolated={is_isolated}: {resp:?}"),
    );

    // F6: Host pre-written file.
    let resp = r
        .send(
            "init",
            Command::FsRead {
                path: "/shared/host_wrote.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_host");
    if matches!(&resp, Response::NotFound) {
        r.record_xfail(
            "F6.host_init",
            "init",
            pass,
            "host_wrote.txt not in rootfs",
            &format!("{resp:?}"),
        );
    } else {
        r.record("F6.host_init", "init", pass, &format!("{resp:?}"));
    }
    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/host_wrote.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_host");
    if matches!(&resp, Response::NotFound) {
        r.record_xfail(
            "F6.host_A",
            "A",
            pass,
            "host_wrote.txt not in rootfs",
            &format!("{resp:?}"),
        );
    } else {
        r.record("F6.host_A", "A", pass, &format!("{resp:?}"));
    }
    // Write for host to read after exit.
    r.send(
        "init",
        Command::FsWrite {
            path: "/shared/for_host.txt".into(),
            data: "from_agent".into(),
        },
    )
    .await;
}

/// Symlink edge-case tests (dir symlink, dangling, nested, relative).
pub(super) async fn symlink_special_tests(r: &mut TestRunner) {
    eprintln!("[special] === Symlink Edge Cases ===");

    // Probe symlink support.
    let probe = r
        .send(
            "A",
            Command::FsSymlink {
                target: "/tmp/special_probe_target".into(),
                link: "/tmp/special_probe_link".into(),
            },
        )
        .await;
    let symlink_unsupported =
        matches!(&probe, Response::Error { error } if error.contains("not supported"));
    let _ = r
        .send(
            "A",
            Command::FsDelete {
                path: "/tmp/special_probe_link".into(),
            },
        )
        .await;

    macro_rules! record_sym {
        ($test:expr, $agent:expr, $pass:expr, $detail:expr) => {
            if symlink_unsupported {
                r.record_xfail($test, $agent, $pass, "symlink() returns ENOTSUP", $detail);
            } else {
                r.record($test, $agent, $pass, $detail);
            }
        };
    }

    // Clean up stale files.
    for name in [
        "s6_dir",
        "s6_dirlink",
        "s7_dangling",
        "s8_link1",
        "s8_link2",
        "s8_file",
        "s9_file",
        "s9_relative",
    ] {
        let _ = r
            .send(
                "init",
                Command::FsDelete {
                    path: format!("/shared/{name}"),
                },
            )
            .await;
    }
    let _ = r
        .send(
            "A",
            exec(vec![
                "rm".into(),
                "-rf".into(),
                "/shared/s6_dir".into(),
                "/shared/s6_dirlink".into(),
            ]),
        )
        .await;

    // S6: Symlink to directory.
    let _ = r
        .send(
            "A",
            exec(vec![
                "bash".into(),
                "-c".into(),
                "mkdir -p /shared/s6_dir && echo S6_CONTENT > /shared/s6_dir/inside.txt".into(),
            ]),
        )
        .await;
    r.send(
        "A",
        Command::FsSymlink {
            target: "/shared/s6_dir".into(),
            link: "/shared/s6_dirlink".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/s6_dirlink/inside.txt".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d.trim() == "S6_CONTENT");
    record_sym!("S6.dir_symlink", "A", pass, &format!("{resp:?}"));

    // S7: Dangling symlink — readlink succeeds, read fails.
    r.send(
        "A",
        Command::FsSymlink {
            target: "/shared/nonexistent_target".into(),
            link: "/shared/s7_dangling".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "A",
            Command::FsReadlink {
                path: "/shared/s7_dangling".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "/shared/nonexistent_target");
    record_sym!("S7.readlink_dangling", "A", pass, &format!("{resp:?}"));

    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/s7_dangling".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Error { .. } | Response::NotFound);
    r.record("S7.read_dangling", "A", pass, &format!("{resp:?}"));

    // S8: Nested symlinks — link1 → link2 → file.
    r.send(
        "A",
        Command::FsWrite {
            path: "/shared/s8_file".into(),
            data: "S8_NESTED".into(),
        },
    )
    .await;
    r.send(
        "A",
        Command::FsSymlink {
            target: "/shared/s8_file".into(),
            link: "/shared/s8_link2".into(),
        },
    )
    .await;
    r.send(
        "A",
        Command::FsSymlink {
            target: "/shared/s8_link2".into(),
            link: "/shared/s8_link1".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/s8_link1".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "S8_NESTED");
    record_sym!("S8.nested", "A", pass, &format!("{resp:?}"));

    // S9: Relative symlink target.
    r.send(
        "A",
        Command::FsWrite {
            path: "/shared/s9_file".into(),
            data: "S9_RELATIVE".into(),
        },
    )
    .await;
    r.send(
        "A",
        Command::FsSymlink {
            target: "s9_file".into(),
            link: "/shared/s9_relative".into(),
        },
    )
    .await;
    let resp = r
        .send(
            "A",
            Command::FsRead {
                path: "/shared/s9_relative".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "S9_RELATIVE");
    record_sym!("S9.relative_target", "A", pass, &format!("{resp:?}"));
}

/// Unix socket edge-case tests (deeper in-process, cross-depth patterns).
pub(super) async fn unix_special_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    eprintln!("[special] === Unix Socket Edge Cases ===");

    // U1b: In-process from depth-2 agent (AA).
    let resp = r
        .send(
            "AA",
            Command::UnixListen {
                path: "/tmp/u1b.sock".into(),
            },
        )
        .await;
    r.record(
        "U1b.listen",
        "AA",
        matches!(&resp, Response::UnixListening { .. }),
        &format!("{resp:?}"),
    );
    let resp = r
        .send(
            "AA",
            Command::UnixConnect {
                path: "/tmp/u1b.sock".into(),
                data: "U1B_DATA".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "U1B_DATA");
    r.record("U1b.connect", "AA", pass, &format!("{resp:?}"));
    let _ = r
        .send(
            "AA",
            Command::UnixUnlisten {
                path: "/tmp/u1b.sock".into(),
            },
        )
        .await;

    // U4: Parent server from deeper worker (AA listens, AA forks client).
    let resp = r
        .send(
            "AA",
            Command::UnixListen {
                path: "/tmp/u4.sock".into(),
            },
        )
        .await;
    r.record(
        "U4.listen",
        "AA",
        matches!(&resp, Response::UnixListening { .. }),
        &format!("{resp:?}"),
    );
    let resp = r
        .send(
            "AA",
            exec(vec![
                self_exe.clone(),
                "unix-echo-client".into(),
                "/tmp/u4.sock".into(),
                "U4_DEEP".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("U4_DEEP"));
    r.record("U4.child_connect", "AA", pass, &format!("{resp:?}"));
    let _ = r
        .send(
            "AA",
            Command::UnixUnlisten {
                path: "/tmp/u4.sock".into(),
            },
        )
        .await;

    // U5: Reverse relay from deeper worker (AA background server, AA connects).
    let resp = r
        .send(
            "AA",
            Command::ExecBackground {
                args: vec![
                    self_exe.clone(),
                    "unix-echo-server".into(),
                    "/tmp/u5.sock".into(),
                ],
            },
        )
        .await;
    let server_pid = match &resp {
        Response::Background { pid } => Some(*pid),
        _ => None,
    };
    r.record(
        "U5.server_start",
        "AA",
        server_pid.is_some(),
        &format!("{resp:?}"),
    );
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let resp = r
        .send(
            "AA",
            Command::UnixConnect {
                path: "/tmp/u5.sock".into(),
                data: "U5_DEEP_REVERSE".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "U5_DEEP_REVERSE");
    r.record("U5.parent_connect", "AA", pass, &format!("{resp:?}"));

    if let Some(pid) = server_pid {
        let _ = r.send("AA", Command::Kill { pid }).await;
    }
    let _ = r
        .send(
            "AA",
            Command::UnixUnlisten {
                path: "/tmp/u5.sock".into(),
            },
        )
        .await;

    // U7: Cross-depth — parent (A) listens, grandchild (AA) connects.
    let resp = r
        .send(
            "A",
            Command::UnixListen {
                path: "/tmp/u7.sock".into(),
            },
        )
        .await;
    r.record(
        "U7.listen",
        "A",
        matches!(&resp, Response::UnixListening { .. }),
        &format!("{resp:?}"),
    );
    let resp = r
        .send(
            "AA",
            Command::UnixConnect {
                path: "/tmp/u7.sock".into(),
                data: "U7_GRANDCHILD".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "U7_GRANDCHILD");
    r.record("U7.grandchild_connect", "AA", pass, &format!("{resp:?}"));
    let _ = r
        .send(
            "A",
            Command::UnixUnlisten {
                path: "/tmp/u7.sock".into(),
            },
        )
        .await;

    // U8: Reverse cross-depth — grandchild (AA) listens, parent (A) connects.
    let resp = r
        .send(
            "AA",
            Command::ExecBackground {
                args: vec![
                    self_exe.clone(),
                    "unix-echo-server".into(),
                    "/tmp/u8.sock".into(),
                ],
            },
        )
        .await;
    let server_pid = match &resp {
        Response::Background { pid } => Some(*pid),
        _ => None,
    };
    r.record(
        "U8.server_start",
        "AA",
        server_pid.is_some(),
        &format!("{resp:?}"),
    );
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let resp = r
        .send(
            "A",
            Command::UnixConnect {
                path: "/tmp/u8.sock".into(),
                data: "U8_PARENT_TO_GRANDCHILD".into(),
            },
        )
        .await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "U8_PARENT_TO_GRANDCHILD");
    r.record("U8.parent_connect", "A", pass, &format!("{resp:?}"));

    if let Some(pid) = server_pid {
        let _ = r.send("AA", Command::Kill { pid }).await;
    }
    let _ = r
        .send(
            "AA",
            Command::UnixUnlisten {
                path: "/tmp/u8.sock".into(),
            },
        )
        .await;
}

/// Fork/exec special-case tests: Node.js, script file narrowing, contamination.
pub(super) async fn fork_special_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    let bash = |cmd: &str| -> Vec<String> { vec!["bash".into(), "-c".into(), cmd.into()] };

    eprintln!("[special] === Node.js Exec Tests ===");

    // X26: Direct Node.js execution from worker.
    let resp = r
        .send(
            "A",
            exec(vec![
                "/usr/local/bin/node".into(),
                "-e".into(),
                "console.log('node_ok')".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("node_ok"));
    r.record("X26.node_direct", "A", pass, &format!("{resp:?}"));

    // X27: Node.js from depth-2 worker.
    let resp = r
        .send(
            "AA",
            exec(vec![
                "/usr/local/bin/node".into(),
                "-e".into(),
                "console.log('node_deep_ok')".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("node_deep_ok"));
    r.record("X27.node_deep", "AA", pass, &format!("{resp:?}"));

    // X28: Script file that echoes (baseline, no node).
    let resp = r
        .send(
            "A",
            exec(bash(
                "echo '#!/usr/bin/bash' > /tmp/x28.sh && \
                 echo 'echo script_echo_ok' >> /tmp/x28.sh && \
                 chmod +x /tmp/x28.sh && \
                 /tmp/x28.sh; \
                 EXIT=$?; rm -f /tmp/x28.sh; exit $EXIT",
            )),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("script_echo_ok"));
    r.record("X28.script_file_echo", "A", pass, &format!("{resp:?}"));

    // X28b: Script file that runs node.
    let resp = r
        .send(
            "A",
            exec(bash(
                "echo '#!/usr/bin/bash' > /tmp/x28b.sh && \
                 echo '/usr/local/bin/node -e \"console.log(\\\"script_node_ok\\\")\"' >> /tmp/x28b.sh && \
                 chmod +x /tmp/x28b.sh && \
                 /tmp/x28b.sh; \
                 EXIT=$?; rm -f /tmp/x28b.sh; exit $EXIT",
            )),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("script_node_ok"));
    r.record("X28b.script_file_node", "A", pass, &format!("{resp:?}"));

    // X28c: Script file with env shebang.
    let resp = r
        .send(
            "A",
            exec(bash(
                "echo '#!/usr/bin/env bash' > /tmp/x28c.sh && \
                 echo '/usr/local/bin/node -e \"console.log(\\\"script_env_ok\\\")\"' >> /tmp/x28c.sh && \
                 chmod +x /tmp/x28c.sh && \
                 /tmp/x28c.sh; \
                 EXIT=$?; rm -f /tmp/x28c.sh; exit $EXIT",
            )),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("script_env_ok"));
    r.record("X28c.script_file_env", "A", pass, &format!("{resp:?}"));

    // X29: Node.js process.stdout.write.
    let resp = r
        .send(
            "A",
            exec(vec![
                "/usr/local/bin/node".into(),
                "-e".into(),
                "process.stdout.write('stdout_write_ok\\n')".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("stdout_write_ok"));
    r.record("X29.node_stdout_write", "A", pass, &format!("{resp:?}"));

    // X30: Script file runs cat (isolates: is it any binary from script or node-specific?).
    let resp = r
        .send(
            "A",
            exec(bash(
                "echo '#!/usr/bin/bash' > /tmp/x30.sh && \
                 echo 'echo cat_input | cat' >> /tmp/x30.sh && \
                 chmod +x /tmp/x30.sh && \
                 /tmp/x30.sh; \
                 EXIT=$?; rm -f /tmp/x30.sh; exit $EXIT",
            )),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("cat_input"));
    r.record("X30.script_file_cat", "A", pass, &format!("{resp:?}"));

    // X31: Nested bash invocation (same depth as X28b but no script file).
    let resp = r
        .send(
            "A",
            exec(bash(
                "bash -c '/usr/local/bin/node -e \"console.log(\\\"nested_ok\\\")\"'",
            )),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("nested_ok"));
    r.record("X31.nested_bash_node", "A", pass, &format!("{resp:?}"));

    // X32: Script file runs self_exe echo-test.
    let resp = r
        .send(
            "A",
            exec(bash(&format!(
                "echo '#!/usr/bin/bash' > /tmp/x32.sh && \
                 echo '{self_exe} echo-test' >> /tmp/x32.sh && \
                 chmod +x /tmp/x32.sh && \
                 /tmp/x32.sh; \
                 EXIT=$?; rm -f /tmp/x32.sh; exit $EXIT"
            ))),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X32.script_file_self_exe", "A", pass, &format!("{resp:?}"));

    // X33: Script file with exec node (replaces bash, no extra fork).
    let resp = r
        .send(
            "A",
            exec(bash(
                "echo '#!/usr/bin/bash' > /tmp/x33.sh && \
                 echo 'exec /usr/local/bin/node -e \"console.log(\\\"exec_ok\\\")\"' >> /tmp/x33.sh && \
                 chmod +x /tmp/x33.sh && \
                 /tmp/x33.sh; \
                 EXIT=$?; rm -f /tmp/x33.sh; exit $EXIT",
            )),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("exec_ok"));
    r.record("X33.script_file_exec_node", "A", pass, &format!("{resp:?}"));

    // X48: Node.js os.networkInterfaces().
    let resp = r
        .send(
            "A",
            super::exec_timeout(
                vec![
                    "/usr/local/bin/node".into(),
                    "-e".into(),
                    "try { const r = require('os').networkInterfaces(); \
                     console.log('NETIF_OK:' + Object.keys(r).length); } \
                     catch(e) { console.log('NETIF_ERR:' + e.code); }"
                        .into(),
                ],
                30,
            ),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
        if stdout.contains("NETIF_OK:") || stdout.contains("NETIF_ERR:"));
    r.record(
        "X48.node_networkInterfaces",
        "A",
        pass,
        &format!("{resp:?}"),
    );

    eprintln!("[special] === Pipe Contamination Tests ===");

    // X43: Init-level contamination.
    let resp = r.send("A", exec(vec!["/nonpie-echo".into()])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record(
            "X43.init_contamination",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
    } else {
        let resp2 = r
            .send("A", exec(vec![self_exe.clone(), "echo-test".into()]))
            .await;
        let pass = matches!(&resp2, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
        r.record("X43.init_contamination", "A", pass, &format!("{resp2:?}"));
    }

    // X44: Child-level contamination.
    let resp = r
        .send(
            "A",
            exec(bash(
                "if [ -x /nonpie-echo ]; then \
                 /nonpie-echo >/dev/null 2>&1; \
                 echo CHILD_CLEAN; \
                 else echo SKIP; fi",
            )),
        )
        .await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP"));
    if skipped {
        r.record(
            "X44.child_contamination",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() == "CHILD_CLEAN");
        r.record("X44.child_contamination", "A", pass, &format!("{resp:?}"));
    }

    // X45: Child-level sequential.
    let resp = r
        .send(
            "A",
            exec(bash(&format!(
                "if [ -x /nonpie-echo ]; then \
                 FIRST=$(/nonpie-echo); \
                 SECOND=$({self_exe} echo-test); \
                 echo \"first=$FIRST\"; \
                 echo \"second=$SECOND\"; \
                 else echo SKIP; fi"
            ))),
        )
        .await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP"));
    if skipped {
        r.record(
            "X45.child_sequential",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
            if stdout.contains("first=NONPIE_OK") && stdout.contains("second=ECHO_TEST_OK"));
        r.record("X45.child_sequential", "A", pass, &format!("{resp:?}"));
    }

    // X46: Grandchild-level non-PIE.
    let resp = r
        .send(
            "A",
            exec(bash(
                "if [ -x /nonpie-echo ]; then \
                 bash -c '/nonpie-echo'; \
                 else echo SKIP; fi",
            )),
        )
        .await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP"));
    if skipped {
        r.record(
            "X46.grandchild_nonpie",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record("X46.grandchild_nonpie", "A", pass, &format!("{resp:?}"));
    }

    // X47: Depth-2 contamination.
    let resp = r
        .send(
            "A",
            exec(bash(&format!(
                "if [ -x /nonpie-echo ]; then \
                 bash -c '/nonpie-echo >/dev/null; {self_exe} echo-test'; \
                 else echo SKIP; fi"
            ))),
        )
        .await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP"));
    if skipped {
        r.record(
            "X47.grandchild_contamination",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
        r.record(
            "X47.grandchild_contamination",
            "A",
            pass,
            &format!("{resp:?}"),
        );
    }
}

/// Contamination isolation sequence tests (X49-X59).
/// These are inherently sequential — each test depends on the state left
/// by prior execs on the same agent.
pub(super) async fn contamination_sequence_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    let bash = |cmd: &str| -> Vec<String> { vec!["bash".into(), "-c".into(), cmd.into()] };

    eprintln!("[special] === Contamination Sequence Tests ===");

    // X49: Two sequential PIE execs from the same agent.
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

    // X50: PIE exec after a non-PIE exec.
    let resp = r.send("A", exec(vec!["/nonpie-echo".into()])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record(
            "X50a.nonpie_then_pie_1",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
        r.record(
            "X50b.nonpie_then_pie_2",
            "A",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
    } else {
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
        r.record("X50a.nonpie_then_pie_1", "A", pass, &format!("{resp:?}"));

        let resp = r
            .send("A", exec(vec![self_exe.clone(), "echo-test".into()]))
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
        r.record("X50b.nonpie_then_pie_2", "A", pass, &format!("{resp:?}"));
    }

    // X51: Non-PIE on fresh agent B.
    let resp = r.send("B", exec(vec!["/nonpie-echo".into()])).await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record(
            "X51.nonpie_fresh_agent",
            "B",
            true,
            "skipped (nonpie-echo not in rootfs)",
        );
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
            let resp = r
                .send("B", exec(vec![self_exe.clone(), "echo-test".into()]))
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
            results.push((format!("{resp:?}"), pass));

            let resp = r.send("B", exec(vec!["/nonpie-echo".into()])).await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
            results.push((format!("{resp:?}"), pass));

            let resp = r
                .send("B", exec(vec![self_exe.clone(), "echo-test".into()]))
                .await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
            results.push((format!("{resp:?}"), pass));

            let resp = r.send("B", exec(vec!["/nonpie-echo".into()])).await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("NONPIE_OK"));
            results.push((format!("{resp:?}"), pass));
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
