// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform fix validation tests — matrix-loop tests that prove specific bug
//! fixes are needed by exercising the exact behavior each fix corrected.
//!
//! Each test category targets a commit in the wportnoy/vscode-server-in-litebox
//! branch and must pass on both native WSL2 (gold standard) and litebox.

use crate::protocol::{Command, Response};
use tokio::time::Duration;

const AGENTS: &[&str] = &["A", "AA", "B"];
const DEPTH_AGENTS: &[&str] = &["A", "AA"];

// ═══════════════════════════════════════════════════════════════════
// POLL: epoll/ppoll IN events (fix 0fb258e2)
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// GSN: getsockname port after bind (fix 336dc79e)
// ═══════════════════════════════════════════════════════════════════

const FAMILIES: &[&str] = &["ipv4", "ipv6"];

// ═══════════════════════════════════════════════════════════════════
// PID: monotonic pipe pair_id (fix c2d0abdc)
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// EXITD: bridge thread join before exit (fix 2def3ac6)
// ═══════════════════════════════════════════════════════════════════

const EXIT_SIZES: &[usize] = &[256, 4096, 65536];
const EXIT_BINARIES: &[&str] = &["pie", "nonpie"];

// ═══════════════════════════════════════════════════════════════════
// NPIPE: non-PIE pipe chain integrity (fix febc3e41)
// ═══════════════════════════════════════════════════════════════════

const NPIPE_REPS: &[usize] = &[1, 5, 10];

/// Run all platform fix validation tests.

// ═══════════════════════════════════════════════════════════════════
// XCONN: cross-worker TCP — first connection must succeed
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// XCONN.self: same-worker loopback (VS Code pattern)
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// BASH: bash fork+exec of child commands
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// FORK-FROM-WORKER-EXEC: fork+exec from non-PIE worker-exec hosts
// (reproduces VS Code ptyHost/extensionHost spawn hang)
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// CWF: Cross-worker file coherence
// (9P broker concurrent read-while-write across worker sessions)
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// SC: $() command substitution capture — various commands
// (readlink -f failure blocks VS Code Server startup)
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// CC: Concurrent fork/exec/pipe tests
// (stress test delayed-fork, CoW, pipe bridging under concurrency)
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// TR: Touch + redirect file coherence
// (9P cache stale inode after touch + fork+exec redirect)
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// KP: PID and /proc visibility across delayed-fork migration
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// FR: File-Redirect — stdout of background process → file via redirect
// (discovered during cross-worker TCP debugging: nc prints to stdout
// but the redirected file stays empty)
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// PN: Pipe Non-blocking — fcntl F_SETFL O_NONBLOCK on pipes
// (dropbear sets pipes non-blocking for its event loop; if F_SETFL
// silently fails, read() returns 0/EOF instead of EAGAIN, causing
// a busy-loop that starves the network worker and blocks new SSH
// connections including the VS Code SOCKS tunnel)
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// EP: Epoll + Socket wakeup — epoll_wait must wake when TCP data arrives
// (the tokio pattern: epoll_wait → futex park → data arrives → must wake)
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// LB: Loopback TCP across delayed-fork workers
// (VS Code exec server uses SOCKS proxy → TCP loopback to CLI port)
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// FKLC: fork-listen-close — VS Code CLI pattern
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// PROC: /proc filesystem tests
// ═══════════════════════════════════════════════════════════════════

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
            timeout_secs: 60,
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
                timeout_secs: 60,
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
            timeout_secs: 60,
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
                    timeout_secs: 60,
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
                timeout_secs: 60,
                run: Box::new(move |r| {
                    let a = agent_s.clone();
                    let _self_exe = r.self_exe.clone();
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
                timeout_secs: 60,
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
            timeout_secs: 60,
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
            timeout_secs: 60,
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
            timeout_secs: 60,
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
            timeout_secs: 60,
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
            timeout_secs: 60,
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
            timeout_secs: 60,
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
            timeout_secs: 60,
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
            timeout_secs: 60,
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
            timeout_secs: 60,
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
            timeout_secs: 60,
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
            timeout_secs: 60,
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
            timeout_secs: 60,
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
            timeout_secs: 60,
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
            timeout_secs: 60,
            run: Box::new(move |r| {
                let _self_exe = r.self_exe.clone();
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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
            timeout_secs: 60,
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
                    timeout_secs: 60,
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
                timeout_secs: 60,
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
            timeout_secs: 60,
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
            timeout_secs: 60,
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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
                timeout_secs: 60,
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

// ═══════════════════════════════════════════════════════════════════
// SK: SIGKILL of a parent agent whose subtree contains SpawnRemote
// (non-PIE) descendants. Reproduces the production hang we hit in
// `cargo test -- 'litebox::PN.B.eof'`: the harness coordinator
// SIGKILLs agent A in teardown, but A's vfork-child stub thread that
// did `wait_worker_host(NP_host_pid)` blocks A's process from being
// reaped because the non-PIE host worker (NP) is never sent a signal.
// The cascading effect is that the coordinator's `Child::wait()` for A
// can hang indefinitely, plus orphan host workers remain alive after
// container shutdown.
//
// Each test spawns its own fresh agent E — independent of the global
// matrix — builds the suspect subtree shape, then SIGKILLs E and
// asserts that the wait completes within a small wall-clock budget.
// On native this is sub-second; under litebox with the platform bug
// unfixed the wait will not return and these tests time out (FAIL).
//
// No `xfail` is recorded: a real FAIL on litebox is the desired
// signal that the underlying platform bug needs fixing. The test
// harness's own teardown is wrapped in a 10-s timeout (commit
// f99cac06), so a FAIL here does not stall the docker container.
// ═══════════════════════════════════════════════════════════════════

/// Wall-clock budget for `Child::wait()` after SIGKILL. Native
/// completes in < 50 ms; we give 5 s to absorb tokio scheduling
/// jitter under heavy parallelism without masking real hangs.
const SK_WAIT_BUDGET_SECS: u64 = 5;

/// Per-test outer budget. Must exceed SpawnRemote setup cost
/// (the broker rewrites a 124 MB binary on first use, plus the
/// well-known `spawn_nonpie_subtree` 30-s timeout under litebox).
const SK_TEST_TIMEOUT_SECS: u64 = 90;

pub(crate) fn register_subtree_kill_tests() -> Vec<super::Test> {
    let mut tests = Vec::new();

    // SK.subtree.direct_nonpie — SIGKILL E whose immediate child is a
    // non-PIE worker spawned via SpawnRemote. Reproduces the exact
    // shape that hung the PN.B.eof teardown.
    tests.push(super::Test {
        suite: "matrix",
        group: "subtree_kill",
        id: "SK.subtree.direct_nonpie".to_string(),
        xfail: None,
        timeout_secs: SK_TEST_TIMEOUT_SECS,
        run: Box::new(|r| {
            let self_exe = r.self_exe.clone();
            Box::pin(async move {
                if crate::find_nonpie_binary().is_none() {
                    return super::TestOutcome::new(
                        "?",
                        false,
                        "FAIL: nonpie binary not found — mount at /opt/nonpie",
                    );
                }
                run_subtree_kill(&self_exe, |e| {
                    Box::pin(async move {
                        let r = super::send_cmd(
                            e,
                            &Command::SpawnRemote {
                                children: vec!["NPx".into()],
                            },
                        )
                        .await;
                        if !matches!(r, Response::Ok { .. }) {
                            return Err(format!("SpawnRemote failed: {r:?}"));
                        }
                        Ok(())
                    })
                })
                .await
            })
        }),
    });

    // SK.subtree.deep_nonpie — SIGKILL E whose subtree is
    // E → EE → NPx (non-PIE leaf). Generalizes the depth axis: tests
    // that the wait4 stub at the *grandchild* level still propagates
    // back when the *root* is SIGKILLed.
    tests.push(super::Test {
        suite: "matrix",
        group: "subtree_kill",
        id: "SK.subtree.deep_nonpie".to_string(),
        xfail: None,
        timeout_secs: SK_TEST_TIMEOUT_SECS,
        run: Box::new(|r| {
            let self_exe = r.self_exe.clone();
            Box::pin(async move {
                if crate::find_nonpie_binary().is_none() {
                    return super::TestOutcome::new(
                        "?",
                        false,
                        "FAIL: nonpie binary not found — mount at /opt/nonpie",
                    );
                }
                run_subtree_kill(&self_exe, |e| {
                    Box::pin(async move {
                        let r = super::send_cmd(
                            e,
                            &Command::Spawn {
                                children: vec!["EE".into()],
                            },
                        )
                        .await;
                        if !matches!(r, Response::Ok { .. }) {
                            return Err(format!("Spawn EE failed: {r:?}"));
                        }
                        let r = super::send_cmd(
                            e,
                            &Command::Forward {
                                target: "EE".into(),
                                inner: Box::new(Command::SpawnRemote {
                                    children: vec!["NPx".into()],
                                }),
                            },
                        )
                        .await;
                        if !matches!(r, Response::Ok { .. }) {
                            return Err(format!("EE.SpawnRemote(NPx) failed: {r:?}"));
                        }
                        Ok(())
                    })
                })
                .await
            })
        }),
    });

    // SK.subtree.exit_then_kill — cooperative Exit on the non-PIE
    // descendant first, then SIGKILL the root. Inverts the timing
    // relative to direct_nonpie: by the time the root is killed, the
    // wait_worker_host stub thread has already seen its host worker
    // exit. SIGKILL+wait should be especially fast. If this also
    // hangs, the bug is in stub-thread cleanup itself, not in
    // worker-exit-signal propagation.
    tests.push(super::Test {
        suite: "matrix",
        group: "subtree_kill",
        id: "SK.subtree.exit_then_kill".to_string(),
        xfail: None,
        timeout_secs: SK_TEST_TIMEOUT_SECS,
        run: Box::new(|r| {
            let self_exe = r.self_exe.clone();
            Box::pin(async move {
                if crate::find_nonpie_binary().is_none() {
                    return super::TestOutcome::new(
                        "?",
                        false,
                        "FAIL: nonpie binary not found — mount at /opt/nonpie",
                    );
                }
                run_subtree_kill(&self_exe, |e| {
                    Box::pin(async move {
                        let r = super::send_cmd(
                            e,
                            &Command::SpawnRemote {
                                children: vec!["NPx".into()],
                            },
                        )
                        .await;
                        if !matches!(r, Response::Ok { .. }) {
                            return Err(format!("SpawnRemote failed: {r:?}"));
                        }
                        // Cooperative shutdown of the non-PIE descendant
                        // before we kill the root. Forward(Exit) reaches
                        // NPx via E. If the response stream desyncs we
                        // ignore — the goal is just to make NPx exit.
                        let _ = super::send_cmd(
                            e,
                            &Command::Forward {
                                target: "NPx".into(),
                                inner: Box::new(Command::Exit),
                            },
                        )
                        .await;
                        Ok(())
                    })
                })
                .await
            })
        }),
    });

    tests
}

/// Spawn a fresh ephemeral agent E, run the caller-supplied subtree
/// builder against it, then SIGKILL E and time the `wait()`. Returns
/// pass=true only if `wait()` returns within `SK_WAIT_BUDGET_SECS`.
async fn run_subtree_kill<F>(self_exe: &str, build: F) -> super::TestOutcome
where
    F: for<'a> FnOnce(
        &'a mut super::Child,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>,
    >,
{
    let mut e = match super::spawn_child(self_exe).await {
        Ok(c) => c,
        Err(err) => return super::TestOutcome::new("E", false, format!("spawn_child: {err}")),
    };

    if let Err(detail) = build(&mut e).await {
        // Best-effort cleanup before reporting the setup failure.
        let _ = e.process.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(2), e.process.wait()).await;
        return super::TestOutcome::new("E", false, format!("setup: {detail}"));
    }

    // Send SIGKILL via tokio's start_kill (non-async; just delivers
    // the signal). Then time how long the kernel takes to report the
    // child as reapable. Under litebox the wait can hang because of
    // un-reaped wait_worker_host stub threads in vfork descendants.
    let send_ok = e.process.start_kill().is_ok();
    let t0 = std::time::Instant::now();
    let wait_res =
        tokio::time::timeout(Duration::from_secs(SK_WAIT_BUDGET_SECS), e.process.wait()).await;
    let elapsed = t0.elapsed();

    let pass = send_ok && matches!(wait_res, Ok(Ok(_)));
    let detail = format!(
        "send_ok={send_ok} wait={} elapsed={}ms budget={}s",
        match &wait_res {
            Ok(Ok(s)) => format!("Ok({s:?})"),
            Ok(Err(err)) => format!("Err({err})"),
            Err(_) => "TIMEOUT".to_string(),
        },
        elapsed.as_millis(),
        SK_WAIT_BUDGET_SECS,
    );
    super::TestOutcome::new("E", pass, detail)
}
