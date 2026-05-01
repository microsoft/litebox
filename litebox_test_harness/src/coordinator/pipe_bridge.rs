// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Pipe bridge tests — extra pipe/socketpair fds across fork+exec.
//!
//! Tests the VS Code `child_process.fork()` pattern where extra pipes
//! beyond stdio (fds 0-2) must survive exec.  In litebox, non-PIE exec
//! goes through `exec_on_remote_host`, which currently only bridges
//! unix socket fds.  Regular pipe fds are NOT bridged, causing the
//! parent to block forever (the code-server ↔ ptyHost IPC bug).
//!
//! Test axes:
//!   - Direction: child→parent (c2p), parent→child (p2c)
//!   - Fd type: pipe (unidirectional), socketpair (bidirectional)
//!   - Binary: PIE (in-process exec), non-PIE (exec_on_remote_host)
//!   - Count: single pipe, multiple pipes
//!   - Agent topology: various depths (A, AA, B, NP, D4)

use super::{TestRunner, exec_timeout};
use crate::protocol::Response;

/// Agents for pipe bridge tests.  Includes depths 1-2 and the
/// non-PIE worker agent (NP) to test nested worker-exec.
const PB_AGENTS: &[&str] = &["A", "AA", "B"];

/// Run all pipe bridge tests.
pub(crate) async fn pipe_bridge_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    let nonpie = crate::find_nonpie_binary();

    eprintln!(
        "[pipe-bridge] === Extra Pipe Fd Bridge Tests ({} agents, nonpie={}) ===",
        PB_AGENTS.len(),
        nonpie.is_some(),
    );

    // ─── PB.c2p: child→parent via extra pipe fd (not stdio) ─────────
    eprintln!("[pipe-bridge] --- PB.c2p (child→parent extra pipe) ---");
    for &agent in PB_AGENTS {
        // PIE child: delayed fork handles pipe bridging → should pass.
        let test = format!("PB.c2p.pie.{agent}");
        let resp = r
            .send(
                agent,
                exec_timeout(
                    vec![
                        self_exe.clone(),
                        "pipe-test".into(),
                        "extra-pipe-c2p".into(),
                        self_exe.clone(),
                    ],
                    20,
                ),
            )
            .await;
        let pass = matches!(
            &resp,
            Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("PB_C2P_OK")
        );
        r.record(&test, agent, pass, &format!("{resp:?}"));
    }

    // Non-PIE child: exec_on_remote_host → pipe NOT bridged → expected FAIL.
    if let Some(ref nonpie_bin) = nonpie {
        for &agent in PB_AGENTS {
            let test = format!("PB.c2p.nonpie.{agent}");
            let resp = r
                .send(
                    agent,
                    exec_timeout(
                        vec![
                            self_exe.clone(),
                            "pipe-test".into(),
                            "extra-pipe-c2p".into(),
                            nonpie_bin.clone(),
                        ],
                        20,
                    ),
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("PB_C2P_OK")
            );
            r.record(&test, agent, pass, &format!("{resp:?}"));
        }
    } else {
        for &agent in PB_AGENTS {
            r.record(
                &format!("PB.c2p.nonpie.{agent}"),
                agent,
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
        }
    }

    // ─── PB.p2c: parent→child via extra pipe fd ─────────────────────
    eprintln!("[pipe-bridge] --- PB.p2c (parent→child extra pipe) ---");
    for &agent in PB_AGENTS {
        let test = format!("PB.p2c.pie.{agent}");
        let resp = r
            .send(
                agent,
                exec_timeout(
                    vec![
                        self_exe.clone(),
                        "pipe-test".into(),
                        "extra-pipe-p2c".into(),
                        self_exe.clone(),
                    ],
                    20,
                ),
            )
            .await;
        let pass = matches!(
            &resp,
            Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("PB_P2C_OK")
        );
        r.record(&test, agent, pass, &format!("{resp:?}"));
    }

    if let Some(ref nonpie_bin) = nonpie {
        for &agent in PB_AGENTS {
            let test = format!("PB.p2c.nonpie.{agent}");
            let resp = r
                .send(
                    agent,
                    exec_timeout(
                        vec![
                            self_exe.clone(),
                            "pipe-test".into(),
                            "extra-pipe-p2c".into(),
                            nonpie_bin.clone(),
                        ],
                        20,
                    ),
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("PB_P2C_OK")
            );
            r.record(&test, agent, pass, &format!("{resp:?}"));
        }
    } else {
        for &agent in PB_AGENTS {
            r.record(
                &format!("PB.p2c.nonpie.{agent}"),
                agent,
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
        }
    }

    // ─── PB.multi: multiple extra pipes ─────────────────────────────
    eprintln!("[pipe-bridge] --- PB.multi (3 extra pipes) ---");
    for &agent in PB_AGENTS {
        let test = format!("PB.multi.pie.{agent}");
        let resp = r
            .send(
                agent,
                exec_timeout(
                    vec![
                        self_exe.clone(),
                        "pipe-test".into(),
                        "extra-pipe-multi".into(),
                        self_exe.clone(),
                        "3".into(),
                    ],
                    20,
                ),
            )
            .await;
        let pass = matches!(
            &resp,
            Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("PB_MULTI_OK")
        );
        r.record(&test, agent, pass, &format!("{resp:?}"));
    }

    if let Some(ref nonpie_bin) = nonpie {
        for &agent in PB_AGENTS {
            let test = format!("PB.multi.nonpie.{agent}");
            let resp = r
                .send(
                    agent,
                    exec_timeout(
                        vec![
                            self_exe.clone(),
                            "pipe-test".into(),
                            "extra-pipe-multi".into(),
                            nonpie_bin.clone(),
                            "3".into(),
                        ],
                        20,
                    ),
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("PB_MULTI_OK")
            );
            r.record(&test, agent, pass, &format!("{resp:?}"));
        }
    } else {
        for &agent in PB_AGENTS {
            r.record(
                &format!("PB.multi.nonpie.{agent}"),
                agent,
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
        }
    }

    // ─── PB.sp: extra AF_UNIX socketpair (positive control) ────────
    // exec_on_remote_host already bridges unix socket fds.  This
    // verifies the bridge mechanism itself works correctly.
    eprintln!("[pipe-bridge] --- PB.sp (extra socketpair) ---");
    for &agent in PB_AGENTS {
        let test = format!("PB.sp.pie.{agent}");
        let resp = r
            .send(
                agent,
                exec_timeout(
                    vec![
                        self_exe.clone(),
                        "pipe-test".into(),
                        "extra-socketpair".into(),
                        self_exe.clone(),
                    ],
                    20,
                ),
            )
            .await;
        let pass = matches!(
            &resp,
            Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("PB_SP_OK")
        );
        r.record(&test, agent, pass, &format!("{resp:?}"));
    }

    if let Some(ref nonpie_bin) = nonpie {
        for &agent in PB_AGENTS {
            let test = format!("PB.sp.nonpie.{agent}");
            let resp = r
                .send(
                    agent,
                    exec_timeout(
                        vec![
                            self_exe.clone(),
                            "pipe-test".into(),
                            "extra-socketpair".into(),
                            nonpie_bin.clone(),
                        ],
                        20,
                    ),
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("PB_SP_OK")
            );
            r.record(&test, agent, pass, &format!("{resp:?}"));
        }
    } else {
        for &agent in PB_AGENTS {
            r.record(
                &format!("PB.sp.nonpie.{agent}"),
                agent,
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
        }
    }

    // ─── PB.xworker: run from non-PIE worker agent (nested exec) ───
    // Tests the pattern where a non-PIE worker (like node) forks another
    // process.  This is exactly what VS Code does: node (non-PIE, in
    // worker-exec) forks ptyHost (another node instance).
    let xworker_agents: &[&str] = &["NP", "D4"];
    eprintln!("[pipe-bridge] --- PB.xworker (from non-PIE worker agents) ---");
    for &agent in xworker_agents {
        // PIE child from a non-PIE worker agent.
        let test = format!("PB.c2p.xworker_pie.{agent}");
        let resp = r
            .send(
                agent,
                exec_timeout(
                    vec![
                        self_exe.clone(),
                        "pipe-test".into(),
                        "extra-pipe-c2p".into(),
                        self_exe.clone(),
                    ],
                    20,
                ),
            )
            .await;
        let pass = matches!(
            &resp,
            Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("PB_C2P_OK")
        );
        r.record(&test, agent, pass, &format!("{resp:?}"));

        // Non-PIE child from a non-PIE worker agent (double worker-exec).
        if let Some(ref nonpie_bin) = nonpie {
            let test = format!("PB.c2p.xworker_nonpie.{agent}");
            let resp = r
                .send(
                    agent,
                    exec_timeout(
                        vec![
                            self_exe.clone(),
                            "pipe-test".into(),
                            "extra-pipe-c2p".into(),
                            nonpie_bin.clone(),
                        ],
                        20,
                    ),
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("PB_C2P_OK")
            );
            r.record(&test, agent, pass, &format!("{resp:?}"));
        }
    }

    // ─── PB.many: many extra pipes (fd collision stress test) ───────
    // Creates 10 pipes (fds 3-22) before fork+exec(nonpie).  This
    // forces bridge guest fd numbers (3, 5, 7, ...) to overlap with
    // the worker's infrastructure fds (exec_image_fd ~5, result_fd ~8).
    // Without proper fd range separation, posix_spawn's dup2 for the
    // bridge clobbers the infrastructure memfd and the worker hangs.
    eprintln!("[pipe-bridge] --- PB.many (10 pipes, fd collision stress) ---");
    for &agent in PB_AGENTS {
        let test = format!("PB.many.pie.{agent}");
        let resp = r
            .send(
                agent,
                exec_timeout(
                    vec![
                        self_exe.clone(),
                        "pipe-test".into(),
                        "extra-pipe-multi".into(),
                        self_exe.clone(),
                        "10".into(),
                    ],
                    20,
                ),
            )
            .await;
        let pass = matches!(
            &resp,
            Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("PB_MULTI_OK")
        );
        r.record(&test, agent, pass, &format!("{resp:?}"));
    }

    if let Some(ref nonpie_bin) = nonpie {
        for &agent in PB_AGENTS {
            let test = format!("PB.many.nonpie.{agent}");
            let resp = r
                .send(
                    agent,
                    exec_timeout(
                        vec![
                            self_exe.clone(),
                            "pipe-test".into(),
                            "extra-pipe-multi".into(),
                            nonpie_bin.clone(),
                            "10".into(),
                        ],
                        20,
                    ),
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("PB_MULTI_OK")
            );
            r.record(&test, agent, pass, &format!("{resp:?}"));
        }
    } else {
        for &agent in PB_AGENTS {
            r.record(
                &format!("PB.many.nonpie.{agent}"),
                agent,
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
        }
    }

    // ─── PB.epoll: epoll wakeup on pipe bridge ─────────────────────
    // Tests the VS Code ptyHost pattern: parent uses epoll_wait to
    // detect data from a child worker. If the bridge relay doesn't
    // wake the epoll Pollee, the parent blocks until timeout.
    eprintln!("[pipe-bridge] --- PB.epoll (epoll wakeup on pipe bridge) ---");
    for &agent in PB_AGENTS {
        let test = format!("PB.epoll.pie.{agent}");
        let resp = r
            .send(
                agent,
                exec_timeout(
                    vec![
                        self_exe.clone(),
                        "pipe-test".into(),
                        "epoll-pipe-bridge".into(),
                        self_exe.clone(),
                        "200".into(),
                    ],
                    15,
                ),
            )
            .await;
        let pass = matches!(
            &resp,
            Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("EPOLL_BRIDGE_OK")
        );
        r.record(&test, agent, pass, &format!("{resp:?}"));
    }

    if let Some(ref nonpie_bin) = nonpie {
        for &agent in PB_AGENTS {
            let test = format!("PB.epoll.nonpie.{agent}");
            let resp = r
                .send(
                    agent,
                    exec_timeout(
                        vec![
                            self_exe.clone(),
                            "pipe-test".into(),
                            "epoll-pipe-bridge".into(),
                            nonpie_bin.clone(),
                            "200".into(),
                        ],
                        15,
                    ),
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("EPOLL_BRIDGE_OK")
            );
            r.record(&test, agent, pass, &format!("{resp:?}"));
        }
    } else {
        for &agent in PB_AGENTS {
            r.record(
                &format!("PB.epoll.nonpie.{agent}"),
                agent,
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
        }
    }
}
