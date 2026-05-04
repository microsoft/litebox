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

    // ─── PB.epoll_sp: epoll wakeup on socketpair bridge ────────────
    // Tests the VS Code ptyHost IPC pattern: socketpair (ReadWrite
    // HostPipeFd) with epoll_wait. Without the check_io_events fix,
    // epoll_wait returns immediately and the event loop spins.
    // The test counts spins — if > 50, the fd reports as always-ready.
    eprintln!("[pipe-bridge] --- PB.epoll_sp (epoll on socketpair bridge) ---");
    for &agent in PB_AGENTS {
        let test = format!("PB.epoll_sp.pie.{agent}");
        let resp = r
            .send(
                agent,
                exec_timeout(
                    vec![
                        self_exe.clone(),
                        "pipe-test".into(),
                        "epoll-socketpair-bridge".into(),
                        self_exe.clone(),
                        "500".into(),
                    ],
                    15,
                ),
            )
            .await;
        let pass = matches!(
            &resp,
            Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("EPOLL_SP_OK")
        );
        r.record(&test, agent, pass, &format!("{resp:?}"));
    }

    if let Some(ref nonpie_bin) = nonpie {
        for &agent in PB_AGENTS {
            let test = format!("PB.epoll_sp.nonpie.{agent}");
            let resp = r
                .send(
                    agent,
                    exec_timeout(
                        vec![
                            self_exe.clone(),
                            "pipe-test".into(),
                            "epoll-socketpair-bridge".into(),
                            nonpie_bin.clone(),
                            "500".into(),
                        ],
                        15,
                    ),
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("EPOLL_SP_OK")
            );
            r.record(&test, agent, pass, &format!("{resp:?}"));
        }
    } else {
        for &agent in PB_AGENTS {
            r.record(
                &format!("PB.epoll_sp.nonpie.{agent}"),
                agent,
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
        }
    }
}

pub(crate) fn register_pipe_bridge(tests: &mut Vec<super::Test>) {
    struct PbCase {
        mode: &'static str,
        subcmd: &'static str,
        use_nonpie: bool,
        extra_args: &'static [&'static str],
        expected: &'static str,
        agents: &'static [&'static str],
        timeout: u64,
    }

    const XWORKER_AGENTS: &[&str] = &["NP", "D4"];

    let cases: &[PbCase] = &[
        PbCase {
            mode: "c2p.pie",
            subcmd: "extra-pipe-c2p",
            use_nonpie: false,
            extra_args: &[],
            expected: "PB_C2P_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "c2p.nonpie",
            subcmd: "extra-pipe-c2p",
            use_nonpie: true,
            extra_args: &[],
            expected: "PB_C2P_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "p2c.pie",
            subcmd: "extra-pipe-p2c",
            use_nonpie: false,
            extra_args: &[],
            expected: "PB_P2C_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "p2c.nonpie",
            subcmd: "extra-pipe-p2c",
            use_nonpie: true,
            extra_args: &[],
            expected: "PB_P2C_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "multi.pie",
            subcmd: "extra-pipe-multi",
            use_nonpie: false,
            extra_args: &["3"],
            expected: "PB_MULTI_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "multi.nonpie",
            subcmd: "extra-pipe-multi",
            use_nonpie: true,
            extra_args: &["3"],
            expected: "PB_MULTI_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "sp.pie",
            subcmd: "extra-socketpair",
            use_nonpie: false,
            extra_args: &[],
            expected: "PB_SP_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "sp.nonpie",
            subcmd: "extra-socketpair",
            use_nonpie: true,
            extra_args: &[],
            expected: "PB_SP_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "c2p.xworker_pie",
            subcmd: "extra-pipe-c2p",
            use_nonpie: false,
            extra_args: &[],
            expected: "PB_C2P_OK",
            agents: XWORKER_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "c2p.xworker_nonpie",
            subcmd: "extra-pipe-c2p",
            use_nonpie: true,
            extra_args: &[],
            expected: "PB_C2P_OK",
            agents: XWORKER_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "many.pie",
            subcmd: "extra-pipe-multi",
            use_nonpie: false,
            extra_args: &["10"],
            expected: "PB_MULTI_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "many.nonpie",
            subcmd: "extra-pipe-multi",
            use_nonpie: true,
            extra_args: &["10"],
            expected: "PB_MULTI_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "epoll.pie",
            subcmd: "epoll-pipe-bridge",
            use_nonpie: false,
            extra_args: &["200"],
            expected: "EPOLL_BRIDGE_OK",
            agents: PB_AGENTS,
            timeout: 15,
        },
        PbCase {
            mode: "epoll.nonpie",
            subcmd: "epoll-pipe-bridge",
            use_nonpie: true,
            extra_args: &["200"],
            expected: "EPOLL_BRIDGE_OK",
            agents: PB_AGENTS,
            timeout: 15,
        },
        PbCase {
            mode: "epoll_sp.pie",
            subcmd: "epoll-socketpair-bridge",
            use_nonpie: false,
            extra_args: &["500"],
            expected: "EPOLL_SP_OK",
            agents: PB_AGENTS,
            timeout: 15,
        },
        PbCase {
            mode: "epoll_sp.nonpie",
            subcmd: "epoll-socketpair-bridge",
            use_nonpie: true,
            extra_args: &["500"],
            expected: "EPOLL_SP_OK",
            agents: PB_AGENTS,
            timeout: 15,
        },
    ];

    for case in cases {
        for &agent in case.agents {
            let id = format!("PB.{}.{agent}", case.mode);
            let agent_s = agent.to_string();
            let subcmd = case.subcmd.to_string();
            let use_nonpie = case.use_nonpie;
            let extra: Vec<String> = case.extra_args.iter().map(|s| s.to_string()).collect();
            let expected = case.expected.to_string();
            let timeout = case.timeout;

            tests.push(super::Test {
                suite: "xworker",
                group: "pipe_bridge",
                id,
                xfail: None,
                run: Box::new(move |r| {
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let child_bin = if use_nonpie {
                            match crate::find_nonpie_binary() {
                                Some(p) => p,
                                None => {
                                    return super::TestOutcome::new(
                                        &agent_s,
                                        false,
                                        "FAIL: nonpie binary not found",
                                    );
                                }
                            }
                        } else {
                            self_exe.clone()
                        };
                        let mut args = vec![self_exe, "pipe-test".into(), subcmd, child_bin];
                        args.extend(extra);
                        let resp = r.send(&agent_s, super::exec_timeout(args, timeout)).await;
                        let pass = matches!(
                            &resp,
                            crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.contains(&*expected)
                        );
                        super::TestOutcome::new(&agent_s, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
}
