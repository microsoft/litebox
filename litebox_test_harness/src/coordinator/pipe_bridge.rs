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

use super::agents::AgentName;
use super::registry::Registry;

/// Agents for pipe bridge tests.  Includes depths 1-2 and the
/// non-PIE worker agent (NP) to test nested worker-exec.
const PB_AGENTS: &[AgentName] = &[AgentName::A, AgentName::AA, AgentName::B];

pub(crate) fn register_pipe_bridge(reg: &mut Registry<'_>) {
    struct PbCase {
        mode: &'static str,
        subcmd: &'static str,
        use_nonpie: bool,
        extra_args: &'static [&'static str],
        expected: &'static str,
        agents: &'static [AgentName],
        timeout: u64,
    }

    const XWORKER_AGENTS: &[AgentName] = &[AgentName::NP, AgentName::D4];

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
            let subcmd = case.subcmd.to_string();
            let use_nonpie = case.use_nonpie;
            let extra: Vec<String> = case
                .extra_args
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            let expected = case.expected.to_string();
            let timeout = case.timeout;
            let agent_label = agent.to_string();

            reg.test("xworker", "pipe_bridge", id)
                .timeout(90)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        Box::pin(async move {
                            let self_exe = run.self_exe().to_string();
                            let child_bin = if use_nonpie {
                                crate::nonpie_binary()
                            } else {
                                self_exe.clone()
                            };
                            let mut args = vec![self_exe, "pipe-test".into(), subcmd, child_bin];
                            args.extend(extra);
                            let resp = run.send(&handle, super::exec_timeout(args, timeout)).await;
                            let pass = matches!(
                                &resp,
                                crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.contains(&*expected)
                            );
                            super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}
