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
//!   - Binary: PIE (in-process exec), non-PIE (`exec_on_remote_host`)
//!   - Count: single pipe, multiple pipes
//!   - Agent topology: various depths (A, AA, B, NP, D4)

use super::agents::AgentName;
use super::registry::Registry;

/// Agents for pipe bridge tests.  Includes depths 1-2 and the
/// non-PIE worker agent (NP) to test nested worker-exec.
const PB_AGENTS: &[AgentName] = &[AgentName::A, AgentName::AA, AgentName::B];

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_pipe_bridge(reg: &mut Registry<'_>) {
    struct PbCase {
        mode: &'static str,
        subcmd: &'static str,
        extra_args: &'static [&'static str],
        expected: &'static str,
        agents: &'static [AgentName],
        timeout: u64,
    }

    const XWORKER_AGENTS: &[AgentName] = &[AgentName::NP, AgentName::D4];

    let cases: &[PbCase] = &[
        PbCase {
            mode: "c2p",
            subcmd: "extra-pipe-c2p",
            extra_args: &[],
            expected: "PB_C2P_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "p2c",
            subcmd: "extra-pipe-p2c",
            extra_args: &[],
            expected: "PB_P2C_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "multi",
            subcmd: "extra-pipe-multi",
            extra_args: &["3"],
            expected: "PB_MULTI_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "sp",
            subcmd: "extra-socketpair",
            extra_args: &[],
            expected: "PB_SP_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "c2p.xworker",
            subcmd: "extra-pipe-c2p",
            extra_args: &[],
            expected: "PB_C2P_OK",
            agents: XWORKER_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "many",
            subcmd: "extra-pipe-multi",
            extra_args: &["10"],
            expected: "PB_MULTI_OK",
            agents: PB_AGENTS,
            timeout: 20,
        },
        PbCase {
            mode: "epoll",
            subcmd: "epoll-pipe-bridge",
            extra_args: &["200"],
            expected: "EPOLL_BRIDGE_OK",
            agents: PB_AGENTS,
            timeout: 15,
        },
        PbCase {
            mode: "epoll_sp",
            subcmd: "epoll-socketpair-bridge",
            extra_args: &["500"],
            expected: "EPOLL_SP_OK",
            agents: PB_AGENTS,
            timeout: 15,
        },
    ];

    for case in cases {
        for &bt in crate::BinaryType::ALL {
            let bt_label = bt.label();
            for &agent in case.agents {
                let id = format!("PB.{}.{bt_label}.{agent}", case.mode);
                let subcmd = case.subcmd.to_string();
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
                            let extra = extra.clone();
                            let agent_label = agent_label.clone();
                            Box::pin(async move {
                                let self_exe = run.self_exe().to_string();
                                let child_bin = crate::binary_path(bt, &self_exe);
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
}
