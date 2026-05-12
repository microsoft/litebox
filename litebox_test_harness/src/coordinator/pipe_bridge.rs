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

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::agents::AgentName;
use super::registry::Registry;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

#[derive(Serialize, Deserialize, Debug)]
struct BashArgs {
    cmd: String,
    timeout_ms: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct BashOut {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

const BASH: HandlerToken<BashArgs, BashOut> = HandlerToken::new("pipe_bridge.bash");

async fn handle_bash(args: BashArgs, _ctx: &mut HandlerCtx<'_>) -> Result<BashOut, HandlerError> {
    let output = tokio::time::timeout(
        Duration::from_millis(u64::from(args.timeout_ms)),
        tokio::process::Command::new("bash")
            .arg("-c")
            .arg(&args.cmd)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| HandlerError(format!("bash timed out after {} ms", args.timeout_ms)))??;

    Ok(BashOut {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code().unwrap_or(-1),
    })
}

fn bash_cmd(args: &[String]) -> String {
    args.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'='))
    {
        return arg.to_string();
    }

    format!("'{}'", arg.replace('\'', "'\\''"))
}

fn timeout_ms(seconds: u64) -> u32 {
    seconds.saturating_mul(1000).min(u64::from(u32::MAX)) as u32
}

/// Agents for pipe bridge tests.  Includes depths 1-2 and the
/// non-PIE worker agent (NP) to test nested worker-exec.
const PB_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2];

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_pipe_bridge(reg: &mut Registry<'_>) {
    register_handler!(BASH, handle_bash);

    struct PbCase {
        mode: &'static str,
        subcmd: &'static str,
        extra_args: &'static [&'static str],
        expected: &'static str,
        agents: &'static [AgentName],
        timeout: u64,
    }

    const XWORKER_AGENTS: &[AgentName] = &[AgentName::Dpg1Dng];

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
                                let mut args =
                                    vec![self_exe, "pipe-test".into(), subcmd, child_bin];
                                args.extend(extra);
                                let resp = run
                                    .send_named_typed(
                                        &handle,
                                        &BASH,
                                        BashArgs {
                                            cmd: bash_cmd(&args),
                                            timeout_ms: timeout_ms(timeout),
                                        },
                                    )
                                    .await;
                                let pass = matches!(
                                    &resp,
                                    Ok(out) if out.exit_code == 0 && out.stdout.contains(&*expected)
                                );
                                super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                            })
                        })
                    });
            }
        }
    }

    for &(mode, subcmd, expected) in &[
        ("sibling_dual.c2p", "extra-pipe-c2p", "PB_C2P_OK"),
        ("sibling_dual.p2c", "extra-pipe-p2c", "PB_P2C_OK"),
        ("sibling_dual.sp", "extra-socketpair", "PB_SP_OK"),
    ] {
        let id = format!("PB.{mode}");
        reg.test("xworker", "pipe_bridge", id)
            .timeout(90)
            .build(move |cx| {
                let left = cx.require(AgentName::Dpg1Dpg1);
                let right = cx.require(AgentName::Dpg1Dpg2);
                Box::new(move |run| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let args = |subcmd: &str| {
                            vec![
                                self_exe.clone(),
                                "pipe-test".into(),
                                subcmd.to_string(),
                                self_exe.clone(),
                            ]
                        };
                        let left_args = args(subcmd);
                        let left_resp = run
                            .send_named_typed(
                                &left,
                                &BASH,
                                BashArgs {
                                    cmd: bash_cmd(&left_args),
                                    timeout_ms: timeout_ms(20),
                                },
                            )
                            .await;
                        let right_args = args(subcmd);
                        let right_resp = run
                            .send_named_typed(
                                &right,
                                &BASH,
                                BashArgs {
                                    cmd: bash_cmd(&right_args),
                                    timeout_ms: timeout_ms(20),
                                },
                            )
                            .await;
                        let left_ok = matches!(
                            &left_resp,
                            Ok(out) if out.exit_code == 0 && out.stdout.trim() == expected
                        );
                        let right_ok = matches!(
                            &right_resp,
                            Ok(out) if out.exit_code == 0 && out.stdout.trim() == expected
                        );
                        super::TestOutcome::new(
                            "AA+AB",
                            left_ok && right_ok,
                            format!("left={left_resp:?} right={right_resp:?}"),
                        )
                    })
                })
            });
    }
}
