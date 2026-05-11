// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Concurrent fork tests — bash pipelines and parallel subprocesses that
//! exercise concurrent 9P file operations from multiple forked children
//! in the same worker.
//!
//! The VS Code install script runs `cat /proc/... | grep ... | sed ... | sed ...`
//! inside the litebox sandbox.  Each pipeline child loads shared libraries
//! (libc, libpcre2, etc.) via the 9P filesystem.  If the 9P transport
//! cannot handle concurrent requests from sibling processes in the same
//! worker, the pipeline deadlocks.
//!
//! Test axes:
//!   - Pipeline depth: 2, 3, 4 commands
//!   - Command types: cat|cat, cat|grep, echo|sed|sed, cat|grep|sed|sed
//!   - Agent topology: A (depth 1), AA (depth 2), NP (non-PIE worker)
//!   - Subcommand vs bash: protocol Exec(bash -c ...) and direct fork

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

use super::agents::AgentName;
use super::registry::Registry;

/// Agents to run concurrent fork tests on.
const CF_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2];

/// Pipeline patterns with increasing concurrency and library diversity.
/// Each child in a pipeline loads different shared libraries via 9P,
/// increasing the chance of concurrent 9P requests.
struct PipelinePattern {
    name: &'static str,
    cmd: &'static str,
    expected: &'static str,
}

const PIPELINE_PATTERNS: &[PipelinePattern] = &[
    // 2-stage: minimal concurrency (2 children).
    PipelinePattern {
        name: "pipe2_cat",
        cmd: "echo pipe2_ok | cat",
        expected: "pipe2_ok",
    },
    // 3-stage: 3 children loading libs concurrently.
    PipelinePattern {
        name: "pipe3_cat",
        cmd: "echo pipe3_ok | cat | cat",
        expected: "pipe3_ok",
    },
    // 3-stage with grep (loads libpcre2 — different lib set from cat).
    PipelinePattern {
        name: "pipe3_grep",
        cmd: "echo pipe3_grep_ok | grep pipe3 | cat",
        expected: "pipe3_grep_ok",
    },
    // 4-stage: the VS Code install script pattern (cat|grep|sed|sed).
    // Each command loads different shared libraries, maximizing
    // concurrent 9P pressure.
    PipelinePattern {
        name: "pipe4_vscode",
        cmd: "echo 'pipe4_vscode_ok: test' | cat | grep pipe4 | sed 's/test/pass/'",
        expected: "pipe4_vscode_ok: pass",
    },
    // 4-stage with all different commands.
    PipelinePattern {
        name: "pipe4_mixed",
        cmd: "echo -e 'x\\npipe4_mixed_ok\\ny' | sort | grep mixed | tr '[:lower:]' '[:upper:]'",
        expected: "PIPE4_MIXED_OK",
    },
    // Sequential commands (&&) — NOT a pipeline, so no concurrent forks.
    // This is the control: if pipelines fail but sequential works,
    // the issue is concurrent 9P, not individual command execution.
    PipelinePattern {
        name: "sequential_control",
        cmd: "echo seq_a > /tmp/cf_test && cat /tmp/cf_test && rm /tmp/cf_test",
        expected: "seq_a",
    },
];

// ─── Handler shared across pipeline + xworker bash tests ────────────

#[derive(Serialize, Deserialize)]
struct BashArgs {
    cmd: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct BashOut {
    stdout: String,
    exit_code: i32,
}

const BASH: HandlerToken<BashArgs, BashOut> = HandlerToken::new("concurrent_fork.bash");

async fn handle_bash(args: BashArgs, _ctx: &mut HandlerCtx<'_>) -> Result<BashOut, HandlerError> {
    let out = tokio::process::Command::new("bash")
        .arg("-c")
        .arg(&args.cmd)
        .output()
        .await?;
    Ok(BashOut {
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        exit_code: out.status.code().unwrap_or(-1),
    })
}

/// Register concurrent fork pipeline tests.
#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_concurrent_fork_pipeline(reg: &mut Registry<'_>) {
    register_handler!(BASH, handle_bash);

    for &agent in CF_AGENTS {
        for pat in PIPELINE_PATTERNS {
            let name = pat.name;
            let cmd = pat.cmd;
            let expected = pat.expected;
            let agent_label = agent.to_string();

            reg.test(
                "xworker",
                "concurrent_fork_pipeline",
                format!("CF.{name}.{agent}"),
            )
            .timeout(90)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    Box::pin(async move {
                        let result = run
                            .send_named_typed(&handle, &BASH, BashArgs { cmd: cmd.into() })
                            .await;
                        let pass = matches!(
                            &result,
                            Ok(out) if out.exit_code == 0 && out.stdout.trim().contains(expected)
                        );
                        super::TestOutcome::new(&agent_label, pass, format!("{result:?}"))
                    })
                })
            });
        }
    }

    // xworker agents — single pipeline + sequential control on Dpg1Dng.
    #[allow(clippy::single_element_loop)]
    // loop preserved for parity with legacy + future expansion
    for &agent in &[AgentName::Dpg1Dng] {
        let agent_label = agent.to_string();
        reg.test(
            "xworker",
            "concurrent_fork_pipeline",
            format!("CF.pipe4_vscode.{agent}"),
        )
        .timeout(90)
        .build(move |cx| {
            let handle = cx.require(agent);
            Box::new(move |run| {
                Box::pin(async move {
                    let result = run
                        .send_named_typed(
                            &handle,
                            &BASH,
                            BashArgs {
                                cmd: "echo 'pipe4_vscode_ok: test' | cat | grep pipe4 \
                                      | sed 's/test/pass/'"
                                    .into(),
                            },
                        )
                        .await;
                    let pass = matches!(
                        &result,
                        Ok(out) if out.exit_code == 0
                            && out.stdout.trim().contains("pipe4_vscode_ok: pass")
                    );
                    super::TestOutcome::new(&agent_label, pass, format!("{result:?}"))
                })
            })
        });

        let agent_label = agent.to_string();
        reg.test(
            "xworker",
            "concurrent_fork_pipeline",
            format!("CF.sequential_control.{agent}"),
        )
        .timeout(90)
        .build(move |cx| {
            let handle = cx.require(agent);
            Box::new(move |run| {
                Box::pin(async move {
                    let result = run
                        .send_named_typed(
                            &handle,
                            &BASH,
                            BashArgs {
                                cmd: "echo seq_a > /tmp/cf_test && cat /tmp/cf_test \
                                      && rm /tmp/cf_test"
                                    .into(),
                            },
                        )
                        .await;
                    let pass = matches!(
                        &result,
                        Ok(out) if out.exit_code == 0 && out.stdout.trim().contains("seq_a")
                    );
                    super::TestOutcome::new(&agent_label, pass, format!("{result:?}"))
                })
            })
        });
    }
}

/// Register concurrent exec tests.
pub(crate) fn register_concurrent_exec(reg: &mut Registry<'_>) {
    for &count in &[2usize, 3, 4] {
        for &bt in crate::BinaryType::ALL {
            let bt_label = bt.label();
            for &agent in CF_AGENTS {
                let agent_label = agent.to_string();
                reg.test(
                    "xworker",
                    "concurrent_exec",
                    format!("CF.concurrent_exec_{count}.{bt_label}.{agent}"),
                )
                .timeout(90)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let agent_label = agent_label.clone();
                        Box::pin(async move {
                            let self_exe = run.self_exe().to_string();
                            let target = crate::binary_path(bt, &self_exe);
                            let cmd = (0..count)
                                .map(|_| format!("{target} echo-test &"))
                                .collect::<Vec<_>>()
                                .join(" ");
                            let full_cmd = format!("{cmd} wait");
                            let resp = run
                                .send(
                                    &handle,
                                    super::exec_timeout(
                                        vec!["bash".into(), "-c".into(), full_cmd],
                                        15,
                                    ),
                                )
                                .await;
                            let pass = match &resp {
                                crate::protocol::Response::ExecResult {
                                    exit_code: 0,
                                    stdout,
                                    ..
                                } => stdout.matches("ECHO_TEST_OK").count() == count,
                                _ => false,
                            };
                            let detail = match &resp {
                                crate::protocol::Response::ExecResult { stdout, .. } => {
                                    format!(
                                        "got {}/{count} ECHO_TEST_OK",
                                        stdout.matches("ECHO_TEST_OK").count()
                                    )
                                }
                                _ => format!("{resp:?}"),
                            };
                            super::TestOutcome::new(&agent_label, pass, detail)
                        })
                    })
                });
            }
        }
    }
}

/// Register VS Code install pipeline tests.
pub(crate) fn register_vscode_install_pipeline(reg: &mut Registry<'_>) {
    let vscode_cmds: &[(&str, &str, &str)] = &[
        ("proc_cat_grep", "cat /proc/loadavg | grep -o '[0-9]'", ""),
        (
            "proc_pipeline_3",
            "cat /proc/cpuinfo | grep -i 'model name' | head -1",
            "",
        ),
        (
            "proc_pipeline_4",
            "cat /proc/meminfo | grep MemTotal | sed 's/MemTotal://' | sed 's/ //g'",
            "kB",
        ),
        (
            "uname_pipeline",
            "uname -a | grep -o 'Linux' | head -1",
            "Linux",
        ),
    ];

    for &agent in CF_AGENTS {
        for &(name, cmd, expected) in vscode_cmds {
            let agent_label = agent.to_string();
            let cmd_s = cmd.to_string();
            let expected_s = expected.to_string();
            reg.test(
                "xworker",
                "vscode_install_pipeline",
                format!("CF.vscode.{name}.{agent}"),
            )
            .timeout(90)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    Box::pin(async move {
                        let resp = run
                            .send(
                                &handle,
                                super::exec_timeout(vec!["bash".into(), "-c".into(), cmd_s], 15),
                            )
                            .await;
                        let pass = match &resp {
                            crate::protocol::Response::ExecResult {
                                exit_code: 0,
                                stdout,
                                ..
                            } => {
                                if expected_s.is_empty() {
                                    !stdout.trim().is_empty()
                                } else {
                                    stdout.contains(&*expected_s)
                                }
                            }
                            _ => false,
                        };
                        super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                    })
                })
            });
        }
    }
}

/// Register concurrent FS rwlock tests.
pub(crate) fn register_concurrent_fs_rwlock(reg: &mut Registry<'_>) {
    for &n in &[2usize, 3, 4] {
        for &bt in crate::BinaryType::ALL {
            let bt_label = bt.label();
            for &agent in CF_AGENTS {
                let agent_label = agent.to_string();
                reg.test(
                    "xworker",
                    "concurrent_fs_rwlock",
                    format!("CF.rwlock_{n}.{bt_label}.{agent}"),
                )
                .timeout(90)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let agent_label = agent_label.clone();
                        Box::pin(async move {
                            let self_exe = run.self_exe().to_string();
                            let target = crate::binary_path(bt, &self_exe);
                            let resp = run
                                .send(
                                    &handle,
                                    super::exec_timeout(
                                        vec![target, "concurrent-fs".into(), n.to_string()],
                                        20,
                                    ),
                                )
                                .await;
                            let pass = matches!(
                                &resp,
                                crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.contains("CONCURRENT_FS_OK")
                            );
                            super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                        })
                    })
                });
            }
        }
    }

    for &n in &[3usize, 4, 6] {
        for &bt in crate::BinaryType::ALL {
            let bt_label = bt.label();
            for &agent in CF_AGENTS {
                let agent_label = agent.to_string();
                reg.test(
                    "xworker",
                    "concurrent_fs_rwlock",
                    format!("CF.rwlock_multi_{n}.{bt_label}.{agent}"),
                )
                .timeout(90)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let agent_label = agent_label.clone();
                        Box::pin(async move {
                            let self_exe = run.self_exe().to_string();
                            let target = crate::binary_path(bt, &self_exe);
                            let resp = run
                                .send(
                                    &handle,
                                    super::exec_timeout(
                                        vec![target, "concurrent-fs-multi".into(), n.to_string()],
                                        20,
                                    ),
                                )
                                .await;
                            let pass = matches!(
                                &resp,
                                crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.contains("CONCURRENT_FS_MULTI_OK")
                            );
                            super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                        })
                    })
                });
            }
        }
    }
}
