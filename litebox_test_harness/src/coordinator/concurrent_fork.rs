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

/// Agents to run concurrent fork tests on.
const CF_AGENTS: &[&str] = &["A", "AA", "B"];

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
/// Register concurrent fork pipeline tests.
pub(crate) fn register_concurrent_fork_pipeline(tests: &mut Vec<super::Test>) {
    for &agent in CF_AGENTS {
        for pat in PIPELINE_PATTERNS {
            let name = pat.name;
            let cmd = pat.cmd;
            let expected = pat.expected;
            let agent_s = agent.to_string();
            tests.push(super::Test {
                suite: "xworker",
                group: "concurrent_fork_pipeline",
                id: format!("CF.{name}.{agent}"),
                xfail: None,
                timeout_secs: 90,
                declared_agents: Vec::new(),
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let resp = r
                            .send(
                                &agent_s,
                                super::exec_timeout(
                                    vec!["bash".into(), "-c".into(), cmd.into()],
                                    15,
                                ),
                            )
                            .await;
                        let pass = match &resp {
                            crate::protocol::Response::ExecResult {
                                exit_code: 0,
                                stdout,
                                ..
                            } => stdout.trim().contains(expected),
                            _ => false,
                        };
                        super::TestOutcome::new(&agent_s, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }

    // xworker agents
    for &agent in &["NP", "D4"] {
        let agent_s = agent.to_string();
        let agent_s2 = agent_s.clone();
        tests.push(super::Test {
            suite: "xworker",
            group: "concurrent_fork_pipeline",
            id: format!("CF.pipe4_vscode.{agent}"),
            xfail: None,
            timeout_secs: 90,
            declared_agents: Vec::new(),
            run: Box::new(move |r| {
                Box::pin(async move {
                    let resp = r
                        .send(
                            &agent_s,
                            super::exec_timeout(
                                vec![
                                    "bash".into(),
                                    "-c".into(),
                                    "echo 'pipe4_vscode_ok: test' | cat | grep pipe4 | sed 's/test/pass/'"
                                        .into(),
                                ],
                                15,
                            ),
                        )
                        .await;
                    let pass = match &resp {
                        crate::protocol::Response::ExecResult {
                            exit_code: 0,
                            stdout,
                            ..
                        } => stdout.trim().contains("pipe4_vscode_ok: pass"),
                        _ => false,
                    };
                    super::TestOutcome::new(&agent_s, pass, format!("{resp:?}"))
                })
            }),
        });

        tests.push(super::Test {
            suite: "xworker",
            group: "concurrent_fork_pipeline",
            id: format!("CF.sequential_control.{agent}"),
            xfail: None,
            timeout_secs: 90,
            declared_agents: Vec::new(),
            run: Box::new(move |r| {
                Box::pin(async move {
                    let resp = r
                        .send(
                            &agent_s2,
                            super::exec_timeout(
                                vec![
                                    "bash".into(),
                                    "-c".into(),
                                    "echo seq_a > /tmp/cf_test && cat /tmp/cf_test && rm /tmp/cf_test"
                                        .into(),
                                ],
                                15,
                            ),
                        )
                        .await;
                    let pass = match &resp {
                        crate::protocol::Response::ExecResult {
                            exit_code: 0,
                            stdout,
                            ..
                        } => stdout.trim().contains("seq_a"),
                        _ => false,
                    };
                    super::TestOutcome::new(&agent_s2, pass, format!("{resp:?}"))
                })
            }),
        });
    }
}

/// Register concurrent exec tests.
pub(crate) fn register_concurrent_exec(tests: &mut Vec<super::Test>) {
    for &count in &[2usize, 3, 4] {
        for &agent in CF_AGENTS {
            let agent_s = agent.to_string();
            tests.push(super::Test {
                suite: "xworker",
                group: "concurrent_exec",
                id: format!("CF.concurrent_exec_{count}.{agent}"),
                xfail: None,
                timeout_secs: 90,
                declared_agents: Vec::new(),
                run: Box::new(move |r| {
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let cmd = (0..count)
                            .map(|_| format!("{self_exe} echo-test &"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        let full_cmd = format!("{cmd} wait");
                        let resp = r
                            .send(
                                &agent_s,
                                super::exec_timeout(vec!["bash".into(), "-c".into(), full_cmd], 15),
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
                        super::TestOutcome::new(&agent_s, pass, detail)
                    })
                }),
            });
        }
    }
}

/// Register VS Code install pipeline tests.
pub(crate) fn register_vscode_install_pipeline(tests: &mut Vec<super::Test>) {
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
            let agent_s = agent.to_string();
            let cmd_s = cmd.to_string();
            let expected_s = expected.to_string();
            tests.push(super::Test {
                suite: "xworker",
                group: "vscode_install_pipeline",
                id: format!("CF.vscode.{name}.{agent}"),
                xfail: None,
                timeout_secs: 90,
                declared_agents: Vec::new(),
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let resp = r
                            .send(
                                &agent_s,
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
                        super::TestOutcome::new(&agent_s, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
}

/// Register concurrent FS rwlock tests.
pub(crate) fn register_concurrent_fs_rwlock(tests: &mut Vec<super::Test>) {
    for &n in &[2usize, 3, 4] {
        for &agent in CF_AGENTS {
            let agent_s = agent.to_string();
            tests.push(super::Test {
                suite: "xworker",
                group: "concurrent_fs_rwlock",
                id: format!("CF.rwlock_{n}.{agent}"),
                xfail: None,
                timeout_secs: 90,
                declared_agents: Vec::new(),
                run: Box::new(move |r| {
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let resp = r
                            .send(
                                &agent_s,
                                super::exec_timeout(
                                    vec![self_exe, "concurrent-fs".into(), n.to_string()],
                                    20,
                                ),
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.contains("CONCURRENT_FS_OK")
                        );
                        super::TestOutcome::new(&agent_s, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }

    for &n in &[3usize, 4, 6] {
        for &agent in CF_AGENTS {
            let agent_s = agent.to_string();
            tests.push(super::Test {
                suite: "xworker",
                group: "concurrent_fs_rwlock",
                id: format!("CF.rwlock_multi_{n}.{agent}"),
                xfail: None,
                timeout_secs: 90,
                declared_agents: Vec::new(),
                run: Box::new(move |r| {
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let resp = r
                            .send(
                                &agent_s,
                                super::exec_timeout(
                                    vec![self_exe, "concurrent-fs-multi".into(), n.to_string()],
                                    20,
                                ),
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.contains("CONCURRENT_FS_MULTI_OK")
                        );
                        super::TestOutcome::new(&agent_s, pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }
}
