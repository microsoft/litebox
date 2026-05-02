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

use super::{TestRunner, exec_timeout};
use crate::protocol::Response;

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

/// Run all concurrent fork pipeline tests.
pub(crate) async fn concurrent_fork_pipeline_tests(r: &mut TestRunner) {
    eprintln!(
        "[concurrent-fork] === Pipeline Tests ({} patterns × {} agents) ===",
        PIPELINE_PATTERNS.len(),
        CF_AGENTS.len(),
    );

    for &agent in CF_AGENTS {
        for pat in PIPELINE_PATTERNS {
            let test = format!("CF.{}.{agent}", pat.name);
            let resp = r
                .send(
                    agent,
                    exec_timeout(vec!["bash".into(), "-c".into(), pat.cmd.into()], 15),
                )
                .await;
            let pass = match &resp {
                Response::ExecResult {
                    exit_code: 0,
                    stdout,
                    ..
                } => stdout.trim().contains(pat.expected),
                _ => false,
            };
            r.record(&test, agent, pass, &format!("{resp:?}"));
        }
    }

    // Also test from non-PIE worker agents (NP, D4) — these run in
    // worker-exec hosts where 9P is the only filesystem.
    let xworker_agents: &[&str] = &["NP", "D4"];
    eprintln!(
        "[concurrent-fork] --- xworker pipelines ({} agents) ---",
        xworker_agents.len()
    );
    for &agent in xworker_agents {
        // Use the VS Code pattern (most likely to deadlock).
        let test = format!("CF.pipe4_vscode.{agent}");
        let resp = r
            .send(
                agent,
                exec_timeout(
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
            Response::ExecResult {
                exit_code: 0,
                stdout,
                ..
            } => stdout.trim().contains("pipe4_vscode_ok: pass"),
            _ => false,
        };
        r.record(&test, agent, pass, &format!("{resp:?}"));

        // Control: sequential should work even if pipeline deadlocks.
        let test = format!("CF.sequential_control.{agent}");
        let resp = r
            .send(
                agent,
                exec_timeout(
                    vec![
                        "bash".into(),
                        "-c".into(),
                        "echo seq_a > /tmp/cf_test && cat /tmp/cf_test && rm /tmp/cf_test".into(),
                    ],
                    15,
                ),
            )
            .await;
        let pass = match &resp {
            Response::ExecResult {
                exit_code: 0,
                stdout,
                ..
            } => stdout.trim().contains("seq_a"),
            _ => false,
        };
        r.record(&test, agent, pass, &format!("{resp:?}"));
    }
}

/// Test concurrent fork+exec without pipes — multiple children exec
/// simultaneously from the same parent.  This isolates whether the
/// issue is pipe-related or pure concurrent 9P loading.
pub(crate) async fn concurrent_exec_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    eprintln!("[concurrent-fork] === Concurrent Exec Tests ===");

    // Fork N children that all exec simultaneously.
    // Each child runs `echo-test` which just prints and exits.
    // If the 9P transport deadlocks under concurrent execs, some
    // children will hang during shared library loading.
    for &count in &[2, 3, 4] {
        for &agent in CF_AGENTS {
            let test = format!("CF.concurrent_exec_{count}.{agent}");
            // Use bash to fork N background children and wait for all.
            let cmd = (0..count)
                .map(|_| format!("{} echo-test &", self_exe))
                .collect::<Vec<_>>()
                .join(" ");
            let full_cmd = format!("{cmd} wait");
            let resp = r
                .send(
                    agent,
                    exec_timeout(vec!["bash".into(), "-c".into(), full_cmd], 15),
                )
                .await;
            let pass = match &resp {
                Response::ExecResult {
                    exit_code: 0,
                    stdout,
                    ..
                } => {
                    let echo_count = stdout.matches("ECHO_TEST_OK").count();
                    echo_count == count
                }
                _ => false,
            };
            let detail = match &resp {
                Response::ExecResult { stdout, .. } => {
                    let echo_count = stdout.matches("ECHO_TEST_OK").count();
                    format!("got {echo_count}/{count} ECHO_TEST_OK")
                }
                _ => format!("{resp:?}"),
            };
            r.record(&test, agent, pass, &detail);
        }
    }
}

/// Test the exact VS Code install script pattern: read /proc files
/// through a pipeline with grep and sed.  This is the closest
/// reproduction of the observed deadlock.
pub(crate) async fn vscode_install_pipeline_tests(r: &mut TestRunner) {
    eprintln!("[concurrent-fork] === VS Code Install Pipeline ===");

    // The exact command from the VS Code install script that hung:
    // cat /proc/... | grep pattern | sed ... | sed ...
    // We use /proc/loadavg as a safe /proc file that always exists.
    let vscode_cmds: &[(&str, &str, &str)] = &[
        (
            "proc_cat_grep",
            "cat /proc/loadavg | grep -o '[0-9]'",
            "", // just check it produces output
        ),
        (
            "proc_pipeline_3",
            "cat /proc/cpuinfo | grep -i 'model name' | head -1",
            "", // just check non-empty
        ),
        (
            "proc_pipeline_4",
            "cat /proc/meminfo | grep MemTotal | sed 's/MemTotal://' | sed 's/ //g'",
            "kB", // should contain "kB"
        ),
        (
            "uname_pipeline",
            "uname -a | grep -o 'Linux' | head -1",
            "Linux",
        ),
    ];

    for &agent in CF_AGENTS {
        for &(name, cmd, expected) in vscode_cmds {
            let test = format!("CF.vscode.{name}.{agent}");
            let resp = r
                .send(
                    agent,
                    exec_timeout(vec!["bash".into(), "-c".into(), cmd.into()], 15),
                )
                .await;
            let pass = match &resp {
                Response::ExecResult {
                    exit_code: 0,
                    stdout,
                    ..
                } => {
                    if expected.is_empty() {
                        !stdout.trim().is_empty()
                    } else {
                        stdout.contains(expected)
                    }
                }
                _ => false,
            };
            r.record(&test, agent, pass, &format!("{resp:?}"));
        }
    }
}

/// Test concurrent file open+close from forked children.
///
/// Reproduces the RwLock deadlock on the layered FS RootDir where
/// concurrent `open()` (read lock + 9P) and `close()` (write lock)
/// from sibling processes cause a fair-RwLock deadlock.
pub(crate) async fn concurrent_fs_rwlock_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    eprintln!("[concurrent-fork] === Concurrent FS RwLock Tests ===");

    // CF.rwlock: fork N children that concurrently open+close the SAME file.
    // Tests the close() path holding write lock during 9P.
    for &n in &[2, 3, 4] {
        for &agent in CF_AGENTS {
            let test = format!("CF.rwlock_{n}.{agent}");
            let resp = r
                .send(
                    agent,
                    exec_timeout(
                        vec![self_exe.clone(), "concurrent-fs".into(), n.to_string()],
                        20,
                    ),
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { exit_code: 0, stdout, .. }
                    if stdout.contains("CONCURRENT_FS_OK")
            );
            r.record(&test, agent, pass, &format!("{resp:?}"));
        }
    }

    // CF.rwlock_multi: fork N children that concurrently open DIFFERENT files.
    // Each child opens multiple shared libraries, triggering uncached
    // lower.open() → write lock.  When two children race to insert the
    // same path, the second hits lower_fd_is_shareable() under the write
    // lock — a 9P fstat that deadlocks with the fair RwLock.
    for &n in &[3, 4, 6] {
        for &agent in CF_AGENTS {
            let test = format!("CF.rwlock_multi_{n}.{agent}");
            let resp = r
                .send(
                    agent,
                    exec_timeout(
                        vec![
                            self_exe.clone(),
                            "concurrent-fs-multi".into(),
                            n.to_string(),
                        ],
                        20,
                    ),
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { exit_code: 0, stdout, .. }
                    if stdout.contains("CONCURRENT_FS_MULTI_OK")
            );
            r.record(&test, agent, pass, &format!("{resp:?}"));
        }
    }
}
