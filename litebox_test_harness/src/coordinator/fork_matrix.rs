// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fork/exec test matrix — expresses multi-axis coverage via structured
//! loops instead of hand-enumerating each combination.
//!
//! Axes:
//! - Shell patterns × agent depth
//! - Delayed fork trigger × binary type × invocation method
//! - Stress exec: binary type × spawn method
//! - Non-PIE invocation method
//!
//! Contamination/isolation tests (X49-X59) remain in fork.rs since they
//! are inherently sequential and stateful.

use super::{TestRunner, exec};
use crate::protocol::Response;

// ── Shell pattern axis ──

/// A shell pattern that exercises a specific fork/pipe topology.
struct ShellPattern {
    /// Test ID suffix (e.g. "pipe", "heredoc").
    name: &'static str,
    /// The bash command template. Must be a valid `bash -c "..."` argument.
    cmd: &'static str,
    /// Substring expected in stdout on success.
    expected: &'static str,
}

const SHELL_PATTERNS: &[ShellPattern] = &[
    ShellPattern {
        name: "echo",
        cmd: "echo hello_from_bash",
        expected: "hello_from_bash",
    },
    ShellPattern {
        name: "cmd_substitution",
        cmd: "echo $(echo inner_value)",
        expected: "inner_value",
    },
    ShellPattern {
        name: "pipe_in_subshell",
        cmd: "echo $(echo pipe_data | cat)",
        expected: "pipe_data",
    },
    ShellPattern {
        name: "process_substitution",
        cmd: "cat <(echo proc_sub_data)",
        expected: "proc_sub_data",
    },
    ShellPattern {
        name: "simple_pipe",
        cmd: "echo pipe_two_stage | cat",
        expected: "pipe_two_stage",
    },
    ShellPattern {
        name: "three_stage_pipe",
        cmd: "echo three_stage | cat | cat",
        expected: "three_stage",
    },
    ShellPattern {
        name: "background_wait",
        cmd: "sleep 0 & wait; echo bg_done",
        expected: "bg_done",
    },
    ShellPattern {
        name: "multi_background",
        cmd: "echo bg_a & echo bg_b & wait",
        expected: "bg_a",
    },
    ShellPattern {
        name: "subshell_exit_code",
        cmd: "(exit 42); echo $?",
        expected: "42",
    },
    ShellPattern {
        name: "sequential_cmds",
        cmd: "echo seq_a && echo seq_b && echo seq_c",
        expected: "seq_a",
    },
    ShellPattern {
        name: "nested_subshell",
        cmd: "echo $(echo $(echo deep_nested))",
        expected: "deep_nested",
    },
    ShellPattern {
        name: "heredoc",
        cmd: "cat <<'EOF'\nheredoc_line\nEOF",
        expected: "heredoc_line",
    },
    ShellPattern {
        name: "herestring",
        cmd: "cat <<< 'herestring_data'",
        expected: "herestring_data",
    },
    ShellPattern {
        name: "pipe_grep",
        cmd: "echo -e 'alpha\\nbeta\\ngamma' | grep beta",
        expected: "beta",
    },
    ShellPattern {
        name: "subshell_pipe_wc",
        cmd: "echo $(echo 'line1\\nline2\\nline3' | wc -l)",
        expected: "", // just checks non-empty
    },
    ShellPattern {
        name: "backtick_subst",
        cmd: "echo `echo backtick_val`",
        expected: "backtick_val",
    },
    ShellPattern {
        name: "pipe_while_read",
        cmd: "echo -e 'a\\nb\\nc' | while read line; do echo \"got_$line\"; done",
        expected: "got_a",
    },
    ShellPattern {
        name: "xargs",
        cmd: "echo -e 'p\\nq\\nr' | xargs -I{} echo xargs_{}",
        expected: "xargs_p",
    },
];

/// Agents at different depths in the process tree.
const DEPTH_AGENTS: &[&str] = &["A", "AA", "AAA"];

/// Run all shell patterns from all depth agents.
pub(super) async fn shell_pattern_tests(r: &mut TestRunner) {
    eprintln!(
        "[fork_matrix] === Shell Patterns ({} patterns × {} depths) ===",
        SHELL_PATTERNS.len(),
        DEPTH_AGENTS.len()
    );

    for agent in DEPTH_AGENTS {
        for pat in SHELL_PATTERNS {
            let test_id = format!("XB.{}.{agent}", pat.name);
            let bash_cmd = vec!["bash".into(), "-c".into(), pat.cmd.into()];
            let resp = r.send(agent, exec(bash_cmd)).await;

            let pass = if pat.expected.is_empty() {
                // Just check non-empty stdout with exit code 0.
                matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if !stdout.trim().is_empty())
            } else {
                matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains(pat.expected))
            };
            let timeout = matches!(&resp, Response::ExecTimeout { .. });
            r.record(
                &test_id,
                agent,
                pass,
                &format!("timeout={timeout} {resp:?}"),
            );
        }
    }
}

// ── Delayed fork axis ──

/// How delayed-fork is triggered.
#[derive(Debug, Clone, Copy)]
enum DelayedForkTrigger {
    /// Vec allocation → mmap → non-pre-exec syscall.
    Mmap,
    /// Thread creation → clone3.
    Thread,
}

impl DelayedForkTrigger {
    fn subcommand(self) -> &'static str {
        match self {
            Self::Mmap => "trigger-delayed-fork",
            Self::Thread => "trigger-delayed-fork-thread",
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::Mmap => "mmap",
            Self::Thread => "thread",
        }
    }
}

/// What binary is exec'd after the delayed fork.
#[derive(Debug, Clone, Copy)]
enum BinaryType {
    /// PIE binary (self_exe echo-test).
    Pie,
    /// Non-PIE binary (/nonpie-echo).
    NonPie,
}

impl BinaryType {
    fn suffix(self) -> &'static str {
        match self {
            Self::Pie => "pie",
            Self::NonPie => "nonpie",
        }
    }

    fn expected_output(self) -> &'static str {
        match self {
            Self::Pie => "ECHO_TEST_OK",
            Self::NonPie => "NONPIE_OK",
        }
    }
}

/// How the exec is invoked.
#[derive(Debug, Clone, Copy)]
enum InvocationMethod {
    /// Direct fork+exec (no shell).
    Direct,
    /// Via a script file (/tmp/test.sh).
    ScriptFile,
}

impl InvocationMethod {
    fn suffix(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::ScriptFile => "script",
        }
    }
}

const TRIGGERS: &[DelayedForkTrigger] = &[DelayedForkTrigger::Mmap, DelayedForkTrigger::Thread];
const BINARY_TYPES: &[BinaryType] = &[BinaryType::Pie, BinaryType::NonPie];
const INVOCATION_METHODS: &[InvocationMethod] =
    &[InvocationMethod::Direct, InvocationMethod::ScriptFile];

/// Run the trigger × binary × invocation matrix.
pub(super) async fn delayed_fork_matrix(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    eprintln!(
        "[fork_matrix] === Delayed Fork ({} triggers × {} binaries × {} invocations) ===",
        TRIGGERS.len(),
        BINARY_TYPES.len(),
        INVOCATION_METHODS.len()
    );

    for &trigger in TRIGGERS {
        for &binary in BINARY_TYPES {
            for &invocation in INVOCATION_METHODS {
                let test_id = format!(
                    "XDF.{}.{}.{}",
                    trigger.suffix(),
                    binary.suffix(),
                    invocation.suffix()
                );

                // Build the inner binary command.
                let (inner_cmd, inner_args): (String, Vec<String>) = match binary {
                    BinaryType::Pie => (self_exe.clone(), vec!["echo-test".into()]),
                    BinaryType::NonPie => ("/nonpie-echo".into(), vec![]),
                };

                let resp = match invocation {
                    InvocationMethod::Direct => {
                        // trigger-delayed-fork <inner_cmd> [inner_args...]
                        let mut args =
                            vec![self_exe.clone(), trigger.subcommand().into(), inner_cmd];
                        args.extend(inner_args);
                        r.send("A", exec(args)).await
                    }
                    InvocationMethod::ScriptFile => {
                        // Write a script that runs: trigger-delayed-fork <inner_cmd> [args]
                        let script_path =
                            format!("/tmp/xdf_{}_{}.sh", trigger.suffix(), binary.suffix());
                        let inner_full = if inner_args.is_empty() {
                            inner_cmd.clone()
                        } else {
                            format!("{inner_cmd} {}", inner_args.join(" "))
                        };
                        let script_body = format!(
                            "echo '#!/usr/bin/bash' > {script_path} && \
                             echo '{self_exe} {} {inner_full}' >> {script_path} && \
                             chmod +x {script_path} && \
                             {script_path}; \
                             EXIT=$?; rm -f {script_path}; exit $EXIT",
                            trigger.subcommand()
                        );
                        r.send("A", exec(vec!["bash".into(), "-c".into(), script_body]))
                            .await
                    }
                };

                // Check if nonpie-echo is available.
                let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
                    || matches!(&resp, Response::Error { error } if error.contains("not found"));
                if matches!(binary, BinaryType::NonPie) && not_found {
                    r.record(&test_id, "A", true, "skipped (nonpie-echo not in rootfs)");
                    continue;
                }

                let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
                    if stdout.contains(binary.expected_output()));
                r.record(&test_id, "A", pass, &format!("{resp:?}"));
            }
        }
    }
}

// ── Stress exec axis ──

/// Binary mode for stress tests.
#[derive(Debug, Clone, Copy)]
enum StressMode {
    Pie,
    NonPie,
    Mixed,
}

impl StressMode {
    fn arg(self) -> &'static str {
        match self {
            Self::Pie => "pie",
            Self::NonPie => "nonpie",
            Self::Mixed => "mixed",
        }
    }
}

/// Spawn method for stress tests.
#[derive(Debug, Clone, Copy)]
enum SpawnMethod {
    Sync,
    Tokio,
}

impl SpawnMethod {
    fn suffix(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Tokio => "tokio",
        }
    }

    fn args(self) -> Vec<String> {
        match self {
            Self::Sync => vec![],
            Self::Tokio => vec!["tokio".into()],
        }
    }
}

const STRESS_MODES: &[StressMode] = &[StressMode::Pie, StressMode::NonPie, StressMode::Mixed];
const SPAWN_METHODS: &[SpawnMethod] = &[SpawnMethod::Sync, SpawnMethod::Tokio];

/// Run the stress exec matrix.
pub(super) async fn stress_exec_matrix(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    eprintln!(
        "[fork_matrix] === Stress Exec ({} modes × {} spawn methods) ===",
        STRESS_MODES.len(),
        SPAWN_METHODS.len()
    );

    let count = "10";
    for &mode in STRESS_MODES {
        for &spawn in SPAWN_METHODS {
            let test_id = format!("XS.{}.{}", mode.arg(), spawn.suffix());
            let mut args = vec![
                self_exe.clone(),
                "stress-exec".into(),
                count.into(),
                mode.arg().into(),
            ];
            args.extend(spawn.args());

            let resp = r.send("A", exec(args)).await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
                if stdout.contains("STRESS_START") && stdout.contains("STRESS_END failures=0"));
            r.record(&test_id, "A", pass, &format!("{resp:?}"));
        }
    }
}

// ── Non-PIE invocation axis ──

/// How a non-PIE binary is invoked.
#[derive(Debug, Clone, Copy)]
enum NonPieInvocation {
    /// Direct exec.
    Direct,
    /// Via a script file.
    ScriptFile,
    /// Via `bash -c "/nonpie-echo"`.
    BashInline,
}

impl NonPieInvocation {
    fn suffix(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::ScriptFile => "script",
            Self::BashInline => "bash_inline",
        }
    }
}

const NONPIE_INVOCATIONS: &[NonPieInvocation] = &[
    NonPieInvocation::Direct,
    NonPieInvocation::ScriptFile,
    NonPieInvocation::BashInline,
];

/// Run the non-PIE invocation method tests.
pub(super) async fn nonpie_invocation_tests(r: &mut TestRunner) {
    eprintln!(
        "[fork_matrix] === Non-PIE Invocation ({} methods) ===",
        NONPIE_INVOCATIONS.len()
    );

    for &inv in NONPIE_INVOCATIONS {
        let test_id = format!("XNP.{}", inv.suffix());

        let resp = match inv {
            NonPieInvocation::Direct => r.send("A", exec(vec!["/nonpie-echo".into()])).await,
            NonPieInvocation::ScriptFile => {
                r.send(
                    "A",
                    exec(vec![
                        "bash".into(),
                        "-c".into(),
                        "if [ -x /nonpie-echo ]; then \
                         echo '#!/usr/bin/bash' > /tmp/xnp.sh && \
                         echo '/nonpie-echo' >> /tmp/xnp.sh && \
                         chmod +x /tmp/xnp.sh && \
                         /tmp/xnp.sh; \
                         EXIT=$?; rm -f /tmp/xnp.sh; exit $EXIT; \
                         else echo SKIP; fi"
                            .into(),
                    ]),
                )
                .await
            }
            NonPieInvocation::BashInline => {
                r.send(
                    "A",
                    exec(vec![
                        "bash".into(),
                        "-c".into(),
                        "if [ -x /nonpie-echo ]; then /nonpie-echo; else echo SKIP; fi".into(),
                    ]),
                )
                .await
            }
        };

        let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
            || matches!(&resp, Response::Error { .. });
        let skipped =
            matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP"));

        if not_found || skipped {
            r.record(&test_id, "A", true, "skipped (nonpie-echo not in rootfs)");
        } else {
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
                if stdout.contains("NONPIE_OK"));
            r.record(&test_id, "A", pass, &format!("{resp:?}"));
        }
    }
}

// ── Exit code propagation test ──

/// Test exit code propagation from different agent depths.
pub(super) async fn exit_code_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    eprintln!("[fork_matrix] === Exit Code Propagation ===");

    let cases: &[(&str, i32)] = &[("A", 42), ("AAA", 7)];
    for &(agent, code) in cases {
        let test_id = format!("X.exit_code.{agent}.{code}");
        let resp = r
            .send(
                agent,
                exec(vec![self_exe.clone(), "exit-with".into(), code.to_string()]),
            )
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code, .. } if *exit_code == code);
        r.record(&test_id, agent, pass, &format!("{resp:?}"));
    }
}

/// Run all fork matrix tests.
pub(super) async fn run_fork_matrix_tests(r: &mut TestRunner) {
    exit_code_tests(r).await;
    shell_pattern_tests(r).await;
    delayed_fork_matrix(r).await;
    nonpie_invocation_tests(r).await;
    stress_exec_matrix(r).await;
}
