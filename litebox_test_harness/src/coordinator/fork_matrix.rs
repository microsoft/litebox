// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fork/exec test matrix — multi-dimensional coverage via loops.
//!
//! Dimensions:
//! - Shell pattern × agent depth
//! - Exec binary type {SelfExe, Node} × agent depth
//! - Exec method {ScriptFile, NestedBash, ExecInScript, ...}
//! - Delayed fork: trigger × binary × invocation × depth × nesting
//! - Stress exec: mode × spawn method
//! - Non-PIE invocation method
//! - Contamination pattern (non-PIE then PIE, various depths)

use super::{TestRunner, exec, exec_timeout};
use crate::protocol::Response;

// ═══════════════════════════════════════════════════════════════════
// SHELL PATTERNS × DEPTH
// ═══════════════════════════════════════════════════════════════════

struct ShellPattern {
    name: &'static str,
    cmd: &'static str,
    expected: &'static str, // empty = just check non-empty stdout + exit 0
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
        expected: "",
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

const DEPTH_AGENTS: &[&str] = &["A", "AA", "AAA"];

async fn shell_pattern_tests(r: &mut TestRunner) {
    eprintln!(
        "[fork_matrix] === Shell Patterns ({} × {} depths) ===",
        SHELL_PATTERNS.len(),
        DEPTH_AGENTS.len()
    );
    for &agent in DEPTH_AGENTS {
        for pat in SHELL_PATTERNS {
            let cmd = vec!["bash".into(), "-c".into(), pat.cmd.into()];
            let resp = r.send(agent, exec(cmd)).await;
            let pass = if pat.expected.is_empty() {
                matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if !stdout.trim().is_empty())
            } else {
                matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains(pat.expected))
            };
            let timeout = matches!(&resp, Response::ExecTimeout { .. });
            r.record(
                &format!("XB.{}.{agent}", pat.name),
                agent,
                pass,
                &format!("timeout={timeout} {resp:?}"),
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// EXEC BINARY × DEPTH
// ═══════════════════════════════════════════════════════════════════

/// Binary type for direct exec tests.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum ExecBinary {
    Node,
}

#[allow(dead_code)]
impl ExecBinary {
    fn suffix(self) -> &'static str {
        match self {
            Self::Node => "node",
        }
    }
}

async fn exec_binary_tests(r: &mut TestRunner) {
    // SelfExe is already covered by matrix.rs run_exec_tests.
    // Node.js at each depth:
    eprintln!(
        "[fork_matrix] === Exec Binary: Node × {} depths ===",
        DEPTH_AGENTS.len()
    );
    for &agent in DEPTH_AGENTS {
        let resp = r
            .send(
                agent,
                exec(vec![
                    "/usr/local/bin/node".into(),
                    "-e".into(),
                    format!("console.log('node_{agent}_ok')"),
                ]),
            )
            .await;
        let expected = format!("node_{agent}_ok");
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains(&expected));
        r.record(
            &format!("X.node.{agent}"),
            agent,
            pass,
            &format!("{resp:?}"),
        );
    }

    // Node.js process.stdout.write (tests different output path).
    let resp = r
        .send(
            "A",
            exec(vec![
                "/usr/local/bin/node".into(),
                "-e".into(),
                "process.stdout.write('stdout_write_ok\\n')".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("stdout_write_ok"));
    r.record("X.node_stdout_write.A", "A", pass, &format!("{resp:?}"));
}

// ═══════════════════════════════════════════════════════════════════
// EXEC METHOD (script files, nested bash, etc.)
// ═══════════════════════════════════════════════════════════════════

struct ExecMethodCase {
    name: &'static str,
    /// Bash -c command. {self_exe} is replaced with the test binary path.
    cmd_template: &'static str,
    expected: &'static str,
}

const EXEC_METHODS: &[ExecMethodCase] = &[
    ExecMethodCase {
        name: "script_echo",
        cmd_template: "echo '#!/usr/bin/bash' > /tmp/xm.sh && echo 'echo script_echo_ok' >> /tmp/xm.sh && chmod +x /tmp/xm.sh && /tmp/xm.sh; EXIT=$?; rm -f /tmp/xm.sh; exit $EXIT",
        expected: "script_echo_ok",
    },
    ExecMethodCase {
        name: "script_node",
        cmd_template: "echo '#!/usr/bin/bash' > /tmp/xm.sh && echo '/usr/local/bin/node -e \"console.log(\\\"script_node_ok\\\")\"' >> /tmp/xm.sh && chmod +x /tmp/xm.sh && /tmp/xm.sh; EXIT=$?; rm -f /tmp/xm.sh; exit $EXIT",
        expected: "script_node_ok",
    },
    ExecMethodCase {
        name: "script_env_shebang",
        cmd_template: "echo '#!/usr/bin/env bash' > /tmp/xm.sh && echo '/usr/local/bin/node -e \"console.log(\\\"script_env_ok\\\")\"' >> /tmp/xm.sh && chmod +x /tmp/xm.sh && /tmp/xm.sh; EXIT=$?; rm -f /tmp/xm.sh; exit $EXIT",
        expected: "script_env_ok",
    },
    ExecMethodCase {
        name: "script_cat_pipe",
        cmd_template: "echo '#!/usr/bin/bash' > /tmp/xm.sh && echo 'echo cat_input | cat' >> /tmp/xm.sh && chmod +x /tmp/xm.sh && /tmp/xm.sh; EXIT=$?; rm -f /tmp/xm.sh; exit $EXIT",
        expected: "cat_input",
    },
    ExecMethodCase {
        name: "nested_bash_node",
        cmd_template: "bash -c '/usr/local/bin/node -e \"console.log(\\\"nested_ok\\\")\"'",
        expected: "nested_ok",
    },
    ExecMethodCase {
        name: "script_self_exe",
        cmd_template: "echo '#!/usr/bin/bash' > /tmp/xm.sh && echo '{self_exe} echo-test' >> /tmp/xm.sh && chmod +x /tmp/xm.sh && /tmp/xm.sh; EXIT=$?; rm -f /tmp/xm.sh; exit $EXIT",
        expected: "ECHO_TEST_OK",
    },
    ExecMethodCase {
        name: "script_exec_node",
        cmd_template: "echo '#!/usr/bin/bash' > /tmp/xm.sh && echo 'exec /usr/local/bin/node -e \"console.log(\\\"exec_ok\\\")\"' >> /tmp/xm.sh && chmod +x /tmp/xm.sh && /tmp/xm.sh; EXIT=$?; rm -f /tmp/xm.sh; exit $EXIT",
        expected: "exec_ok",
    },
];

async fn exec_method_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    eprintln!(
        "[fork_matrix] === Exec Method ({} cases) ===",
        EXEC_METHODS.len()
    );
    for em in EXEC_METHODS {
        let cmd_str = em.cmd_template.replace("{self_exe}", &self_exe);
        let resp = r
            .send("A", exec(vec!["bash".into(), "-c".into(), cmd_str]))
            .await;
        let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains(em.expected));
        r.record(&format!("XM.{}", em.name), "A", pass, &format!("{resp:?}"));
    }

    // Node.js os.networkInterfaces() — VS Code calls this on startup.
    let resp = r
        .send(
            "A",
            exec_timeout(
                vec![
                    "/usr/local/bin/node".into(),
                    "-e".into(),
                    "try { const r = require('os').networkInterfaces(); \
                     console.log('NETIF_OK:' + Object.keys(r).length); } \
                     catch(e) { console.log('NETIF_ERR:' + e.code); }"
                        .into(),
                ],
                30,
            ),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
        if stdout.contains("NETIF_OK:") || stdout.contains("NETIF_ERR:"));
    r.record("XM.node_networkInterfaces", "A", pass, &format!("{resp:?}"));
}

// ═══════════════════════════════════════════════════════════════════
// DELAYED FORK: trigger × binary × invocation × depth × nesting
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy)]
enum DfTrigger {
    Mmap,
    Thread,
}

impl DfTrigger {
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

#[derive(Debug, Clone, Copy)]
enum DfBinary {
    Pie,
    NonPie,
    Node,
}

impl DfBinary {
    fn suffix(self) -> &'static str {
        match self {
            Self::Pie => "pie",
            Self::NonPie => "nonpie",
            Self::Node => "node",
        }
    }
    fn expected(self) -> &'static str {
        match self {
            Self::Pie => "ECHO_TEST_OK",
            Self::NonPie => "ECHO_TEST_OK",
            Self::Node => "df_node_ok",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum DfInvocation {
    Direct,
    ScriptFile,
}

impl DfInvocation {
    fn suffix(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::ScriptFile => "script",
        }
    }
}

const DF_TRIGGERS: &[DfTrigger] = &[DfTrigger::Mmap, DfTrigger::Thread];
const DF_BINARIES: &[DfBinary] = &[DfBinary::Pie, DfBinary::NonPie, DfBinary::Node];
const DF_INVOCATIONS: &[DfInvocation] = &[DfInvocation::Direct, DfInvocation::ScriptFile];
const DF_AGENTS: &[&str] = &["A", "AA"];

async fn delayed_fork_matrix(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    // trigger × binary × invocation × depth
    eprintln!(
        "[fork_matrix] === Delayed Fork ({} × {} × {} × {} depths) ===",
        DF_TRIGGERS.len(),
        DF_BINARIES.len(),
        DF_INVOCATIONS.len(),
        DF_AGENTS.len()
    );

    for &trigger in DF_TRIGGERS {
        for &binary in DF_BINARIES {
            for &invocation in DF_INVOCATIONS {
                for &agent in DF_AGENTS {
                    let test_id = format!(
                        "XDF.{}.{}.{}.{agent}",
                        trigger.suffix(),
                        binary.suffix(),
                        invocation.suffix()
                    );

                    let (inner_cmd, inner_args): (String, Vec<String>) = match binary {
                        DfBinary::Pie => (self_exe.clone(), vec!["echo-test".into()]),
                        DfBinary::NonPie => match crate::find_nonpie_binary() {
                            Some(p) => (p, vec!["echo-test".into()]),
                            None => {
                                r.record(
                                    &test_id,
                                    agent,
                                    false,
                                    "FAIL: nonpie binary not found — mount at /opt/nonpie",
                                );
                                continue;
                            }
                        },
                        DfBinary::Node => (
                            "/usr/local/bin/node".into(),
                            vec!["-e".into(), "console.log('df_node_ok')".into()],
                        ),
                    };

                    let resp = match invocation {
                        DfInvocation::Direct => {
                            let mut args =
                                vec![self_exe.clone(), trigger.subcommand().into(), inner_cmd];
                            args.extend(inner_args);
                            r.send(agent, exec(args)).await
                        }
                        DfInvocation::ScriptFile => {
                            let script = format!("/tmp/xdf_{}.sh", test_id.replace('.', "_"));
                            let inner_full = if inner_args.is_empty() {
                                inner_cmd.clone()
                            } else {
                                // Quote args that contain special characters.
                                let escaped: Vec<String> = inner_args
                                    .iter()
                                    .map(|a| {
                                        if a.contains(|c: char| {
                                            !c.is_alphanumeric()
                                                && c != '_'
                                                && c != '-'
                                                && c != '.'
                                                && c != '/'
                                        }) {
                                            format!("\"{}\"", a.replace('"', "\\\""))
                                        } else {
                                            a.clone()
                                        }
                                    })
                                    .collect();
                                format!("{inner_cmd} {}", escaped.join(" "))
                            };
                            // Use heredoc to avoid nested quoting issues.
                            let body = format!(
                                "cat > {script} <<'XEOF'\n#!/usr/bin/bash\n{self_exe} {} {inner_full}\nXEOF\nchmod +x {script} && {script}; EXIT=$?; rm -f {script}; exit $EXIT",
                                trigger.subcommand()
                            );
                            r.send(agent, exec(vec!["bash".into(), "-c".into(), body]))
                                .await
                        }
                    };

                    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
                        || matches!(&resp, Response::Error { error } if error.contains("not found"));
                    if not_found {
                        r.record(&test_id, agent, false, "FAIL: binary not in rootfs");
                        continue;
                    }

                    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.contains(binary.expected()));
                    r.record(&test_id, agent, pass, &format!("{resp:?}"));
                }
            }
        }
    }

    // Triple nesting (3 levels of delayed fork).
    eprintln!("[fork_matrix] === Delayed Fork Nesting ===");
    let resp = r
        .send(
            "A",
            exec(vec![
                self_exe.clone(),
                "trigger-delayed-fork".into(),
                self_exe.clone(),
                "trigger-delayed-fork".into(),
                self_exe.clone(),
                "echo-test".into(),
            ]),
        )
        .await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("XDF.triple_nesting", "A", pass, &format!("{resp:?}"));
}

// ═══════════════════════════════════════════════════════════════════
// STRESS EXEC: mode × spawn method
// ═══════════════════════════════════════════════════════════════════

const STRESS_MODES: &[&str] = &["pie", "nonpie", "mixed"];
const SPAWN_METHODS: &[(&str, &[&str])] = &[("sync", &[]), ("tokio", &["tokio"])];

async fn stress_exec_matrix(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    let count = "10";

    eprintln!(
        "[fork_matrix] === Stress Exec ({} × {} spawn) ===",
        STRESS_MODES.len(),
        SPAWN_METHODS.len()
    );

    for &mode in STRESS_MODES {
        for &(spawn_name, spawn_args) in SPAWN_METHODS {
            let test_id = format!("XS.{mode}.{spawn_name}");
            let mut args = vec![
                self_exe.clone(),
                "stress-exec".into(),
                count.into(),
                mode.into(),
            ];
            for &a in spawn_args {
                args.push(a.into());
            }
            let resp = r.send("A", exec(args)).await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
                if stdout.contains("STRESS_START") && stdout.contains("STRESS_END failures=0"));
            r.record(&test_id, "A", pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// NON-PIE INVOCATION METHOD
// ═══════════════════════════════════════════════════════════════════

struct NonPieCase {
    name: &'static str,
    /// Bash command (None = direct exec of /nonpie-echo).
    bash_cmd: Option<&'static str>,
}

const NONPIE_CASES: &[NonPieCase] = &[
    NonPieCase {
        name: "direct",
        bash_cmd: None,
    },
    NonPieCase {
        name: "script",
        bash_cmd: Some(
            "if [ -x /nonpie-bin ]; then \
             echo '#!/usr/bin/bash' > /tmp/xnp.sh && \
             echo '/nonpie-cmd' >> /tmp/xnp.sh && \
             chmod +x /tmp/xnp.sh && /tmp/xnp.sh; \
             EXIT=$?; rm -f /tmp/xnp.sh; exit $EXIT; \
             else echo SKIP; fi",
        ),
    },
    NonPieCase {
        name: "bash_inline",
        bash_cmd: Some("if [ -x /nonpie-bin ]; then /nonpie-cmd; else echo SKIP; fi"),
    },
];

async fn nonpie_invocation_tests(r: &mut TestRunner) {
    eprintln!(
        "[fork_matrix] === Non-PIE Invocation ({} methods) ===",
        NONPIE_CASES.len()
    );

    let nonpie_bin = match crate::find_nonpie_binary() {
        Some(p) => p,
        None => {
            for nc in NONPIE_CASES {
                r.record(
                    &format!("XNP.{}", nc.name),
                    "A",
                    false,
                    "FAIL: nonpie binary not found — mount at /opt/nonpie",
                );
            }
            return;
        }
    };

    for nc in NONPIE_CASES {
        let test_id = format!("XNP.{}", nc.name);
        let resp = match nc.bash_cmd {
            None => {
                r.send("A", exec(vec![nonpie_bin.clone(), "echo-test".into()]))
                    .await
            }
            Some(cmd) => {
                let resolved = cmd
                    .replace("/nonpie-bin", &nonpie_bin)
                    .replace("/nonpie-cmd", &format!("{nonpie_bin} echo-test"));
                r.send("A", exec(vec!["bash".into(), "-c".into(), resolved]))
                    .await
            }
        };

        let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
            || matches!(&resp, Response::Error { .. });
        let skipped =
            matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP"));
        if not_found || skipped {
            r.record(
                &test_id,
                "A",
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
        } else {
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
                if stdout.contains("ECHO_TEST_OK"));
            r.record(&test_id, "A", pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// CONTAMINATION PATTERNS
// ═══════════════════════════════════════════════════════════════════

struct ContaminationCase {
    name: &'static str,
    /// Bash command template. {self_exe} is replaced. None = special init-level test.
    bash_template: Option<&'static str>,
    expected: &'static str,
}

const CONTAMINATION_CASES: &[ContaminationCase] = &[
    ContaminationCase {
        name: "child_clean",
        bash_template: Some(
            "if [ -x /nonpie-bin ]; then \
             /nonpie-cmd >/dev/null 2>&1; echo CHILD_CLEAN; \
             else echo SKIP; fi",
        ),
        expected: "CHILD_CLEAN",
    },
    ContaminationCase {
        name: "child_sequential",
        bash_template: Some(
            "if [ -x /nonpie-bin ]; then \
             FIRST=$(/nonpie-cmd); SECOND=$({self_exe} echo-test); \
             echo \"first=$FIRST\"; echo \"second=$SECOND\"; \
             else echo SKIP; fi",
        ),
        expected: "second=ECHO_TEST_OK",
    },
    ContaminationCase {
        name: "grandchild_nonpie",
        bash_template: Some(
            "if [ -x /nonpie-bin ]; then bash -c '/nonpie-cmd'; else echo SKIP; fi",
        ),
        expected: "ECHO_TEST_OK",
    },
    ContaminationCase {
        name: "depth2_clean",
        bash_template: Some(
            "if [ -x /nonpie-bin ]; then \
             bash -c '/nonpie-cmd >/dev/null; {self_exe} echo-test'; \
             else echo SKIP; fi",
        ),
        expected: "ECHO_TEST_OK",
    },
];

async fn contamination_pattern_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    let bash = |cmd: &str| -> Vec<String> { vec!["bash".into(), "-c".into(), cmd.into()] };

    eprintln!(
        "[fork_matrix] === Contamination Patterns ({} + init-level) ===",
        CONTAMINATION_CASES.len()
    );

    let nonpie_bin = match crate::find_nonpie_binary() {
        Some(p) => p,
        None => {
            r.record(
                "XC.init_level",
                "A",
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
            for cc in CONTAMINATION_CASES {
                r.record(
                    &format!("XC.{}", cc.name),
                    "A",
                    false,
                    "FAIL: nonpie binary not found — mount at /opt/nonpie",
                );
            }
            return;
        }
    };
    let nonpie_cmd = format!("{nonpie_bin} echo-test");

    // Init-level: exec non-PIE, then exec PIE — check PIE output is clean.
    let resp = r
        .send("A", exec(vec![nonpie_bin.clone(), "echo-test".into()]))
        .await;
    let not_found = matches!(&resp, Response::ExecResult { exit_code: 127, .. })
        || matches!(&resp, Response::Error { .. });
    if not_found {
        r.record(
            "XC.init_level",
            "A",
            false,
            "FAIL: nonpie binary not found — mount at /opt/nonpie",
        );
    } else {
        let resp2 = r
            .send("A", exec(vec![self_exe.clone(), "echo-test".into()]))
            .await;
        let pass = matches!(&resp2, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
        r.record("XC.init_level", "A", pass, &format!("{resp2:?}"));
    }

    // Loop over bash-based contamination patterns.
    for cc in CONTAMINATION_CASES {
        let test_id = format!("XC.{}", cc.name);
        let cmd_str = cc
            .bash_template
            .unwrap()
            .replace("{self_exe}", &self_exe)
            .replace("/nonpie-bin", &nonpie_bin)
            .replace("/nonpie-cmd", &nonpie_cmd);
        let resp = r.send("A", exec(bash(&cmd_str))).await;
        let skipped =
            matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP"));
        if skipped {
            r.record(
                &test_id,
                "A",
                false,
                "FAIL: nonpie binary not found — mount at /opt/nonpie",
            );
        } else {
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
                if stdout.contains(cc.expected));
            r.record(&test_id, "A", pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// RUNNER
// ═══════════════════════════════════════════════════════════════════

pub(super) async fn run_fork_matrix_tests(r: &mut TestRunner) {
    shell_pattern_tests(r).await;
    exec_binary_tests(r).await;
    exec_method_tests(r).await;
    delayed_fork_matrix(r).await;
    nonpie_invocation_tests(r).await;
    stress_exec_matrix(r).await;
    contamination_pattern_tests(r).await;
}

pub(crate) fn register_fork_matrix(tests: &mut Vec<super::Test>) {
    // Shell patterns x depth
    for &agent in DEPTH_AGENTS {
        for pat in SHELL_PATTERNS {
            let id = format!("XB.{}.{agent}", pat.name);
            let agent_s = agent.to_string();
            let expected = pat.expected.to_string();
            let cmd_str = pat.cmd.to_string();
            tests.push(super::Test {
                suite: "fork",
                group: "fork_matrix",
                id,
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    Box::pin(async move {
                        let cmd = vec!["bash".into(), "-c".into(), cmd_str];
                        let resp = r.send(&agent_s, super::exec(cmd)).await;
                        let pass = if expected.is_empty() {
                            matches!(
                                &resp,
                                crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                                    if !stdout.trim().is_empty()
                            )
                        } else {
                            matches!(
                                &resp,
                                crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.contains(&*expected)
                            )
                        };
                        let timeout =
                            matches!(&resp, crate::protocol::Response::ExecTimeout { .. });
                        super::TestOutcome::new(
                            &agent_s,
                            pass,
                            format!("timeout={timeout} {resp:?}"),
                        )
                    })
                }),
            });
        }
    }

    // Exec binary: Node x depth
    for &agent in DEPTH_AGENTS {
        let id = format!("X.node.{agent}");
        let agent_s = agent.to_string();
        tests.push(super::Test {
            suite: "fork",
            group: "fork_matrix",
            id,
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                let agent_s2 = agent_s.clone();
                Box::pin(async move {
                    let expected = format!("node_{agent_s}_ok");
                    let resp = r
                        .send(
                            &agent_s,
                            super::exec(vec![
                                "/usr/local/bin/node".into(),
                                "-e".into(),
                                format!("console.log('node_{agent_s}_ok')"),
                            ]),
                        )
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains(&expected)
                    );
                    super::TestOutcome::new(&agent_s2, pass, format!("{resp:?}"))
                })
            }),
        });
    }

    // Node.js process.stdout.write
    tests.push(super::Test {
        suite: "fork",
        group: "fork_matrix",
        id: "X.node_stdout_write.A".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r
                    .send(
                        "A",
                        super::exec(vec![
                            "/usr/local/bin/node".into(),
                            "-e".into(),
                            "process.stdout.write('stdout_write_ok\\n')".into(),
                        ]),
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.contains("stdout_write_ok")
                );
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // Exec method tests
    for em in EXEC_METHODS {
        let id = format!("XM.{}", em.name);
        let template = em.cmd_template.to_string();
        let expected = em.expected.to_string();
        tests.push(super::Test {
            suite: "fork",
            group: "fork_matrix",
            id,
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let cmd_str = template.replace("{self_exe}", &self_exe);
                    let resp = r
                        .send("A", super::exec(vec!["bash".into(), "-c".into(), cmd_str]))
                        .await;
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains(&*expected)
                    );
                    super::TestOutcome::new("A", pass, format!("{resp:?}"))
                })
            }),
        });
    }

    // XM.node_networkInterfaces
    tests.push(super::Test {
        suite: "fork",
        group: "fork_matrix",
        id: "XM.node_networkInterfaces".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            Box::pin(async move {
                let resp = r
                    .send(
                        "A",
                        super::exec_timeout(
                            vec![
                                "/usr/local/bin/node".into(),
                                "-e".into(),
                                "try { const r = require('os').networkInterfaces(); \
                                 console.log('NETIF_OK:' + Object.keys(r).length); } \
                                 catch(e) { console.log('NETIF_ERR:' + e.code); }"
                                    .into(),
                            ],
                            30,
                        ),
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.contains("NETIF_OK:") || stdout.contains("NETIF_ERR:")
                );
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // Delayed fork matrix
    for &trigger in DF_TRIGGERS {
        for &binary in DF_BINARIES {
            for &invocation in DF_INVOCATIONS {
                for &agent in DF_AGENTS {
                    let id = format!(
                        "XDF.{}.{}.{}.{agent}",
                        trigger.suffix(),
                        binary.suffix(),
                        invocation.suffix()
                    );
                    let agent_s = agent.to_string();
                    let trigger_sub = trigger.subcommand().to_string();
                    let binary_expected = binary.expected().to_string();

                    tests.push(super::Test {
                        suite: "fork",
                        group: "fork_matrix",
                        id,
                        xfail: None,
                        timeout_secs: 60,
                        run: Box::new(move |r| {
                            let self_exe = r.self_exe.clone();
                            Box::pin(async move {
                                let (inner_cmd, inner_args): (String, Vec<String>) = match binary {
                                    DfBinary::Pie => (self_exe.clone(), vec!["echo-test".into()]),
                                    DfBinary::NonPie => match crate::find_nonpie_binary() {
                                        Some(p) => (p, vec!["echo-test".into()]),
                                        None => {
                                            return super::TestOutcome::new(
                                                &agent_s,
                                                false,
                                                "FAIL: nonpie binary not found",
                                            );
                                        }
                                    },
                                    DfBinary::Node => (
                                        "/usr/local/bin/node".into(),
                                        vec!["-e".into(), "console.log('df_node_ok')".into()],
                                    ),
                                };

                                let resp = match invocation {
                                    DfInvocation::Direct => {
                                        let mut args =
                                            vec![self_exe.clone(), trigger_sub.clone(), inner_cmd];
                                        args.extend(inner_args);
                                        r.send(&agent_s, super::exec(args)).await
                                    }
                                    DfInvocation::ScriptFile => {
                                        let test_id_safe = format!(
                                            "XDF_{}_{}_{}_{}",
                                            trigger.suffix(),
                                            binary.suffix(),
                                            invocation.suffix(),
                                            agent_s
                                        );
                                        let script = format!("/tmp/xdf_{test_id_safe}.sh");
                                        let inner_full = if inner_args.is_empty() {
                                            inner_cmd.clone()
                                        } else {
                                            let escaped: Vec<String> = inner_args
                                                .iter()
                                                .map(|a| {
                                                    if a.contains(|c: char| {
                                                        !c.is_alphanumeric()
                                                            && c != '_'
                                                            && c != '-'
                                                            && c != '.'
                                                            && c != '/'
                                                    }) {
                                                        format!("\"{}\"", a.replace('"', "\\\""))
                                                    } else {
                                                        a.clone()
                                                    }
                                                })
                                                .collect();
                                            format!("{inner_cmd} {}", escaped.join(" "))
                                        };
                                        let body = format!(
                                            "cat > {script} <<'XEOF'\n#!/usr/bin/bash\n\
                                             {self_exe} {trigger_sub} {inner_full}\n\
                                             XEOF\nchmod +x {script} && {script}; \
                                             EXIT=$?; rm -f {script}; exit $EXIT",
                                        );
                                        r.send(
                                            &agent_s,
                                            super::exec(vec!["bash".into(), "-c".into(), body]),
                                        )
                                        .await
                                    }
                                };

                                let not_found = matches!(
                                    &resp,
                                    crate::protocol::Response::ExecResult { exit_code: 127, .. }
                                ) || matches!(
                                    &resp,
                                    crate::protocol::Response::Error { error }
                                        if error.contains("not found")
                                );
                                if not_found {
                                    return super::TestOutcome::new(
                                        &agent_s,
                                        false,
                                        "FAIL: binary not in rootfs",
                                    );
                                }

                                let pass = matches!(
                                    &resp,
                                    crate::protocol::Response::ExecResult {
                                        exit_code: 0, stdout, ..
                                    } if stdout.contains(&*binary_expected)
                                );
                                super::TestOutcome::new(&agent_s, pass, format!("{resp:?}"))
                            })
                        }),
                    });
                }
            }
        }
    }

    // XDF.triple_nesting
    tests.push(super::Test {
        suite: "fork",
        group: "fork_matrix",
        id: "XDF.triple_nesting".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            let self_exe = r.self_exe.clone();
            Box::pin(async move {
                let resp = r
                    .send(
                        "A",
                        super::exec(vec![
                            self_exe.clone(),
                            "trigger-delayed-fork".into(),
                            self_exe.clone(),
                            "trigger-delayed-fork".into(),
                            self_exe.clone(),
                            "echo-test".into(),
                        ]),
                    )
                    .await;
                let pass = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.contains("ECHO_TEST_OK")
                );
                super::TestOutcome::new("A", pass, format!("{resp:?}"))
            })
        }),
    });

    // Stress exec matrix
    for &mode in STRESS_MODES {
        for &(spawn_name, spawn_args) in SPAWN_METHODS {
            let id = format!("XS.{mode}.{spawn_name}");
            let mode_s = mode.to_string();
            let extra: Vec<String> = spawn_args.iter().map(|s| s.to_string()).collect();
            tests.push(super::Test {
                suite: "fork",
                group: "fork_matrix",
                id,
                xfail: None,
                timeout_secs: 60,
                run: Box::new(move |r| {
                    let self_exe = r.self_exe.clone();
                    Box::pin(async move {
                        let mut args = vec![self_exe, "stress-exec".into(), "10".into(), mode_s];
                        args.extend(extra);
                        let resp = r.send("A", super::exec(args)).await;
                        let pass = matches!(
                            &resp,
                            crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.contains("STRESS_START")
                                    && stdout.contains("STRESS_END failures=0")
                        );
                        super::TestOutcome::new("A", pass, format!("{resp:?}"))
                    })
                }),
            });
        }
    }

    // Non-PIE invocation tests
    for nc in NONPIE_CASES {
        let id = format!("XNP.{}", nc.name);
        let bash_cmd = nc.bash_cmd.map(|s| s.to_string());
        tests.push(super::Test {
            suite: "fork",
            group: "fork_matrix",
            id,
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                Box::pin(async move {
                    let nonpie_bin = match crate::find_nonpie_binary() {
                        Some(p) => p,
                        None => {
                            return super::TestOutcome::new(
                                "A",
                                false,
                                "FAIL: nonpie binary not found",
                            );
                        }
                    };
                    let resp = match &bash_cmd {
                        None => {
                            r.send(
                                "A",
                                super::exec(vec![nonpie_bin.clone(), "echo-test".into()]),
                            )
                            .await
                        }
                        Some(cmd) => {
                            let resolved = cmd
                                .replace("/nonpie-bin", &nonpie_bin)
                                .replace("/nonpie-cmd", &format!("{nonpie_bin} echo-test"));
                            r.send("A", super::exec(vec!["bash".into(), "-c".into(), resolved]))
                                .await
                        }
                    };
                    let not_found = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 127, .. }
                    ) || matches!(&resp, crate::protocol::Response::Error { .. });
                    let skipped = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { stdout, .. }
                            if stdout.contains("SKIP")
                    );
                    if not_found || skipped {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            "FAIL: nonpie binary not found",
                        );
                    }
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("ECHO_TEST_OK")
                    );
                    super::TestOutcome::new("A", pass, format!("{resp:?}"))
                })
            }),
        });
    }

    // XC.init_level
    tests.push(super::Test {
        suite: "fork",
        group: "fork_matrix",
        id: "XC.init_level".to_string(),
        xfail: None,
        timeout_secs: 60,
        run: Box::new(|r| {
            let self_exe = r.self_exe.clone();
            Box::pin(async move {
                let nonpie_bin = match crate::find_nonpie_binary() {
                    Some(p) => p,
                    None => {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            "FAIL: nonpie binary not found",
                        );
                    }
                };
                let resp = r
                    .send("A", super::exec(vec![nonpie_bin, "echo-test".into()]))
                    .await;
                let not_found = matches!(
                    &resp,
                    crate::protocol::Response::ExecResult { exit_code: 127, .. }
                ) || matches!(&resp, crate::protocol::Response::Error { .. });
                if not_found {
                    return super::TestOutcome::new("A", false, "FAIL: nonpie binary not found");
                }
                let resp2 = r
                    .send("A", super::exec(vec![self_exe, "echo-test".into()]))
                    .await;
                let pass = matches!(
                    &resp2,
                    crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout == "ECHO_TEST_OK"
                );
                super::TestOutcome::new("A", pass, format!("{resp2:?}"))
            })
        }),
    });

    // Contamination pattern cases
    for cc in CONTAMINATION_CASES {
        let id = format!("XC.{}", cc.name);
        let template = cc.bash_template.unwrap().to_string();
        let expected = cc.expected.to_string();
        tests.push(super::Test {
            suite: "fork",
            group: "fork_matrix",
            id,
            xfail: None,
            timeout_secs: 60,
            run: Box::new(move |r| {
                let self_exe = r.self_exe.clone();
                Box::pin(async move {
                    let nonpie_bin = match crate::find_nonpie_binary() {
                        Some(p) => p,
                        None => {
                            return super::TestOutcome::new(
                                "A",
                                false,
                                "FAIL: nonpie binary not found",
                            );
                        }
                    };
                    let nonpie_cmd = format!("{nonpie_bin} echo-test");
                    let cmd_str = template
                        .replace("{self_exe}", &self_exe)
                        .replace("/nonpie-bin", &nonpie_bin)
                        .replace("/nonpie-cmd", &nonpie_cmd);
                    let resp = r
                        .send("A", super::exec(vec!["bash".into(), "-c".into(), cmd_str]))
                        .await;
                    let skipped = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { stdout, .. }
                            if stdout.contains("SKIP")
                    );
                    if skipped {
                        return super::TestOutcome::new(
                            "A",
                            false,
                            "FAIL: nonpie binary not found",
                        );
                    }
                    let pass = matches!(
                        &resp,
                        crate::protocol::Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains(&*expected)
                    );
                    super::TestOutcome::new("A", pass, format!("{resp:?}"))
                })
            }),
        });
    }
}
