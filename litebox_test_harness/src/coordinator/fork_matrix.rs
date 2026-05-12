// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fork/exec test matrix — multi-dimensional coverage via loops.
//!
//! Dimensions:
//! - Shell pattern × agent depth
//! - Exec binary type {`SelfExe`, Node} × agent depth
//! - Exec method {`ScriptFile`, `NestedBash`, `ExecInScript`, ...}
//! - Delayed fork: trigger × binary × invocation × depth × nesting
//! - Stress exec: mode × spawn method
//! - Non-PIE invocation method
//! - Contamination pattern (non-PIE then PIE, various depths)

use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

use super::agents::{AgentHandle, AgentName};
use super::common;
use super::registry::Registry;
use super::run_context::RunContext;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::protocol::Response;
use crate::register_handler;

#[derive(Clone, Serialize, Deserialize)]
struct BashArgs {
    cmd: String,
    timeout_secs: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ExecBinArgs {
    argv: Vec<String>,
    timeout_secs: Option<u64>,
}

const BASH: HandlerToken<BashArgs, Response> = HandlerToken::new("fork_matrix.bash");
const EXEC_BIN: HandlerToken<ExecBinArgs, Response> = HandlerToken::new("fork_matrix.exec_bin");

async fn handle_bash(args: BashArgs, _ctx: &mut HandlerCtx<'_>) -> Result<Response, HandlerError> {
    Ok(run_exec_argv(
        vec!["bash".into(), "-c".into(), args.cmd],
        args.timeout_secs,
    )
    .await)
}

async fn handle_exec_bin(
    args: ExecBinArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Response, HandlerError> {
    Ok(run_exec_argv(args.argv, args.timeout_secs).await)
}

async fn dispatch_bash(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    cmd: String,
    timeout_secs: Option<u64>,
) -> Response {
    run.send_named_typed(handle, &BASH, BashArgs { cmd, timeout_secs })
        .await
        .unwrap_or_else(|error| Response::Error { error })
}

async fn dispatch_exec_bin(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    argv: Vec<String>,
    timeout_secs: Option<u64>,
) -> Response {
    run.send_named_typed(handle, &EXEC_BIN, ExecBinArgs { argv, timeout_secs })
        .await
        .unwrap_or_else(|error| Response::Error { error })
}

async fn run_exec_argv(argv: Vec<String>, timeout_secs: Option<u64>) -> Response {
    if argv.is_empty() {
        return Response::Error {
            error: "exec: empty argv".into(),
        };
    }

    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Response::Error {
                error: format!("exec spawn: {e}"),
            };
        }
    };

    let mut child_stdout = child.stdout.take().expect("stdout was piped");
    let mut child_stderr = child.stderr.take().expect("stderr was piped");
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(10));
    let result = tokio::time::timeout(timeout, async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let (stdout_result, stderr_result, status) = tokio::join!(
            child_stdout.read_to_end(&mut out),
            child_stderr.read_to_end(&mut err),
            child.wait(),
        );
        let _ = stdout_result;
        let _ = stderr_result;
        (out, err, status)
    })
    .await;

    match result {
        Ok((out, err, Ok(status))) => Response::ExecResult {
            exit_code: status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out).to_string(),
            stderr: String::from_utf8_lossy(&err).to_string(),
        },
        Ok((_, _, Err(e))) => Response::Error {
            error: format!("exec wait: {e}"),
        },
        Err(_) => {
            let _ = child.start_kill();
            Response::ExecTimeout {
                stderr: format!(
                    "process timed out after {}s (likely deadlocked)",
                    timeout.as_secs()
                ),
            }
        }
    }
}

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

const DEPTH_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,
    AgentName::Dpg1Dpg1,
    AgentName::Dpg1Dpg1Dpg1,
];

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

// ═══════════════════════════════════════════════════════════════════
// EXEC METHOD (script files, nested bash, etc.)
// ═══════════════════════════════════════════════════════════════════

struct ExecMethodCase {
    name: &'static str,
    /// Bash -c command. {`self_exe`} is replaced with the test binary path.
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
        cmd_template: "echo '#!/usr/bin/env bash' > /tmp/xm.sh && echo 'echo script_env_ok' >> /tmp/xm.sh && chmod +x /tmp/xm.sh && /tmp/xm.sh; EXIT=$?; rm -f /tmp/xm.sh; exit $EXIT",
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
        name: "script_exec_node",
        cmd_template: "echo '#!/usr/bin/bash' > /tmp/xm.sh && echo 'exec /usr/local/bin/node -e \"console.log(\\\"exec_ok\\\")\"' >> /tmp/xm.sh && chmod +x /tmp/xm.sh && /tmp/xm.sh; EXIT=$?; rm -f /tmp/xm.sh; exit $EXIT",
        expected: "exec_ok",
    },
];

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
    Harness(crate::BinaryType),
    Node,
}

impl DfBinary {
    fn suffix(self) -> &'static str {
        match self {
            Self::Harness(bt) => bt.label(),
            Self::Node => "node",
        }
    }
    fn expected(self) -> &'static str {
        match self {
            Self::Harness(_) => "ECHO_TEST_OK",
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
const DF_BINARIES: &[DfBinary] = &[
    DfBinary::Harness(crate::BinaryType::PieGlibc),
    DfBinary::Harness(crate::BinaryType::NonPieGlibc),
    DfBinary::Harness(crate::BinaryType::StaticPieGlibc),
    DfBinary::Harness(crate::BinaryType::StaticPieMusl),
    DfBinary::Harness(crate::BinaryType::NonPieStaticMusl),
    DfBinary::Node,
];
const DF_INVOCATIONS: &[DfInvocation] = &[DfInvocation::Direct, DfInvocation::ScriptFile];
const DF_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1];

// ═══════════════════════════════════════════════════════════════════
// STRESS EXEC: mode × spawn method
// ═══════════════════════════════════════════════════════════════════

const STRESS_MODES: &[&str] = &["pie", "nonpie", "mixed"];
const SPAWN_METHODS: &[(&str, &[&str])] = &[("sync", &[]), ("tokio", &["tokio"])];

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

// ═══════════════════════════════════════════════════════════════════
// CONTAMINATION PATTERNS
// ═══════════════════════════════════════════════════════════════════

struct ContaminationCase {
    name: &'static str,
    /// Bash command template. {`self_exe`} is replaced. None = special init-level test.
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

// ═══════════════════════════════════════════════════════════════════
// RUNNER
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_fork_matrix(reg: &mut Registry<'_>) {
    register_handler!(BASH, handle_bash);
    register_handler!(EXEC_BIN, handle_exec_bin);

    // Shell patterns x depth
    for &agent in DEPTH_AGENTS {
        for pat in SHELL_PATTERNS {
            let id = format!("XB.{}.{agent}", pat.name);
            let agent_label = agent.to_string();
            let expected = pat.expected.to_string();
            let cmd_str = pat.cmd.to_string();

            reg.test("fork", "fork_matrix", id)
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        Box::pin(async move {
                            let resp = dispatch_bash(run, &handle, cmd_str, None).await;
                            let pass = if expected.is_empty() {
                                matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if !stdout.trim().is_empty()
                                )
                            } else {
                                matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if stdout.contains(&*expected)
                                )
                            };
                            let timeout = matches!(
                                &resp,
                                Response::ExecTimeout { stderr } if !stderr.is_empty()
                            );
                            super::TestOutcome::new(
                                &agent_label,
                                pass,
                                format!("timeout={timeout} {resp:?}"),
                            )
                        })
                    })
                });
        }
    }

    // Exec binary: Node x depth
    for &agent in DEPTH_AGENTS {
        let id = format!("X.node.{agent}");
        let agent_label = agent.to_string();
        reg.test("fork", "fork_matrix", id)
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    Box::pin(async move {
                        let expected = format!("node_{agent_label}_ok");
                        let resp = dispatch_exec_bin(
                            run,
                            &handle,
                            vec![
                                "/usr/local/bin/node".into(),
                                "-e".into(),
                                format!("console.log('node_{agent_label}_ok')"),
                            ],
                            None,
                        )
                        .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.contains(&expected)
                        );
                        super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                    })
                })
            });
    }

    // Node.js process.stdout.write
    reg.test("fork", "fork_matrix", "X.node_stdout_write.A")
        .timeout(60)
        .build(move |cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let resp = dispatch_exec_bin(
                        run,
                        &handle,
                        vec![
                            "/usr/local/bin/node".into(),
                            "-e".into(),
                            "process.stdout.write('stdout_write_ok\\n')".into(),
                        ],
                        None,
                    )
                    .await;
                    let pass = matches!(
                        &resp,
                        Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("stdout_write_ok")
                    );
                    super::TestOutcome::new("A", pass, format!("{resp:?}"))
                })
            })
        });

    // Exec method tests
    for em in EXEC_METHODS {
        let bts: &[Option<crate::BinaryType>] = if em.cmd_template.contains("{self_exe}") {
            &[
                Some(crate::BinaryType::PieGlibc),
                Some(crate::BinaryType::NonPieGlibc),
                Some(crate::BinaryType::StaticPieGlibc),
                Some(crate::BinaryType::StaticPieMusl),
                Some(crate::BinaryType::NonPieStaticMusl),
            ]
        } else {
            &[None]
        };
        for &bt_opt in bts {
            let id = match bt_opt {
                Some(bt) => format!("XM.{}.{}", bt.label(), em.name),
                None => format!("XM.{}", em.name),
            };
            let template = em.cmd_template.to_string();
            let expected = em.expected.to_string();
            let agent = AgentName::Dpg1;
            let agent_label = agent.to_string();
            reg.test("fork", "fork_matrix", id)
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let template = template.clone();
                        let expected = expected.clone();
                        let agent_label = agent_label.clone();
                        Box::pin(async move {
                            let self_exe = run.self_exe().to_string();
                            let target = match bt_opt {
                                Some(bt) => crate::binary_path(bt, &self_exe),
                                None => self_exe,
                            };
                            let cmd_str = template.replace("{self_exe}", &target);
                            let resp = dispatch_bash(run, &handle, cmd_str, None).await;
                            let pass = matches!(
                                &resp,
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.trim() == expected
                            );
                            super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }

    // XM.node_networkInterfaces — blockers-added family.
    // Doesn't take a BinaryType axis: the binary is the system node, not self_exe.
    for &(agent, suffix) in &[
        (AgentName::Dpg1, ""),
        (AgentName::Dpg1Dpg1, ".AA"),
        (AgentName::Dpg2, ".B"),
        (AgentName::Dpg1Dng, ".dpg1_dng"),
    ] {
        let id = format!("XM.node_networkInterfaces{suffix}");
        let agent_label = agent.to_string();
        reg.test("fork", "fork_matrix", id)
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let agent_label = agent_label.clone();
                    Box::pin(async move {
                        let resp = dispatch_exec_bin(
                            run,
                            &handle,
                            vec![
                                "/usr/local/bin/node".into(),
                                "-e".into(),
                                "try { const r = require('os').networkInterfaces(); \
                                 console.log('NETIF_OK:' + Object.keys(r).length); } \
                                 catch(e) { console.log('NETIF_ERR:' + e.code); }"
                                    .into(),
                            ],
                            Some(30),
                        )
                        .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout
                                    .lines()
                                    .find_map(|l| l.strip_prefix("NETIF_OK:"))
                                    .and_then(|s| s.trim().parse::<u32>().ok())
                                    .is_some_and(|n| n > 0)
                        );
                        super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                    })
                })
            });
    }

    // Delayed fork matrix
    for &trigger in DF_TRIGGERS {
        for &binary in DF_BINARIES {
            for &invocation in DF_INVOCATIONS {
                for &agent in DF_AGENTS {
                    let id = format!(
                        "XDF.{}.{}.{}.{agent}",
                        binary.suffix(),
                        trigger.suffix(),
                        invocation.suffix()
                    );
                    let agent_label = agent.to_string();
                    let trigger_sub = trigger.subcommand().to_string();
                    let binary_expected = binary.expected().to_string();

                    reg.test("fork", "fork_matrix", id)
                        .timeout(60)
                        .build(move |cx| {
                            let handle = cx.require(agent);
                            Box::new(move |run| {
                                Box::pin(async move {
                                    let self_exe = run.self_exe().to_string();
                                    let (inner_cmd, inner_args): (String, Vec<String>) =
                                        match binary {
                                            DfBinary::Harness(bt) => (
                                                crate::binary_path(bt, &self_exe),
                                                vec!["echo-test".into()],
                                            ),
                                            DfBinary::Node => (
                                                "/usr/local/bin/node".into(),
                                                vec![
                                                    "-e".into(),
                                                    "console.log('df_node_ok')".into(),
                                                ],
                                            ),
                                        };

                                    let resp = match invocation {
                                        DfInvocation::Direct => {
                                            let mut args = vec![
                                                self_exe.clone(),
                                                trigger_sub.clone(),
                                                inner_cmd,
                                            ];
                                            args.extend(inner_args);
                                            dispatch_exec_bin(run, &handle, args, None).await
                                        }
                                        DfInvocation::ScriptFile => {
                                            let test_id_safe = format!(
                                                "XDF_{}_{}_{}_{}",
                                                trigger.suffix(),
                                                binary.suffix(),
                                                invocation.suffix(),
                                                agent_label
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
                                                            format!(
                                                                "\"{}\"",
                                                                a.replace('"', "\\\"")
                                                            )
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
                                            dispatch_bash(run, &handle, body, None).await
                                        }
                                    };

                                    let not_found = matches!(
                                        &resp,
                                        Response::ExecResult { exit_code: 127, .. }
                                    ) || matches!(
                                        &resp,
                                        Response::Error { error }
                                            if error.contains("not found")
                                    );
                                    if not_found {
                                        return super::TestOutcome::new(
                                            &agent_label,
                                            false,
                                            "FAIL: binary not in rootfs",
                                        );
                                    }

                                    let pass = matches!(
                                        &resp,
                                        Response::ExecResult {
                                            exit_code: 0, stdout, ..
                                        } if stdout.contains(&*binary_expected)
                                    );
                                    super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                                })
                            })
                        });
                }
            }
        }
    }

    // BSF.<bt> — buffered-SCM-fork. Validates p4-fork-restore-tokens:
    // parent buffers an eventfd in a socketpair's recv queue via
    // sendmsg(SCM_RIGHTS), then fork+execs into `bt`. When `bt` is a
    // different binary type from the parent (Dpg1), the cross-host
    // bridge in `commit_delayed_fork` must serialize the buffered
    // SCM_RIGHTS fd via a `BrokerFdToken` for the child to recvmsg
    // a working fd. Native: all binaries pass (real kernel keeps the
    // buffered fd live across fork). Litebox today: returns ENOSYS
    // when buffered_fds is non-empty for a cross-worker bridge.
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test("fork", "fork_matrix", format!("BSF.{bt_label}"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(AgentName::Dpg1);
                Box::new(move |run| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let child_target = crate::binary_path(bt, &self_exe);
                        let result = run
                            .send_named_typed(
                                &handle,
                                &common::EXEC_BIN,
                                common::ExecBinArgs {
                                    argv: vec![
                                        self_exe,
                                        "unix-socket-test".into(),
                                        "buffered-scm-fork".into(),
                                        child_target,
                                    ],
                                    timeout_ms: Some(50_000),
                                    stdin: None,
                                    env: vec![],
                                },
                            )
                            .await;
                        let pass = matches!(
                            &result,
                            Ok(out) if out.exit_code == 0 && out.stdout.contains("BSF_OK")
                        );
                        super::TestOutcome::new("A", pass, format!("{result:?}"))
                    })
                })
            });
    }

    // SXF.<bt> — socketpair-fork-cross. Validates p1-socketpair-fork:
    // parent socketpair → fork+execv into <bt> child → PING/PONG over
    // the inherited endpoint. When <bt> differs from the parent's
    // binary type (Dpg1), commit_delayed_fork must bridge both
    // endpoints across host workers. Today the bridge replaces the
    // unix socket with a host pipe; the basic byte round-trip survives
    // but AF_UNIX semantics (SCM_RIGHTS, SO_PEERCRED, abstract names)
    // are lost — the BSF.<bt> test pins the SCM-loss subset.
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test("fork", "fork_matrix", format!("SXF.{bt_label}"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(AgentName::Dpg1);
                Box::new(move |run| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let child_target = crate::binary_path(bt, &self_exe);
                        let result = run
                            .send_named_typed(
                                &handle,
                                &common::EXEC_BIN,
                                common::ExecBinArgs {
                                    argv: vec![
                                        self_exe,
                                        "unix-socket-test".into(),
                                        "socketpair-fork-cross".into(),
                                        child_target,
                                    ],
                                    timeout_ms: Some(50_000),
                                    stdin: None,
                                    env: vec![],
                                },
                            )
                            .await;
                        let pass = matches!(
                            &result,
                            Ok(out) if out.exit_code == 0 && out.stdout.contains("SXF_OK")
                        );
                        super::TestOutcome::new("A", pass, format!("{result:?}"))
                    })
                })
            });
    }

    // PIF.<bt> — pidfd-inherit-fork. Validates p1-pidfd-inherit:
    // parent spawns a grandchild, pidfd_open's it, fork+execvs into
    // <bt> child that poll+waitid's on the inherited pidfd. When <bt>
    // differs from the parent's binary type, commit_delayed_fork must
    // migrate the pidfd to the child's worker — there is currently no
    // broker-side pidfd state, so the migration may drop the pidfd or
    // fail outright.
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test("fork", "fork_matrix", format!("PIF.{bt_label}"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(AgentName::Dpg1);
                Box::new(move |run| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let child_target = crate::binary_path(bt, &self_exe);
                        let result = run
                            .send_named_typed(
                                &handle,
                                &common::EXEC_BIN,
                                common::ExecBinArgs {
                                    argv: vec![
                                        self_exe,
                                        "unix-socket-test".into(),
                                        "pidfd-inherit-fork".into(),
                                        child_target,
                                    ],
                                    timeout_ms: Some(50_000),
                                    stdin: None,
                                    env: vec![],
                                },
                            )
                            .await;
                        let pass = matches!(
                            &result,
                            Ok(out) if out.exit_code == 0 && out.stdout.contains("PIF_OK")
                        );
                        super::TestOutcome::new("A", pass, format!("{result:?}"))
                    })
                })
            });
    }

    // XDF.triple_nesting
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test(
            "fork",
            "fork_matrix",
            format!("XDF.{bt_label}.triple_nesting"),
        )
        .timeout(60)
        .build(move |cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let self_exe = run.self_exe().to_string();
                    let target = crate::binary_path(bt, &self_exe);
                    let resp = dispatch_exec_bin(
                        run,
                        &handle,
                        vec![
                            target.clone(),
                            "trigger-delayed-fork".into(),
                            target.clone(),
                            "trigger-delayed-fork".into(),
                            target,
                            "echo-test".into(),
                        ],
                        None,
                    )
                    .await;
                    let pass = matches!(
                        &resp,
                        Response::ExecResult { exit_code: 0, stdout, .. }
                            if stdout.contains("ECHO_TEST_OK")
                    );
                    super::TestOutcome::new("A", pass, format!("{resp:?}"))
                })
            })
        });
    }

    // Stress exec matrix
    for &mode in STRESS_MODES {
        for &(spawn_name, spawn_args) in SPAWN_METHODS {
            for &bt in crate::BinaryType::ALL {
                let bt_label = bt.label();
                let id = format!("XS.{bt_label}.{mode}.{spawn_name}");
                let mode_s = mode.to_string();
                let extra: Vec<String> = spawn_args
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                reg.test("fork", "fork_matrix", id)
                    .timeout(60)
                    .build(move |cx| {
                        let handle = cx.require(AgentName::Dpg1);
                        Box::new(move |run| {
                            let extra = extra.clone();
                            let mode_s = mode_s.clone();
                            Box::pin(async move {
                                let self_exe = run.self_exe().to_string();
                                let target = crate::binary_path(bt, &self_exe);
                                let mut args =
                                    vec![target, "stress-exec".into(), "10".into(), mode_s];
                                args.extend(extra);
                                let resp = dispatch_exec_bin(run, &handle, args, None).await;
                                let pass = matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if stdout.contains("STRESS_START")
                                            && stdout.contains("STRESS_END failures=0")
                                );
                                super::TestOutcome::new("A", pass, format!("{resp:?}"))
                            })
                        })
                    });
            }
        }
    }

    // Binary invocation tests
    for nc in NONPIE_CASES {
        for &bt in crate::BinaryType::ALL {
            let bt_label = bt.label();
            let id = format!("XNP.{bt_label}.{}", nc.name);
            let bash_cmd = nc.bash_cmd.map(std::string::ToString::to_string);
            reg.test("fork", "fork_matrix", id)
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(AgentName::Dpg1);
                    Box::new(move |run| {
                        let bash_cmd = bash_cmd.clone();
                        Box::pin(async move {
                            let self_exe = run.self_exe().to_string();
                            let target_bin = crate::binary_path(bt, &self_exe);
                            let resp = match &bash_cmd {
                                None => {
                                    dispatch_exec_bin(
                                        run,
                                        &handle,
                                        vec![target_bin.clone(), "echo-test".into()],
                                        None,
                                    )
                                    .await
                                }
                                Some(cmd) => {
                                    let resolved = cmd
                                        .replace("/nonpie-bin", &target_bin)
                                        .replace("/nonpie-cmd", &format!("{target_bin} echo-test"));
                                    dispatch_bash(run, &handle, resolved, None).await
                                }
                            };
                            let not_found =
                                matches!(&resp, Response::ExecResult { exit_code: 127, .. })
                                    || matches!(&resp, Response::Error { .. });
                            let skipped = matches!(
                                &resp,
                                Response::ExecResult { stdout, .. }
                                    if stdout.contains("SKIP")
                            );
                            if not_found || skipped {
                                return super::TestOutcome::new(
                                    "A",
                                    false,
                                    "FAIL: binary not found",
                                );
                            }
                            let pass = matches!(
                                &resp,
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.contains("ECHO_TEST_OK")
                            );
                            super::TestOutcome::new("A", pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }

    // XC.init_level
    for &bt in crate::BinaryType::ALL {
        let bt_label = bt.label();
        reg.test("fork", "fork_matrix", format!("XC.{bt_label}.init_level"))
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(AgentName::Dpg1);
                Box::new(move |run| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let nonpie_bin = crate::nonpie_binary();
                        let target = crate::binary_path(bt, &self_exe);
                        let resp = dispatch_exec_bin(
                            run,
                            &handle,
                            vec![nonpie_bin, "echo-test".into()],
                            None,
                        )
                        .await;
                        let not_found =
                            matches!(&resp, Response::ExecResult { exit_code: 127, .. })
                                || matches!(&resp, Response::Error { .. });
                        if not_found {
                            return super::TestOutcome::new(
                                "A",
                                false,
                                "FAIL: nonpie binary not found",
                            );
                        }
                        let resp2 =
                            dispatch_exec_bin(run, &handle, vec![target, "echo-test".into()], None)
                                .await;
                        let pass = matches!(
                            &resp2,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.trim() == "ECHO_TEST_OK"
                        );
                        super::TestOutcome::new("A", pass, format!("{resp2:?}"))
                    })
                })
            });
    }

    // Contamination pattern cases
    for cc in CONTAMINATION_CASES {
        let bts: &[Option<crate::BinaryType>] = if cc.bash_template.unwrap().contains("{self_exe}")
        {
            &[
                Some(crate::BinaryType::PieGlibc),
                Some(crate::BinaryType::NonPieGlibc),
                Some(crate::BinaryType::StaticPieGlibc),
                Some(crate::BinaryType::StaticPieMusl),
                Some(crate::BinaryType::NonPieStaticMusl),
            ]
        } else {
            &[None]
        };
        for &bt_opt in bts {
            let id = match bt_opt {
                Some(bt) => format!("XC.{}.{}", bt.label(), cc.name),
                None => format!("XC.{}", cc.name),
            };
            let template = cc.bash_template.unwrap().to_string();
            let expected = cc.expected.to_string();
            reg.test("fork", "fork_matrix", id)
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(AgentName::Dpg1);
                    Box::new(move |run| {
                        let template = template.clone();
                        let expected = expected.clone();
                        Box::pin(async move {
                            let self_exe = run.self_exe().to_string();
                            let nonpie_bin = crate::nonpie_binary();
                            let target = match bt_opt {
                                Some(bt) => crate::binary_path(bt, &self_exe),
                                None => self_exe,
                            };
                            let nonpie_cmd = format!("{nonpie_bin} echo-test");
                            let cmd_str = template
                                .replace("{self_exe}", &target)
                                .replace("/nonpie-bin", &nonpie_bin)
                                .replace("/nonpie-cmd", &nonpie_cmd);
                            let resp = dispatch_bash(run, &handle, cmd_str, None).await;
                            let skipped = matches!(
                                &resp,
                                Response::ExecResult { stdout, .. }
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
                                Response::ExecResult { exit_code: 0, stdout, .. }
                                    if stdout.contains(&*expected)
                            );
                            super::TestOutcome::new("A", pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}
