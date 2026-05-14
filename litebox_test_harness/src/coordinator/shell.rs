// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shell-redirect and substitution test families.
//!
//! Hosts six bash-driven test clusters:
//!
//! | Prefix | Cluster |
//! |--------|---------|
//! | SP     | Stdin-pipe command substitution |
//! | SC     | Substitution capture (`$()`) |
//! | TR     | Touch + redirect file coherence |
//! | FR     | File-redirect — stdout of background process → file |
//! | BR     | Background redirect poll — file visibility while backgrounded |
//! | BRS    | Background redirect stdin poll — stdin pipe + stdout redirect |

#![allow(clippy::items_after_statements)]

use crate::protocol::Response;

use super::agents::AgentName;
use super::matrix::{EXEC, ExecArgs};
use super::registry::Registry;

const AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2];

// ═══════════════════════════════════════════════════════════════════
// SP: stdin-pipe command substitution
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_stdin_pipe_subst_tests(reg: &mut Registry<'_>) {
    struct Def {
        name: &'static str,
        script: &'static str,
        expected: &'static str,
    }
    let defs: &[Def] = &[
        Def {
            name: "simple",
            script: "X=$(echo hello)\necho R=$X\n",
            expected: "R=hello",
        },
        Def {
            name: "pipeline",
            script: "X=$(echo hello | cat)\necho R=$X\n",
            expected: "R=hello",
        },
        Def {
            name: "file_read",
            script: "X=$(head -1 /etc/passwd)\necho R=${X%%:*}\n",
            expected: "R=root",
        },
        Def {
            name: "file_pipe",
            script: "X=$(cat /etc/passwd | head -1)\necho R=${X%%:*}\n",
            expected: "R=root",
        },
        Def {
            name: "multi_subst",
            script: "A=$(echo first)\nB=$(echo second)\necho R=$A.$B\n",
            expected: "R=first.second",
        },
        Def {
            name: "os_detect",
            script: "ARCH=$(uname -m)\nPLATFORM=$(uname -s)\necho R=$ARCH.$PLATFORM\n",
            expected: "R=x86_64.Linux",
        },
    ];
    for &agent in AGENTS {
        for def in defs {
            let agent_s = agent.to_string();
            let script: String = def.script.into();
            let expected: String = def.expected.into();
            let name = def.name;
            reg.test("shell", "stdin_pipe_subst", format!("SP.{name}.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let s = script.clone();
                        let exp = expected.clone();
                        Box::pin(async move {
                            let resp = run
                                .typed_or_error(
                                    &handle,
                                    &EXEC,
                                    ExecArgs {
                                        args: vec!["/bin/sh".into()],
                                        timeout_secs: Some(15),
                                        stdin: Some(s),
                                        background: false,
                                        env: vec![],
                                    },
                                )
                                .await;
                            let pass = matches!(
                                &resp,
                                Response::ExecResult { stdout, .. }
                                    if stdout.trim() == exp
                            );
                            super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// SC: Substitution capture
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_subst_capture_tests(reg: &mut Registry<'_>) {
    struct Def {
        name: &'static str,
        script: &'static str,
        check: fn(&str) -> bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "echo",
            script: "X=$(echo hello); echo $X",
            check: |s| s.trim() == "hello",
        },
        Def {
            name: "cat",
            script: "X=$(cat /etc/hostname); echo $X",
            check: |s| !s.trim().is_empty(),
        },
        Def {
            name: "readlink",
            script: "X=$(readlink -f /usr/bin/bash); echo $X",
            check: |s| s.trim().contains("bash"),
        },
        Def {
            name: "dirname",
            script: "X=$(dirname /usr/bin/bash); echo $X",
            check: |s| s.trim() == "/usr/bin",
        },
        Def {
            name: "nested",
            script: "X=$(dirname $(readlink -f /usr/bin/bash)); echo $X",
            check: |s| !s.trim().is_empty() && s.trim() != "/",
        },
        Def {
            name: "vscode_root",
            script: concat!(
                "SCRIPT=$(which bash); ",
                "ROOT=$(dirname $(dirname $(readlink -f $SCRIPT))); ",
                "echo $ROOT",
            ),
            check: |s| !s.trim().is_empty() && s.trim() != "/" && s.trim() != "",
        },
        Def {
            name: "which",
            script: "X=$(which bash); echo $X",
            check: |s| s.trim().contains("bash"),
        },
        Def {
            name: "uname",
            script: "X=$(uname -m); echo $X",
            check: |s| s.trim() == "x86_64",
        },
    ];
    for &agent in AGENTS {
        for def in defs {
            let agent_s = agent.to_string();
            let script: String = def.script.into();
            let check = def.check;
            let name = def.name;
            reg.test("shell", "subst_capture", format!("SC.{name}.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let s = script.clone();
                        Box::pin(async move {
                            let resp = run
                                .typed_or_error(
                                    &handle,
                                    &EXEC,
                                    ExecArgs {
                                        args: vec!["bash".into(), "-c".into(), s],
                                        timeout_secs: Some(10),
                                        stdin: None,
                                        background: false,
                                        env: vec![],
                                    },
                                )
                                .await;
                            let pass = matches!(
                                &resp,
                                Response::ExecResult { stdout, .. }
                                    if check(stdout)
                            );
                            super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// TR: Touch + redirect file coherence
// ═══════════════════════════════════════════════════════════════════

pub(crate) fn register_touch_redirect_tests(reg: &mut Registry<'_>) {
    struct Def {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "no_touch",
            script_template: concat!(
                "rm -f {path}; ",
                "{exe} echo-test > {path} 2>&1\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "touch",
            script_template: concat!(
                "rm -f {path}; touch {path}; ",
                "{exe} echo-test > {path} 2>&1\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "touch_chmod",
            script_template: concat!(
                "rm -f {path}; touch {path}; chmod 600 {path}; ",
                "{exe} echo-test > {path} 2>&1\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "echo_touch",
            script_template: concat!(
                "rm -f {path}; echo init > {path}; ",
                "{exe} echo-test > {path} 2>&1\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "builtin_touch",
            script_template: concat!(
                "rm -f {path}; touch {path}; chmod 600 {path}; ",
                "echo builtin-data > {path} &\n",
                "wait\ncat {path}\n",
            ),
            check: |s| s.contains("builtin-data"),
        },
    ];
    for &agent in AGENTS {
        for def in defs {
            let agent_s = agent.to_string();
            let template: String = def.script_template.into();
            let check = def.check;
            let name = def.name;
            reg.test("shell", "touch_redirect", format!("TR.{name}.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let t = template.clone();
                        let self_exe = run.self_exe().to_string();
                        Box::pin(async move {
                            let path = format!("/shared/tr-{name}-{a}.txt");
                            let script = t.replace("{path}", &path).replace("{exe}", &self_exe);
                            let resp = run
                                .typed_or_error(
                                    &handle,
                                    &EXEC,
                                    ExecArgs {
                                        args: vec!["bash".into(), "-c".into(), script],
                                        timeout_secs: Some(10),
                                        stdin: None,
                                        background: false,
                                        env: vec![],
                                    },
                                )
                                .await;
                            let pass = matches!(
                                &resp,
                                Response::ExecResult { stdout, .. }
                                    if check(stdout)
                            );
                            super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// FR: File-Redirect — stdout of background process → file
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_file_redirect_tests(reg: &mut Registry<'_>) {
    struct Def {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
        /// If true, the template substitutes `{exe}` and the test
        /// gains a `BinaryType` axis. Otherwise the test is a pure
        /// shell-builtin operation with no binary dimension.
        per_binary_type: bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "fg_redirect",
            script_template: concat!("echo FR_FG > {path}\n", "cat {path}\n"),
            check: |s| s.contains("FR_FG"),
            per_binary_type: false,
        },
        Def {
            name: "bg_echo",
            script_template: concat!("echo FR_BGECHO > {path} &\n", "wait\n", "cat {path}\n"),
            check: |s| s.contains("FR_BGECHO"),
            per_binary_type: false,
        },
        Def {
            name: "bg_exe",
            script_template: concat!("{exe} echo-test > {path} &\n", "wait\n", "cat {path}\n"),
            check: |s| s.contains("ECHO_TEST_OK"),
            per_binary_type: true,
        },
        Def {
            name: "bg_cat_pipe",
            script_template: concat!("echo FR_PIPE | cat > {path} &\n", "wait\n", "cat {path}\n",),
            check: |s| s.contains("FR_PIPE"),
            per_binary_type: false,
        },
        Def {
            name: "bg_append",
            script_template: concat!(
                "echo LINE1 > {path}\n",
                "echo LINE2 >> {path} &\n",
                "wait\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("LINE1") && s.contains("LINE2"),
            per_binary_type: false,
        },
    ];
    for &agent in AGENTS {
        for def in defs {
            // For per-binary-type variants, generate a test per leg of
            // BinaryType::ALL. For shell-builtin variants, generate
            // exactly one test (the binary type is irrelevant).
            let bts: &[Option<crate::BinaryType>] = if def.per_binary_type {
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
                let agent_s = agent.to_string();
                let template: String = def.script_template.into();
                let check = def.check;
                let name = def.name;
                let test_id = match bt_opt {
                    None => format!("FR.{name}.{agent}"),
                    Some(bt) => format!("FR.{name}.{}.{agent}", bt.label()),
                };
                let path_label = match bt_opt {
                    None => name.to_string(),
                    Some(bt) => format!("{name}-{}", bt.label()),
                };
                reg.test("shell", "file_redirect", test_id)
                    .timeout(60)
                    .build(move |cx| {
                        let handle = cx.require(agent);
                        Box::new(move |run| {
                            let a = agent_s.clone();
                            let t = template.clone();
                            let path_label = path_label.clone();
                            let self_exe = run.self_exe().to_string();
                            Box::pin(async move {
                                let path = format!("/shared/fr-{path_label}-{a}.txt");
                                let exe_path = match bt_opt {
                                    None => self_exe.clone(),
                                    Some(bt) => crate::binary_path(bt, &self_exe),
                                };
                                let script = t.replace("{path}", &path).replace("{exe}", &exe_path);
                                let resp = run
                                    .typed_or_error(
                                        &handle,
                                        &EXEC,
                                        ExecArgs {
                                            args: vec!["bash".into(), "-c".into(), script],
                                            timeout_secs: Some(10),
                                            stdin: None,
                                            background: false,
                                            env: vec![],
                                        },
                                    )
                                    .await;
                                let pass = matches!(
                                    &resp,
                                    Response::ExecResult { stdout, .. }
                                        if check(stdout)
                                );
                                super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                            })
                        })
                    });
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// BR: Background Redirect Poll — file visibility while backgrounded
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_bg_redirect_poll_tests(reg: &mut Registry<'_>) {
    #[derive(Clone, Copy)]
    struct Def {
        name: &'static str,
        marker: &'static str,
        script_template: &'static str,
        per_binary_type: bool,
    }

    let defs = [
        Def {
            name: "subshell_stdout",
            marker: "BR_SUBSHELL_STDOUT",
            script_template: "(echo BR_SUBSHELL_STDOUT; sleep 1) > {path} &\n",
            per_binary_type: false,
        },
        Def {
            name: "exe_stdout",
            marker: "ECHO_TEST_OK",
            script_template: "{exe} echo-test > {path} &\n",
            per_binary_type: true,
        },
        Def {
            name: "exe_stderr",
            marker: "STDERR_ONLY_OK",
            script_template: "{exe} stderr-only-test > {path} 2>&1 &\n",
            per_binary_type: true,
        },
    ];

    for &agent in AGENTS {
        for def in defs {
            let bts: &[Option<crate::BinaryType>] = if def.per_binary_type {
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
                let agent_s = agent.to_string();
                let test_id = match bt_opt {
                    None => format!("BR.{}.{agent}", def.name),
                    Some(bt) => format!("BR.{}.{}.{agent}", def.name, bt.label()),
                };
                let path_label = match bt_opt {
                    None => def.name.to_string(),
                    Some(bt) => format!("{}-{}", def.name, bt.label()),
                };
                reg.test("shell", "bg_redirect_poll", test_id)
                    .timeout(60)
                    .build(move |cx| {
                        let handle = cx.require(agent);
                        Box::new(move |run| {
                            let a = agent_s.clone();
                            let path_label = path_label.clone();
                            let self_exe = run.self_exe().to_string();
                            Box::pin(async move {
                                let path = format!("/shared/br-{path_label}-{a}.txt");
                                let exe_path = match bt_opt {
                                    None => self_exe.clone(),
                                    Some(bt) => crate::binary_path(bt, &self_exe),
                                };
                                let script = format!(
                                    "{}PID=$!\nfor _ in 1 2 3 4 5 6 7 8 9 10; do\n  if grep -q '{}' '{}'; then\n    kill $PID 2>/dev/null; wait $PID 2>/dev/null\n    cat '{}'\n    exit 0\n  fi\n  sleep 0.1\ndone\nkill $PID 2>/dev/null; wait $PID 2>/dev/null\ncat '{}' 2>/dev/null\nexit 1\n",
                                    def.script_template
                                        .replace("{path}", &path)
                                        .replace("{exe}", &exe_path),
                                    def.marker,
                                    path,
                                    path,
                                    path,
                                );
                                let resp = run.typed_or_error(&handle, &EXEC, ExecArgs { args: vec!["bash".into(), "-c".into(), script], timeout_secs: Some(10), stdin: None, background: false, env: vec![] }).await;
                                let pass = matches!(
                                    &resp,
                                    Response::ExecResult { exit_code: 0, stdout, .. }
                                        if stdout.contains(def.marker)
                                );
                                super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                            })
                        })
                    });
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// BRS: Background Redirect Stdin Poll — stdin pipe + stdout redirect
// ═══════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_bg_redirect_stdin_poll_tests(reg: &mut Registry<'_>) {
    #[derive(Clone, Copy)]
    struct Def {
        name: &'static str,
        consumer_template: &'static str,
        per_binary_type: bool,
    }

    const SHELLS: &[(&str, &str)] = &[("bash", "bash"), ("sh", "sh")];
    const DELIVERIES: &[&str] = &["tokio_pipe", "bash_heredoc_pipe"];
    let defs = [
        Def {
            name: "subshell_stdin",
            consumer_template: "cat",
            per_binary_type: false,
        },
        Def {
            name: "exe_stdin",
            consumer_template: "{exe} stdin-echo-test",
            per_binary_type: true,
        },
    ];

    for &agent in AGENTS {
        for &(shell_name, shell_bin) in SHELLS {
            for &delivery in DELIVERIES {
                for def in defs {
                    let bts: &[Option<crate::BinaryType>] = if def.per_binary_type {
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
                        let agent_s = agent.to_string();
                        let test_id = match bt_opt {
                            None => format!("BRS.{}.{shell_name}.{delivery}.{agent}", def.name),
                            Some(bt) => format!(
                                "BRS.{}.{shell_name}.{delivery}.{}.{agent}",
                                def.name,
                                bt.label()
                            ),
                        };
                        let path_label = match bt_opt {
                            None => def.name.to_string(),
                            Some(bt) => format!("{}-{}", def.name, bt.label()),
                        };
                        reg.test("shell", "bg_redirect_stdin_poll", test_id)
                            .timeout(60)
                            .build(move |cx| {
                                let handle = cx.require(agent);
                                Box::new(move |run| {
                                    let a = agent_s.clone();
                                    let path_label = path_label.clone();
                                    let self_exe = run.self_exe().to_string();
                                    Box::pin(async move {
                                        let path = format!(
                                            "/shared/brs-{path_label}-{shell_name}-{delivery}-{a}.txt"
                                        );
                                        let marker = format!(
                                            "BRS_PAYLOAD_{}_{}_{}",
                                            def.name, shell_name, delivery
                                        );
                                        let exe_path = match bt_opt {
                                            None => self_exe.clone(),
                                            Some(bt) => crate::binary_path(bt, &self_exe),
                                        };
                                        let consumer = def
                                            .consumer_template
                                            .replace("{exe}", &exe_path);
                                        let (producer_script, stdin) = match delivery {
                                            "tokio_pipe" => (
                                                format!("cat | {consumer} > {path} &\n"),
                                                Some(format!("{marker}\n")),
                                            ),
                                            "bash_heredoc_pipe" => (
                                                format!(
                                                    "cat <<'BRS_EOF' | {consumer} > {path} &\n{marker}\nBRS_EOF\n"
                                                ),
                                                None,
                                            ),
                                            _ => unreachable!(),
                                        };
                                        let script = format!(
                                            "{producer_script}PID=$!\nfor _ in 1 2 3 4 5 6 7 8 9 10; do\n  if grep -q '{marker}' '{path}'; then\n    wait $PID 2>/dev/null\n    cat '{path}'\n    exit 0\n  fi\n  sleep 0.1\ndone\nkill $PID 2>/dev/null; wait $PID 2>/dev/null\ncat '{path}' 2>/dev/null\nexit 1\n"
                                        );
                                        let resp = run.typed_or_error(&handle, &EXEC, ExecArgs { args: vec![shell_bin.into(), "-c".into(), script], timeout_secs: Some(10), stdin, background: false, env: vec![] })
                                        .await;
                                        let pass = matches!(
                                            &resp,
                                            Response::ExecResult { exit_code: 0, stdout, .. }
                                                if stdout.contains(&marker)
                                        );
                                        super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                                    })
                                })
                            });
                    }
                }
            }
        }
    }
}
