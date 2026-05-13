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
//! Test prefixes hosted here:
//!   - `CF.*` — concurrent fork / pipeline / rwlock tests
//!   - `CC.*` — concurrent fork/exec/pipe correctness tests
//!
//! Test axes:
//!   - Pipeline depth: 2, 3, 4 commands
//!   - Command types: cat|cat, cat|grep, echo|sed|sed, cat|grep|sed|sed
//!   - Agent topology: A (depth 1), AA (depth 2), NP (non-PIE worker)
//!   - Subcommand vs bash: protocol Exec(bash -c ...) and direct fork

use serde::{Deserialize, Serialize};

use super::agents::{AgentName, SpawnKind};
use super::common;
use super::matrix::{EXEC, ExecArgs, FS_READ, FsPathArgs};
use super::registry::Registry;
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::protocol::Response;
use crate::register_handler;

/// Agents to run concurrent fork tests on.
const CF_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2];

#[derive(Serialize, Deserialize)]
struct ConcurrentFsArgs {
    n: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct ConcurrentFsOut {
    detail: String,
}

const CONCURRENT_FS: HandlerToken<ConcurrentFsArgs, ConcurrentFsOut> =
    HandlerToken::new("concurrent_fork.concurrent_fs");
const CONCURRENT_FS_MULTI: HandlerToken<ConcurrentFsArgs, ConcurrentFsOut> =
    HandlerToken::new("concurrent_fork.concurrent_fs_multi");

fn fork_binary_label(bt: crate::BinaryType) -> &'static str {
    match bt {
        crate::BinaryType::PieGlibc => "self",
        crate::BinaryType::NonPieGlibc => "nonpie",
        crate::BinaryType::StaticPieGlibc => "static-pie-glibc",
        crate::BinaryType::StaticPieMusl => "static-pie-musl",
        crate::BinaryType::NonPieStaticMusl => "non-pie-static-musl",
    }
}

async fn handle_concurrent_fs(
    args: ConcurrentFsArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ConcurrentFsOut, HandlerError> {
    let n_children = args.n as usize;
    let file_to_open = "/lib/x86_64-linux-gnu/libc.so.6";

    eprintln!("[concurrent-fs] forking {n_children} children, each opens {file_to_open}");

    let mut child_pids = Vec::new();
    for i in 0..n_children {
        let pre_fd = std::fs::File::open(file_to_open);

        // SAFETY: fork is called in a leaf test process. The child does only
        // simple file I/O and exits immediately; the parent records the pid.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            eprintln!("[concurrent-fs] fork {i} failed");
            continue;
        }
        if pid == 0 {
            drop(pre_fd);
            match std::fs::File::open(file_to_open) {
                Ok(mut f) => {
                    use std::io::Read;
                    let mut buf = [0u8; 16];
                    let _ = f.read(&mut buf);
                    drop(f);
                    eprintln!("[concurrent-fs] child {i} OK");
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("[concurrent-fs] child {i} open failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        child_pids.push(pid);
    }

    let all_ok = wait_for_children(&child_pids, "concurrent-fs", "RwLock deadlock?");
    let detail = if all_ok {
        format!("CONCURRENT_FS_OK:{n_children}")
    } else {
        format!("CONCURRENT_FS_FAIL:{n_children} (concurrent open+close deadlocked)")
    };
    Ok(ConcurrentFsOut { detail })
}

async fn handle_concurrent_fs_multi(
    args: ConcurrentFsArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ConcurrentFsOut, HandlerError> {
    let libs: &[&str] = &[
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/x86_64-linux-gnu/libm.so.6",
        "/lib/x86_64-linux-gnu/libdl.so.2",
        "/lib/x86_64-linux-gnu/libpthread.so.0",
        "/lib/x86_64-linux-gnu/librt.so.1",
        "/lib/x86_64-linux-gnu/libresolv.so.2",
        "/lib/x86_64-linux-gnu/libnss_files.so.2",
        "/lib/x86_64-linux-gnu/libnss_dns.so.2",
    ];

    let n_children = args.n as usize;
    eprintln!(
        "[concurrent-fs-multi] forking {n_children} children, each opens {} libs",
        libs.len()
    );

    let mut child_pids = Vec::new();
    for i in 0..n_children {
        let pre_fds: Vec<_> = libs
            .iter()
            .filter_map(|p| std::fs::File::open(p).ok())
            .collect();

        // SAFETY: fork is called in a leaf test process. The child does only
        // simple file I/O and exits immediately; the parent records the pid.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            eprintln!("[concurrent-fs-multi] fork {i} failed");
            continue;
        }
        if pid == 0 {
            drop(pre_fds);

            let mut ok = true;
            for &lib in libs {
                match std::fs::File::open(lib) {
                    Ok(mut f) => {
                        use std::io::Read;
                        let mut buf = [0u8; 16];
                        let _ = f.read(&mut buf);
                        drop(f);
                    }
                    Err(e) => {
                        eprintln!("[concurrent-fs-multi] child {i} open {lib}: {e}");
                        ok = false;
                    }
                }
            }
            eprintln!("[concurrent-fs-multi] child {i} done ok={ok}");
            std::process::exit(i32::from(!ok));
        }
        child_pids.push(pid);
    }

    let all_ok = wait_for_children(
        &child_pids,
        "concurrent-fs-multi",
        "open() write-lock deadlock?",
    );
    let detail = if all_ok {
        format!("CONCURRENT_FS_MULTI_OK:{n_children}")
    } else {
        format!("CONCURRENT_FS_MULTI_FAIL:{n_children} (open write-lock deadlock)")
    };
    Ok(ConcurrentFsOut { detail })
}

fn wait_for_children(child_pids: &[libc::pid_t], label: &str, timeout_reason: &str) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut all_ok = true;
    for (i, &pid) in child_pids.iter().enumerate() {
        let mut status = 0i32;
        loop {
            // SAFETY: pid was returned by fork in this process. status points
            // to valid writable storage and WNOHANG avoids blocking forever.
            let ret = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
            if ret > 0 {
                if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                    break;
                }
                eprintln!("[{label}] child {i} bad exit: {status}");
                all_ok = false;
                break;
            }
            if std::time::Instant::now() >= deadline {
                eprintln!("[{label}] child {i} TIMEOUT ({timeout_reason})");
                // SAFETY: pid is a child process id returned by fork. Sending
                // SIGKILL is the timeout cleanup path for a stuck child.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                // SAFETY: pid is the same child; null status is allowed when
                // the exit status is intentionally discarded after cleanup.
                unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
                all_ok = false;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    all_ok
}

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
#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(crate) fn register_concurrent_fork_pipeline(reg: &mut Registry<'_>) {
    register_handler!(CONCURRENT_FS, handle_concurrent_fs);
    register_handler!(CONCURRENT_FS_MULTI, handle_concurrent_fs_multi);

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
                            .send_named_typed(
                                &handle,
                                &common::BASH,
                                common::BashArgs {
                                    cmd: cmd.into(),
                                    timeout_ms: Some(15_000),
                                },
                            )
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
                            &common::BASH,
                            common::BashArgs {
                                cmd: "echo 'pipe4_vscode_ok: test' | cat | grep pipe4 \
                                      | sed 's/test/pass/'"
                                    .into(),
                                timeout_ms: Some(15_000),
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
                            &common::BASH,
                            common::BashArgs {
                                cmd: "echo seq_a > /tmp/cf_test && cat /tmp/cf_test \
                                      && rm /tmp/cf_test"
                                    .into(),
                                timeout_ms: Some(15_000),
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
                                .send_named_typed(
                                    &handle,
                                    &common::BASH,
                                    common::BashArgs {
                                        cmd: full_cmd,
                                        timeout_ms: Some(15_000),
                                    },
                                )
                                .await;
                            let pass = matches!(
                                &resp,
                                Ok(out) if out.exit_code == 0
                                    && out.stdout.matches("ECHO_TEST_OK").count() == count
                            );
                            let detail = match &resp {
                                Ok(out) => format!(
                                    "got {}/{count} ECHO_TEST_OK",
                                    out.stdout.matches("ECHO_TEST_OK").count()
                                ),
                                Err(_) => format!("{resp:?}"),
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
                            .send_named_typed(
                                &handle,
                                &common::BASH,
                                common::BashArgs {
                                    cmd: cmd_s,
                                    timeout_ms: Some(15_000),
                                },
                            )
                            .await;
                        let pass = match &resp {
                            Ok(out) if out.exit_code == 0 => {
                                if expected_s.is_empty() {
                                    !out.stdout.trim().is_empty()
                                } else {
                                    out.stdout.contains(&*expected_s)
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
                    let leaf = cx.declare_ephemeral(
                        agent,
                        format!("ConcurrentFsLeaf{n}{}{}", bt.short_label(), agent),
                        SpawnKind::Fork {
                            binary: fork_binary_label(bt),
                            inherit_listen_ports: vec![],
                        },
                    );
                    Box::new(move |run| {
                        let agent_label = agent_label.clone();
                        Box::pin(async move {
                            let resp = run
                                .run_leaf(&leaf, &CONCURRENT_FS, ConcurrentFsArgs { n: n as u32 })
                                .await;
                            let pass = matches!(
                                &resp,
                                Ok(out) if out.detail.contains("CONCURRENT_FS_OK")
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
                    let leaf = cx.declare_ephemeral(
                        agent,
                        format!("ConcurrentFsMultiLeaf{n}{}{}", bt.short_label(), agent),
                        SpawnKind::Fork {
                            binary: fork_binary_label(bt),
                            inherit_listen_ports: vec![],
                        },
                    );
                    Box::new(move |run| {
                        let agent_label = agent_label.clone();
                        Box::pin(async move {
                            let resp = run
                                .run_leaf(
                                    &leaf,
                                    &CONCURRENT_FS_MULTI,
                                    ConcurrentFsArgs { n: n as u32 },
                                )
                                .await;
                            let pass = matches!(
                                &resp,
                                Ok(out) if out.detail.contains("CONCURRENT_FS_MULTI_OK")
                            );
                            super::TestOutcome::new(&agent_label, pass, format!("{resp:?}"))
                        })
                    })
                });
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// CC: Concurrent fork/exec/pipe tests
// ═══════════════════════════════════════════════════════════════════

/// Register CC.* concurrent fork/exec/pipe correctness tests.
#[allow(clippy::items_after_statements)]
pub(crate) fn register_concurrent_fork_tests(reg: &mut Registry<'_>) {
    super::platform_fixes::register_pf_specific_handlers();
    struct Def {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "echo",
            script_template: "echo $(echo hello) > {path}",
            check: |s| s.trim() == "hello",
        },
        Def {
            name: "fork_exec",
            script_template: "{exe} echo-test > {path} 2>&1",
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        Def {
            name: "pipe_capture",
            script_template: "echo $(echo data | cat) > {path}",
            check: |s| s.trim() == "data",
        },
        Def {
            name: "file_write",
            script_template: "echo agent-wrote-{agent} > {path}",
            check: |s| s.contains("agent-wrote-"),
        },
    ];
    for def in defs {
        for &agent in CF_AGENTS {
            let agent_s = agent.to_string();
            let template: String = def.script_template.into();
            let check = def.check;
            let name = def.name;
            reg.test("fork", "concurrent_fork", format!("CC.{name}.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let t = template.clone();
                        let self_exe = run.self_exe().to_string();
                        Box::pin(async move {
                            let path = format!("/shared/cc-{name}-{a}.txt");
                            let script = t
                                .replace("{path}", &path)
                                .replace("{exe}", &self_exe)
                                .replace("{agent}", &a);
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
                            if !matches!(&resp, Response::ExecResult { exit_code: 0, .. }) {
                                return super::TestOutcome::new(
                                    &a,
                                    false,
                                    format!("writer failed: {resp:?}"),
                                );
                            }
                            let resp = run
                                .typed_or_error(
                                    &handle,
                                    &FS_READ,
                                    FsPathArgs { path: path.clone() },
                                )
                                .await;
                            let pass = matches!(
                                &resp,
                                Response::Ok { data: Some(d) } if check(d)
                            );
                            super::TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}
