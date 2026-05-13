// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! /proc filesystem and PID-visibility tests (PROC.*, KP.*, KPX.*).
//!
//! This module hosts three families of tests:
//!
//! * `PROC.*` — basic /proc filesystem readability (self/stat, uptime, …).
//! * `KP.*` — per-agent PID visibility after delayed-fork migration.
//! * `KPX.*` — cross-agent PID and /proc visibility (observer × target
//!   pairs across the full agent tree).

#![allow(clippy::items_after_statements)]

use super::*;

use crate::coordinator::TestOutcome;
use crate::coordinator::common::CANARY_AGENTS as AGENTS;
use crate::coordinator::matrix::{EXEC, ExecArgs, FS_READ, FsPathArgs, GET_PID};

// ─── PROC helpers ────────────────────────────────────────────────────────────

fn exec_args(args: Vec<String>) -> ExecArgs {
    ExecArgs {
        args,
        timeout_secs: None,
        stdin: None,
        background: false,
        env: vec![],
    }
}

fn exec_timeout_args(args: Vec<String>, timeout_secs: u64) -> ExecArgs {
    ExecArgs {
        timeout_secs: Some(timeout_secs),
        ..exec_args(args)
    }
}

// ─── KPX helpers ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct KpxProcCase {
    name: &'static str,
    observer: AgentName,
    target: AgentName,
}

const KPX_PROC_CASES: &[KpxProcCase] = &[
    KpxProcCase {
        name: "same_agent",
        observer: AgentName::Dpg1,
        target: AgentName::Dpg1,
    },
    KpxProcCase {
        name: "parent_to_child",
        observer: AgentName::Dpg1,
        target: AgentName::Dpg1Dpg1,
    },
    KpxProcCase {
        name: "child_to_parent",
        observer: AgentName::Dpg1Dpg1,
        target: AgentName::Dpg1,
    },
    KpxProcCase {
        name: "root_sibling",
        observer: AgentName::Dpg1,
        target: AgentName::Dpg2,
    },
    KpxProcCase {
        name: "nested_sibling",
        observer: AgentName::Dpg1Dpg1,
        target: AgentName::Dpg1Dpg2,
    },
    KpxProcCase {
        name: "depth1_to_depth2",
        observer: AgentName::Dpg1Dpg2,
        target: AgentName::Dpg1Dpg1Dpg1,
    },
    KpxProcCase {
        name: "depth2_to_depth1",
        observer: AgentName::Dpg1Dpg1Dpg1,
        target: AgentName::Dpg1Dpg2,
    },
    KpxProcCase {
        name: "depth2_sibling",
        observer: AgentName::Dpg1Dpg1Dpg1,
        target: AgentName::Dpg1Dpg1Dpg2,
    },
    KpxProcCase {
        name: "cross_subtree",
        observer: AgentName::Dpg2,
        target: AgentName::Dpg1Dpg1Dpg1,
    },
];

fn kpx_pid(resp: &Response) -> Result<u32, String> {
    match resp {
        Response::Ok { data: Some(pid) } => pid
            .parse::<u32>()
            .map_err(|e| format!("GetPid returned non-numeric pid {pid:?}: {e}")),
        other => Err(format!("GetPid failed: {other:?}")),
    }
}

fn kpx_observe_proc_args(pid: u32) -> ExecArgs {
    let script = format!(
        "pid={pid}\n\
         if test -d \"/proc/$pid\"; then echo PROC_DIR_OK; else echo PROC_DIR_FAIL; fi\n\
         cat \"/proc/$pid/cmdline\"\n\
         printf '\\n'\n\
         if kill -0 \"$pid\" 2>/dev/null; then echo KILL0_OK; else echo KILL0_FAIL; fi\n"
    );
    exec_timeout_args(vec!["/bin/sh".into(), "-c".into(), script], 10)
}

fn kpx_observe_proc_pass(resp: &Response) -> bool {
    matches!(
        resp,
        Response::ExecResult {
            exit_code: 0,
            stdout,
            ..
        } if stdout.contains("PROC_DIR_OK")
            && stdout.contains("litebox_test_harness")
            && stdout.contains("KILL0_OK")
    )
}

// ─── Registration functions ───────────────────────────────────────────────────

pub(super) fn register_proc_filesystem_tests(reg: &mut Registry<'_>) {
    register_proc_leaf_subcommands();
    for &agent in AGENTS {
        let agent_s = agent.to_string();

        // PROC.self_stat: /proc/self/stat is readable.
        {
            let a = agent_s.clone();
            reg.test(
                "matrix",
                "proc_filesystem",
                format!("PROC.self_stat.{agent}"),
            )
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = a.clone();
                    Box::pin(async move {
                        let resp = run
                            .typed_or_error(
                                &handle,
                                &FS_READ,
                                FsPathArgs {
                                    path: "/proc/self/stat".into(),
                                },
                            )
                            .await;
                        let pass =
                            matches!(&resp, Response::Ok { data: Some(d) } if d.contains(") "));
                        TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });
        }

        // PROC.stat_seekable: /proc/self/stat is seekable (lseek).
        {
            let a = agent_s.clone();
            reg.test(
                "matrix",
                "proc_filesystem",
                format!("PROC.stat_seekable.{agent}"),
            )
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    let a = a.clone();
                    Box::pin(async move {
                        let resp = run
                            .typed_or_error(
                                &handle,
                                &EXEC,
                                exec_args(vec![
                                    "sh".into(),
                                    "-c".into(),
                                    "dd if=/proc/self/stat bs=1 skip=0 count=10 2>/dev/null | wc -c"
                                        .into(),
                                ]),
                            )
                            .await;
                        let pass = matches!(
                            &resp,
                            Response::ExecResult { exit_code: 0, stdout, .. }
                                if stdout.trim().parse::<u32>().unwrap_or(0) > 0
                        );
                        TestOutcome::new(&a, pass, format!("{resp:?}"))
                    })
                })
            });
        }

        // PROC.uptime: /proc/uptime is readable.
        {
            let a = agent_s.clone();
            reg.test("matrix", "proc_filesystem", format!("PROC.uptime.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = a.clone();
                        Box::pin(async move {
                            let resp = run
                                .typed_or_error(
                                    &handle,
                                    &FS_READ,
                                    FsPathArgs {
                                        path: "/proc/uptime".into(),
                                    },
                                )
                                .await;
                            let pass =
                                matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty());
                            TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}

#[allow(clippy::too_many_lines)] // exhaustive registration / runner
pub(super) fn register_pid_visibility_tests(reg: &mut Registry<'_>) {
    register_proc_leaf_subcommands();
    struct Def {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }
    let defs: &[Def] = &[
        Def {
            name: "kill0_bg",
            script_template: concat!(
                "sleep 30 > /dev/null 2>&1 &\n",
                "PID=$!\n",
                "kill -0 $PID 2>/dev/null && echo KILL0_OK || echo KILL0_FAIL\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("KILL0_OK"),
        },
        Def {
            name: "kill0_many",
            script_template: concat!(
                "A=$(cat /etc/os-release | head -1)\n",
                "B=$(uname -m)\n",
                "C=$(ls /tmp | head -1)\n",
                "D=$(echo x | cat)\n",
                "sleep 2 > /dev/null 2>&1 &\n",
                "PID=$!\n",
                "kill -0 $PID 2>/dev/null && echo KILL0_OK || echo KILL0_FAIL\n",
                "sleep 1\n",
                "kill -0 $PID 2>/dev/null && echo KILL0_1s_OK || echo KILL0_1s_FAIL\n",
                "wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("KILL0_OK") && s.contains("KILL0_1s_OK"),
        },
        Def {
            name: "proc_child",
            script_template: concat!(
                "{exe} cross-worker-file write-and-hold /shared/kp-proc-child.txt > /dev/null 2>&1 &\n",
                "PID=$!\n",
                "until cat /proc/$PID/cmdline 2>/dev/null | tr '\\0' ' ' | grep -q litebox_test_harness; do :; done\n",
                "test -d /proc/$PID && echo PROC_DIR_OK || echo PROC_DIR_FAIL\n",
                "cat /proc/$PID/cmdline 2>/dev/null | tr '\\0' ' ' | ",
                "grep -q litebox_test_harness && echo CMDLINE_OK || echo CMDLINE_FAIL\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("PROC_DIR_OK") && s.contains("CMDLINE_OK"),
        },
        Def {
            name: "proc_self",
            script_template: concat!(
                "{exe} proc-probe > /tmp/proc-self.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/proc-self.txt\n",
            ),
            check: |s| {
                s.contains("self=true")
                    && s.contains("self_cmdline=true")
                    && s.contains("own_proc=true")
                    && s.contains("own_cmdline=true")
            },
        },
        Def {
            name: "ppid_proc",
            script_template: concat!(
                "{exe} proc-probe > /tmp/ppid-proc.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-proc.txt\n",
            ),
            check: |s| s.contains("ppid_proc=true"),
        },
        Def {
            name: "ppid_kill0",
            script_template: concat!(
                "{exe} proc-probe > /tmp/ppid-k0.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-k0.txt\n",
            ),
            check: |s| s.contains("ppid_kill0=true"),
        },
        Def {
            name: "ppid_cmdline",
            script_template: concat!(
                "{exe} proc-probe > /tmp/ppid-cl.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-cl.txt\n",
            ),
            check: |s| s.contains("ppid_cmdline=true"),
        },
        Def {
            name: "getppid_correct",
            script_template: concat!(
                "echo $$\n",
                "{exe} check-ppid > /tmp/ppid-val.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-val.txt\n",
            ),
            check: |s| {
                let lines: Vec<&str> = s.lines().collect();
                if lines.len() < 2 {
                    return false;
                }
                let parent_pid = lines[0].trim();
                lines
                    .iter()
                    .any(|l| l.contains(&format!("ppid={parent_pid}")))
            },
        },
        Def {
            name: "parent_monitor",
            script_template: concat!(
                "{exe} proc-probe > /tmp/pmon.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/pmon.txt\n",
            ),
            check: |s| s.contains("ppid_proc=true") && s.contains("ppid_kill0=true"),
        },
    ];
    for &agent in AGENTS {
        for def in defs {
            let agent_s = agent.to_string();
            let template: String = def.script_template.into();
            let check = def.check;
            let name = def.name;
            reg.test("fork", "pid_visibility", format!("KP.{name}.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        let t = template.clone();
                        let self_exe = run.self_exe().to_string();
                        Box::pin(async move {
                            let script = t.replace("{exe}", &self_exe);
                            let resp = run
                                .typed_or_error(
                                    &handle,
                                    &EXEC,
                                    ExecArgs {
                                        args: vec!["bash".into(), "-c".into(), script],
                                        timeout_secs: Some(15),
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
                            TestOutcome::new(&a, pass, format!("{resp:?}"))
                        })
                    })
                });
        }
    }
}

#[allow(clippy::too_many_lines)] // exhaustive pair matrix
pub(super) fn register_cross_pid_visibility_tests(reg: &mut Registry<'_>) {
    register_proc_leaf_subcommands();
    for &case in KPX_PROC_CASES {
        let observer = case.observer;
        let target = case.target;
        let test_id = format!("KPX.cross.{}.{}.to.{target}", case.name, observer);
        reg.test("fork", "cross_pid_visibility", test_id)
            .timeout(60)
            .build(move |cx| {
                let observer_handle = cx.require(observer);
                let target_handle = cx.require(target);
                Box::new(move |run| {
                    Box::pin(async move {
                        let pid_resp = run.typed_or_error(&target_handle, &GET_PID, ()).await;
                        let pid = match kpx_pid(&pid_resp) {
                            Ok(pid) => pid,
                            Err(e) => {
                                return TestOutcome::new(
                                    observer.name(),
                                    false,
                                    format!("{e}; resp={pid_resp:?}"),
                                );
                            }
                        };
                        let observe_resp = run
                            .typed_or_error(
                                &observer_handle,
                                &EXEC,
                                kpx_observe_proc_args(pid),
                            )
                            .await;
                        let pass = kpx_observe_proc_pass(&observe_resp);
                        TestOutcome::new(
                            observer.name(),
                            pass,
                            format!(
                                "observer={observer} target={target} target_pid={pid} pid_resp={pid_resp:?} observe_resp={observe_resp:?}"
                            ),
                        )
                    })
                })
            });
    }
}

// ─── proc-probe / check-ppid leaf subcommands ────────────────────────────────

fn register_proc_leaf_subcommands() {
    crate::register_leaf_subcommand!("proc-probe", proc_leaf_subcmd::subcmd_proc_probe);
    crate::register_leaf_subcommand!("check-ppid", proc_leaf_subcmd::subcmd_check_ppid);
}

mod proc_leaf_subcmd {
    // Safety comments below: libc FFI calls operate on the calling
    // process's own PID / parent PID and signal 0 (no-op); these are
    // always safe to invoke.

    pub(super) fn subcmd_check_ppid(_args: &[String]) -> i32 {
        // Safety: getppid is always safe.
        let ppid = unsafe { libc::getppid() };
        let proc_exists = std::path::Path::new(&format!("/proc/{ppid}")).exists();
        // Safety: kill(ppid, 0) merely checks process existence.
        let kill_ret = unsafe { libc::kill(ppid, 0) };
        let kill_errno = if kill_ret != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        } else {
            0
        };
        let kill_ok = kill_ret == 0;
        println!("ppid={ppid} proc={proc_exists} kill0={kill_ok} errno={kill_errno}");
        0
    }

    pub(super) fn subcmd_proc_probe(args: &[String]) -> i32 {
        // Safety: getpid / getppid are always safe.
        let pid = unsafe { libc::getpid() };
        let parent_pid = unsafe { libc::getppid() };
        let self_exists = std::path::Path::new("/proc/self").exists();
        let self_cmdline = std::fs::read_to_string("/proc/self/cmdline")
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let self_stat = std::fs::read_to_string("/proc/self/stat")
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let own_proc = std::path::Path::new(&format!("/proc/{pid}")).exists();
        let own_cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let ppid_proc = std::path::Path::new(&format!("/proc/{parent_pid}")).exists();
        let ppid_cmdline = std::fs::read_to_string(format!("/proc/{parent_pid}/cmdline"))
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        // Safety: kill(parent_pid, 0) merely checks process existence.
        let ppid_kill0_ret = unsafe { libc::kill(parent_pid, 0) };
        let ppid_kill0_errno = if ppid_kill0_ret != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        } else {
            0
        };
        let ppid_kill0 = ppid_kill0_ret == 0;
        print!("pid={pid} ppid={parent_pid}");
        print!(" self={self_exists} self_cmdline={self_cmdline} self_stat={self_stat}");
        print!(" own_proc={own_proc} own_cmdline={own_cmdline}");
        print!(
            " ppid_proc={ppid_proc} ppid_cmdline={ppid_cmdline} ppid_kill0={ppid_kill0} ppid_kill0_errno={ppid_kill0_errno}"
        );
        if let Some(target) = args.get(2).and_then(|s| s.parse::<i32>().ok()) {
            let t_proc = std::path::Path::new(&format!("/proc/{target}")).exists();
            // Safety: kill(target, 0) merely checks process existence.
            let t_kill0 = unsafe { libc::kill(target, 0) } == 0;
            print!(" target={target} target_proc={t_proc} target_kill0={t_kill0}");
        }
        println!();
        0
    }
}
