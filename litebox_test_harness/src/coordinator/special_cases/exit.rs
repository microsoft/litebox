// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! exit/terminal special-case argv leaves and EXITD (bridge-thread join before
//! exit) data integrity tests.

use super::*;

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use serde::{Deserialize, Serialize};
use std::process::{Command as StdCommand, Stdio};

#[derive(Serialize, Deserialize)]
pub(super) struct LeafArgs {
    pub sub: String,
    pub extra: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct LeafOut {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Simple single-threaded exit. Also used as the target for exec-exit tests.
fn test_single_exit() {
    println!("EX1_BEFORE_EXIT");
    std::process::exit(0);
}

/// Terminal ioctl tests — run as: exit-test term <op> <fd>
/// ops: tcgets, tcsets, tcsetsw, tcsetsf, tiocgwinsz
/// fds: 0, 1, 2
fn test_terminal_ioctl(op: &str, fd_num: i32) {
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };

    match op {
        "tcgets" => {
            let ret = unsafe { libc::tcgetattr(fd_num, &raw mut termios) };
            if ret == 0 {
                println!("TERM_OK:op={op},fd={fd_num}");
            } else {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                println!("TERM_ERR:op={op},fd={fd_num},errno={e}");
            }
        }
        "tcsets" | "tcsetsw" | "tcsetsf" => {
            // First get current attrs
            if unsafe { libc::tcgetattr(fd_num, &raw mut termios) } != 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                println!("TERM_ERR:op={op},fd={fd_num},errno={e},phase=tcgetattr");
                std::process::exit(1);
            }
            let when = match op {
                "tcsets" => libc::TCSANOW,
                "tcsetsw" => libc::TCSADRAIN,
                "tcsetsf" => libc::TCSAFLUSH,
                _ => unreachable!(),
            };
            let ret = unsafe { libc::tcsetattr(fd_num, when, &raw const termios) };
            if ret == 0 {
                println!("TERM_OK:op={op},fd={fd_num}");
            } else {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                println!("TERM_ERR:op={op},fd={fd_num},errno={e}");
            }
        }
        "tiocgwinsz" => {
            let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
            let ret = unsafe { libc::ioctl(fd_num, libc::TIOCGWINSZ, &mut ws) };
            if ret == 0 {
                println!(
                    "TERM_OK:op={op},fd={fd_num},rows={},cols={}",
                    ws.ws_row, ws.ws_col
                );
            } else {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                println!("TERM_ERR:op={op},fd={fd_num},errno={e}");
            }
        }
        _ => {
            println!("TERM_ERR:unknown_op={op}");
            std::process::exit(1);
        }
    }
    std::process::exit(0);
}

pub fn run(sub: &str) {
    match sub {
        "single" => test_single_exit(),
        // Matrix-style: exit-test term <op> <fd>
        "term" => {
            let op = std::env::args().nth(3).unwrap_or_default();
            let fd: i32 = std::env::args()
                .nth(4)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            test_terminal_ioctl(&op, fd);
        }
        other => {
            eprintln!("unknown exit test: {other}");
            std::process::exit(1);
        }
    }
}

#[allow(dead_code)]
pub(super) const RUN: HandlerToken<LeafArgs, LeafOut> = HandlerToken::new("special_cases.exit.run");

#[allow(dead_code)]
pub(super) async fn handle_run(
    args: LeafArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<LeafOut, HandlerError> {
    let output = StdCommand::new(std::env::current_exe()?)
        .arg("exit-test")
        .arg(args.sub)
        .args(args.extra)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    Ok(LeafOut {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

/// Register argv leaves used by exec-driven exit and terminal ioctl tests.
pub(super) fn register() {
    crate::register_handler!(RUN, handle_run);
    crate::register_leaf_subcommand!("exit-test", subcmd_exit_test);
}

fn subcmd_exit_test(args: &[String]) -> i32 {
    let sub = args.get(2).map_or("single", String::as_str);
    run(sub);
    eprintln!("EXIT_TEST_BUG: run() returned instead of exiting");
    99
}

/// Register Node.js exit tests.
pub(super) fn register_node_exit(reg: &mut Registry<'_>) {
    register();
    typed_test!(
        reg,
        "fork",
        "node_exit",
        "EX6.node_version_exit",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = run
                .send_named_typed(
                    &a,
                    &EXEC_BIN,
                    ExecBinArgs {
                        argv: vec!["/usr/local/bin/node".into(), "--version".into()],
                        timeout_ms: Some(10 * 1000),
                        stdin: None,
                        env: vec![],
                    },
                )
                .await;
            let pass =
                matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.starts_with('v'));
            crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "fork",
        "node_exit",
        "EX7.node_process_exit",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = run
                .send_named_typed(
                    &a,
                    &EXEC_BIN,
                    ExecBinArgs {
                        argv: vec![
                            "/usr/local/bin/node".into(),
                            "-e".into(),
                            "process.exit(0)".into(),
                        ],
                        timeout_ms: Some(10 * 1000),
                        stdin: None,
                        env: vec![],
                    },
                )
                .await;
            let pass = matches!(&resp, Ok(out) if out.exit_code == 0);
            crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "fork",
        "node_exit",
        "EX8.node_exit_code",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = run
                .send_named_typed(
                    &a,
                    &EXEC_BIN,
                    ExecBinArgs {
                        argv: vec![
                            "/usr/local/bin/node".into(),
                            "-e".into(),
                            "process.exit(42)".into(),
                        ],
                        timeout_ms: Some(10 * 1000),
                        stdin: None,
                        env: vec![],
                    },
                )
                .await;
            let pass = matches!(&resp, Ok(out) if out.exit_code == 42);
            crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    typed_test!(
        reg,
        "fork",
        "node_exit",
        "EX9.node_console_exit",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = run
                .send_named_typed(
                    &a,
                    &EXEC_BIN,
                    ExecBinArgs {
                        argv: vec![
                            "/usr/local/bin/node".into(),
                            "-e".into(),
                            "console.log(\"NODE_EXIT_OK\")".into(),
                        ],
                        timeout_ms: Some(10 * 1000),
                        stdin: None,
                        env: vec![],
                    },
                )
                .await;
            let pass = matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains("NODE_EXIT_OK"));
            crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    // EX10: node spawns a subprocess via child_process.spawnSync.
    // Copilot CLI uses spawnSync/exec heavily to invoke git, gh, etc.
    // This exercises node's libuv subprocess path under litebox.
    typed_test!(
        reg,
        "fork",
        "node_exit",
        "EX10.node_spawn_sync",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = run
                .send_named_typed(
                    &a,
                    &EXEC_BIN,
                    ExecBinArgs {
                        argv: vec![
                            "/usr/local/bin/node".into(),
                            "-e".into(),
                            "const cp = require('child_process'); const r = cp.spawnSync('/bin/echo', ['SPAWN_OK']); process.stdout.write(r.stdout.toString()); process.exit(r.status === 0 ? 0 : 1);".into(),
                        ],
                        timeout_ms: Some(15 * 1000),
                        stdin: None,
                        env: vec![],
                    },
                )
                .await;
            let pass =
                matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains("SPAWN_OK"));
            crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    // EX11: node async spawn with event emitter (the most common
    // Copilot CLI pattern: spawn child, await close event).
    typed_test!(
        reg,
        "fork",
        "node_exit",
        "EX11.node_spawn_event",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = run
                .send_named_typed(
                    &a,
                    &EXEC_BIN,
                    ExecBinArgs {
                        argv: vec![
                            "/usr/local/bin/node".into(),
                            "-e".into(),
                            "const cp = require('child_process'); const ch = cp.spawn('/bin/echo', ['EVENT_OK']); let out=''; ch.stdout.on('data',d=>out+=d); ch.on('close',c=>{process.stdout.write(out); process.exit(c);});".into(),
                        ],
                        timeout_ms: Some(15 * 1000),
                        stdin: None,
                        env: vec![],
                    },
                )
                .await;
            let pass =
                matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains("EVENT_OK"));
            crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );

    // EX12: node spawns a node subprocess (recursive node) — exercises
    // the cross-bt fork path that Copilot CLI takes when the launcher
    // node spawns the actual agent node.
    typed_test!(
        reg,
        "fork",
        "node_exit",
        "EX12.node_spawn_node",
        timeout = 60,
        agents[a = AgentName::Dpg1],
        |run| {
            let resp = run
                .send_named_typed(
                    &a,
                    &EXEC_BIN,
                    ExecBinArgs {
                        argv: vec![
                            "/usr/local/bin/node".into(),
                            "-e".into(),
                            "const cp = require('child_process'); const r = cp.spawnSync('/usr/local/bin/node', ['-e', 'console.log(\"INNER_OK\")']); process.stdout.write(r.stdout.toString()); process.exit(r.status === 0 ? 0 : 1);".into(),
                        ],
                        timeout_ms: Some(20 * 1000),
                        stdin: None,
                        env: vec![],
                    },
                )
                .await;
            let pass =
                matches!(&resp, Ok(out) if out.exit_code == 0 && out.stdout.contains("INNER_OK"));
            crate::coordinator::TestOutcome::new("A", pass, format!("{resp:?}"))
        }
    );
}

// ═══════════════════════════════════════════════════════════════════
// EXITD: bridge thread join before exit (fix 2def3ac6)
// ═══════════════════════════════════════════════════════════════════

const EXIT_SIZES: &[usize] = &[256, 4096, 65536];
const EXITD_DEPTH_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1];

fn fork_binary_label(bt: crate::BinaryType) -> &'static str {
    match bt {
        crate::BinaryType::PieGlibc => "self",
        crate::BinaryType::NonPieGlibc => "nonpie",
        crate::BinaryType::StaticPieGlibc => "static-pie-glibc",
        crate::BinaryType::StaticPieMusl => "static-pie-musl",
        crate::BinaryType::NonPieStaticMusl => "non-pie-static-musl",
    }
}

pub(super) fn register_exit_data_integrity_tests(reg: &mut Registry<'_>) {
    for &size in EXIT_SIZES {
        for &binary in crate::BinaryType::ALL {
            for &agent in EXITD_DEPTH_AGENTS {
                let agent_s = agent.to_string();
                let binary_label = binary.label();
                reg.test(
                    "fork",
                    "exit_data_integrity",
                    format!("EXITD.{size}.{binary_label}.{agent}"),
                )
                .timeout(60)
                .build(move |cx| {
                    let leaf = cx.declare_ephemeral(
                        agent,
                        format!("ExitData_{size}_{binary_label}_{agent}"),
                        SpawnKind::Fork {
                            binary: fork_binary_label(binary),
                            inherit_listen_ports: vec![],
                        },
                    );
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        Box::pin(async move {
                            let result = run
                                .run_leaf(
                                    &leaf,
                                    &crate::coordinator::common::WRITE_THEN_EXIT,
                                    crate::coordinator::common::WriteThenExitArgs { size },
                                )
                                .await;
                            let pass = matches!(&result, Ok(out) if out.data.len() == size);
                            let detail = match &result {
                                Ok(out) => format!("got {} bytes, expected {size}", out.data.len()),
                                Err(e) => e.clone(),
                            };
                            crate::coordinator::TestOutcome::new(&a, pass, detail)
                        })
                    })
                });
            }
        }
    }
}
