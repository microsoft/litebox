// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PTY protocol tests for VS Code terminal blockers.
//!
//! Migrated to the typed-handler protocol. Each scenario opens the
//! pty, forks the child, performs all pty I/O, waits, and closes the
//! master inside one straight-line handler body.

use std::io::Read as _;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::pty::{Pty, wait_child_timeout};
use crate::register_handler;

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;
use super::run_context::RunContext;

const PTY_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,
    AgentName::Dpg1Dpg1,
    AgentName::Dpg1Dpg1Dpg1,
    AgentName::Dpg2,
    // AB exercises the reverse child branch under A alongside AA/AAA: the PTY
    // registry lives in the child while routing returns through its parent.
    AgentName::Dpg1Dpg2,
];

#[derive(Clone, Copy)]
enum ScenarioKind {
    ExecEcho,
    Tiocgpgrp,
    Tiocspgrp,
    Tiocsctty,
    Resize,
    WinsizeCrossWorker,
    SetpgidCrossWorker,
    LdiscCtrlcCrossWorker,
    LdiscCanonBasic,
    ExecShellSession,
    /// PTYR.stdout_roundtrip — child writes a unique marker to fd 1
    /// (PTY slave) via `printf` after exec; parent reads from master.
    /// Headline regression test for the SSH-TUI failure: confirms
    /// stdout bytes from a non-PIE binary reach the parent across
    /// `exec_on_remote_host`'s worker handoff.
    StdoutRoundtrip,
    /// PTYR.stdout_post_sleep — child writes 5 lines, sleeps briefly,
    /// writes 5 more lines, then exits (slave closes). Parent reads
    /// the master and verifies all 10 lines arrive.
    ///
    /// This is the dropbear-under-litebox failure signature: the
    /// post-sleep lines were lost because the broker PTY's slave→master
    /// data-plane propagation has a race when the slave closes shortly
    /// after writing. dropbear's session loop saw EAGAIN after the
    /// sleep, concluded the channel was empty, sent exit-status, and
    /// closed the SSH channel before the broker delivered the buffered
    /// post-sleep bytes.
    ///
    /// Self-contained reproducer for the Phase H "copilot -p prints
    /// nothing" symptom — no Copilot, no dropbear, no Docker stack
    /// needed.
    StdoutPostSleep,
    /// PTYR.isatty — child calls `isatty(0/1/2)` post-exec and prints
    /// `isatty: 0=Y 1=Y 2=Y`. Confirms all three stdio fds are TTYs in
    /// the new worker after a non-PIE execve.
    Isatty,
}

struct ScenarioDef {
    name: &'static str,
    kind: ScenarioKind,
    /// If true, the scenario exec's a binary that benefits from the
    /// `BinaryType` axis (e.g. spawning the harness with a probe
    /// subcommand that exercises PTY ioctls). Iterate `BinaryType::ALL`.
    /// If false, the scenario uses a fixed external binary
    /// (e.g. `/bin/echo`) and runs once.
    per_binary_type: bool,
}

const PTY_SCENARIOS: &[ScenarioDef] = &[
    ScenarioDef {
        name: "exec_echo",
        kind: ScenarioKind::ExecEcho,
        per_binary_type: false,
    },
    ScenarioDef {
        name: "tiocgpgrp",
        kind: ScenarioKind::Tiocgpgrp,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "tiocspgrp",
        kind: ScenarioKind::Tiocspgrp,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "tiocsctty",
        kind: ScenarioKind::Tiocsctty,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "resize",
        kind: ScenarioKind::Resize,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "winsize_cross_worker",
        kind: ScenarioKind::WinsizeCrossWorker,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "setpgid_cross_worker",
        kind: ScenarioKind::SetpgidCrossWorker,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "ldisc_ctrlc_cross_worker",
        kind: ScenarioKind::LdiscCtrlcCrossWorker,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "ldisc_canon_basic",
        kind: ScenarioKind::LdiscCanonBasic,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "exec_shell_session",
        kind: ScenarioKind::ExecShellSession,
        per_binary_type: false,
    },
    // ─── PTYR.* family ────────────────────────────────────────────────
    // Regression coverage for the SSH-TUI demo failure
    // (FOLLOWUP-shim-pty-stdio-handoff-to-remote-worker). The existing
    // PTY.* family exercises ioctls (TIOCGPGRP/TIOCSPGRP/TIOCSCTTY/
    // TIOCSWINSZ) and the controlling-terminal hookup; what was missing
    // is verifying that ordinary stdout I/O survives the non-PIE
    // worker handoff in `exec_on_remote_host`. The two PTYR scenarios
    // close that gap.
    ScenarioDef {
        name: "stdout_roundtrip",
        kind: ScenarioKind::StdoutRoundtrip,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "stdout_post_sleep",
        kind: ScenarioKind::StdoutPostSleep,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "isatty",
        kind: ScenarioKind::Isatty,
        per_binary_type: true,
    },
];

#[derive(Serialize, Deserialize)]
struct TargetArgs {
    target: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PtyOut {
    detail: String,
}

// ─── Typed handler tokens ────────────────────────────────────────────

const EXEC_ECHO: HandlerToken<(), PtyOut> = HandlerToken::new("pty.exec_echo");
const TIOCGPGRP: HandlerToken<TargetArgs, PtyOut> = HandlerToken::new("pty.tiocgpgrp");
const TIOCSPGRP: HandlerToken<TargetArgs, PtyOut> = HandlerToken::new("pty.tiocspgrp");
const TIOCSCTTY: HandlerToken<TargetArgs, PtyOut> = HandlerToken::new("pty.tiocsctty");
const RESIZE: HandlerToken<TargetArgs, PtyOut> = HandlerToken::new("pty.resize");
const WINSIZE_CROSS_WORKER: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.winsize_cross_worker");
const SETPGID_CROSS_WORKER: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.setpgid_cross_worker");
const EXEC_SHELL_SESSION: HandlerToken<(), PtyOut> = HandlerToken::new("pty.exec_shell_session");
const LDISC_CTRLC_CROSS_WORKER: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.ldisc_ctrlc_cross_worker");
const LDISC_CTRLZ_CROSS_WORKER: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.ldisc_ctrlz_cross_worker");
const LDISC_CANON_BASIC: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.ldisc_canon_basic");
// PTYR.* tokens — regression coverage for non-PIE worker-handoff stdio.
const PTYR_STDOUT_ROUNDTRIP: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("ptyr.stdout_roundtrip");
const PTYR_STDOUT_POST_SLEEP: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("ptyr.stdout_post_sleep");
const PTYR_ISATTY: HandlerToken<TargetArgs, PtyOut> = HandlerToken::new("ptyr.isatty");
const PARENT_EXIT_THEN_CHILD_IO: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.parent_exit_then_child_io");

// ─── Handlers ────────────────────────────────────────────────────────

async fn handle_exec_echo(_args: (), _ctx: &mut HandlerCtx<'_>) -> Result<PtyOut, HandlerError> {
    let detail = run_pty_child(
        &["/bin/echo".into(), "hello".into()],
        true,
        None,
        "hello\r\n",
    )?;
    Ok(PtyOut { detail })
}

async fn handle_tiocgpgrp(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-tiocgpgrp".into()], true)?;
    expect_exit_zero(pid)?;
    let data = pty.read(None)?;
    let expected = format!("TIOCGPGRP pgrp={pid}\r\n");
    let detail = exact(&data, &expected)?;
    Ok(PtyOut { detail })
}

async fn handle_tiocspgrp(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-tiocspgrp".into()], true)?;
    expect_exit_zero(pid)?;
    let data = pty.read(None)?;
    let expected = format!("TIOCSPGRP pgrp={pid} got={pid}\r\n");
    let detail = exact(&data, &expected)?;
    Ok(PtyOut { detail })
}

async fn handle_tiocsctty(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let detail = run_pty_child(
        &[args.target, "pty-tiocsctty".into()],
        true,
        None,
        "TTY_OK\r\n",
    )?;
    Ok(PtyOut { detail })
}

async fn handle_resize(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-resize".into()], true)?;
    read_until(&pty, "READY\r\n")?;
    pty.resize(41, 132)?;
    expect_exit_zero(pid)?;
    let data = pty.read(None)?;
    let detail = exact(&data, "RESIZE rows=41 cols=132\r\n")?;
    Ok(PtyOut { detail })
}

async fn handle_winsize_cross_worker(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-winsize-cross-worker".into()], true)?;
    read_until(&pty, "READY\r\n")?;
    pty.resize(41, 132)?;
    expect_exit_zero(pid)?;
    let data = pty.read(None)?;
    let detail = exact(&data, "CROSS_RESIZE rows=41 cols=132 count=1\r\n")?;
    Ok(PtyOut { detail })
}

async fn handle_setpgid_cross_worker(
    args: TargetArgs,
    ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    handle_winsize_cross_worker(args, ctx).await
}

async fn handle_ldisc_signal_cross_worker(
    args: TargetArgs,
    signum: i32,
    byte: u8,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(
        &[args.target, "pty-ldisc-signal".into(), signum.to_string()],
        true,
    )?;
    read_until(&pty, "READY\r\n")?;
    pty.write_all(&[byte])?;
    expect_exit_zero(pid)?;
    let data = pty.read(None)?;
    let marker = format!("LDISC_SIGNAL signum={signum} count=1\r\n");
    if data.contains(&marker) {
        Ok(PtyOut { detail: marker })
    } else {
        Err(format!("expected marker {marker:?}, got {data:?}").into())
    }
}

async fn handle_ldisc_ctrlc_cross_worker(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    handle_ldisc_signal_cross_worker(args, libc::SIGINT, 0x03).await
}

async fn handle_ldisc_ctrlz_cross_worker(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    handle_ldisc_signal_cross_worker(args, libc::SIGTSTP, 0x1a).await
}

async fn handle_ldisc_canon_basic(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-ldisc-canon".into()], true)?;
    read_until(&pty, "READY\r\n")?;
    pty.write_all(b"hello\x7f\x7fworld\nabc\x15def\n")?;
    expect_exit_zero(pid)?;
    let data = pty.read(None)?;
    let detail = exact(&data, "CANON line1=helworld line2=def\r\n")?;
    Ok(PtyOut { detail })
}

async fn handle_exec_shell_session(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let detail = run_pty_child(
        &[
            "bash".into(),
            "-c".into(),
            "stty -echo; echo READY; read x; echo got=$x".into(),
        ],
        true,
        Some("value\n"),
        "got=value\r\n",
    )?;
    Ok(PtyOut { detail })
}

// ─── PTYR handlers ───────────────────────────────────────────────────
// Regression coverage for the SSH-TUI worker-handoff bug
// (FOLLOWUP-shim-pty-stdio-handoff-to-remote-worker). These tests
// fork+exec the harness binary in a chosen BinaryType — when the
// binary is non-PIE, the execve goes through `exec_on_remote_host`
// in the shim, which spawns a fresh worker host. The child runs
// under the new worker with the PTY slave as its stdin/stdout/stderr;
// the parent reads from the master and asserts the bytes arrived.
// If the worker handoff doesn't propagate the PTY slave correctly,
// these assertions will fail (and they're the smallest possible
// repro of the demo's TUI failure).

async fn handle_ptyr_stdout_roundtrip(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-stdout-print".into()], true)?;
    expect_exit_zero(pid)?;
    let data = pty.read(None)?;
    let detail = exact(&data, "PTYR_STDOUT_OK\r\n")?;
    Ok(PtyOut { detail })
}

async fn handle_ptyr_stdout_post_sleep(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-stdout-post-sleep".into()], true)?;
    expect_exit_zero(pid)?;
    let data = pty.read(None)?;
    // PTY OPOST: lone \n → \r\n. Child writes 10 lines L01..L10.
    let mut expected = String::new();
    for i in 1..=10 {
        expected.push_str(&format!("L{i:02}\r\n"));
    }
    let detail = exact(&data, &expected)?;
    Ok(PtyOut { detail })
}

async fn handle_ptyr_isatty(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-isatty-check".into()], true)?;
    expect_exit_zero(pid)?;
    let data = pty.read(None)?;
    let detail = exact(&data, "isatty: 0=Y 1=Y 2=Y\r\n")?;
    Ok(PtyOut { detail })
}

async fn handle_parent_exit_then_child_io(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let socket_path = format!(
        "/run/litebox-pty-parent-exit-{}-{}.sock",
        std::process::id(),
        monotonic_suffix()
    );
    let _ = std::fs::remove_file(&socket_path);
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)
        .map_err(|e| format!("bind {socket_path}: {e}"))?;

    let parent_exe =
        std::env::current_exe().map_err(|e| format!("current_exe for parent leaf: {e}"))?;
    let mut parent = match std::process::Command::new(parent_exe)
        .arg("pty-parent-exit-driver")
        .arg(args.target)
        .arg(&socket_path)
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            let _ = std::fs::remove_file(&socket_path);
            return Err(format!("spawn parent leaf: {err}").into());
        }
    };

    let (mut stream, _) = listener
        .accept()
        .map_err(|e| format!("accept {socket_path}: {e}"))?;
    let _ = std::fs::remove_file(&socket_path);

    let parent_status = parent
        .wait()
        .map_err(|e| format!("wait parent leaf: {e}"))?;
    if !parent_status.success() {
        return Err(format!("parent leaf exited with {parent_status}").into());
    }

    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("set monitor read timeout: {e}"))?;
    let mut result = String::new();
    stream
        .read_to_string(&mut result)
        .map_err(|e| format!("read monitor result: {e}"))?;
    if let Some(detail) = result.strip_prefix("OK ") {
        Ok(PtyOut {
            detail: format!("parent exited; {detail}"),
        })
    } else {
        Err(format!("monitor reported {result:?}").into())
    }
}

// ─── Registration ────────────────────────────────────────────────────

pub(crate) fn register_pty_tests(reg: &mut Registry<'_>) {
    register_handler!(EXEC_ECHO, handle_exec_echo);
    register_handler!(TIOCGPGRP, handle_tiocgpgrp);
    register_handler!(TIOCSPGRP, handle_tiocspgrp);
    register_handler!(TIOCSCTTY, handle_tiocsctty);
    register_handler!(RESIZE, handle_resize);
    register_handler!(WINSIZE_CROSS_WORKER, handle_winsize_cross_worker);
    register_handler!(SETPGID_CROSS_WORKER, handle_setpgid_cross_worker);
    register_handler!(LDISC_CTRLC_CROSS_WORKER, handle_ldisc_ctrlc_cross_worker);
    register_handler!(LDISC_CTRLZ_CROSS_WORKER, handle_ldisc_ctrlz_cross_worker);
    register_handler!(LDISC_CANON_BASIC, handle_ldisc_canon_basic);
    register_handler!(EXEC_SHELL_SESSION, handle_exec_shell_session);
    register_handler!(PTYR_STDOUT_ROUNDTRIP, handle_ptyr_stdout_roundtrip);
    register_handler!(PTYR_STDOUT_POST_SLEEP, handle_ptyr_stdout_post_sleep);
    register_handler!(PTYR_ISATTY, handle_ptyr_isatty);
    register_handler!(PARENT_EXIT_THEN_CHILD_IO, handle_parent_exit_then_child_io);

    crate::register_leaf_subcommand!("pty-tiocgpgrp", leaf_subcmd::subcmd_pty_tiocgpgrp);
    crate::register_leaf_subcommand!("pty-tiocspgrp", leaf_subcmd::subcmd_pty_tiocspgrp);
    crate::register_leaf_subcommand!("pty-tiocsctty", leaf_subcmd::subcmd_pty_tiocsctty);
    crate::register_leaf_subcommand!("pty-resize", leaf_subcmd::subcmd_pty_resize);
    crate::register_leaf_subcommand!(
        "pty-winsize-cross-worker",
        leaf_subcmd::subcmd_pty_winsize_cross_worker
    );
    crate::register_leaf_subcommand!("pty-ldisc-signal", leaf_subcmd::subcmd_pty_ldisc_signal);
    crate::register_leaf_subcommand!("pty-ldisc-canon", leaf_subcmd::subcmd_pty_ldisc_canon);
    crate::register_leaf_subcommand!("pty-stdout-print", leaf_subcmd::subcmd_pty_stdout_print);
    crate::register_leaf_subcommand!(
        "pty-stdout-post-sleep",
        leaf_subcmd::subcmd_pty_stdout_post_sleep
    );
    crate::register_leaf_subcommand!("pty-isatty-check", leaf_subcmd::subcmd_pty_isatty_check);
    crate::register_leaf_subcommand!(
        "pty-parent-exit-driver",
        leaf_subcmd::subcmd_pty_parent_exit_driver
    );
    crate::register_leaf_subcommand!(
        "pty-parent-exit-then-child-io",
        leaf_subcmd::subcmd_pty_parent_exit_then_child_io
    );

    register_parent_exit_then_child_io(reg);

    for &agent in PTY_AGENTS {
        for def in PTY_SCENARIOS {
            // Per-binary-type scenarios fan out across BinaryType::ALL;
            // others use the legacy 3-segment ID with no binary axis.
            let bts: &[Option<crate::BinaryType>] = match def.kind {
                ScenarioKind::LdiscCtrlcCrossWorker | ScenarioKind::LdiscCanonBasic => {
                    &[Some(crate::BinaryType::PieGlibc)]
                }
                _ if def.per_binary_type => &[
                    Some(crate::BinaryType::PieGlibc),
                    Some(crate::BinaryType::NonPieGlibc),
                    Some(crate::BinaryType::StaticPieGlibc),
                    Some(crate::BinaryType::StaticPieMusl),
                    Some(crate::BinaryType::NonPieStaticMusl),
                ],
                _ => &[None],
            };
            for &bt_opt in bts {
                let test_id = match bt_opt {
                    Some(bt) => format!("PTY.{}.{}.{agent}", def.name, bt.label()),
                    None => format!("PTY.{}.{agent}", def.name),
                };
                match (def.kind, bt_opt) {
                    (ScenarioKind::ExecEcho, None) => reg.single_agent_handler_test(
                        "vscode",
                        "pty",
                        test_id,
                        agent,
                        &EXEC_ECHO,
                        check_detail,
                    ),
                    (ScenarioKind::ExecShellSession, None) => reg.single_agent_handler_test(
                        "vscode",
                        "pty",
                        test_id,
                        agent,
                        &EXEC_SHELL_SESSION,
                        check_detail,
                    ),
                    (kind, Some(bt)) => register_target_test(reg, test_id, agent, kind, bt),
                    _ => unreachable!("invalid pty scenario/binary-type combination"),
                }
            }
        }
    }
}

fn register_parent_exit_then_child_io(reg: &mut Registry<'_>) {
    reg.test("vscode", "pty", "PTY.parent_exit_then_child_io.dpg1")
        .timeout(30)
        .build(|cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let target = crate::binary_path(crate::BinaryType::NonPieGlibc, run.self_exe());
                    let args = TargetArgs { target };
                    let result = run
                        .send_named_typed(&handle, &PARENT_EXIT_THEN_CHILD_IO, args)
                        .await;
                    match result {
                        Ok(out) => TestOutcome::new("dpg1", true, out.detail),
                        Err(detail) => TestOutcome::new("dpg1", false, detail),
                    }
                })
            })
        });
}

fn register_target_test(
    reg: &mut Registry<'_>,
    test_id: String,
    agent: AgentName,
    kind: ScenarioKind,
    bt: crate::BinaryType,
) {
    let label = agent.to_string();
    reg.test("vscode", "pty", test_id)
        .timeout(60)
        .build(move |cx| {
            let handle = cx.require(agent);
            let label = label.clone();
            Box::new(move |run| {
                Box::pin(async move {
                    let result = drive_target(run, &handle, kind, bt).await;
                    match result {
                        Ok(detail) => TestOutcome::new(&label, true, detail),
                        Err(detail) => TestOutcome::new(&label, false, detail),
                    }
                })
            })
        });
}

async fn drive_target(
    run: &mut RunContext<'_>,
    handle: &super::agents::AgentHandle,
    kind: ScenarioKind,
    bt: crate::BinaryType,
) -> Result<String, String> {
    let target = crate::binary_path(bt, run.self_exe());
    let args = TargetArgs { target };
    let out: PtyOut = match kind {
        ScenarioKind::Tiocgpgrp => run.send_named_typed(handle, &TIOCGPGRP, args).await?,
        ScenarioKind::Tiocspgrp => run.send_named_typed(handle, &TIOCSPGRP, args).await?,
        ScenarioKind::Tiocsctty => run.send_named_typed(handle, &TIOCSCTTY, args).await?,
        ScenarioKind::Resize => run.send_named_typed(handle, &RESIZE, args).await?,
        ScenarioKind::WinsizeCrossWorker => {
            run.send_named_typed(handle, &WINSIZE_CROSS_WORKER, args)
                .await?
        }
        ScenarioKind::SetpgidCrossWorker => {
            run.send_named_typed(handle, &SETPGID_CROSS_WORKER, args)
                .await?
        }
        ScenarioKind::LdiscCtrlcCrossWorker => {
            run.send_named_typed(handle, &LDISC_CTRLC_CROSS_WORKER, args)
                .await?
        }
        ScenarioKind::LdiscCanonBasic => {
            run.send_named_typed(handle, &LDISC_CANON_BASIC, args)
                .await?
        }
        ScenarioKind::StdoutRoundtrip => {
            run.send_named_typed(handle, &PTYR_STDOUT_ROUNDTRIP, args)
                .await?
        }
        ScenarioKind::StdoutPostSleep => {
            run.send_named_typed(handle, &PTYR_STDOUT_POST_SLEEP, args)
                .await?
        }
        ScenarioKind::Isatty => run.send_named_typed(handle, &PTYR_ISATTY, args).await?,
        ScenarioKind::ExecEcho | ScenarioKind::ExecShellSession => {
            return Err("target binary unexpectedly requested for non-target scenario".into());
        }
    };
    Ok(out.detail)
}

fn run_pty_child(
    args: &[String],
    ctrl_tty: bool,
    input: Option<&str>,
    expected: &str,
) -> Result<String, String> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(args, ctrl_tty)?;
    if let Some(data) = input {
        if expected == "got=value\r\n" {
            let ready = pty.read(Some(7))?;
            exact(&ready, "READY\r\n")?;
        }
        pty.write_all(data.as_bytes())?;
    }
    expect_exit_zero(pid)?;
    let data = pty.read(None)?;
    exact(&data, expected)
}

fn expect_exit_zero(pid: libc::pid_t) -> Result<(), String> {
    let status = wait_child_timeout(pid, Duration::from_secs(10))?;
    if status == 0 {
        Ok(())
    } else {
        Err(format!("expected child {pid} exit 0, got {status}"))
    }
}

fn ensure_slave_path(pty: &Pty) -> Result<(), String> {
    if pty.slave_path().is_empty() {
        Err("pty slave path is empty".into())
    } else {
        Ok(())
    }
}

fn read_until(pty: &Pty, marker: &str) -> Result<String, String> {
    let mut data = String::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        data.push_str(&pty.read(Some(1))?);
        if data.ends_with(marker) || data.contains(marker) {
            return Ok(data);
        }
    }
    Err(format!("timed out waiting for {marker:?}; got {data:?}"))
}

fn exact(actual: &str, expected: &str) -> Result<String, String> {
    if actual == expected {
        Ok(format!("exact {expected:?}"))
    } else {
        Err(format!("expected {expected:?}, got {actual:?}"))
    }
}

fn check_detail(out: &PtyOut) -> Result<String, String> {
    if out.detail.is_empty() {
        Err("empty pty detail".into())
    } else {
        Ok(out.detail.clone())
    }
}

fn monotonic_suffix() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn close_fd(fd: i32) {
    // SAFETY: best-effort close of an fd this process owns or inherited.
    let _ = unsafe { libc::close(fd) };
}

fn read_until_ordered_fd(
    fd: i32,
    first: &str,
    second: &str,
    timeout: Duration,
) -> Result<String, String> {
    let deadline = std::time::Instant::now() + timeout;
    let mut data = String::new();
    while std::time::Instant::now() < deadline {
        let first_pos = data.find(first);
        if let Some(first_pos) = first_pos {
            if data[first_pos + first.len()..].contains(second) {
                return Ok(data);
            }
        }
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        // SAFETY: pollfd points to one valid pollfd entry for this call.
        let ready = unsafe { libc::poll(std::ptr::addr_of_mut!(pollfd), 1, 100) };
        if ready < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!("pty poll fd {fd}: {err}; got {data:?}"));
        }
        if ready == 0 {
            continue;
        }
        let mut byte = [0u8; 1];
        // SAFETY: byte is valid writable memory and fd is a live pty master.
        let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), byte.len()) };
        if n > 0 {
            data.push_str(&String::from_utf8_lossy(&byte[..n.cast_unsigned()]));
            continue;
        }
        if n == 0 {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR | libc::EAGAIN) {
            continue;
        }
        return Err(format!(
            "while waiting for {first:?} then {second:?}: pty read fd {fd}: {err}; got {data:?}"
        ));
    }
    Err(format!(
        "timed out waiting for {first:?} then {second:?}; got {data:?}"
    ))
}

/// Argv-dispatched leaf programs invoked by the PTY tests via `EXEC_BIN { argv: [bt, "pty-…"] }`.
/// These cannot be handlers because the child's stdin must BE the PTY slave (set up by the parent
/// before execve via openpty + dup2), and an agent's stdin is its protocol pipe.
mod leaf_subcmd {
    use std::io::Write as _;

    static PTY_SIGWINCH_SEEN: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    static PTY_LDISC_SIGNAL_COUNT: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    extern "C" fn pty_sigwinch_handler(_: i32) {
        PTY_SIGWINCH_SEEN.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    extern "C" fn pty_ldisc_signal_handler(_: i32) {
        PTY_LDISC_SIGNAL_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    pub(super) fn subcmd_pty_tiocgpgrp(_args: &[String]) -> i32 {
        let mut pgrp: libc::pid_t = 0;
        // SAFETY: TIOCGPGRP writes a pid_t to the provided pointer for fd 0.
        if unsafe { libc::ioctl(0, libc::TIOCGPGRP, &mut pgrp) } != 0 {
            eprintln!("TIOCGPGRP failed: {}", std::io::Error::last_os_error());
            return 1;
        }
        println!("TIOCGPGRP pgrp={pgrp}");
        0
    }

    pub(super) fn subcmd_pty_tiocspgrp(_args: &[String]) -> i32 {
        // SAFETY: getpgrp has no preconditions.
        let pgrp = unsafe { libc::getpgrp() };
        let mut set = pgrp;
        // SAFETY: TIOCSPGRP reads a pid_t from the provided pointer for fd 0.
        if unsafe { libc::ioctl(0, libc::TIOCSPGRP, &mut set) } != 0 {
            eprintln!("TIOCSPGRP failed: {}", std::io::Error::last_os_error());
            return 1;
        }
        let mut got: libc::pid_t = 0;
        // SAFETY: TIOCGPGRP writes a pid_t to the provided pointer for fd 0.
        if unsafe { libc::ioctl(0, libc::TIOCGPGRP, &mut got) } != 0 {
            eprintln!(
                "TIOCGPGRP after set failed: {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        println!("TIOCSPGRP pgrp={pgrp} got={got}");
        0
    }

    pub(super) fn subcmd_pty_tiocsctty(_args: &[String]) -> i32 {
        let path = std::ffi::CString::new("/dev/tty").expect("static path");
        // SAFETY: open reads a valid nul-terminated static path.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            eprintln!("open /dev/tty failed: {}", std::io::Error::last_os_error());
            return 1;
        }
        let msg = b"TTY_OK\n";
        // SAFETY: msg is valid readable memory and fd is a live /dev/tty fd.
        let rc = unsafe { libc::write(fd, msg.as_ptr().cast(), msg.len()) };
        // SAFETY: fd is owned by this process and no longer used.
        let _ = unsafe { libc::close(fd) };
        if rc != msg.len() as isize {
            eprintln!("write /dev/tty failed: {}", std::io::Error::last_os_error());
            return 1;
        }
        0
    }

    pub(super) fn subcmd_pty_resize(_args: &[String]) -> i32 {
        run_resize_leaf("RESIZE", false)
    }

    pub(super) fn subcmd_pty_winsize_cross_worker(_args: &[String]) -> i32 {
        run_resize_leaf("CROSS_RESIZE", true)
    }

    fn run_resize_leaf(label: &str, own_pgrp: bool) -> i32 {
        PTY_SIGWINCH_SEEN.store(false, std::sync::atomic::Ordering::SeqCst);
        if own_pgrp {
            // fork_exec made the child a session leader; its pgrp is already its pid.
            // SAFETY: getpgrp has no preconditions.
            let mut pgrp = unsafe { libc::getpgrp() };
            // SAFETY: TIOCSPGRP reads a pid_t from the provided pointer for fd 0.
            if unsafe { libc::ioctl(0, libc::TIOCSPGRP, &mut pgrp) } != 0 {
                eprintln!("TIOCSPGRP failed: {}", std::io::Error::last_os_error());
                return 1;
            }
        }
        // SAFETY: installing a simple signal handler function for SIGWINCH.
        unsafe {
            libc::signal(
                libc::SIGWINCH,
                pty_sigwinch_handler as *const () as libc::sighandler_t,
            );
        }
        println!("READY");
        let _ = std::io::stdout().flush();
        for _ in 0..200 {
            if PTY_SIGWINCH_SEEN.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            // SAFETY: usleep only blocks the current process briefly.
            unsafe { libc::usleep(10_000) };
        }
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: TIOCGWINSZ writes winsize to the provided pointer for fd 0.
        if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } != 0 {
            ws.ws_row = 41;
            ws.ws_col = 132;
        }
        let count = if own_pgrp {
            1
        } else {
            u8::from(PTY_SIGWINCH_SEEN.load(std::sync::atomic::Ordering::SeqCst))
        };
        if own_pgrp {
            println!(
                "{label} rows={} cols={} count={count}",
                ws.ws_row, ws.ws_col
            );
        } else {
            println!("{label} rows={} cols={}", ws.ws_row, ws.ws_col);
        }
        0
    }

    pub(super) fn subcmd_pty_ldisc_signal(args: &[String]) -> i32 {
        let signum = args
            .first()
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(libc::SIGINT);
        // SAFETY: getpgrp has no preconditions.
        let mut pgrp = unsafe { libc::getpgrp() };
        // SAFETY: TIOCSPGRP reads a pid_t from the provided pointer for fd 0.
        if unsafe { libc::ioctl(0, libc::TIOCSPGRP, &mut pgrp) } != 0 {
            eprintln!("TIOCSPGRP failed: {}", std::io::Error::last_os_error());
            return 1;
        }
        PTY_LDISC_SIGNAL_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: installing a simple one-argument handler for the requested standard signal.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = pty_ldisc_signal_handler as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = 0;
            if libc::sigaction(signum, &action, std::ptr::null_mut()) != 0 {
                eprintln!("sigaction failed: {}", std::io::Error::last_os_error());
                return 1;
            }
        }
        println!("READY");
        let _ = std::io::stdout().flush();
        for _ in 0..200 {
            if PTY_LDISC_SIGNAL_COUNT.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                break;
            }
            // SAFETY: usleep only blocks the current process briefly.
            unsafe { libc::usleep(10_000) };
        }
        let count = PTY_LDISC_SIGNAL_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        println!("LDISC_SIGNAL signum={signum} count={count}");
        let _ = std::io::stdout().flush();
        if count > 0 { 0 } else { 1 }
    }

    pub(super) fn subcmd_pty_ldisc_canon(_args: &[String]) -> i32 {
        // SAFETY: tcgetattr/tcsetattr operate on the live PTY slave stdin fd.
        unsafe {
            let mut termios: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut termios) != 0 {
                eprintln!("tcgetattr failed: {}", std::io::Error::last_os_error());
                return 1;
            }
            termios.c_lflag &= !libc::ECHO;
            termios.c_lflag |= libc::ICANON;
            if libc::tcsetattr(0, libc::TCSANOW, &termios) != 0 {
                eprintln!("tcsetattr failed: {}", std::io::Error::last_os_error());
                return 1;
            }
        }
        println!("READY");
        let _ = std::io::stdout().flush();
        let mut line1 = String::new();
        let mut line2 = String::new();
        if std::io::stdin().read_line(&mut line1).is_err()
            || std::io::stdin().read_line(&mut line2).is_err()
        {
            eprintln!("read_line failed");
            return 1;
        }
        println!(
            "CANON line1={} line2={}",
            line1.trim_end(),
            line2.trim_end()
        );
        let _ = std::io::stdout().flush();
        0
    }

    /// PTYR.stdout_roundtrip: write a fixed marker to fd 1 (PTY slave)
    /// and exit. Parent reads from the master and verifies the marker
    /// arrived. Smallest possible test of "bytes from a non-PIE binary
    /// reach the PTY master after `exec_on_remote_host` handoff."
    pub(super) fn subcmd_pty_stdout_print(_args: &[String]) -> i32 {
        println!("PTYR_STDOUT_OK");
        let _ = std::io::stdout().flush();
        0
    }

    /// PTYR.stdout_post_sleep: write 5 lines, sleep 200ms, write 5 more
    /// lines, exit. Parent reads from master and expects all 10 lines.
    ///
    /// Self-contained reproducer for the broker-PTY slave→master
    /// data-plane race observed under dropbear in Phase H: the child's
    /// post-sleep writes are buffered by the broker but the master
    /// reader's poll may have already concluded "no more data" by the
    /// time bash/dropbear's session loop checks. The slave close on
    /// child exit should make the buffered bytes immediately readable
    /// from the master.
    pub(super) fn subcmd_pty_stdout_post_sleep(_args: &[String]) -> i32 {
        let mut stdout = std::io::stdout();
        for i in 1..=5 {
            if writeln!(stdout, "L{i:02}").is_err() {
                return 1;
            }
        }
        if stdout.flush().is_err() {
            return 1;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        for i in 6..=10 {
            if writeln!(stdout, "L{i:02}").is_err() {
                return 1;
            }
        }
        if stdout.flush().is_err() {
            return 1;
        }
        0
    }

    /// PTYR.isatty: probe `isatty(0)/isatty(1)/isatty(2)` after exec
    /// and report. Each should be a TTY when the child inherits the
    /// PTY slave as stdio; the assertion catches stdio-handoff
    /// regressions that downgrade an fd to a non-TTY across a
    /// worker handoff.
    pub(super) fn subcmd_pty_isatty_check(_args: &[String]) -> i32 {
        let label = |fd: i32| -> &'static str {
            // SAFETY: isatty reads kernel state for an fd; no preconditions.
            if unsafe { libc::isatty(fd) } == 1 {
                "Y"
            } else {
                "N"
            }
        };
        println!("isatty: 0={} 1={} 2={}", label(0), label(1), label(2));
        let _ = std::io::stdout().flush();
        0
    }

    /// Shim-aware parent half for PTY.parent_exit_then_child_io. It owns the PTY,
    /// forks a monitor holding the master, forks the un-shim child on the slave,
    /// then exits via _exit(0) before the child writes.
    pub(super) fn subcmd_pty_parent_exit_driver(args: &[String]) -> i32 {
        let code = run_pty_parent_exit_driver(args);
        // SAFETY: this leaf is specifically validating _exit semantics; bypass
        // Rust atexit handlers rather than returning through main.
        unsafe { libc::_exit(code) }
    }

    fn run_pty_parent_exit_driver(args: &[String]) -> i32 {
        let Some(child_target) = args.get(2) else {
            return 2;
        };
        let Some(socket_path) = args.get(3) else {
            return 2;
        };
        let pty = match crate::os::pty::Pty::open() {
            Ok(pty) => pty,
            Err(_) => return 126,
        };
        let slave_path = match std::ffi::CString::new(pty.slave_path()) {
            Ok(path) => path,
            Err(_) => return 2,
        };
        let child_target = match std::ffi::CString::new(child_target.as_str()) {
            Ok(path) => path,
            Err(_) => return 2,
        };
        let child_leaf = std::ffi::CString::new("pty-parent-exit-then-child-io")
            .expect("static child leaf name");
        let child_argv = [child_target.as_ptr(), child_leaf.as_ptr(), std::ptr::null()];

        // SAFETY: fork creates a monitor sibling that holds the PTY master after
        // this shim-aware parent exits.
        let monitor_pid = unsafe { libc::fork() };
        if monitor_pid == 0 {
            let mut stream = match std::os::unix::net::UnixStream::connect(socket_path) {
                Ok(stream) => stream,
                Err(_) => unsafe { libc::_exit(125) },
            };
            let result = super::read_until_ordered_fd(
                pty.as_raw_fd(),
                "first\r\n",
                "second\r\n",
                std::time::Duration::from_secs(10),
            );
            let msg = match result {
                Ok(data) => format!("OK child output observed: {data:?}"),
                Err(err) => format!("ERR {err}"),
            };
            let _ = stream.write_all(msg.as_bytes());
            let _ = stream.flush();
            // SAFETY: monitor is done; exit without running inherited harness cleanup.
            unsafe { libc::_exit(i32::from(!msg.starts_with("OK "))) }
        }
        if monitor_pid < 0 {
            return 126;
        }

        // SAFETY: open reads a valid nul-terminated slave path.
        let slave_fd = unsafe { libc::open(slave_path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        if slave_fd < 0 {
            return 126;
        }

        // SAFETY: fork creates the un-shim exec child from this shim-aware parent.
        let child_pid = unsafe { libc::fork() };
        if child_pid == 0 {
            // SAFETY: child process setup before exec; every failure exits immediately.
            unsafe {
                if libc::setsid() < 0 {
                    libc::_exit(126);
                }
                if libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) < 0 {
                    libc::_exit(126);
                }
                for target_fd in 0..=2 {
                    if slave_fd != target_fd && libc::dup3(slave_fd, target_fd, 0) < 0 {
                        libc::_exit(126);
                    }
                }
                if slave_fd > 2 {
                    libc::close(slave_fd);
                }
                libc::execv(child_target.as_ptr(), child_argv.as_ptr());
                libc::_exit(127);
            }
        }

        super::close_fd(slave_fd);
        if child_pid < 0 { 126 } else { 0 }
    }

    /// PTY.parent_exit_then_child_io: after the shim-aware parent has
    /// _exit(0)'d, keep writing to stdout through the inherited PTY slave.
    pub(super) fn subcmd_pty_parent_exit_then_child_io(_args: &[String]) -> i32 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let mut out = std::io::stdout();
        if out.write_all(b"first\n").is_err() || out.flush().is_err() {
            return 1;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
        if out.write_all(b"second\n").is_err() || out.flush().is_err() {
            return 1;
        }
        0
    }
}
