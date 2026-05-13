// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PTY protocol tests for VS Code terminal blockers.
//!
//! Migrated to the typed-handler protocol. Each scenario opens the
//! pty, forks the child, performs all pty I/O, waits, and closes the
//! master inside one straight-line handler body.

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
    ExecShellSession,
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
        name: "exec_shell_session",
        kind: ScenarioKind::ExecShellSession,
        per_binary_type: false,
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
const EXEC_SHELL_SESSION: HandlerToken<(), PtyOut> = HandlerToken::new("pty.exec_shell_session");

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
    let ready = pty.read(Some(7))?;
    exact(&ready, "READY\r\n")?;
    pty.resize(41, 132)?;
    expect_exit_zero(pid)?;
    let data = pty.read(None)?;
    let detail = exact(&data, "RESIZE rows=41 cols=132\r\n")?;
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

// ─── Registration ────────────────────────────────────────────────────

pub(crate) fn register_pty_tests(reg: &mut Registry<'_>) {
    register_handler!(EXEC_ECHO, handle_exec_echo);
    register_handler!(TIOCGPGRP, handle_tiocgpgrp);
    register_handler!(TIOCSPGRP, handle_tiocspgrp);
    register_handler!(TIOCSCTTY, handle_tiocsctty);
    register_handler!(RESIZE, handle_resize);
    register_handler!(EXEC_SHELL_SESSION, handle_exec_shell_session);

    crate::register_leaf_subcommand!("pty-tiocgpgrp", leaf_subcmd::subcmd_pty_tiocgpgrp);
    crate::register_leaf_subcommand!("pty-tiocspgrp", leaf_subcmd::subcmd_pty_tiocspgrp);
    crate::register_leaf_subcommand!("pty-tiocsctty", leaf_subcmd::subcmd_pty_tiocsctty);
    crate::register_leaf_subcommand!("pty-resize", leaf_subcmd::subcmd_pty_resize);

    for &agent in PTY_AGENTS {
        for def in PTY_SCENARIOS {
            // Per-binary-type scenarios fan out across BinaryType::ALL;
            // others use the legacy 3-segment ID with no binary axis.
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

/// Argv-dispatched leaf programs invoked by the PTY tests via `EXEC_BIN { argv: [bt, "pty-…"] }`.
/// These cannot be handlers because the child's stdin must BE the PTY slave (set up by the parent
/// before execve via openpty + dup2), and an agent's stdin is its protocol pipe.
mod leaf_subcmd {
    use std::io::Write as _;

    static PTY_SIGWINCH_SEEN: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    extern "C" fn pty_sigwinch_handler(_: i32) {
        PTY_SIGWINCH_SEEN.store(true, std::sync::atomic::Ordering::SeqCst);
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
        PTY_SIGWINCH_SEEN.store(false, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: installing a simple signal handler function for SIGWINCH.
        unsafe {
            libc::signal(
                libc::SIGWINCH,
                pty_sigwinch_handler as *const () as libc::sighandler_t,
            );
        }
        println!("READY");
        let _ = std::io::stdout().flush();
        while !PTY_SIGWINCH_SEEN.load(std::sync::atomic::Ordering::SeqCst) {
            // SAFETY: pause waits for a signal; EINTR is expected after SIGWINCH.
            unsafe { libc::pause() };
        }
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: TIOCGWINSZ writes winsize to the provided pointer for fd 0.
        if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } != 0 {
            eprintln!("TIOCGWINSZ failed: {}", std::io::Error::last_os_error());
            return 1;
        }
        println!("RESIZE rows={} cols={}", ws.ws_row, ws.ws_col);
        0
    }
}
