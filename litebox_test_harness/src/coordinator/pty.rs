// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PTY protocol tests for VS Code terminal blockers.
//!
//! Migrated to the typed-handler protocol. Each scenario opens the
//! pty, forks the child, performs all pty I/O, waits, and closes the
//! master inside one straight-line handler body.

// TODO(#15): convert legacy wildcard enum dispatch in this file to explicit arms.
#![allow(clippy::wildcard_enum_match_arm)]

use std::io::Read as _;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::pty::{Pty, wait_child_timeout};
use crate::register_handler;

use super::TestOutcome;
use super::agents::AgentName;
use super::matrix::EXEC_AGENTS;
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
    ControllingTtyTostopSigttou,
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
    /// PTYR.slave_write_atomicity — child writes to slave then exits.
    /// Parent reaps the child (`waitpid`), THEN does a single
    /// non-blocking `read(2)` on the master without any poll/sleep.
    ///
    /// Invariant: by the time `waitpid` returns the child's exit
    /// status, every byte the child wrote to its slave fd must be
    /// IMMEDIATELY readable from the master. Real Linux PTY satisfies
    /// this because the kernel updates the master buffer atomically
    /// with the slave write. If the broker PTY's slave→master
    /// notification is asynchronous (e.g., the master subscriber
    /// wake travels via a notification ring with non-zero latency),
    /// the read returns EAGAIN — and any consumer that doesn't
    /// re-poll (like dropbear's session-end loop) loses the data.
    SlaveWriteAtomicity,
    /// PTYR.poll_after_exit — same shape as SlaveWriteAtomicity but
    /// probes via `poll(POLLIN, 0ms)` instead of `read(2)`. This is
    /// dropbear's EXACT pattern: poll the master fd with 0 timeout
    /// at session-end teardown; if POLLIN is set, drain it. The
    /// invariant: after `waitpid` returns the child's exit status,
    /// `poll(master, POLLIN, 0)` MUST report POLLIN if the child
    /// wrote any data.
    PollAfterExit,
    /// PTYR.slave_close_hup — child writes nothing, just exits.
    /// Parent reaps, then polls master with `POLLHUP`. POLLHUP MUST
    /// be set immediately — dropbear and any TTY-aware consumer
    /// uses POLLHUP to detect peer-closed.
    SlaveCloseHup,
    /// PTYR.poll_loop_post_sleep — poll([master], short timeout) loop.
    /// Captures the basic "drain master while child sleeps" invariant.
    PollLoopPostSleep,
    /// PTYR.dropbear_emul — faithful dropbear session-loop emulation.
    /// Parent polls `[master, signalfd(SIGCHLD)]` simultaneously,
    /// reads master on POLLIN, drains and exits when SIGCHLD says the
    /// child reaped AND a final non-blocking master drain returns
    /// EOF/empty. Child exec's `/bin/sh -c 'echo;echo;sleep 1;echo;
    /// echo;echo'` — the exact bash workload that drops L03..L05 under
    /// dropbear-in-litebox.
    ///
    /// If `poll_loop_post_sleep` passes but this fails, the bug is
    /// in the interaction between multiple readiness sources (the
    /// signalfd SIGCHLD firing during the sleep changes the poll
    /// wakeup pattern relative to master's POLLIN delivery).
    DropbearEmul,
    /// PTYR.select_loop_post_sleep — variant of `dropbear_emul` that
    /// uses `select(2)` instead of `poll(2)`. Real dropbear historically
    /// uses select() (it's the portable BSD-derived API). If the
    /// shim's select-on-broker-fd path has a bug that poll() avoids,
    /// this test catches it.
    SelectLoopPostSleep,
    /// PTYR.read_eagain_then_write — child writes 2 lines, sleeps
    /// 200ms, writes 3 more lines, exits. Parent drains GREEDILY
    /// (read until EAGAIN), then waits for the next POLLIN.
    ///
    /// Captures the "edge-triggered notification" hazard: if the
    /// broker fires POLLIN once per write *batch* and the parent
    /// drains to EAGAIN inside that batch, a subsequent write must
    /// fire another POLLIN. If the broker only fires when the
    /// subscriber's ring transitions empty→non-empty, the
    /// post-drain write could be missed if it arrives during a
    /// brief drain race.
    ReadEagainThenWrite,
    /// PTYR.poll_loop_post_sleep_with_inerts — parent polls a 6-fd
    /// set: master + signalfd + 4 inert pipes (nothing ever written).
    /// Real dropbear's poll set has the listen socket, channel data
    /// socket(s), and several pipes — a multi-fd poll with most
    /// entries returning revents=0. If a shim bug only manifests
    /// when the poll() returns POLLIN on one fd in a busy set
    /// (some fd-index ordering issue), this catches it.
    PollLoopPostSleepWithInerts,
    /// PTYR.write_then_exec_then_write — child writes "PRE\n",
    /// then execve's into a sibling leaf that writes "POST\n"
    /// and exits. Both writes use the SAME inherited slave PTY
    /// fd (CLOEXEC clear).
    ///
    /// Captures the Phase H dropbear failure pattern: under
    /// dropbear, `exec /bin/bash -c "echo L2"` after an earlier
    /// `echo L1` loses L2. Bash bytes written *after* an execve
    /// (whether in-place exec or fork+exec) do not reach the
    /// master in the real-stack case. This test exercises the
    /// shim's execve path for slave-PTY-fd inheritance across
    /// re-exec.
    WriteThenExecThenWrite,
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
        name: "controlling_tty.tostop_sigttou",
        kind: ScenarioKind::ControllingTtyTostopSigttou,
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
        name: "slave_write_atomicity",
        kind: ScenarioKind::SlaveWriteAtomicity,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "poll_after_exit",
        kind: ScenarioKind::PollAfterExit,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "slave_close_hup",
        kind: ScenarioKind::SlaveCloseHup,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "poll_loop_post_sleep",
        kind: ScenarioKind::PollLoopPostSleep,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "dropbear_emul",
        kind: ScenarioKind::DropbearEmul,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "select_loop_post_sleep",
        kind: ScenarioKind::SelectLoopPostSleep,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "read_eagain_then_write",
        kind: ScenarioKind::ReadEagainThenWrite,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "poll_loop_post_sleep_with_inerts",
        kind: ScenarioKind::PollLoopPostSleepWithInerts,
        per_binary_type: true,
    },
    ScenarioDef {
        name: "write_then_exec_then_write",
        kind: ScenarioKind::WriteThenExecThenWrite,
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
const CONTROLLING_TTY_TOSTOP_SIGTTOU: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.controlling_tty.tostop_sigttou");
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
const PTYR_SLAVE_WRITE_ATOMICITY: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("ptyr.slave_write_atomicity");
const PTYR_POLL_AFTER_EXIT: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("ptyr.poll_after_exit");
const PTYR_SLAVE_CLOSE_HUP: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("ptyr.slave_close_hup");
const PTYR_POLL_LOOP_POST_SLEEP: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("ptyr.poll_loop_post_sleep");
const PTYR_DROPBEAR_EMUL: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("ptyr.dropbear_emul");
const PTYR_SELECT_LOOP_POST_SLEEP: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("ptyr.select_loop_post_sleep");
const PTYR_READ_EAGAIN_THEN_WRITE: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("ptyr.read_eagain_then_write");
const PTYR_POLL_LOOP_POST_SLEEP_WITH_INERTS: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("ptyr.poll_loop_post_sleep_with_inerts");
const PTYR_WRITE_THEN_EXEC_THEN_WRITE: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("ptyr.write_then_exec_then_write");
const PTYR_ISATTY: HandlerToken<TargetArgs, PtyOut> = HandlerToken::new("ptyr.isatty");
const PTYR_STDIO_LOCKSTEP: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("ptyr.stdio_lockstep");
const PARENT_EXIT_THEN_CHILD_IO: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.parent_exit_then_child_io");
const TERMIOS_ICANON_ECHO: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.termios.icanon_echo");
const WINSIZE_TIOCSWINSZ_PROPAGATES: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.winsize.tiocswinsz_propagates");
const SIGWINCH_DELIVERED_ON_RESIZE: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.sigwinch.delivered_on_resize");
const CONTROLLING_TTY_TIOCSCTTY_SIGTTIN: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.controlling_tty.tiocsctty_sigttin");
const LINE_DISCIPLINE_CR_TO_NL: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.line_discipline.cr_to_nl");
const IOCTL_TIOCGPTN_ONLY_ON_MASTER: HandlerToken<(), PtyOut> =
    HandlerToken::new("pty.ioctl.tiocgptn_only_on_master");
const DEVPTS_DIR_OPENABLE: HandlerToken<(), PtyOut> = HandlerToken::new("pty.devpts.dir_openable");
const SLAVE_REOPEN_WRITE_REACHES_MASTER: HandlerToken<(), PtyOut> =
    HandlerToken::new("pty.slave_reopen.write_reaches_master");
const CHILD_SLAVE_REOPEN_WRITE_REACHES_MASTER: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.child_slave_reopen.write_reaches_master");
const SIGTTIN_DFL_DOES_NOT_KILL: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.sigttin_dfl_does_not_kill");
const READLINK_PROC_SELF_FD_STDIO_RETURNS_PTY_PATH: HandlerToken<TargetArgs, PtyOut> =
    HandlerToken::new("pty.readlink.proc_self_fd_stdio_returns_pty_path");

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

async fn handle_ptyr_slave_write_atomicity(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-slave-write-atomicity".into()], true)?;
    // Reap child FIRST. After waitpid returns the child's exit
    // status, every byte the child wrote to its slave must be
    // IMMEDIATELY readable from the master without poll/wait.
    expect_exit_zero(pid)?;
    let observed = pty.try_read_now(4096)?;
    let bytes = observed
        .ok_or_else(|| "post-reap try_read_now returned EAGAIN — broker PTY slave→master propagation is not synchronous with child exit (dropbear / sshd will lose this data)".to_string())?;
    let s = String::from_utf8_lossy(&bytes).to_string();
    // Expect: "WRITE_ATOMIC_OK\r\n" — single-line marker.
    let detail = exact(&s, "WRITE_ATOMIC_OK\r\n")?;
    Ok(PtyOut { detail })
}

async fn handle_ptyr_poll_after_exit(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-slave-write-atomicity".into()], true)?;
    expect_exit_zero(pid)?;
    // Dropbear's exact session-end pattern: poll(master, POLLIN, 0).
    // Must return POLLIN immediately for the child's writes to be
    // captured before the session loop closes the channel.
    let revents = pty.poll_now(libc::POLLIN)?;
    if revents & libc::POLLIN == 0 {
        return Err(format!(
            "post-reap poll(POLLIN, 0) returned revents={revents:#x} — POLLIN not set; \
             broker PTY does not synchronously expose slave-write data on master \
             before the master worker's notification-ring dispatcher catches up. \
             dropbear/sshd's session-end loop sees the same EAGAIN and closes."
        )
        .into());
    }
    // Now drain to confirm bytes are there.
    let bytes = pty.try_read_now(4096)?.ok_or_else(|| {
        "POLLIN reported but try_read_now returned None (inconsistent)".to_string()
    })?;
    let s = String::from_utf8_lossy(&bytes).to_string();
    let detail = exact(&s, "WRITE_ATOMIC_OK\r\n")?;
    Ok(PtyOut { detail })
}

async fn handle_ptyr_slave_close_hup(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-slave-close-immediate".into()], true)?;
    expect_exit_zero(pid)?;
    // Child wrote nothing; slave is closed. POLLHUP must be set
    // immediately so consumers can detect peer-close (dropbear,
    // tokio's signal_unix wait, etc.).
    let revents = pty.poll_now(libc::POLLIN | libc::POLLHUP)?;
    if revents & libc::POLLHUP == 0 {
        return Err(format!(
            "post-reap poll(POLLIN|POLLHUP, 0) returned revents={revents:#x} — \
             POLLHUP not set after child exit closed slave"
        )
        .into());
    }
    Ok(PtyOut {
        detail: format!("revents={revents:#x}"),
    })
}

async fn handle_ptyr_poll_loop_post_sleep(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-poll-loop-post-sleep".into()], true)?;
    let mut buf = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "timeout draining master; captured={:?}",
                String::from_utf8_lossy(&buf)
            )
            .into());
        }
        let revents = pty.poll_now_timeout(libc::POLLIN | libc::POLLHUP, 50)?;
        if revents & libc::POLLIN != 0
            && let Some(bytes) = pty.try_read_now(4096)?
        {
            if bytes.is_empty() {
                break;
            }
            buf.extend_from_slice(&bytes);
        }
        if revents & libc::POLLHUP != 0 {
            while let Some(bytes) = pty.try_read_now(4096)? {
                if bytes.is_empty() {
                    break;
                }
                buf.extend_from_slice(&bytes);
            }
            break;
        }
    }
    expect_exit_zero(pid)?;
    let s = String::from_utf8_lossy(&buf).to_string();
    let expected = "L01\r\nL02\r\nL03\r\nL04\r\nL05\r\n";
    let detail = exact(&s, expected)?;
    Ok(PtyOut { detail })
}

async fn handle_ptyr_dropbear_emul(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // Block SIGCHLD so it's delivered via signalfd rather than as
    // a signal handler — dropbear's exact pattern.
    // SAFETY: sigfillset on a local sigset_t; sigprocmask is safe.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGCHLD);
        if libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) != 0 {
            return Err(format!(
                "pthread_sigmask SIG_BLOCK SIGCHLD: {}",
                std::io::Error::last_os_error()
            )
            .into());
        }
    }
    // SAFETY: signalfd creates a new fd from the mask; SFD_CLOEXEC|SFD_NONBLOCK make it safe to leak.
    let sigfd_raw = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
    if sigfd_raw < 0 {
        return Err(format!("signalfd: {}", std::io::Error::last_os_error()).into());
    }
    // SAFETY: signalfd returned a valid fd we own.
    let sigfd: OwnedFd = unsafe { OwnedFd::from_raw_fd(sigfd_raw) };

    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-poll-loop-post-sleep".into()], true)?;

    let mut buf = Vec::new();
    let mut child_reaped: Option<i32> = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "dropbear-emul: timeout; reaped={child_reaped:?}; captured={:?}",
                String::from_utf8_lossy(&buf)
            )
            .into());
        }
        let mut pollfds = [
            libc::pollfd {
                fd: pty.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            },
            libc::pollfd {
                fd: sigfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: pollfds is a valid array of 2 pollfd entries.
        let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), 2, 50) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!("poll: {err}").into());
        }
        let m_revents = pollfds[0].revents;
        let s_revents = pollfds[1].revents;
        if m_revents & libc::POLLIN != 0
            && let Some(bytes) = pty.try_read_now(4096)?
        {
            if !bytes.is_empty() {
                buf.extend_from_slice(&bytes);
            }
        }
        if s_revents & libc::POLLIN != 0 {
            // Drain signalfd buffer.
            let mut siginfo = [0u8; 128];
            // SAFETY: signalfd_siginfo is 128 bytes; reading drains one entry.
            let _ = unsafe {
                libc::read(
                    sigfd.as_raw_fd(),
                    siginfo.as_mut_ptr().cast(),
                    siginfo.len(),
                )
            };
            // waitpid(WNOHANG) for any descendant; if our direct
            // child is reaped, remember it but keep draining master.
            loop {
                let mut status: i32 = 0;
                // SAFETY: waitpid is safe; WNOHANG won't block.
                let w = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
                if w <= 0 {
                    break;
                }
                if w == pid {
                    child_reaped = Some(status);
                }
            }
        }
        if m_revents & libc::POLLHUP != 0 {
            while let Some(bytes) = pty.try_read_now(4096)? {
                if bytes.is_empty() {
                    break;
                }
                buf.extend_from_slice(&bytes);
            }
            break;
        }
        if child_reaped.is_some() {
            // Child gone — do a final non-blocking master drain then exit.
            while let Some(bytes) = pty.try_read_now(4096)? {
                if bytes.is_empty() {
                    break;
                }
                buf.extend_from_slice(&bytes);
            }
            // One more poll(0) to see if any bytes are still queued.
            let final_re = pty.poll_now_timeout(libc::POLLIN | libc::POLLHUP, 0)?;
            if final_re & libc::POLLIN == 0 {
                break;
            }
        }
    }
    // Restore signal mask.
    unsafe {
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &mask, std::ptr::null_mut());
    }
    let s = String::from_utf8_lossy(&buf).to_string();
    let expected = "L01\r\nL02\r\nL03\r\nL04\r\nL05\r\n";
    let detail = exact(&s, expected)?;
    Ok(PtyOut {
        detail: format!(
            "{detail} reaped={}",
            child_reaped
                .map(|s| format!("{s:#x}"))
                .unwrap_or_else(|| "none".to_string())
        ),
    })
}

async fn handle_ptyr_select_loop_post_sleep(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-poll-loop-post-sleep".into()], true)?;

    let mut buf = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let pty_fd = pty.as_raw_fd();
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "select-loop: timeout; captured={:?}",
                String::from_utf8_lossy(&buf)
            )
            .into());
        }
        // SAFETY: writing to a zero-initialized fd_set then FD_SET.
        let mut rfds: libc::fd_set = unsafe { std::mem::zeroed() };
        unsafe { libc::FD_SET(pty_fd, &mut rfds) };
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 50_000,
        };
        // SAFETY: rfds is valid; nfds = pty_fd + 1; tv has correct size.
        let rc = unsafe {
            libc::select(
                pty_fd + 1,
                &mut rfds,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut tv,
            )
        };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!("select: {err}").into());
        }
        // SAFETY: rfds is initialized; FD_ISSET reads it.
        if rc > 0 && unsafe { libc::FD_ISSET(pty_fd, &rfds) } {
            match pty.try_read_now(4096)? {
                Some(bytes) if bytes.is_empty() => break,
                Some(bytes) => buf.extend_from_slice(&bytes),
                None => {}
            }
        }
        // Probe completion via poll(POLLHUP, 0) since select() doesn't
        // surface POLLHUP separately.
        let hup = pty.poll_now_timeout(libc::POLLIN | libc::POLLHUP, 0)?;
        if hup & libc::POLLHUP != 0 {
            while let Some(bytes) = pty.try_read_now(4096)? {
                if bytes.is_empty() {
                    break;
                }
                buf.extend_from_slice(&bytes);
            }
            break;
        }
    }
    expect_exit_zero(pid)?;
    let s = String::from_utf8_lossy(&buf).to_string();
    let expected = "L01\r\nL02\r\nL03\r\nL04\r\nL05\r\n";
    let detail = exact(&s, expected)?;
    Ok(PtyOut { detail })
}

async fn handle_ptyr_read_eagain_then_write(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-poll-loop-post-sleep".into()], true)?;
    let mut buf = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "eagain-then-write: timeout; captured={:?}",
                String::from_utf8_lossy(&buf)
            )
            .into());
        }
        let revents = pty.poll_now_timeout(libc::POLLIN | libc::POLLHUP, 200)?;
        if revents & libc::POLLIN != 0 {
            // Drain GREEDILY until EAGAIN. This is the
            // "read-until-empty in a single wakeup" pattern that
            // event loops use. If the broker only fires POLLIN on
            // empty→non-empty transitions, a write that lands
            // during our drain window must still generate a
            // subsequent POLLIN — otherwise it's permanently lost
            // because we never see another readiness event.
            loop {
                match pty.try_read_now(4096)? {
                    Some(b) if b.is_empty() => break,
                    Some(b) => buf.extend_from_slice(&b),
                    None => break, // EAGAIN
                }
            }
        }
        if revents & libc::POLLHUP != 0 {
            while let Some(b) = pty.try_read_now(4096)? {
                if b.is_empty() {
                    break;
                }
                buf.extend_from_slice(&b);
            }
            break;
        }
    }
    expect_exit_zero(pid)?;
    let s = String::from_utf8_lossy(&buf).to_string();
    let expected = "L01\r\nL02\r\nL03\r\nL04\r\nL05\r\n";
    let detail = exact(&s, expected)?;
    Ok(PtyOut { detail })
}

async fn handle_ptyr_poll_loop_post_sleep_with_inerts(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // Create 4 inert pipe pairs; the parent polls the read ends.
    // Nothing is ever written to these — they should always
    // return revents=0. Mimics dropbear's busier poll set.
    let mut inert_fds: Vec<OwnedFd> = Vec::new();
    let mut _write_keep: Vec<OwnedFd> = Vec::new();
    for _ in 0..4 {
        let mut fds = [0i32; 2];
        // SAFETY: pipe2 takes a 2-element i32 array.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(format!("pipe2: {}", std::io::Error::last_os_error()).into());
        }
        // SAFETY: pipe2 returned two valid fds we now own.
        inert_fds.push(unsafe { OwnedFd::from_raw_fd(fds[0]) });
        _write_keep.push(unsafe { OwnedFd::from_raw_fd(fds[1]) });
    }

    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-poll-loop-post-sleep".into()], true)?;

    let mut buf = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "with-inerts: timeout; captured={:?}",
                String::from_utf8_lossy(&buf)
            )
            .into());
        }
        let mut pollfds = Vec::with_capacity(1 + inert_fds.len());
        pollfds.push(libc::pollfd {
            fd: pty.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        });
        for f in &inert_fds {
            pollfds.push(libc::pollfd {
                fd: f.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        // SAFETY: pollfds is a valid Vec<pollfd> with the given length.
        let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 50) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!("poll: {err}").into());
        }
        let m_revents = pollfds[0].revents;
        if m_revents & libc::POLLIN != 0
            && let Some(bytes) = pty.try_read_now(4096)?
        {
            if bytes.is_empty() {
                break;
            }
            buf.extend_from_slice(&bytes);
        }
        if m_revents & libc::POLLHUP != 0 {
            while let Some(bytes) = pty.try_read_now(4096)? {
                if bytes.is_empty() {
                    break;
                }
                buf.extend_from_slice(&bytes);
            }
            break;
        }
    }
    expect_exit_zero(pid)?;
    let s = String::from_utf8_lossy(&buf).to_string();
    let expected = "L01\r\nL02\r\nL03\r\nL04\r\nL05\r\n";
    let detail = exact(&s, expected)?;
    Ok(PtyOut { detail })
}

async fn handle_ptyr_write_then_exec_then_write(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(
        &[
            args.target.clone(),
            "pty-write-then-exec".into(),
            args.target,
        ],
        true,
    )?;

    // Drain master in a dropbear-style loop: poll(POLLIN|POLLHUP);
    // BREAK on POLLHUP (dropbear closes the SSH channel here);
    // accumulate POLLIN bytes. If a spurious POLLHUP fires during
    // the child's in-place execve (slave handle briefly detaches
    // from the broker, master_open_count or slave_open_count
    // momentarily transitions), the post-execve "POST\n" write
    // never makes it to the recorded buffer.
    let mut buf = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "write-then-exec-then-write: timeout; captured={:?}",
                String::from_utf8_lossy(&buf)
            )
            .into());
        }
        let revents = pty.poll_now_timeout(libc::POLLIN | libc::POLLHUP, 50)?;
        if revents & libc::POLLIN != 0 {
            while let Some(bytes) = pty.try_read_now(4096)? {
                if bytes.is_empty() {
                    break;
                }
                buf.extend_from_slice(&bytes);
            }
        }
        if revents & libc::POLLHUP != 0 {
            // Final drain attempt, then exit loop (dropbear pattern).
            while let Some(bytes) = pty.try_read_now(4096)? {
                if bytes.is_empty() {
                    break;
                }
                buf.extend_from_slice(&bytes);
            }
            break;
        }
    }
    expect_exit_zero(pid)?;
    let data = String::from_utf8_lossy(&buf).to_string();
    // PTY OPOST: \n → \r\n.
    let detail = exact(&data, "PRE\r\nPOST\r\n")?;
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

async fn handle_ptyr_stdio_lockstep(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-stdio-lockstep".into()], true)?;
    pty.write_all(b"PTY_STDIN_LOCKSTEP\n")?;
    expect_exit_zero(pid)?;
    let data = pty.read(None)?;
    if data.contains("PTY_STDOUT_LOCKSTEP:PTY_STDIN_LOCKSTEP\r\n")
        && data.contains("PTY_STDERR_LOCKSTEP\r\n")
    {
        Ok(PtyOut {
            detail: "PTY_STDIO_LOCKSTEP_OK".into(),
        })
    } else {
        Err(format!("PTY stdio lockstep markers missing from {data:?}").into())
    }
}

async fn handle_termios_icanon_echo(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-termios-icanon-echo".into()], true)?;
    read_until(&pty, "READY\r\n")?;

    pty.write_all(b"abc\n")?;
    let first = read_until(&pty, "ECHO_OFF_READY\r\n")?;
    if !first.ends_with("abc\r\nLINE1=abc\r\nECHO_OFF_READY\r\n") {
        return Err(format!("expected canonical echo + line report, got {first:?}").into());
    }

    pty.write_all(b"xyz\n")?;
    let second = read_until(&pty, "LINE2=xyz\r\n")?;
    if second.contains("xyz\r\nLINE2=xyz") {
        return Err(format!("ECHO-off input was echoed: {second:?}").into());
    }
    expect_exit_zero(pid)?;
    Ok(PtyOut {
        detail: "ICANON line buffering and ECHO on/off matched native".into(),
    })
}

async fn handle_winsize_tiocswinsz_propagates(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-winsize-propagates".into()], true)?;
    read_until(&pty, "READY\r\n")?;
    pty.resize(57, 143)?;
    pty.write_all(b"\n")?;
    expect_exit_zero(pid)?;
    let data = pty.read(None)?;
    let detail = exact(&data, "WINSIZE rows=57 cols=143\r\n")?;
    Ok(PtyOut { detail })
}

async fn handle_sigwinch_delivered_on_resize(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-sigwinch-delivered".into()], true)?;
    read_until(&pty, "READY\r\n")?;
    pty.resize(58, 144)?;
    expect_exit_zero(pid)?;
    let data = pty.read(None)?;
    let detail = exact(&data, "SIGWINCH count=1 rows=58 cols=144\r\n")?;
    Ok(PtyOut { detail })
}

async fn handle_controlling_tty_tiocsctty_sigttin(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-tiocsctty-sigttin".into()], true)?;
    let status = wait_child_or_stopped_timeout(pid, Duration::from_secs(10))?;
    let data = pty.read(None)?;
    if status != 0 {
        return Err(format!("expected child exit 0, got {status}; output={data:?}").into());
    }
    let detail = exact(&data, "SIGTTIN_OK\r\n")?;
    Ok(PtyOut { detail })
}

async fn handle_controlling_tty_tostop_sigttou(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-tostop-sigttou".into()], true)?;
    let status = wait_child_or_stopped_timeout(pid, Duration::from_secs(10))?;
    let data = pty.read(None)?;
    if status != 0 {
        return Err(format!("expected child exit 0, got {status}; output={data:?}").into());
    }
    let detail = exact(&data, "SIGTTOU_OK\r\n")?;
    Ok(PtyOut { detail })
}

async fn handle_line_discipline_cr_to_nl(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let pid = pty.fork_exec(&[args.target, "pty-line-discipline-cr-to-nl".into()], true)?;
    read_until(&pty, "READY\r\n")?;
    pty.write_all(b"\r")?;
    let first = read_until(&pty, "RAW_READY\r\n")?;
    if !first.contains("FIRST=10\r\n") {
        return Err(format!("ICRNL-on CR was not translated to NL: {first:?}").into());
    }
    pty.write_all(b"\r")?;
    expect_exit_zero(pid)?;
    let data = pty.read(None)?;
    let detail = exact(&data, "ICRNL on=10 off=13\r\n")?;
    Ok(PtyOut { detail })
}

/// `ioctl(slave_fd, TIOCGPTN)` must return `-ENOTTY` (per Linux kernel
/// behavior: `TIOCGPTN` is a ptmx-only ioctl). Under litebox at
/// amalgamation tip `295b26d1`, the shim handler in
/// `litebox_shim_linux/src/syscalls/file.rs:7030-7034` returns
/// `entry.pty_id()` unconditionally for any PTY entry, master or
/// slave — so `TIOCGPTN` on a slave returns `0` instead of `-ENOTTY`.
///
/// Real-world impact: GitHub Copilot CLI (and any TUI app using the
/// same PTY-detection pattern) calls `ioctl(stdin, TIOCGPTN)` at
/// startup to decide whether stdin is a master or slave. Native
/// returns `-ENOTTY` → "must be a slave" → falls back to
/// `readlink("/proc/self/fd/0")` to find `/dev/pts/N` and proceeds.
/// Under litebox the ioctl returns `0` → the app mis-classifies the
/// fd → opens `/dev/null` as the fallback → TUI rendering goes
/// nowhere → screen stays empty and `copilot::tui.*` trials hang.
///
/// Surfaced by Goal A validation session 7c1fc95d (2026-06-05),
/// strace divergence sub-investigation.
async fn handle_ioctl_tiocgptn_only_on_master(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    let master_fd = pty.as_raw_fd();
    let slave_path = std::ffi::CString::new(pty.slave_path())
        .map_err(|e| HandlerError::from(format!("slave path NUL: {e}")))?;

    // Open the slave WITHOUT making it our controlling tty; we only
    // care about the ioctl shape, not session semantics.
    // SAFETY: slave_path is a valid NUL-terminated C string from ptsname.
    let slave_fd = unsafe { libc::open(slave_path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if slave_fd < 0 {
        return Err(HandlerError::from(format!(
            "open({}) failed: {}",
            pty.slave_path(),
            std::io::Error::last_os_error()
        )));
    }

    let mut slave_n: i32 = 0;
    // SAFETY: slave_fd is a live PTY slave fd; slave_n is a valid &mut i32 sink.
    let slave_rc = unsafe { libc::ioctl(slave_fd, libc::TIOCGPTN, &mut slave_n as *mut i32) };
    let slave_errno = std::io::Error::last_os_error().raw_os_error();

    let mut master_n: i32 = -1;
    // SAFETY: master_fd is a live PTY master fd; master_n is a valid &mut i32 sink.
    let master_rc = unsafe { libc::ioctl(master_fd, libc::TIOCGPTN, &mut master_n as *mut i32) };
    let master_errno = std::io::Error::last_os_error().raw_os_error();

    // SAFETY: slave_fd is owned by us; close exactly once.
    unsafe { libc::close(slave_fd) };

    // Master TIOCGPTN must succeed (sanity — every Linux PTY master
    // supports this since 2.6.21).
    if master_rc != 0 {
        return Err(HandlerError::from(format!(
            "ioctl(master, TIOCGPTN) failed: rc={master_rc} errno={master_errno:?}; \
             this is a separate bug, not the TIOCGPTN-on-slave divergence we're probing for"
        )));
    }

    // Slave TIOCGPTN must fail with ENOTTY. Anything else is the bug.
    if slave_rc == 0 {
        return Err(HandlerError::from(format!(
            "ioctl(slave, TIOCGPTN) succeeded (returned slave_n={slave_n}); expected -1/ENOTTY. \
             This is the TIOCGPTN-on-slave divergence: native Linux returns -ENOTTY because \
             TIOCGPTN is only valid on /dev/ptmx, but the litebox shim handler at \
             litebox_shim_linux/src/syscalls/file.rs:7030 returns pty_id() for any PTY entry. \
             master ptn = {master_n}, slave ptn = {slave_n} (they {} match — under the buggy \
             shim, both fds resolve to the same `pty_id`).",
            if slave_n == master_n { "DO" } else { "do NOT" }
        )));
    }

    let want = libc::ENOTTY;
    if slave_errno != Some(want) {
        return Err(HandlerError::from(format!(
            "ioctl(slave, TIOCGPTN) returned -1 with errno={slave_errno:?}, expected ENOTTY({want})"
        )));
    }

    Ok(PtyOut {
        detail: format!(
            "master TIOCGPTN ok (ptn={master_n}); slave TIOCGPTN returned -1/ENOTTY as native does"
        ),
    })
}

/// `openat(AT_FDCWD, "/dev/pts/", O_RDONLY|O_DIRECTORY|O_CLOEXEC)`
/// must succeed (the path is a real devpts mount, the syscall is
/// asking the FS to open it as a directory). Native: succeeds, fd
/// usable with getdents to enumerate ptmx + slave entries. Litebox
/// at amalgamation tip 36973d8a (pre-fix): the shim's
/// `open_broker_pty_path` handler in
/// `litebox_shim_linux/src/syscalls/file.rs:933-936` matches the
/// `/dev/pts/` prefix with an empty remainder, fails to parse the
/// empty string as a u32 pty_id, and returns ENOENT — short-circuiting
/// the rootfs/9P FS that would have served the real directory.
///
/// Real-world impact: GitHub Copilot CLI calls
/// `openat("/dev/pts/", O_DIRECTORY)` immediately after each
/// `ioctl(TIOCGPTN)` returns ENOTTY, as a fallback to enumerate
/// available slaves and find its own. Native succeeds, copilot
/// proceeds. Litebox returns ENOENT, copilot can't find its slave
/// path, TUI rendering stalls — `copilot::tui.*` and
/// `copilot::tui_noLLM.startup_then_exit` trials hang with empty
/// transcripts.
///
/// Surfaced by Goal A validation session 7c1fc95d's second-pass
/// audit-log analysis after the TIOCGPTN-on-slave-returns-ENOTTY fix
/// (commit `7858a614`) made the prior divergence visible.
async fn handle_devpts_dir_openable(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let path = std::ffi::CString::new("/dev/pts/")
        .map_err(|e| HandlerError::from(format!("path NUL: {e}")))?;
    // SAFETY: path is a valid NUL-terminated C string.
    let fd = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(HandlerError::from(format!(
            "openat(AT_FDCWD, \"/dev/pts/\", O_RDONLY|O_DIRECTORY|O_CLOEXEC) failed: {err}. \
             Native should succeed — /dev/pts is a real devpts mount in the container. \
             This is the devpts-directory-openat divergence: the shim's open_broker_pty_path \
             at litebox_shim_linux/src/syscalls/file.rs:933 returns Errno::ENOENT when \
             stripping \"/dev/pts/\" leaves an empty remainder, instead of falling through \
             to the rootfs FS that owns the real directory."
        )));
    }

    // Read a directory entry to prove the fd is usable, not just open.
    // SAFETY: fd is a valid open directory fd.
    let mut buf = [0u8; 1024];
    let n = unsafe {
        libc::syscall(
            libc::SYS_getdents64,
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    let getdents_err = std::io::Error::last_os_error();
    // SAFETY: fd is owned by us; close exactly once.
    unsafe { libc::close(fd) };

    if n < 0 {
        return Err(HandlerError::from(format!(
            "openat succeeded but getdents64 failed: {getdents_err}"
        )));
    }

    Ok(PtyOut {
        detail: format!(
            "openat(\"/dev/pts/\", O_DIRECTORY) ok; getdents64 returned {n} bytes of entries"
        ),
    })
}

/// `readlink("/proc/self/fd/0")` (and fd 1, fd 2) must return the
/// real PTY slave device path (e.g., `"/dev/pts/0"`) when stdio is
/// connected to a PTY slave, NOT a generic placeholder like
/// `"/dev/stdin"` / `"/dev/stdout"` / `"/dev/stderr"`.
///
/// Native: `readlink("/proc/self/fd/2") = "/dev/pts/0"` (10 chars).
/// Litebox at session-7c1fc95d tip (post the TIOCGPTN + devpts-dir
/// fixes): returns `"/dev/stderr"` (11 chars) because the shim's
/// readlink handler at `litebox_shim_linux/src/syscalls/file.rs:4699`
/// falls through to the generic stdio name when the fd is a
/// `BrokerPty` slave (the per-stdio-fd branch at lines 4628-4704
/// has metadata checks for `HostStdioSourceFd`, `HostTtyAlias`, and
/// `HostPtyDeviceFd` but NOT for `BrokerPtySubsystem`, which is what
/// dropbear allocates for SSH sessions).
///
/// Real-world impact: GitHub Copilot CLI (and any program calling
/// `ttyname()`, which uses this readlink as its primary discovery
/// mechanism) needs the PTY slave path to re-open the slave for TUI
/// rendering. Under litebox the readlink returns `/dev/stderr`,
/// copilot cannot find a PTY slave to render through, falls back to
/// scanning `/dev/pts/` (also empty under litebox's rootfs view),
/// gives up, and the TUI never renders → `copilot::tui_noLLM` and
/// `copilot::tui.*` trials hang.
///
/// Surfaced by Goal A validation session 7c1fc95d's third-pass
/// audit-log + native-strace diff after the prior two shim fixes.
async fn handle_readlink_proc_self_fd_stdio_returns_pty_path(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    let pid = pty.fork_exec(
        &[args.target, "pty-readlink-stdio".into()],
        /* ctrl_tty = */ true,
    )?;
    // Child writes three lines: FD0=<path>\nFD1=<path>\nFD2=<path>\nDONE\n
    let data = read_until(&pty, "DONE\r\n")?;
    expect_exit_zero(pid)?;
    let mut fd0: Option<&str> = None;
    let mut fd1: Option<&str> = None;
    let mut fd2: Option<&str> = None;
    for line in data.split("\r\n") {
        if let Some(v) = line.strip_prefix("FD0=") {
            fd0 = Some(v);
        } else if let Some(v) = line.strip_prefix("FD1=") {
            fd1 = Some(v);
        } else if let Some(v) = line.strip_prefix("FD2=") {
            fd2 = Some(v);
        }
    }
    let fd0 = fd0.ok_or_else(|| HandlerError::from(format!("missing FD0= line in {data:?}")))?;
    let fd1 = fd1.ok_or_else(|| HandlerError::from(format!("missing FD1= line in {data:?}")))?;
    let fd2 = fd2.ok_or_else(|| HandlerError::from(format!("missing FD2= line in {data:?}")))?;

    let check = |label: &str, path: &str| -> Result<(), HandlerError> {
        if !path.starts_with("/dev/pts/") {
            return Err(HandlerError::from(format!(
                "readlink(\"/proc/self/{label}\") returned {path:?}; expected a path starting \
                 with \"/dev/pts/\" (the PTY slave device path). Under the buggy shim, the \
                 BrokerPty branch is missing from the stdio (0..=2) readlink path, so the \
                 fallback to a generic \"/dev/std{{in,out,err}}\" path is returned instead. \
                 See litebox_shim_linux/src/syscalls/file.rs:4699 fallback arm."
            )));
        }
        Ok(())
    };
    check("fd/0", fd0)?;
    check("fd/1", fd1)?;
    check("fd/2", fd2)?;

    Ok(PtyOut {
        detail: format!("readlink stdio paths: FD0={fd0:?} FD1={fd1:?} FD2={fd2:?}"),
    })
}

/// Open a PTY pair in the same process, re-open the slave via its
/// path (mimicking the openat("/dev/pts/N") pattern), write to the
/// re-opened fd, and verify the master reads the bytes back. This
/// isolates the broker's dup'd-slave write→master data-path
/// correctness in the simplest (single-process) shape. Both native
/// and litebox should pass.
async fn handle_slave_reopen_write_reaches_master(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    let master_fd = pty.as_raw_fd();
    let slave_path = std::ffi::CString::new(pty.slave_path())
        .map_err(|e| HandlerError::from(format!("slave path NUL: {e}")))?;
    // SAFETY: slave_path is a valid NUL-terminated C string from ptsname.
    let slave_fd = unsafe { libc::open(slave_path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if slave_fd < 0 {
        return Err(HandlerError::from(format!(
            "open({}) failed: {}",
            pty.slave_path(),
            std::io::Error::last_os_error()
        )));
    }
    const MAGIC: &[u8] = b"HELLO_FROM_REOPENED_SLAVE\n";
    // SAFETY: slave_fd is a valid writable PTY slave fd.
    let written =
        unsafe { libc::write(slave_fd, MAGIC.as_ptr() as *const libc::c_void, MAGIC.len()) };
    if written != MAGIC.len() as isize {
        // SAFETY: slave_fd owned by us; close once.
        unsafe { libc::close(slave_fd) };
        return Err(HandlerError::from(format!(
            "write to re-opened slave returned {written}, expected {}",
            MAGIC.len()
        )));
    }
    let mut buf = [0u8; 128];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut total = 0usize;
    while std::time::Instant::now() < deadline && total < MAGIC.len() {
        // SAFETY: master is a live fd; buf is a valid mutable region.
        let n = unsafe {
            libc::read(
                master_fd,
                buf[total..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - total,
            )
        };
        if n > 0 {
            total += n as usize;
        } else if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EAGAIN) {
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            }
            // SAFETY: slave_fd owned by us; close once.
            unsafe { libc::close(slave_fd) };
            return Err(HandlerError::from(format!("read from master failed: {e}")));
        } else {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    // SAFETY: slave_fd owned by us; close once.
    unsafe { libc::close(slave_fd) };
    let got = String::from_utf8_lossy(&buf[..total]).into_owned();
    let expected_lf = String::from_utf8_lossy(MAGIC).into_owned();
    let expected_crlf = expected_lf.replace('\n', "\r\n");
    if got != expected_lf && got != expected_crlf {
        return Err(HandlerError::from(format!(
            "master read {got:?}, expected {expected_lf:?} or {expected_crlf:?}"
        )));
    }
    Ok(PtyOut {
        detail: format!("master read {total} bytes from re-opened slave"),
    })
}

/// Multi-process: parent opens PTY, child has slave as ctrl_tty,
/// child re-opens slave via readlink+openat, writes magic. Parent
/// reads from master.
async fn handle_child_slave_reopen_write_reaches_master(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    let pty = Pty::open()?;
    let pid = pty.fork_exec(
        &[args.target, "pty-child-slave-reopen-write".into()],
        /* ctrl_tty = */ true,
    )?;
    let data = read_until(&pty, "DONE\r\n")?;
    expect_exit_zero(pid)?;
    if !data.contains("MAGIC=PROBE_BYTES_REACHED_MASTER") {
        return Err(HandlerError::from(format!(
            "master did NOT receive magic the child wrote to its re-opened slave fd. \
             transcript: {data:?}"
        )));
    }
    Ok(PtyOut {
        detail: format!("master saw magic bytes via re-opened slave write"),
    })
}

/// `kill(self, SIGTTIN)` with SIG_DFL must NOT terminate the process.
/// Native Linux semantics: default disposition of SIGTTIN is STOP
/// (suspend the process until SIGCONT). It does NOT kill the process.
///
/// Litebox at session-7c1fc95d round-4 tip (pre-fix): the shim's
/// signal-delivery code at
/// `litebox_shim_linux/src/syscalls/signal/mod.rs:1605-1638` treated
/// SignalDisposition::Stop as Terminate ("STOP is not currently
/// supported, so treat as terminate"). Real-world impact: GitHub
/// Copilot CLI's launcher sends SIGTTIN to itself as part of a
/// job-control cleanup pattern; under the buggy shim, this killed
/// the launcher AND any process in the same pgrp (via the cascade
/// that follows when a foreground-pgrp process reads its controlling
/// terminal while backgrounded — kernel default action is to send
/// SIGTTIN to that pgrp).
///
/// Surfaced by Goal A validation session 7c1fc95d round 5 via wait4
/// status diagnostic showing `status_raw=149` (= 128 + 21 = SIGTTIN)
/// on both copilot-linux-x64 and its node child.
async fn handle_sigttin_dfl_does_not_kill(
    args: TargetArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PtyOut, HandlerError> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(&args.target)
        .arg("pty-sigttin-self-kill")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| HandlerError::from(format!("spawn child: {e}")))?;
    let status = child
        .wait()
        .map_err(|e| HandlerError::from(format!("wait child: {e}")))?;
    // Expected: child wrote OK_AFTER_SIGTTIN to stdout and exited 0.
    // Pre-fix: shim killed child with SIGTTIN (status reflects signal
    // termination — not a clean exit code).
    let mut stdout = String::new();
    if let Some(mut o) = child.stdout.take() {
        use std::io::Read as _;
        let _ = o.read_to_string(&mut stdout);
    }
    if !status.success() {
        return Err(HandlerError::from(format!(
            "child did NOT exit 0 after kill(self, SIGTTIN). status={status:?}. \
             This is the SIGTTIN-as-Terminate shim bug: SIG_DFL Stop-disposition \
             signals must be a no-op, not terminate. See \
             litebox_shim_linux/src/syscalls/signal/mod.rs deliver_signal SIG_DFL arm."
        )));
    }
    if !stdout.contains("OK_AFTER_SIGTTIN") {
        return Err(HandlerError::from(format!(
            "child exited 0 but did not print expected marker. stdout={stdout:?}"
        )));
    }
    Ok(PtyOut {
        detail: format!("kill(self, SIGTTIN) with SIG_DFL did not kill the process"),
    })
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
    register_handler!(
        IOCTL_TIOCGPTN_ONLY_ON_MASTER,
        handle_ioctl_tiocgptn_only_on_master
    );
    register_handler!(DEVPTS_DIR_OPENABLE, handle_devpts_dir_openable);
    register_handler!(
        SLAVE_REOPEN_WRITE_REACHES_MASTER,
        handle_slave_reopen_write_reaches_master
    );
    register_handler!(
        CHILD_SLAVE_REOPEN_WRITE_REACHES_MASTER,
        handle_child_slave_reopen_write_reaches_master
    );
    register_handler!(SIGTTIN_DFL_DOES_NOT_KILL, handle_sigttin_dfl_does_not_kill);
    register_handler!(
        READLINK_PROC_SELF_FD_STDIO_RETURNS_PTY_PATH,
        handle_readlink_proc_self_fd_stdio_returns_pty_path
    );
    register_handler!(
        CONTROLLING_TTY_TOSTOP_SIGTTOU,
        handle_controlling_tty_tostop_sigttou
    );
    register_handler!(RESIZE, handle_resize);
    register_handler!(WINSIZE_CROSS_WORKER, handle_winsize_cross_worker);
    register_handler!(SETPGID_CROSS_WORKER, handle_setpgid_cross_worker);
    register_handler!(LDISC_CTRLC_CROSS_WORKER, handle_ldisc_ctrlc_cross_worker);
    register_handler!(LDISC_CTRLZ_CROSS_WORKER, handle_ldisc_ctrlz_cross_worker);
    register_handler!(LDISC_CANON_BASIC, handle_ldisc_canon_basic);
    register_handler!(EXEC_SHELL_SESSION, handle_exec_shell_session);
    register_handler!(PTYR_STDOUT_ROUNDTRIP, handle_ptyr_stdout_roundtrip);
    register_handler!(PTYR_STDOUT_POST_SLEEP, handle_ptyr_stdout_post_sleep);
    register_handler!(
        PTYR_SLAVE_WRITE_ATOMICITY,
        handle_ptyr_slave_write_atomicity
    );
    register_handler!(PTYR_POLL_AFTER_EXIT, handle_ptyr_poll_after_exit);
    register_handler!(PTYR_SLAVE_CLOSE_HUP, handle_ptyr_slave_close_hup);
    register_handler!(PTYR_POLL_LOOP_POST_SLEEP, handle_ptyr_poll_loop_post_sleep);
    register_handler!(PTYR_DROPBEAR_EMUL, handle_ptyr_dropbear_emul);
    register_handler!(
        PTYR_SELECT_LOOP_POST_SLEEP,
        handle_ptyr_select_loop_post_sleep
    );
    register_handler!(
        PTYR_READ_EAGAIN_THEN_WRITE,
        handle_ptyr_read_eagain_then_write
    );
    register_handler!(
        PTYR_POLL_LOOP_POST_SLEEP_WITH_INERTS,
        handle_ptyr_poll_loop_post_sleep_with_inerts
    );
    register_handler!(
        PTYR_WRITE_THEN_EXEC_THEN_WRITE,
        handle_ptyr_write_then_exec_then_write
    );
    register_handler!(PTYR_ISATTY, handle_ptyr_isatty);
    register_handler!(PTYR_STDIO_LOCKSTEP, handle_ptyr_stdio_lockstep);
    register_handler!(PARENT_EXIT_THEN_CHILD_IO, handle_parent_exit_then_child_io);
    register_handler!(TERMIOS_ICANON_ECHO, handle_termios_icanon_echo);
    register_handler!(
        WINSIZE_TIOCSWINSZ_PROPAGATES,
        handle_winsize_tiocswinsz_propagates
    );
    register_handler!(
        SIGWINCH_DELIVERED_ON_RESIZE,
        handle_sigwinch_delivered_on_resize
    );
    register_handler!(
        CONTROLLING_TTY_TIOCSCTTY_SIGTTIN,
        handle_controlling_tty_tiocsctty_sigttin
    );
    register_handler!(LINE_DISCIPLINE_CR_TO_NL, handle_line_discipline_cr_to_nl);

    crate::register_leaf_subcommand!("pty-tiocgpgrp", leaf_subcmd::subcmd_pty_tiocgpgrp);
    crate::register_leaf_subcommand!("pty-tiocspgrp", leaf_subcmd::subcmd_pty_tiocspgrp);
    crate::register_leaf_subcommand!("pty-tiocsctty", leaf_subcmd::subcmd_pty_tiocsctty);
    crate::register_leaf_subcommand!("pty-tostop-sigttou", leaf_subcmd::subcmd_pty_tostop_sigttou);
    crate::register_leaf_subcommand!("pty-resize", leaf_subcmd::subcmd_pty_resize);
    crate::register_leaf_subcommand!(
        "pty-winsize-cross-worker",
        leaf_subcmd::subcmd_pty_winsize_cross_worker
    );
    crate::register_leaf_subcommand!("pty-ldisc-signal", leaf_subcmd::subcmd_pty_ldisc_signal);
    crate::register_leaf_subcommand!("pty-ldisc-canon", leaf_subcmd::subcmd_pty_ldisc_canon);
    crate::register_leaf_subcommand!("pty-stdout-print", leaf_subcmd::subcmd_pty_stdout_print);
    crate::register_leaf_subcommand!("pty-readlink-stdio", leaf_subcmd::subcmd_pty_readlink_stdio);
    crate::register_leaf_subcommand!(
        "pty-child-slave-reopen-write",
        leaf_subcmd::subcmd_pty_child_slave_reopen_write
    );
    crate::register_leaf_subcommand!(
        "pty-sigttin-self-kill",
        leaf_subcmd::subcmd_pty_sigttin_self_kill
    );
    crate::register_leaf_subcommand!(
        "pty-stdout-post-sleep",
        leaf_subcmd::subcmd_pty_stdout_post_sleep
    );
    crate::register_leaf_subcommand!(
        "pty-slave-write-atomicity",
        leaf_subcmd::subcmd_pty_slave_write_atomicity
    );
    crate::register_leaf_subcommand!(
        "pty-slave-close-immediate",
        leaf_subcmd::subcmd_pty_slave_close_immediate
    );
    crate::register_leaf_subcommand!(
        "pty-poll-loop-post-sleep",
        leaf_subcmd::subcmd_pty_poll_loop_post_sleep
    );
    crate::register_leaf_subcommand!(
        "pty-write-then-exec",
        leaf_subcmd::subcmd_pty_write_then_exec
    );
    crate::register_leaf_subcommand!(
        "pty-write-post-exec",
        leaf_subcmd::subcmd_pty_write_post_exec
    );
    crate::register_leaf_subcommand!("pty-isatty-check", leaf_subcmd::subcmd_pty_isatty_check);
    crate::register_leaf_subcommand!("pty-stdio-lockstep", leaf_subcmd::subcmd_pty_stdio_lockstep);
    crate::register_leaf_subcommand!(
        "pty-parent-exit-driver",
        leaf_subcmd::subcmd_pty_parent_exit_driver
    );
    crate::register_leaf_subcommand!(
        "pty-parent-exit-then-child-io",
        leaf_subcmd::subcmd_pty_parent_exit_then_child_io
    );
    crate::register_leaf_subcommand!(
        "pty-termios-icanon-echo",
        leaf_subcmd::subcmd_pty_termios_icanon_echo
    );
    crate::register_leaf_subcommand!(
        "pty-winsize-propagates",
        leaf_subcmd::subcmd_pty_winsize_propagates
    );
    crate::register_leaf_subcommand!(
        "pty-sigwinch-delivered",
        leaf_subcmd::subcmd_pty_sigwinch_delivered
    );
    crate::register_leaf_subcommand!(
        "pty-tiocsctty-sigttin",
        leaf_subcmd::subcmd_pty_tiocsctty_sigttin
    );
    crate::register_leaf_subcommand!(
        "pty-line-discipline-cr-to-nl",
        leaf_subcmd::subcmd_pty_line_discipline_cr_to_nl
    );

    register_pty_semantics_tests(reg);
    register_pty_stdio_lockstep(reg);
    register_parent_exit_then_child_io(reg);
    register_slave_write_after_master_close(reg);
    register_pty_marker_latency_tests(reg);

    // TIOCGPTN-on-slave-must-return-ENOTTY probe. Single-agent
    // because the bug is in the shim's ioctl handler, not in any
    // fork/exec topology — one agent is sufficient and avoids
    // multiplying trial count.
    reg.single_agent_handler_test(
        "vscode",
        "pty",
        "PTY.ioctl.tiocgptn_only_on_master.pie-glibc.dpg1",
        AgentName::Dpg1,
        &IOCTL_TIOCGPTN_ONLY_ON_MASTER,
        |out| Ok(out.detail.clone()),
    );
    reg.single_agent_handler_test(
        "vscode",
        "pty",
        "PTY.devpts.dir_openable.pie-glibc.dpg1",
        AgentName::Dpg1,
        &DEVPTS_DIR_OPENABLE,
        |out| Ok(out.detail.clone()),
    );
    reg.single_agent_handler_test(
        "vscode",
        "pty",
        "PTY.slave_reopen.write_reaches_master.pie-glibc.dpg1",
        AgentName::Dpg1,
        &SLAVE_REOPEN_WRITE_REACHES_MASTER,
        |out| Ok(out.detail.clone()),
    );
    {
        let token = &CHILD_SLAVE_REOPEN_WRITE_REACHES_MASTER;
        reg.test(
            "vscode",
            "pty",
            "PTY.child_slave_reopen.write_reaches_master.pie-glibc.dpg1",
        )
        .timeout(30)
        .build(move |cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let target = crate::binary_path(crate::BinaryType::PieGlibc, run.self_exe());
                    let result = run
                        .send_named_typed(&handle, token, TargetArgs { target })
                        .await;
                    match result {
                        Ok(out) => TestOutcome::new("dpg1", true, out.detail),
                        Err(detail) => TestOutcome::new("dpg1", false, detail),
                    }
                })
            })
        });
    }
    {
        let token = &SIGTTIN_DFL_DOES_NOT_KILL;
        reg.test(
            "vscode",
            "pty",
            "PTY.sigttin_dfl_does_not_kill.pie-glibc.dpg1",
        )
        .timeout(15)
        .build(move |cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let target = crate::binary_path(crate::BinaryType::PieGlibc, run.self_exe());
                    let result = run
                        .send_named_typed(&handle, token, TargetArgs { target })
                        .await;
                    match result {
                        Ok(out) => TestOutcome::new("dpg1", true, out.detail),
                        Err(detail) => TestOutcome::new("dpg1", false, detail),
                    }
                })
            })
        });
    }
    // PTY.readlink.proc_self_fd_stdio_returns_pty_path uses
    // TargetArgs to pass the leaf binary path to the child.
    {
        let token = &READLINK_PROC_SELF_FD_STDIO_RETURNS_PTY_PATH;
        reg.test(
            "vscode",
            "pty",
            "PTY.readlink.proc_self_fd_stdio_returns_pty_path.pie-glibc.dpg1",
        )
        .timeout(30)
        .build(move |cx| {
            let handle = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    let target = crate::binary_path(crate::BinaryType::PieGlibc, run.self_exe());
                    let result = run
                        .send_named_typed(&handle, token, TargetArgs { target })
                        .await;
                    match result {
                        Ok(out) => TestOutcome::new("dpg1", true, out.detail),
                        Err(detail) => TestOutcome::new("dpg1", false, detail),
                    }
                })
            })
        });
    }

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

fn register_pty_stdio_lockstep(reg: &mut Registry<'_>) {
    let agent = AgentName::Dpg1;
    let label = agent.to_string();
    reg.test("vscode", "pty", "PTY.stdio_lockstep.nonpie-glibc.dpg1")
        .timeout(60)
        .build(move |cx| {
            let handle = cx.require(agent);
            let label = label.clone();
            Box::new(move |run| {
                Box::pin(async move {
                    let target = crate::binary_path(crate::BinaryType::NonPieGlibc, run.self_exe());
                    let result = run
                        .send_named_typed(&handle, &PTYR_STDIO_LOCKSTEP, TargetArgs { target })
                        .await;
                    match result {
                        Ok(out) => TestOutcome::new(
                            &label,
                            out.detail == "PTY_STDIO_LOCKSTEP_OK",
                            out.detail,
                        ),
                        Err(detail) => TestOutcome::new(&label, false, detail),
                    }
                })
            })
        });
}

fn register_pty_semantics_tests(reg: &mut Registry<'_>) {
    #[derive(Clone, Copy)]
    struct SemanticsCase {
        id: &'static str,
        token: &'static HandlerToken<TargetArgs, PtyOut>,
    }

    const CASES: &[SemanticsCase] = &[
        SemanticsCase {
            id: "PTY.termios.icanon_echo",
            token: &TERMIOS_ICANON_ECHO,
        },
        SemanticsCase {
            id: "PTY.winsize.tiocswinsz_propagates",
            token: &WINSIZE_TIOCSWINSZ_PROPAGATES,
        },
        SemanticsCase {
            id: "PTY.sigwinch.delivered_on_resize",
            token: &SIGWINCH_DELIVERED_ON_RESIZE,
        },
        SemanticsCase {
            id: "PTY.controlling_tty.tiocsctty_sigttin",
            token: &CONTROLLING_TTY_TIOCSCTTY_SIGTTIN,
        },
        SemanticsCase {
            id: "PTY.line_discipline.cr_to_nl",
            token: &LINE_DISCIPLINE_CR_TO_NL,
        },
    ];

    for &agent in EXEC_AGENTS {
        for case in CASES {
            let test_id = format!("{}.{agent}", case.id);
            let label = agent.to_string();
            let token = case.token;
            reg.test("vscode", "pty", test_id)
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    let label = label.clone();
                    Box::new(move |run| {
                        Box::pin(async move {
                            let target =
                                crate::binary_path(crate::BinaryType::PieGlibc, run.self_exe());
                            let result = run
                                .send_named_typed(&handle, token, TargetArgs { target })
                                .await;
                            match result {
                                Ok(out) => TestOutcome::new(&label, true, out.detail),
                                Err(detail) => TestOutcome::new(&label, false, detail),
                            }
                        })
                    })
                });
        }
    }
}

/// PTYR.slave_write_after_master_close — minimal headless reproducer
/// for the Copilot CLI `tui.find_head` failure documented in
/// `plan.md` (2026-06-01 find_head audit-log diagnosis).
///
/// Shape:
///   1. Open a PTY pair (parent gets master fd via `posix_openpt`).
///   2. Open the slave side independently by path.
///   3. Close the master fd (drop `Pty`).
///   4. `write(2)` on the slave fd MUST fail with `EIO`.
///
/// Real Linux: write returns `-1 / EIO` because the master is closed
/// and the PTY line discipline has nowhere to push the bytes.
///
/// Litebox before the state_service fix: write returns `-1 / EINVAL`
/// because `handle_pty_write` collapsed `PtyError::Closed` into
/// `StatusCode::InvalidValue` (→ `Errno::EINVAL`) instead of a status
/// that maps to `EIO`. Copilot's TUI render loop, hitting EINVAL where
/// it expected EIO/EOF, spun trying to repaint and never produced any
/// visible output, manifesting as a blank screen on `tui.find_head`.
fn register_slave_write_after_master_close(reg: &mut Registry<'_>) {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    reg.test("vscode", "pty", "PTYR.slave_write_after_master_close.dpg1")
        .timeout(15)
        .build(|_cx| {
            Box::new(move |_run| {
                Box::pin(async move {
                    let outcome = (|| -> Result<String, String> {
                        let pty = Pty::open()?;
                        ensure_slave_path(&pty)?;
                        let slave_path = CString::new(pty.slave_path())
                            .map_err(|e| format!("slave_path nul: {e}"))?;
                        // SAFETY: opening /dev/pts/N read/write; we own the
                        // returned fd via OwnedFd.
                        let slave_fd = unsafe {
                            libc::open(slave_path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY)
                        };
                        if slave_fd < 0 {
                            return Err(format!(
                                "open(slave_path={:?}): {}",
                                pty.slave_path(),
                                std::io::Error::last_os_error()
                            ));
                        }
                        // SAFETY: slave_fd was just returned by open and
                        // ownership is transferred to OwnedFd.
                        let slave: OwnedFd = unsafe { OwnedFd::from_raw_fd(slave_fd) };

                        // Sanity check: a write before master close MUST
                        // succeed. This rules out "slave was never writable
                        // in this environment" as a confound.
                        let pre =
                            unsafe { libc::write(slave.as_raw_fd(), b"x".as_ptr().cast(), 1) };
                        if pre != 1 {
                            let e = std::io::Error::last_os_error();
                            return Err(format!("pre-close write(slave) rc={pre} errno={e}"));
                        }

                        // Drop master — triggers broker-side PtyState::drop
                        // for the master endpoint and flips
                        // `master_open_count` to 0.
                        drop(pty);

                        // The shim-side release is synchronous from the
                        // worker's POV (release_state RPC), but we still
                        // give a small grace to absorb any
                        // notification-ring lag before the slave's next
                        // syscall observes the state change.
                        std::thread::sleep(std::time::Duration::from_millis(50));

                        // Post-close write: MUST be EIO.
                        let rc = unsafe { libc::write(slave.as_raw_fd(), b"y".as_ptr().cast(), 1) };
                        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                        if rc >= 0 {
                            return Err(format!(
                                "write(slave) after master close returned rc={rc}; \
                             expected -1/EIO"
                            ));
                        }
                        if errno != libc::EIO {
                            return Err(format!(
                                "write(slave) after master close: errno={errno} \
                             ({}), expected EIO ({})",
                                errno_name(errno),
                                libc::EIO,
                            ));
                        }

                        // Read of slave with master closed must return 0
                        // (EOF), matching Linux PTY semantics. This is a
                        // cheap second invariant that protects the
                        // already-correct read path.
                        let mut buf = [0u8; 16];
                        let r = unsafe {
                            libc::read(slave.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len())
                        };
                        if r != 0 {
                            let e = std::io::Error::last_os_error();
                            return Err(format!(
                                "read(slave) after master close rc={r} errno={e}; \
                             expected 0 (EOF)"
                            ));
                        }

                        Ok("write→EIO; read→0 (EOF)".to_string())
                    })();
                    match outcome {
                        Ok(detail) => TestOutcome::new("dpg1", true, detail),
                        Err(detail) => TestOutcome::new("dpg1", false, detail),
                    }
                })
            })
        });
}

fn errno_name(e: i32) -> &'static str {
    match e {
        libc::EIO => "EIO",
        libc::EINVAL => "EINVAL",
        libc::EBADF => "EBADF",
        libc::EAGAIN => "EAGAIN/EWOULDBLOCK",
        libc::EPIPE => "EPIPE",
        libc::ENOTTY => "ENOTTY",
        libc::EPERM => "EPERM",
        _ => "other",
    }
}

/// PTYM.* — PTY marker-based command-completion-detection latency.
///
/// Reproduces the substrate divergence isolated by session
/// `wave3-copilot-ctx-window` (see `docs/copilot-pty-marker-divergence.md`
/// on the wave3 branch): GitHub Copilot CLI's persistent `node-pty`
/// bash session uses the marker pattern
///
/// ```text
/// write to PTY master:
///     <command>\n
///     echo ___DONE_MARKER_<exitcode>___\n
/// read PTY master until "___DONE_MARKER_" substring appears
/// ```
///
/// to know when each command finishes. Under copilot's wrapping,
/// commands that complete in 30–900 ms when invoked directly (no PTY,
/// no persistent session) routinely hang past `initial_wait=30 s` on
/// litebox. The copilot stack adds many layers (Docker → dropbear →
/// SSH → node-pty → bash); this family strips all of them away and
/// keeps only PTY + interactive bash + marker detection so the
/// divergence — if it's in those primitives — is bisectable.
///
/// # Diagnosed root cause (session `wportnoy/pty-marker-latency`)
///
/// **Under litebox, both `bash_interactive` and `bash_noediting`
/// hang at the SETUP HANDSHAKE — bash never executes the first
/// command.** This is a more fundamental failure than the original
/// "marker arrives late" hypothesis, and it explains why copilot's
/// marker DONE never appeared: bash never ran the command at all.
///
/// Audit-log analysis (`litebox_audit_query sql ... FROM syscalls
/// WHERE exit_ts IS NULL`) shows the failure pattern is a deadlock
/// between:
///
///   * The shim's syscall rewriter, which turns bash's `fork()`
///     (`clone(SIGCHLD)`) into `clone(CLONE_VM | CLONE_VFORK)` —
///     see `litebox_shim_linux/src/syscalls/process.rs:2586-2589`
///     (`"every fork appears as vfork because the syscall rewriter
///     adds CLONE_VM | CLONE_VFORK"`).
///   * Bash's `PGRP_PIPE` job-control pre-exec synchronization
///     (bash `jobs.c:2261-2264`): immediately after `fork()` the
///     child closes the pipe's write end and `read(pp[0], &ch, 1)`
///     to block until the parent has finished setting up
///     `pipeline_pgrp` for every child. The parent later writes
///     one byte to `pgrp_pipe[1]` to release the child.
///
/// Sequence captured in audit log:
///   `seq=12221  pid=2 (bash)   pipe2(0)            → fd 3/4`
///   `seq=12222  pid=2 (bash)   clone(0x4100=VFORK|VM)  ← never returns`
///   `seq=12223  pid=3 (child)  getpid, sigaction, setpgid(3,3),`
///   `             ioctl(255, TIOCSPGRP), close(3)`
///   `seq=12233  pid=3 (child)  read(fd=4, 1)       ← never returns`
///
/// The parent is suspended in `VforkDone::is_done()`
/// (`process.rs:3122-3137`) waiting for the child to `execve`
/// or `exit`. The child is suspended in
/// `pipe_read(pgrp_pipe)` waiting for the parent to write.
/// Neither can make progress.
///
/// Why the existing `delayed-fork-commit` mechanism doesn't break
/// the deadlock: `is_pre_exec_syscall_impl`
/// (`litebox_shim_linux/src/lib.rs:3860-3942`) keeps `Sysno::read`
/// in the pre-exec allowlist (it's required for nested
/// `$(cmd)`). The `unix_socket_read` short-circuit at
/// `lib.rs:3846-3873` forces a delayed-fork commit on blocking
/// reads from Unix-domain sockets, but bash's `pgrp_pipe` is an
/// ordinary `pipe2(2)`, so the short-circuit doesn't trigger.
/// The child therefore stays parked on the vfork path, and the
/// parent stays blocked in `wait_until(vd.is_done())`.
///
/// Bash uses `pgrp_pipe` only when **job control is enabled**, which
/// is the default for interactive shells. Both `bash_interactive`
/// and `bash_noediting` are interactive (no `-c`), so both trip
/// the deadlock. A hypothetical `bash -c "<setup>"` variant would
/// pass under litebox (no job control, no `pgrp_pipe`) — confirming
/// the bug is in the interaction between vfork rewrite and
/// `pgrp_pipe`, not in the PTY layer itself.
///
/// Fix proposal (NOT implemented in this session — owned by parent):
/// extend the `is_pre_exec_syscall_for_task` deadlock-detection to
/// commit the delayed fork on blocking reads from pipes whose
/// write end is held by the (suspended) parent. The narrowest
/// change is in `litebox_shim_linux/src/lib.rs:3846-3873`: add a
/// `pipe_read_would_block` predicate alongside `unix_socket_read`.
///
/// # Test design
///
/// Two scenarios per family member:
///
///  - `echo_marker` — control: send `echo MARKER`. Must complete in
///    a small fixed budget on both native and litebox. If this fails
///    the test fixture itself is broken.
///  - `find_root_home` — workload: send
///    `find /root /home -type f 2>/dev/null | head -5`. The prior
///    probe measured this at ~30 ms native direct, ~907 ms litebox
///    direct, ~5.9 s litebox-through-`script`-PTY, and >30 s in
///    copilot's persistent PTY session.
///
/// Two invocations per scenario:
///
///  - `bash_interactive` — `/bin/bash --noprofile --norc`
///  - `bash_noediting`   — `/bin/bash --noprofile --norc --noediting`
///
/// Both scenarios reuse the SAME persistent bash session for two
/// successive commands (`first`/`second`), to surface any per-session
/// state-accrual effect (e.g., output-buffer growth, scrollback,
/// signal-mask churn) that copilot's persistent-shell wrapper relies
/// on but a one-shot `Pty::open(); fork; exec(bash -c ...)` test
/// would miss.
///
/// Failure mode is `handshake: timed out after Ns waiting for "..."`
/// when the deadlock fires (current litebox behaviour) and
/// `{first,second}: elapsed=Nms over budget=Bms` when bash runs but
/// the marker is slow (the originally-hypothesised mode — not
/// reachable in litebox until the deadlock is fixed). The captured
/// tail bytes go into the detail string so the next investigator can
/// see exactly what bash echoed before the deadlock fired.
fn register_pty_marker_latency_tests(reg: &mut Registry<'_>) {
    // Scenarios are the cross product of:
    //   - {echo_marker, find_root_home}   — control vs. workload
    //   - {bash_interactive, bash_noediting}
    //                                     — bash invocation mode
    //
    // Budget rationale:
    //   - `echo_marker`: 500 ms — bash writes one line, no fork; on
    //     either substrate this should be tens of ms. 500 ms picks up
    //     a 10x regression but tolerates load on shared CI hosts.
    //   - `find_root_home`: 3000 ms — direct litebox measured 907 ms
    //     for this exact pipeline (prior probe). Under PTY-wrapped
    //     `script -qc` it ballooned to 5941 ms. 3000 ms separates the
    //     "direct-litebox" baseline (passing) from the "PTY-amplified"
    //     failure mode (failing). Native consistently sub-100 ms.
    //
    // Invocation rationale:
    //   - `bash_interactive`: `/bin/bash --noprofile --norc` — bash
    //     enters interactive mode because isatty(stdin) is true. Uses
    //     readline for input editing (bracketed paste, line redraw).
    //     This is the EXACT pattern copilot CLI uses (node-pty spawns
    //     `/bin/bash` with no flags; the PTY makes it interactive).
    //   - `bash_noediting`: `/bin/bash --noprofile --norc --noediting`
    //     — interactive bash WITHOUT readline. Reads input via simple
    //     getc in canonical mode. Splits the variable space: if
    //     `_interactive` fails and `_noediting` passes, the bug is in
    //     readline's interaction with litebox PTY (likely a SIGWINCH,
    //     terminal-control-sequence, or input-decoding path). If both
    //     fail with the same shape, the bug is in master→slave input
    //     delivery itself.
    struct Scenario {
        cmd_suffix: &'static str,
        cmd: &'static str,
        budget_ms: u128,
    }
    const SCENARIOS: &[Scenario] = &[
        Scenario {
            cmd_suffix: "echo_marker",
            cmd: "echo hello-from-marker-probe",
            budget_ms: 500,
        },
        Scenario {
            cmd_suffix: "find_root_home",
            cmd: "find /root /home -type f 2>/dev/null | head -5",
            budget_ms: 3000,
        },
    ];

    struct Invocation {
        suffix: &'static str,
        argv: &'static [&'static str],
    }
    const INVOCATIONS: &[Invocation] = &[
        Invocation {
            suffix: "bash_interactive",
            argv: &["/bin/bash", "--noprofile", "--norc"],
        },
        Invocation {
            suffix: "bash_noediting",
            // `--noediting` disables readline entirely; bash reads via
            // simple read(2) in canonical mode. Same interactive
            // command-loop, but without the terminal-control noise
            // readline emits. The litebox-vs-native delta isolates
            // readline as a cause vs. effect of the divergence.
            argv: &["/bin/bash", "--noprofile", "--norc", "--noediting"],
        },
    ];

    for sc in SCENARIOS {
        for inv in INVOCATIONS {
            let test_id = format!("PTYM.{}.{}.dpg1", sc.cmd_suffix, inv.suffix);
            let cmd: &'static str = sc.cmd;
            let budget_ms: u128 = sc.budget_ms;
            let argv: &'static [&'static str] = inv.argv;
            reg.test("vscode", "pty", test_id)
                .timeout(60)
                .build(move |_cx| {
                    Box::new(move |_run| {
                        Box::pin(async move {
                            let outcome = run_pty_marker_scenario(argv, cmd, budget_ms);
                            match outcome {
                                Ok(detail) => TestOutcome::new("dpg1", true, detail),
                                Err(detail) => TestOutcome::new("dpg1", false, detail),
                            }
                        })
                    })
                });
        }
    }
}

/// Drives one PTYM scenario:
///   1. open PTY pair, fork `/bin/bash --noprofile --norc` on slave;
///   2. send a setup line that defines a bash variable
///      `__MK='___PTYM_MARKER___'`, then disables echo + prompt,
///      then prints `${__MK}READY` — read until that constructed
///      string appears, proving bash is past startup AND echo is off
///      AND the constructed marker is detectable;
///   3. send `<cmd>; echo "${__MK}DONE_$?"` and measure wall time
///      from the write to the appearance of `___PTYM_MARKER___DONE_`
///      on master;
///   4. repeat step 3 with the same persistent bash (`second`
///      round) — this exposes per-session state-accrual effects
///      copilot's wrapper relies on;
///   5. tear down (write `exit\n`, reap).
///
/// Why the marker is constructed in-process rather than written
/// verbatim: bash's PTY local echo (enabled by default until
/// `stty -echo` takes effect) replays the typed command line back
/// to the master before bash executes it. A literal marker string
/// in the command line would appear in the echoed input AND in
/// the command's output, and a naive `contains` check would match
/// the echoed-input copy and report success before bash had
/// actually run anything. By splitting the marker across two
/// concatenated bash fragments (`"${__MK}"DONE_`), the joined
/// string `___PTYM_MARKER___DONE_` only ever exists in bash's
/// stdout, never in the typed input. See `pty_marker_round` for
/// the exact construction.
///
/// Returns Ok(detail) with measured timings, or Err(detail) if any
/// individual round overran `budget_ms`, the marker never appeared,
/// or the captured output didn't contain the expected substring.
fn run_pty_marker_scenario(
    bash_argv: &[&str],
    cmd: &'static str,
    budget_ms: u128,
) -> Result<String, String> {
    let pty = Pty::open()?;
    ensure_slave_path(&pty)?;
    let owned_argv: Vec<String> = bash_argv.iter().map(|s| (*s).to_string()).collect();
    let pid = pty.fork_exec(&owned_argv, true)?;
    let mut bash_alive = true;

    let result = (|| -> Result<String, String> {
        // Step 1: ready handshake. Define the marker variable, turn
        // off echo + prompt, emit the constructed `<MK>READY` token
        // and wait for it. `<MK>READY` cannot appear in any echoed
        // input — only in stdout — so the wait is unambiguous.
        //
        // 30 s handshake budget is intentionally large: under the
        // copilot persistent-PTY repro the bash setup line itself
        // takes >30 s to be echoed back, and the natural failure
        // mode is "marker never appears." A short budget would
        // confound "bash never executed the setup" with "bash is
        // slow" — we want the former to be observable as a clean
        // FAIL with the full captured buffer in the detail string.
        let setup_line = "__MK='___PTYM_MARKER___'; stty -echo; PS1=''; echo \"${__MK}READY\"\n";
        pty.write_all(setup_line.as_bytes())?;
        read_until_with_timeout(&pty, "___PTYM_MARKER___READY", Duration::from_secs(30))
            .map_err(|e| format!("handshake: {e}"))?;

        // Step 2 + 3: timed round-trip, twice on the same bash.
        let first = pty_marker_round(&pty, "first", cmd, budget_ms)?;
        let second = pty_marker_round(&pty, "second", cmd, budget_ms)?;

        Ok(format!("first={first} second={second}"))
    })();

    // Tear down: ask bash to exit cleanly, then reap. Best-effort —
    // a measurement failure shouldn't be masked by a teardown error.
    let _ = pty.write_all(b"exit\n");
    let reaped = wait_child_timeout(pid, Duration::from_secs(5));
    if reaped.is_ok() {
        bash_alive = false;
    }
    if bash_alive {
        // SAFETY: pid was returned by fork in this process; SIGKILL+reap is safe.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(pid, &raw mut status, 0);
        }
    }

    result
}

/// One round of "write command + marker; read until marker" with a
/// per-round budget. Returns a string like `cmd_ok elapsed=42ms` on
/// success or an error detail with the actual measurement on
/// failure.
fn pty_marker_round(pty: &Pty, label: &str, cmd: &str, budget_ms: u128) -> Result<String, String> {
    // `<cmd>; echo "${__MK}DONE_<label>_$?"` — the joined string
    // `___PTYM_MARKER___DONE_<label>_<exit>` only exists in the
    // command's stdout, never in the typed input that bash echoes.
    // The `<label>` keeps the first and second rounds distinguishable
    // even if both ran the same command.
    let done_search = format!("___PTYM_MARKER___DONE_{label}_");
    let line = format!("{cmd}; echo \"${{__MK}}DONE_{label}_$?\"\n");

    let start = std::time::Instant::now();
    pty.write_all(line.as_bytes())?;
    let captured = read_until_with_timeout(
        pty,
        &done_search,
        Duration::from_millis(u64::try_from(budget_ms.saturating_mul(2)).unwrap_or(u64::MAX)),
    )?;
    let elapsed_ms = start.elapsed().as_millis();

    if elapsed_ms > budget_ms {
        return Err(format!(
            "{label}: elapsed={elapsed_ms}ms over budget={budget_ms}ms; cmd={cmd:?}; \
             captured_bytes={}; tail={:?}",
            captured.len(),
            // Tail is the last 200 chars — enough to see the marker
            // line plus a few of the command's output lines without
            // dumping kilobytes into the test report.
            tail_chars(&captured, 200),
        ));
    }

    Ok(format!(
        "ok elapsed={elapsed_ms}ms bytes={}",
        captured.len()
    ))
}

/// Drain the PTY master incrementally until `marker` appears or
/// `timeout` expires. Uses non-blocking `poll`+`try_read_now` for
/// efficient byte arrival, unlike the blocking `read_until` helper
/// (which reads byte-by-byte and hard-codes a 10 s deadline).
///
/// This shape matters for the PTYM measurement: we need
/// millisecond-resolution timing to distinguish a fast successful
/// round (~30 ms) from the budget-overrun failure mode (>500 ms or
/// >3000 ms depending on scenario). A byte-per-syscall reader would
/// itself consume measurement headroom on multi-KB outputs like
/// `find /root /home`.
fn read_until_with_timeout(pty: &Pty, marker: &str, timeout: Duration) -> Result<String, String> {
    let deadline = std::time::Instant::now() + timeout;
    let mut data = String::new();
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(format!(
                "timed out after {:?} waiting for {marker:?}; got {} bytes; tail={:?}",
                timeout,
                data.len(),
                tail_chars(&data, 200),
            ));
        }
        let remaining = deadline - now;
        let timeout_ms = i32::try_from(remaining.as_millis().min(1_000)).unwrap_or(1_000);
        let revents = pty.poll_now_timeout(libc::POLLIN | libc::POLLHUP, timeout_ms)?;
        if revents & libc::POLLIN != 0 {
            // Drain everything currently available without re-polling
            // between reads. Each `try_read_now` is a single
            // non-blocking `read(2)`; loop until EAGAIN.
            loop {
                let Some(bytes) = pty.try_read_now(4096)? else {
                    break;
                };
                if bytes.is_empty() {
                    // EOF on the master — bash exited unexpectedly.
                    return Err(format!(
                        "PTY read returned EOF before marker {marker:?}; got {} bytes; tail={:?}",
                        data.len(),
                        tail_chars(&data, 200),
                    ));
                }
                data.push_str(&String::from_utf8_lossy(&bytes));
                if data.contains(marker) {
                    return Ok(data);
                }
            }
        }
        if revents & libc::POLLHUP != 0 && !data.contains(marker) {
            // HUP without POLLIN: bash closed slave without flushing
            // marker. Drain once more in case data was queued, then
            // fail.
            while let Some(bytes) = pty.try_read_now(4096)? {
                if bytes.is_empty() {
                    break;
                }
                data.push_str(&String::from_utf8_lossy(&bytes));
                if data.contains(marker) {
                    return Ok(data);
                }
            }
            return Err(format!(
                "PTY POLLHUP before marker {marker:?}; got {} bytes; tail={:?}",
                data.len(),
                tail_chars(&data, 200),
            ));
        }
    }
}

fn tail_chars(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let start = s.char_indices().nth_back(n - 1).map_or(0, |(i, _)| i);
        s[start..].to_string()
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
        ScenarioKind::ControllingTtyTostopSigttou => {
            run.send_named_typed(handle, &CONTROLLING_TTY_TOSTOP_SIGTTOU, args)
                .await?
        }
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
        ScenarioKind::SlaveWriteAtomicity => {
            run.send_named_typed(handle, &PTYR_SLAVE_WRITE_ATOMICITY, args)
                .await?
        }
        ScenarioKind::PollAfterExit => {
            run.send_named_typed(handle, &PTYR_POLL_AFTER_EXIT, args)
                .await?
        }
        ScenarioKind::SlaveCloseHup => {
            run.send_named_typed(handle, &PTYR_SLAVE_CLOSE_HUP, args)
                .await?
        }
        ScenarioKind::PollLoopPostSleep => {
            run.send_named_typed(handle, &PTYR_POLL_LOOP_POST_SLEEP, args)
                .await?
        }
        ScenarioKind::DropbearEmul => {
            run.send_named_typed(handle, &PTYR_DROPBEAR_EMUL, args)
                .await?
        }
        ScenarioKind::SelectLoopPostSleep => {
            run.send_named_typed(handle, &PTYR_SELECT_LOOP_POST_SLEEP, args)
                .await?
        }
        ScenarioKind::ReadEagainThenWrite => {
            run.send_named_typed(handle, &PTYR_READ_EAGAIN_THEN_WRITE, args)
                .await?
        }
        ScenarioKind::PollLoopPostSleepWithInerts => {
            run.send_named_typed(handle, &PTYR_POLL_LOOP_POST_SLEEP_WITH_INERTS, args)
                .await?
        }
        ScenarioKind::WriteThenExecThenWrite => {
            run.send_named_typed(handle, &PTYR_WRITE_THEN_EXEC_THEN_WRITE, args)
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

fn wait_child_or_stopped_timeout(pid: libc::pid_t, timeout: Duration) -> Result<i32, String> {
    let deadline = std::time::Instant::now() + timeout;
    let mut status = 0;
    loop {
        // SAFETY: waiting for a child pid returned by fork in this process.
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::WUNTRACED) };
        if rc == pid {
            if libc::WIFEXITED(status) {
                return Ok(libc::WEXITSTATUS(status));
            }
            if libc::WIFSIGNALED(status) {
                return Ok(128 + libc::WTERMSIG(status));
            }
            if libc::WIFSTOPPED(status) {
                let sig = libc::WSTOPSIG(status);
                // SAFETY: terminate and reap a stopped child before reporting the failure.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, &mut status, 0);
                }
                return Err(format!("child {pid} stopped by signal {sig}"));
            }
            return Ok(-1);
        }
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(format!("waitpid {pid}: {err}"));
            }
        }
        if std::time::Instant::now() >= deadline {
            // SAFETY: terminate and reap the child after timeout.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &mut status, 0);
            }
            return Err(format!(
                "child {pid} timed out after {}s",
                timeout.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
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
    use std::io::{Read as _, Write as _};

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

    /// PTY.readlink.proc_self_fd_stdio_returns_pty_path: report
    /// readlink results for /proc/self/fd/{0,1,2} when stdio is wired
    /// to a PTY slave. Child runs under `Pty::fork_exec(ctrl_tty=true)`,
    /// so all three stdio fds ARE the slave fd. Native must produce
    /// `/dev/pts/N` paths; the litebox shim's bug under investigation
    /// returns `/dev/std{in,out,err}` placeholders instead because the
    /// stdio readlink branch lacks a BrokerPtySubsystem arm.
    pub(super) fn subcmd_pty_readlink_stdio(_args: &[String]) -> i32 {
        for fd in [0, 1, 2] {
            let path = format!("/proc/self/fd/{fd}");
            match std::fs::read_link(&path) {
                Ok(target) => {
                    println!("FD{fd}={}", target.display());
                }
                Err(e) => {
                    println!("FD{fd}=ERR:{e}");
                }
            }
        }
        println!("DONE");
        let _ = std::io::stdout().flush();
        0
    }

    /// PTY.child_slave_reopen.write_reaches_master: child's stdio
    /// IS a PTY slave (ctrl_tty=true). Re-open the slave via
    /// readlink("/proc/self/fd/0") + openat(path), write a magic
    /// string to the re-opened fd, and write the DONE marker via
    /// the inherited slave (stdio).
    pub(super) fn subcmd_pty_child_slave_reopen_write(_args: &[String]) -> i32 {
        let slave_path = match std::fs::read_link("/proc/self/fd/0") {
            Ok(p) => p,
            Err(e) => {
                println!("REOPENED_PATH=ERR:{e}");
                println!("DONE");
                let _ = std::io::stdout().flush();
                return 1;
            }
        };
        println!("REOPENED_PATH={}", slave_path.display());
        let _ = std::io::stdout().flush();
        let cpath = match std::ffi::CString::new(slave_path.to_string_lossy().as_bytes()) {
            Ok(p) => p,
            Err(e) => {
                println!("OPEN_ERR=NUL:{e}");
                println!("DONE");
                let _ = std::io::stdout().flush();
                return 1;
            }
        };
        // SAFETY: cpath is a valid NUL-terminated C string.
        let reopened = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        if reopened < 0 {
            let e = std::io::Error::last_os_error();
            println!("OPEN_ERR={e}");
            println!("DONE");
            let _ = std::io::stdout().flush();
            return 1;
        }
        const MAGIC: &[u8] = b"MAGIC=PROBE_BYTES_REACHED_MASTER\n";
        // SAFETY: reopened is a valid writable fd we just opened.
        let _ =
            unsafe { libc::write(reopened, MAGIC.as_ptr() as *const libc::c_void, MAGIC.len()) };
        // SAFETY: reopened owned by us; close once.
        unsafe { libc::close(reopened) };
        println!("DONE");
        let _ = std::io::stdout().flush();
        0
    }

    /// PTY.sigttin_dfl_does_not_kill: send SIGTTIN to self with
    /// SIG_DFL. Native semantics: default action is STOP, not
    /// terminate. Pre-fix litebox shim treated SIG_DFL Stop as
    /// terminate; this probe FAILs there. Post-fix (Stop = no-op),
    /// child prints OK and exits 0.
    pub(super) fn subcmd_pty_sigttin_self_kill(_args: &[String]) -> i32 {
        // Explicitly set SIGTTIN to SIG_DFL so probe targets the
        // shim's SIG_DFL Stop-disposition handling.
        // SAFETY: signal() is a libc API; SIG_DFL is the canonical
        // default handler.
        unsafe {
            let prev = libc::signal(libc::SIGTTIN, libc::SIG_DFL);
            if prev == libc::SIG_ERR {
                println!("SIGNAL_ERR");
                let _ = std::io::stdout().flush();
                return 2;
            }
        }
        let pid = std::process::id() as libc::pid_t;
        // SAFETY: sending a signal to our own pid.
        let rc = unsafe { libc::kill(pid, libc::SIGTTIN) };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            println!("KILL_ERR:{e}");
            let _ = std::io::stdout().flush();
            return 3;
        }
        // If we reach here, the process was NOT killed by SIGTTIN.
        println!("OK_AFTER_SIGTTIN pid={pid}");
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

    /// PTYR.slave_write_atomicity: write one short marker line and
    /// exit immediately. Parent waits for child exit, then does a
    /// SINGLE non-blocking read on master. The marker MUST be
    /// readable without any poll/wait — that's the kernel-PTY
    /// guarantee dropbear's session loop depends on.
    pub(super) fn subcmd_pty_slave_write_atomicity(_args: &[String]) -> i32 {
        let mut stdout = std::io::stdout();
        if writeln!(stdout, "WRITE_ATOMIC_OK").is_err() {
            return 1;
        }
        if stdout.flush().is_err() {
            return 1;
        }
        0
    }

    /// PTYR.slave_close_immediate: write nothing and exit. Parent
    /// verifies POLLHUP is set immediately on master.
    pub(super) fn subcmd_pty_slave_close_immediate(_args: &[String]) -> i32 {
        0
    }

    /// PTYR.poll_loop_post_sleep: spawn `/bin/sh -c` running the
    /// exact bash workload that breaks under dropbear (echo, echo,
    /// sleep external, echo, echo, echo, exit). Captures the case
    /// where the slave-side process tree forks an external program
    /// during the quiet period and resumes writes afterwards.
    pub(super) fn subcmd_pty_poll_loop_post_sleep(_args: &[String]) -> i32 {
        use std::process::Command;
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg("echo L01; echo L02; sleep 1; echo L03; echo L04; echo L05")
            .status();
        match status {
            Ok(s) if s.success() => 0,
            _ => 1,
        }
    }

    /// PTYR.write_then_exec leaf — writes "PRE\n" to stdout, then
    /// execve's `argv[2]` (the target binary) with subcmd
    /// `pty-write-post-exec`. The slave PTY fd is fd 1 and CLOEXEC
    /// is clear; the post-exec leaf inherits it and writes "POST\n".
    pub(super) fn subcmd_pty_write_then_exec(args: &[String]) -> i32 {
        use std::io::Write;
        let target = match args.get(2) {
            Some(t) => t.as_str(),
            None => return 2,
        };
        let mut stdout = std::io::stdout();
        if writeln!(stdout, "PRE").is_err() || stdout.flush().is_err() {
            return 1;
        }
        let target_c = match std::ffi::CString::new(target) {
            Ok(c) => c,
            Err(_) => return 2,
        };
        let leaf = std::ffi::CString::new("pty-write-post-exec").expect("static leaf name");
        let argv = [target_c.as_ptr(), leaf.as_ptr(), std::ptr::null()];
        // SAFETY: execv replaces this process; on success no return;
        // on error returns -1. We return 127 on error (standard
        // exec-failure convention).
        unsafe {
            libc::execv(target_c.as_ptr(), argv.as_ptr());
        }
        127
    }

    /// PTYR.write_post_exec leaf — counterpart to write_then_exec.
    /// Writes "POST\n" and exits.
    pub(super) fn subcmd_pty_write_post_exec(_args: &[String]) -> i32 {
        use std::io::Write;
        let mut stdout = std::io::stdout();
        if writeln!(stdout, "POST").is_err() || stdout.flush().is_err() {
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

    pub(super) fn subcmd_pty_stdio_lockstep(_args: &[String]) -> i32 {
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return 1;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        println!("PTY_STDOUT_LOCKSTEP:{line}");
        eprintln!("PTY_STDERR_LOCKSTEP");
        let stdout_ok = std::io::stdout().flush().is_ok();
        let stderr_ok = std::io::stderr().flush().is_ok();
        i32::from(!stdout_ok || !stderr_ok)
    }

    pub(super) fn subcmd_pty_termios_icanon_echo(_args: &[String]) -> i32 {
        if set_stdin_termios(|termios| {
            termios.c_lflag |= libc::ICANON | libc::ECHO;
            termios.c_iflag |= libc::ICRNL;
        })
        .is_err()
        {
            return 1;
        }
        println!("READY");
        let _ = std::io::stdout().flush();

        let mut line1 = String::new();
        if std::io::stdin().read_line(&mut line1).is_err() {
            return 1;
        }
        println!("LINE1={}", line1.trim_end_matches(['\r', '\n']));
        if set_stdin_termios(|termios| {
            termios.c_lflag |= libc::ICANON;
            termios.c_lflag &= !libc::ECHO;
            termios.c_iflag |= libc::ICRNL;
        })
        .is_err()
        {
            return 1;
        }
        println!("ECHO_OFF_READY");
        let _ = std::io::stdout().flush();

        let mut line2 = String::new();
        if std::io::stdin().read_line(&mut line2).is_err() {
            return 1;
        }
        println!("LINE2={}", line2.trim_end_matches(['\r', '\n']));
        let _ = std::io::stdout().flush();
        0
    }

    pub(super) fn subcmd_pty_winsize_propagates(_args: &[String]) -> i32 {
        if set_stdin_termios(|termios| termios.c_lflag &= !libc::ECHO).is_err() {
            return 1;
        }
        println!("READY");
        let _ = std::io::stdout().flush();
        let mut byte = [0u8; 1];
        if std::io::stdin().read_exact(&mut byte).is_err() {
            return 1;
        }
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: TIOCGWINSZ writes winsize to the provided pointer for fd 0.
        if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } != 0 {
            eprintln!("TIOCGWINSZ failed: {}", std::io::Error::last_os_error());
            return 1;
        }
        println!("WINSIZE rows={} cols={}", ws.ws_row, ws.ws_col);
        let _ = std::io::stdout().flush();
        0
    }

    pub(super) fn subcmd_pty_sigwinch_delivered(_args: &[String]) -> i32 {
        PTY_LDISC_SIGNAL_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: installing a simple one-argument handler for SIGWINCH.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = pty_ldisc_signal_handler as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = 0;
            if libc::sigaction(libc::SIGWINCH, &action, std::ptr::null_mut()) != 0 {
                eprintln!(
                    "sigaction SIGWINCH failed: {}",
                    std::io::Error::last_os_error()
                );
                return 1;
            }
        }
        println!("READY");
        let _ = std::io::stdout().flush();
        for _ in 0..200 {
            if PTY_LDISC_SIGNAL_COUNT.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                break;
            }
            // SAFETY: usleep only blocks the current process briefly while waiting for SIGWINCH.
            unsafe { libc::usleep(10_000) };
        }
        let count = PTY_LDISC_SIGNAL_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: TIOCGWINSZ writes winsize to the provided pointer for fd 0.
        if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } != 0 {
            return 1;
        }
        println!(
            "SIGWINCH count={count} rows={} cols={}",
            ws.ws_row, ws.ws_col
        );
        let _ = std::io::stdout().flush();
        if count == 1 { 0 } else { 1 }
    }

    pub(super) fn subcmd_pty_tostop_sigttou(_args: &[String]) -> i32 {
        // SAFETY: getpgrp has no preconditions.
        let mut fg = unsafe { libc::getpgrp() };
        // SAFETY: TIOCSPGRP reads a pid_t from the provided pointer for fd 1.
        if unsafe { libc::ioctl(1, libc::TIOCSPGRP, &mut fg) } != 0 {
            eprintln!(
                "initial TIOCSPGRP failed: {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        // SAFETY: zeroed is a valid starting representation for termios before tcgetattr fills it.
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: tcgetattr writes termios for the controlling tty fd 1.
        if unsafe { libc::tcgetattr(1, &mut termios) } != 0 {
            eprintln!("tcgetattr failed: {}", std::io::Error::last_os_error());
            return 1;
        }
        termios.c_lflag |= libc::TOSTOP;
        // SAFETY: tcsetattr reads a valid termios for fd 1.
        if unsafe { libc::tcsetattr(1, libc::TCSANOW, &termios) } != 0 {
            eprintln!(
                "tcsetattr TOSTOP failed: {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }

        let mut pipe_fds = [0i32; 2];
        // SAFETY: pipe2 initializes a two-fd array owned by this process.
        if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            eprintln!("pipe2 failed: {}", std::io::Error::last_os_error());
            return 1;
        }
        // SAFETY: fork creates a child that will become a background pgrp member.
        let child = unsafe { libc::fork() };
        if child == 0 {
            // SAFETY: child-only signal setup, process-group setup, and pipe notification.
            unsafe {
                libc::close(pipe_fds[0]);
                PTY_LDISC_SIGNAL_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = pty_ldisc_signal_handler as *const () as usize;
                libc::sigemptyset(&mut action.sa_mask);
                action.sa_flags = 0;
                if libc::sigaction(libc::SIGTTOU, &action, std::ptr::null_mut()) != 0 {
                    libc::_exit(2);
                }
                if libc::setpgid(0, 0) != 0 {
                    libc::_exit(3);
                }

                let write_rc = libc::write(1, b"W".as_ptr().cast(), 1);
                let write_signaled = write_rc < 0
                    && PTY_LDISC_SIGNAL_COUNT.load(std::sync::atomic::Ordering::SeqCst) > 0;

                PTY_LDISC_SIGNAL_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
                let mut set = fg;
                let ioctl_rc = libc::ioctl(1, libc::TIOCSPGRP, &mut set);
                let ioctl_signaled = ioctl_rc < 0
                    && PTY_LDISC_SIGNAL_COUNT.load(std::sync::atomic::Ordering::SeqCst) > 0;

                if write_signaled && (ioctl_signaled || ioctl_rc == 0) {
                    let _ = libc::write(pipe_fds[1], b"S".as_ptr().cast(), 1);
                    libc::_exit(0);
                }
                libc::_exit(if write_signaled { 5 } else { 4 });
            }
        }
        // SAFETY: parent no longer writes to the notification pipe.
        unsafe { libc::close(pipe_fds[1]) };
        if child < 0 {
            // SAFETY: close read end on fork failure.
            unsafe { libc::close(pipe_fds[0]) };
            eprintln!("fork failed: {}", std::io::Error::last_os_error());
            return 1;
        }
        let mut pfd = libc::pollfd {
            fd: pipe_fds[0],
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd points to one live pipe read end.
        let ready = unsafe { libc::poll(&mut pfd, 1, 2000) };
        let mut status = 0;
        if ready > 0 && pfd.revents & libc::POLLIN != 0 {
            let mut byte = [0u8; 1];
            // SAFETY: byte is writable and pipe_fds[0] is readable.
            let n = unsafe { libc::read(pipe_fds[0], byte.as_mut_ptr().cast(), 1) };
            // SAFETY: reap the child that reported SIGTTOU delivery.
            unsafe { libc::waitpid(child, &mut status, 0) };
            // SAFETY: close read end after use.
            unsafe { libc::close(pipe_fds[0]) };
            if n == 1
                && byte[0] == b'S'
                && libc::WIFEXITED(status)
                && libc::WEXITSTATUS(status) == 0
            {
                println!("SIGTTOU_OK");
                let _ = std::io::stdout().flush();
                return 0;
            }
            println!("SIGTTOU_BAD_STATUS status={status:#x}");
            let _ = std::io::stdout().flush();
            return 1;
        }
        // SAFETY: child did not report SIGTTOU; terminate and reap it before failing.
        unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, &mut status, 0);
            libc::close(pipe_fds[0]);
        }
        println!("SIGTTOU_MISSING background write/ioctl was not interrupted");
        let _ = std::io::stdout().flush();
        1
    }

    pub(super) fn subcmd_pty_tiocsctty_sigttin(_args: &[String]) -> i32 {
        // SAFETY: getpgrp has no preconditions.
        let mut fg = unsafe { libc::getpgrp() };
        // SAFETY: TIOCSPGRP reads a pid_t from the provided pointer for fd 0.
        if unsafe { libc::ioctl(0, libc::TIOCSPGRP, &mut fg) } != 0 {
            eprintln!("TIOCSPGRP failed: {}", std::io::Error::last_os_error());
            return 1;
        }
        let mut pipe_fds = [0i32; 2];
        // SAFETY: pipe2 initializes a two-fd array owned by this process.
        if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            eprintln!("pipe2 failed: {}", std::io::Error::last_os_error());
            return 1;
        }
        // SAFETY: fork creates a child that will become a background pgrp member.
        let child = unsafe { libc::fork() };
        if child == 0 {
            // SAFETY: child-only signal setup, process-group setup, and pipe notification.
            unsafe {
                libc::close(pipe_fds[0]);
                PTY_LDISC_SIGNAL_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = pty_ldisc_signal_handler as *const () as usize;
                libc::sigemptyset(&mut action.sa_mask);
                action.sa_flags = 0;
                if libc::sigaction(libc::SIGTTIN, &action, std::ptr::null_mut()) != 0 {
                    libc::_exit(2);
                }
                if libc::setpgid(0, 0) != 0 {
                    libc::_exit(2);
                }
                let mut byte = [0u8; 1];
                let _ = libc::read(0, byte.as_mut_ptr().cast(), 1);
                if PTY_LDISC_SIGNAL_COUNT.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                    let _ = libc::write(pipe_fds[1], b"S".as_ptr().cast(), 1);
                    libc::_exit(0);
                }
                libc::_exit(3);
            }
        }
        // SAFETY: parent no longer writes to the notification pipe.
        unsafe { libc::close(pipe_fds[1]) };
        if child < 0 {
            // SAFETY: close read end on fork failure.
            unsafe { libc::close(pipe_fds[0]) };
            eprintln!("fork failed: {}", std::io::Error::last_os_error());
            return 1;
        }
        let mut pfd = libc::pollfd {
            fd: pipe_fds[0],
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd points to one live pipe read end.
        let ready = unsafe { libc::poll(&mut pfd, 1, 2000) };
        let mut status = 0;
        if ready > 0 && pfd.revents & libc::POLLIN != 0 {
            let mut byte = [0u8; 1];
            // SAFETY: byte is writable and pipe_fds[0] is readable.
            let n = unsafe { libc::read(pipe_fds[0], byte.as_mut_ptr().cast(), 1) };
            // SAFETY: reap the child that reported SIGTTIN delivery.
            unsafe { libc::waitpid(child, &mut status, 0) };
            // SAFETY: close read end after use.
            unsafe { libc::close(pipe_fds[0]) };
            if n == 1
                && byte[0] == b'S'
                && libc::WIFEXITED(status)
                && libc::WEXITSTATUS(status) == 0
            {
                println!("SIGTTIN_OK");
                let _ = std::io::stdout().flush();
                return 0;
            }
            println!("SIGTTIN_BAD_STATUS status={status:#x}");
            let _ = std::io::stdout().flush();
            return 1;
        }
        // SAFETY: child did not report SIGTTIN; terminate and reap it before failing.
        unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, &mut status, 0);
            libc::close(pipe_fds[0]);
        }
        println!("SIGTTIN_MISSING background read stayed blocked");
        let _ = std::io::stdout().flush();
        1
    }

    pub(super) fn subcmd_pty_line_discipline_cr_to_nl(_args: &[String]) -> i32 {
        if set_stdin_termios(|termios| {
            termios.c_lflag &= !(libc::ICANON | libc::ECHO);
            termios.c_iflag |= libc::ICRNL;
            termios.c_cc[libc::VMIN] = 1;
            termios.c_cc[libc::VTIME] = 0;
        })
        .is_err()
        {
            return 1;
        }
        println!("READY");
        let _ = std::io::stdout().flush();
        let mut first = [0u8; 1];
        if std::io::stdin().read_exact(&mut first).is_err() {
            return 1;
        }
        println!("FIRST={}", first[0]);
        if set_stdin_termios(|termios| {
            termios.c_lflag &= !(libc::ICANON | libc::ECHO);
            termios.c_iflag &= !libc::ICRNL;
            termios.c_cc[libc::VMIN] = 1;
            termios.c_cc[libc::VTIME] = 0;
        })
        .is_err()
        {
            return 1;
        }
        println!("RAW_READY");
        let _ = std::io::stdout().flush();
        let mut second = [0u8; 1];
        if std::io::stdin().read_exact(&mut second).is_err() {
            return 1;
        }
        println!("ICRNL on={} off={}", first[0], second[0]);
        let _ = std::io::stdout().flush();
        if first[0] == b'\n' && second[0] == b'\r' {
            0
        } else {
            1
        }
    }

    fn set_stdin_termios(mut update: impl FnMut(&mut libc::termios)) -> Result<(), ()> {
        // SAFETY: tcgetattr/tcsetattr operate on the process's live PTY slave stdin fd.
        unsafe {
            let mut termios: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut termios) != 0 {
                eprintln!("tcgetattr failed: {}", std::io::Error::last_os_error());
                return Err(());
            }
            update(&mut termios);
            if libc::tcsetattr(0, libc::TCSANOW, &termios) != 0 {
                eprintln!("tcsetattr failed: {}", std::io::Error::last_os_error());
                return Err(());
            }
        }
        Ok(())
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
