// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `MULTI_INHERIT.*` — combinations of fd kinds inherited across fork+exec.
//!
//! Closes Gap 6 from the vfork-asymmetries audit: today's `INHERIT.*`
//! matrix tests one fd kind at a time, but real workloads (VS Code
//! server, Copilot) hold many simultaneously. The relevant
//! commit_delayed_fork path
//! (`litebox_shim_linux/src/syscalls/process.rs:5891-5917`) makes
//! per-fd accept/reject decisions when building the snapshot. A
//! parent holding *both* an accept-list fd *and* a reject-list fd
//! has different migration semantics than holding either alone.
//!
//! Each test sets up multiple parent-side fds, clears `O_CLOEXEC`,
//! spawns the child, and verifies the child can use **all** of them.
//! Pass iff every per-fd check succeeds.
//!
//! Test ID shape: `MULTI_INHERIT.{combo_name}.{parent_bt}.{child_bt}`.

#![allow(clippy::wildcard_enum_match_arm)]
// `libc::read`/`write` return isize; control flow guards `n > 0` before
// any conversion. The casts here cannot truncate within those guards.
#![allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::eventfd::EventFd;
use crate::os::pidfd::Pidfd;
use crate::{BinaryType, register_handler, register_leaf_subcommand};

use serde::{Deserialize, Serialize};

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;

const MULTI_INHERIT: HandlerToken<MultiInheritTrialArgs, MultiInheritOutput> =
    HandlerToken::new("multi_inherit_matrix.run");

// ─── Wire types ─────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct MultiInheritTrialArgs {
    child_binary: String,
    combo: ComboId,
    timeout_ms: u64,
    test_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct MultiInheritOutput {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ComboId {
    PipeEventfd,
    PipeBrokerfile,
    EventfdSignalfd,
    ThreeAccept,
    PipePidfd,
    PipeTimerfd,
    PipeEpoll,
    PidfdTimerfd,
    EpollInotify,
    EventfdPidfdEpoll,
}

impl ComboId {
    const ALL: &'static [Self] = &[
        Self::PipeEventfd,
        Self::PipeBrokerfile,
        Self::EventfdSignalfd,
        Self::ThreeAccept,
        Self::PipePidfd,
        Self::PipeTimerfd,
        Self::PipeEpoll,
        Self::PidfdTimerfd,
        Self::EpollInotify,
        Self::EventfdPidfdEpoll,
    ];

    const fn id(self) -> &'static str {
        match self {
            Self::PipeEventfd => "combo_pipe_eventfd",
            Self::PipeBrokerfile => "combo_pipe_brokerfile",
            Self::EventfdSignalfd => "combo_eventfd_signalfd",
            Self::ThreeAccept => "combo_three_accept",
            Self::PipePidfd => "combo_pipe_pidfd",
            Self::PipeTimerfd => "combo_pipe_timerfd",
            Self::PipeEpoll => "combo_pipe_epoll",
            Self::PidfdTimerfd => "combo_pidfd_timerfd",
            Self::EpollInotify => "combo_epoll_inotify",
            Self::EventfdPidfdEpoll => "combo_eventfd_pidfd_epoll",
        }
    }

    const fn kinds(self) -> &'static [FdKind] {
        match self {
            Self::PipeEventfd => &[FdKind::Pipe, FdKind::Eventfd],
            Self::PipeBrokerfile => &[FdKind::Pipe, FdKind::Brokerfile],
            Self::EventfdSignalfd => &[FdKind::Eventfd, FdKind::Signalfd],
            Self::ThreeAccept => &[FdKind::Pipe, FdKind::Eventfd, FdKind::Brokerfile],
            Self::PipePidfd => &[FdKind::Pipe, FdKind::Pidfd],
            Self::PipeTimerfd => &[FdKind::Pipe, FdKind::Timerfd],
            Self::PipeEpoll => &[FdKind::Pipe, FdKind::Epoll],
            Self::PidfdTimerfd => &[FdKind::Pidfd, FdKind::Timerfd],
            Self::EpollInotify => &[FdKind::Epoll, FdKind::Inotify],
            Self::EventfdPidfdEpoll => &[FdKind::Eventfd, FdKind::Pidfd, FdKind::Epoll],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FdKind {
    Pipe,
    Eventfd,
    Brokerfile,
    Pidfd,
    Timerfd,
    Epoll,
    Inotify,
    Signalfd,
}

impl FdKind {
    const fn id(self) -> &'static str {
        match self {
            Self::Pipe => "pipe",
            Self::Eventfd => "eventfd",
            Self::Brokerfile => "brokerfile",
            Self::Pidfd => "pidfd",
            Self::Timerfd => "timerfd",
            Self::Epoll => "epoll",
            Self::Inotify => "inotify",
            Self::Signalfd => "signalfd",
        }
    }
}

// ─── Registration ───────────────────────────────────────────────────

pub(crate) fn register_multi_inherit_matrix_tests(reg: &mut Registry<'_>) {
    register_handler!(MULTI_INHERIT, handle_multi_inherit_trial);
    register_leaf_subcommand!("multi-inherit", leaf_subcmd::subcmd_multi_inherit);

    for &combo in ComboId::ALL {
        for &parent_bt in BinaryType::ALL {
            for &child_bt in BinaryType::ALL {
                register_trial(reg, combo, parent_bt, child_bt);
            }
        }
    }
}

fn register_trial(
    reg: &mut Registry<'_>,
    combo: ComboId,
    parent_bt: BinaryType,
    child_bt: BinaryType,
) {
    let id = format!(
        "MULTI_INHERIT.{}.{}.{}",
        combo.id(),
        parent_bt.short_label(),
        child_bt.short_label()
    );
    let parent = parent_agent(parent_bt);

    reg.test("vscode", "multi_inherit_matrix", id.clone())
        .timeout(30)
        .build(move |cx| {
            let parent_handle = cx.require(parent);
            let trial_id = id.clone();
            Box::new(move |run| {
                let trial_id = trial_id.clone();
                Box::pin(async move {
                    let self_exe = run.self_exe().to_string();
                    let child_binary = crate::binary_path(child_bt, &self_exe);
                    let result = run
                        .send_named_typed(
                            &parent_handle,
                            &MULTI_INHERIT,
                            MultiInheritTrialArgs {
                                child_binary,
                                combo,
                                timeout_ms: 4000,
                                test_id: trial_id.clone(),
                            },
                        )
                        .await;
                    match result {
                        Ok(out) if out.exit_code == 0 => TestOutcome::new(
                            parent.name(),
                            true,
                            format!("combo {}: ok", combo.id()),
                        ),
                        Ok(out) => TestOutcome::new(
                            parent.name(),
                            false,
                            format!(
                                "exit_code={} stdout={:?} stderr={:?}",
                                out.exit_code, out.stdout, out.stderr
                            ),
                        ),
                        Err(e) => TestOutcome::new(parent.name(), false, format!("handler: {e}")),
                    }
                })
            })
        });
}

const fn parent_agent(bt: BinaryType) -> AgentName {
    match bt {
        BinaryType::PieGlibc => AgentName::Dpg1,
        BinaryType::NonPieGlibc => AgentName::Dpg1Dng,
        BinaryType::StaticPieGlibc => AgentName::Dpg1Spg,
        BinaryType::StaticPieMusl => AgentName::Dpg1Spm,
        BinaryType::NonPieStaticMusl => AgentName::Dpg1Snm,
    }
}

// ─── Handler ────────────────────────────────────────────────────────

async fn handle_multi_inherit_trial(
    args: MultiInheritTrialArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<MultiInheritOutput, HandlerError> {
    let mut state = TrialState::default();
    let setup_result = setup_combo(args.combo, &args.test_id, &mut state);
    let result = match setup_result {
        Ok(()) => run_trial(&args, &state),
        Err(e) => Err(e),
    };

    // Reap any forked target pids (pidfd setup).
    for pid in &state.target_pids {
        // SAFETY: pid is a child of this process we recorded earlier.
        unsafe {
            let mut status = 0;
            let _ = libc::waitpid(*pid, &raw mut status, libc::WNOHANG);
            let _ = libc::waitpid(*pid, &raw mut status, 0);
        }
    }
    // Cleanup brokerfile / inotify artifacts.
    for path in &state.cleanup_files {
        let _ = std::fs::remove_file(path);
    }
    for dir in &state.cleanup_dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
    result
}

#[derive(Default)]
struct TrialState {
    /// OwnedFds kept alive in the parent until after child exit.
    owned: Vec<OwnedFd>,
    /// Per-kind wire entries (kind id + raw fd) passed to the child.
    wire: Vec<(&'static str, RawFd)>,
    /// Target pids for pidfd combos (reaped after child).
    target_pids: Vec<i32>,
    cleanup_files: Vec<String>,
    cleanup_dirs: Vec<std::path::PathBuf>,
}

fn setup_combo(combo: ComboId, test_id: &str, state: &mut TrialState) -> Result<(), HandlerError> {
    for (i, kind) in combo.kinds().iter().enumerate() {
        setup_kind(*kind, i, test_id, state)?;
    }
    Ok(())
}

fn setup_kind(
    kind: FdKind,
    slot: usize,
    test_id: &str,
    state: &mut TrialState,
) -> Result<(), HandlerError> {
    match kind {
        FdKind::Pipe => setup_pipe(state),
        FdKind::Eventfd => setup_eventfd(state),
        FdKind::Brokerfile => setup_brokerfile(slot, test_id, state),
        FdKind::Pidfd => setup_pidfd(state),
        FdKind::Timerfd => setup_timerfd(state),
        FdKind::Epoll => setup_epoll(state),
        FdKind::Inotify => setup_inotify(slot, test_id, state),
        FdKind::Signalfd => setup_signalfd(state),
    }
}

fn setup_pipe(state: &mut TrialState) -> Result<(), HandlerError> {
    let (r, w) = pipe_owned()?;
    // Pre-write the marker; the read end is what the child inherits.
    write_all_fd(w.as_raw_fd(), b"P", "pipe pre-write")?;
    drop(w);
    let fd = r.as_raw_fd();
    clear_cloexec(fd)?;
    state.owned.push(r);
    state.wire.push((FdKind::Pipe.id(), fd));
    Ok(())
}

fn setup_eventfd(state: &mut TrialState) -> Result<(), HandlerError> {
    let ev = EventFd::open(0, "nonblock|semaphore|cloexec")
        .map_err(|e| HandlerError(format!("eventfd open: {e}")))?;
    ev.write(1)
        .map_err(|e| HandlerError(format!("eventfd pre-write: {e}")))?;
    let fd = ev.as_raw_fd();
    clear_cloexec(fd)?;
    // SAFETY: we transfer ownership of the raw fd to an OwnedFd; the
    // EventFd wrapper is consumed without closing it.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    std::mem::forget(ev);
    state.owned.push(owned);
    state.wire.push((FdKind::Eventfd.id(), fd));
    Ok(())
}

fn setup_brokerfile(
    slot: usize,
    test_id: &str,
    state: &mut TrialState,
) -> Result<(), HandlerError> {
    let path = brokerfile_path(test_id, slot);
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, b"B")
        .map_err(|e| HandlerError(format!("brokerfile seed {path}: {e}")))?;
    state.cleanup_files.push(path.clone());
    let file = std::fs::OpenOptions::new()
        .read(true)
        .open(&path)
        .map_err(|e| HandlerError(format!("brokerfile open {path}: {e}")))?;
    let owned = OwnedFd::from(file);
    let fd = owned.as_raw_fd();
    clear_cloexec(fd)?;
    state.owned.push(owned);
    state.wire.push((FdKind::Brokerfile.id(), fd));
    Ok(())
}

fn setup_pidfd(state: &mut TrialState) -> Result<(), HandlerError> {
    // SAFETY: fork is followed in the child by async-signal-safe libc
    // only (usleep, _exit). Parent continues normal Rust.
    let target_pid = unsafe { libc::fork() };
    if target_pid < 0 {
        return Err(HandlerError(format!(
            "pidfd target fork: {}",
            std::io::Error::last_os_error()
        )));
    }
    if target_pid == 0 {
        // SAFETY: child path uses only async-signal-safe primitives.
        unsafe {
            libc::usleep(50_000);
            libc::_exit(0);
        }
    }
    let target_u32 =
        u32::try_from(target_pid).map_err(|e| HandlerError(format!("pidfd target pid: {e}")))?;
    let pidfd = Pidfd::open(target_u32).map_err(|e| {
        // SAFETY: best-effort reap of the target on error path.
        unsafe {
            let mut status = 0;
            libc::waitpid(target_pid, &raw mut status, 0);
        }
        HandlerError(format!("pidfd_open({target_u32}): {e}"))
    })?;
    state.target_pids.push(target_pid);
    // Wait until the target has actually exited so the inherited
    // pidfd is sticky-readable in the child.
    match pidfd.poll_exit_in(2000) {
        Ok(true) => {}
        Ok(false) => {
            return Err(HandlerError(
                "pidfd target did not exit within 2s of spawn".into(),
            ));
        }
        Err(e) => return Err(HandlerError(format!("pidfd poll_exit_in: {e}"))),
    }
    let fd = pidfd.as_raw_fd();
    clear_cloexec(fd)?;
    // SAFETY: transfer the raw fd to an OwnedFd; consume the wrapper
    // without closing it.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    std::mem::forget(pidfd);
    state.owned.push(owned);
    state.wire.push((FdKind::Pidfd.id(), fd));
    Ok(())
}

fn setup_timerfd(state: &mut TrialState) -> Result<(), HandlerError> {
    // SAFETY: timerfd_create with constant clock/flags; errors checked.
    let raw = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC) };
    if raw < 0 {
        return Err(HandlerError(format!(
            "timerfd_create: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: raw is a fresh fd owned here.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    arm_timerfd_50ms(raw)?;
    poll_in(raw, 2000, "timerfd parent pre-fork expiry")?;
    let fd = owned.as_raw_fd();
    clear_cloexec(fd)?;
    state.owned.push(owned);
    state.wire.push((FdKind::Timerfd.id(), fd));
    Ok(())
}

fn setup_epoll(state: &mut TrialState) -> Result<(), HandlerError> {
    let ev = EventFd::open(0, "nonblock|cloexec")
        .map_err(|e| HandlerError(format!("epoll trial eventfd: {e}")))?;
    ev.write(1)
        .map_err(|e| HandlerError(format!("epoll trial pre-write: {e}")))?;
    let event_fd = ev.as_raw_fd();

    // SAFETY: epoll_create1 returns a fresh fd on success.
    let raw_ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if raw_ep < 0 {
        return Err(HandlerError(format!(
            "epoll_create1: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: raw_ep is a fresh fd owned here.
    let epoll_owned = unsafe { OwnedFd::from_raw_fd(raw_ep) };
    let mut event = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: event_fd.cast_unsigned().into(),
    };
    // SAFETY: epoll_fd and event_fd are live; event points to initialized storage.
    let rc = unsafe { libc::epoll_ctl(raw_ep, libc::EPOLL_CTL_ADD, event_fd, &raw mut event) };
    if rc != 0 {
        return Err(HandlerError(format!(
            "epoll_ctl ADD: {}",
            std::io::Error::last_os_error()
        )));
    }

    clear_cloexec(raw_ep)?;
    clear_cloexec(event_fd)?;

    // SAFETY: transfer the raw fd to OwnedFd; consume EventFd wrapper.
    let ev_owned = unsafe { OwnedFd::from_raw_fd(event_fd) };
    std::mem::forget(ev);
    state.owned.push(ev_owned);
    state.owned.push(epoll_owned);
    // The child inherits both; only the epoll fd is on the wire and
    // the registered eventfd ride along via the aux env var below.
    state.wire.push((FdKind::Epoll.id(), raw_ep));
    Ok(())
}

fn setup_inotify(slot: usize, test_id: &str, state: &mut TrialState) -> Result<(), HandlerError> {
    let dir = inotify_dir_path(test_id, slot);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)
        .map_err(|e| HandlerError(format!("inotify mkdir {}: {e}", dir.display())))?;
    state.cleanup_dirs.push(dir.clone());

    // SAFETY: inotify_init1 returns a fresh fd on success.
    let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if raw < 0 {
        return Err(HandlerError(format!(
            "inotify_init1: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: raw is a fresh fd owned here.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let path_c = CString::new(dir.to_string_lossy().as_ref())
        .map_err(|e| HandlerError(format!("inotify path nul: {e}")))?;
    // SAFETY: path_c is a valid C string; raw is a live inotify fd.
    let wd = unsafe { libc::inotify_add_watch(raw, path_c.as_ptr(), libc::IN_CREATE) };
    if wd < 0 {
        return Err(HandlerError(format!(
            "inotify_add_watch: {}",
            std::io::Error::last_os_error()
        )));
    }
    // Pre-trigger so the event sits in the kernel queue at fork time.
    std::fs::write(dir.join("trigger.txt"), b"x")
        .map_err(|e| HandlerError(format!("inotify trigger: {e}")))?;

    clear_cloexec(raw)?;
    state.owned.push(owned);
    state.wire.push((FdKind::Inotify.id(), raw));
    Ok(())
}

fn setup_signalfd(state: &mut TrialState) -> Result<(), HandlerError> {
    // The signal mask is inherited across fork+exec, but pending
    // signals are not. So we set up the signalfd here with SIGUSR1
    // blocked in the mask; the child raises SIGUSR1 itself to make
    // the inherited signalfd readable.
    let mut set = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    // SAFETY: standard sigset_t manipulation on owned signal set.
    unsafe {
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGUSR1);
        libc::sigprocmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
    }
    // SAFETY: signalfd(-1, ...) creates a fresh fd referring to `set`.
    let raw = unsafe { libc::signalfd(-1, &raw const set, libc::SFD_CLOEXEC) };
    if raw < 0 {
        return Err(HandlerError(format!(
            "signalfd: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: raw is a fresh fd owned here.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    clear_cloexec(raw)?;
    state.owned.push(owned);
    state.wire.push((FdKind::Signalfd.id(), raw));
    Ok(())
}

fn run_trial(
    args: &MultiInheritTrialArgs,
    state: &TrialState,
) -> Result<MultiInheritOutput, HandlerError> {
    let wire = state
        .wire
        .iter()
        .map(|(k, fd)| format!("{k}:{fd}"))
        .collect::<Vec<_>>()
        .join(",");

    let mut cmd = Command::new(&args.child_binary);
    cmd.args([
        "multi-inherit",
        "multi-inherit-child",
        args.combo.id(),
        &wire,
        &args.timeout_ms.to_string(),
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let child = cmd
        .spawn()
        .map_err(|e| HandlerError(format!("spawn {}: {e}", args.child_binary)))?;
    let output = wait_with_timeout(child, Duration::from_millis(args.timeout_ms + 2000))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let exit_code = output.status.code().unwrap_or(-1);
    Ok(MultiInheritOutput {
        exit_code,
        stdout,
        stderr,
    })
}

// ─── Helpers ────────────────────────────────────────────────────────

fn pipe_owned() -> Result<(OwnedFd, OwnedFd), HandlerError> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 initializes both fd slots on success.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(HandlerError(format!(
            "pipe2: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: pipe2 returned two fresh descriptors owned by us.
    let r = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: same.
    let w = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((r, w))
}

fn clear_cloexec(fd: RawFd) -> Result<(), HandlerError> {
    // SAFETY: fcntl on a live fd; errors checked.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    if rc != 0 {
        return Err(HandlerError(format!(
            "fcntl(F_SETFD, 0) fd={fd}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn write_all_fd(fd: RawFd, mut buf: &[u8], context: &str) -> Result<(), HandlerError> {
    while !buf.is_empty() {
        // SAFETY: buf is readable memory; fd is a live fd owned by us.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
        if n > 0 {
            buf = &buf[n.cast_unsigned()..];
            continue;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(HandlerError(format!("{context}: n={n} err={err}")));
        }
    }
    Ok(())
}

fn arm_timerfd_50ms(fd: RawFd) -> Result<(), HandlerError> {
    let spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        },
    };
    // SAFETY: spec is initialized; fd is a live timerfd.
    if unsafe { libc::timerfd_settime(fd, 0, std::ptr::from_ref(&spec), std::ptr::null_mut()) } != 0
    {
        return Err(HandlerError(format!(
            "timerfd_settime: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn poll_in(fd: RawFd, timeout_ms: i32, context: &str) -> Result<(), HandlerError> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pfd is initialized; nfds matches buffer length.
    let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
    if rc <= 0 || pfd.revents & libc::POLLIN == 0 {
        return Err(HandlerError(format!(
            "{context}: poll rc={rc} revents={} err={}",
            pfd.revents,
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn brokerfile_path(test_id: &str, slot: usize) -> String {
    let s = sanitize(test_id);
    format!("/tmp/multi-inherit-{s}-{}-{slot}.txt", std::process::id())
}

fn inotify_dir_path(test_id: &str, slot: usize) -> std::path::PathBuf {
    let s = sanitize(test_id);
    std::path::PathBuf::from(format!(
        "/tmp/multi-inherit-ino-{s}-{}-{slot}",
        std::process::id()
    ))
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '-' => c,
            _ => '_',
        })
        .collect()
}

use std::io::Read as _;

fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, HandlerError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| HandlerError(format!("try_wait: {e}")))?
        {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            if let Some(mut s) = child.stdout.take() {
                let _ = s.read_to_end(&mut stdout);
            }
            if let Some(mut s) = child.stderr.take() {
                let _ = s.read_to_end(&mut stderr);
            }
            return Ok(std::process::Output {
                status,
                stdout,
                stderr,
            });
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(HandlerError("timeout waiting for child".into()));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

// ─── Leaf subcommand (child side) ───────────────────────────────────

mod leaf_subcmd {
    use std::ffi::CString;
    use std::os::fd::RawFd;

    pub(super) fn subcmd_multi_inherit(args: &[String]) -> i32 {
        match args.get(2).map(String::as_str) {
            Some("multi-inherit-child") => multi_inherit_child(args),
            Some(other) => {
                eprintln!("multi-inherit: unknown subcommand: {other}");
                2
            }
            None => {
                eprintln!("multi-inherit: missing subcommand");
                2
            }
        }
    }

    fn multi_inherit_child(args: &[String]) -> i32 {
        let Some(combo) = args.get(3).map(String::as_str) else {
            eprintln!("multi-inherit-child: missing combo");
            return 2;
        };
        let Some(wire) = args.get(4).map(String::as_str) else {
            eprintln!("multi-inherit-child: missing wire");
            return 2;
        };
        let timeout_ms = args
            .get(5)
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(4000);

        let entries: Vec<(&str, RawFd)> = wire
            .split(',')
            .filter_map(|s| {
                let (k, fd) = s.split_once(':')?;
                Some((k, fd.parse::<RawFd>().ok()?))
            })
            .collect();

        if entries.is_empty() {
            eprintln!("multi-inherit-child: empty wire");
            return 2;
        }

        let mut failures: Vec<String> = Vec::new();
        for (kind, fd) in &entries {
            if let Err(e) = check_kind(kind, *fd, timeout_ms) {
                failures.push(format!("{kind}(fd={fd}): {e}"));
            }
        }

        if failures.is_empty() {
            println!("ok combo={combo} fds={}", entries.len());
            0
        } else {
            eprintln!(
                "multi-inherit-child FAIL combo={combo}: {}",
                failures.join("; ")
            );
            1
        }
    }

    fn check_kind(kind: &str, fd: RawFd, timeout_ms: i32) -> Result<(), String> {
        match kind {
            "pipe" => check_pipe(fd),
            "eventfd" => check_eventfd(fd),
            "brokerfile" => check_brokerfile(fd),
            "pidfd" => check_pollin(fd, timeout_ms),
            "timerfd" => check_timerfd(fd),
            "epoll" => check_epoll(fd, timeout_ms),
            "inotify" => check_inotify(fd),
            "signalfd" => check_signalfd(fd),
            other => Err(format!("unknown kind {other}")),
        }
    }

    fn check_pipe(fd: RawFd) -> Result<(), String> {
        let mut buf = [0u8; 1];
        // SAFETY: buf is writable; fd is the inherited pipe read end.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), 1) };
        if n != 1 {
            return Err(format!(
                "read n={n} err={}",
                std::io::Error::last_os_error()
            ));
        }
        if buf[0] != b'P' {
            return Err(format!("got byte {}, expected 'P'", buf[0]));
        }
        Ok(())
    }

    fn check_eventfd(fd: RawFd) -> Result<(), String> {
        let mut value = 0u64;
        // SAFETY: value is 8 bytes of writable storage.
        let n = unsafe { libc::read(fd, std::ptr::from_mut(&mut value).cast::<libc::c_void>(), 8) };
        if n != 8 {
            return Err(format!(
                "read n={n} err={}",
                std::io::Error::last_os_error()
            ));
        }
        if value != 1 {
            return Err(format!("got value {value}, expected 1"));
        }
        Ok(())
    }

    fn check_brokerfile(fd: RawFd) -> Result<(), String> {
        // SAFETY: fd is the inherited file fd, seek the start in case
        // anything advanced the offset; the brokerfile holds "B".
        unsafe {
            libc::lseek(fd, 0, libc::SEEK_SET);
        }
        let mut buf = [0u8; 1];
        // SAFETY: buf is writable storage.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), 1) };
        if n != 1 {
            return Err(format!(
                "read n={n} err={}",
                std::io::Error::last_os_error()
            ));
        }
        if buf[0] != b'B' {
            return Err(format!("got byte {}, expected 'B'", buf[0]));
        }
        Ok(())
    }

    fn check_pollin(fd: RawFd, timeout_ms: i32) -> Result<(), String> {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is initialized; nfds matches buffer length.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        if rc <= 0 || pfd.revents & libc::POLLIN == 0 {
            return Err(format!(
                "poll rc={rc} revents={} err={}",
                pfd.revents,
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn check_timerfd(fd: RawFd) -> Result<(), String> {
        let mut value = 0u64;
        // SAFETY: 8 bytes of writable storage for the timerfd count.
        let n = unsafe { libc::read(fd, std::ptr::from_mut(&mut value).cast::<libc::c_void>(), 8) };
        if n != 8 {
            return Err(format!(
                "read n={n} err={}",
                std::io::Error::last_os_error()
            ));
        }
        if value == 0 {
            return Err("timerfd count was 0".into());
        }
        Ok(())
    }

    fn check_epoll(fd: RawFd, timeout_ms: i32) -> Result<(), String> {
        let mut ev = libc::epoll_event { events: 0, u64: 0 };
        // SAFETY: ev is initialized storage for a single event.
        let rc = unsafe { libc::epoll_wait(fd, std::ptr::from_mut(&mut ev), 1, timeout_ms) };
        if rc != 1 {
            return Err(format!(
                "epoll_wait rc={rc} err={}",
                std::io::Error::last_os_error()
            ));
        }
        let events = ev.events;
        if events & (libc::EPOLLIN as u32) == 0 {
            return Err(format!("events={events:#x}, expected EPOLLIN"));
        }
        Ok(())
    }

    fn check_inotify(fd: RawFd) -> Result<(), String> {
        // Inotify event header is sizeof(struct inotify_event)=16 +
        // name. Buffer of 256 is enough for "trigger.txt".
        let mut buf = [0u8; 256];
        // SAFETY: buf is writable storage.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n < 16 {
            return Err(format!(
                "inotify read n={n} err={}",
                std::io::Error::last_os_error()
            ));
        }
        // Past the 16-byte header, the kernel writes a NUL-terminated
        // filename. We don't validate the name strictly; presence of
        // *some* event suffices.
        let len = u32::from_ne_bytes(buf[12..16].try_into().unwrap_or([0; 4]));
        if len == 0 {
            return Err("inotify event len=0 (no name)".into());
        }
        // Silence unused-CString warning when name-validation paths
        // get added later; for now we just check we read >=16 bytes.
        let _ = CString::new("trigger.txt");
        Ok(())
    }

    fn check_signalfd(fd: RawFd) -> Result<(), String> {
        // Pending signals are not inherited across fork+exec, but the
        // signal mask IS. The parent blocked SIGUSR1 and created the
        // signalfd; raise SIGUSR1 here so it pends on this process and
        // is observable via the inherited signalfd.
        // SAFETY: raise() is async-signal-safe and well-defined here.
        unsafe {
            libc::raise(libc::SIGUSR1);
        }
        let mut buf = [0u8; 128];
        // SAFETY: buf is 128 bytes of writable storage (sizeof signalfd_siginfo).
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n != 128 {
            return Err(format!(
                "signalfd read n={n} err={}",
                std::io::Error::last_os_error()
            ));
        }
        let signo = u32::from_ne_bytes(buf[0..4].try_into().unwrap_or([0; 4]));
        if signo != libc::SIGUSR1.cast_unsigned() {
            return Err(format!("signo={signo}, expected SIGUSR1"));
        }
        Ok(())
    }
}
