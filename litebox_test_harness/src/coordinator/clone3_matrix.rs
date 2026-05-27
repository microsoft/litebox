// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! clone3 flag-combination matrix tests.
//!
//! Migrated to the typed-handler protocol. Each clone3 scenario is a
//! registered handler that performs its syscall probe inline on the agent;
//! the coordinator only sends typed args and checks typed output.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::similar_names
)]

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::pty::{Pty, wait_child_timeout};
use crate::register_handler;

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;

const CL3_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,
    AgentName::Dpg1Dpg1,
    AgentName::Dpg2,
    AgentName::Dpg2Dpg,
];

// ─── Args / outputs ─────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct Clone3ExecArgs {
    exec_target: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Clone3Out {
    pid: u64,
    pidfd: Option<i32>,
    ok: bool,
    error: Option<String>,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
enum DropbearSessionStage {
    ExecOnly,
    Setsid,
    DupStdio,
    Tiocsctty,
    Full,
    FullBash,
    FullSetidNetwork,
}

impl DropbearSessionStage {
    fn label(self) -> &'static str {
        match self {
            DropbearSessionStage::ExecOnly => "exec_only",
            DropbearSessionStage::Setsid => "setsid",
            DropbearSessionStage::DupStdio => "dup_stdio",
            DropbearSessionStage::Tiocsctty => "tiocsctty",
            DropbearSessionStage::Full => "full",
            DropbearSessionStage::FullBash => "full_bash",
            DropbearSessionStage::FullSetidNetwork => "full_setid_network",
        }
    }

    fn uses_pty_stdio(self) -> bool {
        match self {
            DropbearSessionStage::ExecOnly
            | DropbearSessionStage::Setsid
            | DropbearSessionStage::Tiocsctty => false,
            DropbearSessionStage::DupStdio
            | DropbearSessionStage::Full
            | DropbearSessionStage::FullBash => true,
            DropbearSessionStage::FullSetidNetwork => false,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct DropbearSessionArgs {
    stage: DropbearSessionStage,
}

// ─── Typed handler tokens ───────────────────────────────────────────

const THREAD: HandlerToken<(), Clone3Out> = HandlerToken::new("clone3.thread");
const PROCESS: HandlerToken<Clone3ExecArgs, Clone3Out> = HandlerToken::new("clone3.process");
const WITH_PIDFD: HandlerToken<Clone3ExecArgs, Clone3Out> = HandlerToken::new("clone3.with_pidfd");
const WITH_SET_TID: HandlerToken<Clone3ExecArgs, Clone3Out> =
    HandlerToken::new("clone3.with_set_tid");
const WITH_CGROUP: HandlerToken<Clone3ExecArgs, Clone3Out> =
    HandlerToken::new("clone3.with_cgroup");
const VFORK: HandlerToken<(), Clone3Out> = HandlerToken::new("clone3.vfork");
const DROPBEAR_VFORK: HandlerToken<(), Clone3Out> = HandlerToken::new("clone3.dropbear_vfork");
const DROPBEAR_CLONE: HandlerToken<(), Clone3Out> = HandlerToken::new("clone.dropbear_vfork");
const DROPBEAR_SESSION_SETUP: HandlerToken<DropbearSessionArgs, Clone3Out> =
    HandlerToken::new("clone.dropbear_session_setup");

// ─── Handlers ───────────────────────────────────────────────────────

async fn handle_thread(_args: (), _ctx: &mut HandlerCtx<'_>) -> Result<Clone3Out, HandlerError> {
    tokio::task::spawn_blocking(run_clone3_thread)
        .await
        .map_err(|e| HandlerError(format!("clone3 thread task join: {e}")))
}

async fn handle_process(
    args: Clone3ExecArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Clone3Out, HandlerError> {
    tokio::task::spawn_blocking(move || run_clone3_process(false, None, None, args.exec_target))
        .await
        .map_err(|e| HandlerError(format!("clone3 process task join: {e}")))
}

async fn handle_with_pidfd(
    args: Clone3ExecArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Clone3Out, HandlerError> {
    tokio::task::spawn_blocking(move || run_clone3_process(true, None, None, args.exec_target))
        .await
        .map_err(|e| HandlerError(format!("clone3 pidfd task join: {e}")))
}

async fn handle_with_set_tid(
    args: Clone3ExecArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Clone3Out, HandlerError> {
    tokio::task::spawn_blocking(move || {
        run_clone3_process(false, Some(99_999), None, args.exec_target)
    })
    .await
    .map_err(|e| HandlerError(format!("clone3 set_tid task join: {e}")))
}

async fn handle_with_cgroup(
    args: Clone3ExecArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Clone3Out, HandlerError> {
    tokio::task::spawn_blocking(move || run_clone3_with_cgroup(0, args.exec_target))
        .await
        .map_err(|e| HandlerError(format!("clone3 cgroup task join: {e}")))
}

async fn handle_vfork(_args: (), _ctx: &mut HandlerCtx<'_>) -> Result<Clone3Out, HandlerError> {
    tokio::task::spawn_blocking(run_clone3_vfork)
        .await
        .map_err(|e| HandlerError(format!("clone3 vfork task join: {e}")))
}

async fn handle_dropbear_vfork(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Clone3Out, HandlerError> {
    tokio::task::spawn_blocking(run_clone3_dropbear_vfork)
        .await
        .map_err(|e| HandlerError(format!("clone3 dropbear vfork task join: {e}")))
}

async fn handle_dropbear_clone(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Clone3Out, HandlerError> {
    tokio::task::spawn_blocking(run_clone_dropbear_vfork)
        .await
        .map_err(|e| HandlerError(format!("clone dropbear vfork task join: {e}")))
}

async fn handle_dropbear_session_setup(
    args: DropbearSessionArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Clone3Out, HandlerError> {
    tokio::task::spawn_blocking(move || run_clone_dropbear_session_setup(args.stage))
        .await
        .map_err(|e| HandlerError(format!("clone dropbear session setup task join: {e}")))
}

// ─── Registration ──────────────────────────────────────────────────

pub(crate) fn register_clone3_matrix(reg: &mut Registry<'_>) {
    register_handler!(THREAD, handle_thread);
    register_handler!(PROCESS, handle_process);
    register_handler!(WITH_PIDFD, handle_with_pidfd);
    register_handler!(WITH_SET_TID, handle_with_set_tid);
    register_handler!(WITH_CGROUP, handle_with_cgroup);
    register_handler!(VFORK, handle_vfork);
    register_handler!(DROPBEAR_VFORK, handle_dropbear_vfork);
    register_handler!(DROPBEAR_CLONE, handle_dropbear_clone);
    register_handler!(DROPBEAR_SESSION_SETUP, handle_dropbear_session_setup);

    for &agent in CL3_AGENTS {
        reg.single_agent_handler_test(
            "vscode",
            "clone3",
            format!("CL3.thread.{agent}"),
            agent,
            &THREAD,
            check_success_without_pidfd,
        );
        register_exec_case(reg, "process", agent, &PROCESS, check_success_without_pidfd);
        register_exec_case(
            reg,
            "with_pidfd",
            agent,
            &WITH_PIDFD,
            check_success_with_pidfd,
        );
        register_exec_case(
            reg,
            "with_set_tid",
            agent,
            &WITH_SET_TID,
            check_set_tid_outcome,
        );
        register_exec_case(
            reg,
            "with_cgroup",
            agent,
            &WITH_CGROUP,
            check_cgroup_outcome,
        );
        reg.single_agent_handler_test(
            "vscode",
            "clone3",
            format!("CL3.vfork.{agent}"),
            agent,
            &VFORK,
            check_vfork_success,
        );
        reg.single_agent_handler_test(
            "vscode",
            "clone3",
            format!("CL3.dropbear_vfork.{agent}"),
            agent,
            &DROPBEAR_VFORK,
            check_success_without_pidfd,
        );
        reg.single_agent_handler_test(
            "vscode",
            "clone3",
            format!("CL3.dropbear_clone.{agent}"),
            agent,
            &DROPBEAR_CLONE,
            check_dropbear_clone_success,
        );
        register_dropbear_session_setup_cases(reg, agent);
    }
}

fn register_dropbear_session_setup_cases(reg: &mut Registry<'_>, agent: AgentName) {
    for stage in [
        DropbearSessionStage::ExecOnly,
        DropbearSessionStage::Setsid,
        DropbearSessionStage::DupStdio,
        DropbearSessionStage::Tiocsctty,
        DropbearSessionStage::Full,
        DropbearSessionStage::FullBash,
        DropbearSessionStage::FullSetidNetwork,
    ] {
        let label = agent.to_string();
        let test_id = format!("CL3.dropbear_session_setup.{}.{agent}", stage.label());
        reg.test("vscode", "clone3", test_id)
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    Box::pin(async move {
                        let result = run
                            .send_named_typed(
                                &handle,
                                &DROPBEAR_SESSION_SETUP,
                                DropbearSessionArgs { stage },
                            )
                            .await;
                        let (pass, detail) = match result {
                            Ok(out) => match check_dropbear_session_setup_success(&out) {
                                Ok(detail) => (true, detail),
                                Err(error) => (false, format!("{error}; response={out:?}")),
                            },
                            Err(error) => (false, error),
                        };
                        TestOutcome::new(&label, pass, detail)
                    })
                })
            });
    }
}

fn register_exec_case(
    reg: &mut Registry<'_>,
    name: &'static str,
    agent: AgentName,
    token: &'static HandlerToken<Clone3ExecArgs, Clone3Out>,
    check: fn(&Clone3Out) -> Result<String, String>,
) {
    for &bt in crate::BinaryType::ALL {
        let label = agent.to_string();
        let test_id = format!("CL3.{name}.{}.{agent}", bt.label());
        reg.test("vscode", "clone3", test_id)
            .timeout(60)
            .build(move |cx| {
                let handle = cx.require(agent);
                Box::new(move |run| {
                    Box::pin(async move {
                        let args = Clone3ExecArgs {
                            exec_target: Some(crate::binary_path(bt, run.self_exe())),
                        };
                        let result = run.send_named_typed(&handle, token, args).await;
                        let (pass, detail) = match result {
                            Ok(out) => match check(&out) {
                                Ok(detail) => (true, detail),
                                Err(error) => (false, format!("{error}; response={out:?}")),
                            },
                            Err(error) => (false, error),
                        };
                        TestOutcome::new(&label, pass, detail)
                    })
                })
            });
    }
}

fn check_success_without_pidfd(out: &Clone3Out) -> Result<String, String> {
    expect_success_without_pidfd(out)?;
    Ok(format!("{out:?}"))
}

fn check_vfork_success(out: &Clone3Out) -> Result<String, String> {
    expect_vfork_success(out)?;
    Ok(format!("{out:?}"))
}

fn check_dropbear_clone_success(out: &Clone3Out) -> Result<String, String> {
    match out {
        Clone3Out {
            pid,
            pidfd: None,
            ok: true,
            error: None,
        } if *pid > 0 => Ok(format!("{out:?}")),
        other => Err(format!(
            "expected dropbear-shaped clone/vfork child marker, got {other:?}"
        )),
    }
}

fn check_dropbear_session_setup_success(out: &Clone3Out) -> Result<String, String> {
    match out {
        Clone3Out {
            pid,
            pidfd: None,
            ok: true,
            error: None,
        } if *pid > 0 => Ok(format!("{out:?}")),
        other => Err(format!(
            "expected dropbear session child to exec and exit successfully, got {other:?}"
        )),
    }
}

fn check_success_with_pidfd(out: &Clone3Out) -> Result<String, String> {
    expect_success_with_pidfd(out)?;
    Ok(format!("{out:?}"))
}

fn check_set_tid_outcome(out: &Clone3Out) -> Result<String, String> {
    expect_set_tid_outcome(out)?;
    Ok(format!("{out:?}"))
}

fn check_cgroup_outcome(out: &Clone3Out) -> Result<String, String> {
    expect_cgroup_outcome(out)?;
    Ok(format!("{out:?}"))
}

fn expect_success_without_pidfd(out: &Clone3Out) -> Result<(), String> {
    match out {
        Clone3Out {
            pid,
            pidfd: None,
            ok: true,
            error: None,
        } if *pid > 0 => Ok(()),
        Clone3Out {
            ok: false,
            error: Some(error),
            ..
        } if documented_error(error, &["ENOSYS"]) => Ok(()),
        other => Err(format!(
            "expected clone3 success or documented native ENOSYS/seccomp result without pidfd, got {other:?}"
        )),
    }
}

fn expect_vfork_success(out: &Clone3Out) -> Result<(), String> {
    match out {
        Clone3Out {
            pid,
            pidfd: None,
            ok: true,
            error: None,
        } if *pid > 0 => Ok(()),
        Clone3Out {
            ok: false,
            error: Some(error),
            ..
        } if documented_error(error, &["ENOSYS"]) => Ok(()),
        other => Err(format!(
            "expected clone3(CLONE_VFORK) success or documented native ENOSYS/seccomp result without pidfd, got {other:?}"
        )),
    }
}

fn expect_success_with_pidfd(out: &Clone3Out) -> Result<(), String> {
    match out {
        Clone3Out {
            pid,
            pidfd: Some(pidfd),
            ok: true,
            error: None,
        } if *pid > 0 && *pidfd >= 0 => Ok(()),
        Clone3Out {
            ok: false,
            error: Some(error),
            ..
        } if documented_error(error, &["ENOSYS"]) => Ok(()),
        other => Err(format!(
            "expected clone3 success or documented native ENOSYS/seccomp result with pidfd, got {other:?}"
        )),
    }
}

fn expect_set_tid_outcome(out: &Clone3Out) -> Result<(), String> {
    match out {
        Clone3Out {
            pid,
            ok: true,
            error: None,
            ..
        } if *pid > 0 => Ok(()),
        Clone3Out {
            ok: false,
            error: Some(error),
            ..
        } if documented_error(error, &["ENOSYS", "EPERM"]) => Ok(()),
        other => Err(format!(
            "expected set_tid success or documented ENOSYS/EPERM failure, got {other:?}"
        )),
    }
}

fn expect_cgroup_outcome(out: &Clone3Out) -> Result<(), String> {
    match out {
        Clone3Out {
            pid,
            ok: true,
            error: None,
            ..
        } if *pid > 0 => Ok(()),
        Clone3Out {
            ok: false,
            error: Some(error),
            ..
        } if error.starts_with("cgroup_fd_unavailable:")
            || documented_error(
                error,
                &[
                    "EACCES",
                    "EBADF",
                    "EINVAL",
                    "ENOENT",
                    "ENOSYS",
                    "EOPNOTSUPP",
                    "EPERM",
                    "EROFS",
                ],
            ) =>
        {
            Ok(())
        }
        other => Err(format!(
            "expected cgroup success or documented cgroup-fd/permission error, got {other:?}"
        )),
    }
}

fn documented_error(error: &str, names: &[&str]) -> bool {
    names
        .iter()
        .any(|name| error == *name || error.contains(name))
}

// ─── clone3 syscall probes ──────────────────────────────────────────

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

static CLONE3_THREAD_WRITE_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
static CLONE3_THREAD_TID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
static CLONE3_THREAD_SIGNAL: u8 = 1;
static CLONE3_VFORK_STAGE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
static CLONE3_DROPBEAR_MARKER: u8 = 0x48;

fn clone_result_error(error: impl Into<String>) -> Clone3Out {
    Clone3Out {
        pid: 0,
        pidfd: None,
        ok: false,
        error: Some(error.into()),
    }
}

fn errno_name(errno: i32) -> String {
    match errno {
        libc::EACCES => "EACCES".to_string(),
        libc::EBADF => "EBADF".to_string(),
        libc::EINVAL => "EINVAL".to_string(),
        libc::ENOENT => "ENOENT".to_string(),
        libc::ENOSYS => "ENOSYS".to_string(),
        libc::EOPNOTSUPP => "EOPNOTSUPP".to_string(),
        libc::EPERM => "EPERM".to_string(),
        libc::EROFS => "EROFS".to_string(),
        other => format!("errno={other}"),
    }
}

fn last_errno_name() -> String {
    errno_name(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

fn current_fs_base() -> Result<u64, String> {
    let mut fs_base = 0u64;
    // SAFETY: arch_prctl(ARCH_GET_FS) writes one machine word to the valid
    // `fs_base` pointer and does not retain it after returning.
    let rc = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1003_i32, &raw mut fs_base) };
    if rc == 0 {
        Ok(fs_base)
    } else {
        Err(last_errno_name())
    }
}

fn wait_for_child(pid: libc::pid_t) -> Result<(), String> {
    let mut status = 0;
    loop {
        // SAFETY: `status` is a valid output pointer for waitpid, and `pid`
        // is the process id returned by clone3 in this function.
        let rc = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        if rc == pid {
            if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                return Ok(());
            }
            return Err(format!("child status={status}"));
        }
        let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err != libc::EINTR {
            return Err(errno_name(err));
        }
    }
}

fn run_clone3_with_cgroup(cgroup_fd: u64, exec_target: Option<String>) -> Clone3Out {
    if cgroup_fd != 0 {
        return run_clone3_process(false, None, Some(cgroup_fd as i32), exec_target);
    }
    let path = std::ffi::CString::new("/sys/fs/cgroup").expect("literal has no NUL");
    // SAFETY: `path` is a valid C string. On success, `open` returns a new fd
    // that is immediately wrapped in `OwnedFd` for automatic close.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return clone_result_error(format!(
            "cgroup_fd_unavailable:{}; fallback attempted /sys/fs/cgroup",
            last_errno_name()
        ));
    }
    // SAFETY: `fd` was just returned by `open` and is uniquely owned here.
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    run_clone3_process(false, None, Some(owned.as_raw_fd()), exec_target)
}

fn run_clone_dropbear_vfork() -> Clone3Out {
    let mut pipe_fds = [0i32; 2];
    // SAFETY: `pipe_fds` points to two writable i32 slots for pipe2 to fill.
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return clone_result_error(format!("pipe2:{}", last_errno_name()));
    }
    let flags = (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as usize;
    // SAFETY: This issues the legacy clone syscall shape captured from
    // dropbear: CLONE_VM | CLONE_VFORK, SIGCHLD, and no child stack/TID/TLS
    // pointers. Inline syscalls avoid libc's deprecated `vfork` wrapper and
    // avoid perturbing the shared vfork stack between clone and child exit.
    #[cfg(target_arch = "x86_64")]
    let rc: isize = unsafe {
        let mut rax = libc::SYS_clone as usize;
        core::arch::asm!(
            "syscall",
            inlateout("rax") rax,
            in("rdi") flags,
            in("rsi") 0usize,
            in("rdx") 0usize,
            in("r10") 0usize,
            in("r8") 0usize,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
        rax as isize
    };
    #[cfg(not(target_arch = "x86_64"))]
    let rc = unsafe { libc::vfork() } as isize;
    if rc == 0 {
        // SAFETY: In the vfork child, use only raw syscalls and immutable
        // static data, then terminate with SYS_exit to release the parent.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            {
                core::arch::asm!(
                    "mov rax, rsp",
                    "mov r10, 16",
                    "2:",
                    "sub rax, 4096",
                    "mov byte ptr [rax], 0x5a",
                    "dec r10",
                    "jnz 2b",
                    out("rax") _,
                    out("r10") _,
                    options(nostack),
                );
                core::arch::asm!(
                    "syscall",
                    in("rax") libc::SYS_write as usize,
                    in("rdi") pipe_fds[1] as usize,
                    in("rsi") std::ptr::addr_of!(CLONE3_DROPBEAR_MARKER) as usize,
                    in("rdx") 1usize,
                    lateout("rcx") _,
                    lateout("r11") _,
                    options(nostack),
                );
                core::arch::asm!(
                    "syscall",
                    in("rax") libc::SYS_exit as usize,
                    in("rdi") 0usize,
                    options(noreturn),
                );
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                let _ = libc::syscall(
                    libc::SYS_write,
                    pipe_fds[1],
                    std::ptr::addr_of!(CLONE3_DROPBEAR_MARKER).cast::<libc::c_void>(),
                    1usize,
                );
                libc::_exit(0i32);
            }
        }
    }
    close_fd(pipe_fds[1]);
    if rc < 0 {
        close_fd(pipe_fds[0]);
        return clone_result_error(last_errno_name());
    }
    read_marker_and_wait(pipe_fds[0], rc as libc::pid_t, "dropbear_clone")
}

fn run_clone_dropbear_session_setup(stage: DropbearSessionStage) -> Clone3Out {
    let pty = match Pty::open() {
        Ok(pty) => pty,
        Err(error) => return clone_result_error(format!("pty_open:{error}")),
    };
    let slave_path = match CString::new(pty.slave_path()) {
        Ok(path) => path,
        Err(error) => return clone_result_error(format!("slave_path:{error}")),
    };
    // SAFETY: `slave_path` is a valid C string; on success `slave_fd` is closed
    // by both sides according to their post-clone ownership.
    let slave_fd = unsafe { libc::open(slave_path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if slave_fd < 0 {
        return clone_result_error(format!("open_slave:{}", last_errno_name()));
    }

    let network_fds = if matches!(stage, DropbearSessionStage::FullSetidNetwork) {
        // Dropbear's session child inherits live TCP sockets from the server.
        // Keeping these fds open until the setid calls exercises delayed-fork
        // snapshot rejection before the child reaches execve.
        let fd0 = open_network_socket();
        let fd1 = open_network_socket();
        if fd0 < 0 || fd1 < 0 {
            if fd0 >= 0 {
                close_fd(fd0);
            }
            if fd1 >= 0 {
                close_fd(fd1);
            }
            close_fd(slave_fd);
            return clone_result_error(format!("socket:{}", last_errno_name()));
        }
        [fd0, fd1]
    } else {
        [-1, -1]
    };

    let master_fd = pty.as_raw_fd();
    let echo = c"/bin/echo";
    let bash = c"/bin/bash";
    let true_path = c"/bin/true";
    let echo_arg0 = c"echo";
    let bash_arg0 = c"bash";
    let true_arg0 = c"true";
    let arg1 = c"HELLO_CL3";
    let bash_arg1 = c"-c";
    let bash_arg2 = c"echo HELLO_CL3";
    let echo_argv = [echo_arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];
    let bash_argv = [
        bash_arg0.as_ptr(),
        bash_arg1.as_ptr(),
        bash_arg2.as_ptr(),
        std::ptr::null(),
    ];
    let true_argv = [true_arg0.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null::<libc::c_char>()];

    let flags = (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as usize;
    // This is a handler-based probe because the scenario being tested is the
    // child-side setup done after dropbear's own clone(2); the handler itself
    // creates that fresh child and performs only raw syscalls before execve.
    // SAFETY: The legacy clone syscall uses dropbear's CLONE_VM|CLONE_VFORK
    // shape. The child does not run Rust destructors or allocate before exec.
    #[cfg(target_arch = "x86_64")]
    let rc: isize = unsafe {
        let mut rax = libc::SYS_clone as usize;
        core::arch::asm!(
            "syscall",
            inlateout("rax") rax,
            in("rdi") flags,
            in("rsi") 0usize,
            in("rdx") 0usize,
            in("r10") 0usize,
            in("r8") 0usize,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
        rax as isize
    };
    #[cfg(not(target_arch = "x86_64"))]
    let rc = unsafe { libc::vfork() } as isize;

    if rc == 0 {
        // SAFETY: vfork child: use raw syscalls only, then execve or _exit.
        unsafe {
            match stage {
                DropbearSessionStage::ExecOnly => {}
                DropbearSessionStage::Setsid
                | DropbearSessionStage::DupStdio
                | DropbearSessionStage::Tiocsctty
                | DropbearSessionStage::Full
                | DropbearSessionStage::FullBash
                | DropbearSessionStage::FullSetidNetwork => {
                    if libc::syscall(libc::SYS_setsid) < 0 {
                        libc::syscall(libc::SYS_exit, 111i32);
                    }
                }
            }
            match stage {
                DropbearSessionStage::ExecOnly
                | DropbearSessionStage::Setsid
                | DropbearSessionStage::DupStdio => {}
                DropbearSessionStage::Tiocsctty
                | DropbearSessionStage::Full
                | DropbearSessionStage::FullBash
                | DropbearSessionStage::FullSetidNetwork => {
                    if libc::syscall(libc::SYS_ioctl, slave_fd, libc::TIOCSCTTY, 0usize) < 0 {
                        libc::syscall(libc::SYS_exit, 112i32);
                    }
                }
            }
            match stage {
                DropbearSessionStage::ExecOnly
                | DropbearSessionStage::Setsid
                | DropbearSessionStage::Tiocsctty => {}
                DropbearSessionStage::DupStdio
                | DropbearSessionStage::Full
                | DropbearSessionStage::FullBash
                | DropbearSessionStage::FullSetidNetwork => {
                    for target in 0..=2 {
                        if libc::syscall(libc::SYS_dup2, slave_fd, target) < 0 {
                            libc::syscall(libc::SYS_exit, 113i32);
                        }
                    }
                }
            }
            if matches!(stage, DropbearSessionStage::FullSetidNetwork) {
                let gid = libc::syscall(libc::SYS_getgid);
                if libc::syscall(libc::SYS_setgid, gid) < 0 {
                    libc::syscall(libc::SYS_exit, 114i32);
                }
                let uid = libc::syscall(libc::SYS_getuid);
                if libc::syscall(libc::SYS_setuid, uid) < 0 {
                    libc::syscall(libc::SYS_exit, 115i32);
                }
            }
            if slave_fd > 2 {
                libc::syscall(libc::SYS_close, slave_fd);
            }
            libc::syscall(libc::SYS_close, master_fd);
            match stage {
                DropbearSessionStage::DupStdio | DropbearSessionStage::Full => {
                    libc::syscall(
                        libc::SYS_execve,
                        echo.as_ptr(),
                        echo_argv.as_ptr(),
                        envp.as_ptr(),
                    );
                }
                DropbearSessionStage::FullBash => {
                    libc::syscall(
                        libc::SYS_execve,
                        bash.as_ptr(),
                        bash_argv.as_ptr(),
                        envp.as_ptr(),
                    );
                }
                DropbearSessionStage::ExecOnly
                | DropbearSessionStage::Setsid
                | DropbearSessionStage::Tiocsctty
                | DropbearSessionStage::FullSetidNetwork => {
                    libc::syscall(
                        libc::SYS_execve,
                        true_path.as_ptr(),
                        true_argv.as_ptr(),
                        envp.as_ptr(),
                    );
                }
            }
            libc::syscall(libc::SYS_exit, 127i32);
        }
        unreachable!();
    }

    close_fd(slave_fd);
    for fd in network_fds {
        if fd >= 0 {
            close_fd(fd);
        }
    }
    if rc < 0 {
        return clone_result_error(last_errno_name());
    }
    let pid = rc as libc::pid_t;
    if stage.uses_pty_stdio() {
        match pty.read(None) {
            Ok(data) if data.contains("HELLO_CL3") => {}
            Ok(data) => {
                let _ = wait_child_timeout(pid, Duration::from_secs(1));
                return clone_result_error(format!("missing HELLO_CL3 in pty data {data:?}"));
            }
            Err(error) => {
                let _ = wait_child_timeout(pid, Duration::from_secs(1));
                return clone_result_error(format!("pty_read:{error}"));
            }
        }
    }
    match wait_child_timeout(pid, Duration::from_secs(10)) {
        Ok(0) => Clone3Out {
            pid: pid as u64,
            pidfd: None,
            ok: true,
            error: None,
        },
        Ok(status) => clone_result_error(format!("child_status:{status}")),
        Err(error) => clone_result_error(format!("wait:{error}")),
    }
}

fn open_network_socket() -> i32 {
    // SAFETY: socket returns a new fd or -1; caller owns successful fds.
    unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) }
}

fn read_marker_and_wait(read_fd: i32, pid: libc::pid_t, label: &str) -> Clone3Out {
    let mut byte = [0u8; 1];
    // SAFETY: `byte` is a valid one-byte output buffer and `read_fd` is a
    // live read end created by the caller.
    let read_rc = unsafe { libc::read(read_fd, byte.as_mut_ptr().cast(), byte.len()) };
    close_fd(read_fd);
    if read_rc != 1 || byte[0] != CLONE3_DROPBEAR_MARKER {
        let _ = wait_for_child(pid);
        return clone_result_error(format!(
            "{label}_marker_failed:read={read_rc},byte={}",
            byte[0]
        ));
    }
    if let Err(error) = wait_for_child(pid) {
        return Clone3Out {
            pid: pid as u64,
            pidfd: None,
            ok: false,
            error: Some(format!("wait:{error}")),
        };
    }
    Clone3Out {
        pid: pid as u64,
        pidfd: None,
        ok: true,
        error: None,
    }
}

fn run_clone3_dropbear_vfork() -> Clone3Out {
    let mut pipe_fds = [0i32; 2];
    // SAFETY: `pipe_fds` points to two writable i32 slots for pipe2 to fill.
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return clone_result_error(format!("pipe2:{}", last_errno_name()));
    }
    let mut args = CloneArgs {
        flags: (libc::CLONE_VM | libc::CLONE_VFORK) as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    // SAFETY: `args` is a clone_args-compatible struct and lives for the
    // syscall. The vfork child performs only raw syscalls, then exits via
    // SYS_exit so the parent resumes before Rust code continues.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &raw mut args,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if rc == 0 {
        // SAFETY: In the vfork child, use only raw syscalls and immutable
        // static data, then terminate with SYS_exit to release the parent.
        unsafe {
            let _ = libc::syscall(
                libc::SYS_write,
                pipe_fds[1],
                std::ptr::addr_of!(CLONE3_DROPBEAR_MARKER).cast::<libc::c_void>(),
                1usize,
            );
            libc::syscall(libc::SYS_exit, 0i32);
        }
        unreachable!();
    }
    close_fd(pipe_fds[1]);
    if rc < 0 {
        close_fd(pipe_fds[0]);
        return clone_result_error(last_errno_name());
    }
    let pid = rc as libc::pid_t;
    let mut byte = [0u8; 1];
    // SAFETY: `byte` is a valid one-byte output buffer and `pipe_fds[0]` is a
    // live read end created above.
    let read_rc = unsafe { libc::read(pipe_fds[0], byte.as_mut_ptr().cast(), byte.len()) };
    close_fd(pipe_fds[0]);
    if read_rc != 1 || byte[0] != CLONE3_DROPBEAR_MARKER {
        let _ = wait_for_child(pid);
        return clone_result_error(format!(
            "dropbear_vfork_marker_failed:read={read_rc},byte={}",
            byte[0]
        ));
    }
    if let Err(error) = wait_for_child(pid) {
        return Clone3Out {
            pid: pid as u64,
            pidfd: None,
            ok: false,
            error: Some(format!("wait:{error}")),
        };
    }
    Clone3Out {
        pid: pid as u64,
        pidfd: None,
        ok: true,
        error: None,
    }
}

fn run_clone3_vfork() -> Clone3Out {
    CLONE3_VFORK_STAGE.store(0, Ordering::SeqCst);
    let mut child_tid = 0i32;
    let mut args = CloneArgs {
        flags: (libc::CLONE_VM | libc::CLONE_VFORK | libc::CLONE_CHILD_CLEARTID) as u64,
        child_tid: (&raw mut child_tid).addr() as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    // SAFETY: `args` is a clone_args-compatible struct and lives for the
    // syscall. The vfork child performs only raw syscalls and atomics, then
    // terminates with SYS_exit so the parent resumes without Rust unwinding.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &raw mut args,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if rc == 0 {
        // SAFETY: In the vfork child, use only raw syscalls and atomic stores
        // before SYS_exit; SYS_exit releases the suspended parent.
        unsafe {
            CLONE3_VFORK_STAGE.store(1, Ordering::SeqCst);
            for _ in 0..20_000 {
                let _ = libc::syscall(libc::SYS_sched_yield);
            }
            CLONE3_VFORK_STAGE.store(2, Ordering::SeqCst);
            libc::syscall(libc::SYS_exit, 0i32);
        }
        unreachable!();
    }
    if rc < 0 {
        return clone_result_error(last_errno_name());
    }
    let pid = rc as libc::pid_t;
    let stage_after_return = CLONE3_VFORK_STAGE.load(Ordering::SeqCst);
    if stage_after_return != 2 {
        let _ = wait_for_child(pid);
        return Clone3Out {
            pid: pid as u64,
            pidfd: None,
            ok: false,
            error: Some(format!(
                "vfork_parent_resumed_before_child_exit:stage={stage_after_return}"
            )),
        };
    }
    if let Err(error) = wait_for_child(pid) {
        return Clone3Out {
            pid: pid as u64,
            pidfd: None,
            ok: false,
            error: Some(format!("wait:{error}")),
        };
    }
    Clone3Out {
        pid: pid as u64,
        pidfd: None,
        ok: true,
        error: None,
    }
}

fn run_clone3_thread() -> Clone3Out {
    let mut pipe_fds = [0i32; 2];
    // SAFETY: `pipe_fds` points to two writable i32 slots for pipe2 to fill.
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return clone_result_error(format!("pipe2:{}", last_errno_name()));
    }
    CLONE3_THREAD_WRITE_FD.store(pipe_fds[1], Ordering::SeqCst);
    CLONE3_THREAD_TID.store(0, Ordering::SeqCst);
    let mut parent_tid = 0i32;
    let mut child_tid = 0i32;
    let tls = match current_fs_base() {
        Ok(tls) => tls,
        Err(error) => {
            close_fd(pipe_fds[0]);
            close_fd(pipe_fds[1]);
            return clone_result_error(format!("ARCH_GET_FS:{error}"));
        }
    };
    let mut args = CloneArgs {
        flags: (libc::CLONE_VM
            | libc::CLONE_THREAD
            | libc::CLONE_SIGHAND
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID) as u64,
        parent_tid: (&raw mut parent_tid).addr() as u64,
        child_tid: (&raw mut child_tid).addr() as u64,
        tls,
        ..CloneArgs::default()
    };
    // SAFETY: `args` points to a clone_args-compatible struct for the duration
    // of the syscall. The child thread only performs raw syscalls and exits via
    // SYS_exit, avoiding Rust destructors in the manually-created thread.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &raw mut args,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if rc == 0 {
        // SAFETY: In the clone3-created thread, use only raw syscalls and shared
        // atomics/fds, then terminate this thread with SYS_exit (not exit_group).
        unsafe {
            let tid = libc::syscall(libc::SYS_gettid) as i32;
            CLONE3_THREAD_TID.store(tid, Ordering::SeqCst);
            let fd = CLONE3_THREAD_WRITE_FD.load(Ordering::SeqCst);
            let _ = libc::syscall(
                libc::SYS_write,
                fd,
                std::ptr::addr_of!(CLONE3_THREAD_SIGNAL).cast::<libc::c_void>(),
                1usize,
            );
            libc::syscall(libc::SYS_exit, 0i32);
        }
        unreachable!();
    }
    close_fd(pipe_fds[1]);
    if rc < 0 {
        close_fd(pipe_fds[0]);
        return clone_result_error(last_errno_name());
    }
    let mut byte = [0u8; 1];
    // SAFETY: `byte` is a valid one-byte output buffer and `pipe_fds[0]` is a
    // live read end created above.
    let read_rc = unsafe { libc::read(pipe_fds[0], byte.as_mut_ptr().cast(), byte.len()) };
    close_fd(pipe_fds[0]);
    let tid = CLONE3_THREAD_TID.load(Ordering::SeqCst);
    if read_rc == 1 && tid > 0 {
        Clone3Out {
            pid: tid as u64,
            pidfd: None,
            ok: true,
            error: None,
        }
    } else {
        clone_result_error(format!("thread_signal_failed:read={read_rc},tid={tid}"))
    }
}

fn run_clone3_process(
    with_pidfd: bool,
    set_tid: Option<u64>,
    cgroup_fd: Option<i32>,
    exec_target: Option<String>,
) -> Clone3Out {
    let mut pidfd = -1i32;
    let mut child_tid = 0i32;
    let mut requested_tid = set_tid.unwrap_or(0);
    let mut args = CloneArgs {
        flags: libc::CLONE_CHILD_CLEARTID as u64,
        child_tid: (&raw mut child_tid).addr() as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    if with_pidfd {
        args.flags |= libc::CLONE_PIDFD as u64;
        args.pidfd = (&raw mut pidfd).addr() as u64;
    }
    if set_tid.is_some() {
        args.set_tid = (&raw mut requested_tid).addr() as u64;
        args.set_tid_size = 1;
    }
    if let Some(fd) = cgroup_fd {
        // CLONE_INTO_CGROUP is glibc-only in the libc crate (as of
        // libc 0.2.x); musl doesn't expose it. Hard-code the kernel
        // value (0x200000000) when the symbol is missing — it's an
        // ABI-stable kernel constant.
        const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
        args.flags |= CLONE_INTO_CGROUP;
        args.cgroup = fd as u64;
    }
    // SAFETY: `args` is a clone_args-compatible struct. The child immediately
    // execs `/bin/sh -c true` or exits via a raw SYS_exit if exec fails.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &raw mut args,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if rc == 0 {
        // SAFETY: NUL-terminated strings; execl/execv either replaces
        // the process image or returns, after which SYS_exit ends only
        // the child process.
        unsafe {
            if let Some(target) = exec_target {
                let target_c = std::ffi::CString::new(target.as_str())
                    .unwrap_or_else(|_| std::ffi::CString::new("/bin/false").unwrap());
                let arg0 = std::ffi::CString::new(target.as_str())
                    .unwrap_or_else(|_| std::ffi::CString::new("/bin/false").unwrap());
                let arg1 = c"echo-test";
                libc::execl(
                    target_c.as_ptr(),
                    arg0.as_ptr(),
                    arg1.as_ptr(),
                    std::ptr::null::<libc::c_char>(),
                );
            } else {
                let shell = c"/bin/sh";
                let arg0 = c"sh";
                let arg1 = c"-c";
                let arg2 = c"getpid >/dev/null; exit 0";
                libc::execl(
                    shell.as_ptr(),
                    arg0.as_ptr(),
                    arg1.as_ptr(),
                    arg2.as_ptr(),
                    std::ptr::null::<libc::c_char>(),
                );
            }
            libc::syscall(libc::SYS_exit, 127i32);
        }
        unreachable!();
    }
    if rc < 0 {
        return Clone3Out {
            pid: 0,
            pidfd: None,
            ok: false,
            error: Some(last_errno_name()),
        };
    }
    let pid = rc as libc::pid_t;
    let wait = wait_for_child(pid);
    if let Err(error) = &wait {
        if pidfd >= 0 {
            close_fd(pidfd);
        }
        return Clone3Out {
            pid: pid as u64,
            pidfd: None,
            ok: false,
            error: Some(format!("wait:{error}")),
        };
    }
    if with_pidfd && pidfd < 0 {
        return Clone3Out {
            pid: pid as u64,
            pidfd: None,
            ok: false,
            error: Some("missing_pidfd".to_string()),
        };
    }
    Clone3Out {
        pid: pid as u64,
        // Keep the pidfd open in this short-lived agent so the reported fd
        // remains a valid kernel result for the duration of the response.
        pidfd: with_pidfd.then_some(pidfd),
        ok: true,
        error: None,
    }
}

fn close_fd(fd: i32) {
    // SAFETY: Closing an fd is safe; errors are intentionally ignored because
    // cleanup should not mask the operation being tested.
    unsafe {
        libc::close(fd);
    }
}
