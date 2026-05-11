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

use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
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

// ─── Typed handler tokens ───────────────────────────────────────────

const THREAD: HandlerToken<(), Clone3Out> = HandlerToken::new("clone3.thread");
const PROCESS: HandlerToken<Clone3ExecArgs, Clone3Out> = HandlerToken::new("clone3.process");
const WITH_PIDFD: HandlerToken<Clone3ExecArgs, Clone3Out> = HandlerToken::new("clone3.with_pidfd");
const WITH_SET_TID: HandlerToken<Clone3ExecArgs, Clone3Out> =
    HandlerToken::new("clone3.with_set_tid");
const WITH_CGROUP: HandlerToken<Clone3ExecArgs, Clone3Out> =
    HandlerToken::new("clone3.with_cgroup");
const VFORK: HandlerToken<(), Clone3Out> = HandlerToken::new("clone3.vfork");

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

// ─── Registration ──────────────────────────────────────────────────

pub(crate) fn register_clone3_matrix(reg: &mut Registry<'_>) {
    register_handler!(THREAD, handle_thread);
    register_handler!(PROCESS, handle_process);
    register_handler!(WITH_PIDFD, handle_with_pidfd);
    register_handler!(WITH_SET_TID, handle_with_set_tid);
    register_handler!(WITH_CGROUP, handle_with_cgroup);
    register_handler!(VFORK, handle_vfork);

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
