// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Minimal fork + pipe-fd inheritance probes.
//!
//! These probes run as fresh argv leaves rather than handlers because they
//! specifically exercise a process-local `pipe2` followed by raw `fork()` and
//! use the inherited pipe fd in the child before any exec or harness protocol
//! activity can add unrelated fd-transfer semantics.

use std::process::Command;

use super::TestOutcome;
use super::registry::Registry;

const PIPE_FD_INHERITANCE_SUBCMD: &str = "fork-pipe-fd-inheritance";

pub(crate) fn register_fork_pipe_inheritance_tests(reg: &mut Registry<'_>) {
    crate::register_leaf_subcommand!(
        "fork-pipe-fd-inheritance",
        leaf_subcmd::subcmd_pipe_fd_inheritance
    );

    for &bt in crate::BinaryType::ALL {
        let label = bt.label();
        reg.test(
            "vscode",
            "fork",
            format!("FORK.pipe_fd_inheritance.{label}"),
        )
        .timeout(30)
        .build(move |_cx| {
            Box::new(move |run| {
                Box::pin(async move {
                    let self_exe = run.self_exe().to_string();
                    let child_binary = crate::binary_path(bt, &self_exe);
                    let output = Command::new(&child_binary)
                        .arg(PIPE_FD_INHERITANCE_SUBCMD)
                        .output();
                    match output {
                        Ok(out) => {
                            let stdout = String::from_utf8_lossy(&out.stdout);
                            let stderr = String::from_utf8_lossy(&out.stderr);
                            TestOutcome::new(
                                label,
                                out.status.success() && stdout.starts_with("PASS"),
                                format!(
                                    "{child_binary} status={} stdout={stdout:?} stderr={stderr:?}",
                                    out.status
                                ),
                            )
                        }
                        Err(e) => {
                            TestOutcome::new(label, false, format!("spawn {child_binary}: {e}"))
                        }
                    }
                })
            })
        });
    }
}

mod leaf_subcmd {
    /// Fresh-process minimal fork+pipe-fd inheritance probe. This cannot be a
    /// handler because the child must be a direct raw `fork()` child of the
    /// process that created the pipe, with no harness protocol fd passing.
    pub(super) fn subcmd_pipe_fd_inheritance(_args: &[String]) -> i32 {
        match run_pipe_fd_inheritance() {
            Ok(detail) => {
                println!("PASS {detail}");
                0
            }
            Err(e) => {
                println!("FAIL {e}");
                1
            }
        }
    }

    fn run_pipe_fd_inheritance() -> Result<String, String> {
        let pipe_fds = pipe2_cloexec()?;
        let pid = fork()?;
        if pid == 0 {
            // SAFETY: the fork child avoids Rust unwinding and exits via
            // `_exit` after using only async-signal-safe reporting on failure.
            unsafe {
                let code = match child_epoll_add_pipe_read_end(pipe_fds[0]) {
                    Ok(()) => {
                        let _ = write_all(libc::STDOUT_FILENO, b"PASS child epoll_ctl ADD ok\n");
                        0
                    }
                    Err(e) => {
                        let _ = write_all(
                            libc::STDOUT_FILENO,
                            format!("FAIL child epoll_ctl ADD failed: {e}\n").as_bytes(),
                        );
                        1
                    }
                };
                libc::_exit(code);
            }
        }

        wait_for_child(pid)?;
        Ok(format!(
            "child {pid} epoll_ctl ADD accepted inherited pipe read fd"
        ))
    }

    fn pipe2_cloexec() -> Result<[i32; 2], String> {
        let mut fds = [0i32; 2];
        // SAFETY: `fds` points to two valid i32 slots for `pipe2` to initialize.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if rc != 0 {
            return Err(format!("pipe2: {}", std::io::Error::last_os_error()));
        }
        Ok(fds)
    }

    fn fork() -> Result<libc::pid_t, String> {
        // SAFETY: `fork` has no Rust-side preconditions; the child immediately
        // runs a tiny syscall-only path and exits via `_exit`.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            Err(format!("fork: {}", std::io::Error::last_os_error()))
        } else {
            Ok(pid)
        }
    }

    fn child_epoll_add_pipe_read_end(pipe_read_fd: i32) -> Result<(), String> {
        // SAFETY: `epoll_create1` has no pointer arguments.
        let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if ep < 0 {
            return Err(format!(
                "epoll_create1: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: 1,
        };
        // SAFETY: `event` points to a valid `epoll_event`; `ep` is the epoll fd
        // just created and `pipe_read_fd` is the inherited read end under test.
        let rc = unsafe {
            libc::epoll_ctl(
                ep,
                libc::EPOLL_CTL_ADD,
                pipe_read_fd,
                std::ptr::addr_of_mut!(event),
            )
        };
        let epoll_err = if rc != 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        // SAFETY: `ep` is a valid fd from `epoll_create1`; close errors do not
        // affect the probe result.
        unsafe {
            libc::close(ep);
        }
        match epoll_err {
            Some(e) => Err(format!("epoll_ctl ADD pipe read fd: {e}")),
            None => Ok(()),
        }
    }

    fn wait_for_child(pid: libc::pid_t) -> Result<(), String> {
        let mut status = 0;
        loop {
            // SAFETY: `status` is a valid out pointer and `pid` is the child
            // returned by `fork` above.
            let rc = unsafe { libc::waitpid(pid, std::ptr::addr_of_mut!(status), 0) };
            if rc == pid {
                break;
            }
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(format!("waitpid({pid}): {err}"));
            }
        }

        if libc::WIFEXITED(status) {
            let code = libc::WEXITSTATUS(status);
            if code == 0 {
                Ok(())
            } else {
                Err(format!("child exited {code}"))
            }
        } else if libc::WIFSIGNALED(status) {
            Err(format!("child killed by signal {}", libc::WTERMSIG(status)))
        } else {
            Err(format!("child unexpected wait status {status:#x}"))
        }
    }

    fn write_all(fd: i32, mut bytes: &[u8]) -> Result<(), ()> {
        while !bytes.is_empty() {
            // SAFETY: `bytes.as_ptr()` is valid for `bytes.len()` bytes and the
            // child writes to an inherited stdout fd.
            let rc = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(());
            }
            let n = usize::try_from(rc).map_err(|_| ())?;
            if n == 0 {
                return Err(());
            }
            bytes = &bytes[n..];
        }
        Ok(())
    }
}
