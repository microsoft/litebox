// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Isolated HypB probes for broker pipe readiness notification flushing.
//!
//! These tests deliberately execute an argv leaf binary directly from the
//! coordinator instead of using harness agents. The leaf performs the pipe,
//! fork, write, epoll, and waitpid syscalls itself, so failures are not
//! entangled with the tokio-based agent control socket or SCM_RIGHTS teardown.

use std::process::Command;

use super::TestOutcome;
use super::registry::Registry;

const PIPE_DOUBLE_WAKE_SUBCMD: &str = "hypb-pipe-double-wake";
const PIPE_DOUBLE_WAKE_BINARY_TYPES: &[crate::BinaryType] = crate::BinaryType::ALL;

pub(crate) fn register_hypb_tests(reg: &mut Registry<'_>) {
    crate::register_leaf_subcommand!(
        "hypb-pipe-double-wake",
        leaf_subcmd::subcmd_pipe_double_wake
    );

    for &bt in PIPE_DOUBLE_WAKE_BINARY_TYPES {
        let label = bt.label();
        reg.test("vscode", "hypb", format!("HypB.pipe_double_wake.{label}"))
            .timeout(30)
            .build(move |_cx| {
                Box::new(move |run| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let child_binary = crate::binary_path(bt, &self_exe);
                        let output = Command::new(&child_binary)
                            .arg(PIPE_DOUBLE_WAKE_SUBCMD)
                            .output();
                        match output {
                            Ok(out) => {
                                let stdout = String::from_utf8_lossy(&out.stdout);
                                let stderr = String::from_utf8_lossy(&out.stderr);
                                let detail =
                                    format!("{child_binary} stdout={stdout:?} stderr={stderr:?}");
                                TestOutcome::new(
                                    label,
                                    out.status.success() && stdout.starts_with("PASS"),
                                    detail,
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
    use std::time::Instant;

    const TIMEOUT_MS: i32 = 2000;

    /// Fresh-process HypB probe. This is an argv leaf, not a handler, because
    /// the test must avoid the tokio agent runtime entirely and must let the
    /// producer process exit close its pipe write end implicitly.
    pub(super) fn subcmd_pipe_double_wake(_args: &[String]) -> i32 {
        match run_pipe_double_wake() {
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

    fn run_pipe_double_wake() -> Result<String, String> {
        let data = pipe("data pipe")?;
        let ready = pipe("ready pipe")?;

        let consumer = fork("consumer fork")?;
        if consumer == 0 {
            // SAFETY: child owns inherited raw fds and exits via _exit.
            unsafe {
                let code = match consumer_main(data[0], ready[1]) {
                    Ok(detail) => {
                        let _ = write_all(
                            libc::STDOUT_FILENO,
                            format!("PASS consumer PASS {detail}\n").as_bytes(),
                        );
                        0
                    }
                    Err(e) => {
                        let _ = write_all(
                            libc::STDOUT_FILENO,
                            format!("FAIL consumer FAIL {e}\n").as_bytes(),
                        );
                        1
                    }
                };
                libc::_exit(code);
            }
        }

        // This process is the producer. After the two writes it exits via _exit,
        // so the write end is closed by process teardown rather than close(2).
        // SAFETY: producer never writes to the readiness pipe; closing this end
        // lets setup failures in the consumer surface as EOF instead of a hang.
        unsafe { close_fd(ready[1]) };
        read_ready(ready[0])?;
        producer_main(data[1])?;
        unsafe { libc::_exit(0) }
    }

    fn consumer_main(pipe_read_fd: i32, ready_signal_fd: i32) -> Result<String, String> {
        let ep = epoll_create()?;
        epoll_add(ep, pipe_read_fd)?;
        write_all(ready_signal_fd, b"R")?;
        // SAFETY: ready notification has been sent; this child no longer needs the fd.
        unsafe { close_fd(ready_signal_fd) };

        let wake1 = wait_and_read(ep, pipe_read_fd, "wake1", b'x')?;
        let wake2 = wait_and_read(ep, pipe_read_fd, "wake2", b'y')?;

        // SAFETY: consumer is done with epoll and the data pipe before reporting success.
        unsafe {
            close_fd(ep);
            close_fd(pipe_read_fd);
        }
        Ok(format!(
            "wake1={}ms events={:#x}; wake2={}ms events={:#x}",
            wake1.elapsed_ms, wake1.events, wake2.elapsed_ms, wake2.events
        ))
    }

    fn producer_main(write_fd: i32) -> Result<(), String> {
        write_all(write_fd, b"x").map_err(|e| format!("producer write 'x': {e}"))?;
        write_all(write_fd, b"y").map_err(|e| format!("producer write 'y': {e}"))?;
        // Deliberately do not close write_fd here. _exit closes it implicitly.
        Ok(())
    }

    struct Wake {
        elapsed_ms: u128,
        events: u32,
    }

    fn wait_and_read(ep: i32, read_fd: i32, wake: &str, expected: u8) -> Result<Wake, String> {
        let started = Instant::now();
        let events = epoll_wait_one(ep, TIMEOUT_MS)?;
        let elapsed_ms = started.elapsed().as_millis();
        if events == 0 {
            return Err(format!(
                "probe line {wake}: epoll_wait({TIMEOUT_MS}) timed out without EPOLLIN — deferred-edge bit orphaned (HypB)"
            ));
        }
        if events & libc::EPOLLIN as u32 == 0 {
            return Err(format!(
                "probe line {wake}: epoll_wait returned events={events:#x} without EPOLLIN"
            ));
        }
        let byte = read_one(read_fd).map_err(|e| format!("probe line {wake}: {e}"))?;
        if byte != expected {
            return Err(format!(
                "probe line {wake}: read expected {:?}, got {:?}",
                expected as char, byte as char
            ));
        }
        Ok(Wake { elapsed_ms, events })
    }

    fn pipe(context: &str) -> Result<[i32; 2], String> {
        let mut fds = [0i32; 2];
        // SAFETY: fds points at two valid i32 slots for pipe2 to initialize.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if rc != 0 {
            return Err(format!("{context}: {}", std::io::Error::last_os_error()));
        }
        Ok(fds)
    }

    fn fork(context: &str) -> Result<libc::pid_t, String> {
        // SAFETY: fork has no Rust-side preconditions; children immediately avoid unwinding.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            Err(format!("{context}: {}", std::io::Error::last_os_error()))
        } else {
            Ok(pid)
        }
    }

    fn epoll_create() -> Result<i32, String> {
        // SAFETY: epoll_create1 has no pointer arguments.
        let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if ep < 0 {
            Err(format!(
                "epoll_create1: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(ep)
        }
    }

    fn epoll_add(ep: i32, read_fd: i32) -> Result<(), String> {
        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: 1,
        };
        // SAFETY: event points to a valid epoll_event; ep and read_fd are live fds.
        let rc = unsafe {
            libc::epoll_ctl(
                ep,
                libc::EPOLL_CTL_ADD,
                read_fd,
                std::ptr::addr_of_mut!(event),
            )
        };
        if rc != 0 {
            Err(format!(
                "epoll_ctl add pipe read end: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(())
        }
    }

    fn epoll_wait_one(ep: i32, timeout_ms: i32) -> Result<u32, String> {
        let mut event = libc::epoll_event { events: 0, u64: 0 };
        loop {
            // SAFETY: event points to one valid epoll_event output slot.
            let rc = unsafe { libc::epoll_wait(ep, std::ptr::addr_of_mut!(event), 1, timeout_ms) };
            if rc > 0 {
                return Ok(event.events);
            }
            if rc == 0 {
                return Ok(0);
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!("epoll_wait: {err}"));
        }
    }

    fn read_one(fd: i32) -> Result<u8, String> {
        let mut byte = [0u8; 1];
        loop {
            // SAFETY: byte is a valid one-byte writable buffer; fd is live.
            let rc = unsafe { libc::read(fd, byte.as_mut_ptr().cast::<libc::c_void>(), 1) };
            if rc == 1 {
                return Ok(byte[0]);
            }
            if rc == 0 {
                return Err("read returned EOF".to_string());
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!("read: {err}"));
        }
    }

    fn read_ready(fd: i32) -> Result<(), String> {
        let byte = read_one(fd)?;
        if byte == b'R' {
            Ok(())
        } else {
            Err(format!("ready pipe: expected 'R', got {byte:?}"))
        }
    }

    fn write_all(fd: i32, mut data: &[u8]) -> Result<(), String> {
        while !data.is_empty() {
            // SAFETY: data points to a valid readable buffer; fd is live.
            let rc = unsafe { libc::write(fd, data.as_ptr().cast::<libc::c_void>(), data.len()) };
            if rc > 0 {
                let written = usize::try_from(rc).map_err(|e| format!("write size: {e}"))?;
                data = &data[written..];
                continue;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!("write: {err}"));
        }
        Ok(())
    }

    unsafe fn close_fd(fd: i32) {
        // SAFETY: callers pass raw fds they no longer use; close errors are non-actionable here.
        let _ = unsafe { libc::close(fd) };
    }
}
