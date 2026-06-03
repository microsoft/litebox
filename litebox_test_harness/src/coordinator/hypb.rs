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

const PIPE_WAKE_SUBCMD: &str = "hypb-pipe-wake";
const PIPE_WAKE_BINARY_TYPES: &[crate::BinaryType] = crate::BinaryType::ALL;

struct PipeWakeScenario {
    id: &'static str,
    arg: &'static str,
}

const PIPE_WAKE_SCENARIOS: &[PipeWakeScenario] = &[
    PipeWakeScenario {
        id: "pipe_double_wake",
        arg: "double-wake",
    },
    PipeWakeScenario {
        id: "pipe_single_wake_no_exit",
        arg: "single-wake-no-exit",
    },
    PipeWakeScenario {
        id: "pipe_wake_explicit_close",
        arg: "wake-explicit-close",
    },
    PipeWakeScenario {
        id: "pipe_wake_epollin_hup",
        arg: "wake-epollin-hup",
    },
    PipeWakeScenario {
        id: "pipe_read_no_epoll",
        arg: "read-no-epoll",
    },
    PipeWakeScenario {
        id: "pipe_wake_create_after_fork",
        arg: "wake-create-after-fork",
    },
];

pub(crate) fn register_hypb_tests(reg: &mut Registry<'_>) {
    crate::register_leaf_subcommand!("hypb-pipe-wake", leaf_subcmd::subcmd_pipe_wake);

    for scenario in PIPE_WAKE_SCENARIOS {
        for &bt in PIPE_WAKE_BINARY_TYPES {
            let label = bt.label();
            let test_id = format!("HypB.{}.{label}", scenario.id);
            let scenario_arg = scenario.arg;
            reg.test("vscode", "hypb", test_id)
                .timeout(30)
                .build(move |_cx| {
                    Box::new(move |run| {
                        Box::pin(async move {
                            let self_exe = run.self_exe().to_string();
                            let child_binary = crate::binary_path(bt, &self_exe);
                            let output = Command::new(&child_binary)
                                .arg(PIPE_WAKE_SUBCMD)
                                .arg(scenario_arg)
                                .output();
                            match output {
                                Ok(out) => {
                                    let stdout = String::from_utf8_lossy(&out.stdout);
                                    let stderr = String::from_utf8_lossy(&out.stderr);
                                    let detail = format!(
                                        "{child_binary} {scenario_arg} stdout={stdout:?} stderr={stderr:?}"
                                    );
                                    TestOutcome::new(
                                        label,
                                        out.status.success() && stdout.starts_with("PASS"),
                                        detail,
                                    )
                                }
                                Err(e) => TestOutcome::new(
                                    label,
                                    false,
                                    format!("spawn {child_binary}: {e}"),
                                ),
                            }
                        })
                    })
                });
        }
    }
}

mod leaf_subcmd {
    use std::time::Instant;

    const TIMEOUT_MS: i32 = 2000;

    #[derive(Copy, Clone)]
    enum Scenario {
        DoubleWake,
        SingleWakeNoExit,
        WakeExplicitClose,
        WakeEpollInHup,
        ReadNoEpoll,
        WakeCreateAfterFork,
    }

    /// Fresh-process HypB probe. This is an argv leaf, not a handler, because
    /// the test must avoid the tokio agent runtime entirely and some variants
    /// must let process exit close pipe write ends implicitly.
    pub(super) fn subcmd_pipe_wake(args: &[String]) -> i32 {
        let Some(arg) = args.get(2) else {
            println!("FAIL missing HypB pipe-wake scenario");
            return 1;
        };
        let scenario = match arg.as_str() {
            "double-wake" => Scenario::DoubleWake,
            "single-wake-no-exit" => Scenario::SingleWakeNoExit,
            "wake-explicit-close" => Scenario::WakeExplicitClose,
            "wake-epollin-hup" => Scenario::WakeEpollInHup,
            "read-no-epoll" => Scenario::ReadNoEpoll,
            "wake-create-after-fork" => Scenario::WakeCreateAfterFork,
            other => {
                println!("FAIL unknown HypB pipe-wake scenario {other}");
                return 1;
            }
        };

        match run_pipe_wake(scenario) {
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

    fn run_pipe_wake(scenario: Scenario) -> Result<String, String> {
        match scenario {
            Scenario::WakeCreateAfterFork => run_pipe_wake_create_after_fork(),
            Scenario::DoubleWake
            | Scenario::SingleWakeNoExit
            | Scenario::WakeExplicitClose
            | Scenario::WakeEpollInHup
            | Scenario::ReadNoEpoll => run_parent_created_pipe_wake(scenario),
        }
    }

    fn run_parent_created_pipe_wake(scenario: Scenario) -> Result<String, String> {
        let data = pipe("data pipe")?;
        let ready = pipe("ready pipe")?;

        let consumer = fork("consumer fork")?;
        if consumer == 0 {
            // SAFETY: child owns inherited raw fds and exits via _exit.
            unsafe {
                let code = match consumer_main(data[0], ready[1], scenario) {
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

        // This process is the producer for the parent-created-pipe variants.
        // SAFETY: producer never writes to the readiness pipe; closing this end
        // lets setup failures in the consumer surface as EOF instead of a hang.
        unsafe { close_fd(ready[1]) };
        read_ready(ready[0])?;
        producer_main(data[1], scenario)?;

        match scenario {
            Scenario::SingleWakeNoExit => {
                let status = wait_for_child(consumer, "consumer")?;
                if child_exited_successfully(status) {
                    Ok("producer stayed alive until consumer exit".to_string())
                } else {
                    Err(format!(
                        "consumer exited unsuccessfully: status={status:#x}"
                    ))
                }
            }
            Scenario::WakeExplicitClose => {
                // SAFETY: this variant differs from the original only by closing
                // the producer's data write end before process teardown.
                unsafe { close_fd(data[1]) };
                unsafe { libc::_exit(0) }
            }
            Scenario::DoubleWake | Scenario::WakeEpollInHup => {
                // Deliberately do not close data[1] here. _exit closes it implicitly.
                unsafe { libc::_exit(0) }
            }
            Scenario::ReadNoEpoll => {
                let status = wait_for_child(consumer, "consumer")?;
                if child_exited_successfully(status) {
                    Ok("producer write reached blocking consumer read".to_string())
                } else {
                    Err(format!(
                        "consumer exited unsuccessfully: status={status:#x}"
                    ))
                }
            }
            Scenario::WakeCreateAfterFork => unreachable!("handled by create-after-fork path"),
        }
    }

    fn run_pipe_wake_create_after_fork() -> Result<String, String> {
        let consumer = fork("consumer fork")?;
        if consumer == 0 {
            // SAFETY: child owns raw fds created below and exits via _exit.
            unsafe {
                let code = match consumer_creates_pipe_main() {
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

        let status = wait_for_child(consumer, "consumer")?;
        if child_exited_successfully(status) {
            Ok("consumer-created pipe completed".to_string())
        } else {
            Err(format!(
                "consumer exited unsuccessfully: status={status:#x}"
            ))
        }
    }

    fn consumer_main(
        pipe_read_fd: i32,
        ready_signal_fd: i32,
        scenario: Scenario,
    ) -> Result<String, String> {
        if let Scenario::ReadNoEpoll = scenario {
            write_all(ready_signal_fd, b"R")?;
            // SAFETY: ready notification has been sent; this child no longer needs the fd.
            unsafe { close_fd(ready_signal_fd) };
            let started = Instant::now();
            let byte = read_one(pipe_read_fd).map_err(|e| format!("probe line read1: {e}"))?;
            if byte != b'x' {
                return Err(format!(
                    "probe line read1: read expected 'x', got {:?}",
                    byte as char
                ));
            }
            // SAFETY: consumer is done with the data pipe before reporting success.
            unsafe { close_fd(pipe_read_fd) };
            return Ok(format!("read1={}ms byte=x", started.elapsed().as_millis()));
        }

        let ep = epoll_create()?;
        let interest = match scenario {
            Scenario::WakeEpollInHup => (libc::EPOLLIN | libc::EPOLLHUP) as u32,
            Scenario::DoubleWake | Scenario::SingleWakeNoExit | Scenario::WakeExplicitClose => {
                libc::EPOLLIN as u32
            }
            Scenario::ReadNoEpoll | Scenario::WakeCreateAfterFork => {
                unreachable!("handled by non-epoll/create-after-fork path")
            }
        };
        epoll_add(ep, pipe_read_fd, interest)?;
        write_all(ready_signal_fd, b"R")?;
        // SAFETY: ready notification has been sent; this child no longer needs the fd.
        unsafe { close_fd(ready_signal_fd) };

        let wake1 = wait_and_read(ep, pipe_read_fd, "wake1", b'x')?;
        let detail = match scenario {
            Scenario::SingleWakeNoExit | Scenario::WakeExplicitClose | Scenario::WakeEpollInHup => {
                format!("wake1={}ms events={:#x}", wake1.elapsed_ms, wake1.events)
            }
            Scenario::DoubleWake => {
                let wake2 = wait_and_read(ep, pipe_read_fd, "wake2", b'y')?;
                format!(
                    "wake1={}ms events={:#x}; wake2={}ms events={:#x}",
                    wake1.elapsed_ms, wake1.events, wake2.elapsed_ms, wake2.events
                )
            }
            Scenario::ReadNoEpoll | Scenario::WakeCreateAfterFork => {
                unreachable!("handled by non-epoll/create-after-fork path")
            }
        };

        // SAFETY: consumer is done with epoll and the data pipe before reporting success.
        unsafe {
            close_fd(ep);
            close_fd(pipe_read_fd);
        }
        Ok(detail)
    }

    fn consumer_creates_pipe_main() -> Result<String, String> {
        let data = pipe("consumer-created data pipe")?;
        let ep = epoll_create()?;
        epoll_add(ep, data[0], libc::EPOLLIN as u32)?;

        let producer = fork("producer fork")?;
        if producer == 0 {
            // SAFETY: producer grandchild exits via _exit after writing.
            unsafe {
                close_fd(data[0]);
                let code = match write_all(data[1], b"x") {
                    Ok(()) => 0,
                    Err(e) => {
                        let _ = write_all(
                            libc::STDOUT_FILENO,
                            format!("FAIL producer write 'x': {e}\n").as_bytes(),
                        );
                        1
                    }
                };
                libc::_exit(code);
            }
        }

        // SAFETY: consumer only waits on the read end; close its local write end
        // so this variant has exactly one writer in the producer process.
        unsafe { close_fd(data[1]) };
        let wake1 = wait_and_read(ep, data[0], "wake1", b'x')?;
        let status = wait_for_child(producer, "producer")?;
        if !child_exited_successfully(status) {
            return Err(format!(
                "producer exited unsuccessfully: status={status:#x}"
            ));
        }
        // SAFETY: consumer is done with epoll and pipe read end.
        unsafe {
            close_fd(ep);
            close_fd(data[0]);
        }
        Ok(format!(
            "consumer-created pipe wake1={}ms events={:#x}",
            wake1.elapsed_ms, wake1.events
        ))
    }

    fn producer_main(write_fd: i32, scenario: Scenario) -> Result<(), String> {
        write_all(write_fd, b"x").map_err(|e| format!("producer write 'x': {e}"))?;
        match scenario {
            Scenario::DoubleWake => {
                write_all(write_fd, b"y").map_err(|e| format!("producer write 'y': {e}"))?;
            }
            Scenario::SingleWakeNoExit
            | Scenario::WakeExplicitClose
            | Scenario::WakeEpollInHup
            | Scenario::ReadNoEpoll => {}
            Scenario::WakeCreateAfterFork => unreachable!("handled by create-after-fork path"),
        }
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

    fn wait_for_child(pid: libc::pid_t, context: &str) -> Result<i32, String> {
        let mut status = 0;
        loop {
            // SAFETY: status points to a valid i32 and pid is a child pid returned by fork.
            let rc = unsafe { libc::waitpid(pid, std::ptr::addr_of_mut!(status), 0) };
            if rc == pid {
                return Ok(status);
            }
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(format!("waitpid {context}: {err}"));
            }
        }
    }

    fn child_exited_successfully(status: i32) -> bool {
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
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

    fn epoll_add(ep: i32, read_fd: i32, interest: u32) -> Result<(), String> {
        let mut event = libc::epoll_event {
            events: interest,
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
