// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// main.rs holds agent runtime + integration sub-commands. Three lint
// classes are pervasive here and not signal:
//
//   * cast_possible_truncation / cast_possible_wrap / cast_sign_loss —
//     test code routinely deals in port numbers, fd indices, packet
//     lengths whose value range is structurally safe. Per-site
//     try_from would add boilerplate without catching real bugs.
//
//   * items_after_statements — sub-commands often inline small
//     helper fns next to where they're used, for readability.
//
//   * match_same_arms — protocol dispatch tables intentionally
//     enumerate distinct cases that share a body, for documentation.
//
//   * similar_names — pid/ppid, args/argv, src/dst show up in many
//     POSIX-shaped test bodies; renaming reduces clarity.
//
//   * ptr_as_ptr / ref_as_ptr — libc FFI patterns
//     (`buf.as_ptr() as *const _`) appear in many test scaffolds.
//
// Everything else stays under pedantic-deny.
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::similar_names)]
#![allow(clippy::ptr_as_ptr)]
#![allow(clippy::ref_as_ptr)]

//! `LiteBox` process tree test harness.
//!
//! Two modes:
//! - `spawn-tree` — coordinator: spawns tree, drives tests through pipes
//! - `agent` — command executor: reads commands from stdin, responds on stdout
//!
//! # IMPORTANT: Running tests inside litebox vs native
//!
//! This binary can run on **native Linux** (gold standard) or **inside litebox**
//! (sandbox under test). The environment affects what syscall implementation is
//! tested. Always use the `litebox-test` Docker image for reproducible results.
//!
//! ## Native (gold standard — real kernel syscalls):
//! ```sh
//! docker run --rm --cap-add SYS_PTRACE \
//!   -v target/debug:/opt/litebox:ro \
//!   -v target/nonpie/debug:/opt/nonpie:ro \
//!   litebox-test /opt/litebox/litebox_test_harness spawn-tree
//! ```
//!
//! ## Litebox sandbox (tests the shim's syscall virtualization):
//! ```sh
//! docker run --rm --cap-add SYS_PTRACE -e LITEBOX_NO_AUDIT=1 \
//!   -v target/debug:/opt/litebox:ro \
//!   -v target/nonpie/debug:/opt/nonpie:ro \
//!   litebox-test /opt/litebox/litebox_tool_executor \
//!     --rootfs / --record-baseline \
//!     -- /opt/litebox/litebox_test_harness spawn-tree
//! ```
//!
//! Add `--filter=<suite>` or `--filter=<suite>.<group>` to run a subset:
//!   `--filter=fork` (all fork groups), `--filter=fork.capture_pipe` (one group).
//!
//! The coordinator prints a `[coord] runtime:` diagnostic at startup to
//! make the environment visible. Running outside Docker or without
//! `litebox_tool_executor` will produce a warning.

mod agent;
mod agent_listen;
use litebox_test_harness::coordinator;
use litebox_test_harness::protocol;

use std::io::Write as _;

/// Resolve the target binary that an M/BS subcommand should spawn.
///
/// The M and BS minimal canary subcommands spawn a child binary
/// internally (originally always the non-PIE harness companion).
/// Tests exercise per-binary-type behavior by setting
/// `LITEBOX_M_TARGET_BINARY=<path>` via the Exec command's `env`
/// field; when that env var is set, the subcommand spawns that path
/// instead. When unset, defaults to
/// `litebox_test_harness::nonpie_binary()` so existing behavior is
/// preserved for M tests that don't yet thread a binary type
/// through.
fn m_target_binary() -> String {
    if let Ok(p) = std::env::var("LITEBOX_M_TARGET_BINARY")
        && !p.is_empty()
    {
        return p;
    }
    litebox_test_harness::nonpie_binary()
}

#[allow(clippy::too_many_lines)] // exhaustive runner / dispatch table
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map_or("spawn-tree", String::as_str);
    let self_exe = &args[0];

    // Log the resolved binary path so stale rootfs copies are immediately
    // obvious (args[0] may differ from the real on-disk path).
    if !cmd.starts_with("pty-")
        && let Ok(real) = std::env::current_exe()
    {
        eprintln!("[harness] self_exe={self_exe} resolved={}", real.display());
    }

    // Dispatch through the leaf-subcommand registry first. Family
    // files register their argv-only leaves via
    // `register_leaf_subcommand!`; collect_all_tests() populates the
    // registry as a side-effect. If a registration matches `cmd`,
    // run it and exit. Otherwise fall through to the legacy `match`
    // arms below (which are being migrated family-by-family).
    if !matches!(cmd, "spawn-tree" | "agent" | "agent-listen") {
        let _ = coordinator::collect_all_tests();
        if let Some(code) = coordinator::leaf_subcommand::dispatch(&args) {
            std::process::exit(code);
        }
    }

    match cmd {
        "spawn-tree" => {
            // Optional: --filter=matrix to run only matrix tests.
            let filter = args.iter().find_map(|a| a.strip_prefix("--filter="));
            // JSON results are emitted incrementally on stdout from
            // TestRunner::record as each test completes (see coordinator/mod.rs).
            // We just compute the summary counts here. Outcomes are strictly
            // `pass` or `FAIL` — there is no expected-failure mechanism.
            let results = coordinator::run_filtered(self_exe, filter);
            let pass_count = results.iter().filter(|r| r.outcome() == "pass").count();
            let fail_count = results.iter().filter(|r| r.outcome() == "FAIL").count();
            eprintln!(
                "\n=== SUMMARY: {} total, {} passed, {} failed ===",
                results.len(),
                pass_count,
                fail_count,
            );
            // Exit non-zero on any FAIL.
            //
            // Use `std::process::exit` (not a `return` from `main`) so we
            // skip Drop on the tokio runtime and on any leaked
            // `tokio::process::Child` handles. Under litebox, `teardown_tree`
            // can leave non-PIE worker processes (NP, NPC, D4) running as
            // host child processes whose pipe-relay threads in the runner
            // would otherwise prevent the runner from exiting; the kernel
            // SIGKILLs everything when this process terminates.
            let exit_code = i32::from(fail_count > 0);
            std::process::exit(exit_code);
        }
        "agent" => {
            // Populate the handler registry as a side-effect; every
            // process needs the same handlers registered under the
            // same names. Discard the returned Test list.
            let _tests = coordinator::collect_all_tests();
            agent::run(self_exe);
        }
        "agent-listen" => {
            // TCP variant of agent mode. Listens on a TCP port, accepts
            // one connection, and runs the same agent protocol over that
            // connection (by dup2-ing the socket onto stdin/stdout).
            let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(9090);
            let _tests = coordinator::collect_all_tests();
            agent_listen::run(self_exe, port);
        }
        "echo-test" => {
            println!("ECHO_TEST_OK");
        }
        "cli-startup-mimic" => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind cli startup mimic listener");
                let addr = listener.local_addr().expect("listener addr");
                println!("CLI_STARTUP_MIMIC_OK {addr}");
            });
        }
        "M1-tokio-spawn-nonpie" => {
            // M1: PIE process, current_thread tokio runtime, spawn one
            // non-PIE child, wait, verify parent still alive.
            let nonpie = m_target_binary();
            let parent_pid = std::process::id();
            eprintln!("[M1] pid={parent_pid} spawning nonpie={nonpie}");

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let result: Result<(), String> = rt.block_on(async {
                let out = tokio::process::Command::new(&nonpie)
                    .arg("echo-test")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .output()
                    .await
                    .map_err(|e| format!("spawn: {e}"))?;
                if !out.status.success() {
                    return Err(format!("child exit: {:?}", out.status));
                }
                let stdout = String::from_utf8_lossy(&out.stdout);
                if !stdout.contains("ECHO_TEST_OK") {
                    return Err(format!("child stdout missing ECHO_TEST_OK: {stdout:?}"));
                }
                Ok(())
            });
            match result {
                Ok(()) => {
                    eprintln!("[M1] pid={parent_pid} child OK, parent surviving");
                    println!("M1_OK pid={parent_pid}");
                }
                Err(e) => {
                    eprintln!("[M1] pid={parent_pid} FAIL: {e}");
                    println!("M1_FAIL:{e}");
                    std::process::exit(1);
                }
            }
        }
        "M2-libc-spawn-nonpie" => {
            // M2: PIE process, NO tokio. Raw libc fork+execve(nonpie),
            // waitpid, verify parent still alive. Isolates whether
            // tokio is required to trigger the bug.
            let nonpie = m_target_binary();
            let parent_pid = std::process::id();
            eprintln!("[M2] pid={parent_pid} libc fork+execve nonpie={nonpie}");

            // Pipe so we can read child stdout from parent.
            let mut pipefd = [-1i32; 2];
            if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
                println!("M2_FAIL:pipe");
                std::process::exit(1);
            }
            let pipe_r = pipefd[0];
            let pipe_w = pipefd[1];

            let pid = unsafe { libc::fork() };
            if pid < 0 {
                println!("M2_FAIL:fork");
                std::process::exit(1);
            }
            if pid == 0 {
                // Child: dup pipe_w to stdout, close fds, execve.
                unsafe {
                    libc::dup2(pipe_w, 1);
                    libc::close(pipe_r);
                    libc::close(pipe_w);
                }
                use std::ffi::CString;
                let bin = CString::new(nonpie.as_str()).unwrap();
                let arg_sub = CString::new("echo-test").unwrap();
                let argv = [bin.as_ptr(), arg_sub.as_ptr(), core::ptr::null()];
                unsafe { libc::execv(bin.as_ptr(), argv.as_ptr()) };
                std::process::exit(127);
            }
            // Parent: close write end, read child stdout, waitpid.
            unsafe { libc::close(pipe_w) };
            let mut buf = [0u8; 4096];
            let n = unsafe { libc::read(pipe_r, buf.as_mut_ptr() as *mut _, buf.len()) };
            unsafe { libc::close(pipe_r) };
            let mut status = 0i32;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            loop {
                let ret = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
                if ret > 0 {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
                    println!("M2_FAIL:wait_timeout");
                    std::process::exit(1);
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
                println!("M2_FAIL:child_status={status}");
                std::process::exit(1);
            }
            if n <= 0 {
                println!("M2_FAIL:no_child_stdout");
                std::process::exit(1);
            }
            let out = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
            if !out.contains("ECHO_TEST_OK") {
                println!("M2_FAIL:bad_stdout:{out:?}");
                std::process::exit(1);
            }
            eprintln!("[M2] pid={parent_pid} child OK, parent surviving");
            println!("M2_OK pid={parent_pid}");
        }
        "M3-tokio-spawn-nonpie-then-work" => {
            // M3: M1 + parent does post-spawn syscalls. If parent is
            // "almost dead" after the spawn (e.g. relay threads gone
            // but main thread still serving), the post-work step
            // catches it.
            let nonpie = m_target_binary();
            let parent_pid = std::process::id();
            eprintln!("[M3] pid={parent_pid} step 1: spawn nonpie");

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let m1_result: Result<(), String> = rt.block_on(async {
                let out = tokio::process::Command::new(&nonpie)
                    .arg("echo-test")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .output()
                    .await
                    .map_err(|e| format!("spawn: {e}"))?;
                if !out.status.success() {
                    return Err(format!("child exit: {:?}", out.status));
                }
                Ok(())
            });
            if let Err(e) = m1_result {
                println!("M3_FAIL:step1:{e}");
                std::process::exit(1);
            }
            eprintln!("[M3] pid={parent_pid} step 2: post-spawn work");
            // Several real syscalls to verify parent is still
            // functional. Drop the tokio runtime first to sever any
            // dependency on its threads.
            drop(rt);
            // Read /proc/self/stat — exercises FS path.
            let stat = std::fs::read_to_string("/proc/self/stat")
                .map_err(|e| format!("read /proc/self/stat: {e}"));
            // Write to a file in /tmp and read it back.
            let scratch = format!("/tmp/m3-{parent_pid}.txt");
            let write_res = std::fs::write(&scratch, b"M3_PARENT_ALIVE\n")
                .map_err(|e| format!("write {scratch}: {e}"));
            let read_back =
                std::fs::read_to_string(&scratch).map_err(|e| format!("read {scratch}: {e}"));
            let _ = std::fs::remove_file(&scratch);
            match (stat, write_res, read_back) {
                (Ok(_), Ok(()), Ok(s)) if s.contains("M3_PARENT_ALIVE") => {
                    eprintln!("[M3] pid={parent_pid} step 2 OK");
                    println!("M3_OK pid={parent_pid}");
                }
                (s, w, r) => {
                    println!("M3_FAIL:step2:stat={s:?},write={w:?},read={r:?}");
                    std::process::exit(1);
                }
            }
        }
        "M4-tokio-spawn-nonpie-repeated" => {
            // M4: spawn non-PIE N times in sequence from one parent
            // tokio runtime. Counts how many spawns the parent
            // survives before dying.
            let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
            let nonpie = m_target_binary();
            let parent_pid = std::process::id();
            eprintln!("[M4] pid={parent_pid} N={n} spawning nonpie={nonpie}");

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let result: Result<usize, String> = rt.block_on(async {
                for i in 0..n {
                    let out = tokio::process::Command::new(&nonpie)
                        .arg("echo-test")
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .output()
                        .await
                        .map_err(|e| format!("spawn iter={i}: {e}"))?;
                    if !out.status.success() {
                        return Err(format!("iter={i} child exit: {:?}", out.status));
                    }
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    if !stdout.contains("ECHO_TEST_OK") {
                        return Err(format!("iter={i} bad stdout: {stdout:?}"));
                    }
                    eprintln!("[M4] pid={parent_pid} iter={i} OK");
                }
                Ok(n)
            });
            match result {
                Ok(k) => {
                    eprintln!("[M4] pid={parent_pid} all {k} iterations OK");
                    println!("M4_OK pid={parent_pid} iterations={k}");
                }
                Err(e) => {
                    println!("M4_FAIL:{e}");
                    std::process::exit(1);
                }
            }
        }
        "BS1-tokio-spawn-nonpie-stderr" => {
            // BS1: PIE process, tokio runtime, spawns non-PIE child that
            // writes only to stderr. Tests whether STDERR bridging from
            // a non-PIE worker has the same Bug-B shape as STDOUT (which
            // M1 covers). If BS1 passes but M1 fails (or vice versa),
            // the bug is direction-specific.
            let nonpie = m_target_binary();
            let parent_pid = std::process::id();
            eprintln!("[BS1] pid={parent_pid} spawning nonpie={nonpie} stderr-only-test");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let result: Result<(), String> = rt.block_on(async {
                let out = tokio::process::Command::new(&nonpie)
                    .arg("stderr-only-test")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .output()
                    .await
                    .map_err(|e| format!("spawn: {e}"))?;
                if !out.status.success() {
                    return Err(format!("child exit: {:?}", out.status));
                }
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !stderr.contains("STDERR_ONLY_OK") {
                    return Err(format!("child stderr missing STDERR_ONLY_OK: {stderr:?}"));
                }
                Ok(())
            });
            match result {
                Ok(()) => {
                    eprintln!("[BS1] pid={parent_pid} OK");
                    println!("BS1_OK pid={parent_pid}");
                }
                Err(e) => {
                    println!("BS1_FAIL:{e}");
                    std::process::exit(1);
                }
            }
        }
        "BS2-tokio-spawn-nonpie-stdin-echo" => {
            // BS2: PIE process, tokio, spawns non-PIE child with stdin
            // piped + stdout piped. Parent writes "BS2_PING\n" to child
            // stdin; child echoes back to stdout. Parent verifies it
            // reads "BS2_PING\n" from stdout. Tests bidirectional
            // bridging: parent → child stdin AND child → parent stdout.
            let nonpie = m_target_binary();
            let parent_pid = std::process::id();
            eprintln!("[BS2] pid={parent_pid} spawning nonpie={nonpie} stdin-echo-test");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let result: Result<(), String> = rt.block_on(async {
                use tokio::io::AsyncWriteExt;
                let mut child = tokio::process::Command::new(&nonpie)
                    .arg("stdin-echo-test")
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("spawn: {e}"))?;
                if let Some(mut stdin) = child.stdin.take() {
                    stdin
                        .write_all(b"BS2_PING\n")
                        .await
                        .map_err(|e| format!("write stdin: {e}"))?;
                    drop(stdin);
                }
                let out = child
                    .wait_with_output()
                    .await
                    .map_err(|e| format!("wait: {e}"))?;
                if !out.status.success() {
                    return Err(format!("child exit: {:?}", out.status));
                }
                let stdout = String::from_utf8_lossy(&out.stdout);
                if !stdout.contains("BS2_PING") {
                    return Err(format!("child stdout missing BS2_PING: {stdout:?}"));
                }
                Ok(())
            });
            match result {
                Ok(()) => {
                    eprintln!("[BS2] pid={parent_pid} OK");
                    println!("BS2_OK pid={parent_pid}");
                }
                Err(e) => {
                    println!("BS2_FAIL:{e}");
                    std::process::exit(1);
                }
            }
        }
        "BS3-tokio-spawn-nonpie-large-stdout" => {
            // BS3: PIE process, tokio, spawns non-PIE child that writes
            // 65536 bytes to stdout. Tests whether stdout bridging works
            // for payloads larger than typical pipe buffers (~64K). If
            // M1 fails (small) but BS3 passes (large), the bug is
            // small-payload-specific (e.g. lost wakeup before EOF).
            // If both fail, the bug is general.
            let nonpie = m_target_binary();
            let parent_pid = std::process::id();
            eprintln!("[BS3] pid={parent_pid} spawning nonpie={nonpie} large-stdout-test");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let result: Result<(), String> = rt.block_on(async {
                let out = tokio::process::Command::new(&nonpie)
                    .arg("large-stdout-test")
                    .arg("65536")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .output()
                    .await
                    .map_err(|e| format!("spawn: {e}"))?;
                if !out.status.success() {
                    return Err(format!("child exit: {:?}", out.status));
                }
                let stdout = String::from_utf8_lossy(&out.stdout);
                if !stdout.contains("LARGE_STDOUT_OK") {
                    return Err(format!(
                        "child stdout missing LARGE_STDOUT_OK (got {} bytes)",
                        stdout.len()
                    ));
                }
                Ok(())
            });
            match result {
                Ok(()) => {
                    eprintln!("[BS3] pid={parent_pid} OK");
                    println!("BS3_OK pid={parent_pid}");
                }
                Err(e) => {
                    println!("BS3_FAIL:{e}");
                    std::process::exit(1);
                }
            }
        }
        "fork-exec-pie" => {
            // Fork a child that exec's a PIE binary.  Tests fork from
            // within a worker-exec host (the VS Code ptyHost pattern:
            // worker-exec node forks a PIE child like bash).
            //
            // Usage: fork-exec-pie <binary> [subcommand]
            let binary = args.get(2).map_or_else(
                || {
                    for p in ["/opt/litebox/litebox_test_harness"] {
                        if std::path::Path::new(p).exists() {
                            return p;
                        }
                    }
                    "/opt/litebox/litebox_test_harness"
                },
                String::as_str,
            );
            let sub = args.get(3).map_or("echo-test", String::as_str);

            eprintln!(
                "[fork-exec-pie] pid={} forking child to exec {binary} {sub}",
                std::process::id()
            );

            let pid = unsafe { libc::fork() };
            if pid < 0 {
                eprintln!(
                    "[fork-exec-pie] fork failed: {}",
                    std::io::Error::last_os_error()
                );
                println!("FORK_EXEC_PIE_FAIL:fork");
                std::process::exit(1);
            }
            if pid == 0 {
                use std::ffi::CString;
                let bin = CString::new(binary).unwrap();
                let arg_sub = CString::new(sub).unwrap();
                let args = [bin.as_ptr(), arg_sub.as_ptr(), core::ptr::null()];
                unsafe { libc::execv(bin.as_ptr(), args.as_ptr()) };
                let err = std::io::Error::last_os_error();
                eprintln!("[fork-exec-pie] child execv failed: {err}");
                std::process::exit(127);
            }

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            let mut status = 0i32;
            loop {
                let ret = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
                if ret > 0 {
                    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                        eprintln!("[fork-exec-pie] child exited OK");
                        println!("FORK_EXEC_PIE_OK");
                        std::process::exit(0);
                    } else {
                        eprintln!("[fork-exec-pie] child bad exit: {status}");
                        println!("FORK_EXEC_PIE_FAIL:exit={status}");
                        std::process::exit(1);
                    }
                }
                if std::time::Instant::now() >= deadline {
                    eprintln!("[fork-exec-pie] child TIMEOUT (execve hung?)");
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
                    println!("FORK_EXEC_PIE_FAIL:timeout");
                    std::process::exit(1);
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        "epoll-socket" => {
            // Minimal reproduction of epoll + TCP socket wakeup.
            //
            // Two variants:
            // 1. Direct: epoll_wait blocks until data arrives (works)
            // 2. Tokio pattern: epoll_wait(timeout=0) → no events → futex park
            //    → data arrives → must wake via eventfd/pipe wakeup
            //
            // Variant 2 is how tokio works: it polls epoll non-blocking,
            // and if no events, parks the thread on a futex. The I/O driver
            // uses an eventfd to wake the parker when new events arrive.
            let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(19990);
            let variant = args.get(3).map_or("direct", std::string::String::as_str);

            unsafe {
                // Create server socket
                let srv = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
                assert!(srv >= 0, "socket failed");
                let one: libc::c_int = 1;
                libc::setsockopt(
                    srv,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    (&raw const one).cast::<libc::c_void>(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                let addr = libc::sockaddr_in {
                    sin_family: libc::AF_INET as u16,
                    sin_port: port.to_be(),
                    sin_addr: libc::in_addr { s_addr: 0 },
                    sin_zero: [0; 8],
                };
                let ret = libc::bind(
                    srv,
                    (&raw const addr).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                );
                assert!(ret == 0, "bind failed: {}", std::io::Error::last_os_error());
                libc::listen(srv, 5);

                // Create epoll
                let epfd = libc::epoll_create1(0);
                assert!(epfd >= 0, "epoll_create1 failed");

                let mut ev = libc::epoll_event {
                    events: libc::EPOLLIN as u32,
                    u64: srv as u64,
                };
                libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, srv, &raw mut ev);

                // Spawn client thread
                let port_copy = port;
                let client = std::thread::spawn(move || {
                    // Delay so server parks first (for tokio variant)
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    let sock = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                    let addr = libc::sockaddr_in {
                        sin_family: libc::AF_INET as u16,
                        sin_port: port_copy.to_be(),
                        sin_addr: libc::in_addr {
                            s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
                        },
                        sin_zero: [0; 8],
                    };
                    libc::connect(
                        sock,
                        (&raw const addr).cast::<libc::sockaddr>(),
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    );
                    let msg = b"EPOLL_DATA";
                    libc::send(sock, msg.as_ptr().cast(), msg.len(), 0);
                    libc::close(sock);
                });

                // Server: wait for accept + data
                let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];

                if variant == "tokio" {
                    // Tokio pattern: poll epoll non-blocking first. If nothing
                    // ready, park on a futex. Data arriving later must wake us
                    // via the epoll eventfd mechanism.
                    let n = libc::epoll_wait(epfd, events.as_mut_ptr(), 4, 0);
                    if n > 0 {
                        println!("EPOLL_ACCEPT=IMMEDIATE");
                    } else {
                        // No events yet. In tokio, this is where the thread
                        // would park on a futex. We simulate by using a long
                        // blocking epoll_wait (which in litebox might miss
                        // the notification if it arrived during the gap).
                        let n = libc::epoll_wait(epfd, events.as_mut_ptr(), 4, 5000);
                        if n <= 0 {
                            println!("EPOLL_ACCEPT=TIMEOUT");
                            client.join().ok();
                            libc::close(srv);
                            libc::close(epfd);
                            std::process::exit(0);
                        }
                        println!("EPOLL_ACCEPT=WOKE");
                    }
                } else {
                    // Direct: blocking epoll_wait
                    let n = libc::epoll_wait(epfd, events.as_mut_ptr(), 4, 5000);
                    if n <= 0 {
                        println!("EPOLL_ACCEPT=TIMEOUT");
                        client.join().ok();
                        libc::close(srv);
                        libc::close(epfd);
                        std::process::exit(0);
                    }
                    println!("EPOLL_ACCEPT=READY");
                }

                // Accept
                let conn = libc::accept4(
                    srv,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_NONBLOCK,
                );
                if conn < 0 {
                    println!("EPOLL_ACCEPT=FAIL");
                } else {
                    let mut ev2 = libc::epoll_event {
                        events: libc::EPOLLIN as u32,
                        u64: conn as u64,
                    };
                    libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, conn, &raw mut ev2);

                    // Wait for data
                    let n2 = libc::epoll_wait(epfd, events.as_mut_ptr(), 4, 5000);
                    if n2 <= 0 {
                        println!("EPOLL_READ=TIMEOUT");
                    } else {
                        let mut buf = [0u8; 64];
                        let nr = libc::recv(conn, buf.as_mut_ptr().cast(), buf.len(), 0);
                        if nr > 0 {
                            let data = std::str::from_utf8(&buf[..nr as usize]).unwrap_or("?");
                            println!("EPOLL_READ=OK data={data}");
                        } else {
                            println!("EPOLL_READ=NO_DATA nr={nr}");
                        }
                    }
                    libc::close(conn);
                }
                client.join().ok();
                libc::close(srv);
                libc::close(epfd);
            }
        }
        "pipe-nonblock" => {
            // Test pipe F_SETFL O_NONBLOCK behavior.
            // Creates a pipe, sets the read end to non-blocking, then verifies:
            //   1. read() returns EAGAIN (not 0) when pipe is empty
            //   2. read() returns data after write
            //   3. read() returns 0 only after write end is closed
            //
            // This is the pattern dropbear uses. If F_SETFL silently fails,
            // read() returns 0 (EOF) instead of EAGAIN, causing a busy-loop.
            unsafe {
                let mut fds = [0i32; 2];
                if libc::pipe(fds.as_mut_ptr()) != 0 {
                    println!("PIPE_NB_PIPE=FAIL");
                    std::process::exit(1);
                }
                let read_fd = fds[0];
                let write_fd = fds[1];

                // Set read end to non-blocking
                let flags = libc::fcntl(read_fd, libc::F_GETFL);
                let ret = libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                println!("PIPE_NB_SETFL={}", if ret == 0 { "OK" } else { "FAIL" });

                // Test 1: read from empty pipe should return EAGAIN, not 0
                let mut buf = [0u8; 64];
                let n = libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len());
                let errno = *libc::__errno_location();
                if n == -1 && (errno == libc::EAGAIN || errno == libc::EWOULDBLOCK) {
                    println!("PIPE_NB_EMPTY=EAGAIN");
                } else {
                    println!("PIPE_NB_EMPTY=UNEXPECTED n={n} errno={errno}");
                }

                // Test 2: write data, then non-blocking read should return it
                let msg = b"HELLO";
                libc::write(write_fd, msg.as_ptr().cast(), msg.len());
                let n = libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len());
                if n == 5 {
                    println!("PIPE_NB_DATA=OK");
                } else {
                    println!("PIPE_NB_DATA=UNEXPECTED n={n}");
                }

                // Test 3: close write end, read should return 0 (real EOF)
                libc::close(write_fd);
                let n = libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len());
                if n == 0 {
                    println!("PIPE_NB_EOF=OK");
                } else {
                    let errno = *libc::__errno_location();
                    println!("PIPE_NB_EOF=UNEXPECTED n={n} errno={errno}");
                }

                libc::close(read_fd);
            }
        }
        "pipe-child-nonblock" => {
            // Dropbear pattern: parent creates pipe, forks child, sets pipe
            // to non-blocking, then polls for child exit via the pipe.
            // The child writes a byte and exits. The parent should see:
            //   1. EAGAIN (child alive, no data yet)
            //   2. Data (child wrote)
            //   3. 0/EOF (child exited, pipe closed)
            unsafe {
                let mut fds = [0i32; 2];
                libc::pipe(fds.as_mut_ptr());
                let read_fd = fds[0];
                let write_fd = fds[1];

                let pid = libc::fork();
                if pid == 0 {
                    // Child: close read end, sleep, write, exit
                    libc::close(read_fd);
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    let msg = b"X";
                    libc::write(write_fd, msg.as_ptr().cast(), 1);
                    libc::close(write_fd);
                    std::process::exit(0);
                }

                // Parent: close write end, set read to non-blocking
                libc::close(write_fd);
                let flags = libc::fcntl(read_fd, libc::F_GETFL);
                libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);

                // Poll: initially should get EAGAIN (child still alive)
                let mut buf = [0u8; 1];
                let n = libc::read(read_fd, buf.as_mut_ptr().cast(), 1);
                let errno = *libc::__errno_location();
                if n == -1 && (errno == libc::EAGAIN || errno == libc::EWOULDBLOCK) {
                    println!("PCHILD_INITIAL=EAGAIN");
                } else {
                    println!("PCHILD_INITIAL=UNEXPECTED n={n} errno={errno}");
                }

                // Wait for child to finish
                std::thread::sleep(std::time::Duration::from_secs(1));

                // Now should get the data byte
                let n = libc::read(read_fd, buf.as_mut_ptr().cast(), 1);
                if n == 1 {
                    println!("PCHILD_DATA=OK");
                } else {
                    let errno = *libc::__errno_location();
                    println!("PCHILD_DATA=UNEXPECTED n={n} errno={errno}");
                }

                // Then EOF
                let n = libc::read(read_fd, buf.as_mut_ptr().cast(), 1);
                if n == 0 {
                    println!("PCHILD_EOF=OK");
                } else {
                    let errno = *libc::__errno_location();
                    println!("PCHILD_EOF=UNEXPECTED n={n} errno={errno}");
                }

                libc::close(read_fd);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
        }
        "check-ppid" => {
            // Reports parent PID visibility via /proc and kill -0.
            // Used to test cross-worker PID visibility after delayed-fork migration.
            let ppid = unsafe { libc::getppid() };
            let proc_exists = std::path::Path::new(&format!("/proc/{ppid}")).exists();
            let kill_ret = unsafe { libc::kill(ppid, 0) };
            let kill_errno = if kill_ret != 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            } else {
                0
            };
            let kill_ok = kill_ret == 0;
            println!("ppid={ppid} proc={proc_exists} kill0={kill_ok} errno={kill_errno}");
        }
        "proc-probe" => {
            // Comprehensive /proc self-check. Reports own PID visibility
            // and optionally checks a target PID passed as arg.
            let pid = unsafe { libc::getpid() };
            let ppid = unsafe { libc::getppid() };

            // /proc/self basics
            let self_exists = std::path::Path::new("/proc/self").exists();
            let self_cmdline = std::fs::read_to_string("/proc/self/cmdline")
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            let self_stat = std::fs::read_to_string("/proc/self/stat")
                .map(|s| !s.is_empty())
                .unwrap_or(false);

            // /proc/<own pid>
            let own_proc = std::path::Path::new(&format!("/proc/{pid}")).exists();
            let own_cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                .map(|s| !s.is_empty())
                .unwrap_or(false);

            // /proc/<ppid>
            let ppid_proc = std::path::Path::new(&format!("/proc/{ppid}")).exists();
            let ppid_cmdline = std::fs::read_to_string(format!("/proc/{ppid}/cmdline"))
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            let ppid_kill0_ret = unsafe { libc::kill(ppid, 0) };
            let ppid_kill0_errno = if ppid_kill0_ret != 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            } else {
                0
            };
            let ppid_kill0 = ppid_kill0_ret == 0;

            print!("pid={pid} ppid={ppid}");
            print!(" self={self_exists} self_cmdline={self_cmdline} self_stat={self_stat}");
            print!(" own_proc={own_proc} own_cmdline={own_cmdline}");
            print!(
                " ppid_proc={ppid_proc} ppid_cmdline={ppid_cmdline} ppid_kill0={ppid_kill0} ppid_kill0_errno={ppid_kill0_errno}"
            );

            // Optional: check a target PID
            if let Some(target) = args.get(2).and_then(|s| s.parse::<i32>().ok()) {
                let t_proc = std::path::Path::new(&format!("/proc/{target}")).exists();
                let t_kill0 = unsafe { libc::kill(target, 0) } == 0;
                print!(" target={target} target_proc={t_proc} target_kill0={t_kill0}");
            }
            println!();
        }
        "write-then-exit" => {
            // Write exactly `size` bytes of known pattern to stdout, then exit.
            // Used to test bridge thread join — without it, large writes truncate.
            let size: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(256);
            let pattern = b"ABCDEFGHIJKLMNOP"; // 16-byte repeating pattern
            let mut remaining = size;
            while remaining > 0 {
                let chunk = remaining.min(pattern.len());
                use std::io::Write;
                let _ = std::io::stdout().write_all(&pattern[..chunk]);
                remaining -= chunk;
            }
            // Flush and exit immediately — exercises the bridge-join race.
            let _ = std::io::stdout().flush();
        }
        "write-known" => {
            // Write "PIPEDATA:{tag}\n" to stdout. Used for pipe chain integrity.
            let tag = args.get(2).map_or("default", String::as_str);
            println!("PIPEDATA:{tag}");
        }
        "stress-exec" => {
            // Bypass test harness protocol entirely. Directly fork+exec
            // from a single process to test if litebox's fork/exec leaks
            // state between sequential calls.
            //
            // Usage: stress-exec <count> <pie|nonpie|mixed> [sync|tokio]
            // Outputs results to BOTH stdout and stderr.
            let count: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);
            let mode = args.get(3).map_or("pie", String::as_str);
            let use_tokio = args.get(4).map(String::as_str) == Some("tokio");
            let mut failures = 0;
            // Lazy: only pay the panic if mode actually needs it.
            let nonpie_bin: String = if matches!(mode, "nonpie" | "mixed") {
                litebox_test_harness::nonpie_binary()
            } else {
                String::new()
            };
            println!("STRESS_START mode={mode} count={count} tokio={use_tokio}");
            if use_tokio {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime");
                failures = rt.block_on(async {
                    let mut failures = 0;
                    for i in 0..count {
                        let (cmd_args, expected): (Vec<&str>, &str) = match mode {
                            "nonpie" => (vec![&nonpie_bin, "echo-test"], "ECHO_TEST_OK"),
                            "mixed" if i % 2 == 0 => (vec![self_exe, "echo-test"], "ECHO_TEST_OK"),
                            "mixed" => (vec![&nonpie_bin, "echo-test"], "ECHO_TEST_OK"),
                            _ => (vec![self_exe, "echo-test"], "ECHO_TEST_OK"),
                        };
                        let result = tokio::process::Command::new(cmd_args[0])
                            .args(&cmd_args[1..])
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::piped())
                            .stderr(std::process::Stdio::piped())
                            .output()
                            .await;
                        match result {
                            Ok(out) => {
                                let stdout =
                                    String::from_utf8_lossy(&out.stdout).trim().to_string();
                                if stdout == expected {
                                    eprintln!("i={i} ok={stdout}");
                                } else {
                                    eprintln!(
                                        "i={i} FAIL: expected={expected:?} got={stdout:?} exit={}",
                                        out.status
                                    );
                                    failures += 1;
                                }
                            }
                            Err(e) => {
                                eprintln!("i={i} FAIL: spawn error: {e}");
                                failures += 1;
                            }
                        }
                    }
                    failures
                });
            } else {
                for i in 0..count {
                    let (cmd_args, expected): (Vec<&str>, &str) = match mode {
                        "nonpie" => (vec![&nonpie_bin, "echo-test"], "ECHO_TEST_OK"),
                        "mixed" if i % 2 == 0 => (vec![self_exe, "echo-test"], "ECHO_TEST_OK"),
                        "mixed" => (vec![&nonpie_bin, "echo-test"], "ECHO_TEST_OK"),
                        _ => (vec![self_exe, "echo-test"], "ECHO_TEST_OK"),
                    };
                    let result = std::process::Command::new(cmd_args[0])
                        .args(&cmd_args[1..])
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .output();
                    match result {
                        Ok(out) => {
                            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                            if stdout == expected {
                                eprintln!("i={i} ok={stdout}");
                            } else {
                                eprintln!(
                                    "i={i} FAIL: expected={expected:?} got={stdout:?} exit={}",
                                    out.status
                                );
                                failures += 1;
                            }
                        }
                        Err(e) => {
                            eprintln!("i={i} FAIL: spawn error: {e}");
                            failures += 1;
                        }
                    }
                }
            }
            println!("STRESS_END failures={failures}");
            eprintln!("stress-exec: {count} execs, {failures} failures");
            if failures > 0 {
                std::process::exit(1);
            }
        }
        "exit-with" => {
            let code: i32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            std::process::exit(code);
        }
        // --- Subcommands used as child-process behaviors by tests ---
        "trigger-delayed-fork" => {
            // Usage: trigger-delayed-fork <cmd> [args...]
            // Triggers a delayed-fork by doing a non-pre-exec syscall (mmap
            // via Vec allocation), then fork+execs the given command.
            // Used to test nested delayed-fork: the parent forks this process,
            // which migrates to a worker, then fork+execs <cmd>.
            if args.len() < 3 {
                eprintln!("usage: trigger-delayed-fork <cmd> [args...]");
                std::process::exit(1);
            }

            // Force a non-pre-exec syscall to trigger delayed-fork migration.
            let trigger: Vec<u8> = vec![0u8; 64 * 1024];
            assert_eq!(trigger[0], 0);

            // Fork+exec the given command from within the delayed-fork child.
            let output = std::process::Command::new(&args[2])
                .args(&args[3..])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .expect("nested fork+exec failed");
            let stdout = String::from_utf8_lossy(&output.stdout);
            print!("{stdout}");
        }
        "trigger-delayed-fork-thread" => {
            // Usage: trigger-delayed-fork-thread <cmd> [args...]
            // Like trigger-delayed-fork but uses thread creation (clone3)
            // instead of mmap to trigger delayed-fork. This is how Node.js
            // triggers it (V8 creates worker threads on startup).
            if args.len() < 3 {
                eprintln!("usage: trigger-delayed-fork-thread <cmd> [args...]");
                std::process::exit(1);
            }

            // Trigger delayed-fork via thread creation (clone3).
            let handle = std::thread::spawn(|| {
                // Thread does nothing — just its creation triggers delayed-fork.
            });
            handle.join().expect("thread join failed");

            // Fork+exec the given command from within the delayed-fork child.
            let output = std::process::Command::new(&args[2])
                .args(&args[3..])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .expect("nested fork+exec failed");
            let stdout = String::from_utf8_lossy(&output.stdout);
            print!("{stdout}");
        }
        // Check if the pre-warmed code-server is running (reads pid.txt + log.txt)
        "cross-worker-file" => {
            // Minimal reproduction: forked child execs a binary that writes
            // to a file, parent reads it while child is still alive.
            // Reproduces VS Code CLI's "Input/output error" on log file.
            //
            // The child must exec (triggering delayed-fork worker migration)
            // for the bug to manifest — direct fork without exec stays in
            // the same worker and works fine.
            //
            // Usage: cross-worker-file [write-and-sleep|write-and-exit]
            let sub = args.get(2).map_or("", String::as_str);
            if sub == "write-and-sleep" || sub == "write-and-exit" || sub == "write-and-hold" {
                // Child mode: write lines to the file path in arg[3].
                let path = args.get(3).map_or("/tmp/cwf.log", String::as_str);
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)
                    .unwrap();
                use std::io::Write;
                for i in 0..5 {
                    writeln!(f, "line{i}").unwrap();
                }
                f.flush().unwrap();
                eprintln!("[cross-worker-file] READY");
                if sub == "write-and-hold" {
                    // Keep the fd OPEN (like VS Code CLI does with its log).
                    std::thread::sleep(std::time::Duration::from_secs(10));
                    drop(f);
                } else {
                    drop(f);
                    if sub == "write-and-sleep" {
                        std::thread::sleep(std::time::Duration::from_secs(10));
                    }
                }
                std::process::exit(0);
            }
            if sub == "write-stdout" {
                // Write to stdout (for bash redirect tests).
                // When bash does `cmd > file &`, stdout IS the file.
                use std::io::Write;
                for i in 0..5 {
                    println!("line{i}");
                }
                std::io::stdout().flush().unwrap();
                eprintln!("[cross-worker-file] READY");
                // Stay alive so parent can read the file concurrently.
                std::thread::sleep(std::time::Duration::from_secs(10));
                std::process::exit(0);
            }

            // Parent mode: fork+exec child that writes to a file, then read it.
            let self_exe = std::env::current_exe().unwrap();
            let path = "/tmp/cross-worker-test.log";
            let _ = std::fs::remove_file(path);
            std::fs::write(path, "").unwrap();

            let child = std::process::Command::new(&self_exe)
                .args(["cross-worker-file", "write-and-sleep", path])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            let mut child = match child {
                Ok(c) => c,
                Err(e) => {
                    println!("CROSS_WORKER_FILE:fail (spawn error: {e})");
                    std::process::exit(1);
                }
            };

            // Wait for child to write.
            std::thread::sleep(std::time::Duration::from_secs(3));

            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    let lines: Vec<&str> = contents.lines().collect();
                    if lines.len() >= 5 && lines[0] == "line0" {
                        println!("CROSS_WORKER_FILE:pass ({} lines)", lines.len());
                    } else {
                        println!(
                            "CROSS_WORKER_FILE:fail (got {} lines: {:?})",
                            lines.len(),
                            &lines[..lines.len().min(3)]
                        );
                    }
                }
                Err(e) => {
                    println!("CROSS_WORKER_FILE:fail (read error: {e})");
                }
            }
            let _ = child.kill();
            let _ = child.wait();
            std::process::exit(0);
        }
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(1);
        }
    }
}
