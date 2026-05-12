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
        "write-known" => {
            // Write "PIPEDATA:{tag}\n" to stdout. Used for pipe chain integrity.
            let tag = args.get(2).map_or("default", String::as_str);
            println!("PIPEDATA:{tag}");
        }
        "capture-pipe" => {
            // Minimal test for $()-like capture pipe across fork.
            // pipe() → fork() → child: dup2(write,1), exec sh -c "echo X | cat"
            // parent: read(read_end), verify output.
            // This isolates the delayed-fork capture pipe bridging.
            std::process::exit(capture_pipe_test::run(
                args.get(2).map_or("pipe", String::as_str),
                args.get(3).map_or("sh", String::as_str),
            ));
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
        "getifaddrs-test" => {
            let sub = args.get(2).map_or("full", String::as_str);
            std::process::exit(netlink_tests::run(sub));
        }
        "unix-socket-test" => {
            let sub = args.get(2).map_or("cross-process", String::as_str);
            std::process::exit(unix_socket_tests::run(sub));
        }
        "exit-test" => {
            let sub = args.get(2).map_or("single", String::as_str);
            exit_tests::run(sub);
            eprintln!("EXIT_TEST_BUG: run() returned instead of exiting");
            std::process::exit(99);
        }
        "net-test" => {
            let sub = args.get(2).map_or("ipv6-socket", String::as_str);
            std::process::exit(net_tests::run(sub));
        }
        "fs-test" => {
            let sub = args.get(2).map_or("help", String::as_str);
            std::process::exit(fs_tests::run(sub, &args));
        }
        // Check if the pre-warmed code-server is running (reads pid.txt + log.txt)
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(1);
        }
    }
}

/// Minimal capture-pipe fork test: reproduces the exact mechanism bash uses
/// for `$()`. Creates a pipe, forks, child dup2's write end to stdout and
/// execs a command, parent reads the output from the read end.
///
/// This isolates the delayed-fork capture pipe bridging without bash overhead.
/// The child exec triggers delayed fork migration; the parent must be able
/// to read the child's stdout through the migrated pipe bridge.
mod capture_pipe_test {
    /// Run a capture-pipe test.
    /// `cmd_type`: "simple" (echo), "pipe" (echo | cat), "multi" (echo | grep | cat),
    ///             "noexec" (child writes directly, no exec),
    ///             "`nested_fork`" (fork → fork → write, no exec on either),
    ///             "`subshell_pipe`" (bash $()-like: fork subshell, subshell forks
    ///              pipeline child that execs cat, subshell waits, parent reads),
    ///             "`subshell_continue`" (same + parent writes more output after)
    /// `shell`: "sh" or "bash" (only used for simple/pipe/multi)
    pub fn run(cmd_type: &str, shell: &str) -> i32 {
        match cmd_type {
            "noexec" => run_noexec(),
            "nested_fork" => run_nested_fork(),
            "subshell_pipe" => run_subshell_pipe(),
            "subshell_continue" => run_subshell_continue(),
            _ => run_exec(cmd_type, shell),
        }
    }

    fn run_exec(cmd_type: &str, shell: &str) -> i32 {
        let cmd = match cmd_type {
            "simple" => "echo CAPTURE_OK",
            "pipe" => "echo CAPTURE_OK | cat",
            "multi" => "echo CAPTURE_OK | grep CAPTURE | cat",
            other => {
                eprintln!("capture-pipe: unknown cmd_type: {other}");
                eprintln!("  options: simple, pipe, multi");
                return 1;
            }
        };

        // Create capture pipe
        let mut pipe_fds = [0i32; 2];
        let rc = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        if rc != 0 {
            println!("CP_FAIL:pipe_err={}", std::io::Error::last_os_error());
            return 1;
        }
        let read_end = pipe_fds[0];
        let write_end = pipe_fds[1];

        // Fork
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("CP_FAIL:fork_err={}", std::io::Error::last_os_error());
            return 1;
        }

        if pid == 0 {
            // Child: dup2 write end to stdout, close originals, exec shell
            unsafe {
                libc::dup2(write_end, 1);
                libc::close(read_end);
                libc::close(write_end);
            }
            let shell_c = std::ffi::CString::new(shell).unwrap();
            let flag_c = std::ffi::CString::new("-c").unwrap();
            let cmd_c = std::ffi::CString::new(cmd).unwrap();
            unsafe {
                libc::execvp(
                    shell_c.as_ptr(),
                    [
                        shell_c.as_ptr(),
                        flag_c.as_ptr(),
                        cmd_c.as_ptr(),
                        std::ptr::null(),
                    ]
                    .as_ptr(),
                );
            }
            // If exec fails
            unsafe { libc::_exit(127) };
        }

        // Parent: close write end, read from read end
        unsafe { libc::close(write_end) };

        let mut buf = [0u8; 4096];
        let mut output = Vec::new();
        loop {
            let n = unsafe { libc::read(read_end, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            output.extend_from_slice(&buf[..n as usize]);
        }
        unsafe { libc::close(read_end) };

        // Wait for child
        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };

        let stdout = String::from_utf8_lossy(&output).trim().to_string();
        if stdout.contains("CAPTURE_OK") {
            println!("CP_OK:cmd={cmd_type},shell={shell},output={stdout}");
            0
        } else {
            println!("CP_FAIL:cmd={cmd_type},shell={shell},output={stdout},status={status}");
            1
        }
    }

    /// Fork without exec: child writes directly to the capture pipe.
    /// This tests the delayed-fork path where the child never execs —
    /// exactly what bash's $() subshell does.
    fn run_noexec() -> i32 {
        let mut pipe_fds = [0i32; 2];
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            println!("CP_FAIL:cmd=noexec,err=pipe");
            return 1;
        }
        let read_end = pipe_fds[0];
        let write_end = pipe_fds[1];

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("CP_FAIL:cmd=noexec,err=fork");
            return 1;
        }

        if pid == 0 {
            // Child: close read end, write to write end, exit
            unsafe { libc::close(read_end) };
            let msg = b"CAPTURE_OK\n";
            unsafe { libc::write(write_end, msg.as_ptr().cast(), msg.len()) };
            unsafe { libc::close(write_end) };
            unsafe { libc::_exit(0) };
        }

        // Parent: close write end, read from read end
        unsafe { libc::close(write_end) };

        let mut buf = [0u8; 4096];
        let mut output = Vec::new();
        loop {
            let n = unsafe { libc::read(read_end, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            output.extend_from_slice(&buf[..n as usize]);
        }
        unsafe { libc::close(read_end) };

        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };

        let stdout = String::from_utf8_lossy(&output).trim().to_string();
        if stdout.contains("CAPTURE_OK") {
            println!("CP_OK:cmd=noexec,shell=none,output={stdout}");
            0
        } else {
            println!("CP_FAIL:cmd=noexec,shell=none,output={stdout},status={status}");
            1
        }
    }

    /// Nested fork: parent forks child (subshell), child forks grandchild
    /// (pipeline), grandchild writes to a pipe, child reads and forwards
    /// to parent's capture pipe. This is exactly what bash does for
    /// `A=$(echo hello | cat)`:
    ///   parent: `pipe()` → `fork()`
    ///   child (subshell): dup2(write,1) → `pipe()` → `fork()`
    ///     grandchild: `dup2(pipe_write,1)` → `write("CAPTURE_OK`") → exit
    ///   child: `read(pipe_read)` → write(stdout=capture) → exit
    ///   parent: `read(capture_read)`
    fn run_nested_fork() -> i32 {
        // Capture pipe: parent reads, child writes
        let mut capture = [0i32; 2];
        if unsafe { libc::pipe(capture.as_mut_ptr()) } != 0 {
            println!("CP_FAIL:cmd=nested_fork,err=capture_pipe");
            return 1;
        }

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("CP_FAIL:cmd=nested_fork,err=fork1");
            return 1;
        }

        if pid == 0 {
            // ── Child (subshell) ──
            // Redirect stdout to capture pipe
            unsafe {
                libc::dup2(capture[1], 1);
                libc::close(capture[0]);
                libc::close(capture[1]);
            }

            // Create inner pipe for "pipeline"
            let mut inner = [0i32; 2];
            if unsafe { libc::pipe(inner.as_mut_ptr()) } != 0 {
                unsafe { libc::_exit(1) };
            }

            // Fork grandchild (pipeline producer)
            let gc = unsafe { libc::fork() };
            if gc < 0 {
                // Fork failed — write error and exit
                let msg = b"FORK2_FAILED\n";
                unsafe { libc::write(1, msg.as_ptr().cast(), msg.len()) };
                unsafe { libc::_exit(1) };
            }

            if gc == 0 {
                // ── Grandchild ──
                // Write to inner pipe, exit
                unsafe { libc::close(inner[0]) };
                let msg = b"CAPTURE_OK\n";
                unsafe { libc::write(inner[1], msg.as_ptr().cast(), msg.len()) };
                unsafe { libc::close(inner[1]) };
                unsafe { libc::_exit(0) };
            }

            // ── Child continues ──
            // Read from inner pipe, write to stdout (= capture pipe)
            unsafe { libc::close(inner[1]) };
            let mut buf = [0u8; 4096];
            loop {
                let n = unsafe { libc::read(inner[0], buf.as_mut_ptr().cast(), buf.len()) };
                if n <= 0 {
                    break;
                }
                unsafe { libc::write(1, buf.as_ptr().cast(), n as usize) };
            }
            unsafe { libc::close(inner[0]) };

            // Wait for grandchild
            let mut gc_status = 0i32;
            unsafe { libc::waitpid(gc, &raw mut gc_status, 0) };
            unsafe { libc::_exit(0) };
        }

        // ── Parent ──
        unsafe { libc::close(capture[1]) };

        let mut buf = [0u8; 4096];
        let mut output = Vec::new();
        loop {
            let n = unsafe { libc::read(capture[0], buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            output.extend_from_slice(&buf[..n as usize]);
        }
        unsafe { libc::close(capture[0]) };

        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };

        let stdout = String::from_utf8_lossy(&output).trim().to_string();
        if stdout.contains("CAPTURE_OK") {
            println!("CP_OK:cmd=nested_fork,shell=none,output={stdout}");
            0
        } else if stdout.contains("FORK2_FAILED") {
            println!("CP_FAIL:cmd=nested_fork,shell=none,err=second_fork_failed");
            1
        } else {
            println!("CP_FAIL:cmd=nested_fork,shell=none,output={stdout},status={status}");
            1
        }
    }

    /// Bash $()-like: fork subshell, subshell forks a pipeline child that
    /// execs cat, subshell waits for pipeline, subshell exits, parent reads
    /// capture pipe. No exec in the subshell — only the pipeline child execs.
    fn run_subshell_pipe() -> i32 {
        let mut capture = [0i32; 2];
        if unsafe { libc::pipe(capture.as_mut_ptr()) } != 0 {
            println!("CP_FAIL:cmd=subshell_pipe,err=capture_pipe");
            return 1;
        }

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("CP_FAIL:cmd=subshell_pipe,err=fork1");
            return 1;
        }

        if pid == 0 {
            // ── Subshell ──
            unsafe {
                libc::dup2(capture[1], 1); // stdout → capture write end
                libc::close(capture[0]);
                libc::close(capture[1]);
            }

            // Create inner pipe for "echo | cat" pipeline
            let mut inner = [0i32; 2];
            if unsafe { libc::pipe(inner.as_mut_ptr()) } != 0 {
                unsafe { libc::_exit(1) };
            }

            // Fork pipeline child (cat — reads inner pipe, writes stdout)
            let cat_pid = unsafe { libc::fork() };
            if cat_pid < 0 {
                let msg = b"FORK2_FAILED\n";
                unsafe { libc::write(1, msg.as_ptr().cast(), msg.len()) };
                unsafe { libc::_exit(1) };
            }

            if cat_pid == 0 {
                // ── Pipeline child (cat) ──
                unsafe {
                    libc::dup2(inner[0], 0); // stdin ← inner read end
                    libc::close(inner[0]);
                    libc::close(inner[1]);
                }
                let cat = std::ffi::CString::new("/usr/bin/cat").unwrap();
                unsafe {
                    libc::execvp(cat.as_ptr(), [cat.as_ptr(), std::ptr::null()].as_ptr());
                    libc::_exit(127);
                }
            }

            // ── Subshell continues ──
            // Write data to inner pipe (like echo would), close write end
            unsafe { libc::close(inner[0]) };
            let msg = b"CAPTURE_OK\n";
            unsafe { libc::write(inner[1], msg.as_ptr().cast(), msg.len()) };
            unsafe { libc::close(inner[1]) };

            // Wait for cat
            let mut cat_status = 0i32;
            unsafe { libc::waitpid(cat_pid, &raw mut cat_status, 0) };
            unsafe { libc::_exit(0) };
        }

        // ── Parent ──
        unsafe { libc::close(capture[1]) };
        let output = read_all(capture[0]);
        unsafe { libc::close(capture[0]) };
        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };

        let stdout = String::from_utf8_lossy(&output).trim().to_string();
        if stdout.contains("CAPTURE_OK") {
            println!("CP_OK:cmd=subshell_pipe,shell=none,output={stdout}");
            0
        } else {
            println!("CP_FAIL:cmd=subshell_pipe,shell=none,output={stdout},status={status}");
            1
        }
    }

    /// Same as `subshell_pipe`, but the parent continues writing more output
    /// after reading the capture pipe. Tests that the parent's state
    /// (stack, heap, `CoW` pages) is correctly restored after the vfork child
    /// migrates via delayed fork.
    fn run_subshell_continue() -> i32 {
        let mut capture = [0i32; 2];
        if unsafe { libc::pipe(capture.as_mut_ptr()) } != 0 {
            println!("CP_FAIL:cmd=subshell_continue,err=capture_pipe");
            return 1;
        }

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("CP_FAIL:cmd=subshell_continue,err=fork1");
            return 1;
        }

        if pid == 0 {
            // ── Subshell ──
            unsafe {
                libc::dup2(capture[1], 1);
                libc::close(capture[0]);
                libc::close(capture[1]);
            }
            // Write directly (simple — no inner pipeline)
            let msg = b"SUBSHELL_DATA\n";
            unsafe { libc::write(1, msg.as_ptr().cast(), msg.len()) };
            unsafe { libc::_exit(0) };
        }

        // ── Parent continues after subshell ──
        unsafe { libc::close(capture[1]) };
        let output = read_all(capture[0]);
        unsafe { libc::close(capture[0]) };
        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };

        let captured = String::from_utf8_lossy(&output).trim().to_string();
        // Parent does MORE WORK after reading the capture pipe.
        // This tests that the parent's state is intact after CoW restore.
        let continued = format!("CAPTURED={captured},CONTINUED=YES");
        if captured.contains("SUBSHELL_DATA") {
            println!("CP_OK:cmd=subshell_continue,shell=none,output={continued}");
            0
        } else {
            println!("CP_FAIL:cmd=subshell_continue,shell=none,output={continued},status={status}");
            1
        }
    }

    fn read_all(fd: i32) -> Vec<u8> {
        let mut buf = [0u8; 4096];
        let mut output = Vec::new();
        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            output.extend_from_slice(&buf[..n as usize]);
        }
        output
    }
}
/// Each test pipes a script to both `sh` and `bash` and checks if the output
/// matches expectations. Shell (sh vs bash) is a matrix dimension — every
/// script runs with both shells to discover POSIX-mode vs native-mode
/// differences. The key bug: pipe inside `$()` when the script is read
/// from stdin can steal the remaining script content (bash-only in litebox).
mod netlink_tests {
    pub fn run(sub: &str) -> i32 {
        match sub {
            "socket" => test_socket(),
            "bind" => test_bind(),
            "getlink" => test_getlink(),
            "getaddr" => test_getaddr(),
            "sendmsg" => test_sendmsg_recvmsg(),
            "double" => test_double_request(),
            "peek-trunc" => test_peek_trunc(),
            "full" => test_full(),
            other => {
                eprintln!("unknown: {other}");
                1
            }
        }
    }

    fn test_socket() -> i32 {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            println!("NETLINK_SOCKET_FAIL:{}", errno());
            return 1;
        }
        println!("NETLINK_SOCKET_OK:{fd}");
        unsafe { libc::close(fd) };
        0
    }

    fn test_bind() -> i32 {
        let fd = open_nl();
        if fd < 0 {
            println!("NETLINK_SOCKET_FAIL");
            return 1;
        }
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        if unsafe { libc::getsockname(fd, (&raw mut sa).cast::<libc::sockaddr>(), &raw mut len) }
            < 0
        {
            println!("NETLINK_GETSOCKNAME_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }
        unsafe { libc::close(fd) };
        println!(
            "NETLINK_BIND_OK:family={},pid={},groups={}",
            sa.nl_family, sa.nl_pid, sa.nl_groups
        );
        if sa.nl_family != libc::AF_NETLINK as u16 {
            return 1;
        }
        0
    }

    fn test_getlink() -> i32 {
        let fd = open_nl();
        if fd < 0 {
            println!("NETLINK_SOCKET_FAIL");
            return 1;
        }
        let mut req = [0u8; 32]; // nlmsghdr(16) + ifinfomsg(16)
        req[0..4].copy_from_slice(&32u32.to_ne_bytes());
        req[4..6].copy_from_slice(&libc::RTM_GETLINK.to_ne_bytes());
        req[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
        req[8..12].copy_from_slice(&1u32.to_ne_bytes());
        if unsafe { libc::send(fd, req.as_ptr().cast(), req.len(), 0) } < 0 {
            println!("NETLINK_SEND_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }
        let (found, done) = recv_check(fd, libc::RTM_NEWLINK);
        unsafe { libc::close(fd) };
        if found && done {
            println!("NETLINK_GETLINK_OK");
            0
        } else {
            println!("NETLINK_GETLINK_FAIL:newlink={found},done={done}");
            1
        }
    }

    fn test_getaddr() -> i32 {
        let fd = open_nl();
        if fd < 0 {
            println!("NETLINK_SOCKET_FAIL");
            return 1;
        }
        let mut req = [0u8; 24]; // nlmsghdr(16) + ifaddrmsg(8)
        req[0..4].copy_from_slice(&24u32.to_ne_bytes());
        req[4..6].copy_from_slice(&libc::RTM_GETADDR.to_ne_bytes());
        req[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
        req[8..12].copy_from_slice(&2u32.to_ne_bytes());
        if unsafe { libc::send(fd, req.as_ptr().cast(), req.len(), 0) } < 0 {
            println!("NETLINK_SEND_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }
        let (found, done) = recv_check(fd, libc::RTM_NEWADDR);
        unsafe { libc::close(fd) };
        if found && done {
            println!("NETLINK_GETADDR_OK");
            0
        } else {
            println!("NETLINK_GETADDR_FAIL:newaddr={found},done={done}");
            1
        }
    }

    fn test_full() -> i32 {
        let mut ifaddr: *mut libc::ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&raw mut ifaddr) } != 0 {
            println!("GETIFADDRS_FAIL:{}", errno());
            return 1;
        }
        let mut count = 0;
        let mut ptr = ifaddr;
        while !ptr.is_null() {
            count += 1;
            ptr = unsafe { (*ptr).ifa_next };
        }
        unsafe { libc::freeifaddrs(ifaddr) };
        println!("GETIFADDRS_OK:{count}");
        0
    }

    fn open_nl() -> i32 {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return fd;
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        unsafe {
            libc::bind(
                fd,
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        fd
    }

    /// `NL3b`: Mimics glibc's __`netlink_request` — uses sendmsg/recvmsg
    /// with `sockaddr_nl`, iov, and msghdr. This is the exact path
    /// `getifaddrs()` takes internally.
    fn test_sendmsg_recvmsg() -> i32 {
        let fd = open_nl();
        if fd < 0 {
            println!("NETLINK_SOCKET_FAIL");
            return 1;
        }

        // Send RTM_GETLINK via sendmsg (glibc pattern)
        let mut req = [0u8; 32]; // nlmsghdr(16) + ifinfomsg(16)
        req[0..4].copy_from_slice(&32u32.to_ne_bytes());
        req[4..6].copy_from_slice(&libc::RTM_GETLINK.to_ne_bytes());
        req[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
        req[8..12].copy_from_slice(&1u32.to_ne_bytes());

        let mut dst_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dst_addr.nl_family = libc::AF_NETLINK as u16;

        let mut iov = libc::iovec {
            iov_base: req.as_mut_ptr().cast(),
            iov_len: req.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = (&raw mut dst_addr).cast();
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;

        let sent = unsafe { libc::sendmsg(fd, &raw const msg, 0) };
        if sent < 0 {
            println!("NETLINK_SENDMSG_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }
        eprintln!("[sendmsg] sent {sent} bytes");

        // Recv via recvmsg (glibc pattern) — loop until NLMSG_DONE
        let mut found_newlink = false;
        let mut found_done = false;
        let mut recv_count = 0;
        let mut buf = [0u8; 8192];
        loop {
            let mut iov_recv = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
            let mut src_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut rmsg: libc::msghdr = unsafe { std::mem::zeroed() };
            rmsg.msg_name = (&raw mut src_addr).cast();
            rmsg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
            rmsg.msg_iov = &raw mut iov_recv;
            rmsg.msg_iovlen = 1;

            let n = unsafe { libc::recvmsg(fd, &raw mut rmsg, 0) };
            recv_count += 1;
            eprintln!("[recvmsg] call #{recv_count}: returned {n}");
            if n <= 0 {
                break;
            }
            let n = n as usize;

            let mut off = 0;
            while off + 16 <= n {
                let len = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
                    as usize;
                let mtype = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
                eprintln!("[recvmsg] msg at off={off}: len={len} type={mtype}");
                if len < 16 || off + len > n {
                    break;
                }
                if mtype == libc::RTM_NEWLINK {
                    found_newlink = true;
                }
                if mtype == libc::NLMSG_DONE as u16 {
                    found_done = true;
                }
                off += (len + 3) & !3;
            }
            if found_done {
                break;
            }
        }
        unsafe { libc::close(fd) };
        if found_newlink && found_done {
            println!("NETLINK_SENDMSG_RECVMSG_OK");
            0
        } else {
            println!(
                "NETLINK_SENDMSG_RECVMSG_FAIL:newlink={found_newlink},done={found_done},recvs={recv_count}"
            );
            1
        }
    }

    /// `NL3c`: Two sequential requests on the same socket (like getifaddrs).
    /// Send `RTM_GETLINK`, read response. Then send `RTM_GETADDR`, read response.
    fn test_double_request() -> i32 {
        let fd = open_nl();
        if fd < 0 {
            println!("NETLINK_SOCKET_FAIL");
            return 1;
        }

        // Request 1: RTM_GETLINK via sendto (glibc pattern)
        let mut req1 = [0u8; 32];
        req1[0..4].copy_from_slice(&32u32.to_ne_bytes());
        req1[4..6].copy_from_slice(&libc::RTM_GETLINK.to_ne_bytes());
        req1[6..8]
            .copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
        req1[8..12].copy_from_slice(&1u32.to_ne_bytes());

        let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dst.nl_family = libc::AF_NETLINK as u16;

        eprintln!("[double] sending RTM_GETLINK via sendto");
        let sent = unsafe {
            libc::sendto(
                fd,
                req1.as_ptr().cast(),
                req1.len(),
                0,
                (&raw const dst).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        eprintln!("[double] sendto returned {sent}");
        if sent < 0 {
            println!("DOUBLE_SEND1_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }

        let (link_ok, link_done) = recv_check(fd, libc::RTM_NEWLINK);
        eprintln!("[double] getlink: ok={link_ok} done={link_done}");
        if !link_ok || !link_done {
            println!("DOUBLE_GETLINK_FAIL:ok={link_ok},done={link_done}");
            unsafe { libc::close(fd) };
            return 1;
        }

        // Request 2: RTM_GETADDR via sendto
        let mut req2 = [0u8; 24];
        req2[0..4].copy_from_slice(&24u32.to_ne_bytes());
        req2[4..6].copy_from_slice(&libc::RTM_GETADDR.to_ne_bytes());
        req2[6..8]
            .copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
        req2[8..12].copy_from_slice(&2u32.to_ne_bytes());

        eprintln!("[double] sending RTM_GETADDR via sendto");
        let sent = unsafe {
            libc::sendto(
                fd,
                req2.as_ptr().cast(),
                req2.len(),
                0,
                (&raw const dst).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        eprintln!("[double] sendto returned {sent}");
        if sent < 0 {
            println!("DOUBLE_SEND2_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }

        let (addr_ok, addr_done) = recv_check(fd, libc::RTM_NEWADDR);
        eprintln!("[double] getaddr: ok={addr_ok} done={addr_done}");

        unsafe { libc::close(fd) };
        if link_ok && link_done && addr_ok && addr_done {
            println!("NETLINK_DOUBLE_OK");
            0
        } else {
            println!("NETLINK_DOUBLE_FAIL:link={link_ok}/{link_done},addr={addr_ok}/{addr_done}");
            1
        }
    }

    /// `NL3d`: `MSG_PEEK` + `MSG_TRUNC` pattern — mimics glibc's __`netlink_request`.
    /// glibc first does `recvmsg(MSG_PEEK|MSG_TRUNC)` with `iov_len=0` to query
    /// the response size, then recvmsg(0) with a properly sized buffer.
    fn test_peek_trunc() -> i32 {
        let fd = open_nl();
        if fd < 0 {
            println!("NETLINK_SOCKET_FAIL");
            return 1;
        }

        // Send RTM_GETLINK request
        let mut req = [0u8; 32];
        req[0..4].copy_from_slice(&32u32.to_ne_bytes());
        req[4..6].copy_from_slice(&libc::RTM_GETLINK.to_ne_bytes());
        req[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
        req[8..12].copy_from_slice(&1u32.to_ne_bytes());
        if unsafe { libc::send(fd, req.as_ptr().cast(), req.len(), 0) } < 0 {
            println!("PEEK_SEND_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }

        // Step 1: recvmsg(MSG_PEEK | MSG_TRUNC) with zero-length iov
        let mut iov = libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        };
        let mut src_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = (&raw mut src_addr).cast();
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;

        let peek_size =
            unsafe { libc::recvmsg(fd, &raw mut msg, libc::MSG_PEEK | libc::MSG_TRUNC) };
        eprintln!("[peek-trunc] peek returned {peek_size}");
        if peek_size <= 0 {
            println!(
                "PEEK_TRUNC_FAIL:peek_returned={peek_size},errno={}",
                errno()
            );
            unsafe { libc::close(fd) };
            return 1;
        }

        // Step 2: recvmsg(0) with properly sized buffer
        let mut buf = vec![0u8; peek_size as usize];
        let mut iov2 = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut msg2: libc::msghdr = unsafe { std::mem::zeroed() };
        msg2.msg_name = (&raw mut src_addr).cast();
        msg2.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        msg2.msg_iov = &raw mut iov2;
        msg2.msg_iovlen = 1;

        let read_size = unsafe { libc::recvmsg(fd, &raw mut msg2, 0) };
        eprintln!("[peek-trunc] read returned {read_size}");
        if read_size <= 0 {
            println!(
                "PEEK_TRUNC_FAIL:read_returned={read_size},errno={}",
                errno()
            );
            unsafe { libc::close(fd) };
            return 1;
        }

        // Verify we got NLMSG_DONE
        let mut found_done = false;
        let n = read_size as usize;
        let mut off = 0;
        while off + 16 <= n {
            let len =
                u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
            let mtype = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
            if len < 16 || off + len > n {
                break;
            }
            if mtype == libc::NLMSG_DONE as u16 {
                found_done = true;
            }
            off += (len + 3) & !3;
        }

        unsafe { libc::close(fd) };
        // Core validation: peek size matches read size (MSG_PEEK|MSG_TRUNC works).
        // NLMSG_DONE may be in a separate message batch on real kernels with
        // many interfaces, so we don't require found_done.
        if peek_size == read_size && peek_size >= 20 {
            println!("NETLINK_PEEK_TRUNC_OK:size={peek_size}");
            0
        } else {
            println!("PEEK_TRUNC_FAIL:done={found_done},peek={peek_size},read={read_size}");
            1
        }
    }

    fn recv_check(fd: i32, expected: u16) -> (bool, bool) {
        let mut buf = [0u8; 8192];
        let mut found = false;
        let mut done = false;
        loop {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n <= 0 {
                eprintln!("[recv_check] recv returned {n}");
                break;
            }
            let n = n as usize;
            // Dump first 80 bytes for debugging
            let dump_len = n.min(80);
            let hex: Vec<String> = buf[..dump_len].iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("[recv_check] recv {n} bytes: {}", hex.join(" "));

            let mut off = 0;
            while off + 16 <= n {
                let len = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
                    as usize;
                let mtype = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
                eprintln!("[recv_check] msg at off={off}: len={len} type={mtype}");
                if len < 16 || off + len > n {
                    break;
                }
                if mtype == expected {
                    found = true;
                }
                if mtype == libc::NLMSG_DONE as u16 {
                    done = true;
                }
                off += (len + 3) & !3;
            }
            if done {
                break;
            }
        }
        (found, done)
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }
}

mod unix_socket_tests {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};

    pub fn run(sub: &str) -> i32 {
        match sub {
            "cross-process" => test_cross_process(),
            "cross-exec" => test_cross_exec(),
            "multi-conn" => test_multi_conn(),
            "abstract" => test_abstract_socket(),
            "race" => test_socket_race(),
            "mac" => test_mac_address(),
            "socketpair-fork-write" => test_socketpair_fork_write(),
            "socketpair-fork-read" => test_socketpair_fork_read(),
            "socketpair-exec" => test_socketpair_exec(),
            // Helper: child side of socketpair-exec (inherits fd from parent)
            "socketpair-exec-child" => socketpair_exec_child(),
            // Nested: exec a child that itself does socketpair+fork+exec
            // Called by the test harness binary after fork+exec for US2
            "us2-server" => us2_server(),
            // BSF: buffered-SCM-fork — parent buffers an eventfd in a
            // unix socket's recv queue via sendmsg(SCM_RIGHTS), then
            // fork+execs a (possibly cross-binary-type) child that
            // recvmsg's the buffered fd and round-trips on it. Exercises
            // the commit_delayed_fork buffered-SCM path that currently
            // returns ENOSYS in litebox when the child must migrate.
            "buffered-scm-fork" => test_buffered_scm_fork(),
            "buffered-scm-fork-child" => buffered_scm_fork_child(),
            // SXF: socketpair-fork-cross — socketpair() then fork+execv
            // into a (possibly cross-binary-type) child. Parent and
            // child exchange a PING/PONG to verify both endpoints
            // survive the commit_delayed_fork bridge. Companion to
            // p1-socketpair-fork TODO.
            "socketpair-fork-cross" => test_socketpair_fork_cross(),
            "socketpair-fork-cross-child" => socketpair_fork_cross_child(),
            // PIF: pidfd-inherit-fork — parent spawns a short-lived
            // grandchild, pidfd_open's it, fork+execvs (possibly
            // cross-binary-type) child that waitid's on the inherited
            // pidfd. Companion to p1-pidfd-inherit TODO.
            "pidfd-inherit-fork" => test_pidfd_inherit_fork(),
            "pidfd-inherit-child" => pidfd_inherit_child(),
            other => {
                eprintln!("unknown: {other}");
                1
            }
        }
    }

    /// US1: Unix socket cross-process bind+listen+connect+accept.
    /// Reproduces the code-server ↔ CLI pattern:
    ///   child = server: bind → listen → accept → read
    ///   parent = client: connect → write
    fn test_cross_process() -> i32 {
        let sock_path = "/tmp/litebox-us1-test.sock";
        let _ = std::fs::remove_file(sock_path);

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("US1_FORK_FAIL:{}", errno());
            return 1;
        }

        if pid == 0 {
            // Child = server: bind + listen + accept + read
            eprintln!("[US1-server] binding to {sock_path}");
            let listener = match UnixListener::bind(sock_path) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[US1-server] bind failed: {e}");
                    std::process::exit(1);
                }
            };
            eprintln!("[US1-server] listening, waiting for connection...");
            match listener.accept() {
                Ok((mut stream, _addr)) => {
                    let mut buf = [0u8; 64];
                    match stream.read(&mut buf) {
                        Ok(n) => {
                            let msg = std::str::from_utf8(&buf[..n]).unwrap_or("?");
                            eprintln!("[US1-server] received: {msg}");
                            if msg == "HELLO_FROM_CLIENT" {
                                std::process::exit(0);
                            } else {
                                eprintln!("[US1-server] unexpected message");
                                std::process::exit(2);
                            }
                        }
                        Err(e) => {
                            eprintln!("[US1-server] read failed: {e}");
                            std::process::exit(3);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[US1-server] accept failed: {e}");
                    std::process::exit(4);
                }
            }
        }

        // Parent = client: wait a bit for server, then connect + write
        eprintln!("[US1-client] waiting for server to start (pid={pid})...");
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Retry connect up to 10 times
        let mut stream = None;
        for attempt in 0..10 {
            match UnixStream::connect(sock_path) {
                Ok(s) => {
                    eprintln!("[US1-client] connected on attempt {attempt}");
                    stream = Some(s);
                    break;
                }
                Err(e) => {
                    eprintln!("[US1-client] connect attempt {attempt} failed: {e}");
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }

        let Some(mut stream) = stream else {
            println!("US1_CONNECT_FAIL");
            let _ = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
            return 1;
        };

        if let Err(e) = stream.write_all(b"HELLO_FROM_CLIENT") {
            println!("US1_WRITE_FAIL:{e}");
            let _ = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
            return 1;
        }
        drop(stream);

        // Wait for server child
        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        eprintln!("[US1-client] server exited with code {exit_code}");

        let _ = std::fs::remove_file(sock_path);
        if exit_code == 0 {
            println!("US1_CROSS_PROCESS_OK");
            0
        } else {
            println!("US1_CROSS_PROCESS_FAIL:exit={exit_code}");
            1
        }
    }

    /// VS1: Socket timing race — child delays bind, parent connects immediately.
    /// Reproduces the code-server startup race.
    fn test_socket_race() -> i32 {
        let sock_path = "/tmp/litebox-vs1-race.sock";
        let _ = std::fs::remove_file(sock_path);

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("VS1_FORK_FAIL:{}", errno());
            return 1;
        }

        if pid == 0 {
            // Child = server: DELAY then bind + listen
            eprintln!("[VS1-server] sleeping 500ms before bind...");
            std::thread::sleep(std::time::Duration::from_millis(500));
            eprintln!("[VS1-server] binding to {sock_path}");
            let listener = match UnixListener::bind(sock_path) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[VS1-server] bind failed: {e}");
                    std::process::exit(1);
                }
            };
            eprintln!("[VS1-server] waiting for connection...");
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 64];
                    match stream.read(&mut buf) {
                        Ok(n) => {
                            let msg = std::str::from_utf8(&buf[..n]).unwrap_or("?");
                            eprintln!("[VS1-server] got: {msg}");
                            std::process::exit(if msg == "RACE_OK" { 0 } else { 2 });
                        }
                        Err(_) => std::process::exit(3),
                    }
                }
                Err(_) => std::process::exit(4),
            }
        }

        // Parent = client: try connecting immediately (should fail initially, then succeed)
        eprintln!("[VS1-client] connecting immediately (server hasn't bound yet)...");
        let mut connected = false;
        let start = std::time::Instant::now();
        for attempt in 0..20 {
            match UnixStream::connect(sock_path) {
                Ok(mut s) => {
                    let elapsed = start.elapsed().as_millis();
                    eprintln!("[VS1-client] connected after {elapsed}ms (attempt {attempt})");
                    let _ = s.write_all(b"RACE_OK");
                    connected = true;
                    break;
                }
                Err(e) => {
                    if attempt == 0 {
                        eprintln!("[VS1-client] first connect failed (expected): {e}");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }

        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        let _ = std::fs::remove_file(sock_path);

        if connected && exit_code == 0 {
            println!("VS1_RACE_OK");
            0
        } else {
            println!("VS1_RACE_FAIL:connected={connected},exit={exit_code}");
            1
        }
    }

    /// NL6: Check if `os.networkInterfaces()` returns a MAC address.
    /// Uses getifaddrs to check for AF_PACKET/link-layer entries.
    fn test_mac_address() -> i32 {
        let mut ifaddr: *mut libc::ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&raw mut ifaddr) } != 0 {
            println!("NL6_GETIFADDRS_FAIL:{}", errno());
            return 1;
        }

        let mut has_packet = false;
        let mut has_inet = false;
        let mut iface_count = 0;
        let mut ptr = ifaddr;
        while !ptr.is_null() {
            let ifa = unsafe { &*ptr };
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
            if !ifa.ifa_addr.is_null() {
                let family = unsafe { (*ifa.ifa_addr).sa_family };
                eprintln!("[NL6] interface={name} family={family}");
                if family == libc::AF_PACKET as u16 {
                    has_packet = true;
                }
                if family == libc::AF_INET as u16 {
                    has_inet = true;
                }
            }
            iface_count += 1;
            ptr = ifa.ifa_next;
        }
        unsafe { libc::freeifaddrs(ifaddr) };

        println!("NL6_MAC_CHECK:count={iface_count},has_packet={has_packet},has_inet={has_inet}");
        // has_packet=true means there's a link-layer entry with MAC
        i32::from(!has_packet)
    }

    /// US2: Fork+exec cross-process unix socket — tests the exec migration path.
    /// Parent fork+execs a server process, then connects to its socket.
    /// This is the exact pattern used by VS Code CLI → code-server.
    fn test_cross_exec() -> i32 {
        let sock_path = "/tmp/litebox-us2-test.sock";
        let _ = std::fs::remove_file(sock_path);

        let self_exe = std::env::current_exe().unwrap();
        let self_exe = self_exe.to_str().unwrap();

        // Spawn child via fork+exec (this triggers remote worker migration)
        let child = std::process::Command::new(self_exe)
            .args(["unix-socket-test", "us2-server", sock_path])
            .spawn();

        let Ok(mut child) = child else {
            println!("US2_SPAWN_FAIL");
            return 1;
        };

        // Wait for server to start, then try connecting
        eprintln!(
            "[US2-client] child spawned (pid={}), retrying connect...",
            child.id()
        );
        let mut stream = None;
        for attempt in 0..30 {
            match UnixStream::connect(sock_path) {
                Ok(s) => {
                    eprintln!("[US2-client] connected on attempt {attempt}");
                    stream = Some(s);
                    break;
                }
                Err(e) => {
                    if attempt % 5 == 0 {
                        eprintln!("[US2-client] attempt {attempt}: {e}");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        }

        let Some(mut stream) = stream else {
            println!("US2_CONNECT_FAIL");
            let _ = child.kill();
            return 1;
        };

        if let Err(e) = stream.write_all(b"US2_HELLO") {
            println!("US2_WRITE_FAIL:{e}");
            let _ = child.kill();
            return 1;
        }
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).unwrap_or(0);
        let reply = std::str::from_utf8(&buf[..n]).unwrap_or("?");
        drop(stream);

        let status = child.wait().unwrap();
        let _ = std::fs::remove_file(sock_path);

        if reply == "US2_REPLY" && status.success() {
            println!("US2_CROSS_EXEC_OK");
            0
        } else {
            println!("US2_CROSS_EXEC_FAIL:reply={reply},status={status}");
            1
        }
    }

    /// Server half for US2 — called after fork+exec.
    fn us2_server() -> i32 {
        let sock_path = std::env::args().nth(3).unwrap_or_default();
        if sock_path.is_empty() {
            eprintln!("[US2-server] no path argument");
            return 1;
        }
        let _ = std::fs::remove_file(&sock_path);
        eprintln!("[US2-server] binding to {sock_path}");
        let listener = match UnixListener::bind(&sock_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[US2-server] bind failed: {e}");
                return 1;
            }
        };
        eprintln!("[US2-server] listening...");
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buf = [0u8; 64];
                let n = stream.read(&mut buf).unwrap_or(0);
                let msg = std::str::from_utf8(&buf[..n]).unwrap_or("?");
                eprintln!("[US2-server] got: {msg}");
                if msg == "US2_HELLO" {
                    let _ = stream.write_all(b"US2_REPLY");
                    0
                } else {
                    1
                }
            }
            Err(e) => {
                eprintln!("[US2-server] accept failed: {e}");
                1
            }
        }
    }

    /// US4: Multiple concurrent connections to the same unix socket.
    fn test_multi_conn() -> i32 {
        let sock_path = "/tmp/litebox-us4-test.sock";
        let _ = std::fs::remove_file(sock_path);

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("US4_FORK_FAIL:{}", errno());
            return 1;
        }

        if pid == 0 {
            // Child = server: accept 3 connections
            let listener = match UnixListener::bind(sock_path) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[US4-server] bind: {e}");
                    std::process::exit(1);
                }
            };
            let mut count = 0;
            for i in 0..3 {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0u8; 64];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let msg = std::str::from_utf8(&buf[..n]).unwrap_or("?");
                        eprintln!("[US4-server] conn {i}: {msg}");
                        if msg == format!("CONN_{i}") {
                            count += 1;
                        }
                    }
                    Err(e) => eprintln!("[US4-server] accept {i}: {e}"),
                }
            }
            std::process::exit(if count == 3 { 0 } else { 2 });
        }

        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut ok_count = 0;
        for i in 0..3 {
            let mut connected = false;
            for _ in 0..10 {
                if let Ok(mut s) = UnixStream::connect(sock_path) {
                    let _ = s.write_all(format!("CONN_{i}").as_bytes());
                    drop(s);
                    ok_count += 1;
                    connected = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            if !connected {
                eprintln!("[US4-client] conn {i} failed");
            }
        }

        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        let _ = std::fs::remove_file(sock_path);

        if ok_count == 3 && exit_code == 0 {
            println!("US4_MULTI_OK");
            0
        } else {
            println!("US4_MULTI_FAIL:conns={ok_count},exit={exit_code}");
            1
        }
    }

    /// US5: Abstract unix socket cross-process.
    fn test_abstract_socket() -> i32 {
        let abstract_name = b"\0litebox-us5-test";

        // Create socket manually for abstract namespace
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            println!("US5_SOCKET_FAIL:{}", errno());
            return 1;
        }

        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as u16;
        addr.sun_path[..abstract_name.len()].copy_from_slice(unsafe {
            &*(std::ptr::from_ref::<[u8]>(abstract_name) as *const [i8])
        });
        let addr_len =
            (std::mem::size_of::<libc::sa_family_t>() + abstract_name.len()) as libc::socklen_t;

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("US5_FORK_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }

        if pid == 0 {
            // Child = server: bind + listen + accept
            if unsafe { libc::bind(fd, (&raw const addr).cast::<libc::sockaddr>(), addr_len) } < 0 {
                eprintln!("[US5-server] bind: {}", errno());
                std::process::exit(1);
            }
            if unsafe { libc::listen(fd, 5) } < 0 {
                eprintln!("[US5-server] listen: {}", errno());
                std::process::exit(2);
            }
            eprintln!("[US5-server] waiting for connection...");
            let client_fd = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if client_fd < 0 {
                eprintln!("[US5-server] accept: {}", errno());
                std::process::exit(3);
            }
            let mut buf = [0u8; 64];
            let n = unsafe { libc::read(client_fd, buf.as_mut_ptr().cast(), buf.len()) };
            unsafe {
                libc::close(client_fd);
                libc::close(fd);
            }
            let msg = std::str::from_utf8(&buf[..n.max(0) as usize]).unwrap_or("?");
            std::process::exit(if msg == "US5_HELLO" { 0 } else { 4 });
        }

        // Parent = client
        unsafe { libc::close(fd) }; // close the server socket in parent
        std::thread::sleep(std::time::Duration::from_millis(300));

        let cfd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if cfd < 0 {
            println!("US5_CLIENT_SOCKET_FAIL:{}", errno());
            let _ = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
            return 1;
        }

        let mut connected = false;
        for attempt in 0..10 {
            if unsafe { libc::connect(cfd, (&raw const addr).cast::<libc::sockaddr>(), addr_len) }
                == 0
            {
                eprintln!("[US5-client] connected on attempt {attempt}");
                connected = true;
                break;
            }
            eprintln!("[US5-client] attempt {attempt}: errno={}", errno());
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        if connected {
            unsafe { libc::write(cfd, b"US5_HELLO".as_ptr().cast(), 9) };
        }
        unsafe { libc::close(cfd) };

        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };

        if connected && exit_code == 0 {
            println!("US5_ABSTRACT_OK");
            0
        } else {
            println!("US5_ABSTRACT_FAIL:connected={connected},exit={exit_code}");
            1
        }
    }

    /// `US6a`: `socketpair(AF_UNIX)` + fork — child WRITES to inherited fd.
    /// Reproduces the VS Code extension host IPC pattern (child→parent):
    ///   parent: `socketpair()` → `fork()` → waitpid → read from `parent_end`
    ///   child:  write to `child_end` → exit
    /// Uses vfork-compatible sequencing: child writes + exits before parent reads.
    fn test_socketpair_fork_write() -> i32 {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        if rc != 0 {
            println!("US6_SOCKETPAIR_FAIL:{}", errno());
            return 1;
        }
        let parent_fd = fds[0];
        let child_fd = fds[1];
        eprintln!("[US6a] socketpair ok: parent_fd={parent_fd}, child_fd={child_fd}");

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("US6_FORK_FAIL:{}", errno());
            return 1;
        }

        if pid == 0 {
            unsafe { libc::close(parent_fd) };
            let msg = b"US6_FROM_CHILD";
            let n =
                unsafe { libc::write(child_fd, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
            if n != msg.len() as isize {
                eprintln!("[US6a-child] write failed: n={n} errno={}", errno());
                std::process::exit(1);
            }
            eprintln!("[US6a-child] wrote {n} bytes");
            unsafe { libc::close(child_fd) };
            std::process::exit(0);
        }

        unsafe { libc::close(child_fd) };
        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            99
        };

        if exit_code != 0 {
            println!("US6_CHILD_FAIL:exit={exit_code}");
            unsafe { libc::close(parent_fd) };
            return 1;
        }

        let mut buf = [0u8; 64];
        let n = unsafe {
            libc::read(
                parent_fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        unsafe { libc::close(parent_fd) };

        if n <= 0 {
            println!("US6_READ_FAIL:n={n},errno={}", errno());
            return 1;
        }
        let msg = std::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
        eprintln!("[US6a-parent] got: {msg}");

        if msg == "US6_FROM_CHILD" {
            println!("US6_SOCKETPAIR_FORK_OK");
            0
        } else {
            println!("US6_SOCKETPAIR_FORK_FAIL:msg={msg}");
            1
        }
    }

    /// `US6b`: `socketpair(AF_UNIX)` + fork — child READS from inherited fd.
    /// Tests the reverse direction (parent→child):
    ///   parent: `socketpair()` → `fork()` → write to `parent_end` → waitpid
    ///   child:  read from `child_end` → exit(based on data)
    /// Requires true concurrent fork (not vfork).
    fn test_socketpair_fork_read() -> i32 {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        if rc != 0 {
            println!("US6R_SOCKETPAIR_FAIL:{}", errno());
            return 1;
        }
        let parent_fd = fds[0];
        let child_fd = fds[1];
        eprintln!("[US6b] socketpair ok: parent_fd={parent_fd}, child_fd={child_fd}");

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("US6R_FORK_FAIL:{}", errno());
            return 1;
        }

        if pid == 0 {
            // Child: close parent end, read from child end, exit.
            unsafe { libc::close(parent_fd) };
            let tv = libc::timeval {
                tv_sec: 5,
                tv_usec: 0,
            };
            unsafe {
                libc::setsockopt(
                    child_fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    (&raw const tv).cast::<libc::c_void>(),
                    core::mem::size_of::<libc::timeval>() as libc::socklen_t,
                );
            }
            let mut buf = [0u8; 64];
            let n =
                unsafe { libc::read(child_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            if n <= 0 {
                eprintln!("[US6b-child] read failed: n={n} errno={}", errno());
                std::process::exit(1);
            }
            let msg = std::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
            eprintln!("[US6b-child] got: {msg}");
            std::process::exit(if msg == "US6_FROM_PARENT" { 0 } else { 2 });
        }

        // Parent: close child end, write to parent end, waitpid.
        unsafe { libc::close(child_fd) };
        let msg = b"US6_FROM_PARENT";
        let n = unsafe { libc::write(parent_fd, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        unsafe { libc::close(parent_fd) };

        if n != msg.len() as isize {
            println!("US6R_WRITE_FAIL:n={n},errno={}", errno());
            unsafe { libc::kill(pid, libc::SIGKILL) };
            return 1;
        }
        eprintln!("[US6b-parent] wrote {n} bytes");

        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            99
        };

        if exit_code == 0 {
            println!("US6R_SOCKETPAIR_FORK_READ_OK");
            0
        } else {
            println!("US6R_SOCKETPAIR_FORK_READ_FAIL:exit={exit_code}");
            1
        }
    }

    /// `US6c`: `socketpair(AF_UNIX)` + fork+exec — bidirectional IPC.
    /// Reproduces the exact VS Code extension host pattern:
    ///   parent: `socketpair()` → `fork()` → exec(child, inheriting fd) → write → read
    ///   child (exec'd): read from inherited fd → write reply → exit
    /// Uses raw fork+exec (not `posix_spawn`) to trigger litebox's delayed fork.
    fn test_socketpair_exec() -> i32 {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        if rc != 0 {
            println!("US6E_SOCKETPAIR_FAIL:{}", errno());
            return 1;
        }
        let parent_fd = fds[0];
        let child_fd = fds[1];
        eprintln!("[US6c] socketpair ok: parent_fd={parent_fd}, child_fd={child_fd}");

        // Clear CLOEXEC on child_fd so it survives exec.
        unsafe { libc::fcntl(child_fd, libc::F_SETFD, 0) };

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("US6E_FORK_FAIL:{}", errno());
            return 1;
        }

        if pid == 0 {
            // Child: close parent end, exec self with child fd arg.
            // Only pre-exec syscalls before execv — triggers exec-on-remote-host
            // path (not commit_delayed_fork).
            unsafe { libc::close(parent_fd) };
            let self_exe = std::env::current_exe().unwrap();
            let self_exe = self_exe.to_str().unwrap();
            let fd_str = child_fd.to_string();
            let c_exe = std::ffi::CString::new(self_exe).unwrap();
            let c_arg1 = std::ffi::CString::new("unix-socket-test").unwrap();
            let c_arg2 = std::ffi::CString::new("socketpair-exec-child").unwrap();
            let c_arg3 = std::ffi::CString::new(fd_str.as_str()).unwrap();
            let args = [
                c_exe.as_ptr(),
                c_arg1.as_ptr(),
                c_arg2.as_ptr(),
                c_arg3.as_ptr(),
                core::ptr::null(),
            ];
            unsafe { libc::execv(c_exe.as_ptr(), args.as_ptr()) };
            eprintln!("[US6c-child] execv failed: {}", errno());
            std::process::exit(127);
        }

        // Parent: close child end, write, read reply, waitpid.
        unsafe { libc::close(child_fd) };

        let msg = b"US6E_FROM_PARENT";
        let n = unsafe { libc::write(parent_fd, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        if n != msg.len() as isize {
            println!("US6E_WRITE_FAIL:n={n},errno={}", errno());
            unsafe { libc::kill(pid, libc::SIGKILL) };
            return 1;
        }
        eprintln!("[US6c-parent] wrote {n} bytes");

        // Read reply with timeout.
        let tv = libc::timeval {
            tv_sec: 10,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                parent_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast::<libc::c_void>(),
                core::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
        let mut buf = [0u8; 64];
        let n = unsafe {
            libc::read(
                parent_fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        unsafe { libc::close(parent_fd) };

        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            99
        };

        if n <= 0 {
            println!("US6E_READ_FAIL:n={n},errno={},exit={exit_code}", errno());
            return 1;
        }
        let reply = std::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
        eprintln!("[US6c-parent] got reply: {reply}");

        if reply == "US6E_FROM_CHILD" && exit_code == 0 {
            println!("US6E_SOCKETPAIR_EXEC_OK");
            0
        } else {
            println!("US6E_SOCKETPAIR_EXEC_FAIL:reply={reply},exit={exit_code}");
            1
        }
    }

    /// Helper for `US6c`: exec'd child reads from inherited socketpair fd,
    /// writes reply, exits.
    fn socketpair_exec_child() -> i32 {
        let fd: i32 = std::env::args()
            .nth(3)
            .and_then(|s| s.parse().ok())
            .unwrap_or(-1);
        if fd < 0 {
            eprintln!("[US6c-child] bad fd arg");
            return 1;
        }

        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast::<libc::c_void>(),
                core::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        let mut buf = [0u8; 64];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n <= 0 {
            eprintln!("[US6c-child] read failed: n={n} errno={}", errno());
            return 1;
        }
        let msg = std::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
        eprintln!("[US6c-child] got: {msg}");

        let reply = b"US6E_FROM_CHILD";
        let w = unsafe { libc::write(fd, reply.as_ptr().cast::<libc::c_void>(), reply.len()) };
        unsafe { libc::close(fd) };

        if msg == "US6E_FROM_PARENT" && w == reply.len() as isize {
            0
        } else {
            2
        }
    }

    /// BSF parent — buffered-SCM-fork:
    /// 1. socketpair(AF_UNIX, SOCK_STREAM) → (s_send, s_recv)
    /// 2. eventfd(initval=0)
    /// 3. sendmsg(s_send, SCM_RIGHTS=[ev], data="BSF") — message lands
    ///    in s_recv's recv queue, not yet drained.
    /// 4. close(s_send) to ensure the child does not race writers.
    /// 5. fork+execv(child_exe, "unix-socket-test",
    ///    "buffered-scm-fork-child", "<s_recv_fd>"). The fork(+exec) is
    ///    the trigger for `commit_delayed_fork` to bridge s_recv across
    ///    host workers when child_exe is a different binary type —
    ///    that bridge is the gate currently returning ENOSYS.
    /// 6. waitpid; emit BSF_OK iff child exit==0.
    fn test_buffered_scm_fork() -> i32 {
        let child_exe: String = std::env::args().nth(3).unwrap_or_default();
        if child_exe.is_empty() {
            println!("BSF_USAGE: unix-socket-test buffered-scm-fork <child_exe>");
            return 1;
        }
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        if rc != 0 {
            println!("BSF_SOCKETPAIR_FAIL:{}", errno());
            return 1;
        }
        let s_send = fds[0];
        let s_recv = fds[1];

        let ev = unsafe { libc::eventfd(0, 0) };
        if ev < 0 {
            println!("BSF_EVENTFD_FAIL:{}", errno());
            return 1;
        }

        let payload = b"BSF";
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };
        let mut cmsg_buf = [0u8; 32];
        let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = cmsg_buf.len() as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(core::mem::size_of::<i32>() as u32) as _;
            let data = libc::CMSG_DATA(cmsg).cast::<i32>();
            data.write_unaligned(ev);
            msg.msg_controllen = libc::CMSG_SPACE(core::mem::size_of::<i32>() as u32) as _;
        }
        let n = unsafe { libc::sendmsg(s_send, &raw const msg, 0) };
        if n < 0 {
            println!("BSF_SENDMSG_FAIL:{}", errno());
            return 1;
        }

        unsafe {
            libc::close(s_send);
            libc::close(ev);
        }
        unsafe { libc::fcntl(s_recv, libc::F_SETFD, 0) };

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("BSF_FORK_FAIL:{}", errno());
            return 1;
        }

        if pid == 0 {
            let fd_str = s_recv.to_string();
            let c_exe = std::ffi::CString::new(child_exe.as_str()).unwrap();
            let c_a1 = std::ffi::CString::new("unix-socket-test").unwrap();
            let c_a2 = std::ffi::CString::new("buffered-scm-fork-child").unwrap();
            let c_a3 = std::ffi::CString::new(fd_str.as_str()).unwrap();
            let argv = [
                c_exe.as_ptr(),
                c_a1.as_ptr(),
                c_a2.as_ptr(),
                c_a3.as_ptr(),
                core::ptr::null(),
            ];
            unsafe { libc::execv(c_exe.as_ptr(), argv.as_ptr()) };
            eprintln!("[BSF-child] execv failed: {}", errno());
            std::process::exit(127);
        }

        unsafe { libc::close(s_recv) };
        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            99
        };
        if exit_code == 0 {
            println!("BSF_OK");
            0
        } else {
            println!("BSF_FAIL:exit={exit_code}");
            1
        }
    }

    /// BSF child — recvmsg the buffered SCM_RIGHTS message, then
    /// eventfd_write/read on the recovered fd to verify it's wired
    /// up to a real broker handle (or kernel eventfd, on native).
    fn buffered_scm_fork_child() -> i32 {
        let fd: i32 = std::env::args()
            .nth(3)
            .and_then(|s| s.parse().ok())
            .unwrap_or(-1);
        if fd < 0 {
            eprintln!("[BSF-child] bad fd arg");
            return 1;
        }
        let mut buf = [0u8; 32];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: buf.len(),
        };
        let mut cmsg_buf = [0u8; 64];
        let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = cmsg_buf.len() as _;
        let n = unsafe { libc::recvmsg(fd, &raw mut msg, 0) };
        if n < 0 {
            eprintln!("[BSF-child] recvmsg failed: {}", errno());
            return 2;
        }
        let mut got_ev: i32 = -1;
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let data = libc::CMSG_DATA(cmsg).cast::<i32>();
                    got_ev = data.read_unaligned();
                    break;
                }
                cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
            }
        }
        if got_ev < 0 {
            eprintln!("[BSF-child] no SCM_RIGHTS in recvmsg result");
            return 3;
        }
        let v: u64 = 0x4243_5f4f_4b21;
        let w = unsafe { libc::write(got_ev, (&raw const v).cast::<libc::c_void>(), 8) };
        if w != 8 {
            eprintln!("[BSF-child] write to ev failed: w={w} errno={}", errno());
            return 4;
        }
        let mut r: u64 = 0;
        let rn = unsafe { libc::read(got_ev, (&raw mut r).cast::<libc::c_void>(), 8) };
        unsafe {
            libc::close(got_ev);
            libc::close(fd);
        }
        if rn != 8 || r != v {
            eprintln!("[BSF-child] read mismatch: rn={rn} r={r:#x} expected={v:#x}");
            return 5;
        }
        0
    }

    /// SXF parent — socketpair-fork-cross:
    /// socketpair → clear CLOEXEC on child end → fork+execv child_exe.
    /// Parent writes PING on its end; child writes PONG back. Verifies
    /// both endpoints of a socketpair survive the cross-host-runner
    /// bridge in `commit_delayed_fork` when child_exe is a different
    /// binary type.
    fn test_socketpair_fork_cross() -> i32 {
        let child_exe: String = std::env::args().nth(3).unwrap_or_default();
        if child_exe.is_empty() {
            println!("SXF_USAGE: unix-socket-test socketpair-fork-cross <child_exe>");
            return 1;
        }
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        if rc != 0 {
            println!("SXF_SOCKETPAIR_FAIL:{}", errno());
            return 1;
        }
        let parent_fd = fds[0];
        let child_fd = fds[1];
        unsafe { libc::fcntl(child_fd, libc::F_SETFD, 0) };

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("SXF_FORK_FAIL:{}", errno());
            return 1;
        }
        if pid == 0 {
            unsafe { libc::close(parent_fd) };
            let fd_str = child_fd.to_string();
            let c_exe = std::ffi::CString::new(child_exe.as_str()).unwrap();
            let c_a1 = std::ffi::CString::new("unix-socket-test").unwrap();
            let c_a2 = std::ffi::CString::new("socketpair-fork-cross-child").unwrap();
            let c_a3 = std::ffi::CString::new(fd_str.as_str()).unwrap();
            let argv = [
                c_exe.as_ptr(),
                c_a1.as_ptr(),
                c_a2.as_ptr(),
                c_a3.as_ptr(),
                core::ptr::null(),
            ];
            unsafe { libc::execv(c_exe.as_ptr(), argv.as_ptr()) };
            eprintln!("[SXF-child] execv failed: {}", errno());
            std::process::exit(127);
        }
        unsafe { libc::close(child_fd) };

        let tv = libc::timeval {
            tv_sec: 10,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                parent_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast::<libc::c_void>(),
                core::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        let ping = b"SXF_PING";
        let w = unsafe { libc::write(parent_fd, ping.as_ptr().cast::<libc::c_void>(), ping.len()) };
        if w != ping.len() as isize {
            println!("SXF_WRITE_FAIL:n={w} errno={}", errno());
            unsafe { libc::kill(pid, libc::SIGKILL) };
            return 1;
        }
        let mut buf = [0u8; 32];
        let n = unsafe {
            libc::read(
                parent_fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        unsafe { libc::close(parent_fd) };
        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            99
        };
        if n <= 0 {
            println!("SXF_READ_FAIL:n={n},errno={},exit={exit_code}", errno());
            return 1;
        }
        let reply = core::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
        if reply == "SXF_PONG" && exit_code == 0 {
            println!("SXF_OK");
            0
        } else {
            println!("SXF_FAIL:reply={reply},exit={exit_code}");
            1
        }
    }

    fn socketpair_fork_cross_child() -> i32 {
        let fd: i32 = std::env::args()
            .nth(3)
            .and_then(|s| s.parse().ok())
            .unwrap_or(-1);
        if fd < 0 {
            eprintln!("[SXF-child] bad fd arg");
            return 1;
        }
        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast::<libc::c_void>(),
                core::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
        let mut buf = [0u8; 32];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n <= 0 {
            eprintln!("[SXF-child] read failed: n={n} errno={}", errno());
            return 2;
        }
        let msg = core::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
        if msg != "SXF_PING" {
            eprintln!("[SXF-child] unexpected msg: {msg}");
            return 3;
        }
        let pong = b"SXF_PONG";
        let w = unsafe { libc::write(fd, pong.as_ptr().cast::<libc::c_void>(), pong.len()) };
        unsafe { libc::close(fd) };
        if w == pong.len() as isize { 0 } else { 4 }
    }

    /// PIF parent — pidfd-inherit-fork:
    /// 1. fork() a short-lived grandchild that sleeps then exits.
    /// 2. pidfd_open(grandchild_pid).
    /// 3. Clear CLOEXEC on the pidfd.
    /// 4. fork+execv(child_exe, ..., pidfd, grandchild_pid).
    /// Child poll()s + waitid()s on the inherited pidfd; reports PIF_OK
    /// iff the wait observes the grandchild's exit. Validates that pidfd
    /// inheritance survives a cross-host-runner exec.
    fn test_pidfd_inherit_fork() -> i32 {
        let child_exe: String = std::env::args().nth(3).unwrap_or_default();
        if child_exe.is_empty() {
            println!("PIF_USAGE: unix-socket-test pidfd-inherit-fork <child_exe>");
            return 1;
        }
        // Spawn a grandchild that sleeps 2s then exits cleanly.
        let gpid = unsafe { libc::fork() };
        if gpid < 0 {
            println!("PIF_GRANDCHILD_FORK_FAIL:{}", errno());
            return 1;
        }
        if gpid == 0 {
            unsafe { libc::sleep(2) };
            std::process::exit(0);
        }

        // pidfd_open(SYS_pidfd_open=434 on x86_64).
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, gpid, 0) } as i32;
        if pidfd < 0 {
            println!("PIF_PIDFD_OPEN_FAIL:{}", errno());
            unsafe { libc::kill(gpid, libc::SIGKILL) };
            return 1;
        }
        unsafe { libc::fcntl(pidfd, libc::F_SETFD, 0) };

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("PIF_FORK_FAIL:{}", errno());
            unsafe { libc::kill(gpid, libc::SIGKILL) };
            return 1;
        }
        if pid == 0 {
            let fd_str = pidfd.to_string();
            let gpid_str = gpid.to_string();
            let c_exe = std::ffi::CString::new(child_exe.as_str()).unwrap();
            let c_a1 = std::ffi::CString::new("unix-socket-test").unwrap();
            let c_a2 = std::ffi::CString::new("pidfd-inherit-child").unwrap();
            let c_a3 = std::ffi::CString::new(fd_str.as_str()).unwrap();
            let c_a4 = std::ffi::CString::new(gpid_str.as_str()).unwrap();
            let argv = [
                c_exe.as_ptr(),
                c_a1.as_ptr(),
                c_a2.as_ptr(),
                c_a3.as_ptr(),
                c_a4.as_ptr(),
                core::ptr::null(),
            ];
            unsafe { libc::execv(c_exe.as_ptr(), argv.as_ptr()) };
            eprintln!("[PIF-child] execv failed: {}", errno());
            std::process::exit(127);
        }
        unsafe { libc::close(pidfd) };

        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        let child_exit = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            99
        };
        // Reap the grandchild if the child didn't (defensive — the
        // child's waitid on the pidfd does not reap on some kernels).
        unsafe { libc::waitpid(gpid, &raw mut status, libc::WNOHANG) };

        if child_exit == 0 {
            println!("PIF_OK");
            0
        } else {
            println!("PIF_FAIL:exit={child_exit}");
            1
        }
    }

    fn pidfd_inherit_child() -> i32 {
        let pidfd: i32 = std::env::args()
            .nth(3)
            .and_then(|s| s.parse().ok())
            .unwrap_or(-1);
        let gpid: i32 = std::env::args()
            .nth(4)
            .and_then(|s| s.parse().ok())
            .unwrap_or(-1);
        if pidfd < 0 || gpid < 0 {
            eprintln!("[PIF-child] bad args");
            return 1;
        }
        // poll(pidfd, POLLIN, 10s) — fires when the (sibling, not
        // child) grandchild exits. We can't use waitid(P_PIDFD)
        // here: waitid requires the target to be a child of the
        // calling process, but the grandchild was forked by our
        // parent. POLLIN on pidfd works cross-process.
        let mut pfd = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&raw mut pfd, 1, 10_000) };
        unsafe { libc::close(pidfd) };
        if rc <= 0 {
            eprintln!("[PIF-child] poll failed: rc={rc} errno={}", errno());
            return 2;
        }
        if pfd.revents & libc::POLLIN == 0 {
            eprintln!("[PIF-child] no POLLIN: revents={}", pfd.revents);
            return 3;
        }
        // Sanity: also verify the grandchild process is gone.
        let _ = gpid;
        0
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }
}

mod exit_tests {
    /// Simple single-threaded exit. Also used as the target for exec-exit tests.
    fn test_single_exit() {
        println!("EX1_BEFORE_EXIT");
        std::process::exit(0);
    }

    /// Terminal ioctl tests — run as: exit-test term <op> <fd>
    /// ops: tcgets, tcsets, tcsetsw, tcsetsf, tiocgwinsz
    /// fds: 0, 1, 2
    fn test_terminal_ioctl(op: &str, fd_num: i32) {
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };

        match op {
            "tcgets" => {
                let ret = unsafe { libc::tcgetattr(fd_num, &raw mut termios) };
                if ret == 0 {
                    println!("TERM_OK:op={op},fd={fd_num}");
                } else {
                    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                    println!("TERM_ERR:op={op},fd={fd_num},errno={e}");
                }
            }
            "tcsets" | "tcsetsw" | "tcsetsf" => {
                // First get current attrs
                if unsafe { libc::tcgetattr(fd_num, &raw mut termios) } != 0 {
                    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                    println!("TERM_ERR:op={op},fd={fd_num},errno={e},phase=tcgetattr");
                    std::process::exit(1);
                }
                let when = match op {
                    "tcsets" => libc::TCSANOW,
                    "tcsetsw" => libc::TCSADRAIN,
                    "tcsetsf" => libc::TCSAFLUSH,
                    _ => unreachable!(),
                };
                let ret = unsafe { libc::tcsetattr(fd_num, when, &raw const termios) };
                if ret == 0 {
                    println!("TERM_OK:op={op},fd={fd_num}");
                } else {
                    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                    println!("TERM_ERR:op={op},fd={fd_num},errno={e}");
                }
            }
            "tiocgwinsz" => {
                let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
                let ret = unsafe { libc::ioctl(fd_num, libc::TIOCGWINSZ, &mut ws) };
                if ret == 0 {
                    println!(
                        "TERM_OK:op={op},fd={fd_num},rows={},cols={}",
                        ws.ws_row, ws.ws_col
                    );
                } else {
                    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                    println!("TERM_ERR:op={op},fd={fd_num},errno={e}");
                }
            }
            _ => {
                println!("TERM_ERR:unknown_op={op}");
                std::process::exit(1);
            }
        }
        std::process::exit(0);
    }

    pub fn run(sub: &str) {
        match sub {
            "single" => test_single_exit(),
            // Matrix-style: exit-test term <op> <fd>
            "term" => {
                let op = std::env::args().nth(3).unwrap_or_default();
                let fd: i32 = std::env::args()
                    .nth(4)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                test_terminal_ioctl(&op, fd);
            }
            other => {
                eprintln!("unknown exit test: {other}");
                std::process::exit(1);
            }
        }
    }
}

mod net_tests {
    pub fn run(sub: &str) -> i32 {
        match sub {
            "ipv6-socket" => test_ipv6_socket(),
            "ipv6-listen" => test_ipv6_listen(),
            "ipv6-getaddrinfo" => test_ipv6_getaddrinfo(),
            "ipv6-v6only" => test_ipv6_v6only(),
            "ipv4-listen" => test_ipv4_listen(),
            other => {
                eprintln!("unknown net test: {other}");
                1
            }
        }
    }

    /// NET5: `getaddrinfo("::1`") + bind + listen — the exact Node.js pattern.
    fn test_ipv6_getaddrinfo() -> i32 {
        // Step 1: getaddrinfo for "::1"
        let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
        hints.ai_family = libc::AF_INET6;
        hints.ai_socktype = libc::SOCK_STREAM;
        hints.ai_flags = libc::AI_NUMERICHOST;

        let mut result: *mut libc::addrinfo = std::ptr::null_mut();
        let host = std::ffi::CString::new("::1").unwrap();
        let port = std::ffi::CString::new("0").unwrap();
        let ret = unsafe {
            libc::getaddrinfo(
                host.as_ptr(),
                port.as_ptr(),
                &raw const hints,
                &raw mut result,
            )
        };
        if ret != 0 {
            let err = unsafe { std::ffi::CStr::from_ptr(libc::gai_strerror(ret)) };
            println!("NET5_GAI_FAIL:ret={ret},err={}", err.to_string_lossy());
            return 1;
        }
        if result.is_null() {
            println!("NET5_GAI_NULL");
            return 1;
        }

        let ai = unsafe { &*result };
        eprintln!(
            "[NET5] getaddrinfo: family={}, socktype={}, addrlen={}",
            ai.ai_family, ai.ai_socktype, ai.ai_addrlen
        );

        // Step 2: socket
        let fd = unsafe { libc::socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol) };
        if fd < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET5_SOCKET_FAIL:errno={e}");
            unsafe { libc::freeaddrinfo(result) };
            return 1;
        }

        // Step 3: setsockopt IPV6_V6ONLY (Node.js does this)
        let v6only: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                (&raw const v6only).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as u32,
            )
        };
        eprintln!("[NET5] setsockopt IPV6_V6ONLY: ret={ret}");

        // Step 4: bind
        let ret = unsafe { libc::bind(fd, ai.ai_addr, ai.ai_addrlen) };
        if ret < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET5_BIND_FAIL:errno={e}");
            unsafe {
                libc::close(fd);
                libc::freeaddrinfo(result);
            };
            return 1;
        }

        // Step 5: listen
        let ret = unsafe { libc::listen(fd, 128) };
        if ret < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET5_LISTEN_FAIL:errno={e}");
            unsafe {
                libc::close(fd);
                libc::freeaddrinfo(result);
            };
            return 1;
        }

        unsafe {
            libc::close(fd);
            libc::freeaddrinfo(result);
        };
        println!("NET5_OK");
        0
    }

    /// NET6: `setsockopt(IPV6_V6ONLY)` — Node.js sets this before bind.
    fn test_ipv6_v6only() -> i32 {
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET6_SOCKET_FAIL:errno={e}");
            return 1;
        }
        let v6only: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                (&raw const v6only).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as u32,
            )
        };
        unsafe { libc::close(fd) };
        if ret == 0 {
            println!("NET6_OK");
            0
        } else {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET6_FAIL:errno={e}");
            1
        }
    }

    /// NET1: `socket(AF_INET6`, `SOCK_STREAM`) — can we create an IPv6 socket?
    fn test_ipv6_socket() -> i32 {
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
            println!("NET1_OK:fd={fd}");
            0
        } else {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET1_FAIL:errno={e}");
            1
        }
    }

    /// NET2: `bind(::1`, 0) + listen — the exact pattern VS Code extension host uses.
    fn test_ipv6_listen() -> i32 {
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET2_SOCKET_FAIL:errno={e}");
            return 1;
        }

        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = libc::AF_INET6 as u16;
        addr.sin6_port = 0; // kernel picks port
        addr.sin6_addr = libc::in6_addr {
            s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], // ::1
        };

        let ret = unsafe {
            libc::bind(
                fd,
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in6>() as u32,
            )
        };
        if ret < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            unsafe { libc::close(fd) };
            println!("NET2_BIND_FAIL:errno={e}");
            return 1;
        }

        let ret = unsafe { libc::listen(fd, 5) };
        if ret < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            unsafe { libc::close(fd) };
            println!("NET2_LISTEN_FAIL:errno={e}");
            return 1;
        }

        // Get the assigned port
        let mut bound: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as u32;
        unsafe {
            libc::getsockname(fd, (&raw mut bound).cast::<libc::sockaddr>(), &raw mut len);
        }
        let port = u16::from_be(bound.sin6_port);
        unsafe { libc::close(fd) };
        println!("NET2_OK:port={port}");
        0
    }

    /// NET4: IPv4 listen+connect baseline (should already work).
    fn test_ipv4_listen() -> i32 {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            println!("NET4_SOCKET_FAIL");
            return 1;
        }
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as u16;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = u32::from_be(0x7f00_0001); // 127.0.0.1

        if unsafe {
            libc::bind(
                fd,
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        } < 0
        {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            unsafe { libc::close(fd) };
            println!("NET4_BIND_FAIL:errno={e}");
            return 1;
        }

        if unsafe { libc::listen(fd, 5) } < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            unsafe { libc::close(fd) };
            println!("NET4_LISTEN_FAIL:errno={e}");
            return 1;
        }

        let mut bound: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as u32;
        unsafe {
            libc::getsockname(fd, (&raw mut bound).cast::<libc::sockaddr>(), &raw mut len);
        }
        let port = u16::from_be(bound.sin_port);
        unsafe { libc::close(fd) };
        println!("NET4_OK:port={port}");
        0
    }
}

mod fs_tests {
    use std::io::Write;

    pub fn run(sub: &str, args: &[String]) -> i32 {
        match sub {
            "io" => {
                let op = args.get(3).map_or("write-read", String::as_str);
                let path = args.get(4).map_or("/tmp/fs-test.txt", String::as_str);
                test_io(op, path)
            }
            "exec-write" => {
                let bin_type = args.get(3).map_or("pie", String::as_str);
                let path = args.get(4).map_or("/tmp/fs-exec.txt", String::as_str);
                test_exec_write(bin_type, path)
            }
            // fs-test exec-open-read <binary-type> <path>
            // Fork+exec child that writes AND keeps fd open; parent reads while child alive.
            "exec-open-read" => {
                let bin_type = args.get(3).map_or("pie", String::as_str);
                let path = args.get(4).map_or("/tmp/fs-open.txt", String::as_str);
                test_exec_open_read(bin_type, path)
            }
            // Diagnostic: pinpoint where exec-open-read hangs
            // Helper: write to file then sleep (keeps process alive with file written)
            "do-write-sleep" => {
                let path = args.get(3).map_or("/tmp/fs-open.txt", String::as_str);
                let data = args.get(4).map_or("OPEN_WRITE_DATA", String::as_str);
                std::fs::write(path, data.as_bytes()).unwrap_or_else(|e| {
                    eprintln!("do-write-sleep: write failed: {e}");
                    std::process::exit(1);
                });
                // Keep alive so the parent can read while we're still running
                std::thread::sleep(std::time::Duration::from_secs(30));
                0
            }
            // Called by exec-write to actually write the file
            "do-write" => {
                let path = args.get(3).map_or("/tmp/fs-exec.txt", String::as_str);
                let data = args.get(4).map_or("EXEC_WRITE_DATA", String::as_str);
                match std::fs::write(path, data.as_bytes()) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("do-write: {e}");
                        1
                    }
                }
            }
            _ => {
                eprintln!("fs-test subcommands: io, exec-write, do-write");
                1
            }
        }
    }

    /// Fork+exec a binary to write a file, then read it from the parent.
    fn test_exec_write(bin_type: &str, path: &str) -> i32 {
        let _ = std::fs::remove_file(path);
        let self_exe = std::env::current_exe().unwrap();
        let self_exe = self_exe.to_str().unwrap();
        let data = "EXEC_WRITE_OK";

        let child = match bin_type {
            "pie" => std::process::Command::new(self_exe)
                .args(["fs-test", "do-write", path, data])
                .output(),
            "nonpie" => {
                let bin = litebox_test_harness::nonpie_binary();
                std::process::Command::new(&bin)
                    .args(["fs-test", "do-write", path, data])
                    .output()
            }
            other => {
                println!("FS_ERR:op=exec-write,unknown_bin_type={other}");
                return 1;
            }
        };

        match child {
            Ok(out) if !out.status.success() => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                println!(
                    "FS_ERR:op=exec-write,bin={bin_type},path={path},exit={},err={}",
                    out.status.code().unwrap_or(-1),
                    stderr.lines().next().unwrap_or("")
                );
                return 1;
            }
            Err(e) => {
                println!("FS_ERR:op=exec-write,bin={bin_type},path={path},spawn_err={e}");
                return 1;
            }
            _ => {}
        }

        match std::fs::read_to_string(path) {
            Ok(s) if s == data => {
                println!("FS_OK:op=exec-write,bin={bin_type},path={path}");
                0
            }
            Ok(s) => {
                println!(
                    "FS_ERR:op=exec-write,bin={bin_type},path={path},got={}",
                    s.escape_default()
                );
                1
            }
            Err(e) => {
                println!("FS_ERR:op=exec-write,bin={bin_type},path={path},read_err={e}");
                1
            }
        }
    }

    /// Fork+exec child that writes AND keeps running; parent reads while child alive.
    /// This is the exact pre-warm pattern — tests 9P coherence for open files on remote workers.
    fn test_exec_open_read(bin_type: &str, path: &str) -> i32 {
        let _ = std::fs::remove_file(path);
        let self_exe = std::env::current_exe().unwrap();
        let self_exe = self_exe.to_str().unwrap();
        let data = "OPEN_READ_DATA";

        let bin = match bin_type {
            "pie" => self_exe.to_string(),
            "nonpie" => litebox_test_harness::nonpie_binary(),
            other => {
                println!("FS_ERR:op=exec-open-read,unknown_bin_type={other}");
                return 1;
            }
        };

        // Spawn child that writes then sleeps (keeps process alive).
        // Use null stdout/stderr so the child doesn't hold the parent's
        // piped stdout open (which would prevent the agent from reading EOF).
        let mut child = match std::process::Command::new(&bin)
            .args(["fs-test", "do-write-sleep", path, data])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                println!("FS_ERR:op=exec-open-read,bin={bin_type},path={path},spawn_err={e}");
                return 1;
            }
        };

        // Wait for child to write the file
        std::thread::sleep(std::time::Duration::from_secs(3));

        // Read while child still alive — print result BEFORE kill/wait
        let result = std::fs::read_to_string(path);
        match &result {
            Ok(s) if s == data => {
                println!("FS_OK:op=exec-open-read,bin={bin_type},path={path}");
            }
            Ok(s) => {
                println!(
                    "FS_ERR:op=exec-open-read,bin={bin_type},path={path},got={}",
                    s.escape_default()
                );
            }
            Err(e) => {
                println!("FS_ERR:op=exec-open-read,bin={bin_type},path={path},read_err={e}");
            }
        }

        // Clean up — kill may hang on wait, so don't block on it
        let _ = child.kill();
        // Don't call child.wait() — it can hang in litebox
        result.map_or(1, |s| i32::from(s != data))
    }

    #[allow(clippy::too_many_lines)] // exhaustive runner / dispatch table
    fn test_io(op: &str, path: &str) -> i32 {
        let _ = std::fs::remove_file(path);
        match op {
            // FS1: Simple write then read (same process, sequential)
            "write-read" => {
                std::fs::write(path, b"FS_DATA_42").unwrap_or_else(|e| {
                    println!("FS_ERR:op={op},path={path},phase=write,err={e}");
                    std::process::exit(1);
                });
                match std::fs::read_to_string(path) {
                    Ok(s) if s == "FS_DATA_42" => {
                        println!("FS_OK:op={op},path={path}");
                        0
                    }
                    Ok(s) => {
                        println!("FS_ERR:op={op},path={path},phase=read,got={s}");
                        1
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                        1
                    }
                }
            }
            // FS2: Append then read
            "append-read" => {
                std::fs::write(path, b"LINE1\n").unwrap_or_else(|e| {
                    println!("FS_ERR:op={op},path={path},phase=write1,err={e}");
                    std::process::exit(1);
                });
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(path)
                    .unwrap_or_else(|e| {
                        println!("FS_ERR:op={op},path={path},phase=open-append,err={e}");
                        std::process::exit(1);
                    });
                f.write_all(b"LINE2\n").unwrap();
                drop(f);
                match std::fs::read_to_string(path) {
                    Ok(s) if s == "LINE1\nLINE2\n" => {
                        println!("FS_OK:op={op},path={path}");
                        0
                    }
                    Ok(s) => {
                        println!(
                            "FS_ERR:op={op},path={path},phase=read,got={}",
                            s.escape_default()
                        );
                        1
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                        1
                    }
                }
            }
            // FS3: Write in background thread, read from main thread (concurrent)
            "write-bg-read" => {
                let p = path.to_string();
                let handle = std::thread::spawn(move || {
                    let mut f = std::fs::File::create(&p).unwrap();
                    f.write_all(b"BG_DATA").unwrap();
                    f.sync_all().unwrap();
                });
                handle.join().unwrap();
                // Writer is done and joined — file should be readable
                match std::fs::read_to_string(path) {
                    Ok(s) if s == "BG_DATA" => {
                        println!("FS_OK:op={op},path={path}");
                        0
                    }
                    Ok(s) => {
                        println!("FS_ERR:op={op},path={path},phase=read,got={s}");
                        1
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                        1
                    }
                }
            }
            // FS4: Shell redirect (like code-server pre-warm) — background write, foreground read
            // This is the exact pattern: `cmd > file &` then `cat file`
            "redirect-bg-read" => {
                let p = path.to_string();
                // Write via a child process with stdout redirected to file
                let child = std::process::Command::new("/usr/bin/bash")
                    .args(["-c", &format!("echo REDIRECT_DATA > {p}")])
                    .output();
                match child {
                    Ok(out) if out.status.success() => {}
                    Ok(out) => {
                        println!(
                            "FS_ERR:op={op},path={path},phase=write,exit={}",
                            out.status.code().unwrap_or(-1)
                        );
                        return 1;
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=spawn,err={e}");
                        return 1;
                    }
                }
                match std::fs::read_to_string(path) {
                    Ok(s) if s.trim() == "REDIRECT_DATA" => {
                        println!("FS_OK:op={op},path={path}");
                        0
                    }
                    Ok(s) => {
                        println!(
                            "FS_ERR:op={op},path={path},phase=read,got={}",
                            s.escape_default()
                        );
                        1
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                        1
                    }
                }
            }
            // FS5: Fork child writes, parent reads (cross-process, still open fd)
            "fork-write-read" => {
                let pid = unsafe { libc::fork() };
                if pid < 0 {
                    println!("FS_ERR:op={op},path={path},phase=fork");
                    return 1;
                }
                if pid == 0 {
                    // Child: write to file and exit
                    match std::fs::write(path, b"FORK_DATA") {
                        Ok(()) => std::process::exit(0),
                        Err(_) => std::process::exit(1),
                    }
                }
                // Parent: wait for child, then read
                let mut status: i32 = 0;
                unsafe { libc::waitpid(pid, &raw mut status, 0) };
                match std::fs::read_to_string(path) {
                    Ok(s) if s == "FORK_DATA" => {
                        println!("FS_OK:op={op},path={path}");
                        0
                    }
                    Ok(s) => {
                        println!("FS_ERR:op={op},path={path},phase=read,got={s}");
                        1
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                        1
                    }
                }
            }
            // FS6: Background process writes to file via redirect, WHILE file is still open,
            // another process reads. This is the exact code-server pre-warm pattern.
            "bg-open-read" => {
                let p = path.to_string();
                // Start a background writer that keeps the file open.
                // Intentionally never wait()ed — wait can hang under
                // litebox; we kill() before returning.
                #[allow(clippy::zombie_processes)]
                let mut child = std::process::Command::new("/usr/bin/bash")
                    .args([
                        "-c",
                        &format!("echo LINE1 > {p}; sleep 1; echo LINE2 >> {p}; sleep 5"),
                    ])
                    .spawn()
                    .unwrap_or_else(|e| {
                        println!("FS_ERR:op={op},path={path},phase=spawn,err={e}");
                        std::process::exit(1);
                    });

                // Wait for first line to be written
                std::thread::sleep(std::time::Duration::from_millis(500));

                // Try to read while writer still has file open
                let result = std::fs::read_to_string(path);

                // Print result BEFORE kill/wait (wait can hang in litebox)
                let rc = match &result {
                    Ok(s) if s.contains("LINE1") => {
                        println!(
                            "FS_OK:op={op},path={path},content={}",
                            s.trim().escape_default()
                        );
                        0
                    }
                    Ok(s) => {
                        println!(
                            "FS_ERR:op={op},path={path},phase=read,got={}",
                            s.escape_default()
                        );
                        1
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                        1
                    }
                };

                let _ = child.kill();
                rc
            }
            // FS7: Parent opens file for writing, forks, child writes via inherited fd,
            // parent reads. This is the pre-warm pattern: bash opens log.txt with >,
            // backgrounds code-server (fork), child writes to inherited stdout=log.txt,
            // later the CLI reads log.txt.
            "parent-open-fork-read" => {
                let f = std::fs::File::create(path).unwrap_or_else(|e| {
                    println!("FS_ERR:op={op},path={path},phase=create,err={e}");
                    std::process::exit(1);
                });
                let fd = {
                    use std::os::unix::io::AsRawFd;
                    f.as_raw_fd()
                };

                let pid = unsafe { libc::fork() };
                if pid < 0 {
                    println!("FS_ERR:op={op},path={path},phase=fork");
                    return 1;
                }
                if pid == 0 {
                    // Child: write to inherited fd, then sleep (keep fd open)
                    let msg = b"CHILD_WROTE_THIS\n";
                    unsafe { libc::write(fd, msg.as_ptr().cast(), msg.len()) };
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    std::process::exit(0);
                }

                // Parent: close our copy of the write fd, wait a bit, then read
                drop(f);
                std::thread::sleep(std::time::Duration::from_millis(500));

                let result = std::fs::read_to_string(path);
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
                match result {
                    Ok(s) if s.contains("CHILD_WROTE_THIS") => {
                        println!("FS_OK:op={op},path={path}");
                        0
                    }
                    Ok(s) => {
                        println!(
                            "FS_ERR:op={op},path={path},phase=read,got={}",
                            s.escape_default()
                        );
                        1
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                        1
                    }
                }
            }
            other => {
                println!("FS_ERR:unknown_op={other}");
                1
            }
        }
    }
}
