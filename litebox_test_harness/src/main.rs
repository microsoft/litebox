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
        "exit-with" => {
            let code: i32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            std::process::exit(code);
        }
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(1);
        }
    }
}
