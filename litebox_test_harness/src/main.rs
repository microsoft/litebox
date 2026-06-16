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

#[allow(clippy::too_many_lines)] // exhaustive runner / dispatch table
fn main() {
    litebox_timing::init_from_env();
    // Stage B fd-double-close diagnostic: SIGABRT (the abort std uses
    // for IO Safety violations) normally kills the process with no
    // backtrace. Install a handler that prints one before re-aborting.
    install_sigabrt_backtrace_handler();
    // In the native pass the harness is container PID 1, so the first
    // marker it emits IS the container_pid1_started_ns boundary. The
    // integration harness sets LITEBOX_TIMING_CONTAINER_PID1=1 in
    // native pass to ask for this marker; we emit it BEFORE
    // harness_first_output_ns so the file ordering reflects reality
    // and `t_harness_load_ms = harness_first_output_ns - container_pid1`
    // stays non-negative.
    if std::env::var_os("LITEBOX_TIMING_CONTAINER_PID1").is_some() {
        litebox_timing::emit("container_pid1_started_ns");
    }
    litebox_timing::emit("harness_first_output_ns");

    let args: Vec<String> = std::env::args().collect();
    litebox_timing::emit("harness_args_parsed_ns");
    let cmd = args.get(1).map_or("spawn-tree", String::as_str);
    let self_exe = &args[0];
    if let Some(code) = coordinator::dispatch_fast_leaf(&args) {
        litebox_timing::emit("harness_dispatch_ready_ns");
        std::process::exit(code);
    }
    // PTY tests dup the harness's stderr as stdout; gate diagnostic
    // prints (including the stderr `[TIMING]` proxy line used by the
    // integration harness to bracket the guest under a virtualized
    // CLOCK_MONOTONIC) so they don't contaminate PTY assertions.
    // The file-channel emissions above are structurally PTY-safe (they
    // go to a bind-mounted host directory, not stderr), so they fire
    // unconditionally.
    let is_pty_child = cmd.starts_with("pty-");

    if !is_pty_child {
        // Host-clock proxy: in litebox pass, the guest's
        // CLOCK_MONOTONIC is virtualized, so the integration harness
        // uses the host arrival time of this stderr line as the
        // `harness_first_output_ns` boundary. Keep this minimal sentinel
        // ONLY for that one boundary. All other markers live in the
        // file channel (litebox_timing).
        eprintln!(
            "[TIMING] harness_first_output_ns={}",
            litebox_timing::monotonic_nanos()
        );
    }

    // Log the resolved binary path so stale rootfs copies are immediately
    // obvious (args[0] may differ from the real on-disk path).
    if !is_pty_child && let Ok(real) = std::env::current_exe() {
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
        litebox_timing::emit("harness_dispatch_ready_ns");
        if let Some(code) = coordinator::leaf_subcommand::dispatch(&args) {
            std::process::exit(code);
        }
    } else {
        litebox_timing::emit("harness_dispatch_ready_ns");
    }

    match cmd {
        "spawn-tree" => {
            // Optional: --filter=matrix to run only matrix tests.
            let filter = args.iter().find_map(|a| a.strip_prefix("--filter="));
            // JSON results are emitted incrementally on stdout from
            // TestRunner::record as each test completes (see coordinator/mod.rs).
            // We just compute the summary counts here.
            let results = coordinator::run_filtered(self_exe, filter);
            let pass_count = results.iter().filter(|r| r.outcome() == "pass").count();
            let fail_count = results.iter().filter(|r| r.outcome() == "fail").count();
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
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(1);
        }
    }
}

/// Install a SIGABRT handler that prints a backtrace before letting
/// the default action kill the process. Useful for diagnosing
/// `fatal runtime error: IO Safety violation: owned file descriptor
/// already closed, aborting`, which calls `libc::abort()` with no
/// stack trace.
fn install_sigabrt_backtrace_handler() {
    extern "C" fn handler(_sig: libc::c_int) {
        // SAFETY: write(2) is signal-safe. We use it instead of
        // eprintln to be reentrant. The Backtrace::capture call
        // technically isn't signal-safe but in practice works
        // well enough for diagnostic dumps before re-aborting.
        let bt = std::backtrace::Backtrace::force_capture();
        let msg = format!("[litebox-sigabrt] backtrace:\n{bt}\n");
        unsafe {
            libc::write(2, msg.as_ptr().cast(), msg.len());
        }
        // Restore default SIGABRT and re-raise so the process actually dies.
        unsafe {
            let mut sa: libc::sigaction = core::mem::zeroed();
            sa.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(libc::SIGABRT, &sa, core::ptr::null_mut());
            libc::raise(libc::SIGABRT);
        }
    }
    // SAFETY: installing a signal handler with a well-formed sigaction.
    unsafe {
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = handler as *const () as usize;
        sa.sa_flags = libc::SA_RESETHAND;
        libc::sigaction(libc::SIGABRT, &sa, core::ptr::null_mut());
    }
}
