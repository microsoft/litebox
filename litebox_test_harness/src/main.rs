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

fn monotonic_nanos() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out-pointer for `clock_gettime`.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) };
    if rc == 0 {
        let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
        let nanos = u64::try_from(ts.tv_nsec).unwrap_or(0);
        secs * 1_000_000_000 + nanos
    } else {
        0
    }
}

#[allow(clippy::too_many_lines)] // exhaustive runner / dispatch table
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map_or("spawn-tree", String::as_str);
    let self_exe = &args[0];
    // Gate diagnostic prints when invoked as a PTY-test child: the PTY
    // captures the child's stderr alongside its stdout, so any harness
    // boilerplate contaminates PTY-test output assertions.
    let is_pty_child = cmd.starts_with("pty-");

    if !is_pty_child {
        if std::env::var_os("LITEBOX_TIMING_CONTAINER_PID1").is_some() {
            eprintln!("[TIMING] container_pid1_started_ns={}", monotonic_nanos());
        }
        eprintln!("[TIMING] harness_first_output_ns={}", monotonic_nanos());
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
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(1);
        }
    }
}
