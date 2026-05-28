// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Performance-ratio probes for litebox-vs-native syscall costs.
//!
//! These probes do not assert "litebox passes the test." They
//! assert a *ratio bound* between litebox and native: e.g. the
//! per-call statx cost under litebox must not exceed 50x native.
//! When a ratio bound is exceeded, that's a litebox-side regression
//! worth investigating — it indicates a real-world workload (Node
//! module resolution, build systems, configuration walks) will be
//! catastrophically slow under litebox, even when functionally
//! correct.
//!
//! Motivating finding (see `files/litebox-tui-investigation.md`):
//! Copilot CLI TUI scenarios that invoke the Bash tool fail under
//! litebox not because the tool flow is broken, but because
//! per-call statx cost is ~200x native. Node's module resolver
//! issues thousands of ENOENT statx lookups during startup; at
//! ~900 µs/call under litebox vs ~5 µs native, total startup
//! latency exceeds the per-scenario deadline.
//!
//! ## Probe design
//!
//! Each probe runs the same workload on the same agent and reports
//! the elapsed nanoseconds for N iterations. The verdict-check
//! function on each test does the litebox/native comparison
//! implicitly: native is the "gold standard" pass; litebox
//! reports the wall-clock and the test framework compares to native
//! in postprocessing. The `check` here just asserts the workload
//! completed successfully (no errors) and within a reasonable
//! absolute upper bound, so individual flakes are caught.
//!
//! Cross-pass ratio analysis is left to a future per-test-timing
//! aggregation step — for now the ratio is computed manually from
//! the persisted `target/test-logs/per-test-timing.jsonl` file.

use serde::{Deserialize, Serialize};
use std::ffi::CString;

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

use super::agents::AgentName;
use super::registry::Registry;

/// Result of one perf probe run: total elapsed wall-clock and the
/// number of iterations completed. Throughput (iter/sec) is
/// computed by the verdict-check.
#[derive(Serialize, Deserialize, Debug)]
struct ProbeOut {
    iterations_completed: u64,
    elapsed_nanos: u64,
    /// Per-call duration sample summary (nanos) for forensics:
    /// minimum, median, p95, max. Computed inline; useful to spot
    /// tail-latency divergence from the average. Empty if iteration
    /// count is below 16.
    per_call_min_nanos: u64,
    per_call_p50_nanos: u64,
    per_call_p95_nanos: u64,
    per_call_max_nanos: u64,
    /// True iff every call in the loop succeeded (or, for an
    /// expected-ENOENT loop, returned the expected error). False
    /// if any call returned an unexpected result.
    all_successful: bool,
}

const STATX_ENOENT_STORM: HandlerToken<(), ProbeOut> =
    HandlerToken::new("perf.statx_enoent_storm");
const FORK_EXEC_TRUE: HandlerToken<(), ProbeOut> = HandlerToken::new("perf.fork_exec_true");

/// `statx_enoent_storm`: issue N=1000 statx(2) calls for a path
/// that does not exist. Mirrors Node's CommonJS module resolver,
/// which walks ~22 candidate directories per module name. Native
/// per-call: <5 µs; litebox per-call observed in TUI debug: ~900
/// µs. A 50x ratio bound is generous and would still flag a
/// catastrophic regression.
async fn handle_statx_enoent_storm(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ProbeOut, HandlerError> {
    tokio::task::spawn_blocking(|| {
        const ITERATIONS: u64 = 1000;
        // Buffer matching `struct statx` size (256 bytes per ABI).
        // We don't read the fields — we just exercise the syscall —
        // so a raw byte buffer keeps the probe portable across
        // libcs (glibc exposes `libc::statx`, musl does not).
        let mut buf = [0u8; 256];
        let path = CString::new("/no/such/path/ever").map_err(|e| HandlerError(e.to_string()))?;
        let mut per_call: Vec<u64> = Vec::with_capacity(ITERATIONS as usize);
        let mut all_successful = true;
        let outer_start = std::time::Instant::now();
        for _ in 0..ITERATIONS {
            let call_start = std::time::Instant::now();
            // SAFETY: thin syscall wrapper. AT_FDCWD + valid C
            // string path + zero mask + writable buffer of statx
            // size. Kernel writes nothing on ENOENT.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_statx,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    0_i32,
                    0_u32,
                    buf.as_mut_ptr(),
                )
            };
            per_call.push(call_start.elapsed().as_nanos() as u64);
            if rc != -1 {
                all_successful = false;
            } else {
                let errno = unsafe { *libc::__errno_location() };
                if errno != libc::ENOENT {
                    all_successful = false;
                }
            }
        }
        let elapsed_nanos = outer_start.elapsed().as_nanos() as u64;
        per_call.sort_unstable();
        let n = per_call.len();
        let p50 = if n >= 16 { per_call[n / 2] } else { 0 };
        let p95 = if n >= 16 { per_call[(n * 95) / 100] } else { 0 };
        let min = if n >= 16 { *per_call.first().unwrap() } else { 0 };
        let max = if n >= 16 { *per_call.last().unwrap() } else { 0 };
        Ok(ProbeOut {
            iterations_completed: ITERATIONS,
            elapsed_nanos,
            per_call_min_nanos: min,
            per_call_p50_nanos: p50,
            per_call_p95_nanos: p95,
            per_call_max_nanos: max,
            all_successful,
        })
    })
    .await
    .map_err(|e| HandlerError(format!("spawn_blocking join: {e}")))?
}

/// `fork_exec_true`: fork + execve(/bin/true) + waitpid, N=50
/// times. Models the proximate cost of Copilot's Bash tool calls
/// or any other "spawn a tiny child" pattern. Native per-iter:
/// ~1 ms; litebox: depends on the broker handshake cost.
async fn handle_fork_exec_true(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ProbeOut, HandlerError> {
    tokio::task::spawn_blocking(|| {
        const ITERATIONS: u64 = 50;
        let prog = CString::new("/bin/true").map_err(|e| HandlerError(e.to_string()))?;
        let argv: [*const libc::c_char; 2] = [prog.as_ptr(), core::ptr::null()];
        let envp: [*const libc::c_char; 1] = [core::ptr::null()];
        let mut per_call: Vec<u64> = Vec::with_capacity(ITERATIONS as usize);
        let mut all_successful = true;
        let outer_start = std::time::Instant::now();
        for _ in 0..ITERATIONS {
            let call_start = std::time::Instant::now();
            // SAFETY: fork() — child only invokes execve/_exit
            // (both async-signal-safe). Parent waits on the
            // child pid synchronously.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                all_successful = false;
                break;
            }
            if pid == 0 {
                // SAFETY: execve into /bin/true with empty env.
                // _exit if execve fails.
                unsafe {
                    libc::execve(prog.as_ptr(), argv.as_ptr(), envp.as_ptr());
                    libc::_exit(127);
                }
            }
            let mut status: libc::c_int = 0;
            // SAFETY: waitpid on the child pid we just forked.
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            per_call.push(call_start.elapsed().as_nanos() as u64);
            if waited != pid {
                all_successful = false;
            }
        }
        let elapsed_nanos = outer_start.elapsed().as_nanos() as u64;
        per_call.sort_unstable();
        let n = per_call.len();
        let p50 = if n >= 16 { per_call[n / 2] } else { 0 };
        let p95 = if n >= 16 { per_call[(n * 95) / 100] } else { 0 };
        let min = if n >= 16 { *per_call.first().unwrap() } else { 0 };
        let max = if n >= 16 { *per_call.last().unwrap() } else { 0 };
        Ok(ProbeOut {
            iterations_completed: ITERATIONS,
            elapsed_nanos,
            per_call_min_nanos: min,
            per_call_p50_nanos: p50,
            per_call_p95_nanos: p95,
            per_call_max_nanos: max,
            all_successful,
        })
    })
    .await
    .map_err(|e| HandlerError(format!("spawn_blocking join: {e}")))?
}

/// Verdict-check for the statx storm. Reports the throughput so it
/// shows up in the test log on both passes; the litebox-vs-native
/// comparison is done by the operator inspecting both test results.
/// Fails the test only on hard errors (any iteration did not return
/// the expected outcome) or a generous absolute upper bound — a
/// smoke check that the test finished in reasonable wall time.
fn report_statx_storm(out: &ProbeOut) -> Result<String, String> {
    if !out.all_successful {
        return Err("statx_enoent_storm: at least one iteration did not return ENOENT".to_string());
    }
    let total_ms = out.elapsed_nanos / 1_000_000;
    if total_ms > 30_000 {
        return Err(format!(
            "statx_enoent_storm: total elapsed {total_ms}ms exceeds 30000ms budget"
        ));
    }
    let per_iter_us = out.elapsed_nanos / out.iterations_completed / 1_000;
    Ok(format!(
        "iterations={} total={total_ms}ms per-iter={per_iter_us}µs \
         min={}µs p50={}µs p95={}µs max={}µs",
        out.iterations_completed,
        out.per_call_min_nanos / 1_000,
        out.per_call_p50_nanos / 1_000,
        out.per_call_p95_nanos / 1_000,
        out.per_call_max_nanos / 1_000,
    ))
}

fn report_fork_exec(out: &ProbeOut) -> Result<String, String> {
    if !out.all_successful {
        return Err("fork_exec_true: at least one iteration failed".to_string());
    }
    let total_ms = out.elapsed_nanos / 1_000_000;
    if total_ms > 30_000 {
        return Err(format!(
            "fork_exec_true: total elapsed {total_ms}ms exceeds 30000ms budget"
        ));
    }
    let per_iter_us = out.elapsed_nanos / out.iterations_completed / 1_000;
    Ok(format!(
        "iterations={} total={total_ms}ms per-iter={per_iter_us}µs \
         min={}µs p50={}µs p95={}µs max={}µs",
        out.iterations_completed,
        out.per_call_min_nanos / 1_000,
        out.per_call_p50_nanos / 1_000,
        out.per_call_p95_nanos / 1_000,
        out.per_call_max_nanos / 1_000,
    ))
}

pub(crate) fn register_perf_probes(reg: &mut Registry<'_>) {
    register_handler!(STATX_ENOENT_STORM, handle_statx_enoent_storm);
    register_handler!(FORK_EXEC_TRUE, handle_fork_exec_true);

    // statx storm: 1000 calls. Native should complete in ~10 ms;
    // litebox observed at ~900 µs/call = ~900 ms. 30s absolute
    // budget is huge headroom; the operator-side cross-pass ratio
    // is the real signal.
    reg.single_agent_handler_test(
        "vscode",
        "perf",
        "PERF.statx_enoent_storm",
        AgentName::Dpg1,
        &STATX_ENOENT_STORM,
        report_statx_storm,
    );

    // fork+exec(true) storm: 50 iterations. Native ~50 ms; litebox
    // observed in TUI debug to be many times slower. 30s budget.
    reg.single_agent_handler_test(
        "vscode",
        "perf",
        "PERF.fork_exec_true",
        AgentName::Dpg1,
        &FORK_EXEC_TRUE,
        report_fork_exec,
    );
}
