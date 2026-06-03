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

const STATX_ENOENT_STORM: HandlerToken<(), ProbeOut> = HandlerToken::new("perf.statx_enoent_storm");
const FORK_EXEC_TRUE: HandlerToken<(), ProbeOut> = HandlerToken::new("perf.fork_exec_true");
const FORK_ONLY_EXIT: HandlerToken<(), ProbeOut> = HandlerToken::new("perf.fork_only_exit");
const FORK_WITH_INHERITED_PIPE: HandlerToken<(), ProbeOut> =
    HandlerToken::new("perf.fork_with_inherited_pipe");

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
        let min = if n >= 16 {
            *per_call.first().unwrap()
        } else {
            0
        };
        let max = if n >= 16 {
            *per_call.last().unwrap()
        } else {
            0
        };
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
        let min = if n >= 16 {
            *per_call.first().unwrap()
        } else {
            0
        };
        let max = if n >= 16 {
            *per_call.last().unwrap()
        } else {
            0
        };
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

/// `fork_only_exit`: fork + child immediately calls a non-pre-exec
/// syscall (getppid) and `_exit(0)`; parent waitpid. N=50 iterations.
/// This isolates the cost of the delayed-fork commit path
/// (`spawn_worker_host_for_fork_restore` in
/// `litebox_shim_linux/src/syscalls/process.rs`) from execve overhead
/// and from any broker pipe / notification dependency that the
/// existing harness fork probes (HypB, FORK.*) introduce.
///
/// The `getppid` syscall is the trigger: it is not on the pre-exec
/// allowlist, so it forces the shim to commit the delayed fork and
/// migrate the child to a worker host. The subsequent `_exit(0)` is
/// the only other syscall the child runs, so essentially all
/// per-iter time is spent in clone + commit_delayed_fork + waitpid.
/// Pair with the `[DELAYED-FORK-TIMING]` per-phase log lines emitted
/// by `commit_delayed_fork` to attribute the cost to a phase.
///
/// Native baseline per-iter is ~100µs (just clone + exit + wait); a
/// litebox per-iter measurement plus the per-phase log lines tell
/// you both *whether* spawn_worker_host_for_fork_restore is the
/// dominant cost and *which sub-phase* dominates within it.
async fn handle_fork_only_exit(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ProbeOut, HandlerError> {
    tokio::task::spawn_blocking(|| {
        const ITERATIONS: u64 = 50;
        let mut per_call: Vec<u64> = Vec::with_capacity(ITERATIONS as usize);
        let mut all_successful = true;
        let outer_start = std::time::Instant::now();
        for _ in 0..ITERATIONS {
            let call_start = std::time::Instant::now();
            // SAFETY: fork() — child only invokes async-signal-safe
            // syscalls (getppid, _exit). Parent waits synchronously
            // on the child pid.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                all_successful = false;
                break;
            }
            if pid == 0 {
                // SAFETY: getppid is async-signal-safe and forces a
                // non-pre-exec syscall, triggering commit_delayed_fork
                // in the shim. _exit is async-signal-safe.
                unsafe {
                    libc::getppid();
                    libc::_exit(0);
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
        let min = if n >= 16 {
            *per_call.first().unwrap()
        } else {
            0
        };
        let max = if n >= 16 {
            *per_call.last().unwrap()
        } else {
            0
        };
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

/// `fork_with_inherited_pipe`: parent creates an OS pipe via pipe2(),
/// then forks. Child closes both pipe ends, calls getppid (forces
/// commit_delayed_fork), then _exit(0). Parent waitpids and closes
/// both pipe ends. N=20 iterations.
///
/// Difference vs `fork_only_exit`: the child inherits an open pipe
/// pair, so the shim's commit_delayed_fork path runs the pipe-bridging
/// phase (`pre_pipe_bridging` → `pre_snapshot_serialize`). This is
/// the suspected location of the ~2.2s `commit_delayed_fork` latency
/// observed by HypB probes.
///
/// Compared to PERF.fork_only_exit:
///   - fork_only_exit       — no pipes; isolates spawn-worker-host cost.
///   - fork_with_inherited_pipe — adds 1 pipe-pair; isolates the
///     incremental cost of pipe bridging per snapshot.
async fn handle_fork_with_inherited_pipe(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ProbeOut, HandlerError> {
    tokio::task::spawn_blocking(|| {
        const ITERATIONS: u64 = 20;
        let mut per_call: Vec<u64> = Vec::with_capacity(ITERATIONS as usize);
        let mut all_successful = true;
        let outer_start = std::time::Instant::now();
        for _ in 0..ITERATIONS {
            let mut fds: [libc::c_int; 2] = [-1, -1];
            // SAFETY: pipe2 with O_CLOEXEC into a 2-element array.
            let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
            if rc != 0 {
                all_successful = false;
                break;
            }
            let call_start = std::time::Instant::now();
            // SAFETY: fork — child only invokes async-signal-safe syscalls
            // (close, getppid, _exit). Parent waits synchronously.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                all_successful = false;
                // SAFETY: close fds we just created.
                unsafe {
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                }
                break;
            }
            if pid == 0 {
                // SAFETY: async-signal-safe path.
                unsafe {
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                    libc::getppid();
                    libc::_exit(0);
                }
            }
            let mut status: libc::c_int = 0;
            // SAFETY: waitpid on the child pid we just forked.
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            per_call.push(call_start.elapsed().as_nanos() as u64);
            if waited != pid {
                all_successful = false;
            }
            // SAFETY: close parent-side pipe fds.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
        }
        let elapsed_nanos = outer_start.elapsed().as_nanos() as u64;
        per_call.sort_unstable();
        let n = per_call.len();
        let p50 = if n >= 16 { per_call[n / 2] } else { 0 };
        let p95 = if n >= 16 { per_call[(n * 95) / 100] } else { 0 };
        let min = if n >= 16 {
            *per_call.first().unwrap()
        } else {
            0
        };
        let max = if n >= 16 {
            *per_call.last().unwrap()
        } else {
            0
        };
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

fn report_fork_only_exit(out: &ProbeOut) -> Result<String, String> {
    if !out.all_successful {
        return Err("fork_only_exit: at least one iteration failed".to_string());
    }
    let total_ms = out.elapsed_nanos / 1_000_000;
    if total_ms > 30_000 {
        return Err(format!(
            "fork_only_exit: total elapsed {total_ms}ms exceeds 30000ms budget"
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

fn report_fork_with_inherited_pipe(out: &ProbeOut) -> Result<String, String> {
    if !out.all_successful {
        return Err("fork_with_inherited_pipe: at least one iteration failed".to_string());
    }
    let total_ms = out.elapsed_nanos / 1_000_000;
    // Headroom: 20 iterations * 5s/iter worst-case worker-spawn = 100s.
    if total_ms > 120_000 {
        return Err(format!(
            "fork_with_inherited_pipe: total elapsed {total_ms}ms exceeds 120000ms budget"
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
    register_handler!(FORK_ONLY_EXIT, handle_fork_only_exit);
    register_handler!(FORK_WITH_INHERITED_PIPE, handle_fork_with_inherited_pipe);

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

    // fork-only (no execve, no pipe, no notification): 50 iterations
    // of fork → getppid → _exit → waitpid. Isolates the cost of
    // spawn_worker_host_for_fork_restore (commit_delayed_fork path)
    // from execve and from any broker pipe / notification dependency.
    // Pair with `[DELAYED-FORK-TIMING]` per-phase log lines in the
    // shim to attribute per-iter cost to a sub-phase. Native ~5 ms
    // (clone + exit + wait only); litebox per-iter measurement
    // surfaces the fork-restore handshake overhead in isolation.
    reg.single_agent_handler_test(
        "vscode",
        "perf",
        "PERF.fork_only_exit",
        AgentName::Dpg1,
        &FORK_ONLY_EXIT,
        report_fork_only_exit,
    );

    // fork-with-inherited-pipe (no execve, no notification, but ONE
    // OS pipe is open at fork time): 20 iterations. Isolates the
    // marginal cost of the shim's pipe-bridging phase
    // (pre_pipe_bridging → pre_snapshot_serialize) versus
    // PERF.fork_only_exit. Suspected location of the ~2.2s
    // commit_delayed_fork latency observed in HypB probes.
    reg.single_agent_handler_test(
        "vscode",
        "perf",
        "PERF.fork_with_inherited_pipe",
        AgentName::Dpg1,
        &FORK_WITH_INHERITED_PIPE,
        report_fork_with_inherited_pipe,
    );
}
