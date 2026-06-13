// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Integration test: runs the test harness inside a Docker container to
//! verify behavior against the native Linux gold standard and litebox.
//!
//! Uses `libtest-mimic` for per-suite test discovery. Each coordinator
//! suite (matrix, fork, shell, ...) is a separate Trial under `native::`
//! and `litebox::`, so `cargo test -- native::fork` runs only the fork
//! suite in a single docker container (~20s instead of ~5min).
//!
//! Usage:
//!   cargo test -p `litebox_test_harness` --test integration                          # all
//!   cargo test -p `litebox_test_harness` --test integration -- native                # all native
//!   cargo test -p `litebox_test_harness` --test integration -- `native::fork`          # native fork groups
//!   cargo test -p `litebox_test_harness` --test integration -- `native::fork::capture_pipe`  # one group
//!   cargo test -p `litebox_test_harness` --test integration -- fork                  # fork in both passes
//!   cargo test -p `litebox_test_harness` --test integration -- `litebox::PB` `litebox::EPIPE`  # OR of multiple filters (one process, one setup, shared LITEBOX_TEST_JOBS pool)
//!   cargo test -p `litebox_test_harness` --test integration -- --list                # list all trials
//!
//! Multi-filter note: stock libtest treats multiple positional args as
//! OR'd filters (see <https://doc.rust-lang.org/rustc/tests/index.html#filters>).
//! `libtest-mimic` 0.8 only accepts a single positional, so `main()`
//! pre-scans argv and pre-filters trials before handing them to
//! libtest-mimic, restoring the documented behavior.
//!
//! Target directory: uses `CARGO_TARGET_DIR` if set, otherwise `target/`.
//!
//! To add a rootfs dependency, edit the Dockerfile. There is no other path.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

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

use libtest_mimic::{Arguments, Failed, Trial};

// ── Per-test timing telemetry ────────────────────────────────────────
//
// Per-test results land in the central dashboard sqlite at
// `<main-worktree>/.dashboard/results.sqlite`. The producer writes
// directly there via the `dashboard_store` module below; there is no
// JSONL sink. See litebox_test_harness/scripts/dashboard.py and
// litebox_test_harness/scripts/analyze-test-timing.py for the
// consumer side.

/// Path to the per-trial timing file (host side). Bind-mounted into the
/// container at `/tmp/litebox-timing.log`; each in-container process
/// opens that path via `litebox_timing::init_from_env` and appends its
/// own `[TIMING] name=ns\n` lines.
///
/// The file must exist on the host before `docker run` so the bind
/// mount creates a file (not an implicit directory).
fn timing_log_path_for(pass: &str, test_id: &str) -> PathBuf {
    log_dir().join(format!("{pass}-{}.timing", sanitize_id(test_id)))
}

fn ensure_timing_log_file(path: &Path) {
    // Create (or truncate) so concurrent trials never see stale data.
    // Mode defaults to 0o644; the container bind-mounts the parent
    // directory (not the file itself), so the in-container process
    // creates new file contents via append and host permissions are
    // not the bottleneck.
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
}

fn read_timing_log(
    path: &Path,
    markers: &mut TimingMarkers,
    runtime_rewrites: &mut Vec<String>,
    pass: &str,
) {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return;
    };
    for raw in contents.lines() {
        // Broker emits one of these per runtime ELF rewrite (cache
        // miss in both memory and disk caches). We assert this list
        // is empty for litebox pass — setup() pre-populates the
        // disk cache for the 5 harness variants and the broker's
        // own `pre_warm_elf_cache` covers the shared libraries.
        if let Some(p) = raw.strip_prefix("broker_runtime_rewrite:") {
            // Drop the trailing `=<ns>` value if present.
            let path_only = p.split('=').next().unwrap_or(p);
            runtime_rewrites.push(path_only.to_string());
            continue;
        }
        // The on-disk format is `name=ns\n` (no `[TIMING] ` prefix —
        // that prefix was only for the stderr channel). Prepend it so
        // `record_timing_marker` can reuse the existing parser.
        let synthetic = format!("[TIMING] {raw}");
        record_timing_marker(markers, &synthetic, pass, 0);
    }
}

/// Per-cargo-test broker ELF cache directory (bind-mounted into every
/// litebox-pass docker container). The broker writes pre-warmed
/// rewritten copies of libc/ld-linux/libstdc++ etc. here on first
/// miss; subsequent broker invocations populate their in-memory cache
/// from disk and skip the ~400 ms rewriting step entirely.
fn broker_elf_cache_dir() -> &'static PathBuf {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = target_dir().join("litebox-broker-elf-cache");
        let _ = std::fs::create_dir_all(&dir);
        dir
    })
}

// ── Dashboard sqlite store ───────────────────────────────────────────
// Producer-side direct writes. See `tests/common/dashboard_store.rs`
// for the schema, init, record, finalize, and selection logic.
#[path = "common/dashboard_store.rs"]
mod dashboard_store;

// ── Cross-session concurrency lease ──────────────────────────────────
// Registers this harness invocation in the shared dashboard sqlite so
// every concurrent `cargo test --test integration` invocation on this
// host self-coordinates: each takes `GLOBAL_CAP / live_lease_count`
// of the concurrent docker-dispatch budget. See `tests/common/lease.rs`.
#[path = "common/lease.rs"]
mod lease;

// ── Per-trial container lifecycle framework ──────────────────────────
// Single entry point `framework::run_trial(...)` that every test
// family uses. Owns the dispatch-gate acquire, canonical container
// name allocation, PR_SET_PDEATHSIG, cleanup-registry registration,
// spawn_drain / explicit teardown, and emit_timing_main recording.
// See `tests/common/framework.rs` for the surface + rationale.
#[allow(dead_code)]
#[path = "common/framework.rs"]
mod framework;

// ── Per-worktree Docker image tag helper ─────────────────────────────
// One source of truth for image tag resolution so two concurrent
// worktrees never `docker build -t litebox-test` over each other.
// See `tests/common/image_tag.rs` for resolution order + escape
// hatches (`LITEBOX_IMAGE_TAG`, `LITEBOX_WORKTREE_PATH`).
#[allow(dead_code)]
#[path = "common/image_tag.rs"]
mod image_tag;

fn emit_timing_main(
    test: &str,
    pass: &str,
    suite: &str,
    group: &str,
    t_acquire_ms: u128,
    t_docker_start_ms: u128,
    t_docker_spawn_ms: Option<u128>,
    t_litebox_init_ms: Option<u128>,
    t_harness_load_ms: Option<u128>,
    sub_phases: &SubPhaseMs,
    t_useful_ms: u128,
    verdict: &str,
    _jobs: usize,
) {
    dashboard_store::record_result(
        test,
        pass,
        verdict,
        suite,
        group,
        dashboard_store::Timings {
            t_acquire_ms,
            t_docker_start_ms,
            t_useful_ms,
            t_docker_spawn_ms,
            t_litebox_init_ms,
            t_harness_load_ms,
            t_harness_args_ms: sub_phases.field_value("t_harness_args_ms"),
            t_harness_dispatch_ms: sub_phases.field_value("t_harness_dispatch_ms"),
        },
    );
}

/// All timing markers we recognise on the file channel + the
/// stderr `[TIMING] harness_first_output_ns=` proxy.
///
/// First-wins per name: see `record_timing_marker`. Fields are
/// optional because (a) some code paths skip markers (e.g.
/// `litebox_shim_ready_ns` is absent in native pass) and (b) the
/// stderr scraper only sees `harness_first_output_ns`.
#[derive(Clone, Copy, Default)]
struct TimingMarkers {
    container_pid1_started_ns: Option<u64>,
    tool_executor_args_parsed_ns: Option<u64>,
    tool_executor_audit_open_ns: Option<u64>,
    broker_spawn_called_ns: Option<u64>,
    broker_socket_ready_ns: Option<u64>,
    // Broker-internal phases (litebox_broker emits these via
    // litebox_timing once it inherits LITEBOX_TIMING_PATH from
    // tool_executor). All on host CLOCK_MONOTONIC.
    broker_main_started_ns: Option<u64>,
    broker_args_parsed_ns: Option<u64>,
    broker_policy_loaded_ns: Option<u64>,
    broker_audit_open_ns: Option<u64>,
    broker_listen_called_ns: Option<u64>,
    broker_prewarm_done_ns: Option<u64>,
    broker_first_accept_ns: Option<u64>,
    runner_spawn_called_ns: Option<u64>,
    runner_started_ns: Option<u64>,
    runner_broker_connected_ns: Option<u64>,
    runner_rootfs_ready_ns: Option<u64>,
    runner_program_loaded_ns: Option<u64>,
    litebox_shim_ready_ns: Option<u64>,
    /// Host-clock view of "harness started" — populated from the
    /// stderr arrival_ns proxy in litebox pass, or from the file in
    /// native pass. Used for `t_harness_load_ms` which bridges
    /// runner (host clock) → guest harness.
    harness_first_output_ns: Option<u64>,
    /// Guest-clock view of harness_first_output_ns. In native pass
    /// equal to `harness_first_output_ns`; in litebox pass differs
    /// because the guest's CLOCK_MONOTONIC is virtualized. Used as
    /// the start anchor for `t_harness_args_ms` so harness-internal
    /// sub-phases stay on a single clock domain.
    harness_first_output_ns_guest: Option<u64>,
    harness_args_parsed_ns: Option<u64>,
    harness_dispatch_ready_ns: Option<u64>,
}

/// Sub-phase deltas in milliseconds. All optional — only present when
/// both endpoint markers were observed for the trial.
#[derive(Default)]
struct SubPhaseMs {
    // t_litebox_init_ms breakdown (container_pid1 → litebox_shim_ready)
    t_tool_executor_args_ms: Option<u128>,
    t_tool_executor_audit_ms: Option<u128>,
    t_broker_spawn_ms: Option<u128>,
    t_broker_bind_ms: Option<u128>,
    t_runner_spawn_call_ms: Option<u128>,
    t_runner_fork_ms: Option<u128>,
    t_runner_broker_conn_ms: Option<u128>,
    t_runner_rootfs_ms: Option<u128>,
    t_runner_program_load_ms: Option<u128>,
    t_runner_shim_handoff_ms: Option<u128>,
    // Broker-internal sub-phases. Bracket the broker's own startup
    // gap between bind() and first_accept; on the host clock these
    // overlap with t_runner_spawn_call_ms / t_runner_fork_ms / the
    // tail of t_runner_broker_conn_ms (broker runs concurrently with
    // runner spawn). The "broker_*_ms" deltas are reported separately
    // so they don't double-count against t_litebox_init_ms.
    t_broker_args_ms: Option<u128>,
    t_broker_policy_ms: Option<u128>,
    t_broker_audit_ms: Option<u128>,
    t_broker_listen_ms: Option<u128>,
    t_broker_prewarm_ms: Option<u128>,
    t_broker_accept_ms: Option<u128>,
    // t_harness_load_ms breakdown
    t_guest_runtime_init_ms: Option<u128>,
    t_harness_args_ms: Option<u128>,
    t_harness_dispatch_ms: Option<u128>,
}

impl SubPhaseMs {
    fn compute(m: &TimingMarkers) -> Self {
        let d = |a: Option<u64>, b: Option<u64>| a.zip(b).and_then(|(a, b)| ns_delta_ms(a, b));
        Self {
            t_tool_executor_args_ms: d(m.container_pid1_started_ns, m.tool_executor_args_parsed_ns),
            t_tool_executor_audit_ms: d(
                m.tool_executor_args_parsed_ns,
                m.tool_executor_audit_open_ns,
            ),
            t_broker_spawn_ms: d(m.tool_executor_audit_open_ns, m.broker_spawn_called_ns),
            t_broker_bind_ms: d(m.broker_spawn_called_ns, m.broker_socket_ready_ns),
            t_runner_spawn_call_ms: d(m.broker_socket_ready_ns, m.runner_spawn_called_ns),
            t_runner_fork_ms: d(m.runner_spawn_called_ns, m.runner_started_ns),
            t_runner_broker_conn_ms: d(m.runner_started_ns, m.runner_broker_connected_ns),
            t_runner_rootfs_ms: d(m.runner_broker_connected_ns, m.runner_rootfs_ready_ns),
            t_runner_program_load_ms: d(m.runner_rootfs_ready_ns, m.runner_program_loaded_ns),
            t_runner_shim_handoff_ms: d(m.runner_program_loaded_ns, m.litebox_shim_ready_ns),
            t_broker_args_ms: d(m.broker_main_started_ns, m.broker_args_parsed_ns),
            t_broker_policy_ms: d(m.broker_args_parsed_ns, m.broker_policy_loaded_ns),
            t_broker_audit_ms: d(m.broker_policy_loaded_ns, m.broker_audit_open_ns),
            t_broker_listen_ms: d(m.broker_audit_open_ns, m.broker_listen_called_ns),
            t_broker_prewarm_ms: d(m.broker_listen_called_ns, m.broker_prewarm_done_ns),
            t_broker_accept_ms: d(m.broker_prewarm_done_ns, m.broker_first_accept_ns),
            t_guest_runtime_init_ms: d(m.litebox_shim_ready_ns, m.harness_first_output_ns),
            t_harness_args_ms: d(m.harness_first_output_ns_guest, m.harness_args_parsed_ns),
            t_harness_dispatch_ms: d(m.harness_args_parsed_ns, m.harness_dispatch_ready_ns),
        }
    }

    fn fields(&self) -> [(&'static str, Option<u128>); 19] {
        [
            ("t_tool_executor_args_ms", self.t_tool_executor_args_ms),
            ("t_tool_executor_audit_ms", self.t_tool_executor_audit_ms),
            ("t_broker_spawn_ms", self.t_broker_spawn_ms),
            ("t_broker_bind_ms", self.t_broker_bind_ms),
            ("t_runner_spawn_call_ms", self.t_runner_spawn_call_ms),
            ("t_runner_fork_ms", self.t_runner_fork_ms),
            ("t_runner_broker_conn_ms", self.t_runner_broker_conn_ms),
            ("t_runner_rootfs_ms", self.t_runner_rootfs_ms),
            ("t_runner_program_load_ms", self.t_runner_program_load_ms),
            ("t_runner_shim_handoff_ms", self.t_runner_shim_handoff_ms),
            ("t_broker_args_ms", self.t_broker_args_ms),
            ("t_broker_policy_ms", self.t_broker_policy_ms),
            ("t_broker_audit_ms", self.t_broker_audit_ms),
            ("t_broker_listen_ms", self.t_broker_listen_ms),
            ("t_broker_prewarm_ms", self.t_broker_prewarm_ms),
            ("t_broker_accept_ms", self.t_broker_accept_ms),
            ("t_guest_runtime_init_ms", self.t_guest_runtime_init_ms),
            ("t_harness_args_ms", self.t_harness_args_ms),
            ("t_harness_dispatch_ms", self.t_harness_dispatch_ms),
        ]
    }

    /// Lookup a single field by its emitted JSON key. Used by the
    /// dashboard sqlite writer so we don't have to re-derive each
    /// timing slot at the call site.
    fn field_value(&self, name: &str) -> Option<u128> {
        self.fields()
            .into_iter()
            .find(|(k, _)| *k == name)
            .and_then(|(_, v)| v)
    }
}

fn record_timing_marker(markers: &mut TimingMarkers, line: &str, pass: &str, arrival_ns: u64) {
    let Some(rest) = line.strip_prefix("[TIMING] ") else {
        return;
    };
    let Some((name, value)) = rest.split_once('=') else {
        return;
    };
    let Ok(marker_ns) = value.parse::<u64>() else {
        return;
    };
    let ns = if name == "harness_first_output_ns" && pass == "litebox" && arrival_ns != 0 {
        // Stderr arrival_ns proxy: in litebox pass, the in-guest harness
        // emits this on a virtualized CLOCK_MONOTONIC. The stderr line
        // arrives on the host shortly after the guest writes it; use
        // the host arrival time as the boundary for measurements that
        // bridge the runner → guest seam. arrival_ns=0 means "called
        // from the file reader" — keep the (virtual) value since we
        // have no host-clock proxy to use instead.
        arrival_ns
    } else {
        marker_ns
    };
    // Always preserve the guest-clock value of harness_first_output_ns
    // for harness-internal sub-phase computation (`t_harness_args_ms`
    // etc.) where mixing clocks would underflow.
    if name == "harness_first_output_ns"
        && arrival_ns == 0
        && markers.harness_first_output_ns_guest.is_none()
    {
        markers.harness_first_output_ns_guest = Some(marker_ns);
    }
    macro_rules! first_wins {
        ($field:ident) => {
            if markers.$field.is_none() {
                markers.$field = Some(ns);
            }
        };
    }
    match name {
        "container_pid1_started_ns" => first_wins!(container_pid1_started_ns),
        "tool_executor_args_parsed_ns" => first_wins!(tool_executor_args_parsed_ns),
        "tool_executor_audit_open_ns" => first_wins!(tool_executor_audit_open_ns),
        "broker_spawn_called_ns" => first_wins!(broker_spawn_called_ns),
        "broker_socket_ready_ns" => first_wins!(broker_socket_ready_ns),
        "broker_main_started_ns" => first_wins!(broker_main_started_ns),
        "broker_args_parsed_ns" => first_wins!(broker_args_parsed_ns),
        "broker_policy_loaded_ns" => first_wins!(broker_policy_loaded_ns),
        "broker_audit_open_ns" => first_wins!(broker_audit_open_ns),
        "broker_listen_called_ns" => first_wins!(broker_listen_called_ns),
        "broker_prewarm_done_ns" => first_wins!(broker_prewarm_done_ns),
        "broker_first_accept_ns" => first_wins!(broker_first_accept_ns),
        "runner_spawn_called_ns" => first_wins!(runner_spawn_called_ns),
        "runner_started_ns" => first_wins!(runner_started_ns),
        "runner_broker_connected_ns" => first_wins!(runner_broker_connected_ns),
        "runner_rootfs_ready_ns" => first_wins!(runner_rootfs_ready_ns),
        "runner_program_loaded_ns" => first_wins!(runner_program_loaded_ns),
        "litebox_shim_ready_ns" => first_wins!(litebox_shim_ready_ns),
        "harness_first_output_ns" => first_wins!(harness_first_output_ns),
        "harness_args_parsed_ns" => first_wins!(harness_args_parsed_ns),
        "harness_dispatch_ready_ns" => first_wins!(harness_dispatch_ready_ns),
        _ => {}
    }
}

fn ns_delta_ms(start_ns: u64, end_ns: u64) -> Option<u128> {
    end_ns
        .checked_sub(start_ns)
        .map(|delta_ns| u128::from(delta_ns) / 1_000_000)
}

fn emit_timing_drain(test: &str, pass: &str, t_drain_ms: u128) {
    dashboard_store::record_drain(test, pass, t_drain_ms);
}

// ── Per-test docker run model ────────────────────────────────────────
//
// Each Trial spawns its own docker run with `--filter=<test_id>`. We
// read stdout incrementally; the moment the harness emits the JSON
// result line for our test ID, we record the verdict and let the
// container drain (teardown_tree, kernel reap) in a background thread
// so the next Trial isn't blocked by the ~10 s teardown.
//
// Concurrency is bounded by two semaphores:
//   * `active_jobs` (default 5, env LITEBOX_TEST_JOBS): how many
//     `docker run` invocations may be in their "useful" phase
//     (bringing up agent matrix + running the test). This is the cap
//     that controls peak memory / docker pressure.
//   * `drain_backlog` (default 20, env LITEBOX_DRAIN_BACKLOG): how
//     many post-result containers can be draining concurrently. When
//     we hit this cap the test loop exerts back-pressure rather than
//     letting zombies pile up. With teardown bounded at ~10 s, 20 is
//     comfortably above the steady-state size of (active_jobs *
//     teardown / per_test_useful_phase).
//
// The slow-exit fix (commit 1c1ae050) and lazy-agent-matrix
// (441c7efb) make the per-test useful phase cheap enough (~6 s for
// PIE-only tests) that this model is competitive with the old
// single-docker-per-pass cache.

/// Cached test (id, timeout_secs) tuples from `collect_all_tests`
/// (direct library call, no subprocess).
static TEST_METADATA: std::sync::OnceLock<Vec<TestMeta>> = std::sync::OnceLock::new();

/// (test_id, suite, group, timeout_secs) per registered trial.
/// Authoritative for suite/group — the outer harness uses these
/// instead of the inner coordinator's JSON line so we always have
/// the right metadata even when a test times out before printing.
struct TestMeta {
    id: String,
    suite: &'static str,
    group: &'static str,
    timeout_secs: u64,
}

fn get_test_metadata() -> &'static Vec<TestMeta> {
    TEST_METADATA.get_or_init(|| {
        let tests = litebox_test_harness::coordinator::collect_all_tests();
        let meta: Vec<TestMeta> = tests
            .into_iter()
            .map(|t| TestMeta {
                id: t.id,
                suite: t.suite,
                group: t.group,
                timeout_secs: t.timeout_secs,
            })
            .collect();
        eprintln!(
            "[integration] {} test IDs from collect_all_tests",
            meta.len()
        );
        meta
    })
}

fn get_test_ids() -> Vec<String> {
    get_test_metadata().iter().map(|m| m.id.clone()).collect()
}

/// Lookup the harness-declared per-test timeout (the `.timeout(N)` value
/// the coordinator enforces). Returns 60s as a defensive fallback if
/// the test ID isn't in the registry (shouldn't happen).
fn test_timeout_secs(test_id: &str) -> u64 {
    get_test_metadata()
        .iter()
        .find(|m| m.id == test_id)
        .map(|m| m.timeout_secs)
        .unwrap_or(60)
}

/// Look up (suite, group) from the canonical in-process registry.
/// Used by the producer so dashboard rows always carry the right
/// labels regardless of whether the in-container coordinator
/// managed to emit its JSON line.
fn test_suite_group(test_id: &str) -> Option<(&'static str, &'static str)> {
    get_test_metadata()
        .iter()
        .find(|m| m.id == test_id)
        .map(|m| (m.suite, m.group))
}

/// Whether to keep docker containers after exit (for debugging).
fn keep_containers() -> bool {
    std::env::var("LITEBOX_KEEP_CONTAINER").is_ok()
}

/// `--rm` unless `LITEBOX_KEEP_CONTAINER` is set, plus per-container
/// cgroup-v2 safety bounds so a runaway test (memory leak, fork bomb)
/// can't take down the host. Defaults are deliberately non-binding
/// for normal tests; tighten them via env vars if you're stress-
/// testing or running on a smaller machine:
///   * `LITEBOX_TEST_CPUS`   — `--cpus` value (default unset: no CPU cap)
///   * `LITEBOX_TEST_MEMORY` — `--memory` and `--memory-swap` value (default "8g")
///   * `LITEBOX_TEST_PIDS`   — `--pids-limit` value (default "8192")
///
/// `--memory-swap` is set equal to `--memory` so an exploding test
/// gets OOM-killed instead of thrashing host swap. CPU cap is OFF by
/// default because matrix-heavy tests (e.g., `PB.sp.*`) fork many
/// child processes whose throughput craters under a low `--cpus`
/// value; opt in with `LITEBOX_TEST_CPUS=N` if you're stress-testing
/// concurrency on a host where containers actually compete for CPU.
///
/// The 8 GB / 8192-pid defaults are far above what any test in the
/// current suite needs (typical: ~500 MB, <100 procs); they're a
/// safety net, not a tuning knob. The cgroup-setup overhead they add
/// per `docker run` is small (<5% wall at the default 10-job
/// concurrency on a 16-core host).
fn docker_run_base_args() -> Vec<String> {
    let memory = std::env::var("LITEBOX_TEST_MEMORY").unwrap_or_else(|_| "8g".to_string());
    let pids = std::env::var("LITEBOX_TEST_PIDS").unwrap_or_else(|_| "8192".to_string());
    let mut v: Vec<String> = vec!["run".to_string()];
    if !keep_containers() {
        v.push("--rm".to_string());
    }
    // Capture detailed Rust panic backtraces for diagnostics; harmless
    // when nothing panics.
    v.extend(["-e".to_string(), "RUST_BACKTRACE=full".to_string()]);
    // Forward selected LITEBOX_* env vars into the container so test
    // invocations can flip runtime gates without a rebuild.
    for var in [
        "LITEBOX_EAGER_BROKER_SOCKETPAIR",
        "LITEBOX_EAGER_BROKER_SOCKETSEQPACKET",
        "LITEBOX_BROKER_TCP_CONN",
        "LITEBOX_BROKER_INET_RAW",
        "LITEBOX_BROKER_INET_DELAY_NS",
        "LITEBOX_PE10_DIAG",
        "LITEBOX_PE5_DIAG",
        "LITEBOX_CLEANUP_DELAY_MS",
        "RUST_LOG",
    ] {
        if let Ok(val) = std::env::var(var) {
            v.extend(["-e".to_string(), format!("{var}={val}")]);
        }
    }
    v.extend([
        "--cap-add".to_string(),
        "SYS_PTRACE".to_string(),
        "--memory".to_string(),
        memory.clone(),
        "--memory-swap".to_string(),
        memory,
        "--pids-limit".to_string(),
        pids,
    ]);
    if let Ok(cpus) = std::env::var("LITEBOX_TEST_CPUS") {
        v.extend(["--cpus".to_string(), cpus]);
    }
    v
}

// ── Bounded semaphore (std-only) ─────────────────────────────────────

struct Semaphore {
    permits: Mutex<usize>,
    cv: Condvar,
}

impl Semaphore {
    fn new(n: usize) -> Self {
        Self {
            permits: Mutex::new(n),
            cv: Condvar::new(),
        }
    }

    fn acquire(&'static self) -> SemaphoreGuard {
        let mut p = self.permits.lock().unwrap();
        while *p == 0 {
            p = self.cv.wait(p).unwrap();
        }
        *p -= 1;
        SemaphoreGuard { sem: self }
    }
}

struct SemaphoreGuard {
    sem: &'static Semaphore,
}

impl Drop for SemaphoreGuard {
    fn drop(&mut self) {
        let mut p = self.sem.permits.lock().unwrap();
        *p += 1;
        self.sem.cv.notify_one();
    }
}

// ── Lease-aware dispatch gate ────────────────────────────────────────
//
// The active-dispatch gate has a dynamic cap that floats with
// `lease::live_lease_count()`. Concretely:
//
//     my_cap_now = max(1, min(default_jobs, GLOBAL_CAP / live_leases))
//
// `default_jobs` is the harness's own intrinsic upper bound (today's
// `LITEBOX_TEST_JOBS` / `default_jobs()` value — dockerd starts to
// serialize past it). `GLOBAL_CAP` is the host-wide budget on
// concurrent docker children (default `nproc`, override via
// `LITEBOX_GLOBAL_JOBS`).
//
// When a peer harness appears or exits, the atomic in `lease` is
// refreshed; the next `acquire()` call sees the new cap. Already
// in-flight dispatches finish on their own — we never retract.
struct DispatchGate {
    in_flight: Mutex<usize>,
    cv: Condvar,
}

impl DispatchGate {
    const fn new() -> Self {
        Self {
            in_flight: Mutex::new(0),
            cv: Condvar::new(),
        }
    }

    fn acquire(&'static self) -> DispatchGuard {
        let mut n = self.in_flight.lock().unwrap();
        loop {
            let cap = dynamic_dispatch_cap();
            if *n < cap {
                *n += 1;
                return DispatchGuard { gate: self };
            }
            // Wait with timeout so we re-check the cap periodically;
            // the cap can change without any acquire/release event
            // (e.g. a peer's heartbeat lapses and is pruned).
            let (n2, _) = self
                .cv
                .wait_timeout(n, std::time::Duration::from_secs(2))
                .unwrap();
            n = n2;
        }
    }
}

struct DispatchGuard {
    gate: &'static DispatchGate,
}

impl Drop for DispatchGuard {
    fn drop(&mut self) {
        let mut n = self.gate.in_flight.lock().unwrap();
        *n -= 1;
        self.gate.cv.notify_one();
    }
}

static ACTIVE_JOBS: DispatchGate = DispatchGate::new();
static DRAIN_BACKLOG: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();

static JOBS_CAP: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
static GLOBAL_CAP: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// Dockerd serializes container creation past ~20 concurrent
/// creates regardless of available CPU. This is the per-process
/// safety cap on top of the global lease-divided budget.
const DOCKERD_SAFE_MAX: usize = 20;

fn default_jobs() -> usize {
    // Derive from the host-wide budget so we have one source of
    // truth for "how much parallelism is healthy on this box," with
    // `DOCKERD_SAFE_MAX` clamping the per-process upper bound. The
    // historical `clamp(nproc/1.5, 2, 20)` formula was numerically
    // ~identical to `(nproc*2/3).min(20)` (= global_cap.min(20)),
    // so this preserves behavior while removing the duplicate
    // nproc-based formula.
    global_cap().min(DOCKERD_SAFE_MAX).max(2)
}

fn current_jobs_cap() -> usize {
    *JOBS_CAP.get_or_init(|| {
        std::env::var("LITEBOX_TEST_JOBS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(default_jobs)
    })
}

/// Host-wide budget on concurrent docker children, summed across
/// all live harnesses.
///
/// Default `(nproc * 2) / 3` (e.g. 21 on a 32-CPU box). Lower than
/// raw `nproc` because each litebox-mode container is a small
/// process stack (PID1 → tool_executor → broker → runner →
/// test binary), averaging ~1.5 CPU in steady state. At raw nproc
/// dispatches, the effective load lands around 50, which causes
/// poll-wakeup-sensitive tests (`SCM.pass_eventfd_poll_wake`,
/// pty/signalfd timing) to flake. Capping at 2/3 keeps effective
/// load near nproc.
///
/// Override via `LITEBOX_GLOBAL_JOBS` for stress runs.
fn global_cap() -> usize {
    *GLOBAL_CAP.get_or_init(|| {
        std::env::var("LITEBOX_GLOBAL_JOBS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                let n = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(8);
                (n * 2 / 3).max(2)
            })
    })
}

fn dynamic_dispatch_cap() -> usize {
    let intrinsic = current_jobs_cap();
    let global = global_cap();
    let live = lease::live_lease_count();
    intrinsic.min(global / live).max(1)
}

fn active_jobs() -> &'static DispatchGate {
    &ACTIVE_JOBS
}

fn drain_backlog() -> &'static Semaphore {
    DRAIN_BACKLOG.get_or_init(|| {
        let n = std::env::var("LITEBOX_DRAIN_BACKLOG")
            .ok()
            .and_then(|s| s.parse().ok())
            // Scale with active_jobs: containers finishing their
            // useful phase queue up in the drain backlog while still
            // owning their docker pid/cgroup. ~4× jobs gives enough
            // headroom that we never back-pressure the test loop.
            .unwrap_or_else(|| current_jobs_cap() * 4);
        Semaphore::new(n)
    })
}

// ── Cleanup infrastructure ───────────────────────────────────────────
//
// Two-layer cleanup contract (see also dashboard.py and the plan in
// docs):
//
//   * The dashboard supervisor owns `cargo` and reaps the whole
//     process-group via `killpg`. It is the sledgehammer.
//   * The harness (this binary) owns its in-flight `docker run`
//     children and the containers they launched. Each container is
//     named `litebox-{pass}-{test_id}-{harness_pid}-{nanos}`, so the
//     `{harness_pid}` salt uniquely identifies them.
//
// Three mechanisms compose to make orphaning impossible in practice:
//
//   1. A global registry of (docker_run_pid → container_name) entries
//      that we maintain via `register_docker_child` /
//      `deregister_docker_child` around each `spawn_drain`.
//   2. A top-level SIGTERM/SIGINT handler (installed in `main`) that
//      iterates the registry and runs `docker rm -f` + SIGTERM in
//      parallel, then `exit(130)`.
//   3. `PR_SET_PDEATHSIG=SIGTERM` on (a) the harness itself, so if
//      cargo dies abruptly the kernel signals us → handler fires; and
//      (b) each `docker run` child via `pre_exec`, so if the harness
//      dies abruptly the `docker run` host process self-terminates
//      (its `--rm` flag then garbage-collects the container).
//
// PGIDs are a flat label, not a tree, so we deliberately do NOT call
// `setsid` here — we stay in cargo's process group so the supervisor's
// `killpg` continues to reach us.
mod cleanup {
    use std::collections::HashMap;
    use std::process::{Command, Stdio};
    use std::sync::{Mutex, OnceLock};

    /// Per-registered container: the host docker-run PID (used for
    /// graceful SIGTERM during foreground drain) and a hint about
    /// whether the docker-run host process is still expected to be
    /// alive. Detached containers (`docker run -d`) record the
    /// short-lived docker-run PID which exits as soon as the
    /// container starts; the `pid_alive` field is set false for
    /// those so reap_all skips the SIGTERM step.
    pub(crate) struct ChildEntry {
        pub pid: u32,
        pub pid_alive: bool,
    }

    /// Keyed by **container name** so detached and foreground
    /// containers coexist cleanly (PID alone is ambiguous: a
    /// detached docker-run PID exits and may be reused).
    static CHILDREN: OnceLock<Mutex<HashMap<String, ChildEntry>>> = OnceLock::new();

    fn registry() -> &'static Mutex<HashMap<String, ChildEntry>> {
        CHILDREN.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Register a live container. `pid` is the docker-run host
    /// process's PID; `pid_alive=true` means it's still running and
    /// reap_all should SIGTERM it (foreground), `false` means the
    /// docker-run process already exited (detached) so reap_all
    /// should only do `docker rm -f`.
    pub(crate) fn register_docker_child(pid: u32, container_name: &str, pid_alive: bool) {
        if let Ok(mut g) = registry().lock() {
            g.insert(container_name.to_string(), ChildEntry { pid, pid_alive });
        }
    }

    /// Deregister a container after it's been cleaned up (graceful
    /// drain, explicit teardown, or signal-handler reap).
    pub(crate) fn deregister_docker_child(container_name: &str) {
        if let Ok(mut g) = registry().lock() {
            g.remove(container_name);
        }
    }

    /// Set `PR_SET_PDEATHSIG=SIGTERM` on the current process. Call
    /// early in `main()`. If the parent (cargo) dies, the kernel
    /// sends us SIGTERM, which the top-level handler then turns into
    /// an orderly cleanup of in-flight `docker run` children.
    pub(crate) fn set_self_pdeathsig() {
        // SAFETY: `prctl(PR_SET_PDEATHSIG, sig)` is a no-side-effect
        // single-process self-configuration call; signal is delivered
        // asynchronously only on parent death and is caught by our
        // top-level SIGTERM handler.
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
        }
    }

    /// Snapshot the registry and run `docker rm -f` + (for
    /// foreground entries) SIGTERM on each entry in parallel-bounded
    /// fashion. Best-effort: any individual failure is logged and
    /// skipped. Returns when all entries have been processed (or
    /// 30 s elapsed, whichever first).
    pub(crate) fn reap_all() {
        let snapshot: Vec<(String, u32, bool)> = registry()
            .lock()
            .map(|g| {
                g.iter()
                    .map(|(name, e)| (name.clone(), e.pid, e.pid_alive))
                    .collect()
            })
            .unwrap_or_default();
        if snapshot.is_empty() {
            return;
        }
        eprintln!(
            "[cleanup] reaping {} in-flight docker containers",
            snapshot.len()
        );
        // Bound parallelism to 8: each `docker rm -f` is a daemon RPC
        // and we don't want to amplify daemon load during shutdown.
        // Respect LITEBOX_KEEP_CONTAINER: if set, skip the rm so the
        // user can inspect containers post-mortem even after an
        // unclean shutdown. Foreground SIGTERM is still sent so the
        // docker-run host process can exit cleanly (which lets its
        // container drain naturally; `--rm` was already absent at
        // spawn time so the container survives in `docker ps -a`).
        let keep_containers = std::env::var("LITEBOX_KEEP_CONTAINER").is_ok();
        let chunk = 8usize;
        for batch in snapshot.chunks(chunk) {
            let mut threads = Vec::with_capacity(batch.len());
            for (name, pid, pid_alive) in batch {
                let pid = *pid;
                let pid_alive = *pid_alive;
                let name = name.clone();
                threads.push(std::thread::spawn(move || {
                    if !keep_containers {
                        // 5 s timeout on the docker call via timeout(1).
                        let _ = Command::new("timeout")
                            .args(["5", "docker", "rm", "-f", &name])
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .status();
                    }
                    if pid_alive {
                        // SAFETY: pid came from std::process::Child::id()
                        // of a child we own; SIGTERM is the documented
                        // signal for orderly shutdown. For detached
                        // entries (pid_alive=false) the PID was already
                        // reaped and could be reused — skip the kill.
                        unsafe {
                            libc::kill(pid as i32, libc::SIGTERM);
                        }
                    }
                }));
            }
            for t in threads {
                let _ = t.join();
            }
        }
    }

    /// Install a SIGTERM + SIGINT handler that reaps in-flight docker
    /// children and exits with code 130. Idempotent (safe to call
    /// multiple times — only the first call installs).
    pub(crate) fn install_signal_handler() {
        use signal_hook::consts::{SIGINT, SIGTERM};
        use signal_hook::iterator::Signals;
        let mut signals = match Signals::new([SIGTERM, SIGINT]) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[cleanup] failed to install signal handler: {e}");
                return;
            }
        };
        std::thread::spawn(move || {
            if let Some(sig) = signals.forever().next() {
                eprintln!("[cleanup] received signal {sig}; reaping");
                reap_all();
                // Finalize the dashboard run row so pass_count /
                // fail_count get stamped before we exit. Without
                // this, supervisor-induced timeouts (cycle exceeds
                // wall budget → SIGTERM) leave runs marked OPEN
                // forever (finished_ts_ms IS NULL), even though
                // thousands of result rows landed. The fields are
                // computed from existing run_results so the call
                // is safe + idempotent.
                crate::dashboard_store::finalize();
                // Also deregister our cross-session lease so peers
                // see the live count drop immediately (rather than
                // waiting for STALE_THRESHOLD_MS to prune us).
                crate::lease::deregister();
                std::process::exit(130);
            }
        });
    }
}

/// Best-effort sanitize a test id into a docker container name suffix.
fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// Build the inner docker-run args (everything after `docker run`
/// `[--rm]`) for a standard coordinator-suite trial. Mirrors what
/// the now-deleted `build_docker_cmd` constructed, but as data
/// (Vec<String>) so `framework::run_trial` can own the actual
/// docker invocation.
fn build_standard_docker_args(pass: &str, test_id: &str, bins: &BinaryPaths) -> Vec<String> {
    let mut v: Vec<String> = Vec::with_capacity(40);
    // Skip the first two args of `docker_run_base_args` (`run` +
    // possibly `--rm`) — framework owns those. Everything after
    // that is uniform across families and we want to preserve it.
    let mut base = docker_run_base_args().into_iter();
    let _ = base.next(); // "run"
    if !keep_containers() {
        let _ = base.next(); // "--rm"
    }
    v.extend(base);
    if test_id.starts_with("IOR.") {
        // Docker's default seccomp profile blocks io_uring_setup
        // with EPERM, hiding the WSL2/native kernel baseline this
        // family is meant to test.
        v.push("--security-opt".into());
        v.push("seccomp=unconfined".into());
    }
    if test_id.starts_with("UDS_STREAM.eager_on.") {
        v.push("-e".into());
        v.push("LITEBOX_EAGER_BROKER_SOCKETPAIR=1".into());
    } else if test_id.starts_with("UDS_STREAM.eager_off.") {
        v.push("-e".into());
        v.push("LITEBOX_EAGER_BROKER_SOCKETPAIR=0".into());
    }
    let mounts = [
        (&bins.pie_glibc, "/opt/litebox"),
        (&bins.nonpie_glibc, "/opt/nonpie"),
        (&bins.static_pie_glibc, "/opt/static-pie-glibc"),
        (&bins.static_pie_musl, "/opt/static-pie-musl"),
        (&bins.non_pie_static_musl, "/opt/non-pie-static-musl"),
    ];
    for (src, dst) in mounts {
        v.push("-v".into());
        v.push(format!("{}:{dst}:ro", src.display()));
    }
    v.push("-v".into());
    v.push(format!("{}:/litebox-test-logs", log_dir().display()));
    v.push("-e".into());
    v.push(format!(
        "LITEBOX_TIMING_PATH=/litebox-test-logs/{}",
        timing_log_path_for(pass, test_id)
            .file_name()
            .expect("timing_log_path_for has file name")
            .to_string_lossy(),
    ));
    v.push("-v".into());
    v.push(format!(
        "{}:/litebox-broker-elf-cache",
        broker_elf_cache_dir().display()
    ));
    v.push("-e".into());
    v.push("LITEBOX_BROKER_ELF_CACHE_DIR=/litebox-broker-elf-cache".into());
    if pass == "native" {
        v.push("-e".into());
        v.push("LITEBOX_TIMING_CONTAINER_PID1=1".into());
    }
    v
}

/// Build the full `ContainerSpec` for a standard coordinator-suite
/// trial. Native pass: bare `litebox_test_harness spawn-tree`. Litebox
/// pass: wrap with `timeout --signal=KILL N litebox_tool_executor … --
/// litebox_test_harness spawn-tree`. The inner `timeout` is embedded
/// in `spec.command` rather than using `spec.timeout_secs` because
/// only the litebox path needs it (and only around the inner
/// tool_executor command).
fn build_standard_spec(pass: &str, test_id: &str) -> framework::ContainerSpec {
    let (_, bins) = setup();
    let docker_args = build_standard_docker_args(pass, test_id, &bins);
    let filter = format!("--filter={test_id}");
    let command: Vec<String> = match pass {
        "native" => vec![
            "/opt/litebox/litebox_test_harness".into(),
            "spawn-tree".into(),
            filter,
        ],
        "litebox" => {
            let outer = test_timeout_secs(test_id).saturating_add(15);
            vec![
                "timeout".into(),
                "--signal=KILL".into(),
                outer.to_string(),
                "/opt/litebox/litebox_tool_executor".into(),
                "--rootfs".into(),
                "/".into(),
                "--record-baseline".into(),
                "--".into(),
                "/opt/litebox/litebox_test_harness".into(),
                "spawn-tree".into(),
                filter,
            ]
        }
        _ => panic!("unknown pass: {pass}"),
    };
    framework::ContainerSpec {
        image: image_tag::image_tag("litebox-test"),
        docker_args,
        command,
        detached: false,
        timeout_secs: None,
    }
}

/// Drive closure body for a standard coordinator-suite trial.
/// Owns: stderr-thread for timing-marker scraping, stdout-line
/// parse for the JSON verdict, file-based timing marker
/// computation, runtime-rewrite invariant check. Returns a
/// `DriveResult` for `framework::run_trial` to record + spawn_drain
/// the still-running child.
fn parse_standard_verdict(
    pass: &str,
    test_id: &str,
    child: &mut std::process::Child,
) -> framework::DriveResult {
    use std::io::Write as _;
    let t_spawn = Instant::now();
    let docker_run_invoke_ns = monotonic_nanos();
    let stdout_log = log_path_for(pass, test_id, "stdout");
    let stderr_log = log_path_for(pass, test_id, "stderr");
    let timing_log = timing_log_path_for(pass, test_id);
    ensure_timing_log_file(&timing_log);
    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let timing_markers = Arc::new(Mutex::new(TimingMarkers::default()));
    let stderr_timing_markers = Arc::clone(&timing_markers);
    let stderr_log_for_thread = stderr_log.clone();
    let pass_for_stderr = pass.to_string();
    let _stderr_thread = std::thread::spawn(move || {
        let mut stderr_log_file = std::fs::File::create(&stderr_log_for_thread)
            .unwrap_or_else(|e| panic!("create {}: {e}", stderr_log_for_thread.display()));
        for line in BufReader::new(stderr).lines() {
            let arrival_ns = monotonic_nanos();
            let Ok(line) = line else { break };
            if let Ok(mut markers) = stderr_timing_markers.lock() {
                record_timing_marker(&mut markers, &line, &pass_for_stderr, arrival_ns);
            }
            let _ = writeln!(stderr_log_file, "{line}");
        }
    });
    let mut stdout_log_file = std::fs::File::create(&stdout_log)
        .unwrap_or_else(|e| panic!("create {}: {e}", stdout_log.display()));
    let mut found: Option<serde_json::Value> = None;
    let mut t_first_byte: Option<Instant> = None;
    for line in BufReader::new(stdout).lines() {
        let Ok(line) = line else { break };
        if t_first_byte.is_none() {
            t_first_byte = Some(Instant::now());
        }
        let _ = writeln!(stdout_log_file, "{line}");
        if found.is_none()
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&line)
            && v.get("test").and_then(|t| t.as_str()) == Some(test_id)
        {
            found = Some(v);
            break;
        }
    }
    let t_json = Instant::now();
    let t_json_ns = monotonic_nanos();
    let t_first_byte = t_first_byte.unwrap_or(t_json);
    let mut markers = TimingMarkers::default();
    let mut runtime_rewrites: Vec<String> = Vec::new();
    {
        let stderr_snapshot = *timing_markers.lock().expect("timing markers lock poisoned");
        if let Some(ns) = stderr_snapshot.harness_first_output_ns {
            markers.harness_first_output_ns = Some(ns);
        }
        if let Some(ns) = stderr_snapshot.container_pid1_started_ns {
            markers.container_pid1_started_ns = Some(ns);
        }
        if let Some(ns) = stderr_snapshot.litebox_shim_ready_ns {
            markers.litebox_shim_ready_ns = Some(ns);
        }
    }
    read_timing_log(&timing_log, &mut markers, &mut runtime_rewrites, pass);
    let shim_ready_ns = markers
        .litebox_shim_ready_ns
        .or(markers.container_pid1_started_ns);
    let t_docker_spawn_ms = markers
        .container_pid1_started_ns
        .and_then(|ns| ns_delta_ms(docker_run_invoke_ns, ns));
    let t_litebox_init_ms = markers
        .container_pid1_started_ns
        .zip(shim_ready_ns)
        .and_then(|(start, end)| ns_delta_ms(start, end));
    let t_harness_load_ms = shim_ready_ns
        .zip(markers.harness_first_output_ns)
        .and_then(|(start, end)| ns_delta_ms(start, end));
    let t_docker_start_ms = markers
        .harness_first_output_ns
        .and_then(|ns| ns_delta_ms(docker_run_invoke_ns, ns))
        .unwrap_or_else(|| t_first_byte.duration_since(t_spawn).as_millis());
    let t_useful_ms = markers
        .harness_first_output_ns
        .and_then(|ns| ns_delta_ms(ns, t_json_ns))
        .unwrap_or_else(|| t_json.duration_since(t_first_byte).as_millis());
    let allow_runtime_rewrites = std::env::var_os("LITEBOX_ALLOW_RUNTIME_REWRITES").is_some();
    if pass == "litebox" && !runtime_rewrites.is_empty() && !allow_runtime_rewrites {
        let mut unique: Vec<String> = runtime_rewrites.clone();
        unique.sort();
        unique.dedup();
        let detail = format!(
            "unexpected runtime ELF rewrites ({} unique path(s)): {}; \
             pre-populate via setup() / pre_warm_elf_cache, or set \
             LITEBOX_ALLOW_RUNTIME_REWRITES=1 to bypass",
            unique.len(),
            unique.join(", "),
        );
        found = Some(serde_json::json!({
            "test": test_id,
            "result": "FAIL",
            "detail": detail,
        }));
    }
    let verdict: &'static str = match &found {
        Some(v) => match v.get("result").and_then(|r| r.as_str()) {
            Some("pass") => "pass",
            Some("FAIL") => "FAIL",
            _ => "other",
        },
        None => "no_result",
    };
    let sub_phases = SubPhaseMs::compute(&markers);
    let detail = match (verdict, &found) {
        ("pass", _) => None,
        ("FAIL", Some(v)) => Some(format!(
            "{pass}::{test_id}: {} (logs: {} {})",
            v.get("detail").and_then(|d| d.as_str()).unwrap_or(""),
            stdout_log.display(),
            stderr_log.display(),
        )),
        ("no_result", _) => Some(format!(
            "{pass}[{test_id}]: no JSON result for {test_id} on stdout (full log: {})",
            stdout_log.display(),
        )),
        _ => Some(format!(
            "{pass}::{test_id}: unexpected verdict {verdict} (logs: {} {})",
            stdout_log.display(),
            stderr_log.display(),
        )),
    };
    framework::DriveResult {
        verdict,
        detail,
        t_docker_start_ms,
        t_useful_ms,
        sub_phases,
        t_docker_spawn_ms,
        t_litebox_init_ms,
        t_harness_load_ms,
    }
}

/// Per-trial log directory. Each Trial writes its docker stdout +
/// stderr here so failure investigation is trivial. libtest-mimic
/// captures test-function stdout (where the harness emits its JSON
/// result detail), so without these files the only thing visible in
/// `cargo test` output for a failed trial is the bare "FAILED" line.
fn log_dir() -> &'static PathBuf {
    static LOG_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    LOG_DIR.get_or_init(|| {
        let dir = target_dir().join("test-logs");
        let _ = std::fs::create_dir_all(&dir);
        dir
    })
}

/// Path to a per-Trial log file. `kind` is "stdout" or "stderr".
/// Overwritten on every run; we don't accumulate across runs.
fn log_path_for(pass: &str, test_id: &str, kind: &str) -> PathBuf {
    log_dir().join(format!("{pass}-{}.{kind}.log", sanitize_id(test_id)))
}

/// Wall-clock cap on the post-result drain phase. The drain thread
/// waits for the docker run process to exit on its own; if the
/// inner harness wedges *after* emitting the JSON result line,
/// `child.wait()` would otherwise block until the docker-side
/// `timeout --signal=KILL 120` (litebox pass) catches it. That's
/// 120 s of `drain_backlog` permit pinned for nothing — and on
/// passes without an inner timeout (native), it would be
/// indefinite. This budget is the defensive bound: after it fires,
/// the watchdog forcibly tears the container down via
/// `docker rm -f` plus a SIGTERM to the docker-run client.
///
/// 30 s is generous (the harness's own teardown cap is 5 s, plus
/// container shutdown) but short enough that one wedged test
/// can't paralyse the orchestrator.
fn drain_timeout_secs() -> u64 {
    std::env::var("LITEBOX_DRAIN_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

/// Background drain: hold a `drain_backlog` permit until the child
/// docker process exits, with a wall-clock-bounded watchdog.
///
/// In the normal case the harness's own `teardown_tree` (5 s cap)
/// + `std::process::exit` causes the inner spawn-tree to exit, the
/// docker container terminates, `docker run --rm` cleans up, and
/// `child.wait()` returns within a few seconds. The watchdog
/// observes the wait completion via a oneshot channel and exits
/// without taking action.
///
/// In the wedge case (harness reports JSON, then teardown_tree
/// hangs, or dockerd itself stalls) the watchdog fires after
/// `LITEBOX_DRAIN_TIMEOUT_SECS` and force-tears-down:
///   * `docker rm -f <name>` — destroys the container regardless
///     of internal state.
///   * `kill(docker_run_pid, SIGTERM)` — unblocks our `wait()` even
///     if dockerd isn't responsive.
fn spawn_drain(
    mut child: std::process::Child,
    container_name: String,
    test_id: String,
    pass: &'static str,
    t_drain_start: Instant,
) {
    let backlog_permit = drain_backlog().acquire();
    std::thread::spawn(move || {
        let _hold_backlog = backlog_permit;
        let timeout = Duration::from_secs(drain_timeout_secs());
        let pid = child.id() as i32;
        let cname = container_name;
        // Register so the top-level SIGTERM handler can reap us if the
        // harness is asked to shut down before this drain completes.
        cleanup::register_docker_child(pid as u32, &cname, /* pid_alive */ true);
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let cname_for_watchdog = cname.clone();
        let watchdog = std::thread::spawn(move || {
            if rx.recv_timeout(timeout).is_ok() {
                return;
            }
            eprintln!(
                "[drain] timeout after {} s; forcing teardown of {cname_for_watchdog}",
                timeout.as_secs()
            );
            if !keep_containers() {
                let _ = Command::new("docker")
                    .args(["rm", "-f", &cname_for_watchdog])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            // SAFETY: PID came from std::process::Child::id() of a child we
            // own; signal delivery is synchronous and side-effect-free
            // beyond what we want here.
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
        });
        let _ = child.wait();
        let _ = tx.send(());
        let _ = watchdog.join();
        cleanup::deregister_docker_child(&cname);
        let t_drain_ms = t_drain_start.elapsed().as_millis();
        emit_timing_drain(&test_id, pass, t_drain_ms);
    });
}

// ── Main ─────────────────────────────────────────────────────────────

/// libtest-mimic 0.8 long options that consume the next argv token as
/// their value (i.e. `--foo BAR`). The `--foo=BAR` form is handled
/// separately since it's a single token. Keep in sync with
/// `libtest_mimic::Arguments` (see vendored crate, src/args.rs).
const VALUE_TAKING_LONG: &[&str] = &[
    "--test-threads",
    "--logfile",
    "--skip",
    "--color",
    "--format",
];

/// Walk `argv` (with `argv[0]` being the program name) and return the
/// indices of positional arguments. Implements the standard rule:
///   * args after a bare `--` are all positional;
///   * options of the form `--opt=value` or short flags are a single
///     token;
///   * options listed in [`VALUE_TAKING_LONG`] and the short `-Z`
///     consume the next token as their value;
///   * everything else not starting with `-` is positional.
///
/// Pre-scanning ourselves lets us recover stock-libtest's OR-of-
/// positionals filter semantics (see rustc book, "CLI arguments →
/// Filters"). libtest-mimic 0.8 only accepts a single positional and
/// errors otherwise; we strip the extras before handing argv to it.
fn collect_positionals(argv: &[String]) -> Vec<usize> {
    let mut positionals = Vec::new();
    let mut i = 1;
    let mut after_dashdash = false;
    while i < argv.len() {
        let a = &argv[i];
        if after_dashdash {
            positionals.push(i);
            i += 1;
            continue;
        }
        if a == "--" {
            after_dashdash = true;
            i += 1;
            continue;
        }
        if let Some(rest) = a.strip_prefix("--") {
            if rest.contains('=') {
                i += 1;
            } else if VALUE_TAKING_LONG.iter().any(|v| &v[2..] == rest) {
                i += 2;
            } else {
                i += 1;
            }
        } else if a.starts_with('-') && a.len() > 1 {
            // Short option. `-Z` is the only short option in
            // libtest-mimic that takes a value.
            if a == "-Z" {
                i += 2;
            } else {
                i += 1;
            }
        } else {
            positionals.push(i);
            i += 1;
        }
    }
    positionals
}

fn main() {
    // Cleanup-protocol init (see `cleanup` module). Two side-effects:
    //   * PR_SET_PDEATHSIG=SIGTERM on ourselves, so cargo dying →
    //     kernel SIGTERMs us → handler reaps in-flight containers.
    //   * Install the SIGTERM/SIGINT handler thread. Must happen
    //     before any docker run is dispatched.
    cleanup::set_self_pdeathsig();
    cleanup::install_signal_handler();

    // Normal-exit deregister bridge for the cross-session lease.
    // The signal handler path also deregisters; this guard handles
    // the clean-exit path (libtest-mimic returns normally).
    struct LeaseDropGuard;
    impl Drop for LeaseDropGuard {
        fn drop(&mut self) {
            lease::deregister();
        }
    }
    let _lease_drop_guard = LeaseDropGuard;

    let argv: Vec<String> = std::env::args().collect();
    let pos_idx = collect_positionals(&argv);

    // Extract the positional strings, then strip all but the first
    // from the argv we hand to libtest-mimic (so its single-positional
    // parser doesn't error). We'll apply OR-filtering ourselves below.
    let positionals: Vec<String> = pos_idx.iter().map(|&i| argv[i].clone()).collect();
    // `--fill[=N]` extension: select up to N trials that have no
    // run_results row at the current clean HEAD (dirty_hash IS NULL).
    // Parsed and stripped before handing to libtest-mimic.
    let fill_cap: Option<FillCap> = parse_fill_flag(&argv);
    let mut args = if positionals.len() >= 2 || fill_cap.is_some() {
        let drop: std::collections::HashSet<usize> = pos_idx.iter().skip(1).copied().collect();
        let trimmed: Vec<String> = argv
            .iter()
            .enumerate()
            .filter(|(i, s)| !drop.contains(i) && !is_fill_arg(s))
            .map(|(_, s)| s.clone())
            .collect();
        Arguments::from_iter(trimmed)
    } else {
        Arguments::from_args()
    };

    // Initialize the central dashboard sqlite — but only when the user
    // is actually going to run trials. `--list` mode bypasses init so
    // we don't create empty `runs` rows from discovery passes.
    if !args.list {
        let _ = dashboard_store::init();
        // Register as a live harness so concurrent `cargo test` runs
        // on this host share the host-wide GLOBAL_CAP fairly. Skipped
        // in --list mode (no containers dispatched). Best-effort — if
        // it fails, we fall back to uncoordinated default.
        lease::register();
        // Print the (initial) dispatch cap for visibility — it can
        // shift during execution as peers come and go.
        let intrinsic = current_jobs_cap();
        let global = global_cap();
        let live = lease::live_lease_count();
        let effective = dynamic_dispatch_cap();
        eprintln!(
            "[integration] dispatch cap: intrinsic={intrinsic} global={global} \
             live_peers={live} effective={effective}",
        );
        // Advisory: if the user set LITEBOX_TEST_JOBS explicitly and it's
        // strictly less than the share the lease would otherwise grant,
        // they're self-limiting below their fair share for no benefit
        // (the lease coordinator handles fairness across concurrent
        // runners on its own). The most common cause is a cargo-culted
        // "LITEBOX_TEST_JOBS=4" or "=$(nproc)" in a shared script; both
        // are usually wrong. Speak up at startup so it's discoverable in
        // the agent's own log, not just on a host-debug deep-dive.
        if std::env::var("LITEBOX_TEST_JOBS").is_ok() {
            let lease_share = (global / live).max(1);
            if intrinsic < lease_share {
                eprintln!(
                    "[integration] advisory: LITEBOX_TEST_JOBS={intrinsic} is below \
                     your lease share ({lease_share}); you are self-throttling. The \
                     lease coordinator already divides global={global} fairly across \
                     {live} live runner(s). Unset LITEBOX_TEST_JOBS unless you have \
                     a specific stress-test reason to override.",
                );
            } else if intrinsic > lease_share {
                eprintln!(
                    "[integration] advisory: LITEBOX_TEST_JOBS={intrinsic} exceeds \
                     your lease share ({lease_share}); effective dispatch is clamped \
                     to {lease_share}. The env var only matters when you're the only \
                     test runner on the host; otherwise the lease auto-shares.",
                );
            }
        }
    }

    let mut trials: Vec<Trial> = Vec::new();

    // Generate one Trial per test ID. Each Trial spawns its own
    // docker run with `--filter=<test_id>`; results are recorded as
    // soon as the JSON line for that test ID is observed on stdout,
    // and the container is allowed to drain in a background thread
    // (see `spawn_drain`). Concurrent docker runs are bounded by
    // LITEBOX_TEST_JOBS (default 5).
    let test_ids = get_test_ids();
    for tid in test_ids {
        let tid2 = tid.clone();
        trials.push(Trial::test(format!("native::{tid}"), move || {
            run_pass_group("native", &tid2)
        }));

        let tid2 = tid.clone();
        trials.push(Trial::test(format!("litebox::{tid}"), move || {
            run_pass_group("litebox", &tid2)
        }));
    }

    // Host forwarding trial (not a coordinator suite — uses its own docker run).
    trials.push(Trial::test("host::fwd".to_string(), move || {
        let (_, bins) = setup();
        run_host_fwd(&bins.pie_glibc, &bins.nonpie_glibc);
        Ok(())
    }));

    // Phase H dropbear + bash red-gate scenarios. These are token-free
    // and always registered so regular filters can select them.
    dropbear_bash::register_trials(&mut trials);

    // Copilot CLI integration scenarios — always registered so the
    // dashboard universe stays consistent and the autonomous `--fill`
    // selector can pick them up. Missing GitHub token (a normal
    // dev-environment state for sessions without `gh auth login`)
    // fails each trial cheaply inside its body rather than panicking
    // the whole process; see `mod copilot::run_scenario`.
    //
    // setup() is still called here so litebox-pass copilot trials
    // have the bind-mountable binaries available. The docker image
    // build is deferred to `ensure_copilot_image` inside each trial
    // (idempotent inspect-then-build), so a token-less run incurs
    // zero docker-build cost.
    let _ = setup();
    copilot::register_trials(&mut trials);

    // VS Code Remote Server integration scenarios — always registered
    // (no token required). See `mod vscode` for the scenario set and
    // `litebox_test_harness/CLAUDE.md` "VS Code Server integration
    // scenarios" for invocation knobs.
    vscode::register_trials(&mut trials);

    // Record the universe size on the runs row so the renderer can
    // show "N covered of M known".
    if !args.list {
        dashboard_store::record_universe_size(i64::try_from(trials.len()).unwrap_or(0));
    }

    // `--fill[=N|=Ns]`: pick a batch of trials that have no run_results
    // row at the current clean HEAD. Positional filters take
    // precedence (manual debugging stays sharp).
    if let Some(cap) = fill_cap
        && positionals.is_empty()
    {
        let cap_for_selector = match cap {
            FillCap::Count(n) => dashboard_store::FillCap::Count(n),
            FillCap::BudgetSecs(s) => dashboard_store::FillCap::BudgetSecs {
                secs: s,
                jobs: current_jobs_cap() as u64,
            },
        };
        let kept: std::collections::HashSet<String> =
            dashboard_store::select_fill_batch(&trials, cap_for_selector)
                .into_iter()
                .collect();
        let total = trials.len();
        trials.retain(|t| kept.contains(t.name()));
        let cap_str = match cap {
            FillCap::Count(n) => format!("count={n}"),
            FillCap::BudgetSecs(s) => format!("budget={s}s"),
        };
        eprintln!(
            "[fill] selected {}/{} trials missing for current HEAD ({cap_str})",
            trials.len(),
            total,
        );
    }

    // OR-of-positionals prefilter. When two or more positional filters
    // were given, we already stripped the extras from libtest-mimic's
    // argv; here we drop trials that don't match ANY positional and
    // null out `args.filter` so libtest-mimic doesn't double-filter
    // with just the first positional.
    if positionals.len() >= 2 {
        let exact = args.exact;
        trials.retain(|t| {
            let name = t.name();
            positionals
                .iter()
                .any(|p| if exact { name == p } else { name.contains(p) })
        });
        args.filter = None;
    }

    let conclusion = libtest_mimic::run(&args, trials);
    dashboard_store::finalize();
    // Explicit deregister: `conclusion.exit()` below calls
    // `process::exit()` which bypasses Drop handlers (including our
    // LeaseDropGuard). The Drop guard still serves the panic-unwind
    // path; this line covers normal exit.
    lease::deregister();
    conclusion.exit();
}

/// Parsed `--fill` argument: a hard count cap or a wall-time
/// budget that the selector translates into "as many tests as
/// fit." `--fill` with no value defaults to 300 count.
#[derive(Clone, Copy, Debug)]
enum FillCap {
    Count(usize),
    BudgetSecs(u64),
}

/// Parse `--fill` / `--fill=N` / `--fill=Ns` from argv.
///   `--fill`     → Count(300)
///   `--fill=200` → Count(200)
///   `--fill=600s` → BudgetSecs(600)
fn parse_fill_flag(argv: &[String]) -> Option<FillCap> {
    const DEFAULT_FILL: usize = 300;
    for a in argv {
        if a == "--fill" {
            return Some(FillCap::Count(DEFAULT_FILL));
        }
        if let Some(rest) = a.strip_prefix("--fill=") {
            if let Some(secs) = rest.strip_suffix('s') {
                return Some(FillCap::BudgetSecs(secs.parse().unwrap_or(600)));
            }
            return Some(FillCap::Count(rest.parse().unwrap_or(DEFAULT_FILL)));
        }
    }
    None
}

fn is_fill_arg(a: &str) -> bool {
    a == "--fill" || a.starts_with("--fill=")
}

// ── Per-Trial runner ─────────────────────────────────────────────────

/// Run one Trial: build a `ContainerSpec` + drive closure + call
/// `framework::run_trial`. The framework owns the entire trial
/// lifecycle (gate, name, PDEATHSIG, registry, spawn-drain handoff,
/// recording). The drive closure does the standard-family work:
/// parse the in-container JSON verdict from stdout + scrape timing
/// markers from stderr. See `parse_standard_verdict` and
/// `tests/common/framework.rs`.
fn run_pass_group(pass: &'static str, test_id: &str) -> Result<(), Failed> {
    let (suite, group) = test_suite_group(test_id).expect(
        "test_id missing from registry — run_pass_group only \
         reachable from Trials generated over get_test_ids()",
    );
    let test_id_owned = test_id.to_string();
    let spec = build_standard_spec(pass, test_id);
    framework::run_trial(pass, test_id, suite, group, spec, move |container| {
        let child = container
            .child
            .as_mut()
            .expect("foreground spec → child is Some");
        parse_standard_verdict(pass, &test_id_owned, child)
    })
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Find the workspace root (directory containing Cargo.toml with [workspace]).
fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    // litebox_test_harness/Cargo.toml → workspace root is one level up.
    manifest_dir.parent().expect("workspace root").to_path_buf()
}

/// Determine the target directory for builds.
///
/// Uses `CARGO_TARGET_DIR` if set, otherwise `target/` in the workspace
/// root (the natural cargo default).
fn target_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    workspace_root().join("target")
}

/// Directory containing PIE debug binaries.
fn debug_dir() -> PathBuf {
    target_dir().join("debug")
}

/// Directory containing non-PIE debug binaries.
fn nonpie_dir() -> PathBuf {
    target_dir().join("nonpie/debug")
}

/// Directory containing the static-PIE-glibc debug binary.
fn static_pie_glibc_dir() -> PathBuf {
    target_dir().join("static-pie-glibc/x86_64-unknown-linux-gnu/debug")
}

/// Directory containing the static-PIE-musl debug binary.
fn static_pie_musl_dir() -> PathBuf {
    target_dir().join("static-pie-musl/x86_64-unknown-linux-musl/debug")
}

/// Directory containing the non-PIE-static-musl debug binary.
fn non_pie_static_musl_dir() -> PathBuf {
    target_dir().join("non-pie-static-musl/x86_64-unknown-linux-musl/debug")
}

/// Bundle of all binary-type bind-mount sources discovered during
/// [`setup`]. Each path corresponds to a leg of
/// [`litebox_test_harness::BinaryType`] and is bind-mounted into the
/// Docker container at the conventional `/opt/<label>` path.
///
/// Track 1+2 amortisation (unified): the syscall-rewriter is invoked
/// once per variant in `setup()` and the resulting bytes are written
/// directly into the broker's persistent ELF cache directory
/// (`LITEBOX_BROKER_ELF_CACHE_DIR`, see [`broker_elf_cache_dir`]).
/// On the first 9P read of each `litebox_test_harness` variant the
/// broker hits the disk cache, populates its in-memory cache, and
/// never invokes the rewriter at runtime. Same mechanism the broker
/// uses for its own `pre_warm_elf_cache` of shared libraries —
/// see `litebox_broker::nine_p::server::disk_cache_key`.
#[derive(Debug, Clone)]
struct BinaryPaths {
    pie_glibc: PathBuf,
    nonpie_glibc: PathBuf,
    static_pie_glibc: PathBuf,
    static_pie_musl: PathBuf,
    non_pie_static_musl: PathBuf,
}

/// Find `litebox_syscall_rewriter` in the workspace's target dir.
fn rewriter_path() -> PathBuf {
    debug_dir().join("litebox_syscall_rewriter")
}

/// Sanitise an absolute path into a filesystem-safe filename
/// component, matching `litebox_broker::nine_p::server::disk_cache_key`
/// (sans the mtime suffix it appends). Keep in sync — divergence
/// would cause cache misses where hits are expected.
fn broker_cache_path_component(p: &Path) -> String {
    let mut out = String::new();
    for c in p.as_os_str().to_string_lossy().chars() {
        match c {
            '/' => out.push('_'),
            c if c.is_ascii_alphanumeric() || c == '-' || c == '.' => out.push(c),
            _ => out.push('-'),
        }
    }
    out
}

/// Rewrite `binary` and write the result directly into the broker's
/// persistent ELF cache, keyed by the **in-container** path the
/// broker will resolve when the runner asks for it
/// (`in_container_path`) plus the host file's mtime (which equals
/// the in-container mtime since the file is bind-mounted).
///
/// Idempotent + mtime-validated: if the destination cache file
/// already exists (concurrent setup() in another worktree, or a
/// previous run with the same mtime), do nothing.
fn ensure_rewritten_in_broker_cache(binary: &Path, in_container_path: &Path) {
    let src_meta =
        std::fs::metadata(binary).unwrap_or_else(|e| panic!("stat {}: {e}", binary.display()));
    let mtime = src_meta
        .modified()
        .unwrap()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = format!(
        "{}.{mtime}.elf",
        broker_cache_path_component(in_container_path),
    );
    let dir = broker_elf_cache_dir();
    let cache_path = dir.join(&key);
    if cache_path.exists() {
        return;
    }
    let tmp = dir.join(format!("{key}.tmp.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let rewriter = rewriter_path();
    let status = Command::new(&rewriter)
        .arg(binary)
        .arg("-o")
        .arg(&tmp)
        .status()
        .unwrap_or_else(|e| panic!("invoke {}: {e}", rewriter.display()));
    assert!(
        status.success(),
        "{} {} -> {} failed",
        rewriter.display(),
        binary.display(),
        tmp.display()
    );
    // Atomic rename. If a concurrent writer beat us, the rename
    // either replaces theirs with an identical-content file or our
    // rename loses — either way the resulting file is valid because
    // the rewriter is deterministic for a given input.
    std::fs::rename(&tmp, &cache_path).unwrap_or_else(|e| {
        let _ = std::fs::remove_file(&tmp);
        panic!("rename {} -> {}: {e}", tmp.display(), cache_path.display())
    });
}

/// Build the Docker test image if needed.
fn ensure_docker_image(ws_root: &Path) {
    let tag = image_tag::image_tag("litebox-test");
    eprintln!("Building Docker image {tag}...");
    let dockerfile = ws_root.join("litebox_tool_executor/rootfs/Dockerfile");
    assert!(
        dockerfile.exists(),
        "Dockerfile not found at {}",
        dockerfile.display()
    );
    let status = Command::new("docker")
        .args(["build", "--target", "litebox-test", "-t", &tag, "-f"])
        .arg(&dockerfile)
        .arg(ws_root)
        .status()
        .expect("docker build");
    assert!(status.success(), "Docker build failed for {tag}");
}

/// Build all required binaries (5 legs of `BinaryType`) to the
/// target directory.
///
/// Strict-mode invariant: every leg builds unconditionally; failure to
/// build any one (e.g. missing musl rust target) panics with a clear
/// pointer to the install command. There is no opt-out env var — if
/// the test matrix is going to run, all legs must be available.
fn ensure_binaries_built(ws_root: &Path) {
    let td = target_dir();
    let td_str = td.to_string_lossy();

    eprintln!("Building litebox binaries (PIE-glibc) to {td_str}...");
    let mut build_args: Vec<&str> = vec![
        "build",
        "--target-dir",
        &td_str,
        "-p",
        "litebox_tool_executor",
        "-p",
        "litebox_broker",
        "-p",
        "litebox_runner_linux_userland",
        "-p",
        "litebox_test_harness",
    ];
    let trace_feature_runner;
    if std::env::var("LITEBOX_TRACE_SYSCALLS").is_ok() {
        trace_feature_runner = String::from("litebox_runner_linux_userland/trace_syscalls");
        build_args.push("--features");
        build_args.push(&trace_feature_runner);
    }
    let status = Command::new("cargo")
        .current_dir(ws_root)
        .args(&build_args)
        .status()
        .expect("cargo build");
    assert!(status.success(), "cargo build (PIE-glibc) failed");

    build_companion_binary(
        ws_root,
        "non-PIE-glibc",
        &td.join("nonpie"),
        None,
        None,
        Some("link-args=-no-pie"),
    );
    build_companion_binary(
        ws_root,
        "static-PIE-glibc",
        &td.join("static-pie-glibc"),
        Some("x86_64-unknown-linux-gnu"),
        Some("-C target-feature=+crt-static"),
        None,
    );

    // The musl legs require the rust target to be installed.
    ensure_rust_target("x86_64-unknown-linux-musl");

    build_companion_binary(
        ws_root,
        "static-PIE-musl",
        &td.join("static-pie-musl"),
        Some("x86_64-unknown-linux-musl"),
        Some("-C target-feature=+crt-static"),
        None,
    );
    build_companion_binary(
        ws_root,
        "non-PIE-static-musl",
        &td.join("non-pie-static-musl"),
        Some("x86_64-unknown-linux-musl"),
        Some(
            "-C link-args=-no-pie -C target-feature=+crt-static \
             -C relocation-model=static",
        ),
        None,
    );
}

/// Build a single companion harness binary into `target_dir` with
/// the given Rust target triple, RUSTFLAGS, and optional rustc
/// `-C` flag (passed via `--`). Panics on build failure.
fn build_companion_binary(
    ws_root: &Path,
    label: &str,
    target_dir: &Path,
    rust_target: Option<&str>,
    rustflags: Option<&str>,
    extra_cflag: Option<&str>,
) {
    let td_str = target_dir.to_string_lossy();
    eprintln!("Building litebox_test_harness ({label}) to {td_str}...");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(ws_root);
    if let Some(flags) = rustflags {
        cmd.env("RUSTFLAGS", flags);
    }
    cmd.args([
        "rustc",
        "-p",
        "litebox_test_harness",
        "--bin",
        "litebox_test_harness",
        "--target-dir",
        &td_str,
    ]);
    if let Some(t) = rust_target {
        cmd.args(["--target", t]);
    }
    if let Some(flag) = extra_cflag {
        cmd.args(["--", "-C", flag]);
    }
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("cargo rustc {label}: {e}"));
    assert!(status.success(), "cargo build ({label}) failed");
}

/// Verify the requested rust target is installed via rustup. If it
/// isn't, panic with a clear pointer to `rustup target add`.
fn ensure_rust_target(target: &str) {
    let output = match Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        Ok(o) => panic!(
            "rustup target list failed with status {}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr),
        ),
        Err(e) => panic!("rustup not available: {e}; required for static-PIE-musl build"),
    };
    let installed = String::from_utf8_lossy(&output.stdout);
    assert!(
        installed.lines().any(|line| line.trim() == target),
        "rust target {target} is not installed. Required for the \
         static-PIE-musl and non-PIE-static-musl legs of the test \
         matrix. Install with: rustup target add {target}"
    );
}

/// Shared setup: build binaries and Docker image once per `cargo test`
/// process, return cached paths. libtest-mimic dispatches Trials in
/// threads of one process, so a `OnceLock` guarantees `cargo build`
/// and `docker build` are invoked at most once per run rather than
/// once per Trial. Under `cargo nextest` (where each Trial is its
/// own process) we'd additionally need a `flock`-based file lock;
/// out of scope for this iteration.
static SETUP_ONCE: std::sync::OnceLock<(PathBuf, BinaryPaths)> = std::sync::OnceLock::new();

fn setup() -> (PathBuf, BinaryPaths) {
    SETUP_ONCE
        .get_or_init(|| {
            let ws_root = workspace_root();
            ensure_binaries_built(&ws_root);
            ensure_docker_image(&ws_root);
            // Also build the syscall rewriter so we can pre-rewrite the
            // test_harness variants below. It lives in the default
            // target dir; ensure_binaries_built already pulls it in
            // transitively but be explicit.
            let rewriter_status = Command::new("cargo")
                .current_dir(&ws_root)
                .args([
                    "build",
                    "--target-dir",
                    &target_dir().to_string_lossy(),
                    "-p",
                    "litebox_syscall_rewriter",
                ])
                .status()
                .expect("cargo build litebox_syscall_rewriter");
            assert!(rewriter_status.success(), "cargo build rewriter failed");
            assert!(
                rewriter_path().exists(),
                "rewriter binary missing at {}",
                rewriter_path().display()
            );

            let bins = BinaryPaths {
                pie_glibc: debug_dir(),
                nonpie_glibc: nonpie_dir(),
                static_pie_glibc: static_pie_glibc_dir(),
                static_pie_musl: static_pie_musl_dir(),
                non_pie_static_musl: non_pie_static_musl_dir(),
            };
            // Pre-populate the broker's persistent ELF cache so the
            // first 9P read of each harness variant hits the disk
            // cache and the broker never invokes the rewriter at
            // runtime. The cache key is the **in-container** path
            // the broker will resolve (e.g.
            // `/opt/litebox/litebox_test_harness`) + the host file's
            // mtime (which equals the in-container mtime via the
            // bind mount). See
            // `ensure_rewritten_in_broker_cache` for the key format,
            // which mirrors `litebox_broker::nine_p::server::disk_cache_key`.
            for (label, host_dir, in_container_path) in [
                (
                    "PIE-glibc",
                    &bins.pie_glibc,
                    "/opt/litebox/litebox_test_harness",
                ),
                (
                    "non-PIE-glibc",
                    &bins.nonpie_glibc,
                    "/opt/nonpie/litebox_test_harness",
                ),
                (
                    "static-PIE-glibc",
                    &bins.static_pie_glibc,
                    "/opt/static-pie-glibc/litebox_test_harness",
                ),
                (
                    "static-PIE-musl",
                    &bins.static_pie_musl,
                    "/opt/static-pie-musl/litebox_test_harness",
                ),
                (
                    "non-PIE-static-musl",
                    &bins.non_pie_static_musl,
                    "/opt/non-pie-static-musl/litebox_test_harness",
                ),
            ] {
                let bin = host_dir.join("litebox_test_harness");
                assert!(
                    bin.exists(),
                    "{label} litebox_test_harness not found at {} \
                     after ensure_binaries_built",
                    bin.display()
                );
                let t0 = std::time::Instant::now();
                ensure_rewritten_in_broker_cache(&bin, Path::new(in_container_path));
                let elapsed = t0.elapsed();
                if elapsed.as_millis() > 50 {
                    eprintln!(
                        "[setup] pre-rewrote {label} into broker cache in {} ms",
                        elapsed.as_millis()
                    );
                }
            }
            // Touch suppression: variable is fully initialised by the
            // literal above. No further mutation needed.
            (ws_root, bins)
        })
        .clone()
}

/// Run host-side tests that exercise TCP port forwarding through the broker.
///
/// Launches litebox inside Docker with:
///   --forward-port 19090:10.0.0.2:9090  (control channel)
///   --forward-port 19091:10.0.0.2:9091  (data test port)
///
/// The guest runs `litebox-test-harness agent-listen 9090`, and the host
/// connects via `localhost:19090` to send commands.
#[allow(clippy::too_many_lines)] // exhaustive runner / dispatch table
fn run_host_fwd(debug: &Path, nonpie: &Path) {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    let mut results: Vec<(&str, bool, String)> = Vec::new();

    // Start litebox in Docker with port forwarding + agent-listen mode.
    let pid = std::process::id();
    let container_name = format!("litebox-host-test-{pid}");
    // Dynamic ports to avoid collisions with concurrent test runs.
    let ctrl_port = 19000 + (pid % 1000) * 2;
    let data_port = ctrl_port + 1;
    let ctrl_map = format!("{ctrl_port}:19090");
    let data_map = format!("{data_port}:19091");
    let mut docker = Command::new("docker");
    docker
        .args(if keep_containers() {
            vec!["run", "--name", &container_name]
        } else {
            vec!["run", "--rm", "--name", &container_name]
        })
        .args(["--cap-add", "SYS_PTRACE"])
        .args(["-p", &ctrl_map, "-p", &data_map])
        .arg("-v")
        .arg(format!("{}:/opt/litebox:ro", debug.display()))
        .arg("-v")
        .arg(format!("{}:/opt/nonpie:ro", nonpie.display()))
        .arg(image_tag::image_tag("litebox-test"))
        .args([
            "/opt/litebox/litebox_tool_executor",
            "--rootfs",
            "/",
            "--record-baseline",
            "--forward-port",
            "19090:10.0.0.2:9090",
            "--forward-port",
            "19091:10.0.0.2:9091",
            "--",
            "/opt/litebox/litebox_test_harness",
            "agent-listen",
            "9090",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = docker.spawn().expect("failed to start host-test container");
    eprintln!("[host-test] Container {container_name} started");

    // Helper: send a command and read the JSON response.
    let send_cmd = |w: &mut TcpStream, r: &mut BufReader<TcpStream>, cmd: &str| -> Option<String> {
        let msg = format!("{cmd}\n");
        w.write_all(msg.as_bytes()).ok()?;
        w.flush().ok()?;
        let mut line = String::new();
        r.read_line(&mut line).ok()?;
        Some(line.trim().to_string())
    };

    // Wait for the TCP agent to be ready by retrying a protocol command.
    // Docker's published port can accept before the broker/guest listener is
    // ready, so a bare TCP connect is not a sufficient readiness signal: we
    // probe by issuing `cwd_get` until it returns a well-formed response.
    // The probed connection is then handed off to the H tests; H1 below
    // independently re-issues `cwd_get` and asserts the contract.
    let (mut writer, mut reader) = {
        let mut attempts = 0;
        let mut last_error: Option<String>;
        loop {
            std::thread::sleep(Duration::from_millis(500));
            match TcpStream::connect_timeout(
                &format!("127.0.0.1:{ctrl_port}").parse().unwrap(),
                Duration::from_secs(2),
            ) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
                    let mut probe_reader =
                        BufReader::new(stream.try_clone().expect("clone stream"));
                    match send_cmd(&mut stream, &mut probe_reader, r#"{"cmd":"cwd_get"}"#) {
                        Some(resp) if resp.contains(r#""status":"ok""#) => {
                            eprintln!("[host-test] Agent ready after {attempts} retries");
                            break (stream, probe_reader);
                        }
                        Some(resp) => last_error = Some(format!("unexpected response: {resp}")),
                        None => last_error = Some("no response".to_string()),
                    }
                }
                Err(e) => last_error = Some(e.to_string()),
            }

            attempts += 1;
            if attempts > 30 {
                let _ = Command::new("docker")
                    .args(["kill", &container_name])
                    .status();
                let _ = child.wait();
                let detail = last_error.unwrap_or_else(|| "no readiness attempts made".to_string());
                panic!("[host-test] TCP agent not ready after 15s: {detail}");
            }
        }
    };

    // ── H1: Control channel works ──
    {
        let cmd = r#"{"cmd":"cwd_get"}"#;
        let resp = send_cmd(&mut writer, &mut reader, cmd);
        let pass = resp
            .as_ref()
            .is_some_and(|r| r.contains(r#""status":"ok""#));
        let detail = resp.unwrap_or_else(|| "no response".to_string());
        eprintln!(
            "  {}: H1.control_channel [host] {detail}",
            if pass { "pass" } else { "FAIL" }
        );
        results.push(("H1.control_channel", pass, detail));
    }

    // ── H2: Data forwarding — guest listens, host connects via second forwarded port ──
    {
        let cmd = r#"{"cmd":"net_listen","port":9091}"#;
        let resp = send_cmd(&mut writer, &mut reader, cmd);
        let listen_ok = resp
            .as_ref()
            .is_some_and(|r| r.contains(r#""status":"listening""#));

        let mut data_pass = false;
        let mut detail = format!("listen={listen_ok}");
        if listen_ok {
            // Connect to the echo server via the second forwarded port.
            std::thread::sleep(Duration::from_millis(200));
            match TcpStream::connect_timeout(
                &format!("127.0.0.1:{data_port}").parse().unwrap(),
                Duration::from_secs(5),
            ) {
                Ok(mut data_stream) => {
                    data_stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .ok();
                    let _ = data_stream.write_all(b"HOST_ECHO_TEST");
                    let _ = data_stream.flush();
                    let mut buf = [0u8; 256];
                    match data_stream.read(&mut buf) {
                        Ok(n) if n > 0 => {
                            let echo = String::from_utf8_lossy(&buf[..n]).to_string();
                            data_pass = echo == "HOST_ECHO_TEST";
                            detail = format!("echo={echo:?}");
                        }
                        Ok(_) => detail = "no echo data".to_string(),
                        Err(e) => detail = format!("read error: {e}"),
                    }
                }
                Err(e) => detail = format!("connect to 19091 failed: {e}"),
            }
            // Unlisten.
            let _ = send_cmd(
                &mut writer,
                &mut reader,
                r#"{"cmd":"net_unlisten","port":9091}"#,
            );
        }
        eprintln!(
            "  {}: H2.data_forward [host] {detail}",
            if data_pass { "pass" } else { "FAIL" }
        );
        results.push(("H2.data_forward", data_pass, detail));
    }

    // ── H3: File read via 9P (host wrote file in rootfs, guest reads) ──
    // Note: this only works with directory rootfs. With tar rootfs the host
    // can't write to the guest filesystem. Skip if not applicable.
    {
        let cmd = r#"{"cmd":"env_get","var":"HOME"}"#;
        let resp = send_cmd(&mut writer, &mut reader, cmd);
        let pass = resp
            .as_ref()
            .is_some_and(|r| r.contains(r#""status":"ok""#));
        let detail = resp.unwrap_or_else(|| "no response".to_string());
        eprintln!(
            "  {}: H3.env_get [host] {detail}",
            if pass { "pass" } else { "FAIL" }
        );
        results.push(("H3.env_get", pass, detail));
    }

    // ── Shutdown ──
    let _ = send_cmd(&mut writer, &mut reader, r#"{"cmd":"exit"}"#);
    drop(writer);
    drop(reader);

    // Wait for the container to exit.
    let _ = child.wait();

    // ── Report results ──
    let pass_count = results.iter().filter(|(_, p, _)| *p).count();
    let fail_count = results.iter().filter(|(_, p, _)| !*p).count();
    eprintln!(
        "\n=== [host-test] {pass_count} passed, {fail_count} failed out of {} ===",
        results.len()
    );

    if fail_count > 0 {
        eprintln!("\n=== [host-test] FAILURES ===");
        for (name, pass, detail) in &results {
            if !pass {
                eprintln!("  {name}: {detail}");
            }
        }
        panic!(
            "[host-test] {fail_count} host-side test(s) failed. \
             See details above."
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//
// Copilot CLI integration scenarios
//
// Trials that exercise Copilot CLI under litebox using the real
// deployment shape (sshd-inside-sandbox, agent driven over SSH).
// Two invocation modes per scenario, both fully automated via the
// existing host-side PTY primitive (`litebox_test_harness::os::pty::Pty`):
//
//   copilot::pminus.<scenario>  — `ssh -tt root@127.0.0.1 -p N copilot -p ...`
//   copilot::tui.<scenario>     — `ssh -tt root@127.0.0.1 -p N copilot` (prompt loop)
//
// Each registers `native::<full_id>` and `litebox::<full_id>` Trials.
// Native pass runs plain dropbear; litebox pass wraps dropbear in
// `litebox_tool_executor --rootfs / -- dropbear ...`. The ssh client
// invocation is identical in both passes.
//
// Unconditional registration: copilot trials are always part of the
// trial set so the dashboard universe stays consistent and the
// autonomous `--fill` selector picks them up like any other
// `<pass>::<id>` trial. Missing GitHub token (a normal
// dev-environment state) is reported as a per-trial Failed result
// rather than panicking the test process at registration time —
// see `mod copilot::token` and `run_scenario`. The docker image
// build is deferred to the per-trial `ensure_copilot_image` call,
// so token-less runs incur zero docker cost.
//
// Concurrency cap `LITEBOX_COPILOT_JOBS` (default 1, serial) bounds
// concurrent Copilot trials independently of `LITEBOX_TEST_JOBS`.
// The serial default protects shared/autonomous runs from GitHub
// API throttling; one-shot validation runs should raise it (e.g.
// `LITEBOX_COPILOT_JOBS=4`) — nothing in-tree forces serialization.
//
// Three scenarios (`pipeline_wc`, `find_head`, `build`) are expected
// to FAIL on the litebox pass on `wportnoy/vscode-server-in-litebox`
// HEAD today. That is the TDD contract for the
// bash-output-read-hang shim bug: native passes 12/12 (gold standard);
// litebox passes 6/12 today and 12/12 after the shim is fixed. See
// `litebox_test_harness/CLAUDE.md` "Copilot CLI integration scenarios".
//
// ════════════════════════════════════════════════════════════════════

mod copilot {
    use super::{Failed, Trial};
    use litebox_test_harness::os::pty::Pty;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    /// Headless xterm-class terminal emulator backing `drive_tui`.
    ///
    /// Wraps [`alacritty_terminal::Term`] so the harness presents a
    /// real terminal model to the Copilot CLI's TUI library. Without
    /// this, the TUI's initial capability discovery (OSC color
    /// queries, kitty keyboard protocol, cursor position) blocks
    /// forever waiting for replies the raw PTY pair cannot produce.
    ///
    /// API:
    /// - [`Emulator::feed`] pumps PTY-master bytes into the emulator;
    ///   while parsing, the [`alacritty_terminal::Term`] generates
    ///   [`Event::PtyWrite`] / [`Event::ColorRequest`] / etc. for
    ///   sequences that demand a reply. They are collected into the
    ///   `pending_writes` queue.
    /// - [`Emulator::take_pty_writes`] drains queued replies for the
    ///   driver to write back to the PTY master.
    /// - [`Emulator::screen_text`] returns the visible region as a
    ///   plain-text snapshot, lines joined with `\n`. Used by the
    ///   scenario `check` functions and for forensic transcripts.
    ///
    /// The emulator is 100 x 30 by default — wide enough for the
    /// Copilot CLI's panels without scrolling concerns.
    pub(super) mod term_emu {
        use alacritty_terminal::event::{Event, EventListener, WindowSize};
        use alacritty_terminal::index::{Column, Line, Point};
        use alacritty_terminal::term::cell::Flags;
        use alacritty_terminal::term::test::TermSize;
        use alacritty_terminal::term::{Config, Term};
        use alacritty_terminal::vte::ansi::Processor;
        use std::sync::Mutex;

        /// `Term::send_event` calls this listener for actions that
        /// require host-side handling (writes back to PTY, clipboard,
        /// color queries, window size). The driver only cares about
        /// `PtyWrite` and `ColorRequest`; everything else is dropped.
        struct Listener {
            queue: Mutex<Vec<Vec<u8>>>,
        }

        impl Listener {
            fn new() -> Self {
                Self {
                    queue: Mutex::new(Vec::new()),
                }
            }

            fn push(&self, bytes: Vec<u8>) {
                self.queue.lock().unwrap().push(bytes);
            }

            fn drain(&self) -> Vec<Vec<u8>> {
                std::mem::take(&mut *self.queue.lock().unwrap())
            }
        }

        /// Newtype wrapper so we can `impl EventListener` (the trait
        /// is foreign and `Arc<Listener>` is a foreign type).
        #[derive(Clone)]
        struct ListenerHandle(std::sync::Arc<Listener>);

        impl EventListener for ListenerHandle {
            fn send_event(&self, event: Event) {
                match event {
                    Event::PtyWrite(s) => self.0.push(s.into_bytes()),
                    Event::ColorRequest(idx, fmt) => {
                        // Reply with a plausible color for the queried
                        // index. The Copilot CLI just needs *some*
                        // reply to unblock. We use a fixed gray
                        // palette — the actual values do not matter
                        // for headless testing.
                        let rgb = alacritty_terminal::vte::ansi::Rgb {
                            r: 0x80,
                            g: 0x80,
                            b: 0x80,
                        };
                        let _ = idx;
                        self.0.push(fmt(rgb).into_bytes());
                    }
                    Event::TextAreaSizeRequest(fmt) => {
                        let ws = WindowSize {
                            num_lines: 30,
                            num_cols: 100,
                            cell_width: 10,
                            cell_height: 20,
                        };
                        self.0.push(fmt(ws).into_bytes());
                    }
                    _ => {}
                }
            }
        }

        pub(in super::super) struct Emulator {
            term: Term<ListenerHandle>,
            parser: Processor,
            listener: ListenerHandle,
            cols: usize,
            rows: usize,
        }

        impl Emulator {
            pub(in super::super) fn new() -> Self {
                let cols = 100usize;
                let rows = 30usize;
                let listener = ListenerHandle(std::sync::Arc::new(Listener::new()));
                let size = TermSize::new(cols, rows);
                let term = Term::new(Config::default(), &size, listener.clone());
                Self {
                    term,
                    parser: Processor::new(),
                    listener,
                    cols,
                    rows,
                }
            }

            /// Feed bytes received from the PTY master into the
            /// emulator. Any auto-reply sequences (color, cursor,
            /// kitty-keyboard, device-status …) are queued by the
            /// listener.
            pub(in super::super) fn feed(&mut self, bytes: &[u8]) {
                self.parser.advance(&mut self.term, bytes);
            }

            /// Return queued PTY-bound replies, clearing the queue.
            pub(in super::super) fn take_pty_writes(&mut self) -> Vec<Vec<u8>> {
                self.listener.0.drain()
            }

            /// Snapshot the visible region as plain text, lines joined
            /// with `\n`. Trailing whitespace is preserved on each
            /// line so callers can detect alignment patterns; empty
            /// trailing lines are NOT trimmed.
            pub(in super::super) fn screen_text(&self) -> String {
                let grid = self.term.grid();
                let mut out = String::with_capacity(self.cols * self.rows);
                for row in 0..self.rows {
                    let line = Line(row as i32);
                    let mut line_buf = String::with_capacity(self.cols);
                    for col in 0..self.cols {
                        let point = Point::new(line, Column(col));
                        let cell = &grid[point];
                        if cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
                            continue;
                        }
                        line_buf.push(cell.c);
                    }
                    // Trim trailing spaces on each line — the grid is
                    // padded with U+0020 cells, which would dominate
                    // the snapshot otherwise.
                    let trimmed = line_buf.trim_end_matches(' ');
                    out.push_str(trimmed);
                    out.push('\n');
                }
                out
            }
        }
    }

    /// Concurrency cap. Independent of `LITEBOX_TEST_JOBS` — the
    /// Copilot scenarios call the GitHub API, so default to serial
    /// to protect shared/autonomous runs from rate-limiting. One-
    /// shot validation runs should raise this (`LITEBOX_COPILOT_JOBS=4`
    /// is a reasonable starting point) — nothing in-tree forces serial
    /// execution; the cap is purely an external-service safety knob.
    fn jobs_cap() -> usize {
        std::env::var("LITEBOX_COPILOT_JOBS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1)
    }

    fn copilot_semaphore() -> &'static std::sync::Mutex<usize> {
        static SEM: OnceLock<std::sync::Mutex<usize>> = OnceLock::new();
        SEM.get_or_init(|| std::sync::Mutex::new(jobs_cap()))
    }

    /// Tiny manual semaphore: acquire a slot or sleep.
    /// (libtest-mimic uses a thread-per-trial pool; this throttles
    /// Copilot trials specifically.)
    struct CopilotPermit;
    impl CopilotPermit {
        fn acquire() -> Self {
            loop {
                {
                    let mut g = copilot_semaphore().lock().expect("copilot sem");
                    if *g > 0 {
                        *g -= 1;
                        return CopilotPermit;
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    impl Drop for CopilotPermit {
        fn drop(&mut self) {
            if let Ok(mut g) = copilot_semaphore().lock() {
                *g += 1;
            }
        }
    }

    /// Token discovery + loud-FAIL preflight. Order:
    /// `COPILOT_GITHUB_TOKEN` → `GH_TOKEN` → `gh auth token`. The
    /// returned token is never embedded in a panic message or
    /// command-line argument visible via host `ps`.
    pub(super) fn discover_token() -> Result<String, String> {
        for var in ["COPILOT_GITHUB_TOKEN", "GH_TOKEN"] {
            if let Ok(t) = std::env::var(var) {
                if !t.is_empty() {
                    return Ok(t);
                }
            }
        }
        match Command::new("gh").args(["auth", "token"]).output() {
            Ok(out) if out.status.success() => {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if s.is_empty() {
                    Err("`gh auth token` succeeded but returned empty output. \
                         Run `gh auth login`."
                        .into())
                } else {
                    Ok(s)
                }
            }
            Ok(out) => Err(format!(
                "`gh auth token` exited {}. Run `gh auth login`. \
                 (stderr suppressed; rerun manually to inspect.)",
                out.status
            )),
            Err(e) => Err(format!(
                "could not invoke `gh`: {e}. Install the GitHub CLI \
                 and run `gh auth login`, or set COPILOT_GITHUB_TOKEN \
                 / GH_TOKEN."
            )),
        }
    }

    /// Token cached once per test process. First successful call to
    /// `discover_token()` is memoized. Returns Err when the token is
    /// not available so the per-trial body can fail gracefully
    /// instead of panicking the whole test process — the previous
    /// `panic!("copilot token preflight: ...")` behavior killed every
    /// other trial in the run, which is the wrong tradeoff for
    /// autonomous fill (where a missing token is a normal
    /// environment state, not a logic error).
    ///
    /// Memoization rationale: `discover_token()` invokes `gh auth
    /// token` as a fallback (subprocess fork+exec); caching avoids
    /// re-invoking it per-trial.
    fn token() -> Result<&'static str, &'static str> {
        static TOKEN: OnceLock<Result<String, String>> = OnceLock::new();
        TOKEN
            .get_or_init(discover_token)
            .as_ref()
            .map(String::as_str)
            .map_err(String::as_str)
    }

    /// Mode = which copilot invocation channel is being driven.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub(super) enum Mode {
        Pminus,
        Tui,
    }

    impl Mode {
        fn label(self) -> &'static str {
            match self {
                Mode::Pminus => "pminus",
                Mode::Tui => "tui",
            }
        }
    }

    /// Driver = how the prompt is interpreted on the copilot side.
    /// `Llm` routes the prompt through the model (current default
    /// behavior). `Bang` types a literal `!<shell-cmd>` into the TUI
    /// input, exercising Copilot CLI's shell-command passthrough
    /// without an LLM round-trip and (verified) without a token.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub(super) enum Driver {
        Llm,
        Bang,
    }

    impl Driver {
        fn label(self) -> &'static str {
            match self {
                Driver::Llm => "llm",
                Driver::Bang => "bang",
            }
        }
    }

    /// LLM-only scenario: prompt template, response-check function,
    /// per-trial timeout, fixtures. Same shape as the original
    /// `Scenario` struct. Used for scenarios where no shell-command
    /// equivalent exists (e.g. `simple_math`) or where the LLM-mode
    /// behavior is the specific thing being tested (`find_head_*`
    /// dimension bisects of an LLM-mode bug).
    struct LlmOnlyScenario {
        id: &'static str,
        prompt: fn(&str) -> String,
        check: fn(canary: &str, response: &str) -> bool,
        /// Per-trial timeout in seconds for the `read` phase. Build
        /// scenario is generous; everything else is bounded so the
        /// bash-output-hang failure mode is detected reliably.
        timeout_secs: u64,
        /// Files to plant under workspace/ (relative path -> contents).
        fixtures: &'static [(&'static str, &'static str)],
    }

    /// Matrix scenario: supports both LLM and Bang drivers (and both
    /// Pminus and Tui modes, except `(Pminus, Bang)` which is
    /// structurally absent — `!` is a TUI-only primitive). The
    /// non-Option `bang_cmd` and `bang_check` fields are how we
    /// statically guarantee every matrix scenario actually has a
    /// bang variant — mis-classifying a scenario fails at compile
    /// time rather than at registration time.
    struct MatrixScenario {
        id: &'static str,
        llm_prompt: fn(&str) -> String,
        llm_check: fn(canary: &str, response: &str) -> bool,
        /// Bang command body (no leading `!` — that's prepended by
        /// the driver). Receives the per-trial canary string; may
        /// ignore it if the canary lives in a fixture instead.
        bang_cmd: fn(&str) -> String,
        /// Check fn for bang-driver output. Often the same as
        /// `llm_check`, but `simple_bash`-style scenarios need a
        /// stricter check that distinguishes the input-echo
        /// occurrence of the canary from a real shell-output
        /// occurrence (see `simple_bash_bang_check`).
        bang_check: fn(canary: &str, response: &str) -> bool,
        timeout_secs: u64,
        fixtures: &'static [(&'static str, &'static str)],
    }

    /// Default canary check: response contains the canary string.
    /// Used by scenarios where the canary is planted in a fixture
    /// file (so the model must invoke a tool to surface it), not
    /// in the prompt text itself.
    fn default_check(canary: &str, response: &str) -> bool {
        let r = strip_ansi(response);
        r.contains(canary)
    }

    /// Hard-answer check for `simple_math`: response contains "4"
    /// somewhere meaningful (digit '4' as a standalone token, not
    /// "14" or "40"). The prompt does not embed any canary.
    fn simple_math_check(_canary: &str, response: &str) -> bool {
        let r = strip_ansi(response);
        // Look for "4" as a digit token. Crude but sufficient: the
        // model's answer will say something like "4" or "Four" near
        // the answer. We require either standalone digit '4' or
        // the word "four" (case-insensitive).
        let r_lower = r.to_lowercase();
        if r_lower.contains("four") {
            return true;
        }
        // Standalone '4': preceded/followed by non-digit or boundary.
        let bytes = r.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b != b'4' {
                continue;
            }
            let prev_non_digit = i == 0 || !bytes[i - 1].is_ascii_digit();
            let next_non_digit = i + 1 == bytes.len() || !bytes[i + 1].is_ascii_digit();
            if prev_non_digit && next_non_digit {
                return true;
            }
        }
        false
    }

    /// Bash-echo check for `simple_bash`: the prompt asks copilot to
    /// run `echo CN-...` (the canary). The canary appears in the
    /// response only if copilot's Bash tool actually executed and
    /// the agent surfaced the output back.
    fn simple_bash_check(canary: &str, response: &str) -> bool {
        let r = strip_ansi(response);
        r.contains(canary)
    }

    /// Stricter check for bang-driver `simple_bash`: the canary appears
    /// once in the input echo (`! echo <canary>`) regardless of whether
    /// the shell command actually ran. Requiring `>=2` occurrences
    /// ensures the bang passthrough actually executed the command and
    /// the rendered output (`│ <canary>`) is on screen.
    fn simple_bash_bang_check(canary: &str, response: &str) -> bool {
        let r = strip_ansi(response);
        r.matches(canary).count() >= 2
    }

    /// `pipeline_wc` canary check: response mentions either fixture
    /// filename and contains a digit (i.e., Copilot's Bash tool got
    /// output back and Copilot summarized it). Today's failure mode
    /// is a timeout message with no byte counts.
    fn pipeline_wc_check(_canary: &str, response: &str) -> bool {
        let r = strip_ansi(response).to_lowercase();
        let has_filename = r.contains("a.txt") || r.contains("b.txt");
        let has_digit = r.chars().any(|c| c.is_ascii_digit());
        let no_timeout = !r.contains("timed out") && !r.contains("timeout");
        has_filename && has_digit && no_timeout
    }

    /// `find_head` canary check: response references at least two
    /// fixture filenames (the canary is the set of one..six.txt).
    fn find_head_check(_canary: &str, response: &str) -> bool {
        let r = strip_ansi(response).to_lowercase();
        let hits = [
            "one.txt",
            "two.txt",
            "three.txt",
            "four.txt",
            "five.txt",
            "six.txt",
        ]
        .iter()
        .filter(|n| r.contains(*n))
        .count();
        let no_timeout = !r.contains("timed out") && !r.contains("timeout");
        hits >= 2 && no_timeout
    }

    /// Wave 10 Track A — variants that perturb one dimension of
    /// `find_head` at a time. Whichever variant *passes* tells us
    /// what the bug is sensitive to. See plan.md Wave 10 section.

    /// `find_head_one`: head -1 instead of -5. Single line through
    /// the pipeline. If this passes where `find_head` fails, bug is
    /// about multi-line drainage / SIGPIPE-killed find chain.
    fn find_head_one_check(_canary: &str, response: &str) -> bool {
        let r = strip_ansi(response).to_lowercase();
        let hits = [
            "one.txt",
            "two.txt",
            "three.txt",
            "four.txt",
            "five.txt",
            "six.txt",
        ]
        .iter()
        .filter(|n| r.contains(*n))
        .count();
        let no_timeout = !r.contains("timed out") && !r.contains("timeout");
        hits >= 1 && no_timeout
    }

    /// `find_head_unpiped`: find without head. If this passes where
    /// `find_head` fails, bug is in the pipe/SIGPIPE interaction.
    /// If it fails too, bug is in multi-line readdir output reading.
    fn find_head_unpiped_check(_canary: &str, response: &str) -> bool {
        let r = strip_ansi(response).to_lowercase();
        let hits = [
            "one.txt",
            "two.txt",
            "three.txt",
            "four.txt",
            "five.txt",
            "six.txt",
        ]
        .iter()
        .filter(|n| r.contains(*n))
        .count();
        let no_timeout = !r.contains("timed out") && !r.contains("timeout");
        hits >= 4 && no_timeout
    }

    /// `find_head_seq`: `seq 1 5` — no find, no fixtures, no pipe,
    /// 5 lines of bytes. If this fails too, the bug is multi-line
    /// output reading per se. If it passes, bug needs find/pipe.
    fn find_head_seq_check(_canary: &str, response: &str) -> bool {
        let r = strip_ansi(response).to_lowercase();
        let hits = ["1", "2", "3", "4", "5"]
            .iter()
            .filter(|n| r.contains(*n))
            .count();
        let no_timeout = !r.contains("timed out") && !r.contains("timeout");
        hits >= 3 && no_timeout
    }

    /// `find_head_cat_multi`: `cat one.txt two.txt … five.txt` —
    /// multi-file output through single process, no pipeline. Each
    /// fixture content is a distinct word. If this passes where
    /// `find_head` fails, bug requires the pipeline.
    fn find_head_cat_multi_check(_canary: &str, response: &str) -> bool {
        let r = strip_ansi(response).to_lowercase();
        let hits = ["alpha", "bravo", "charlie", "delta", "echo"]
            .iter()
            .filter(|n| r.contains(*n))
            .count();
        let no_timeout = !r.contains("timed out") && !r.contains("timeout");
        hits >= 3 && no_timeout
    }

    /// `find_head_ls`: `ls /workspace/*.txt | head -5`. Same shape
    /// as find_head but with shell globbing instead of find.
    /// Isolates whether the bug is in find's readdir behavior.
    fn find_head_ls_check(_canary: &str, response: &str) -> bool {
        let r = strip_ansi(response).to_lowercase();
        let hits = [
            "one.txt",
            "two.txt",
            "three.txt",
            "four.txt",
            "five.txt",
            "six.txt",
        ]
        .iter()
        .filter(|n| r.contains(*n))
        .count();
        let no_timeout = !r.contains("timed out") && !r.contains("timeout");
        hits >= 2 && no_timeout
    }

    /// `build` canary check: response mentions cargo build status
    /// keywords (compiled / compiling / finished / error / warning)
    /// and isn't a hang/timeout message.
    fn build_check(_canary: &str, response: &str) -> bool {
        let r = strip_ansi(response).to_lowercase();
        let saw_build = [
            "compiling",
            "compiled",
            "finished",
            "error",
            "warning",
            "litebox_timing",
        ]
        .iter()
        .any(|kw| r.contains(*kw));
        let no_timeout = !r.contains("timed out") && !r.contains("timeout");
        saw_build && no_timeout
    }

    /// 5 matrix scenarios: each registers across both drivers
    /// (Llm, Bang) and — for Llm — both modes (Pminus, Tui). Bang
    /// is Tui-only by axis design (`!` is a TUI primitive).
    fn matrix_scenarios() -> &'static [MatrixScenario] {
        &[
            MatrixScenario {
                id: "simple_bash",
                llm_prompt: |c| {
                    format!("Run the shell command `echo {c}` and tell me exactly what it printed.")
                },
                llm_check: simple_bash_check,
                bang_cmd: |c| format!("echo {c}"),
                bang_check: simple_bash_bang_check,
                timeout_secs: 90,
                fixtures: &[],
            },
            MatrixScenario {
                id: "read_file",
                llm_prompt: |_| {
                    "Run `cat /workspace/canary.txt` and tell me the entire contents of \
                     the file, including the line that starts with `CN-`."
                        .to_string()
                },
                llm_check: default_check,
                // Canary lives in the fixture, not the command — single
                // occurrence in screen output is sufficient.
                bang_cmd: |_| "cat /workspace/canary.txt".to_string(),
                bang_check: default_check,
                timeout_secs: 90,
                fixtures: &[("canary.txt", "__CANARY_PLACEHOLDER__\n")],
            },
            MatrixScenario {
                id: "pipeline_wc",
                llm_prompt: |_| {
                    "Run `wc -c /workspace/a.txt /workspace/b.txt` and tell me which file \
                     has more bytes."
                        .to_string()
                },
                llm_check: pipeline_wc_check,
                bang_cmd: |_| "wc -c /workspace/a.txt /workspace/b.txt".to_string(),
                bang_check: pipeline_wc_check,
                timeout_secs: 120,
                fixtures: &[
                    ("a.txt", "aaa\n"),                      // 4 bytes
                    ("b.txt", "bbbbbbbbbbbbbbbbbbbbbbbb\n"), // 25 bytes
                ],
            },
            MatrixScenario {
                id: "find_head",
                llm_prompt: |_| {
                    "Run `find /workspace -name '*.txt' | head -5` and list the filenames \
                     you find."
                        .to_string()
                },
                llm_check: find_head_check,
                bang_cmd: |_| "find /workspace -name '*.txt' | head -5".to_string(),
                bang_check: find_head_check,
                timeout_secs: 120,
                fixtures: &[
                    ("one.txt", "1\n"),
                    ("two.txt", "2\n"),
                    ("three.txt", "3\n"),
                    ("four.txt", "4\n"),
                    ("five.txt", "5\n"),
                    ("six.txt", "6\n"),
                ],
            },
            MatrixScenario {
                id: "build",
                llm_prompt: |_| {
                    "Run `CARGO_TARGET_DIR=/tmp/copilot-build cargo build -p litebox_timing` \
                     inside /workspace/litebox-src and report whether it succeeded or what \
                     compile errors it reported."
                        .to_string()
                },
                llm_check: build_check,
                // Bang form composes the cd into the command directly so
                // there's no model reasoning involved.
                bang_cmd: |_| {
                    "cd /workspace/litebox-src && \
                     CARGO_TARGET_DIR=/tmp/copilot-build cargo build -p litebox_timing"
                        .to_string()
                },
                bang_check: build_check,
                timeout_secs: 300,
                fixtures: &[],
            },
        ]
    }

    /// 6 LLM-only scenarios. `simple_math` has no shell equivalent;
    /// the `find_head_*` dimension variants are targeted bisects of
    /// an LLM-mode bug, not relevant under the bang driver.
    fn llm_only_scenarios() -> &'static [LlmOnlyScenario] {
        &[
            LlmOnlyScenario {
                id: "simple_math",
                prompt: |_| "What is 2 plus 2? Reply with just the number.".to_string(),
                check: simple_math_check,
                timeout_secs: 60,
                fixtures: &[],
            },
            // ---- Wave 10 Track A: find_head dimension variants ----
            LlmOnlyScenario {
                id: "find_head_one",
                prompt: |_| {
                    "Run `find /workspace -name '*.txt' | head -1` and list the filename \
                     you find."
                        .to_string()
                },
                check: find_head_one_check,
                timeout_secs: 120,
                fixtures: &[
                    ("one.txt", "1\n"),
                    ("two.txt", "2\n"),
                    ("three.txt", "3\n"),
                    ("four.txt", "4\n"),
                    ("five.txt", "5\n"),
                    ("six.txt", "6\n"),
                ],
            },
            LlmOnlyScenario {
                id: "find_head_unpiped",
                prompt: |_| {
                    "Run `find /workspace -name '*.txt'` and list every filename it prints."
                        .to_string()
                },
                check: find_head_unpiped_check,
                timeout_secs: 120,
                fixtures: &[
                    ("one.txt", "1\n"),
                    ("two.txt", "2\n"),
                    ("three.txt", "3\n"),
                    ("four.txt", "4\n"),
                    ("five.txt", "5\n"),
                    ("six.txt", "6\n"),
                ],
            },
            LlmOnlyScenario {
                id: "find_head_seq",
                prompt: |_| "Run `seq 1 5` and list every number it prints.".to_string(),
                check: find_head_seq_check,
                timeout_secs: 120,
                fixtures: &[],
            },
            LlmOnlyScenario {
                id: "find_head_cat_multi",
                prompt: |_| {
                    "Run `cat /workspace/one.txt /workspace/two.txt /workspace/three.txt \
                     /workspace/four.txt /workspace/five.txt` and list every word it prints."
                        .to_string()
                },
                check: find_head_cat_multi_check,
                timeout_secs: 120,
                fixtures: &[
                    ("one.txt", "alpha\n"),
                    ("two.txt", "bravo\n"),
                    ("three.txt", "charlie\n"),
                    ("four.txt", "delta\n"),
                    ("five.txt", "echo\n"),
                ],
            },
            LlmOnlyScenario {
                id: "find_head_ls",
                prompt: |_| {
                    "Run `ls /workspace/*.txt | head -5` and list the filenames you find."
                        .to_string()
                },
                check: find_head_ls_check,
                timeout_secs: 120,
                fixtures: &[
                    ("one.txt", "1\n"),
                    ("two.txt", "2\n"),
                    ("three.txt", "3\n"),
                    ("four.txt", "4\n"),
                    ("five.txt", "5\n"),
                    ("six.txt", "6\n"),
                ],
            },
        ]
    }

    /// Register all Copilot Trials (24 = 6 scenarios × 2 modes × 2 passes).
    /// Called from `main()` only when `requested()` returned true.
    pub(super) fn register_trials(trials: &mut Vec<Trial>) {
        // Registration is unconditional and side-effect free: the
        // copilot trial set should always be visible to the dashboard
        // (and to the autonomous `--fill` selector) so coverage gaps
        // surface as failing trials rather than as silently-missing
        // universe entries. Token discovery is deferred to the
        // per-trial body — see `run_scenario`. A missing token fails
        // the individual trial cheaply (no docker spawn) with a clear
        // diagnostic, instead of panicking the whole test process at
        // registration time. `Driver::Bang` trials skip token
        // discovery entirely — verified token-free against the
        // host-installed copilot.

        // Matrix scenarios: every entry supports all 3 cells
        // (Pminus,Llm), (Tui,Llm), (Tui,Bang). The loop body
        // *is* the validity statement — no per-scenario gate field.
        for scn in matrix_scenarios() {
            for (mode, driver) in &[
                (Mode::Pminus, Driver::Llm),
                (Mode::Tui, Driver::Llm),
                (Mode::Tui, Driver::Bang),
            ] {
                for pass in ["native", "litebox"] {
                    let id = format!("copilot::{}.{}.{}", mode.label(), driver.label(), scn.id);
                    let name = format!("{pass}::{id}");
                    let scn_id = scn.id;
                    let mode = *mode;
                    let driver = *driver;
                    let pass_owned = pass.to_string();
                    trials.push(Trial::test(name, move || {
                        run_matrix_scenario(&pass_owned, mode, driver, scn_id)
                    }));
                }
            }
        }

        // LLM-only scenarios: 2 cells per scenario, driver is always
        // Llm. The `.llm.` segment is hard-coded in the ID to keep
        // the 4-segment shape uniform across the whole copilot
        // namespace.
        for scn in llm_only_scenarios() {
            for mode in [Mode::Pminus, Mode::Tui] {
                for pass in ["native", "litebox"] {
                    let id = format!("copilot::{}.llm.{}", mode.label(), scn.id);
                    let name = format!("{pass}::{id}");
                    let scn_id = scn.id;
                    let pass_owned = pass.to_string();
                    trials.push(Trial::test(name, move || {
                        run_llm_only_scenario(&pass_owned, mode, scn_id)
                    }));
                }
            }
        }

        // Startup probe: 3 segments (no prompt, so no driver
        // segment). Renamed from copilot::tui_noLLM.startup_then_exit;
        // bang driver subsumes the old `_noLLM` suffix elsewhere but
        // this probe has no prompt at all and doesn't fit the matrix.
        for pass in ["native", "litebox"] {
            let name = format!("{pass}::copilot::tui.startup_then_exit");
            let pass_owned = pass.to_string();
            trials.push(Trial::test(name, move || {
                run_startup_then_exit(&pass_owned, "startup_then_exit")
            }));
        }
    }

    fn run_startup_then_exit(pass: &str, scenario_id: &str) -> Result<(), Failed> {
        let github_token = token().map_err(|e| {
            Failed::from(format!(
                "GitHub token not available: {e}. Set \
                 COPILOT_GITHUB_TOKEN or GH_TOKEN, or run \
                 `gh auth login`."
            ))
        })?;

        if scenario_id != "startup_then_exit" {
            return Err(Failed::from(format!(
                "unknown startup_then_exit scenario {scenario_id}"
            )));
        }

        let _permit = CopilotPermit::acquire();
        let fixture_dir = super::fixture_dir(pass, "tui", scenario_id);
        let _ = std::fs::remove_dir_all(&fixture_dir);
        std::fs::create_dir_all(&fixture_dir)
            .map_err(|e| format!("create fixture dir {}: {e}", fixture_dir.display()))?;
        super::ensure_copilot_image(&super::workspace_root());

        let token_env_path = fixture_dir.join(".copilot-env");
        super::write_token_env(&token_env_path, github_token)?;

        let pass_static: &'static str = match pass {
            "native" => "native",
            "litebox" => "litebox",
            _ => "unknown",
        };
        let test_id = format!("copilot::tui.{scenario_id}");
        let spec = build_copilot_spec(pass, &fixture_dir, false);
        let pass_owned = pass.to_string();
        let scenario_id_owned = scenario_id.to_string();

        super::framework::run_trial(
            pass_static,
            &test_id,
            "copilot_cli",
            "tui",
            spec,
            move |container| {
                let t_dispatch = Instant::now();
                let Some(&port) = container.published_ports.get(&22) else {
                    return super::framework::DriveResult {
                        verdict: "FAIL",
                        detail: Some(format!(
                            "container {} did not publish port 22",
                            container.name
                        )),
                        t_docker_start_ms: 0,
                        t_useful_ms: 0,
                        sub_phases: super::SubPhaseMs::default(),
                        t_docker_spawn_ms: None,
                        t_litebox_init_ms: None,
                        t_harness_load_ms: None,
                    };
                };
                if let Err(e) = wait_for_sshd(port, Duration::from_secs(30)) {
                    return super::framework::DriveResult {
                        verdict: "FAIL",
                        detail: Some(format!("wait_for_sshd port {port}: {e}")),
                        t_docker_start_ms: t_dispatch.elapsed().as_millis(),
                        t_useful_ms: 0,
                        sub_phases: super::SubPhaseMs::default(),
                        t_docker_spawn_ms: None,
                        t_litebox_init_ms: None,
                        t_harness_load_ms: None,
                    };
                }
                let t_useful_start = Instant::now();
                let t_docker_start_ms = t_useful_start.duration_since(t_dispatch).as_millis();

                let response = match drive_tui_startup_then_exit(port, 90) {
                    Ok(r) => r,
                    Err(e) => {
                        return super::framework::DriveResult {
                            verdict: "FAIL",
                            detail: Some(format!("drive: {e}")),
                            t_docker_start_ms,
                            t_useful_ms: t_useful_start.elapsed().as_millis(),
                            sub_phases: super::SubPhaseMs::default(),
                            t_docker_spawn_ms: None,
                            t_litebox_init_ms: None,
                            t_harness_load_ms: None,
                        };
                    }
                };
                let log_dir = super::log_dir();
                let _ = std::fs::create_dir_all(log_dir);
                let safe = format!("copilot-{pass_owned}-tui-{scenario_id_owned}");
                let _ = std::fs::write(log_dir.join(format!("{safe}.raw.log")), &response);
                let stripped = strip_ansi(&response);
                let _ = std::fs::write(log_dir.join(format!("{safe}.stripped.log")), &stripped);
                let _ = std::fs::write(
                    log_dir.join(format!("{safe}.prompt.txt")),
                    "No prompt submitted; startup probe exits with /exit after input-ready markers.\n",
                );
                let t_useful_ms = t_useful_start.elapsed().as_millis();

                let ok = stripped.contains("startup_reached_input_ready=true")
                    && stripped.contains("startup_exit_clean=true")
                    && (stripped.contains("/ commands")
                        || stripped.contains("@ files")
                        || stripped.contains("? help"));
                if !ok {
                    let preview: String = stripped.chars().take(800).collect();
                    return super::framework::DriveResult {
                        verdict: "FAIL",
                        detail: Some(format!(
                            "copilot::tui.{scenario_id_owned} startup check failed.\n\
                             transcript: {}\n\
                             first 800 chars of response (ANSI-stripped):\n{preview}",
                            log_dir.join(format!("{safe}.stripped.log")).display(),
                        )),
                        t_docker_start_ms,
                        t_useful_ms,
                        sub_phases: super::SubPhaseMs::default(),
                        t_docker_spawn_ms: None,
                        t_litebox_init_ms: None,
                        t_harness_load_ms: None,
                    };
                }
                super::framework::DriveResult {
                    verdict: "pass",
                    detail: None,
                    t_docker_start_ms,
                    t_useful_ms,
                    sub_phases: super::SubPhaseMs::default(),
                    t_docker_spawn_ms: None,
                    t_litebox_init_ms: None,
                    t_harness_load_ms: None,
                }
            },
        )
    }

    /// Matrix-scenario driver: dispatches a (Mode, Driver, scenario)
    /// cell. `Driver::Bang` skips token discovery — the bang
    /// passthrough is local and verified token-free.
    fn run_matrix_scenario(
        pass: &str,
        mode: Mode,
        driver: Driver,
        scenario_id: &str,
    ) -> Result<(), Failed> {
        let scn = matrix_scenarios()
            .iter()
            .find(|s| s.id == scenario_id)
            .expect("matrix scenario lookup");

        // (Pminus, Bang) is structurally absent from the registration
        // loop; guard here too in case someone calls this directly.
        if driver == Driver::Bang && mode != Mode::Tui {
            return Err(Failed::from(format!(
                "(Mode::{mode:?}, Driver::Bang) is not supported — \
                 ! is a TUI-only primitive"
            )));
        }

        let requires_token = driver == Driver::Llm;
        let github_token = if requires_token {
            Some(token().map_err(|e| {
                Failed::from(format!(
                    "GitHub token not available: {e}. Set \
                     COPILOT_GITHUB_TOKEN or GH_TOKEN, or run \
                     `gh auth login`."
                ))
            })?)
        } else {
            None
        };

        let canary = format!(
            "CN-{}-{}-{}-{}-{}",
            scenario_id,
            mode.label(),
            driver.label(),
            pass,
            std::process::id()
        );

        let (prompt_text, check) = match driver {
            Driver::Llm => ((scn.llm_prompt)(&canary), scn.llm_check),
            Driver::Bang => (format!("!{}", (scn.bang_cmd)(&canary)), scn.bang_check),
        };

        run_copilot_trial(
            pass,
            mode,
            driver,
            scenario_id,
            &canary,
            &prompt_text,
            check,
            scn.timeout_secs,
            scn.fixtures,
            scn.id == "build",
            github_token,
        )
    }

    /// LLM-only scenario driver: always Driver::Llm; reproduces the
    /// pre-refactor behavior 1:1 (just with a renamed ID emitter).
    fn run_llm_only_scenario(pass: &str, mode: Mode, scenario_id: &str) -> Result<(), Failed> {
        let scn = llm_only_scenarios()
            .iter()
            .find(|s| s.id == scenario_id)
            .expect("llm_only scenario lookup");

        let github_token = token().map_err(|e| {
            Failed::from(format!(
                "GitHub token not available: {e}. Set \
                 COPILOT_GITHUB_TOKEN or GH_TOKEN, or run \
                 `gh auth login`."
            ))
        })?;

        let canary = format!(
            "CN-{}-{}-llm-{}-{}",
            scenario_id,
            mode.label(),
            pass,
            std::process::id()
        );
        let prompt_text = (scn.prompt)(&canary);

        run_copilot_trial(
            pass,
            mode,
            Driver::Llm,
            scenario_id,
            &canary,
            &prompt_text,
            scn.check,
            scn.timeout_secs,
            scn.fixtures,
            scn.id == "build",
            Some(github_token),
        )
    }

    /// Shared body for both matrix and LLM-only trials. Builds the
    /// fixture tree, optional token env file, container spec; then
    /// dispatches `drive_pminus` or `drive_tui` based on `mode` and
    /// runs the check fn against the resulting transcript.
    #[allow(clippy::too_many_arguments)]
    fn run_copilot_trial(
        pass: &str,
        mode: Mode,
        driver: Driver,
        scenario_id: &str,
        canary: &str,
        prompt_text: &str,
        check: fn(&str, &str) -> bool,
        timeout_secs: u64,
        fixtures: &'static [(&'static str, &'static str)],
        mount_workspace_src: bool,
        github_token: Option<&str>,
    ) -> Result<(), Failed> {
        let _permit = CopilotPermit::acquire();

        // Use a fixture subdir that distinguishes drivers so parallel
        // (tui, llm) and (tui, bang) trials don't stomp each other.
        let fixture_kind = format!("{}-{}", mode.label(), driver.label());
        let fixture_dir = super::fixture_dir(pass, &fixture_kind, scenario_id);
        let _ = std::fs::remove_dir_all(&fixture_dir);
        std::fs::create_dir_all(&fixture_dir)
            .map_err(|e| format!("create fixture dir {}: {e}", fixture_dir.display()))?;
        for (rel, content) in fixtures {
            let body = content.replace("__CANARY_PLACEHOLDER__", canary);
            let path = fixture_dir.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
            }
            std::fs::write(&path, body).map_err(|e| format!("write {}: {e}", path.display()))?;
        }
        super::ensure_copilot_image(&super::workspace_root());

        // Token env file written even for Bang trials so the remote
        // `sh -c '. .copilot-env; …'` invocation has *something* to
        // source (an empty file is fine — the bang driver doesn't
        // exercise the LLM path). Skipping the file entirely would
        // require a separate remote-command shape; this is simpler.
        let token_env_path = fixture_dir.join(".copilot-env");
        match github_token {
            Some(tok) => super::write_token_env(&token_env_path, tok)?,
            None => std::fs::write(&token_env_path, "")
                .map_err(|e| format!("write empty .copilot-env: {e}"))?,
        }

        let pass_static: &'static str = match pass {
            "native" => "native",
            "litebox" => "litebox",
            _ => "unknown",
        };
        // ID format mirrors the registration emitter — but the
        // startup probe is the only 3-segment exception, and it has
        // its own helper.
        let test_id = format!(
            "copilot::{}.{}.{}",
            mode.label(),
            driver.label(),
            scenario_id
        );
        let spec = build_copilot_spec(pass, &fixture_dir, mount_workspace_src);

        let prompt_text_owned = prompt_text.to_string();
        let canary_owned = canary.to_string();
        let canary_for_log = canary.to_string();
        let prompt_text_for_log = prompt_text.to_string();
        let pass_owned = pass.to_string();
        let scenario_id_owned = scenario_id.to_string();
        let mode_label = mode.label();
        let driver_label = driver.label();
        let group_static: &'static str = mode.label();

        super::framework::run_trial(
            pass_static,
            &test_id,
            "copilot_cli",
            group_static,
            spec,
            move |container| {
                let t_dispatch = Instant::now();
                let Some(&port) = container.published_ports.get(&22) else {
                    return super::framework::DriveResult {
                        verdict: "FAIL",
                        detail: Some(format!(
                            "container {} did not publish port 22",
                            container.name
                        )),
                        t_docker_start_ms: 0,
                        t_useful_ms: 0,
                        sub_phases: super::SubPhaseMs::default(),
                        t_docker_spawn_ms: None,
                        t_litebox_init_ms: None,
                        t_harness_load_ms: None,
                    };
                };
                if let Err(e) = wait_for_sshd(port, Duration::from_secs(30)) {
                    return super::framework::DriveResult {
                        verdict: "FAIL",
                        detail: Some(format!("wait_for_sshd port {port}: {e}")),
                        t_docker_start_ms: t_dispatch.elapsed().as_millis(),
                        t_useful_ms: 0,
                        sub_phases: super::SubPhaseMs::default(),
                        t_docker_spawn_ms: None,
                        t_litebox_init_ms: None,
                        t_harness_load_ms: None,
                    };
                }
                let t_useful_start = Instant::now();
                let t_docker_start_ms = t_useful_start.duration_since(t_dispatch).as_millis();

                let response = match mode {
                    Mode::Pminus => drive_pminus(port, &prompt_text_owned, timeout_secs),
                    Mode::Tui => drive_tui(port, &prompt_text_owned, timeout_secs),
                };
                let response = match response {
                    Ok(r) => r,
                    Err(e) => {
                        return super::framework::DriveResult {
                            verdict: "FAIL",
                            detail: Some(format!("drive: {e}")),
                            t_docker_start_ms,
                            t_useful_ms: t_useful_start.elapsed().as_millis(),
                            sub_phases: super::SubPhaseMs::default(),
                            t_docker_spawn_ms: None,
                            t_litebox_init_ms: None,
                            t_harness_load_ms: None,
                        };
                    }
                };
                let log_dir = super::log_dir();
                let _ = std::fs::create_dir_all(log_dir);
                let safe =
                    format!("copilot-{pass_owned}-{mode_label}-{driver_label}-{scenario_id_owned}");
                let _ = std::fs::write(log_dir.join(format!("{safe}.raw.log")), &response);
                let _ = std::fs::write(
                    log_dir.join(format!("{safe}.stripped.log")),
                    strip_ansi(&response),
                );
                let _ = std::fs::write(
                    log_dir.join(format!("{safe}.prompt.txt")),
                    format!("canary={canary_for_log}\n\n--- prompt ---\n{prompt_text_for_log}\n"),
                );
                let t_useful_ms = t_useful_start.elapsed().as_millis();

                let ok = check(&canary_owned, &response);
                if !ok {
                    let preview: String = strip_ansi(&response).chars().take(800).collect();
                    return super::framework::DriveResult {
                        verdict: "FAIL",
                        detail: Some(format!(
                            "copilot::{mode_label}.{driver_label}.{scenario_id_owned} check failed.\n\
                             canary={canary_owned}\n\
                             transcript: {}\n\
                             first 800 chars of response (ANSI-stripped):\n{preview}",
                            log_dir.join(format!("{safe}.stripped.log")).display(),
                        )),
                        t_docker_start_ms,
                        t_useful_ms,
                        sub_phases: super::SubPhaseMs::default(),
                        t_docker_spawn_ms: None,
                        t_litebox_init_ms: None,
                        t_harness_load_ms: None,
                    };
                }
                super::framework::DriveResult {
                    verdict: "pass",
                    detail: None,
                    t_docker_start_ms,
                    t_useful_ms,
                    sub_phases: super::SubPhaseMs::default(),
                    t_docker_spawn_ms: None,
                    t_litebox_init_ms: None,
                    t_harness_load_ms: None,
                }
            },
        )
    }

    /// Build the `ContainerSpec` for a copilot_cli scenario. Mirrors
    /// what `ContainerHandle::spawn` used to construct, but returns
    /// data instead of spawning — `framework::run_trial` owns the
    /// docker invocation + lifecycle.
    fn build_copilot_spec(
        pass: &str,
        fixture_dir: &Path,
        mount_workspace_src: bool,
    ) -> super::framework::ContainerSpec {
        let ws_root = super::workspace_root();
        let bin_dir = super::debug_dir();
        let mut docker_args: Vec<String> = vec![
            "--cap-add".into(),
            "SYS_PTRACE".into(),
            "-p".into(),
            "127.0.0.1:0:22".into(),
            "-v".into(),
            format!("{}:/opt/litebox:ro", bin_dir.display()),
            "-v".into(),
            format!("{}:/workspace", fixture_dir.display()),
        ];
        for var in [
            "LITEBOX_EAGER_BROKER_SOCKETPAIR",
            "LITEBOX_EAGER_BROKER_SOCKETSEQPACKET",
            "LITEBOX_BROKER_TCP_CONN",
            "LITEBOX_BROKER_INET_RAW",
            "LITEBOX_BROKER_INET_DELAY_NS",
            "LITEBOX_PE10_DIAG",
            "LITEBOX_PE5_DIAG",
            "LITEBOX_CLEANUP_DELAY_MS",
            "RUST_LOG",
            "RUST_BACKTRACE",
        ] {
            if let Ok(val) = std::env::var(var) {
                docker_args.push("-e".into());
                docker_args.push(format!("{var}={val}"));
            }
        }
        if mount_workspace_src {
            docker_args.push("-v".into());
            docker_args.push(format!("{}:/workspace/litebox-src:ro", ws_root.display()));
        }
        let command: Vec<String> = match pass {
            "native" => vec![
                "/usr/sbin/dropbear".into(),
                "-F".into(),
                "-E".into(),
                "-B".into(),
                "-R".into(),
                "-p".into(),
                "22".into(),
            ],
            "litebox" => vec![
                "/opt/litebox/litebox_tool_executor".into(),
                "--rootfs".into(),
                "/".into(),
                "--record-baseline".into(),
                "--ssh".into(),
                "--ssh-port".into(),
                "22".into(),
            ],
            _ => panic!("unknown pass {pass}"),
        };
        super::framework::ContainerSpec {
            image: super::copilot_image_tag(),
            docker_args,
            command,
            detached: true,
            timeout_secs: None,
        }
    }

    pub(super) fn wait_for_sshd(port: u16, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if std::net::TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}").parse().unwrap(),
                Duration::from_millis(500),
            )
            .is_ok()
            {
                // dropbear under litebox can accept TCP before its SSH
                // handshake path is ready; mirror the ssh_mode smoke tests.
                std::thread::sleep(Duration::from_secs(3));
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Err(format!(
            "sshd on 127.0.0.1:{port} did not accept TCP within {timeout:?}"
        ))
    }

    /// Common ssh argv (host-side options). Caller appends the remote
    /// command. `sshpass -p ""` provides empty-password auth for
    /// dropbear's `-B` flag.
    pub(super) fn ssh_argv_base(port: u16) -> Vec<String> {
        vec![
            "sshpass".into(),
            "-p".into(),
            "".into(),
            "ssh".into(),
            "-tt".into(),
            "-p".into(),
            port.to_string(),
            "-o".into(),
            "StrictHostKeyChecking=no".into(),
            "-o".into(),
            "UserKnownHostsFile=/dev/null".into(),
            "-o".into(),
            "PreferredAuthentications=password".into(),
            "-o".into(),
            "PubkeyAuthentication=no".into(),
            "-o".into(),
            "NumberOfPasswordPrompts=1".into(),
            "-o".into(),
            "LogLevel=ERROR".into(),
            "root@127.0.0.1".into(),
        ]
    }

    /// `-p` mode: invoke `copilot -p <prompt>` as the ssh remote
    /// command, read its merged stdout/stderr to EOF.
    ///
    /// SSH concatenates remote argv with spaces and hands a single
    /// string to the remote shell, so the prompt must be shell-quoted
    /// before it joins the ssh argv. The remote shell first sources
    /// the per-trial env file (containing COPILOT_GITHUB_TOKEN etc.)
    /// because dropbear strips most environment variables when
    /// exec'ing the session command.
    fn drive_pminus(port: u16, prompt: &str, timeout_secs: u64) -> Result<String, String> {
        // Two-shot kex retry: dropbear under litebox can accept TCP
        // before its SSH handshake path is fully ready; mirror the
        // `drive_bash` helper in the dropbear_bash suite.
        let first = drive_pminus_once(port, prompt, timeout_secs)?;
        if first.contains("kex_exchange_identification") || first.trim().is_empty() {
            std::thread::sleep(Duration::from_secs(7));
            return drive_pminus_once(port, prompt, timeout_secs);
        }
        Ok(first)
    }

    fn drive_pminus_once(port: u16, prompt: &str, timeout_secs: u64) -> Result<String, String> {
        let pty = Pty::open()?;
        let mut argv = ssh_argv_base(port);
        let remote_cmd = format!(
            "set -a; . /workspace/.copilot-env; set +a; exec copilot -p {} --allow-all --no-color",
            shell_quote(prompt),
        );
        argv.push(remote_cmd);
        let pid = pty.fork_exec(&argv, /* ctrl_tty = */ true)?;
        let result = read_with_deadline(&pty, Duration::from_secs(timeout_secs))?;
        let _ = wait_pid(pid, Duration::from_secs(10));
        Ok(result)
    }

    /// TUI mode: invoke `copilot --allow-all` interactively, send
    /// the prompt followed by `\n`, then read until quiet, then send
    /// the CLI's exit shortcut.
    fn drive_tui(port: u16, prompt: &str, timeout_secs: u64) -> Result<String, String> {
        let first = drive_tui_once(port, prompt, timeout_secs)?;
        if first.contains("kex_exchange_identification") {
            std::thread::sleep(Duration::from_secs(7));
            return drive_tui_once(port, prompt, timeout_secs);
        }
        Ok(first)
    }

    fn drive_tui_once(port: u16, prompt: &str, timeout_secs: u64) -> Result<String, String> {
        let pty = Pty::open()?;
        // Match the headless emulator's 100x30 grid so the TUI lays
        // out for the right dimensions. Default PTY winsize is 0x0
        // which makes some TUIs degenerate.
        let _ = pty.resize(30, 100);
        let mut argv = ssh_argv_base(port);
        // Force a known TERM so the TUI doesn't probe further than
        // alacritty_terminal can emulate.
        argv.push(
            "set -a; . /workspace/.copilot-env; set +a; \
             stty rows 30 cols 100 2>/dev/null; \
             exec env TERM=xterm-256color COLORTERM=truecolor copilot --allow-all"
                .to_string(),
        );
        let pid = pty.fork_exec(&argv, /* ctrl_tty = */ true)?;

        let mut emu = term_emu::Emulator::new();
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        let mut trust_answered = false;
        let mut prompt_sent = false;
        let mut prompt_sent_at: Option<Instant> = None;
        let mut idle_since: Option<Instant> = None;
        const POLL_TICK: Duration = Duration::from_millis(50);
        const READY_QUIET: Duration = Duration::from_millis(800);
        const RESPONSE_QUIET: Duration = Duration::from_millis(2500);

        // Run the read/feed/respond loop until either we've sent the
        // prompt and observed a long-enough quiet window after the
        // model reply, or the per-scenario deadline elapses.
        while Instant::now() < deadline {
            let mut activity = false;
            // Drain whatever the PTY has produced.
            loop {
                match pty.try_read_now(8192) {
                    Ok(Some(buf)) if buf.is_empty() => break, // EOF
                    Ok(Some(buf)) => {
                        emu.feed(&buf);
                        activity = true;
                    }
                    Ok(None) => break, // EAGAIN
                    Err(e) => return Err(format!("pty read: {e}")),
                }
            }
            // Flush any synthetic replies (color, cursor, keyboard
            // protocol, device-status, …) the emulator queued in
            // response to TUI capability queries.
            for reply in emu.take_pty_writes() {
                let _ = pty.write_all(&reply);
            }
            // State machine.
            let screen = emu.screen_text();
            if !trust_answered {
                if screen.contains("Do you trust") {
                    pty.write_all(b"\r")?;
                    trust_answered = true;
                    idle_since = None;
                }
                std::thread::sleep(POLL_TICK);
                continue;
            }
            // After trust is dismissed, wait for the trust modal to
            // be gone AND the input area to appear.
            let trust_gone = !screen.contains("Do you trust");
            let input_ready = trust_gone
                && (screen.contains("/ commands")
                    || screen.contains("@ files")
                    || screen.contains("? help"));
            if !prompt_sent {
                let elapsed_idle = idle_since.map(|t| t.elapsed()).unwrap_or_default();
                if !activity && elapsed_idle >= READY_QUIET && input_ready {
                    // The TUI has rendered the input prompt and is
                    // sitting quiet — send the user prompt.
                    //
                    // Submit sequence: type the prompt via bracketed
                    // paste (so the input library treats it as a
                    // single atomic insert rather than typing
                    // each character through the kitty keyboard
                    // protocol), give the TUI a beat to render the
                    // populated input box, then send bare \r as
                    // Enter. The Copilot CLI's input box accepts
                    // \r as submit when the buffer is non-empty and
                    // the cursor is at end-of-line.
                    let mut buf = Vec::with_capacity(prompt.len() + 16);
                    buf.extend_from_slice(b"\x1b[200~"); // start paste
                    buf.extend_from_slice(prompt.as_bytes());
                    buf.extend_from_slice(b"\x1b[201~"); // end paste
                    pty.write_all(&buf)?;
                    std::thread::sleep(Duration::from_millis(300));
                    pty.write_all(b"\r")?;
                    prompt_sent = true;
                    prompt_sent_at = Some(Instant::now());
                    idle_since = None;
                } else if activity {
                    idle_since = Some(Instant::now());
                } else if idle_since.is_none() {
                    idle_since = Some(Instant::now());
                }
            } else {
                let since_prompt = prompt_sent_at.map(|t| t.elapsed()).unwrap_or_default();
                if activity {
                    idle_since = Some(Instant::now());
                } else if let Some(t) = idle_since {
                    if t.elapsed() >= RESPONSE_QUIET && since_prompt >= RESPONSE_QUIET {
                        break;
                    }
                } else {
                    idle_since = Some(Instant::now());
                }
            }
            std::thread::sleep(POLL_TICK);
        }

        // Take a screen snapshot before issuing /exit so the screen
        // text isn't lost when the TUI tears down its panels.
        let visible = emu.screen_text();

        // Best-effort clean exit. CR because TUI raw mode treats it
        // as Enter; LF would be a literal character.
        let _ = pty.write_all(b"/exit\r");
        // Drain a little more so any final model output gets into the
        // grid and any teardown queries get their synthetic reply.
        let drain_until = Instant::now() + Duration::from_secs(3);
        while Instant::now() < drain_until {
            match pty.try_read_now(8192) {
                Ok(Some(buf)) if buf.is_empty() => break,
                Ok(Some(buf)) => emu.feed(&buf),
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => break,
            }
            for reply in emu.take_pty_writes() {
                let _ = pty.write_all(&reply);
            }
        }
        let final_visible = emu.screen_text();
        let _ = wait_pid(pid, Duration::from_secs(5));

        // Compose a transcript with the pre-/exit and post-/exit
        // screen snapshots. The canary check function runs against
        // this combined text; it's also what gets persisted for
        // forensics. Pre- and post- snapshots are both useful because
        // the model response often scrolls partly off the top of the
        // grid by the time /exit is sent.
        Ok(format!(
            "--- [drive_tui screen before /exit] ---\n{visible}\n\
             --- [drive_tui screen after /exit] ---\n{final_visible}"
        ))
    }

    fn drive_tui_startup_then_exit(port: u16, timeout_secs: u64) -> Result<String, String> {
        let first = drive_tui_startup_then_exit_once(port, timeout_secs)?;
        if first.contains("kex_exchange_identification") {
            std::thread::sleep(Duration::from_secs(7));
            return drive_tui_startup_then_exit_once(port, timeout_secs);
        }
        Ok(first)
    }

    fn drive_tui_startup_then_exit_once(port: u16, timeout_secs: u64) -> Result<String, String> {
        let pty = Pty::open()?;
        let _ = pty.resize(30, 100);
        let mut argv = ssh_argv_base(port);
        argv.push(
            "set -a; . /workspace/.copilot-env; set +a; \
             stty rows 30 cols 100 2>/dev/null; \
             exec env TERM=xterm-256color COLORTERM=truecolor copilot --allow-all"
                .to_string(),
        );
        let pid = pty.fork_exec(&argv, /* ctrl_tty = */ true)?;

        let mut emu = term_emu::Emulator::new();
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        let mut trust_seen = false;
        let mut trust_answered = false;
        let mut reached_input_ready = false;
        let mut idle_since: Option<Instant> = None;
        const POLL_TICK: Duration = Duration::from_millis(50);
        const READY_QUIET: Duration = Duration::from_millis(800);

        while Instant::now() < deadline {
            let mut activity = false;
            let mut eof = false;
            loop {
                match pty.try_read_now(8192) {
                    Ok(Some(buf)) if buf.is_empty() => {
                        eof = true;
                        break;
                    }
                    Ok(Some(buf)) => {
                        emu.feed(&buf);
                        activity = true;
                    }
                    Ok(None) => break,
                    Err(e) => return Err(format!("pty read: {e}")),
                }
            }
            for reply in emu.take_pty_writes() {
                let _ = pty.write_all(&reply);
            }

            let screen = emu.screen_text();
            if screen.contains("Do you trust") {
                trust_seen = true;
                if !trust_answered {
                    pty.write_all(b"\r")?;
                    trust_answered = true;
                    idle_since = None;
                }
                std::thread::sleep(POLL_TICK);
                continue;
            }

            let input_ready = screen.contains("/ commands")
                || screen.contains("@ files")
                || screen.contains("? help");
            if input_ready {
                reached_input_ready = true;
                let elapsed_idle = idle_since.map(|t| t.elapsed()).unwrap_or_default();
                if !activity && elapsed_idle >= READY_QUIET {
                    break;
                }
            }

            if eof {
                break;
            } else if activity {
                idle_since = Some(Instant::now());
            } else if idle_since.is_none() {
                idle_since = Some(Instant::now());
            }
            std::thread::sleep(POLL_TICK);
        }

        let visible = emu.screen_text();
        let _ = pty.write_all(b"/exit\r");
        let drain_until = Instant::now() + Duration::from_secs(3);
        while Instant::now() < drain_until {
            match pty.try_read_now(8192) {
                Ok(Some(buf)) if buf.is_empty() => break,
                Ok(Some(buf)) => emu.feed(&buf),
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => break,
            }
            for reply in emu.take_pty_writes() {
                let _ = pty.write_all(&reply);
            }
        }
        let final_visible = emu.screen_text();
        let startup_exit_clean = wait_pid_exited(pid, Duration::from_secs(5))?;
        if !startup_exit_clean {
            let _ = pty.write_all(b"\x03");
            let _ = wait_pid_exited(pid, Duration::from_secs(2));
        }

        Ok(format!(
            "--- [drive_tui_startup_then_exit summary] ---\n\
             startup_trust_seen={trust_seen}\n\
             startup_trust_answered={trust_answered}\n\
             startup_reached_input_ready={reached_input_ready}\n\
             startup_exit_clean={startup_exit_clean}\n\
             --- [drive_tui_startup_then_exit screen before /exit] ---\n{visible}\n\
             --- [drive_tui_startup_then_exit screen after /exit] ---\n{final_visible}"
        ))
    }

    fn wait_pid_exited(pid: libc::pid_t, timeout: Duration) -> Result<bool, String> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut status: libc::c_int = 0;
            // SAFETY: `pid` is the child process returned by `fork_exec`; `status`
            // points to valid writable memory for this `waitpid` call.
            let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if r == pid {
                return Ok(true);
            }
            if r < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if err.raw_os_error() == Some(libc::ECHILD) {
                    return Ok(true);
                }
                return Err(format!("waitpid({pid}): {err}"));
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// POSIX shell single-quote escaping: wrap in '...' and replace
    /// any internal `'` with `'\''`.
    pub(super) fn shell_quote(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('\'');
        for c in s.chars() {
            if c == '\'' {
                out.push_str("'\\''");
            } else {
                out.push(c);
            }
        }
        out.push('\'');
        out
    }

    /// Read everything from `pty` until EOF or `deadline` elapses.
    pub(super) fn read_with_deadline(pty: &Pty, deadline: Duration) -> Result<String, String> {
        let start = Instant::now();
        let mut out = String::new();
        while start.elapsed() < deadline {
            match pty.try_read_now(4096) {
                Ok(Some(chunk)) if chunk.is_empty() => break, // EOF / EIO
                Ok(Some(chunk)) => out.push_str(&String::from_utf8_lossy(&chunk)),
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Read until `idle_window` of silence has elapsed (after any
    /// data has been seen) or until `deadline` overall. Used for
    /// TUI mode where there is no EOF until we send `/exit`.
    fn read_until_idle(
        pty: &Pty,
        deadline: Duration,
        idle_window: Duration,
    ) -> Result<String, String> {
        let start = Instant::now();
        let mut out = String::new();
        let mut last_data: Option<Instant> = None;
        while start.elapsed() < deadline {
            match pty.try_read_now(4096) {
                Ok(Some(chunk)) if chunk.is_empty() => break,
                Ok(Some(chunk)) => {
                    out.push_str(&String::from_utf8_lossy(&chunk));
                    last_data = Some(Instant::now());
                }
                Ok(None) => {
                    if let Some(t) = last_data {
                        if t.elapsed() >= idle_window {
                            break;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    pub(super) fn wait_pid(pid: libc::pid_t, _timeout: Duration) -> Result<(), String> {
        let mut status: libc::c_int = 0;
        // SAFETY: standard waitpid usage.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r < 0 {
            return Err(format!(
                "waitpid({pid}): {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    /// Strip ANSI CSI / OSC escapes. Best-effort; survives partial
    /// sequences. Used for assertion-time text matching.
    pub(super) fn strip_ansi(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut out = String::with_capacity(input.len());
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b == 0x1B && i + 1 < bytes.len() {
                let nxt = bytes[i + 1];
                if nxt == b'[' {
                    // CSI: ESC [ params final
                    i += 2;
                    while i < bytes.len() {
                        let c = bytes[i];
                        i += 1;
                        if (0x40..=0x7E).contains(&c) {
                            break;
                        }
                    }
                    continue;
                } else if nxt == b']' {
                    // OSC: ESC ] ... BEL or ESC \
                    i += 2;
                    while i < bytes.len() {
                        let c = bytes[i];
                        i += 1;
                        if c == 0x07 {
                            break;
                        }
                        if c == 0x1B && i < bytes.len() && bytes[i] == b'\\' {
                            i += 1;
                            break;
                        }
                    }
                    continue;
                } else {
                    // Two-char sequence (ESC X)
                    i += 2;
                    continue;
                }
            }
            if b == b'\r' {
                i += 1;
                continue;
            }
            out.push(b as char);
            i += 1;
        }
        out
    }
}

// ════════════════════════════════════════════════════════════════════
// mod vscode — VS Code Remote Server integration scenarios
// ════════════════════════════════════════════════════════════════════
//
// Mirrors `mod copilot` exactly in shape: per-pass `docker run` of a
// dropbear-in-container image, host-side driven via SSH-over-PTY. The
// VS Code Server scenarios are the end-to-end validation layer that
// Goal B's `docs/product-goal-map.md` calls out as the remaining gap
// after the capability nodes flipped to ✅.
//
// Trial namespace: `vscode::<scenario>`. Each registers as
// `native::vscode::<scenario>` and `litebox::vscode::<scenario>`.
//
//   vscode::bootstrap          — replay the captured Remote-SSH
//                                bootstrap script through `sh -s`.
//   vscode::server_listen      — start `code command-shell` directly,
//                                capture its TCP listening port.
//   vscode::connect_loopback   — same SSH session opens a TCP
//                                connection to the captured port.
//   vscode::connect_cross_ssh  — second independent SSH session
//                                does the same connect (Remote-SSH
//                                SOCKS-proxy pattern).
//
// Image flexibility: `LITEBOX_VSCODE_IMAGE_STAGE` env var picks
// `litebox-vscode` (default — runtime-rewritten) or
// `litebox-vscode-prewrite` (faster startup, requires
// `litebox_syscall_rewriter`, which `setup()` already builds).
//
// Concurrency cap: `LITEBOX_VSCODE_JOBS` (default `1`). The serial
// default protects shared / autonomous runs from dockerd
// stress and from cross-test port conflicts in the cross-SSH
// scenario. One-shot validation runs can raise it
// (`LITEBOX_VSCODE_JOBS=4`).
//
// No GitHub token plumbing — VS Code's `--connection-token` is
// locally-generated and never validated against an external
// service.
//
// Native is the gold standard. Any litebox-pass failure is a real
// shim/runner regression; see CLAUDE.md "Investigating a failure"
// for the workflow.

mod vscode {
    use super::{Failed, Trial, copilot};
    use litebox_test_harness::os::pty::Pty;
    use std::path::Path;
    use std::process::Command;
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    // ───────────────────────────────────────────────────────────────
    // Image-stage selection
    // ───────────────────────────────────────────────────────────────

    /// Docker stage to use for the trials. Default = `litebox-vscode`
    /// (no extra build prerequisite beyond what `setup()` already
    /// does). `LITEBOX_VSCODE_IMAGE_STAGE=prewrite` switches to
    /// `litebox-vscode-prewrite` (pre-rewritten node / dropbear /
    /// bash; saves ~10.5 s startup per trial; requires
    /// `litebox_syscall_rewriter` to be copied into the build
    /// context — `ensure_vscode_image` handles that).
    fn vscode_image_base() -> &'static str {
        match std::env::var("LITEBOX_VSCODE_IMAGE_STAGE").as_deref() {
            Ok("prewrite") | Ok("litebox-vscode-prewrite") => "litebox-vscode-prewrite",
            _ => "litebox-vscode",
        }
    }

    /// Per-worktree resolved tag (`<stage>:wt-<sha256>`). Mirrors
    /// `copilot_image_tag` in the outer scope.
    fn vscode_image_tag() -> String {
        super::image_tag::image_tag(vscode_image_base())
    }

    /// Build the requested VS Code Docker image if missing.
    ///
    /// For the prewrite stage, copies `litebox_syscall_rewriter`
    /// (built by `setup()` in `target/debug/`) into the path the
    /// Dockerfile's `COPY` instruction expects. The copy is
    /// idempotent — re-running over an up-to-date file is a no-op
    /// on disk but always invalidates the layer's cache key only
    /// when the binary actually changes.
    fn ensure_vscode_image(ws_root: &Path) {
        let stage = vscode_image_base();
        let tag = vscode_image_tag();
        let check = Command::new("docker")
            .args(["image", "inspect", &tag])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if matches!(check, Ok(s) if s.success()) {
            return;
        }
        eprintln!("Building {tag} Docker image (stage={stage})...");

        if stage == "litebox-vscode-prewrite" {
            // The prewrite stage's `COPY
            // litebox_tool_executor/rootfs/litebox_syscall_rewriter
            // /tmp/rewriter` instruction needs the rewriter binary
            // at that path in the build context. setup() already
            // built it in target/debug/.
            let rewriter_src = super::debug_dir().join("litebox_syscall_rewriter");
            let rewriter_dst =
                ws_root.join("litebox_tool_executor/rootfs/litebox_syscall_rewriter");
            std::fs::copy(&rewriter_src, &rewriter_dst).unwrap_or_else(|e| {
                panic!(
                    "ensure_vscode_image: copy {} -> {} for prewrite stage: {e}",
                    rewriter_src.display(),
                    rewriter_dst.display(),
                )
            });
        }

        let dockerfile = ws_root.join("litebox_tool_executor/rootfs/Dockerfile");
        let status = Command::new("docker")
            .args(["build", "--target", stage, "-t", &tag, "-f"])
            .arg(&dockerfile)
            .arg(ws_root)
            .status()
            .expect("docker build vscode image");
        assert!(
            status.success(),
            "docker build {tag} (stage={stage}) failed"
        );
    }

    // ───────────────────────────────────────────────────────────────
    // Concurrency cap
    // ───────────────────────────────────────────────────────────────

    fn jobs_cap() -> usize {
        std::env::var("LITEBOX_VSCODE_JOBS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1)
    }

    fn vscode_semaphore() -> &'static std::sync::Mutex<usize> {
        static SEM: OnceLock<std::sync::Mutex<usize>> = OnceLock::new();
        SEM.get_or_init(|| std::sync::Mutex::new(jobs_cap()))
    }

    /// Tiny manual semaphore: acquire a slot or sleep. Mirrors
    /// `CopilotPermit` — keeps VS Code Server trials from saturating
    /// dockerd and from racing each other on port allocation in
    /// the cross-SSH scenario.
    struct VsCodePermit;

    impl VsCodePermit {
        fn acquire() -> Self {
            loop {
                {
                    let mut g = vscode_semaphore().lock().expect("vscode sem");
                    if *g > 0 {
                        *g -= 1;
                        return VsCodePermit;
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    impl Drop for VsCodePermit {
        fn drop(&mut self) {
            if let Ok(mut g) = vscode_semaphore().lock() {
                *g += 1;
            }
        }
    }

    // ───────────────────────────────────────────────────────────────
    // Per-pass container spec
    // ───────────────────────────────────────────────────────────────

    /// Build the per-trial container spec. Same shape as
    /// `build_copilot_spec` (native = bare dropbear; litebox =
    /// `litebox_tool_executor --ssh`), but pointed at the
    /// `litebox-vscode[-prewrite]` image. The fixture dir is
    /// bind-mounted at `/workspace` so scenarios can stage
    /// patched scripts or other inputs there and reach them
    /// from the container.
    fn build_vscode_spec(pass: &str, fixture_dir: &Path) -> super::framework::ContainerSpec {
        let bin_dir = super::debug_dir();
        let mut docker_args: Vec<String> = vec![
            "--cap-add".into(),
            "SYS_PTRACE".into(),
            "-p".into(),
            "127.0.0.1:0:22".into(),
            "-v".into(),
            format!("{}:/opt/litebox:ro", bin_dir.display()),
            "-v".into(),
            format!("{}:/workspace", fixture_dir.display()),
        ];
        // Pass through the same env vars `build_copilot_spec` does
        // so a session's broker/runner tuning knobs apply uniformly.
        for var in [
            "LITEBOX_EAGER_BROKER_SOCKETPAIR",
            "LITEBOX_EAGER_BROKER_SOCKETSEQPACKET",
            "LITEBOX_BROKER_TCP_CONN",
            "LITEBOX_BROKER_INET_RAW",
            "LITEBOX_BROKER_INET_DELAY_NS",
            "LITEBOX_PE10_DIAG",
            "LITEBOX_PE5_DIAG",
            "LITEBOX_CLEANUP_DELAY_MS",
            "RUST_LOG",
            "RUST_BACKTRACE",
        ] {
            if let Ok(val) = std::env::var(var) {
                docker_args.push("-e".into());
                docker_args.push(format!("{var}={val}"));
            }
        }
        let command: Vec<String> = match pass {
            "native" => vec![
                "/usr/sbin/dropbear".into(),
                "-F".into(),
                "-E".into(),
                "-B".into(),
                "-R".into(),
                "-p".into(),
                "22".into(),
            ],
            "litebox" => vec![
                "/opt/litebox/litebox_tool_executor".into(),
                "--rootfs".into(),
                "/".into(),
                "--record-baseline".into(),
                "--ssh".into(),
                "--ssh-port".into(),
                "22".into(),
            ],
            _ => panic!("unknown pass {pass}"),
        };
        super::framework::ContainerSpec {
            image: vscode_image_tag(),
            docker_args,
            command,
            detached: true,
            timeout_secs: None,
        }
    }

    // ───────────────────────────────────────────────────────────────
    // Trial registration
    // ───────────────────────────────────────────────────────────────

    /// All trial scenarios, in declared order. Each registers a
    /// `native::vscode::<id>` and `litebox::vscode::<id>` Trial.
    const SCENARIOS: &[&str] = &[
        "bootstrap",
        "server_listen",
        "connect_loopback",
        "connect_cross_ssh",
    ];

    /// Register every `vscode::<scenario>` Trial pair. Called
    /// unconditionally from `main()` so the dashboard universe
    /// stays consistent and the autonomous `--fill` selector can
    /// pick them up.
    pub(super) fn register_trials(trials: &mut Vec<Trial>) {
        for scn in SCENARIOS {
            for pass in ["native", "litebox"] {
                let name = format!("{pass}::vscode::{scn}");
                let pass_owned = pass.to_string();
                let scn_owned = (*scn).to_string();
                trials.push(Trial::test(name, move || {
                    run_scenario(&pass_owned, &scn_owned)
                }));
            }
        }
    }

    /// Dispatch on scenario id. Each scenario function is
    /// self-contained: acquire permit, ensure image, build spec,
    /// run trial via `framework::run_trial`.
    fn run_scenario(pass: &str, scenario_id: &str) -> Result<(), Failed> {
        match scenario_id {
            "bootstrap" => run_bootstrap(pass),
            "server_listen" => run_server_listen(pass),
            "connect_loopback" => run_connect_loopback(pass),
            "connect_cross_ssh" => run_connect_cross_ssh(pass),
            other => Err(Failed::from(format!("unknown vscode scenario: {other}"))),
        }
    }

    // ───────────────────────────────────────────────────────────────
    // Scenario stubs — bodies land in vscode-{bootstrap,...}-scenario
    // todos. Each fails loudly until implemented so the trial set is
    // present in the dashboard universe from skeleton commit onward.
    // ───────────────────────────────────────────────────────────────

    fn run_bootstrap(pass: &str) -> Result<(), Failed> {
        let _permit = VsCodePermit::acquire();
        let fixture_dir = prep_fixture_dir(pass, "bootstrap").map_err(Failed::from)?;
        ensure_vscode_image(&super::workspace_root());

        // Stage the captured bootstrap script into the per-trial
        // fixture directory (bind-mounted at /workspace in the
        // container). We patch two things at runtime:
        //   1) The hardcoded COMMIT_ID in the captured script with
        //      whatever commit the Docker image has staged. The
        //      Dockerfile pre-installs the CLI as both `code` and
        //      `code-${VSCODE_COMMIT}`, but the script's "is the
        //      CLI installed?" check looks for `code-${COMMIT_ID}`
        //      against its hardcoded ID — without patching, the
        //      script falls into the download path.
        //   2) The trailing `while true; do sleep 180; printf ' ';
        //      done` keepalive — designed to hold the SSH session
        //      open forever while VS Code Remote-SSH uses the
        //      backgrounded CLI. For an end-to-end test we want
        //      the script to exit normally once it's printed its
        //      success markers.
        let template =
            include_str!("../../litebox_tool_executor/scripts/vscode/vscode-bootstrap-captured.sh");
        let script_path = fixture_dir.join("bootstrap.sh");

        let test_id = "vscode::bootstrap".to_string();
        let spec = build_vscode_spec(pass, &fixture_dir);

        super::framework::run_trial(
            pass_static(pass),
            &test_id,
            "vscode",
            "bootstrap",
            spec,
            move |container| {
                let t_dispatch = Instant::now();
                let Some(&port) = container.published_ports.get(&22) else {
                    return drive_fail(
                        format!("container {} did not publish port 22", container.name),
                        0,
                        0,
                    );
                };
                if let Err(e) = copilot::wait_for_sshd(port, Duration::from_secs(30)) {
                    return drive_fail(
                        format!("wait_for_sshd port {port}: {e}"),
                        t_dispatch.elapsed().as_millis(),
                        0,
                    );
                }
                let t_useful_start = Instant::now();
                let t_docker_start_ms = t_useful_start.duration_since(t_dispatch).as_millis();

                // Step 1: detect the installed CLI commit hash.
                let commit = match detect_cli_commit(port, Duration::from_secs(30)) {
                    Ok(c) => c,
                    Err(e) => {
                        return drive_fail(
                            format!("detect_cli_commit: {e}"),
                            t_docker_start_ms,
                            t_useful_start.elapsed().as_millis(),
                        );
                    }
                };
                if commit.len() != 40 || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
                    return drive_fail(
                        format!("detected commit not a 40-hex-char hash: {commit:?}"),
                        t_docker_start_ms,
                        t_useful_start.elapsed().as_millis(),
                    );
                }

                // Step 2: patch the captured script.
                let patched = template
                    .replace(
                        "COMMIT_ID=\"41dd792b5e652393e7787322889ed5fdc58bd75b\"",
                        &format!("COMMIT_ID=\"{commit}\""),
                    )
                    .replace("while true; do sleep 180; printf ' '; done", "exit 0");
                if patched == template {
                    return drive_fail(
                        "bootstrap script patch produced no changes — the captured \
                         script no longer contains the expected commit-id or \
                         keepalive-loop lines"
                            .to_string(),
                        t_docker_start_ms,
                        t_useful_start.elapsed().as_millis(),
                    );
                }
                if let Err(e) = std::fs::write(&script_path, patched.as_bytes()) {
                    return drive_fail(
                        format!("write patched script {}: {e}", script_path.display()),
                        t_docker_start_ms,
                        t_useful_start.elapsed().as_millis(),
                    );
                }

                // Step 3: run `sh /workspace/bootstrap.sh` over SSH
                // and read its complete output.
                let output = match run_remote_script(port, "/workspace/bootstrap.sh", 120) {
                    Ok(o) => o,
                    Err(e) => {
                        return drive_fail(
                            format!("run_remote_script: {e}"),
                            t_docker_start_ms,
                            t_useful_start.elapsed().as_millis(),
                        );
                    }
                };

                let log_dir = super::log_dir();
                let _ = std::fs::create_dir_all(log_dir);
                let safe = format!("vscode-{pass}-bootstrap");
                let _ = std::fs::write(log_dir.join(format!("{safe}.raw.log")), &output);

                let t_useful_ms = t_useful_start.elapsed().as_millis();

                // Step 4: validate markers.
                let stripped = copilot::strip_ansi(&output);
                let has_start = stripped.contains(": start");
                let has_end = stripped.contains(": end");
                let has_listening = stripped.contains("listeningOn==");
                let has_found = stripped.contains("Found existing installation");

                if has_start && has_end && has_listening && has_found {
                    return super::framework::DriveResult {
                        verdict: "pass",
                        detail: None,
                        t_docker_start_ms,
                        t_useful_ms,
                        sub_phases: super::SubPhaseMs::default(),
                        t_docker_spawn_ms: None,
                        t_litebox_init_ms: None,
                        t_harness_load_ms: None,
                    };
                }
                let preview: String = stripped.chars().take(1200).collect();
                drive_fail(
                    format!(
                        "bootstrap markers missing: start={has_start} end={has_end} \
                         listening={has_listening} found_existing_install={has_found} \
                         (detected_commit={commit}). raw log: {}\n\
                         first 1200 chars (ANSI-stripped):\n{preview}",
                        log_dir.join(format!("{safe}.raw.log")).display(),
                    ),
                    t_docker_start_ms,
                    t_useful_ms,
                )
            },
        )
    }

    fn run_server_listen(pass: &str) -> Result<(), Failed> {
        let _permit = VsCodePermit::acquire();
        let fixture_dir = prep_fixture_dir(pass, "server_listen").map_err(Failed::from)?;
        ensure_vscode_image(&super::workspace_root());

        let test_id = "vscode::server_listen".to_string();
        let spec = build_vscode_spec(pass, &fixture_dir);

        super::framework::run_trial(
            pass_static(pass),
            &test_id,
            "vscode",
            "server_listen",
            spec,
            move |container| {
                let t_dispatch = Instant::now();
                let Some(&port) = container.published_ports.get(&22) else {
                    return drive_fail(
                        format!("container {} did not publish port 22", container.name),
                        0,
                        0,
                    );
                };
                if let Err(e) = copilot::wait_for_sshd(port, Duration::from_secs(30)) {
                    return drive_fail(
                        format!("wait_for_sshd port {port}: {e}"),
                        t_dispatch.elapsed().as_millis(),
                        0,
                    );
                }
                let t_useful_start = Instant::now();
                let t_docker_start_ms = t_useful_start.duration_since(t_dispatch).as_millis();

                let commit = match detect_cli_commit(port, Duration::from_secs(30)) {
                    Ok(c) => c,
                    Err(e) => {
                        return drive_fail(
                            format!("detect_cli_commit: {e}"),
                            t_docker_start_ms,
                            t_useful_start.elapsed().as_millis(),
                        );
                    }
                };

                // One SSH session: start the CLI in the background,
                // poll its log for "Listening on N.N.N.N:PORT", emit
                // a stable VSL_PORT=<port> marker on stdout. We use
                // host-side `nohup` + `disown` to detach the CLI
                // from the SSH session so it survives the session's
                // exit; whether it actually stays alive after the
                // session closes is incidental — we only validate
                // that it reached the listening state.
                let cli_path = format!("/root/.vscode-server/code-{commit}");
                let remote_cmd = build_server_listen_remote_cmd(&cli_path, 60);
                let output = match run_remote_command_retry(port, &remote_cmd, 90) {
                    Ok(o) => o,
                    Err(e) => {
                        return drive_fail(
                            format!("run_remote_command_retry: {e}"),
                            t_docker_start_ms,
                            t_useful_start.elapsed().as_millis(),
                        );
                    }
                };

                let log_dir = super::log_dir();
                let _ = std::fs::create_dir_all(log_dir);
                let safe = format!("vscode-{pass}-server_listen");
                let _ = std::fs::write(log_dir.join(format!("{safe}.raw.log")), &output);

                let t_useful_ms = t_useful_start.elapsed().as_millis();
                let stripped = copilot::strip_ansi(&output);

                match parse_vsl_port(&stripped) {
                    Some(captured) if captured != 0 => super::framework::DriveResult {
                        verdict: "pass",
                        detail: None,
                        t_docker_start_ms,
                        t_useful_ms,
                        sub_phases: super::SubPhaseMs::default(),
                        t_docker_spawn_ms: None,
                        t_litebox_init_ms: None,
                        t_harness_load_ms: None,
                    },
                    Some(_) => drive_fail(
                        format!(
                            "VSL_PORT=0 parsed from output (CLI bound to port 0?). raw log: {}",
                            log_dir.join(format!("{safe}.raw.log")).display(),
                        ),
                        t_docker_start_ms,
                        t_useful_ms,
                    ),
                    None => {
                        let preview: String = stripped.chars().take(1500).collect();
                        drive_fail(
                            format!(
                                "no VSL_PORT marker in `code command-shell` output \
                                 (detected_commit={commit}). raw log: {}\n\
                                 first 1500 chars (ANSI-stripped):\n{preview}",
                                log_dir.join(format!("{safe}.raw.log")).display(),
                            ),
                            t_docker_start_ms,
                            t_useful_ms,
                        )
                    }
                }
            },
        )
    }

    fn run_connect_loopback(pass: &str) -> Result<(), Failed> {
        let _permit = VsCodePermit::acquire();
        let fixture_dir = prep_fixture_dir(pass, "connect_loopback").map_err(Failed::from)?;
        ensure_vscode_image(&super::workspace_root());

        let test_id = "vscode::connect_loopback".to_string();
        let spec = build_vscode_spec(pass, &fixture_dir);

        super::framework::run_trial(
            pass_static(pass),
            &test_id,
            "vscode",
            "connect_loopback",
            spec,
            move |container| {
                let t_dispatch = Instant::now();
                let Some(&port) = container.published_ports.get(&22) else {
                    return drive_fail(
                        format!("container {} did not publish port 22", container.name),
                        0,
                        0,
                    );
                };
                if let Err(e) = copilot::wait_for_sshd(port, Duration::from_secs(30)) {
                    return drive_fail(
                        format!("wait_for_sshd port {port}: {e}"),
                        t_dispatch.elapsed().as_millis(),
                        0,
                    );
                }
                let t_useful_start = Instant::now();
                let t_docker_start_ms = t_useful_start.duration_since(t_dispatch).as_millis();

                let commit = match detect_cli_commit(port, Duration::from_secs(30)) {
                    Ok(c) => c,
                    Err(e) => {
                        return drive_fail(
                            format!("detect_cli_commit: {e}"),
                            t_docker_start_ms,
                            t_useful_start.elapsed().as_millis(),
                        );
                    }
                };

                // Same SSH session does the start-CLI-then-connect
                // sequence. The CLI stays alive for the entire
                // session lifetime, so the connect runs while it's
                // still listening.
                let cli_path = format!("/root/.vscode-server/code-{commit}");
                let remote_cmd = build_connect_loopback_remote_cmd(&cli_path, 60);
                let output = match run_remote_command_retry(port, &remote_cmd, 120) {
                    Ok(o) => o,
                    Err(e) => {
                        return drive_fail(
                            format!("run_remote_command_retry: {e}"),
                            t_docker_start_ms,
                            t_useful_start.elapsed().as_millis(),
                        );
                    }
                };

                let log_dir = super::log_dir();
                let _ = std::fs::create_dir_all(log_dir);
                let safe = format!("vscode-{pass}-connect_loopback");
                let _ = std::fs::write(log_dir.join(format!("{safe}.raw.log")), &output);

                let t_useful_ms = t_useful_start.elapsed().as_millis();
                let stripped = copilot::strip_ansi(&output);

                let port_captured = parse_vsl_port(&stripped);
                let conn_ok = stripped.lines().any(|l| l.trim() == "VSL_CONN_OK");

                match (port_captured, conn_ok) {
                    (Some(p), true) if p != 0 => super::framework::DriveResult {
                        verdict: "pass",
                        detail: None,
                        t_docker_start_ms,
                        t_useful_ms,
                        sub_phases: super::SubPhaseMs::default(),
                        t_docker_spawn_ms: None,
                        t_litebox_init_ms: None,
                        t_harness_load_ms: None,
                    },
                    (port_opt, conn_opt) => {
                        let preview: String = stripped.chars().take(1500).collect();
                        drive_fail(
                            format!(
                                "connect_loopback failed: port={port_opt:?} conn_ok={conn_opt} \
                                 (detected_commit={commit}). raw log: {}\n\
                                 first 1500 chars (ANSI-stripped):\n{preview}",
                                log_dir.join(format!("{safe}.raw.log")).display(),
                            ),
                            t_docker_start_ms,
                            t_useful_ms,
                        )
                    }
                }
            },
        )
    }

    fn run_connect_cross_ssh(pass: &str) -> Result<(), Failed> {
        let _permit = VsCodePermit::acquire();
        let fixture_dir = prep_fixture_dir(pass, "connect_cross_ssh").map_err(Failed::from)?;
        ensure_vscode_image(&super::workspace_root());

        let test_id = "vscode::connect_cross_ssh".to_string();
        let spec = build_vscode_spec(pass, &fixture_dir);

        super::framework::run_trial(
            pass_static(pass),
            &test_id,
            "vscode",
            "connect_cross_ssh",
            spec,
            move |container| {
                let t_dispatch = Instant::now();
                let Some(&port) = container.published_ports.get(&22) else {
                    return drive_fail(
                        format!("container {} did not publish port 22", container.name),
                        0,
                        0,
                    );
                };
                if let Err(e) = copilot::wait_for_sshd(port, Duration::from_secs(30)) {
                    return drive_fail(
                        format!("wait_for_sshd port {port}: {e}"),
                        t_dispatch.elapsed().as_millis(),
                        0,
                    );
                }
                let t_useful_start = Instant::now();
                let t_docker_start_ms = t_useful_start.duration_since(t_dispatch).as_millis();

                let commit = match detect_cli_commit(port, Duration::from_secs(30)) {
                    Ok(c) => c,
                    Err(e) => {
                        return drive_fail(
                            format!("detect_cli_commit: {e}"),
                            t_docker_start_ms,
                            t_useful_start.elapsed().as_millis(),
                        );
                    }
                };

                let log_dir = super::log_dir();
                let _ = std::fs::create_dir_all(log_dir);
                let safe = format!("vscode-{pass}-connect_cross_ssh");

                // SSH session A — starts the CLI in background,
                // captures the port from the CLI's log, writes the
                // port to /tmp/vscode-port-A inside the container,
                // then exits. The CLI keeps running after session A
                // ends because of `nohup` + `--parent-process-id 1`
                // (= the container's init = sshd/litebox; never
                // exits during the trial) + `< /dev/null`.
                let cli_path = format!("/root/.vscode-server/code-{commit}");
                let session_a_cmd = build_cross_ssh_session_a_cmd(&cli_path, 60);
                let session_a_out = match run_remote_command_retry(port, &session_a_cmd, 90) {
                    Ok(o) => o,
                    Err(e) => {
                        return drive_fail(
                            format!("session A (start CLI + capture port): {e}"),
                            t_docker_start_ms,
                            t_useful_start.elapsed().as_millis(),
                        );
                    }
                };
                let _ = std::fs::write(
                    log_dir.join(format!("{safe}.session-a.log")),
                    &session_a_out,
                );
                let stripped_a = copilot::strip_ansi(&session_a_out);
                let captured_port = match parse_vsl_port(&stripped_a) {
                    Some(p) if p != 0 => p,
                    _ => {
                        let preview: String = stripped_a.chars().take(1500).collect();
                        return drive_fail(
                            format!(
                                "session A: no VSL_PORT marker \
                                 (detected_commit={commit}). session-a log: {}\n\
                                 first 1500 chars (ANSI-stripped):\n{preview}",
                                log_dir.join(format!("{safe}.session-a.log")).display(),
                            ),
                            t_docker_start_ms,
                            t_useful_start.elapsed().as_millis(),
                        );
                    }
                };

                // SSH session B — a completely fresh SSH session
                // to the same container. Connects to the port
                // session A told us about. Under litebox this
                // exercises cross-worker loopback TCP (each SSH
                // session is its own dropbear → bash worker tree).
                let session_b_cmd = build_cross_ssh_session_b_cmd(captured_port);
                let session_b_out = match run_remote_command_retry(port, &session_b_cmd, 30) {
                    Ok(o) => o,
                    Err(e) => {
                        return drive_fail(
                            format!("session B (cross-ssh connect to port {captured_port}): {e}"),
                            t_docker_start_ms,
                            t_useful_start.elapsed().as_millis(),
                        );
                    }
                };
                let _ = std::fs::write(
                    log_dir.join(format!("{safe}.session-b.log")),
                    &session_b_out,
                );
                let stripped_b = copilot::strip_ansi(&session_b_out);

                let t_useful_ms = t_useful_start.elapsed().as_millis();
                let conn_ok = stripped_b.lines().any(|l| l.trim() == "VSL_CONN_OK");

                if conn_ok {
                    super::framework::DriveResult {
                        verdict: "pass",
                        detail: None,
                        t_docker_start_ms,
                        t_useful_ms,
                        sub_phases: super::SubPhaseMs::default(),
                        t_docker_spawn_ms: None,
                        t_litebox_init_ms: None,
                        t_harness_load_ms: None,
                    }
                } else {
                    let preview: String = stripped_b.chars().take(1500).collect();
                    drive_fail(
                        format!(
                            "session B: no VSL_CONN_OK marker \
                             (port from session A = {captured_port}). \
                             session-b log: {}\n\
                             first 1500 chars (ANSI-stripped):\n{preview}",
                            log_dir.join(format!("{safe}.session-b.log")).display(),
                        ),
                        t_docker_start_ms,
                        t_useful_ms,
                    )
                }
            },
        )
    }

    // ───────────────────────────────────────────────────────────────
    // Shared helpers (kept ready for scenario bodies)
    // ───────────────────────────────────────────────────────────────

    /// Per-trial fixture directory. Cleared and recreated at the
    /// start of each scenario so a re-run sees a fresh `/workspace`.
    fn vscode_fixture_dir(pass: &str, scenario_id: &str) -> std::path::PathBuf {
        super::target_dir()
            .join("vscode-fixtures")
            .join(format!("{pass}-{scenario_id}"))
    }

    /// Create + return a fresh fixture dir. Borrowed from the
    /// per-scenario bootstrap in `run_startup_then_exit` /
    /// `run_copilot_trial`.
    fn prep_fixture_dir(pass: &str, scenario_id: &str) -> Result<std::path::PathBuf, String> {
        let dir = vscode_fixture_dir(pass, scenario_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("create fixture dir {}: {e}", dir.display()))?;
        Ok(dir)
    }

    /// Convert the static `&str` pass label into a `&'static str`
    /// suitable for `framework::run_trial`'s typed pass argument.
    fn pass_static(pass: &str) -> &'static str {
        match pass {
            "native" => "native",
            "litebox" => "litebox",
            _ => "unknown",
        }
    }

    /// Build a uniform `DriveResult::FAIL` envelope from a detail
    /// string and the timing fields the caller has already captured.
    /// Hides the noise of the seven-field struct literal at each
    /// failure site.
    fn drive_fail(
        detail: String,
        t_docker_start_ms: u128,
        t_useful_ms: u128,
    ) -> super::framework::DriveResult {
        super::framework::DriveResult {
            verdict: "FAIL",
            detail: Some(detail),
            t_docker_start_ms,
            t_useful_ms,
            sub_phases: super::SubPhaseMs::default(),
            t_docker_spawn_ms: None,
            t_litebox_init_ms: None,
            t_harness_load_ms: None,
        }
    }

    /// Run a shell command over SSH (no PTY needed; `-T` disables
    /// remote PTY allocation so bytes flow through clean pipes),
    /// read its merged stdout/stderr to EOF within `timeout_secs`,
    /// and return the captured output as a String.
    ///
    /// Uses a single SSH session: argv is the literal remote
    /// command. Caller is responsible for any shell-quoting inside
    /// `remote_cmd`.
    fn run_remote_command(
        port: u16,
        remote_cmd: &str,
        timeout_secs: u64,
    ) -> Result<String, String> {
        let pty = Pty::open()?;
        let mut argv = copilot::ssh_argv_base(port);
        argv.push(remote_cmd.to_string());
        let pid = pty.fork_exec(&argv, /* ctrl_tty = */ true)?;
        let result = copilot::read_with_deadline(&pty, Duration::from_secs(timeout_secs))?;
        let _ = copilot::wait_pid(pid, Duration::from_secs(10));
        Ok(result)
    }

    /// Two-shot retry for `run_remote_command` to absorb the
    /// "dropbear accepted TCP before SSH handshake was ready"
    /// flake that `drive_pminus` already documents in mod copilot.
    fn run_remote_command_retry(
        port: u16,
        remote_cmd: &str,
        timeout_secs: u64,
    ) -> Result<String, String> {
        let first = run_remote_command(port, remote_cmd, timeout_secs)?;
        if first.contains("kex_exchange_identification") || first.trim().is_empty() {
            std::thread::sleep(Duration::from_secs(7));
            return run_remote_command(port, remote_cmd, timeout_secs);
        }
        Ok(first)
    }

    /// Detect the installed VS Code CLI commit hash inside the
    /// running container by calling `/root/.vscode-server/code
    /// --version` over SSH and finding a 40-char lowercase-hex
    /// token anywhere in the output. `code --version` prints
    /// `code <ver> (commit <40-hex>)\n<arch>` — the original VSI
    /// code grepped with Perl `'commit \K[a-f0-9]{40}'`; a plain
    /// scan over the bytes is equivalent and doesn't need a regex
    /// dep.
    fn detect_cli_commit(port: u16, timeout: Duration) -> Result<String, String> {
        let cmd = "/root/.vscode-server/code --version 2>/dev/null";
        let output = run_remote_command_retry(port, cmd, timeout.as_secs())?;
        if let Some(commit) = extract_first_hex40(&output) {
            return Ok(commit);
        }
        Err(format!(
            "no 40-char hex commit substring in `code --version` output:\n{}",
            output.chars().take(800).collect::<String>(),
        ))
    }

    /// Return the first contiguous 40-lowercase-hex substring in
    /// `s`, or None. Used to lift the VS Code commit hash out of
    /// `code --version` output without pulling in a regex dep.
    ///
    /// The contract is exercised end-to-end by `native::vscode::bootstrap`:
    /// that trial calls `detect_cli_commit` against the live `code`
    /// binary in the `litebox-vscode` image; a regression in this
    /// helper would produce a precise FAIL there (`detect_cli_commit:
    /// no 40-char hex commit substring …`). The harness uses
    /// `libtest_mimic` (`harness = false`) so `#[test]` functions
    /// here would not be auto-collected — the integration trial is
    /// the contract test.
    fn extract_first_hex40(s: &str) -> Option<String> {
        let bytes = s.as_bytes();
        let is_lc_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
        let mut i = 0;
        while i + 40 <= bytes.len() {
            if !is_lc_hex(bytes[i]) {
                i += 1;
                continue;
            }
            let mut j = i;
            while j < bytes.len() && is_lc_hex(bytes[j]) {
                j += 1;
            }
            // Exactly 40 hex chars — VS Code's commit format. A
            // longer run is some other hex blob; skip it.
            if j - i == 40 {
                return Some(s[i..j].to_string());
            }
            i = j + 1;
        }
        None
    }

    /// Run an executable script that lives at `remote_script_path`
    /// in the container (typically `/workspace/<name>.sh` via the
    /// fixture bind mount). Uses `sh <path>` so the script doesn't
    /// need the executable bit set.
    fn run_remote_script(
        port: u16,
        remote_script_path: &str,
        timeout_secs: u64,
    ) -> Result<String, String> {
        let cmd = format!("sh {}", copilot::shell_quote(remote_script_path));
        run_remote_command_retry(port, &cmd, timeout_secs)
    }

    /// Construct the remote-shell command for `vscode::server_listen`.
    /// One SSH session does it all: start the CLI in background,
    /// poll its log up to `poll_secs` times (1 sample/s), emit
    /// `VSL_PORT=<port>` once the listen line shows up, exit.
    ///
    /// `nohup` + `disown` + `< /dev/null` mirrors the bootstrap
    /// script's CLI launch shape. The CLI's `--parent-process-id`
    /// gets bound to PID 1 (the container's init = sshd/litebox)
    /// so the CLI doesn't auto-exit when our SSH session ends —
    /// useful for the downstream `connect_loopback` /
    /// `connect_cross_ssh` scenarios.
    fn build_server_listen_remote_cmd(cli_path: &str, poll_secs: u32) -> String {
        let cli_q = copilot::shell_quote(cli_path);
        let token = "litebox-vscode-itest-token";
        format!(
            "set -e; \
             LOG=/tmp/vscode-server-listen.log; \
             rm -f \"$LOG\"; \
             nohup env VSCODE_CLI_REQUIRE_TOKEN={token} \
                {cli_q} command-shell \
                --cli-data-dir /tmp/vscode-cli-data \
                --parent-process-id 1 \
                --on-host=127.0.0.1 --on-port=0 \
                > \"$LOG\" 2>&1 < /dev/null & \
             CLI_PID=$!; \
             disown $CLI_PID 2>/dev/null || true; \
             echo VSL_CLI_PID=$CLI_PID; \
             for _ in $(seq 1 {poll_secs}); do \
                LISTEN_LINE=$(grep -aE 'Listening on .+' \"$LOG\" 2>/dev/null | head -1); \
                if [ -n \"$LISTEN_LINE\" ]; then \
                    PORT=$(echo \"$LISTEN_LINE\" | sed -nE 's/.*:([0-9]+).*/\\1/p'); \
                    if [ -n \"$PORT\" ]; then \
                        echo VSL_PORT=$PORT; \
                        echo VSL_LISTEN_LINE=$LISTEN_LINE; \
                        exit 0; \
                    fi; \
                fi; \
                if ! kill -0 $CLI_PID 2>/dev/null; then \
                    echo VSL_CLI_DIED; \
                    cat \"$LOG\"; \
                    exit 1; \
                fi; \
                sleep 1; \
             done; \
             echo VSL_NO_PORT; \
             cat \"$LOG\"; \
             exit 1"
        )
    }

    /// Parse the `VSL_PORT=<u16>` marker emitted by
    /// `build_server_listen_remote_cmd`. Returns `Some(port)` on
    /// successful parse, `None` if the marker is absent or
    /// non-numeric. End-to-end contracted by the
    /// `native::vscode::server_listen` trial (= the
    /// `libtest_mimic` harness doesn't run `#[test]` functions).
    fn parse_vsl_port(s: &str) -> Option<u16> {
        for line in s.lines() {
            if let Some(rest) = line.trim().strip_prefix("VSL_PORT=") {
                if let Ok(p) = rest.trim().parse::<u16>() {
                    return Some(p);
                }
            }
        }
        None
    }

    /// Remote-shell program for `vscode::connect_loopback`. Reuses
    /// the start-CLI-and-poll logic from
    /// `build_server_listen_remote_cmd`, then opens a TCP
    /// connection to the captured port via bash's `/dev/tcp/`
    /// pseudo-device, gated on a 3 s `timeout` so a litebox-side
    /// bug that hangs `connect(2)` produces a bounded FAIL
    /// instead of running out the trial deadline.
    ///
    /// Just the TCP handshake completing is sufficient — we don't
    /// try to speak the VS Code tunnel protocol (custom mTLS-ish
    /// shape). A successful 3-way handshake proves the CLI bound
    /// the port AND that loopback TCP delivery works through
    /// litebox's broker.
    fn build_connect_loopback_remote_cmd(cli_path: &str, poll_secs: u32) -> String {
        let cli_q = copilot::shell_quote(cli_path);
        let token = "litebox-vscode-itest-token";
        format!(
            "set -e; \
             LOG=/tmp/vscode-connect-loopback.log; \
             rm -f \"$LOG\"; \
             nohup env VSCODE_CLI_REQUIRE_TOKEN={token} \
                {cli_q} command-shell \
                --cli-data-dir /tmp/vscode-cli-data \
                --parent-process-id 1 \
                --on-host=127.0.0.1 --on-port=0 \
                > \"$LOG\" 2>&1 < /dev/null & \
             CLI_PID=$!; \
             disown $CLI_PID 2>/dev/null || true; \
             echo VSL_CLI_PID=$CLI_PID; \
             PORT=; \
             for _ in $(seq 1 {poll_secs}); do \
                LISTEN_LINE=$(grep -aE 'Listening on .+' \"$LOG\" 2>/dev/null | head -1); \
                if [ -n \"$LISTEN_LINE\" ]; then \
                    PORT=$(echo \"$LISTEN_LINE\" | sed -nE 's/.*:([0-9]+).*/\\1/p'); \
                    if [ -n \"$PORT\" ]; then \
                        echo VSL_PORT=$PORT; \
                        break; \
                    fi; \
                fi; \
                if ! kill -0 $CLI_PID 2>/dev/null; then \
                    echo VSL_CLI_DIED; \
                    cat \"$LOG\"; \
                    exit 1; \
                fi; \
                sleep 1; \
             done; \
             if [ -z \"$PORT\" ]; then \
                echo VSL_NO_PORT; \
                cat \"$LOG\"; \
                exit 1; \
             fi; \
             if timeout 3 bash -c \"exec 3<>/dev/tcp/127.0.0.1/$PORT\" 2>&1; then \
                echo VSL_CONN_OK; \
                exit 0; \
             else \
                echo VSL_CONN_FAIL exit=$?; \
                cat \"$LOG\"; \
                exit 1; \
             fi"
        )
    }

    /// Remote-shell program for SSH session A of
    /// `vscode::connect_cross_ssh`. Same start-CLI-and-poll shape
    /// as `build_server_listen_remote_cmd`, but additionally
    /// writes the captured port to `/tmp/vscode-port-A` in the
    /// container's filesystem so session B can read it from a
    /// completely separate SSH session. Exits after emitting
    /// `VSL_PORT=` (the CLI keeps running because of `nohup` +
    /// `--parent-process-id 1`).
    fn build_cross_ssh_session_a_cmd(cli_path: &str, poll_secs: u32) -> String {
        let cli_q = copilot::shell_quote(cli_path);
        let token = "litebox-vscode-itest-token";
        format!(
            "set -e; \
             LOG=/tmp/vscode-cross-ssh.log; \
             PORT_FILE=/tmp/vscode-port-A; \
             rm -f \"$LOG\" \"$PORT_FILE\"; \
             nohup env VSCODE_CLI_REQUIRE_TOKEN={token} \
                {cli_q} command-shell \
                --cli-data-dir /tmp/vscode-cli-data \
                --parent-process-id 1 \
                --on-host=127.0.0.1 --on-port=0 \
                > \"$LOG\" 2>&1 < /dev/null & \
             CLI_PID=$!; \
             disown $CLI_PID 2>/dev/null || true; \
             echo VSL_CLI_PID=$CLI_PID; \
             for _ in $(seq 1 {poll_secs}); do \
                LISTEN_LINE=$(grep -aE 'Listening on .+' \"$LOG\" 2>/dev/null | head -1); \
                if [ -n \"$LISTEN_LINE\" ]; then \
                    PORT=$(echo \"$LISTEN_LINE\" | sed -nE 's/.*:([0-9]+).*/\\1/p'); \
                    if [ -n \"$PORT\" ]; then \
                        printf '%s' \"$PORT\" > \"$PORT_FILE\"; \
                        echo VSL_PORT=$PORT; \
                        exit 0; \
                    fi; \
                fi; \
                if ! kill -0 $CLI_PID 2>/dev/null; then \
                    echo VSL_CLI_DIED; \
                    cat \"$LOG\"; \
                    exit 1; \
                fi; \
                sleep 1; \
             done; \
             echo VSL_NO_PORT; \
             cat \"$LOG\"; \
             exit 1"
        )
    }

    /// Remote-shell program for SSH session B of
    /// `vscode::connect_cross_ssh`. Connects to the CLI's bound
    /// port (passed in directly from the host so we don't depend
    /// on reading session A's `/tmp/vscode-port-A` file — the
    /// host already parsed VSL_PORT from session A's stdout). 3 s
    /// `timeout` on the connect bounds litebox-side hangs.
    fn build_cross_ssh_session_b_cmd(captured_port: u16) -> String {
        format!(
            "if timeout 3 bash -c \"exec 3<>/dev/tcp/127.0.0.1/{captured_port}\" 2>&1; then \
                echo VSL_CONN_OK; \
                exit 0; \
             else \
                echo VSL_CONN_FAIL exit=$?; \
                exit 1; \
             fi"
        )
    }
}

mod dropbear_bash {
    use super::{Failed, Trial, copilot};
    use litebox_test_harness::os::pty::Pty;
    use std::path::Path;
    use std::time::{Duration, Instant};

    struct Scenario {
        id: &'static str,
        command: &'static str,
        expected: &'static [&'static str],
        fixtures: &'static [(&'static str, &'static str)],
    }

    fn scenarios() -> &'static [Scenario] {
        &[
            Scenario {
                id: "echo_one_line",
                command: "echo HELLO_PHASE_H",
                expected: &["HELLO_PHASE_H"],
                fixtures: &[],
            },
            Scenario {
                id: "echo_two_lines",
                command: "echo PRE; echo POST",
                expected: &["PRE", "POST"],
                fixtures: &[],
            },
            Scenario {
                id: "echo_after_sleep",
                command: "echo PRE; sleep 0.1; echo POST",
                expected: &["PRE", "POST"],
                fixtures: &[],
            },
            Scenario {
                id: "exec_chain",
                command: "exec bash -c 'echo CHILD'",
                expected: &["CHILD"],
                fixtures: &[],
            },
            Scenario {
                id: "script_file",
                command: "bash /workspace/phase-h-test-script.sh",
                expected: &["L1", "L2", "L3"],
                fixtures: &[(
                    "phase-h-test-script.sh",
                    "echo L1\necho L2\nsleep 0.1\necho L3\n",
                )],
            },
            // Phase-H triangulation probes (added 2026-05-27).
            // These distinguish "bash internally fork+execs another binary"
            // from "bash takes real wallclock time" from "two sequential
            // writes with anything between them". Together with the existing
            // echo_two_lines (no separator) and echo_after_sleep (fork+exec
            // sleep with non-zero duration), they isolate the trigger.
            Scenario {
                // Pure bash builtins, no fork. If FAIL: bug is in any
                // sequence of two writes with anything between them, even
                // a no-op. If PASS: bash builtins are fine; trigger needs
                // a fork.
                id: "echo_builtin_true",
                command: "echo PRE; true; echo POST",
                expected: &["PRE", "POST"],
                fixtures: &[],
            },
            Scenario {
                // fork+exec /bin/true (no sleep). If FAIL: bug is in
                // fork+exec of a child between two writes, not in the
                // sleep itself. If PASS: bug needs real wallclock time
                // or specific sleep behavior.
                id: "echo_fork_true",
                command: "echo PRE; /bin/true; echo POST",
                expected: &["PRE", "POST"],
                fixtures: &[],
            },
            Scenario {
                // fork+exec /bin/sleep with 0 duration. Isolates "is it
                // /bin/sleep specifically?" If FAIL: bug needs sleep.
                // If PASS but echo_fork_true PASSES: bug is the wallclock
                // delay in sleep with non-zero arg.
                id: "echo_sleep_zero",
                command: "echo PRE; /bin/sleep 0; echo POST",
                expected: &["PRE", "POST"],
                fixtures: &[],
            },
            // Copilot CLI shell tool repro probes (added 2026-05-31).
            // The copilot::tui.{read_file,find_head,build} and
            // copilot::pminus.find_head trials regress because copilot's
            // node-side "shell" tool reads child output by spawning
            // bash, draining the child's stdout pipe to EOF, then
            // calling waitpid. Several real shell idioms appear to
            // deadlock that EOF wait under litebox while passing on
            // native. These dropbear_bash probes exercise the same
            // idioms over SSH+bash so the failure can be reproduced
            // without copilot in the loop.
            Scenario {
                // Pipeline where downstream (head -1) exits early,
                // sending SIGPIPE upstream. Copilot's find_head
                // scenario uses this exact shape.
                id: "pipe_head_early_exit",
                command: "find /tmp -maxdepth 1 -type d | head -1; echo DONE",
                expected: &["DONE"],
                fixtures: &[],
            },
            Scenario {
                // Pipeline with file producer + small consumer.
                // Variant of pipe_head_early_exit where producer is
                // 'cat' on a real file.
                id: "pipe_cat_head",
                command: "printf 'a\\nb\\nc\\n' > /tmp/p.txt; cat /tmp/p.txt | head -1; echo DONE",
                expected: &["DONE"],
                fixtures: &[],
            },
            Scenario {
                // cat of a small bind-mounted file. Variant of
                // pminus.read_file but via dropbear, no copilot. Mounted
                // /workspace contains the fixture; same setup as
                // copilot tests.
                id: "cat_workspace_file",
                command: "cat /workspace/cat-target.txt; echo DONE",
                expected: &["L1", "L2", "DONE"],
                fixtures: &[("cat-target.txt", "L1\nL2\n")],
            },
            // node `child_process.spawn` probes — copilot's shell tool
            // runs commands by spawning bash via node's
            // `child_process.spawn`, draining stdout to EOF, then
            // waitpid'ing the bash. The pipeline probes above proved
            // bash + pipeline works fine over SSH; these isolate the
            // node-side drain path that copilot actually uses.
            Scenario {
                id: "node_spawn_bash_pipeline",
                command: "node -e \"const{spawn}=require('child_process');\
const c=spawn('bash',['-c','find /tmp -maxdepth 1 -type d | head -1; echo INNER_DONE']);\
let o='';c.stdout.on('data',d=>o+=d);c.on('close',code=>{process.stdout.write('out=['+o.replace(/\\n/g,'|')+'] code='+code+' OUTER_DONE\\n');});\"",
                expected: &["INNER_DONE", "OUTER_DONE"],
                fixtures: &[],
            },
            Scenario {
                id: "node_spawn_bash_cat",
                command: "node -e \"const{spawn}=require('child_process');\
const c=spawn('bash',['-c','cat /workspace/cat-target2.txt; echo INNER_DONE']);\
let o='';c.stdout.on('data',d=>o+=d);c.on('close',code=>{process.stdout.write('out=['+o.replace(/\\n/g,'|')+'] code='+code+' OUTER_DONE\\n');});\"",
                expected: &["L1", "L2", "INNER_DONE", "OUTER_DONE"],
                fixtures: &[("cat-target2.txt", "L1\nL2\n")],
            },
            // Mirror of `copilot::tui.find_head`: node spawns bash
            // running `find … | head -5` over a bind-mounted /workspace
            // with 6 .txt files. Multi-line drainage through node's
            // child_process pipe AND SIGPIPE-killed upstream — the
            // exact shape that copilot's shell tool deadlocks under
            // litebox today. Pre-fix this probe FAILs on litebox with
            // truncated output; native PASSes with all 5 filenames.
            Scenario {
                id: "node_spawn_bash_find_head",
                command: "node -e \"const{spawn}=require('child_process');\
const c=spawn('bash',['-c',\\\"find /workspace -name '*.txt' | head -5; echo INNER_DONE\\\"]);\
let o='';c.stdout.on('data',d=>o+=d);c.on('close',code=>{process.stdout.write('out=['+o.replace(/\\n/g,'|')+'] code='+code+' OUTER_DONE\\n');});\"",
                expected: &["nf1.txt", "nf2.txt", "INNER_DONE", "OUTER_DONE"],
                fixtures: &[
                    ("nf1.txt", "1\n"),
                    ("nf2.txt", "2\n"),
                    ("nf3.txt", "3\n"),
                    ("nf4.txt", "4\n"),
                    ("nf5.txt", "5\n"),
                    ("nf6.txt", "6\n"),
                ],
            },
            // Nested-PTY probes — copilot's shell tool spawns bash on
            // a PTY allocated by node-pty (UnixTerminal). The dropbear
            // SSH session also runs the outer shell on a PTY, so this
            // is a nested-pty scenario: outer PTY (sshd → bash) hosts
            // an inner PTY (script(1) → bash). `script -q` is the
            // closest userland approximation of node-pty: it calls
            // openpty + fork + setsid + dup2 in the child, then
            // drains the master fd in the parent.
            Scenario {
                id: "nested_pty_pipeline",
                command: "script -q -c 'find /tmp -maxdepth 1 -type d | head -1; echo INNER_DONE' /dev/null; echo OUTER_DONE",
                expected: &["INNER_DONE", "OUTER_DONE"],
                fixtures: &[],
            },
            // Nested-PTY mirror of `copilot::tui.find_head`. script(1)
            // approximates node-pty; the inner pipeline matches copilot's
            // shell tool prompt exactly. Native produces 5 lines; copilot
            // under litebox reports "1 line". This probe is the headless
            // repro for the bash-output-read-hang shim bug.
            Scenario {
                id: "nested_pty_find_head",
                command: "script -q -c \"find /workspace -name '*.txt' | head -5; echo INNER_DONE\" /dev/null; echo OUTER_DONE",
                expected: &["pf2.txt", "pf3.txt", "INNER_DONE", "OUTER_DONE"],
                fixtures: &[
                    ("pf1.txt", "1\n"),
                    ("pf2.txt", "2\n"),
                    ("pf3.txt", "3\n"),
                    ("pf4.txt", "4\n"),
                    ("pf5.txt", "5\n"),
                    ("pf6.txt", "6\n"),
                ],
            },
            Scenario {
                id: "nested_pty_cat",
                command: "script -q -c 'cat /workspace/cat-target3.txt; echo INNER_DONE' /dev/null; echo OUTER_DONE",
                expected: &["L1", "L2", "INNER_DONE", "OUTER_DONE"],
                fixtures: &[("cat-target3.txt", "L1\nL2\n")],
            },
            Scenario {
                // Most minimal nested-pty case: script(1) running a
                // bare echo. If this fails: foreground-pgrp / pty
                // teardown bug. If it passes but other nested_pty_*
                // fail: the bug needs the inner command to do real
                // I/O.
                id: "nested_pty_echo",
                command: "script -q -c 'echo INNER_DONE' /dev/null; echo OUTER_DONE",
                expected: &["INNER_DONE", "OUTER_DONE"],
                fixtures: &[],
            },
            Scenario {
                // Baseline: forked child that DOESN'T open /dev/ptmx,
                // just inherits stdio. If this passes but
                // nested_pty_echo fails: bug is specifically in
                // /dev/ptmx open + close interaction with inherited
                // pty slave fds.
                id: "fork_no_ptmx",
                command: "bash -c 'echo INNER_DONE'; echo OUTER_DONE",
                expected: &["INNER_DONE", "OUTER_DONE"],
                fixtures: &[],
            },
            Scenario {
                // Forked child opens /dev/ptmx then immediately
                // closes it (TIOCGPTPEER for inner slave omitted).
                // Isolates "does open(/dev/ptmx) + close + child-exit
                // corrupt parent's inherited slave fds?"
                id: "fork_ptmx_open_close",
                command: "bash -c 'exec 9<>/dev/ptmx; exec 9<&-; echo INNER_DONE'; echo OUTER_DONE",
                expected: &["INNER_DONE", "OUTER_DONE"],
                fixtures: &[],
            },
            // Wave 10 Track A: drive copilot's own bundled node-pty
            // native module (pty.node) against a multi-line subprocess.
            // Mirrors copilot's shell tool exactly: pty.fork(...) +
            // fs.createReadStream(masterFd) drain. If THIS reproduces
            // truncated output on litebox while PTYR_STDOUT_POST_SLEEP
            // (blocking C reader, same shape) passes, the bug is in
            // non-blocking master read + libuv's epoll-driven event
            // loop interaction with litebox PTY emulation.
            Scenario {
                id: "nodepty_seq",
                command: "node /workspace/nodepty_probe.mjs",
                expected: &["END_TOTAL=", "5\\r\\n"],
                fixtures: &[(
                    "nodepty_probe.mjs",
                    "import { createRequire } from \"module\";\n\
const require = createRequire(\"/usr/local/lib/node_modules/@github/copilot/index.js\");\n\
const pty = require(\"/usr/local/lib/node_modules/@github/copilot/prebuilds/linux-x64/pty.node\");\n\
import * as net from \"net\";\n\
const env = Object.entries(process.env).map(([k,v]) => `${k}=${v}`);\n\
const r = pty.fork(\"/usr/bin/seq\", [\"1\",\"5\"], env, \"/tmp\", 80, 24, -1, -1, true, \"\", (c,sig)=>console.log(\"EXIT\",c,sig));\n\
console.log(\"PID\",r.pid,\"FD\",r.fd);\n\
// node-pty wraps master fd in net.Socket via Pipe binding to bypass\n\
// node's TTY-fd check. This is the actual code path copilot's shell\n\
// tool exercises.\n\
const { Pipe, constants } = process.binding(\"pipe_wrap\");\n\
const handle = new Pipe(constants.SOCKET);\n\
handle.open(r.fd);\n\
const s = new net.Socket({ handle, readable: true, writable: true });\n\
let total = \"\";\n\
s.on(\"data\", (c) => { total += c.toString(); console.log(\"CHUNK\",JSON.stringify(c.toString())); });\n\
s.on(\"end\", () => { console.log(\"END_TOTAL=\",JSON.stringify(total)); process.exit(0); });\n\
s.on(\"close\", () => { console.log(\"CLOSE_TOTAL=\",JSON.stringify(total)); process.exit(0); });\n\
s.on(\"error\", (e) => { console.log(\"ERR\",e.code,\"END_TOTAL=\",JSON.stringify(total)); });\n\
setTimeout(() => { console.log(\"TIMEOUT END_TOTAL=\",JSON.stringify(total)); process.exit(2); }, 5000);\n",
                )],
            },
            // Wave 10 Track A: bare blocking read(2) on a node-pty
            // master fd. Diagnoses whether litebox's PTY master is
            // O_NONBLOCK by default (or is otherwise refusing to
            // block on first read). C-level minimal probe — no node
            // event loop, no libuv — so it isolates the kernel-shape
            // bug from any node-side adaptation.
            Scenario {
                id: "nodepty_seq_blocking",
                command: "node /workspace/nodepty_blocking.mjs",
                expected: &["END_TOTAL=", "5\\r\\n"],
                fixtures: &[(
                    "nodepty_blocking.mjs",
                    "import { createRequire } from \"module\";\n\
const require = createRequire(\"/usr/local/lib/node_modules/@github/copilot/index.js\");\n\
const pty = require(\"/usr/local/lib/node_modules/@github/copilot/prebuilds/linux-x64/pty.node\");\n\
import * as fs from \"fs\";\n\
import { execSync } from \"child_process\";\n\
const env = Object.entries(process.env).map(([k,v]) => `${k}=${v}`);\n\
const r = pty.fork(\"/usr/bin/seq\", [\"1\",\"5\"], env, \"/tmp\", 80, 24, -1, -1, true, \"\", (c,s)=>console.log(\"EXIT\",c,s));\n\
console.log(\"PID\",r.pid,\"FD\",r.fd);\n\
try { const fl = execSync(`cat /proc/self/fdinfo/${r.fd} 2>/dev/null || true`).toString(); console.log(\"FDINFO\",fl); } catch(e) {}\n\
const buf = Buffer.alloc(4096);\n\
let total = \"\";\n\
for (let i = 0; i < 50; i++) {\n\
  try {\n\
    const n = fs.readSync(r.fd, buf, 0, 4096, null);\n\
    if (n === 0) { console.log(\"EOF\"); break; }\n\
    total += buf.slice(0,n).toString();\n\
    console.log(\"READ\", n, JSON.stringify(buf.slice(0,n).toString()));\n\
  } catch (e) {\n\
    console.log(\"ERR\", e.code, \"i=\", i);\n\
    if (e.code === \"EAGAIN\") { await new Promise(r=>setTimeout(r,50)); continue; }\n\
    break;\n\
  }\n\
}\n\
console.log(\"END_TOTAL=\", JSON.stringify(total));\n\
process.exit(0);\n",
                )],
            },
            // Goal A validation session 7c1fc95d (2026-06-05) found
            // copilot::tui.* trials hang at startup under litebox:
            // the transcript shows zero output and the kernel still
            // line-discipline-echoes /exit (proving copilot never
            // reached setRawMode). The existing dropbear_bash probes
            // cover node *as a child* of bash; these new probes cover
            // node *as the foreground controlling-tty process*, which
            // is the position copilot occupies via `sh -c "... exec
            // copilot --allow-all"`. They escalate one capability per
            // step so a single FAIL pinpoints the missing primitive.
            Scenario {
                // Minimal node startup as the controlling-tty
                // process. If FAIL: node itself hangs at startup
                // when foreground on a litebox-served PTY (covers
                // module load, libuv init, signalfd setup,
                // io_uring probe). dropbear_bash.node_spawn_bash_*
                // pass because there node is a child of bash, not
                // the controlling-tty leader — different fd shape
                // and different ctty relationship.
                id: "node_pty_stdout_write",
                command: "node -e \"process.stdout.write('NODE_ALIVE\\n')\"",
                expected: &["NODE_ALIVE"],
                fixtures: &[],
            },
            Scenario {
                // Node + isatty on stdout. If FAIL but
                // node_pty_stdout_write PASSES: bug is in
                // isatty(fd)/TIOCGWINSZ probe on the PTY slave.
                id: "node_pty_istty",
                command: "node -e \"process.stdout.write('ISTTY='+process.stdout.isTTY+'\\n')\"",
                expected: &["ISTTY=true"],
                fixtures: &[],
            },
            Scenario {
                // Node + tty.setRawMode (= tcsetattr with TCSANOW
                // disabling ICANON+ECHO+ISIG). If FAIL but
                // node_pty_istty PASSES: setRawMode/tcsetattr on the
                // litebox PTY blocks or errors. This is the exact
                // primitive copilot needs in early TUI init.
                id: "node_pty_setrawmode",
                command: "node -e \"process.stdout.write('BEFORE_RAW\\n');process.stdin.setRawMode(true);process.stdout.write('AFTER_RAW\\n');process.exit(0)\"",
                expected: &["BEFORE_RAW", "AFTER_RAW"],
                fixtures: &[],
            },
            Scenario {
                // copilot --version run as the controlling-tty
                // process. Just prints the version string and exits.
                // No TUI render loop, no auth, no prompt. If FAIL but
                // node_pty_setrawmode PASSES: copilot's own startup
                // (module load / capability detection) hangs even in
                // the trivial --version code path; the bug is inside
                // the copilot bundle, not in node-under-PTY itself.
                // If FAIL identically to node_pty_setrawmode: copilot
                // hits the same primitive node hits — fix one fixes
                // both.
                id: "copilot_version_via_pty",
                command: "copilot --version",
                expected: &["GitHub Copilot CLI"],
                fixtures: &[],
            },
        ]
    }

    pub(super) fn register_trials(trials: &mut Vec<Trial>) {
        for scn in scenarios() {
            for pass in ["native", "litebox"] {
                let name = format!("{pass}::dropbear_bash.{}", scn.id);
                let pass_owned = pass.to_string();
                let scenario_id = scn.id;
                trials.push(Trial::test(name, move || {
                    run_scenario(&pass_owned, scenario_id)
                }));
            }
        }
    }

    fn run_scenario(pass: &str, scenario_id: &str) -> Result<(), Failed> {
        // Build fixtures + ensure prerequisites, then hand off to the
        // shared `framework::run_trial` which owns the entire trial
        // lifecycle: gate acquire, canonical container name, PDEATHSIG
        // pre_exec, cleanup-registry registration, docker spawn +
        // teardown, and `emit_timing_main` recording. The driver
        // closure does the family-specific work: open SSH to the
        // published port (host-side, preserving the docker-bridge →
        // litebox-inbound-TCP test semantics), drive bash, check
        // output. See `tests/common/framework.rs` for the lifecycle.
        let scn = scenarios()
            .iter()
            .find(|s| s.id == scenario_id)
            .expect("scenario lookup");
        let pass_static: &'static str = match pass {
            "native" => "native",
            "litebox" => "litebox",
            _ => "unknown",
        };
        let test_id = format!("dropbear_bash.{scenario_id}");

        let fixture_dir = super::fixture_dir(pass, "dropbear_bash", scenario_id);
        let _ = std::fs::remove_dir_all(&fixture_dir);
        std::fs::create_dir_all(&fixture_dir)
            .map_err(|e| format!("create fixture dir {}: {e}", fixture_dir.display()))?;
        for (rel, content) in scn.fixtures {
            let path = fixture_dir.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
            }
            std::fs::write(&path, content).map_err(|e| format!("write {}: {e}", path.display()))?;
        }
        if pass == "litebox" {
            let _ = super::setup();
        }
        super::ensure_copilot_image(&super::workspace_root());

        let spec = build_dropbear_spec(pass, &fixture_dir, false);
        let expected: Vec<&'static str> = scn.expected.to_vec();
        let command = scn.command;
        let pass_owned = pass.to_string();
        let scenario_id_owned = scenario_id.to_string();

        super::framework::run_trial(
            pass_static,
            &test_id,
            "dropbear_bash",
            "phase_h",
            spec,
            move |container| {
                let t_dispatch = Instant::now();
                let Some(&port) = container.published_ports.get(&22) else {
                    return super::framework::DriveResult {
                        verdict: "FAIL",
                        detail: Some(format!(
                            "container {} did not publish port 22 (ports={:?})",
                            container.name, container.published_ports,
                        )),
                        t_docker_start_ms: 0,
                        t_useful_ms: 0,
                        sub_phases: super::SubPhaseMs::default(),
                        t_docker_spawn_ms: None,
                        t_litebox_init_ms: None,
                        t_harness_load_ms: None,
                    };
                };
                if let Err(e) = copilot::wait_for_sshd(port, Duration::from_secs(30)) {
                    return super::framework::DriveResult {
                        verdict: "FAIL",
                        detail: Some(format!("wait_for_sshd port {port}: {e}")),
                        t_docker_start_ms: t_dispatch.elapsed().as_millis(),
                        t_useful_ms: 0,
                        sub_phases: super::SubPhaseMs::default(),
                        t_docker_spawn_ms: None,
                        t_litebox_init_ms: None,
                        t_harness_load_ms: None,
                    };
                }
                let t_useful_start = Instant::now();
                let t_docker_start_ms = t_useful_start.duration_since(t_dispatch).as_millis();

                let response = match drive_bash(port, command) {
                    Ok(r) => r,
                    Err(e) => {
                        return super::framework::DriveResult {
                            verdict: "FAIL",
                            detail: Some(format!("drive_bash: {e}")),
                            t_docker_start_ms,
                            t_useful_ms: t_useful_start.elapsed().as_millis(),
                            sub_phases: super::SubPhaseMs::default(),
                            t_docker_spawn_ms: None,
                            t_litebox_init_ms: None,
                            t_harness_load_ms: None,
                        };
                    }
                };
                let stripped = copilot::strip_ansi(&response);
                persist_transcript(&pass_owned, &scenario_id_owned, &response, &stripped);
                let t_useful_ms = t_useful_start.elapsed().as_millis();

                let missing: Vec<&str> = expected
                    .iter()
                    .copied()
                    .filter(|exp| !stripped.contains(exp))
                    .collect();
                if !missing.is_empty() {
                    let preview: String = stripped.chars().take(800).collect();
                    let log_path = super::log_dir().join(format!(
                        "dropbear_bash-{pass_owned}-{scenario_id_owned}.stripped.log"
                    ));
                    return super::framework::DriveResult {
                        verdict: "FAIL",
                        detail: Some(format!(
                            "dropbear_bash.{scenario_id_owned} missing expected output {:?}.\n\
                             transcript: {}\n\
                             first 800 chars of ANSI-stripped response:\n{preview}",
                            missing,
                            log_path.display(),
                        )),
                        t_docker_start_ms,
                        t_useful_ms,
                        sub_phases: super::SubPhaseMs::default(),
                        t_docker_spawn_ms: None,
                        t_litebox_init_ms: None,
                        t_harness_load_ms: None,
                    };
                }
                super::framework::DriveResult {
                    verdict: "pass",
                    detail: None,
                    t_docker_start_ms,
                    t_useful_ms,
                    sub_phases: super::SubPhaseMs::default(),
                    t_docker_spawn_ms: None,
                    t_litebox_init_ms: None,
                    t_harness_load_ms: None,
                }
            },
        )
    }

    /// Build the `ContainerSpec` for a dropbear scenario. Mirrors
    /// what `copilot::ContainerHandle::spawn` used to construct, but
    /// returns data instead of spawning — `framework::run_trial`
    /// owns the spawn + lifecycle.
    fn build_dropbear_spec(
        pass: &str,
        fixture_dir: &Path,
        mount_workspace_src: bool,
    ) -> super::framework::ContainerSpec {
        let ws_root = super::workspace_root();
        let bin_dir = super::debug_dir();
        let mut docker_args: Vec<String> = vec![
            "--cap-add".into(),
            "SYS_PTRACE".into(),
            "-p".into(),
            "127.0.0.1:0:22".into(),
            "-v".into(),
            format!("{}:/opt/litebox:ro", bin_dir.display()),
            "-v".into(),
            format!("{}:/workspace", fixture_dir.display()),
        ];
        for var in [
            "LITEBOX_EAGER_BROKER_SOCKETPAIR",
            "LITEBOX_EAGER_BROKER_SOCKETSEQPACKET",
            "LITEBOX_BROKER_TCP_CONN",
            "LITEBOX_PE10_DIAG",
            "LITEBOX_PE5_DIAG",
            "LITEBOX_CLEANUP_DELAY_MS",
            "RUST_LOG",
            "RUST_BACKTRACE",
        ] {
            if let Ok(val) = std::env::var(var) {
                docker_args.push("-e".into());
                docker_args.push(format!("{var}={val}"));
            }
        }
        if mount_workspace_src {
            docker_args.push("-v".into());
            docker_args.push(format!("{}:/workspace/litebox-src:ro", ws_root.display()));
        }
        let command: Vec<String> = match pass {
            "native" => vec![
                "/usr/sbin/dropbear".into(),
                "-F".into(),
                "-E".into(),
                "-B".into(),
                "-R".into(),
                "-p".into(),
                "22".into(),
            ],
            "litebox" => vec![
                "/opt/litebox/litebox_tool_executor".into(),
                "--rootfs".into(),
                "/".into(),
                "--record-baseline".into(),
                "--ssh".into(),
                "--ssh-port".into(),
                "22".into(),
            ],
            _ => panic!("unknown pass {pass}"),
        };
        super::framework::ContainerSpec {
            image: super::copilot_image_tag(),
            docker_args,
            command,
            detached: true,
            timeout_secs: None,
        }
    }

    fn drive_bash(port: u16, command: &str) -> Result<String, String> {
        let first = drive_bash_once(port, command)?;
        if first.contains("kex_exchange_identification") {
            std::thread::sleep(Duration::from_secs(7));
            return drive_bash_once(port, command);
        }
        Ok(first)
    }

    fn drive_bash_once(port: u16, command: &str) -> Result<String, String> {
        let pty = Pty::open()?;
        let mut argv = copilot::ssh_argv_base(port);
        argv.push(format!("exec bash -c {}", copilot::shell_quote(command)));
        let pid = pty.fork_exec(&argv, /* ctrl_tty = */ true)?;
        let result = copilot::read_with_deadline(&pty, Duration::from_secs(20))?;
        let _ = copilot::wait_pid(pid, Duration::from_secs(10));
        Ok(result)
    }

    fn persist_transcript(pass: &str, scenario_id: &str, raw: &str, stripped: &str) {
        let log_dir = super::log_dir();
        let _ = std::fs::create_dir_all(log_dir);
        let safe = format!("dropbear_bash-{pass}-{scenario_id}");
        let _ = std::fs::write(log_dir.join(format!("{safe}.raw.log")), raw);
        let _ = std::fs::write(log_dir.join(format!("{safe}.stripped.log")), stripped);
    }
}

/// Image name (base) for the Copilot CLI rootfs. The actual tag
/// used at build/run time goes through `image_tag::image_tag()`
/// so concurrent worktrees don't clobber each other.
fn copilot_image_base() -> &'static str {
    "litebox-agent-cli"
}

/// Per-worktree resolved tag.
fn copilot_image_tag() -> String {
    image_tag::image_tag(copilot_image_base())
}

/// Per-trial fixture directory.
fn fixture_dir(pass: &str, mode: &str, scenario_id: &str) -> PathBuf {
    target_dir()
        .join("copilot-fixtures")
        .join(format!("{pass}-{mode}-{scenario_id}"))
}

/// Write `COPILOT_GITHUB_TOKEN=<tok>` (plus the same value as
/// `GH_TOKEN` and `GITHUB_TOKEN` so any Copilot-CLI variant finds
/// it) to `path` with mode 0600. The token never appears in any
/// command-line argv.
fn write_token_env(path: &Path, tok: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir env parent: {e}"))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("open env file {}: {e}", path.display()))?;
    writeln!(f, "COPILOT_GITHUB_TOKEN={tok}").map_err(|e| format!("write env: {e}"))?;
    writeln!(f, "GH_TOKEN={tok}").map_err(|e| format!("write env: {e}"))?;
    writeln!(f, "GITHUB_TOKEN={tok}").map_err(|e| format!("write env: {e}"))?;
    writeln!(f, "COPILOT_AUTO_UPDATE=false").map_err(|e| format!("write env: {e}"))?;
    Ok(())
}

/// Build the `litebox-agent-cli` Docker image if missing. Called
/// only when Copilot trials are being registered.
fn ensure_copilot_image(ws_root: &Path) {
    let tag = copilot_image_tag();
    let check = Command::new("docker")
        .args(["image", "inspect", &tag])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if matches!(check, Ok(s) if s.success()) {
        return;
    }
    eprintln!("Building {tag} Docker image...");
    let dockerfile = ws_root.join("litebox_tool_executor/rootfs/Dockerfile");
    let status = Command::new("docker")
        .args(["build", "--target", copilot_image_base(), "-t", &tag, "-f"])
        .arg(&dockerfile)
        .arg(ws_root)
        .status()
        .expect("docker build litebox-agent-cli");
    assert!(status.success(), "docker build {tag} failed",);
}
