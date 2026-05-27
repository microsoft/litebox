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
// Each test produces JSONL lines in `target/test-logs/per-test-timing.jsonl`:
//   * One synchronous line emitted from run_one_test once the JSON
//     result is observed: includes t_acquire_ms / t_docker_start_ms /
//     t_useful_ms / verdict. Always present, even if drain gets cut.
//   * One optional drain line emitted from spawn_drain when the
//     container actually exits: `{test, pass, t_drain_ms}`. Joined
//     to the main line by (test, pass) in the analyzer. May be missing
//     if cargo-test exits before the drain thread completes.
//
// Used to verify that subsequent perf optimizations (cgroup limits,
// docker overhead trims, timeout budgets) actually help. See plan in
// `~/.copilot/session-state/.../plan.md`.

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

fn timing_file() -> &'static Mutex<std::fs::File> {
    static FILE: std::sync::OnceLock<Mutex<std::fs::File>> = std::sync::OnceLock::new();
    FILE.get_or_init(|| {
        let path = log_dir().join("per-test-timing.jsonl");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
        Mutex::new(f)
    })
}

fn emit_timing_main(
    test: &str,
    pass: &str,
    t_acquire_ms: u128,
    t_docker_start_ms: u128,
    t_docker_spawn_ms: Option<u128>,
    t_litebox_init_ms: Option<u128>,
    t_harness_load_ms: Option<u128>,
    sub_phases: &SubPhaseMs,
    t_useful_ms: u128,
    verdict: &str,
    jobs: usize,
) {
    use std::io::Write as _;
    let mut line = format!(
        "{{\"test\":\"{test}\",\"pass\":\"{pass}\",\
         \"t_acquire_ms\":{t_acquire_ms},\"t_docker_start_ms\":{t_docker_start_ms}",
    );
    if let Some(v) = t_docker_spawn_ms {
        line.push_str(&format!(",\"t_docker_spawn_ms\":{v}"));
    }
    if let Some(v) = t_litebox_init_ms {
        line.push_str(&format!(",\"t_litebox_init_ms\":{v}"));
    }
    if let Some(v) = t_harness_load_ms {
        line.push_str(&format!(",\"t_harness_load_ms\":{v}"));
    }
    // Phase A sub-phase split. Each is the delta between adjacent
    // markers in `litebox_timing`'s file channel; cumulative should
    // sum to `t_litebox_init_ms`/`t_harness_load_ms` (within rounding).
    // See `SubPhaseMs::compute` for the full marker order.
    for (key, value) in sub_phases.fields() {
        if let Some(v) = value {
            line.push_str(&format!(",\"{key}\":{v}"));
        }
    }
    line.push_str(&format!(
        ",\"t_useful_ms\":{t_useful_ms},\"verdict\":\"{verdict}\",\"jobs\":{jobs}}}\n"
    ));
    if let Ok(mut f) = timing_file().lock() {
        let _ = f.write_all(line.as_bytes());
    }
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
    use std::io::Write as _;
    let line = format!("{{\"test\":\"{test}\",\"pass\":\"{pass}\",\"t_drain_ms\":{t_drain_ms}}}\n");
    if let Ok(mut f) = timing_file().lock() {
        let _ = f.write_all(line.as_bytes());
    }
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
static TEST_METADATA: std::sync::OnceLock<Vec<(String, u64)>> = std::sync::OnceLock::new();

fn get_test_metadata() -> &'static Vec<(String, u64)> {
    TEST_METADATA.get_or_init(|| {
        let tests = litebox_test_harness::coordinator::collect_all_tests();
        let meta: Vec<(String, u64)> = tests.into_iter().map(|t| (t.id, t.timeout_secs)).collect();
        eprintln!(
            "[integration] {} test IDs from collect_all_tests",
            meta.len()
        );
        meta
    })
}

fn get_test_ids() -> Vec<String> {
    get_test_metadata()
        .iter()
        .map(|(id, _)| id.clone())
        .collect()
}

/// Lookup the harness-declared per-test timeout (the `.timeout(N)` value
/// the coordinator enforces). Returns 60s as a defensive fallback if
/// the test ID isn't in the registry (shouldn't happen).
fn test_timeout_secs(test_id: &str) -> u64 {
    get_test_metadata()
        .iter()
        .find(|(id, _)| id == test_id)
        .map(|(_, t)| *t)
        .unwrap_or(60)
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
        "LITEBOX_BROKER_TCP_CONN",
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

static ACTIVE_JOBS: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();
static DRAIN_BACKLOG: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();

static JOBS_CAP: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

fn default_jobs() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    // Roughly num_cpus / 1.5, clamped to a reasonable range. Past
    // jobs=10 dockerd serializes container creation badly enough that
    // further parallelism gives diminishing returns (verified by
    // phase-2 measurement: jobs=5→10 cut wall by ~9% on PB.* family).
    ((cpus as f32 / 1.5) as usize).clamp(2, 10)
}

fn current_jobs_cap() -> usize {
    *JOBS_CAP.get_or_init(|| {
        std::env::var("LITEBOX_TEST_JOBS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(default_jobs)
    })
}

fn active_jobs() -> &'static Semaphore {
    ACTIVE_JOBS.get_or_init(|| {
        let n = current_jobs_cap();
        eprintln!("[integration] LITEBOX_TEST_JOBS={n}");
        Semaphore::new(n)
    })
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

/// Best-effort sanitize a test id into a docker container name suffix.
fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn test_container_suffix(test_id: &str) -> &'static str {
    if test_id.starts_with("IOR.") {
        "-ior"
    } else if test_id.starts_with("RAND.") {
        "-rand"
    } else if test_id.starts_with("CL3.vfork.") {
        "-cl3v"
    } else if test_id.starts_with("INO.") {
        "-ino"
    } else if test_id.starts_with("SCM.") {
        "-scm"
    } else {
        ""
    }
}

/// Build the docker command for a single-test run. We pass `--name`
/// so the container is identifiable in `docker ps` and so
/// `LITEBOX_KEEP_CONTAINER` users can find it after the test
/// finishes; the orchestrator never force-kills it externally.
fn build_docker_cmd(
    pass: &str,
    test_id: &str,
    container_name: &str,
    bins: &BinaryPaths,
) -> Command {
    let filter = format!("--filter={test_id}");
    let mut cmd = Command::new("docker");
    cmd.args(docker_run_base_args())
        .arg("--name")
        .arg(container_name);
    if test_id.starts_with("IOR.") {
        // Docker's default seccomp profile blocks io_uring_setup with EPERM,
        // hiding the WSL2/native kernel baseline this family is meant to test.
        cmd.args(["--security-opt", "seccomp=unconfined"]);
    }
    // Each binary-type leg is mounted at `/opt/<label>/` so the
    // corresponding `find_*_binary()` helpers in lib.rs find them.
    cmd.arg("-v")
        .arg(format!("{}:/opt/litebox:ro", bins.pie_glibc.display()))
        .arg("-v")
        .arg(format!("{}:/opt/nonpie:ro", bins.nonpie_glibc.display()))
        .arg("-v")
        .arg(format!(
            "{}:/opt/static-pie-glibc:ro",
            bins.static_pie_glibc.display()
        ))
        .arg("-v")
        .arg(format!(
            "{}:/opt/static-pie-musl:ro",
            bins.static_pie_musl.display()
        ))
        .arg("-v")
        .arg(format!(
            "{}:/opt/non-pie-static-musl:ro",
            bins.non_pie_static_musl.display()
        ));
    // For litebox pass, no additional mounts are needed for the
    // harness binaries — pre-rewriting is amortised in the broker's
    // persistent ELF cache (LITEBOX_BROKER_ELF_CACHE_DIR) which
    // setup() pre-populates from rewrites of all 5 variants. The
    // broker hits the disk cache on first 9P read and never invokes
    // the rewriter at runtime. Native pass gets the original
    // (unmodified) binaries via the directory bind mounts above.
    cmd.arg("-v")
        // Bind-mount the host test-logs/ directory into the container so
        // all in-container processes (tool_executor, broker, runner, the
        // in-guest harness) can append timing markers via
        // `litebox_timing::emit` to a per-trial file. WSL2 + Docker
        // returns EACCES on a single-file bind-mount even when the
        // container runs as root, so we bind-mount the directory and
        // each component opens the per-trial file name.
        .arg(format!("{}:/litebox-test-logs", log_dir().display()))
        .args([
            "-e",
            &format!(
                "LITEBOX_TIMING_PATH=/litebox-test-logs/{}",
                timing_log_path_for(pass, test_id)
                    .file_name()
                    .expect("timing_log_path_for has file name")
                    .to_string_lossy(),
            ),
        ])
        // Bind-mount a persistent host directory for the broker's
        // pre-warmed ELF cache. Without this, each test pays
        // ~400ms in pre_warm_elf_cache for libc/ld-linux/libstdc++/etc.
        // because the broker is per-container and its in-memory
        // cache is cold on every spawn.
        .arg("-v")
        .arg(format!(
            "{}:/litebox-broker-elf-cache",
            broker_elf_cache_dir().display()
        ))
        .args([
            "-e",
            "LITEBOX_BROKER_ELF_CACHE_DIR=/litebox-broker-elf-cache",
        ]);
    if pass == "native" {
        cmd.args(["-e", "LITEBOX_TIMING_CONTAINER_PID1=1"]);
    }
    cmd.arg("litebox-test");
    match pass {
        "native" => {
            cmd.arg("/opt/litebox/litebox_test_harness")
                .arg("spawn-tree")
                .arg(&filter);
        }
        "litebox" => {
            // Outer timeout = per-test harness budget + 15 s grace
            // for teardown_tree (5 s cap) and container shutdown.
            // Replaces the previous blanket 120 s, which made
            // failing fast-tests cost 120 s each.
            let outer = test_timeout_secs(test_id).saturating_add(15);
            let outer_str = outer.to_string();
            cmd.args(["timeout", "--signal=KILL"])
                .arg(&outer_str)
                .args([
                    "/opt/litebox/litebox_tool_executor",
                    "--rootfs",
                    "/",
                    "--record-baseline",
                    "--",
                    "/opt/litebox/litebox_test_harness",
                    "spawn-tree",
                ])
                .arg(&filter);
        }
        _ => panic!("unknown pass: {pass}"),
    }
    cmd
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

/// Run one test and return its JSON result. Holds an `active_jobs`
/// Run one test and return its JSON result. Holds an `active_jobs`
/// permit for the duration of the result-bearing phase, then hands
/// the still-running child off to a background drain thread that
/// holds a `drain_backlog` permit until the container exits.
///
/// Per-Trial logs (`target/test-logs/<pass>-<id>.{stdout,stderr}.log`)
/// are written via the OS:
///   * stderr — `Stdio::from(File::create(...))` so the docker
///     daemon writes straight to disk; no in-process forwarding.
///   * stdout — we still parse line by line for the JSON result,
///     but each line is written to the stdout log file as it
///     arrives.
///
/// Both files are populated synchronously while we still hold the
/// `active_jobs` permit, so they're durable even if cargo-test exits
/// the moment we return — no need for a drain-side join hook.
fn run_one_test(pass: &str, test_id: &str) -> Result<serde_json::Value, Failed> {
    use std::io::Write as _;
    let t_start = Instant::now();
    let permit = active_jobs().acquire();
    let t_acquired = Instant::now();
    let t_acquire_ms = t_acquired.duration_since(t_start).as_millis();
    let (_, bins) = setup();
    let container_name = format!(
        "litebox-{}-{}{}-{}-{}",
        pass,
        sanitize_id(test_id),
        test_container_suffix(test_id),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    );

    let stdout_log = log_path_for(pass, test_id, "stdout");
    let stderr_log = log_path_for(pass, test_id, "stderr");
    let timing_log = timing_log_path_for(pass, test_id);
    ensure_timing_log_file(&timing_log);

    let mut cmd = build_docker_cmd(pass, test_id, &container_name, &bins);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let label = format!("{pass}[{test_id}]");
    let t_spawn = Instant::now();
    let docker_run_invoke_ns = monotonic_nanos();
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("docker spawn failed for {label}: {e}"));

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

    // Read stdout line by line; tee each line to the stdout log
    // file, and record the first JSON line whose "test" field
    // matches our test_id.
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
            // Don't break — keep tee'ing later lines into
            // the log so post-result harness output (e.g.
            // teardown_tree messages) is captured for
            // forensics. The drain thread takes over when
            // we return and finishes draining the rest.
            break;
        }
    }
    let t_json = Instant::now();
    let t_json_ns = monotonic_nanos();

    let t_first_byte = t_first_byte.unwrap_or(t_json);
    // Markers come from two sources:
    //   * The bind-mounted timing-log file: tool_executor + broker +
    //     runner + in-guest harness append `name=ns\n` via
    //     `litebox_timing::emit`. All on host CLOCK_MONOTONIC EXCEPT
    //     the in-guest harness in litebox pass, whose clock is
    //     virtualized.
    //   * The stderr `[TIMING] harness_first_output_ns=` proxy line
    //     from the harness — used as a host-side arrival_ns boundary
    //     for `harness_first_output_ns` in litebox pass (where the
    //     guest's CLOCK_MONOTONIC value is not comparable to the
    //     host-side markers).
    // We pre-populate from the file first (all init markers are
    // flushed by the time the JSON result line arrives on stdout),
    // then merge the stderr snapshot — `record_timing_marker` is
    // first-wins so the stderr arrival_ns proxy overrides the
    // file's virtual-clock value when both are present.
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
    // Runtime-rewrite assertion: every binary the test loaded should
    // have been pre-populated in the broker ELF cache (harness
    // variants from setup(), shared libraries from
    // pre_warm_elf_cache). A non-empty list means some binary was
    // rewritten in-band, which costs ~hundreds of ms per file —
    // worth surfacing as a perf bug to investigate, not silently
    // tolerating. Override with `LITEBOX_ALLOW_RUNTIME_REWRITES=1`
    // for one-off debugging.
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
    let pass_static: &'static str = match pass {
        "native" => "native",
        "litebox" => "litebox",
        _ => "unknown",
    };
    let jobs = current_jobs_cap();

    let sub_phases = SubPhaseMs::compute(&markers);

    // Emit the main timing line synchronously (drain may get cut off
    // if cargo-test exits early).
    emit_timing_main(
        test_id,
        pass_static,
        t_acquire_ms,
        t_docker_start_ms,
        t_docker_spawn_ms,
        t_litebox_init_ms,
        t_harness_load_ms,
        &sub_phases,
        t_useful_ms,
        verdict,
        jobs,
    );

    // Hand off the still-running child to a drain worker. It just
    // waits for clean exit so we bound zombies / per-host docker
    // population. Logs are already on disk (stderr via Stdio::from,
    // stdout via the tee above). The drain thread emits its own
    // t_drain_ms line when wait() returns.
    spawn_drain(
        child,
        container_name.clone(),
        test_id.to_string(),
        pass_static,
        t_json,
    );
    drop(permit);

    found.ok_or_else(|| {
        format!(
            "{label}: no JSON result for {test_id} on stdout (full log: {})",
            stdout_log.display(),
        )
        .into()
    })
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
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let watchdog = std::thread::spawn(move || {
            if rx.recv_timeout(timeout).is_ok() {
                return;
            }
            eprintln!(
                "[drain] timeout after {} s; forcing teardown of {cname}",
                timeout.as_secs()
            );
            let _ = Command::new("docker")
                .args(["rm", "-f", &cname])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
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
    let argv: Vec<String> = std::env::args().collect();
    let pos_idx = collect_positionals(&argv);

    // Extract the positional strings, then strip all but the first
    // from the argv we hand to libtest-mimic (so its single-positional
    // parser doesn't error). We'll apply OR-filtering ourselves below.
    let positionals: Vec<String> = pos_idx.iter().map(|&i| argv[i].clone()).collect();
    let args = if positionals.len() >= 2 {
        let drop: std::collections::HashSet<usize> = pos_idx.iter().skip(1).copied().collect();
        let trimmed: Vec<String> = argv
            .iter()
            .enumerate()
            .filter(|(i, _)| !drop.contains(i))
            .map(|(_, s)| s.clone())
            .collect();
        Arguments::from_iter(trimmed)
    } else {
        Arguments::from_args()
    };

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

    // Copilot CLI integration scenarios — only register when explicitly
    // requested via filter or env. See `mod copilot` below for the full
    // contract and the documented FAIL-today scenarios.
    if copilot::requested(&positionals) {
        // Run the canonical setup() too: copilot tests bind-mount
        // /opt/litebox/litebox_tool_executor into the litebox-pass
        // container, so all 5 binary-type debug builds must exist.
        let _ = setup();
        let ws_root = workspace_root();
        ensure_copilot_image(&ws_root);
        copilot::register_trials(&mut trials);
    }

    // OR-of-positionals prefilter. When two or more positional filters
    // were given, we already stripped the extras from libtest-mimic's
    // argv; here we drop trials that don't match ANY positional and
    // null out `args.filter` so libtest-mimic doesn't double-filter
    // with just the first positional.
    let args = if positionals.len() >= 2 {
        let exact = args.exact;
        trials.retain(|t| {
            let name = t.name();
            positionals
                .iter()
                .any(|p| if exact { name == p } else { name.contains(p) })
        });
        Arguments {
            filter: None,
            ..args
        }
    } else {
        args
    };

    libtest_mimic::run(&args, trials).exit();
}

// ── Per-Trial runner ─────────────────────────────────────────────────

/// Run one Trial: spawn its own `docker run` with `--filter=<test_id>`,
/// read the JSON result, return pass/fail.
fn run_pass_group(pass: &str, test_id: &str) -> Result<(), Failed> {
    let result = run_one_test(pass, test_id)?;
    let outcome = result["result"].as_str().unwrap_or("?");
    if outcome == "FAIL" {
        let detail = result["detail"].as_str().unwrap_or("");
        let stdout_log = log_path_for(pass, test_id, "stdout");
        let stderr_log = log_path_for(pass, test_id, "stderr");
        return Err(format!(
            "{pass}::{test_id}: {detail} (logs: {} {})",
            stdout_log.display(),
            stderr_log.display(),
        )
        .into());
    }
    Ok(())
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
    eprintln!("Building litebox-test Docker image...");
    let dockerfile = ws_root.join("litebox_tool_executor/rootfs/Dockerfile");
    assert!(
        dockerfile.exists(),
        "Dockerfile not found at {}",
        dockerfile.display()
    );
    let status = Command::new("docker")
        .args([
            "build",
            "--target",
            "litebox-test",
            "-t",
            "litebox-test",
            "-f",
        ])
        .arg(&dockerfile)
        .arg(ws_root)
        .status()
        .expect("docker build");
    assert!(status.success(), "Docker build failed");
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
        .arg("litebox-test")
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
// Conditional registration: only registers when a positional filter
// contains `copilot::` or `LITEBOX_INCLUDE_COPILOT=1` is set, so the
// canonical full-suite `cargo test -p litebox_test_harness --test
// integration` runs are unaffected.
//
// Concurrency cap `LITEBOX_COPILOT_JOBS` (default 1) bounds
// concurrent Copilot trials independently of `LITEBOX_TEST_JOBS`.
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

    /// Decision: should this `cargo test` invocation register the
    /// Copilot Trials? Reads the env knob and scans the positional
    /// filters (passed in from main()).
    pub(super) fn requested(positionals: &[String]) -> bool {
        if std::env::var_os("LITEBOX_INCLUDE_COPILOT").is_some() {
            return true;
        }
        positionals.iter().any(|p| p.contains("copilot::"))
    }

    /// Concurrency cap. Independent of `LITEBOX_TEST_JOBS` — the
    /// Copilot scenarios call the GitHub API, so default to serial.
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

    /// Token cached once per test process. Discovered up front when
    /// Copilot trials are registered, so any failure surfaces before
    /// libtest-mimic starts scheduling trials.
    fn token() -> &'static str {
        static TOKEN: OnceLock<String> = OnceLock::new();
        TOKEN.get_or_init(|| {
            discover_token().unwrap_or_else(|e| panic!("copilot token preflight: {e}"))
        })
    }

    /// One scenario: prompt template (canary → prompt text), how to
    /// check the response against the canary, and per-trial timeout.
    struct Scenario {
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

    /// The 6 scenarios. Same workloads in both invocation modes.
    fn scenarios() -> &'static [Scenario] {
        &[
            Scenario {
                id: "simple_math",
                prompt: |_| "What is 2 plus 2? Reply with just the number.".to_string(),
                check: simple_math_check,
                timeout_secs: 60,
                fixtures: &[],
            },
            Scenario {
                id: "simple_bash",
                prompt: |c| {
                    format!("Run the shell command `echo {c}` and tell me exactly what it printed.")
                },
                check: simple_bash_check,
                timeout_secs: 90,
                fixtures: &[],
            },
            Scenario {
                id: "read_file",
                prompt: |_| {
                    "Run `cat /workspace/canary.txt` and tell me the entire contents of \
                     the file, including the line that starts with `CN-`."
                        .to_string()
                },
                check: default_check, // canary in fixture, not in prompt
                timeout_secs: 90,
                fixtures: &[("canary.txt", "__CANARY_PLACEHOLDER__\n")],
            },
            Scenario {
                id: "pipeline_wc",
                prompt: |_| {
                    "Run `wc -c /workspace/a.txt /workspace/b.txt` and tell me which file \
                     has more bytes."
                        .to_string()
                },
                check: pipeline_wc_check,
                timeout_secs: 120,
                fixtures: &[
                    ("a.txt", "aaa\n"),                      // 4 bytes
                    ("b.txt", "bbbbbbbbbbbbbbbbbbbbbbbb\n"), // 25 bytes
                ],
            },
            Scenario {
                id: "find_head",
                prompt: |_| {
                    "Run `find /workspace -name '*.txt' | head -5` and list the filenames \
                     you find."
                        .to_string()
                },
                check: find_head_check,
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
            Scenario {
                id: "build",
                prompt: |_| {
                    "Run `CARGO_TARGET_DIR=/tmp/copilot-build cargo build -p litebox_timing` \
                     inside /workspace/litebox-src and report whether it succeeded or what \
                     compile errors it reported."
                        .to_string()
                },
                check: build_check,
                timeout_secs: 300,
                fixtures: &[],
            },
        ]
    }

    /// Register all Copilot Trials (24 = 6 scenarios × 2 modes × 2 passes).
    /// Called from `main()` only when `requested()` returned true.
    pub(super) fn register_trials(trials: &mut Vec<Trial>) {
        // Eagerly run the token preflight so failure surfaces before
        // any Trial begins.
        let _ = token();

        for scn in scenarios() {
            for mode in ["pminus", "tui"] {
                for pass in ["native", "litebox"] {
                    let id = format!("copilot::{mode}.{}", scn.id);
                    let name = format!("{pass}::{id}");
                    let scn_id = scn.id;
                    let mode_owned = mode.to_string();
                    let pass_owned = pass.to_string();
                    trials.push(Trial::test(name, move || {
                        run_scenario(&pass_owned, &mode_owned, scn_id)
                    }));
                }
            }
        }
    }

    fn run_scenario(pass: &str, mode: &str, scenario_id: &str) -> Result<(), Failed> {
        let _permit = CopilotPermit::acquire();
        let scn = scenarios()
            .iter()
            .find(|s| s.id == scenario_id)
            .expect("scenario lookup");

        // Per-trial canary: marker the model is asked to surface verbatim.
        let canary = format!(
            "CN-{}-{}-{}-{}",
            scenario_id,
            mode,
            pass,
            std::process::id()
        );

        // Fixture tree.
        let fixture_dir = super::fixture_dir(pass, mode, scenario_id);
        let _ = std::fs::remove_dir_all(&fixture_dir);
        std::fs::create_dir_all(&fixture_dir)
            .map_err(|e| format!("create fixture dir {}: {e}", fixture_dir.display()))?;
        for (rel, content) in scn.fixtures {
            let body = content.replace("__CANARY_PLACEHOLDER__", &canary);
            let path = fixture_dir.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
            }
            std::fs::write(&path, body).map_err(|e| format!("write {}: {e}", path.display()))?;
        }
        // For `build`, the workspace itself needs to be visible inside
        // the container. Symlinks won't work (target path doesn't
        // exist inside container). Bind-mount the host workspace at
        // /workspace/litebox-src via an extra `-v` flag in the
        // container spawn. The flag is added at ContainerHandle::spawn
        // time based on scenario_id.
        // Token env file inside the bind-mounted workspace. Mode 0600.
        // dropbear strips env vars from session children (only PATH /
        // HOME / SHELL / USER / LOGNAME / MAIL survive), so we can't
        // rely on `docker run --env-file` reaching copilot. The remote
        // command sources this file before exec'ing copilot.
        let token_env_path = fixture_dir.join(".copilot-env");
        super::write_token_env(&token_env_path, token())?;

        // Spawn container.
        let container =
            ContainerHandle::spawn(pass, scenario_id, mode, &fixture_dir, scn.id == "build")?;
        let port = container.ssh_port;

        // Wait for sshd to listen.
        wait_for_sshd(port, Duration::from_secs(30))?;

        // Build the response by running the appropriate mode.
        let prompt_text = (scn.prompt)(&canary);
        let response = match mode {
            "pminus" => drive_pminus(port, &prompt_text, scn.timeout_secs)?,
            "tui" => drive_tui(port, &prompt_text, scn.timeout_secs)?,
            _ => return Err(format!("unknown mode {mode}").into()),
        };

        // Persist the raw + ANSI-stripped transcript for forensics.
        // Path mirrors test-logs convention so debuggers know where
        // to look.
        let log_dir = super::log_dir();
        let _ = std::fs::create_dir_all(&log_dir);
        let safe = format!("copilot-{pass}-{mode}-{scenario_id}");
        let _ = std::fs::write(log_dir.join(format!("{safe}.raw.log")), &response);
        let _ = std::fs::write(
            log_dir.join(format!("{safe}.stripped.log")),
            strip_ansi(&response),
        );
        let _ = std::fs::write(
            log_dir.join(format!("{safe}.prompt.txt")),
            format!("canary={canary}\n\n--- prompt ---\n{prompt_text}\n"),
        );

        // Verdict.
        let ok = (scn.check)(&canary, &response);
        if !ok {
            let preview: String = strip_ansi(&response).chars().take(800).collect();
            return Err(format!(
                "{pass}::copilot::{mode}.{scenario_id} \
                 canary check failed.\n\
                 canary={canary}\n\
                 transcript: {}\n\
                 first 800 chars of response (ANSI-stripped):\n{preview}",
                log_dir.join(format!("{safe}.stripped.log")).display(),
            )
            .into());
        }
        Ok(())
    }

    /// Owned container that destroys itself on Drop.
    pub(super) struct ContainerHandle {
        name: String,
        pub(super) ssh_port: u16,
    }

    impl ContainerHandle {
        pub(super) fn spawn(
            pass: &str,
            scenario_id: &str,
            mode: &str,
            fixture_dir: &Path,
            mount_workspace_src: bool,
        ) -> Result<Self, String> {
            let ws_root = super::workspace_root();
            let bin_dir = super::debug_dir();
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let name = format!("litebox-copilot-{pass}-{mode}-{scenario_id}-{pid}-{nanos}");

            // CMD per pass.
            let mut cmd = Command::new("docker");
            cmd.args(["run", "-d", "--rm"])
                .args(["--name", &name])
                .args(["--cap-add", "SYS_PTRACE"])
                .args(["-p", "127.0.0.1:0:22"])
                .arg("-v")
                .arg(format!("{}:/opt/litebox:ro", bin_dir.display()))
                .arg("-v")
                .arg(format!("{}:/workspace", fixture_dir.display()));
            if mount_workspace_src {
                cmd.arg("-v")
                    .arg(format!("{}:/workspace/litebox-src:ro", ws_root.display()));
            }
            cmd.arg(super::copilot_image_name());
            match pass {
                "native" => {
                    cmd.args(["/usr/sbin/dropbear", "-F", "-E", "-B", "-R", "-p", "22"]);
                }
                "litebox" => {
                    // Use `--ssh` (no `--ssh-command`) so litebox sets
                    // up the host:22 → sandbox:22 port forward AND lets
                    // the ssh client choose the per-session remote
                    // command. `--record-baseline` is the unconstrained
                    // audit-only mode (no policy file) — this iteration
                    // is about validating Copilot under litebox, not
                    // policy enforcement.
                    cmd.args([
                        "/opt/litebox/litebox_tool_executor",
                        "--rootfs",
                        "/",
                        "--record-baseline",
                        "--ssh",
                        "--ssh-port",
                        "22",
                    ]);
                }
                _ => return Err(format!("unknown pass {pass}")),
            }
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            let out = cmd.output().map_err(|e| format!("docker run spawn: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "docker run failed (exit {}): {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr)
                ));
            }

            // Find the host port mapped to container port 22.
            let port_out = Command::new("docker")
                .args(["port", &name, "22"])
                .output()
                .map_err(|e| format!("docker port: {e}"))?;
            if !port_out.status.success() {
                let _ = Command::new("docker").args(["rm", "-f", &name]).output();
                return Err(format!(
                    "docker port {name} 22 failed: {}",
                    String::from_utf8_lossy(&port_out.stderr)
                ));
            }
            let mapping = String::from_utf8_lossy(&port_out.stdout);
            let port = mapping
                .lines()
                .find_map(|l| {
                    l.rsplit(':')
                        .next()
                        .and_then(|p| p.trim().parse::<u16>().ok())
                })
                .ok_or_else(|| format!("could not parse host port from `{mapping}`"))?;

            Ok(ContainerHandle {
                name,
                ssh_port: port,
            })
        }
    }

    impl Drop for ContainerHandle {
        fn drop(&mut self) {
            let _ = Command::new("docker")
                .args(["rm", "-f", &self.name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
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
        let pty = Pty::open()?;
        let mut argv = ssh_argv_base(port);
        argv.push(
            "set -a; . /workspace/.copilot-env; set +a; exec copilot --allow-all".to_string(),
        );
        let pid = pty.fork_exec(&argv, /* ctrl_tty = */ true)?;
        // Wait for the first quiet window (the TUI has rendered its prompt).
        let _initial = read_until_idle(&pty, Duration::from_secs(20), Duration::from_millis(1200))?;
        // Send the prompt.
        pty.write_all(prompt.as_bytes())?;
        pty.write_all(b"\n")?;
        // Read the response (longer idle window for model latency).
        let response = read_until_idle(
            &pty,
            Duration::from_secs(timeout_secs),
            Duration::from_millis(2500),
        )?;
        // Best-effort clean exit.
        let _ = pty.write_all(b"/exit\n");
        let _ = read_with_deadline(&pty, Duration::from_secs(5));
        let _ = wait_pid(pid, Duration::from_secs(5));
        Ok(response)
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

mod dropbear_bash {
    use super::{Failed, Trial, copilot};
    use litebox_test_harness::os::pty::Pty;
    use std::time::Duration;

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
        let scn = scenarios()
            .iter()
            .find(|s| s.id == scenario_id)
            .expect("scenario lookup");

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
        let container = copilot::ContainerHandle::spawn(
            pass,
            scenario_id,
            "dropbear_bash",
            &fixture_dir,
            false,
        )?;
        let port = container.ssh_port;
        copilot::wait_for_sshd(port, Duration::from_secs(30))?;

        let response = drive_bash(port, scn.command)?;
        let stripped = copilot::strip_ansi(&response);
        persist_transcript(pass, scenario_id, &response, &stripped);

        let missing: Vec<&str> = scn
            .expected
            .iter()
            .copied()
            .filter(|expected| !stripped.contains(expected))
            .collect();
        if !missing.is_empty() {
            let preview: String = stripped.chars().take(800).collect();
            return Err(format!(
                "{pass}::dropbear_bash.{scenario_id} missing expected output {:?}.\n\
                 transcript: {}\n\
                 first 800 chars of ANSI-stripped response:\n{preview}",
                missing,
                super::log_dir()
                    .join(format!("dropbear_bash-{pass}-{scenario_id}.stripped.log"))
                    .display(),
            )
            .into());
        }

        Ok(())
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

/// Image name for the Copilot CLI rootfs.
fn copilot_image_name() -> &'static str {
    "litebox-agent-cli"
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
    let check = Command::new("docker")
        .args(["image", "inspect", copilot_image_name()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if matches!(check, Ok(s) if s.success()) {
        return;
    }
    eprintln!("Building {} Docker image...", copilot_image_name());
    let dockerfile = ws_root.join("litebox_tool_executor/rootfs/Dockerfile");
    let status = Command::new("docker")
        .args([
            "build",
            "--target",
            copilot_image_name(),
            "-t",
            copilot_image_name(),
            "-f",
        ])
        .arg(&dockerfile)
        .arg(ws_root)
        .status()
        .expect("docker build litebox-agent-cli");
    assert!(
        status.success(),
        "docker build {} failed",
        copilot_image_name()
    );
}
