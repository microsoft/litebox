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
//!   cargo test -p `litebox_test_harness` --test integration -- --list                # list all trials
//!
//! Target directory: uses `CARGO_TARGET_DIR` if set, otherwise `target/`.
//!
//! To add a rootfs dependency, edit the Dockerfile. There is no other path.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Condvar, Mutex};

use libtest_mimic::{Arguments, Failed, Trial};

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

/// Cached test IDs from `collect_all_tests` (direct library call, no subprocess).
static TEST_IDS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

fn get_test_ids() -> &'static Vec<String> {
    TEST_IDS.get_or_init(|| {
        let tests = litebox_test_harness::coordinator::collect_all_tests();
        let ids: Vec<String> = tests.into_iter().map(|t| t.id).collect();
        eprintln!(
            "[integration] {} test IDs from collect_all_tests",
            ids.len()
        );
        ids
    })
}

/// Whether to keep docker containers after exit (for debugging).
fn keep_containers() -> bool {
    std::env::var("LITEBOX_KEEP_CONTAINER").is_ok()
}

/// `--rm` unless `LITEBOX_KEEP_CONTAINER` is set. We pass `--name` so
/// the container is identifiable in `docker ps` for debugging.
fn docker_run_base_args() -> Vec<&'static str> {
    if keep_containers() {
        vec!["run", "--cap-add", "SYS_PTRACE"]
    } else {
        vec!["run", "--rm", "--cap-add", "SYS_PTRACE"]
    }
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

fn active_jobs() -> &'static Semaphore {
    ACTIVE_JOBS.get_or_init(|| {
        let n = std::env::var("LITEBOX_TEST_JOBS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);
        eprintln!("[integration] LITEBOX_TEST_JOBS={n}");
        Semaphore::new(n)
    })
}

fn drain_backlog() -> &'static Semaphore {
    DRAIN_BACKLOG.get_or_init(|| {
        let n = std::env::var("LITEBOX_DRAIN_BACKLOG")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);
        Semaphore::new(n)
    })
}

/// Best-effort sanitize a test id into a docker container name suffix.
fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// Build the docker command for a single-test run. We pass `--name`
/// so the container is identifiable in `docker ps` and so
/// `LITEBOX_KEEP_CONTAINER` users can find it after the test
/// finishes; the orchestrator never force-kills it externally.
fn build_docker_cmd(
    pass: &str,
    test_id: &str,
    container_name: &str,
    debug: &Path,
    nonpie: &Path,
) -> Command {
    let filter = format!("--filter={test_id}");
    let mut cmd = Command::new("docker");
    cmd.args(docker_run_base_args())
        .arg("--name")
        .arg(container_name)
        .arg("-v")
        .arg(format!("{}:/opt/litebox:ro", debug.display()))
        .arg("-v")
        .arg(format!("{}:/opt/nonpie:ro", nonpie.display()))
        .arg("litebox-test");
    match pass {
        "native" => {
            cmd.arg("/opt/litebox/litebox_test_harness")
                .arg("spawn-tree")
                .arg(&filter);
        }
        "litebox" => {
            cmd.args(["timeout", "--signal=KILL", "120"])
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
    let permit = active_jobs().acquire();
    let (_, debug, nonpie) = setup();
    let container_name = format!(
        "litebox-{}-{}-{}-{}",
        pass,
        sanitize_id(test_id),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    );

    let stdout_log = log_path_for(pass, test_id, "stdout");
    let stderr_log = log_path_for(pass, test_id, "stderr");

    let mut cmd = build_docker_cmd(pass, test_id, &container_name, &debug, &nonpie);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::from(
        std::fs::File::create(&stderr_log)
            .unwrap_or_else(|e| panic!("create {}: {e}", stderr_log.display())),
    ));

    let label = format!("{pass}[{test_id}]");
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("docker spawn failed for {label}: {e}"));

    let stdout = child.stdout.take().expect("stdout piped");

    // Read stdout line by line; tee each line to the stdout log
    // file, and record the first JSON line whose "test" field
    // matches our test_id.
    let mut stdout_log_file = std::fs::File::create(&stdout_log)
        .unwrap_or_else(|e| panic!("create {}: {e}", stdout_log.display()));
    let mut found: Option<serde_json::Value> = None;
    for line in BufReader::new(stdout).lines() {
        let Ok(line) = line else { break };
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

    // Hand off the still-running child to a drain worker. It just
    // waits for clean exit so we bound zombies / per-host docker
    // population. Logs are already on disk (stderr via Stdio::from,
    // stdout via the tee above).
    spawn_drain(child);
    drop(permit);

    found.ok_or_else(|| {
        format!(
            "{label}: no JSON result for {test_id} on stdout (full log: {})",
            stdout_log.display(),
        )
        .into()
    })
}

/// Background drain: hold a `drain_backlog` permit until the child
/// container exits on its own. We deliberately do **not** force-kill
/// from out here:
///
///   * The harness's `teardown_tree` is already wall-clock-bounded
///     (commit 1c1ae050: 10 s) and main hard-exits via
///     `std::process::exit`, so the host process tree collapses
///     promptly.
///   * The outer `docker run` for the litebox pass wraps its inner
///     process in `timeout --signal=KILL`, so a genuinely stuck
///     container will be killed by docker itself.
///   * `--rm` cleans up the container record once the inner process
///     exits.
///
/// The drain thread bounds the backlog: if drain takes longer than
/// the test loop, callers block on `active_jobs.acquire` (because
/// new test slots only open after a drain finishes), which is the
/// right back-pressure signal.
fn spawn_drain(mut child: std::process::Child) {
    let backlog_permit = drain_backlog().acquire();
    std::thread::spawn(move || {
        let _hold_backlog = backlog_permit;
        let _ = child.wait();
    });
}

// ── Main ─────────────────────────────────────────────────────────────

fn main() {
    let args = Arguments::from_args();

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
        let (_, debug, nonpie) = setup();
        run_host_fwd(&debug, &nonpie);
        Ok(())
    }));

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

/// Build all required binaries (PIE + non-PIE) to the target directory.
fn ensure_binaries_built(ws_root: &Path) {
    let td = target_dir();
    let td_str = td.to_string_lossy();

    eprintln!("Building litebox binaries (PIE) to {td_str}...");
    let status = Command::new("cargo")
        .current_dir(ws_root)
        .args([
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
        ])
        .status()
        .expect("cargo build");
    assert!(status.success(), "cargo build (PIE) failed");

    let nonpie_td = td.join("nonpie");
    let nonpie_td_str = nonpie_td.to_string_lossy();
    eprintln!("Building litebox_test_harness (non-PIE) to {nonpie_td_str}...");
    let status = Command::new("cargo")
        .current_dir(ws_root)
        .args([
            "rustc",
            "-p",
            "litebox_test_harness",
            "--bin",
            "litebox_test_harness",
            "--target-dir",
            &nonpie_td_str,
            "--",
            "-C",
            "link-args=-no-pie",
        ])
        .status()
        .expect("cargo rustc nonpie");
    assert!(status.success(), "cargo build (non-PIE) failed");
}

/// Shared setup: build binaries and Docker image once per `cargo test`
/// process, return cached paths. libtest-mimic dispatches Trials in
/// threads of one process, so a `OnceLock` guarantees `cargo build`
/// and `docker build` are invoked at most once per run rather than
/// once per Trial. Under `cargo nextest` (where each Trial is its
/// own process) we'd additionally need a `flock`-based file lock;
/// out of scope for this iteration.
static SETUP_ONCE: std::sync::OnceLock<(PathBuf, PathBuf, PathBuf)> = std::sync::OnceLock::new();

fn setup() -> (PathBuf, PathBuf, PathBuf) {
    SETUP_ONCE
        .get_or_init(|| {
            let ws_root = workspace_root();
            ensure_binaries_built(&ws_root);
            ensure_docker_image(&ws_root);
            let debug = debug_dir();
            let nonpie = nonpie_dir();
            let harness = debug.join("litebox_test_harness");
            assert!(
                harness.exists(),
                "litebox_test_harness not found at {}",
                harness.display()
            );
            let nonpie_bin = nonpie.join("litebox_test_harness");
            assert!(
                nonpie_bin.exists(),
                "non-PIE litebox_test_harness not found at {}",
                nonpie_bin.display()
            );
            (ws_root, debug, nonpie)
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
